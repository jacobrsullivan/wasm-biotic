//! Explicitly rooted, persistent implementations of the native mechanisms.

use crate::bindings::root::wasm_biotic::factory::{
    activation, audit_log, blob_store, clock, component_runner, foundation, http_transport,
    key_service, transaction_store,
};
use crate::http_transport as bounded_http;
use crate::{KernelError, Sha256Digest, TrustedCertifier};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{self, Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

const STATE_SCHEMA: u32 = 1;
const STATE_FILE: &str = "mechanisms.json";
const STATE_TEMP_FILE: &str = "mechanisms.json.tmp";
const STATE_LOCK_FILE: &str = "mechanisms.lock";
const HTTP_DISPATCH_LOCK_FILE: &str = "http-dispatch.lock";
const BLOBS_DIR: &str = "blobs";
const COMPONENTS_DIR: &str = "components";
const MAX_IDENTIFIER_BYTES: usize = 512;
const MAX_PACKAGE_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;
const MAX_OPERATOR_CONFIG_BYTES: u64 = 64 * 1024;
const OPERATOR_CONFIG_SCHEMA: &str = "wasm-biotic.operator-mechanism-capacity.v1";
const OPERATOR_CONFIG_SCHEMA_V2: &str = "wasm-biotic.operator-mechanism-capacity.v2";
const MAX_ROOT_INSTANCES: u32 = 256;
const MAX_ROOT_MEMORIES: u32 = 128;
const MAX_ROOT_TABLES: u32 = 128;
const MAX_ROOT_TABLE_ELEMENTS: u32 = 1_000_000;
const IMPLEMENTATION_ID: &[u8] = b"wasm-biotic-kernel-mechanisms-v1";
const R2_OPERATION_SCHEMA: &str = "wasm-biotic.principal-operation.v1";

pub(crate) struct PackageDirectory {
    root: PathBuf,
}

impl PackageDirectory {
    pub(crate) fn open(root: impl AsRef<Path>) -> Result<Self, KernelError> {
        let root = fs::canonicalize(root.as_ref()).map_err(persistence)?;
        if !root.is_dir() {
            return Err(KernelError::InvalidConfiguration(
                "launch package path is not a directory".to_string(),
            ));
        }
        Ok(Self { root })
    }

    pub(crate) fn read(&self, relative: impl AsRef<Path>) -> Result<Vec<u8>, KernelError> {
        let relative = relative.as_ref();
        if relative.is_absolute()
            || relative
                .components()
                .any(|part| !matches!(part, std::path::Component::Normal(_)))
        {
            return Err(KernelError::InvalidConfiguration(
                "launch package contains an invalid artifact path".to_string(),
            ));
        }
        let path = fs::canonicalize(self.root.join(relative)).map_err(persistence)?;
        if !path.starts_with(&self.root) || !path.is_file() {
            return Err(KernelError::InvalidConfiguration(
                "launch package artifact escapes its directory or is not a file".to_string(),
            ));
        }
        let size = fs::metadata(&path).map_err(persistence)?.len();
        if size > MAX_PACKAGE_ARTIFACT_BYTES {
            return Err(KernelError::InvalidConfiguration(
                "launch package artifact exceeds the native admission bound".to_string(),
            ));
        }
        fs::read(path).map_err(persistence)
    }
}

struct StateFileLock(File);

impl StateFileLock {
    fn acquire(root: &Path) -> Result<Self, KernelError> {
        let mut options = OpenOptions::new();
        options.create(true).read(true).write(true);
        #[cfg(unix)]
        options.mode(0o600);
        let file = options
            .open(root.join(STATE_LOCK_FILE))
            .map_err(persistence)?;
        file.lock().map_err(persistence)?;
        Ok(Self(file))
    }
}

impl Drop for StateFileLock {
    fn drop(&mut self) {
        let _ = File::unlock(&self.0);
    }
}

struct HttpDispatchLease(File);

impl HttpDispatchLease {
    fn acquire(root: &Path) -> Result<Self, KernelError> {
        let mut options = OpenOptions::new();
        options.create(true).read(true).write(true);
        #[cfg(unix)]
        options.mode(0o600);
        let file = options
            .open(root.join(HTTP_DISPATCH_LOCK_FILE))
            .map_err(persistence)?;
        file.try_lock().map_err(|error| {
            KernelError::InvalidConfiguration(format!(
                "HTTP-enabled mechanism root already has a dispatch owner: {error}"
            ))
        })?;
        Ok(Self(file))
    }
}

impl Drop for HttpDispatchLease {
    fn drop(&mut self) {
        let _ = File::unlock(&self.0);
    }
}

/// Bounds and scopes enforced independently of application payload meaning.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalConfig {
    max_blob_bytes: u64,
    max_total_blob_bytes: u64,
    max_random_bytes: u32,
    max_wake_delay_ms: u64,
    max_http_timeout_ms: u64,
    max_component_fuel: u64,
    max_component_memory_bytes: u64,
    max_component_output_bytes: u64,
    max_component_wall_time_ms: u64,
    allowed_namespaces: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    http_transport: Option<bounded_http::HttpOperatorCapacity>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperatorConfigDocument {
    schema: String,
    mechanisms: LocalConfig,
}

pub(crate) struct RequiredCapacity {
    pub(crate) max_blob_bytes: u64,
    pub(crate) max_total_blob_bytes: u64,
    pub(crate) max_random_bytes: u32,
    pub(crate) max_wake_delay_ms: u64,
    pub(crate) max_http_timeout_ms: u64,
    pub(crate) max_component_fuel: u64,
    pub(crate) max_component_memory_bytes: u64,
    pub(crate) max_component_output_bytes: u64,
    pub(crate) max_component_wall_time_ms: u64,
    pub(crate) transaction_namespaces: BTreeSet<String>,
}

impl Default for LocalConfig {
    fn default() -> Self {
        Self {
            max_blob_bytes: 16 * 1024 * 1024,
            max_total_blob_bytes: 256 * 1024 * 1024,
            max_random_bytes: 4096,
            max_wake_delay_ms: 30 * 24 * 60 * 60 * 1000,
            max_http_timeout_ms: 30_000,
            max_component_fuel: 50_000_000,
            max_component_memory_bytes: 64 * 1024 * 1024,
            max_component_output_bytes: 16 * 1024 * 1024,
            max_component_wall_time_ms: 30_000,
            allowed_namespaces: BTreeSet::new(),
            http_transport: None,
        }
    }
}

impl LocalConfig {
    /// Loads an explicitly selected, canonical operator-capacity document.
    ///
    /// The document contains only generic mechanism bounds and exact opaque
    /// transaction namespaces. A single terminal line feed is accepted for a
    /// POSIX text file; all JSON bytes before it must be canonical.
    pub fn from_canonical_json_file(path: impl AsRef<Path>) -> Result<Self, KernelError> {
        let path = fs::canonicalize(path.as_ref()).map_err(persistence)?;
        if !path.is_file() {
            return Err(KernelError::InvalidConfiguration(
                "operator capacity path is not a file".to_string(),
            ));
        }
        if fs::metadata(&path).map_err(persistence)?.len() > MAX_OPERATOR_CONFIG_BYTES {
            return Err(KernelError::InvalidConfiguration(
                "operator capacity document exceeds the native input bound".to_string(),
            ));
        }
        let bytes = fs::read(path).map_err(persistence)?;
        let canonical_input = bytes.strip_suffix(b"\n").unwrap_or(&bytes);
        let value: serde_json::Value =
            serde_json::from_slice(canonical_input).map_err(|error| {
                KernelError::InvalidConfiguration(format!(
                    "operator capacity document is not valid JSON: {error}"
                ))
            })?;
        let mut canonical = Vec::new();
        write_canonical_config_value(&value, &mut canonical)?;
        if canonical != canonical_input {
            return Err(KernelError::InvalidConfiguration(
                "operator capacity document is not canonical JSON".to_string(),
            ));
        }
        let document: OperatorConfigDocument = serde_json::from_value(value).map_err(|error| {
            KernelError::InvalidConfiguration(format!(
                "operator capacity document does not match its closed schema: {error}"
            ))
        })?;
        if (document.schema != OPERATOR_CONFIG_SCHEMA
            && document.schema != OPERATOR_CONFIG_SCHEMA_V2)
            || (document.schema == OPERATOR_CONFIG_SCHEMA
                && document.mechanisms.http_transport.is_some())
            || (document.schema == OPERATOR_CONFIG_SCHEMA_V2
                && document.mechanisms.http_transport.is_none())
        {
            return Err(KernelError::InvalidConfiguration(format!(
                "unsupported operator capacity schema '{}'",
                document.schema
            )));
        }
        let typed_value = serde_json::to_value(&document)
            .map_err(|error| KernelError::InvalidConfiguration(error.to_string()))?;
        let mut typed_canonical = Vec::new();
        write_canonical_config_value(&typed_value, &mut typed_canonical)?;
        if typed_canonical != canonical_input {
            return Err(KernelError::InvalidConfiguration(
                "operator capacity document is not the canonical closed-schema representation"
                    .to_string(),
            ));
        }
        validate_config(&document.mechanisms)?;
        Ok(document.mechanisms)
    }

    pub(crate) fn from_manifest_ceiling(required: RequiredCapacity) -> Self {
        Self {
            max_blob_bytes: required.max_blob_bytes,
            max_total_blob_bytes: required.max_total_blob_bytes,
            max_random_bytes: required.max_random_bytes,
            max_wake_delay_ms: required.max_wake_delay_ms,
            max_http_timeout_ms: required.max_http_timeout_ms,
            max_component_fuel: required.max_component_fuel,
            max_component_memory_bytes: required.max_component_memory_bytes,
            max_component_output_bytes: required.max_component_output_bytes,
            max_component_wall_time_ms: required.max_component_wall_time_ms,
            allowed_namespaces: required.transaction_namespaces,
            http_transport: None,
        }
    }

    /// Adds one exact opaque transaction namespace to the local grant.
    #[must_use]
    pub fn allow_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.allowed_namespaces.insert(namespace.into());
        self
    }

    /// Sets the maximum size of one immutable blob.
    #[must_use]
    pub const fn with_max_blob_bytes(mut self, value: u64) -> Self {
        self.max_blob_bytes = value;
        self
    }

    /// Sets the cumulative immutable-blob quota.
    #[must_use]
    pub const fn with_max_total_blob_bytes(mut self, value: u64) -> Self {
        self.max_total_blob_bytes = value;
        self
    }

    /// Sets the largest secure-random response.
    #[must_use]
    pub const fn with_max_random_bytes(mut self, value: u32) -> Self {
        self.max_random_bytes = value;
        self
    }

    /// Sets the largest admitted per-call component fuel request.
    #[must_use]
    pub const fn with_max_component_fuel(mut self, value: u64) -> Self {
        self.max_component_fuel = value;
        self
    }

    /// Sets the largest admitted per-call component memory request.
    #[must_use]
    pub const fn with_max_component_memory_bytes(mut self, value: u64) -> Self {
        self.max_component_memory_bytes = value;
        self
    }
}

/// Source of epoch milliseconds used by the clock mechanism.
pub trait TimeSource: Send + Sync {
    /// Returns the current epoch millisecond value.
    fn now_ms(&self) -> u64;
}

/// One deterministic crash boundary exposed by the local persistence harness.
///
/// These sites describe generic mechanism phases only. They deliberately do
/// not name factory roles, workflows, services, operations, or policy values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DurabilityFaultPoint {
    /// Immediately before bytes are written to an atomic temporary file.
    BeforeTempWrite,
    /// Immediately after all bytes are written to an atomic temporary file.
    AfterTempWrite,
    /// Immediately before the temporary file is synchronized.
    BeforeTempSync,
    /// Immediately after the temporary file is synchronized.
    AfterTempSync,
    /// Immediately before the temporary file is renamed over its target.
    BeforeRename,
    /// Immediately after the temporary file is renamed over its target.
    AfterRename,
    /// Immediately before the target directory is synchronized.
    BeforeDirectorySync,
    /// Immediately after the target directory is synchronized.
    AfterDirectorySync,
    /// Immediately before an in-memory mechanism-state transition.
    BeforeStateChange,
    /// Immediately after an in-memory mechanism-state transition.
    AfterStateChange,
    /// Immediately before changed mechanism state is durably committed.
    BeforeStateCommit,
    /// Immediately after changed mechanism state is durably committed.
    AfterStateCommit,
    /// Immediately before dispatching an admitted component invocation.
    BeforeComponentDispatch,
    /// Immediately after an admitted component invocation returns.
    AfterComponentDispatch,
    /// Immediately before the component completion value is constructed.
    BeforeComponentCompletion,
    /// After the component completion value is fully constructed.
    AfterComponentCompletion,
    /// Immediately before a component-run receipt is durably committed.
    BeforeRunReceiptCommit,
    /// Immediately after a component-run receipt is durably committed.
    AfterRunReceiptCommit,
    /// Immediately before an HTTP operation is durably marked dispatching.
    BeforeHttpDispatchRecord,
    /// Immediately after an HTTP operation is durably marked dispatching.
    AfterHttpDispatchRecord,
    /// Immediately before the single admitted HTTP socket attempt.
    BeforeHttpSocketDispatch,
    /// Immediately after an HTTP response has been received and bounded.
    AfterHttpResponse,
    /// Immediately before a terminal HTTP outcome is durably committed.
    BeforeHttpOutcomeCommit,
    /// Immediately after a terminal HTTP outcome is durably committed.
    AfterHttpOutcomeCommit,
}

/// Exact one-shot fault selected by a conformance test.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurabilityFaultSpec {
    /// Generic phase at which the simulated crash occurs.
    pub point: DurabilityFaultPoint,
    /// Opaque mechanism operation label, such as `mechanism-state`.
    pub operation: String,
    /// Number of matching observations to skip before firing.
    pub skip_matches: u64,
}

#[derive(Debug, Default)]
struct FaultState {
    armed: Option<DurabilityFaultSpec>,
    fired: Vec<DurabilityFaultSpec>,
}

/// Cloneable, explicitly injected controller for deterministic crash tests.
///
/// Ordinary `LocalMechanisms` constructors install a permanently disarmed
/// controller. A test must opt in through `open_with_fault_injection`, arm one
/// exact site, and discard every mechanism handle after that site returns an
/// injected persistence error, just as it would after a process crash.
#[derive(Clone, Debug, Default)]
pub struct DurabilityFaultController {
    state: Arc<Mutex<FaultState>>,
}

impl DurabilityFaultController {
    /// Arms the next matching phase and operation label.
    pub fn arm(&self, point: DurabilityFaultPoint, operation: impl Into<String>) {
        self.arm_after(point, operation, 0);
    }

    /// Arms a matching phase after deterministically skipping `skip_matches`.
    pub fn arm_after(
        &self,
        point: DurabilityFaultPoint,
        operation: impl Into<String>,
        skip_matches: u64,
    ) {
        let mut state = self
            .state
            .lock()
            .expect("fault controller lock is not poisoned");
        state.armed = Some(DurabilityFaultSpec {
            point,
            operation: operation.into(),
            skip_matches,
        });
    }

    /// Disarms a pending fault without altering the fired-site record.
    pub fn disarm(&self) {
        self.state
            .lock()
            .expect("fault controller lock is not poisoned")
            .armed = None;
    }

    /// Returns the exact sites that fired, in observation order.
    pub fn fired(&self) -> Vec<DurabilityFaultSpec> {
        self.state
            .lock()
            .expect("fault controller lock is not poisoned")
            .fired
            .clone()
    }

    fn inject(&self, point: DurabilityFaultPoint, operation: &str) -> Result<(), KernelError> {
        let mut state = self.state.lock().map_err(|_| {
            KernelError::Persistence("fault controller lock is poisoned".to_string())
        })?;
        let Some(armed) = state.armed.as_mut() else {
            return Ok(());
        };
        if armed.point != point || armed.operation != operation {
            return Ok(());
        }
        if armed.skip_matches != 0 {
            armed.skip_matches -= 1;
            return Ok(());
        }
        let fired = state.armed.take().expect("matched fault remains armed");
        let diagnostic = format!(
            "injected crash at {:?} for opaque mechanism operation '{}'",
            fired.point, fired.operation
        );
        state.fired.push(fired);
        Err(KernelError::Persistence(diagnostic))
    }
}

/// Operating-system wall clock used by the ordinary local profile.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemTimeSource;

impl TimeSource for SystemTimeSource {
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct IdempotentCommit {
    request_digest: String,
    receipt: transaction_store::CommitReceipt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WakeRecord {
    request_digest: String,
    request: clock::WakeRequest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    caller_principal_seed: Option<Sha256Digest>,
    cancelled: bool,
    fired_at_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct StoredRun {
    pub(crate) request_digest: String,
    pub(crate) operation_id: String,
    pub(crate) completion: component_runner::RunCompletion,
    #[serde(default)]
    pub(crate) provenance: Option<crate::root_runtime::ExecutionProvenance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) caller_principal_seed: Option<Sha256Digest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct StoredExecutionBinding {
    executable_digest: String,
    source_component_digests: Vec<String>,
    #[serde(default)]
    grants: Vec<StoredGrant>,
    #[serde(default)]
    principal_seeds: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct StoredGrant {
    capability: String,
    scope: String,
    constraint_digest: String,
}

#[derive(Clone, Debug)]
pub(crate) struct AdmittedGrant {
    pub(crate) capability: String,
    pub(crate) scope: String,
    pub(crate) constraint_digest: Sha256Digest,
}

pub(crate) type AdmittedExecutionBinding = (
    Sha256Digest,
    Sha256Digest,
    Vec<Sha256Digest>,
    Vec<AdmittedGrant>,
    Vec<Sha256Digest>,
);

pub(crate) struct RootBindingAdmission<'a> {
    pub(crate) manifest_digest: Sha256Digest,
    pub(crate) composed_root_digest: Sha256Digest,
    pub(crate) source_component_digests: &'a [Sha256Digest],
    pub(crate) execution_bindings: &'a [AdmittedExecutionBinding],
    pub(crate) r2_principals: &'a [crate::root_runtime::AdmittedPrincipal],
    pub(crate) r2_invocations: &'a [(Sha256Digest, Sha256Digest)],
    pub(crate) r2_root_principal_seeds: &'a [Sha256Digest],
    pub(crate) validation_report_digest: Sha256Digest,
    pub(crate) release_certification_digest: Sha256Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct StoredHostImport {
    alias: String,
    source_import: String,
    capability: String,
    scope: String,
    constraint_digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct StoredPrincipal {
    consumer: String,
    authority_component_digest: String,
    principal_seed: String,
    scoped_component_digest: String,
    host_imports: Vec<StoredHostImport>,
}

fn stored_principal_to_admitted(
    principal: &StoredPrincipal,
) -> Result<crate::root_runtime::AdmittedPrincipal, foundation::Failure> {
    let parse = |value: &str| {
        format!("sha256:{value}")
            .parse()
            .map_err(|_| failure("integrity-error", "stored principal digest is invalid"))
    };
    Ok(crate::root_runtime::AdmittedPrincipal {
        consumer: principal.consumer.clone(),
        authority_component_digest: parse(&principal.authority_component_digest)?,
        principal_seed: parse(&principal.principal_seed)?,
        scoped_component_digest: parse(&principal.scoped_component_digest)?,
        host_imports: principal
            .host_imports
            .iter()
            .map(|import| {
                Ok(crate::root_runtime::AdmittedHostImport {
                    alias: import.alias.clone(),
                    source_import: import.source_import.clone(),
                    capability: import.capability.clone(),
                    scope: import.scope.clone(),
                    constraint_digest: parse(&import.constraint_digest)?,
                })
            })
            .collect::<Result<Vec<_>, foundation::Failure>>()?,
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct StoredRootBinding {
    composed_root_digest: String,
    source_component_digests: Vec<String>,
    execution_bindings: BTreeMap<String, StoredExecutionBinding>,
    #[serde(default)]
    scoped_component_digests: Vec<String>,
    #[serde(default)]
    principals: BTreeMap<String, StoredPrincipal>,
    #[serde(default)]
    invocation_targets: BTreeMap<String, BTreeSet<String>>,
    #[serde(default)]
    root_principal_seeds: Vec<String>,
    #[serde(default)]
    validation_report_digest: String,
    #[serde(default)]
    release_certification_digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredActivation {
    request_digest: String,
    target_graph: foundation::Digest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    caller_principal_seed: Option<Sha256Digest>,
    #[serde(default)]
    target_state: Option<foundation::BlobRef>,
    status: activation::ActivationStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredAudit {
    request_digest: String,
    entry: audit_log::AuditEntry,
    receipt: audit_log::AuditReceipt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredKey {
    key_id: String,
    pkcs8: Vec<u8>,
    public_key: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredHttpOwner {
    graph_manifest_digest: Sha256Digest,
    principal_seed: Sha256Digest,
    alias: String,
    constraint_digest: Sha256Digest,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpTransportReceiptV1 {
    schema: String,
    operation_id: String,
    owner: StoredHttpOwner,
    request_digest: Sha256Digest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resolved_address: Option<String>,
    disposition: String,
    started_at_ms: u64,
    finished_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    facts: Option<bounded_http::TransportFactsV1>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "kebab-case", deny_unknown_fields)]
enum StoredHttpState {
    Prepared,
    Dispatching {
        resolved_address: String,
    },
    Completed {
        response: http_transport::Response,
        transport_receipt: HttpTransportReceiptV1,
    },
    DefiniteFailure {
        failure: foundation::Failure,
        transport_receipt: HttpTransportReceiptV1,
    },
    CancelledBeforeDispatch {
        failure: foundation::Failure,
        transport_receipt: HttpTransportReceiptV1,
    },
    Indeterminate {
        failure: foundation::Failure,
        transport_receipt: HttpTransportReceiptV1,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredHttpOperation {
    owner: StoredHttpOwner,
    request_digest: Sha256Digest,
    request: http_transport::Request,
    started_at_ms: u64,
    state: StoredHttpState,
}

#[derive(Clone, Debug)]
pub(crate) struct HttpAuthority {
    pub(crate) graph_manifest_digest: Sha256Digest,
    pub(crate) principal_seed: Sha256Digest,
    pub(crate) alias: String,
    pub(crate) constraint_digest: Sha256Digest,
}

impl HttpAuthority {
    fn stored(&self) -> StoredHttpOwner {
        StoredHttpOwner {
            graph_manifest_digest: self.graph_manifest_digest,
            principal_seed: self.principal_seed,
            alias: self.alias.clone(),
            constraint_digest: self.constraint_digest,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DurableState {
    schema: u32,
    #[serde(default)]
    generation: u64,
    #[serde(default)]
    configured_capacity: Option<LocalConfig>,
    #[serde(default)]
    trusted_bootstrap_manifest: Option<Sha256Digest>,
    #[serde(default)]
    trusted_certifier: Option<TrustedCertifier>,
    total_blob_bytes: u64,
    blobs: BTreeMap<String, u64>,
    transaction_version: u64,
    values: BTreeMap<String, BTreeMap<String, transaction_store::VersionedValue>>,
    commits: BTreeMap<String, IdempotentCommit>,
    wakes: BTreeMap<String, WakeRecord>,
    wake_idempotency: BTreeMap<String, String>,
    runs: BTreeMap<String, StoredRun>,
    operation_runs: BTreeMap<String, String>,
    admitted_components: BTreeMap<String, u64>,
    admitted_graphs: BTreeSet<String>,
    #[serde(default)]
    root_bindings: BTreeMap<String, StoredRootBinding>,
    activations: BTreeMap<String, StoredActivation>,
    activation_idempotency: BTreeMap<String, String>,
    #[serde(default, alias = "active_graph")]
    active_manifest: Option<foundation::Digest>,
    #[serde(default)]
    active_state: Option<foundation::BlobRef>,
    #[serde(default, alias = "last_known_good_graph")]
    last_known_good_manifest: Option<foundation::Digest>,
    #[serde(default)]
    last_known_good_state: Option<foundation::BlobRef>,
    audit: Vec<StoredAudit>,
    audit_idempotency: BTreeMap<String, u64>,
    keys: BTreeMap<String, StoredKey>,
    #[serde(default)]
    http_operations: BTreeMap<String, StoredHttpOperation>,
    #[serde(default)]
    http_idempotency: BTreeMap<String, String>,
}

impl Default for DurableState {
    fn default() -> Self {
        Self {
            schema: STATE_SCHEMA,
            generation: 0,
            configured_capacity: None,
            trusted_bootstrap_manifest: None,
            trusted_certifier: None,
            total_blob_bytes: 0,
            blobs: BTreeMap::new(),
            transaction_version: 0,
            values: BTreeMap::new(),
            commits: BTreeMap::new(),
            wakes: BTreeMap::new(),
            wake_idempotency: BTreeMap::new(),
            runs: BTreeMap::new(),
            operation_runs: BTreeMap::new(),
            admitted_components: BTreeMap::new(),
            admitted_graphs: BTreeSet::new(),
            root_bindings: BTreeMap::new(),
            activations: BTreeMap::new(),
            activation_idempotency: BTreeMap::new(),
            active_manifest: None,
            active_state: None,
            last_known_good_manifest: None,
            last_known_good_state: None,
            audit: Vec::new(),
            audit_idempotency: BTreeMap::new(),
            keys: BTreeMap::new(),
            http_operations: BTreeMap::new(),
            http_idempotency: BTreeMap::new(),
        }
    }
}

fn recover_interrupted_http(
    state: &mut DurableState,
    finished_at_ms: u64,
) -> Result<(), KernelError> {
    let mut changed = false;
    for (operation_id, operation) in &mut state.http_operations {
        if let StoredHttpState::Dispatching { resolved_address } = &operation.state {
            let resolved_address = resolved_address.clone();
            let failure = failure(
                "transport-outcome-unknown",
                "HTTP dispatch crossed a restart boundary; native replay is forbidden",
            );
            let receipt = http_transport_receipt(
                operation_id,
                &operation.owner,
                operation.request_digest,
                Some(resolved_address),
                "indeterminate",
                (operation.started_at_ms, finished_at_ms),
                None,
            );
            operation.state = StoredHttpState::Indeterminate {
                failure,
                transport_receipt: receipt,
            };
            changed = true;
        }
    }
    if changed {
        state.generation = state.generation.checked_add(1).ok_or_else(|| {
            KernelError::Persistence("mechanism-state generation exhausted".to_string())
        })?;
    }
    Ok(())
}

fn http_transport_receipt(
    operation_id: &str,
    owner: &StoredHttpOwner,
    request_digest: Sha256Digest,
    resolved_address: Option<String>,
    disposition: &str,
    times: (u64, u64),
    facts: Option<bounded_http::TransportFactsV1>,
) -> HttpTransportReceiptV1 {
    HttpTransportReceiptV1 {
        schema: "wasm-biotic.http-transport-receipt.v1".to_string(),
        operation_id: operation_id.to_string(),
        owner: owner.clone(),
        request_digest,
        resolved_address,
        disposition: disposition.to_string(),
        started_at_ms: times.0,
        finished_at_ms: times.1,
        facts,
    }
}

fn graph_principal_handle_key(
    graph_manifest_digest: Sha256Digest,
    principal_seed: Sha256Digest,
    capability: &str,
    handle: &str,
) -> String {
    format!(
        "{}:{}:{}:{}",
        digest_hex(graph_manifest_digest),
        digest_hex(principal_seed),
        capability,
        handle
    )
}

fn verified_graph_principal_handle_key(
    state: &DurableState,
    graph_manifest_digest: Sha256Digest,
    principal_seed: Sha256Digest,
    capability: &str,
    scope: &str,
    source_import: &str,
    handle: &str,
) -> Result<String, foundation::Failure> {
    let graph_key = digest_hex(graph_manifest_digest);
    if !state.admitted_graphs.contains(&graph_key) {
        return Err(failure(
            "not-admitted",
            "handle destination graph is not admitted",
        ));
    }
    let binding = state.root_bindings.get(&graph_key).ok_or_else(|| {
        failure(
            "not-admitted",
            "handle destination graph has no verified root binding",
        )
    })?;
    let seed_key = digest_hex(principal_seed);
    let principal = binding.principals.get(&seed_key).ok_or_else(|| {
        failure(
            "not-granted",
            "handle destination graph does not retain the caller principal",
        )
    })?;
    if principal.principal_seed != seed_key
        || !principal.host_imports.iter().any(|import| {
            import.capability == capability
                && import.scope == scope
                && import.source_import == source_import
                && !import.alias.is_empty()
        })
    {
        return Err(failure(
            "not-granted",
            "handle destination principal has no matching host import",
        ));
    }
    Ok(graph_principal_handle_key(
        graph_manifest_digest,
        principal_seed,
        capability,
        handle,
    ))
}

fn rekey_activation_owner(
    state: &mut DurableState,
    source_key: &str,
    destination_key: String,
    record: StoredActivation,
) -> Result<(), foundation::Failure> {
    if destination_key != source_key && state.activations.contains_key(&destination_key) {
        return Err(failure(
            "conflict",
            "activation destination handle already exists",
        ));
    }
    state.activations.remove(source_key).ok_or_else(|| {
        failure(
            "integrity-error",
            "activation source handle disappeared during ownership transfer",
        )
    })?;
    if state
        .activations
        .insert(destination_key.clone(), record)
        .is_some()
    {
        return Err(failure(
            "integrity-error",
            "activation ownership transfer replaced an existing handle",
        ));
    }
    for owned_handle in state.activation_idempotency.values_mut() {
        if owned_handle == source_key {
            *owned_handle = destination_key.clone();
        }
    }
    Ok(())
}

#[derive(Clone)]
struct GraphScope {
    manifest_digest: Sha256Digest,
    source_components: BTreeSet<String>,
    execution_bindings: BTreeMap<String, StoredExecutionBinding>,
    principals: BTreeMap<String, StoredPrincipal>,
    invocation_targets: BTreeMap<String, BTreeSet<String>>,
}

struct Inner {
    root: PathBuf,
    config: LocalConfig,
    http_material_root: Option<PathBuf>,
    _http_dispatch_lease: Option<HttpDispatchLease>,
    time: Arc<dyn TimeSource>,
    faults: DurabilityFaultController,
    state: Mutex<DurableState>,
    authority_trace: Mutex<Vec<crate::root_runtime::AuthorityTrace>>,
}

/// Cloneable handle to the explicitly rooted local native mechanisms.
#[derive(Clone)]
pub struct LocalMechanisms {
    inner: Arc<Inner>,
    graph_scope: Option<Arc<GraphScope>>,
}

impl LocalMechanisms {
    /// Initializes a persistent mechanism root with immutable operator capacity
    /// and the exact manifest digest permitted to perform first bootstrap,
    /// plus the independent public key trusted to certify every admission.
    pub fn initialize(
        root: impl AsRef<Path>,
        config: LocalConfig,
        trusted_bootstrap_manifest: Sha256Digest,
        trusted_certifier: TrustedCertifier,
    ) -> Result<Self, KernelError> {
        Self::open_with_time_and_trust(
            root,
            config,
            Arc::new(SystemTimeSource),
            Some(trusted_bootstrap_manifest),
            Some(trusted_certifier),
            DurabilityFaultController::default(),
            None,
        )
    }

    /// Opens or creates a persistent local mechanism root.
    ///
    /// This generic mechanism-only entry point does not configure bootstrap
    /// trust; a root manager therefore cannot bootstrap from it.
    pub fn open(root: impl AsRef<Path>, config: LocalConfig) -> Result<Self, KernelError> {
        Self::open_with_time(root, config, Arc::new(SystemTimeSource))
    }

    /// Opens with an injected clock, primarily for deterministic verification.
    pub fn open_with_time(
        root: impl AsRef<Path>,
        config: LocalConfig,
        time: Arc<dyn TimeSource>,
    ) -> Result<Self, KernelError> {
        Self::open_with_time_and_trust(
            root,
            config,
            time,
            None,
            None,
            DurabilityFaultController::default(),
            None,
        )
    }

    /// Opens a mechanism root with an explicit deterministic crash controller.
    ///
    /// This is a conformance harness, not a production recovery strategy. Once
    /// an injected site fires, callers must discard this handle and reopen the
    /// root to observe exactly the state a restarted process would load.
    pub fn open_with_fault_injection(
        root: impl AsRef<Path>,
        config: LocalConfig,
        time: Arc<dyn TimeSource>,
        faults: DurabilityFaultController,
    ) -> Result<Self, KernelError> {
        Self::open_with_time_and_trust(root, config, time, None, None, faults, None)
    }

    /// Opens an HTTP-enabled mechanism root with separately rooted, owner-only
    /// credential files and optional DER trust roots. The material path and
    /// its bytes are never copied into durable mechanism state.
    pub fn open_with_http_materials(
        root: impl AsRef<Path>,
        config: LocalConfig,
        http_material_root: impl AsRef<Path>,
    ) -> Result<Self, KernelError> {
        let material = bounded_http::validate_material_root(http_material_root.as_ref())?;
        Self::open_with_time_and_trust(
            root,
            config,
            Arc::new(SystemTimeSource),
            None,
            None,
            DurabilityFaultController::default(),
            Some(material),
        )
    }

    /// Opens the HTTP mechanism with deterministic time and crash injection.
    /// This constructor exists for restart and dispatch-boundary conformance.
    pub fn open_with_http_fault_injection(
        root: impl AsRef<Path>,
        config: LocalConfig,
        http_material_root: impl AsRef<Path>,
        time: Arc<dyn TimeSource>,
        faults: DurabilityFaultController,
    ) -> Result<Self, KernelError> {
        let material = bounded_http::validate_material_root(http_material_root.as_ref())?;
        Self::open_with_time_and_trust(root, config, time, None, None, faults, Some(material))
    }

    fn open_with_time_and_trust(
        root: impl AsRef<Path>,
        config: LocalConfig,
        time: Arc<dyn TimeSource>,
        trusted_bootstrap_manifest: Option<Sha256Digest>,
        trusted_certifier: Option<TrustedCertifier>,
        faults: DurabilityFaultController,
        http_material_root: Option<PathBuf>,
    ) -> Result<Self, KernelError> {
        validate_config(&config)?;
        fs::create_dir_all(root.as_ref()).map_err(persistence)?;
        #[cfg(unix)]
        fs::set_permissions(root.as_ref(), fs::Permissions::from_mode(0o700))
            .map_err(persistence)?;
        let root = fs::canonicalize(root.as_ref()).map_err(persistence)?;
        fs::create_dir_all(root.join(BLOBS_DIR)).map_err(persistence)?;
        fs::create_dir_all(root.join(COMPONENTS_DIR)).map_err(persistence)?;
        let http_dispatch_lease = config
            .http_transport
            .as_ref()
            .map(|_| HttpDispatchLease::acquire(&root))
            .transpose()?;
        let _writer_lock = StateFileLock::acquire(&root)?;
        let mut state = load_state(&root, &faults)?;
        let was_initialized = state.configured_capacity.is_some();
        match state.configured_capacity.as_ref() {
            Some(existing) if existing != &config => {
                return Err(KernelError::InvalidConfiguration(
                    "mechanism root is already bound to a different operator capacity".to_string(),
                ));
            }
            Some(_) => {}
            None => {
                state.configured_capacity = Some(config.clone());
            }
        }
        match (state.trusted_bootstrap_manifest, trusted_bootstrap_manifest) {
            (Some(existing), Some(requested)) if existing != requested => {
                return Err(KernelError::InvalidConfiguration(
                    "mechanism root is already bound to a different bootstrap manifest".to_string(),
                ));
            }
            (Some(_), _) => {}
            (None, Some(_)) if was_initialized => {
                return Err(KernelError::InvalidConfiguration(
                    "bootstrap trust cannot be added after mechanism initialization".to_string(),
                ));
            }
            (None, Some(requested)) => {
                state.trusted_bootstrap_manifest = Some(requested);
            }
            (None, None) => {}
        }
        match (state.trusted_certifier.as_ref(), trusted_certifier.as_ref()) {
            (Some(existing), Some(requested)) if existing != requested => {
                return Err(KernelError::InvalidConfiguration(
                    "mechanism root is already bound to a different certifier key".to_string(),
                ));
            }
            (Some(_), _) => {}
            (None, Some(_)) if was_initialized => {
                return Err(KernelError::InvalidConfiguration(
                    "certifier trust cannot be added after mechanism initialization".to_string(),
                ));
            }
            (None, Some(requested)) => {
                state.trusted_certifier = Some(requested.clone());
            }
            (None, None) => {}
        }
        recover_interrupted_http(&mut state, time.now_ms())?;
        persist_state(&root, &state, &faults)?;
        Ok(Self {
            inner: Arc::new(Inner {
                root,
                config,
                http_material_root,
                _http_dispatch_lease: http_dispatch_lease,
                time,
                faults,
                state: Mutex::new(state),
                authority_trace: Mutex::new(Vec::new()),
            }),
            graph_scope: None,
        })
    }

    /// Reopens an existing mechanism root using its immutable operator
    /// capacity. Changing that capacity requires a separate administrative
    /// migration rather than a package-supplied value.
    pub fn open_existing(root: impl AsRef<Path>) -> Result<Self, KernelError> {
        Self::open_existing_with_optional_http_materials(root, None)
    }

    /// Reopens an existing HTTP-enabled root with its separately supplied,
    /// owner-only material directory.
    pub fn open_existing_with_http_materials(
        root: impl AsRef<Path>,
        http_material_root: impl AsRef<Path>,
    ) -> Result<Self, KernelError> {
        let material = bounded_http::validate_material_root(http_material_root.as_ref())?;
        Self::open_existing_with_optional_http_materials(root, Some(material))
    }

    fn open_existing_with_optional_http_materials(
        root: impl AsRef<Path>,
        http_material_root: Option<PathBuf>,
    ) -> Result<Self, KernelError> {
        let root = fs::canonicalize(root.as_ref()).map_err(persistence)?;
        if !root.join(STATE_FILE).is_file() {
            return Err(KernelError::InvalidConfiguration(
                "mechanism root has not been explicitly initialized".to_string(),
            ));
        }
        let _writer_lock = StateFileLock::acquire(&root)?;
        let mut state = load_state(&root, &DurabilityFaultController::default())?;
        let config = state.configured_capacity.clone().ok_or_else(|| {
            KernelError::InvalidConfiguration(
                "mechanism root has no persisted operator capacity".to_string(),
            )
        })?;
        validate_config(&config)?;
        let http_dispatch_lease = config
            .http_transport
            .as_ref()
            .map(|_| HttpDispatchLease::acquire(&root))
            .transpose()?;
        let before = state.generation;
        recover_interrupted_http(&mut state, SystemTimeSource.now_ms())?;
        if state.generation != before {
            persist_state(&root, &state, &DurabilityFaultController::default())?;
        }
        Ok(Self {
            inner: Arc::new(Inner {
                root,
                config,
                http_material_root,
                _http_dispatch_lease: http_dispatch_lease,
                time: Arc::new(SystemTimeSource),
                faults: DurabilityFaultController::default(),
                state: Mutex::new(state),
                authority_trace: Mutex::new(Vec::new()),
            }),
            graph_scope: None,
        })
    }

    /// Stores immutable bytes and returns their verified reference.
    pub fn put_blob(
        &self,
        media_type: String,
        content: Vec<u8>,
    ) -> Result<foundation::BlobRef, foundation::Failure> {
        require_nonempty(&media_type, "media-type")?;
        let size = u64::try_from(content.len())
            .map_err(|_| failure("size-overflow", "blob size exceeds u64"))?;
        if size > self.inner.config.max_blob_bytes {
            return Err(failure(
                "quota-exceeded",
                "blob exceeds configured per-item quota",
            ));
        }
        let digest = Sha256Digest::from_bytes(&content);
        let key = digest_hex(digest);
        let path = self.blob_path(digest);
        let mut state = self.lock_state()?;
        if let Some(existing_size) = state.blobs.get(&key) {
            if *existing_size != size || verify_file(&path, digest, size).is_err() {
                return Err(failure(
                    "integrity-error",
                    "existing blob failed content verification",
                ));
            }
            return Ok(blob_reference(digest, size, media_type));
        }
        let new_total = state
            .total_blob_bytes
            .checked_add(size)
            .ok_or_else(|| failure("quota-exceeded", "blob quota overflow"))?;
        if new_total > self.inner.config.max_total_blob_bytes {
            return Err(failure(
                "quota-exceeded",
                "blob store exceeds configured total quota",
            ));
        }
        let _writer_lock = self.fence_writer(&state).map_err(wit_persistence)?;
        write_atomic(&path, &content, &self.inner.faults, "blob-content")
            .map_err(wit_persistence)?;
        let previous = state.clone();
        if let Err(error) = self
            .inner
            .faults
            .inject(DurabilityFaultPoint::BeforeStateChange, "blob-index-commit")
        {
            return Err(wit_persistence(error));
        }
        state.blobs.insert(key, size);
        state.total_blob_bytes = new_total;
        state.generation = state.generation.checked_add(1).ok_or_else(|| {
            *state = previous.clone();
            failure("version-exhausted", "mechanism-state generation exhausted")
        })?;
        for point in [
            DurabilityFaultPoint::AfterStateChange,
            DurabilityFaultPoint::BeforeStateCommit,
        ] {
            if let Err(error) = self.inner.faults.inject(point, "blob-index-commit") {
                *state = previous;
                return Err(wit_persistence(error));
            }
        }
        if let Err(error) = persist_state(&self.inner.root, &state, &self.inner.faults) {
            *state = previous;
            return Err(wit_persistence(error));
        }
        if let Err(error) = self
            .inner
            .faults
            .inject(DurabilityFaultPoint::AfterStateCommit, "blob-index-commit")
        {
            *state = previous;
            return Err(wit_persistence(error));
        }
        Ok(blob_reference(digest, size, media_type))
    }

    /// Resolves and verifies immutable bytes from a supplied reference.
    pub fn get_blob(&self, reference: foundation::BlobRef) -> Result<Vec<u8>, foundation::Failure> {
        let digest = validate_blob_ref(&reference, self.inner.config.max_blob_bytes)?;
        let state = self.lock_state()?;
        let expected_size = state
            .blobs
            .get(&digest_hex(digest))
            .copied()
            .ok_or_else(|| failure("not-found", "blob digest is not present"))?;
        if expected_size != reference.size_bytes {
            return Err(failure(
                "integrity-error",
                "blob reference size does not match stored size",
            ));
        }
        drop(state);
        read_verified(&self.blob_path(digest), digest, expected_size).map_err(wit_persistence)
    }

    /// Tests whether a validated digest is present and intact.
    pub fn has_blob(&self, digest: foundation::Digest) -> Result<bool, foundation::Failure> {
        let digest = validate_digest(&digest)?;
        let state = self.lock_state()?;
        let Some(size) = state.blobs.get(&digest_hex(digest)).copied() else {
            return Ok(false);
        };
        drop(state);
        Ok(verify_file(&self.blob_path(digest), digest, size).is_ok())
    }

    /// Admits exact Component Model bytes under their caller-supplied digest.
    pub fn admit_component(&self, expected: Sha256Digest, bytes: &[u8]) -> Result<(), KernelError> {
        let actual = Sha256Digest::from_bytes(bytes);
        if actual != expected {
            return Err(KernelError::ComponentDigestMismatch {
                node: "admission".to_string(),
                expected,
                actual,
            });
        }
        if !wasmparser::Parser::is_component(bytes) {
            return Err(KernelError::Compile {
                node: "admission".to_string(),
                reason: "bytes are not a Component Model binary".to_string(),
            });
        }
        let path = self.component_path(expected);
        self.mutate_state("component-admission", |state| {
            write_atomic(&path, bytes, &self.inner.faults, "component-content")?;
            state.admitted_components.insert(
                digest_hex(expected),
                u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            );
            Ok(())
        })
    }

    /// Admits an exact graph-manifest digest after the manifest bytes are stored.
    pub fn admit_graph(&self, manifest: &foundation::BlobRef) -> Result<(), foundation::Failure> {
        let digest = validate_blob_ref(manifest, self.inner.config.max_blob_bytes)?;
        self.get_blob(manifest.clone())?;
        self.mutate_state_wit("graph-admission", |state| {
            state.admitted_graphs.insert(digest_hex(digest));
            Ok(())
        })
    }

    /// Resolves the exact canonical manifest bytes currently selected by the
    /// durable activation pointer.
    pub fn active_manifest_reference(
        &self,
    ) -> Result<Option<foundation::BlobRef>, foundation::Failure> {
        self.selected_manifest_reference(false)
    }

    /// Resolves the exact opaque state pointer selected atomically with the
    /// active graph. State bytes and schemas remain uninterpreted.
    pub fn active_state_reference(
        &self,
    ) -> Result<Option<foundation::BlobRef>, foundation::Failure> {
        let reference = self.lock_state()?.active_state.clone();
        let Some(reference) = reference else {
            return Ok(None);
        };
        validate_blob_ref(&reference, self.inner.config.max_blob_bytes)?;
        self.get_blob(reference.clone())?;
        Ok(Some(reference))
    }

    /// Selects the first verified manifest for an empty mechanism root. This
    /// one-time compare-and-set exists only to bootstrap the component that
    /// owns subsequent activation decisions.
    pub fn bootstrap_active_manifest(
        &self,
        manifest_digest: Sha256Digest,
    ) -> Result<(), KernelError> {
        self.mutate_state("bootstrap-active-manifest", |state| {
            let trusted = state.trusted_bootstrap_manifest.ok_or_else(|| {
                KernelError::InvalidConfiguration(
                    "no operator-trusted bootstrap manifest is configured".to_string(),
                )
            })?;
            if trusted != manifest_digest {
                return Err(KernelError::InvalidConfiguration(format!(
                    "initial manifest {manifest_digest} does not match operator trust anchor {trusted}"
                )));
            }
            let key = digest_hex(manifest_digest);
            if !state.root_bindings.contains_key(&key) {
                return Err(KernelError::InvalidConfiguration(
                    "initial manifest has no verified root binding".to_string(),
                ));
            }
            match state.active_manifest.as_ref() {
                Some(existing)
                    if validate_digest(existing)
                        .map_err(|error| KernelError::Persistence(error.message))?
                        != manifest_digest =>
                {
                    return Err(KernelError::InvalidConfiguration(
                        "an active manifest is already selected".to_string(),
                    ));
                }
                Some(_) => {}
                None => state.active_manifest = Some(digest_value(manifest_digest)),
            }
            Ok(())
        })
    }

    pub(crate) fn require_bootstrap_manifest_trust(
        &self,
        manifest_digest: Sha256Digest,
    ) -> Result<(), KernelError> {
        let trusted = self.require_bootstrap_trust()?;
        if trusted != manifest_digest {
            return Err(KernelError::InvalidConfiguration(format!(
                "initial manifest {manifest_digest} does not match operator trust anchor {trusted}"
            )));
        }
        Ok(())
    }

    pub(crate) fn require_bootstrap_trust(&self) -> Result<Sha256Digest, KernelError> {
        self.inner
            .state
            .lock()
            .map_err(|_| KernelError::Persistence("persistent state lock is poisoned".to_string()))?
            .trusted_bootstrap_manifest
            .ok_or_else(|| {
                KernelError::InvalidConfiguration(
                    "no operator-trusted bootstrap manifest is configured".to_string(),
                )
            })
    }

    pub(crate) fn require_certifier_trust(&self) -> Result<TrustedCertifier, KernelError> {
        self.inner
            .state
            .lock()
            .map_err(|_| KernelError::Persistence("persistent state lock is poisoned".to_string()))?
            .trusted_certifier
            .clone()
            .ok_or_else(|| {
                KernelError::InvalidConfiguration(
                    "no operator-trusted release certifier is configured".to_string(),
                )
            })
    }

    /// Returns the operator's immutable root fuel and memory capacity together
    /// with the kernel's generic instance and table bounds.
    #[must_use]
    pub fn root_runtime_capacity(&self) -> crate::ResourceLimits {
        crate::ResourceLimits {
            fuel: self.inner.config.max_component_fuel,
            max_memory_bytes: self.inner.config.max_component_memory_bytes,
            max_instances: MAX_ROOT_INSTANCES,
            max_memories: MAX_ROOT_MEMORIES,
            max_tables: MAX_ROOT_TABLES,
            max_table_elements: MAX_ROOT_TABLE_ELEMENTS,
        }
    }

    /// Returns the in-process trace of calls that crossed an R2
    /// per-consumer import alias. V1 canonical imports never create entries.
    pub fn authority_trace(&self) -> Result<Vec<crate::root_runtime::AuthorityTrace>, KernelError> {
        self.inner
            .authority_trace
            .lock()
            .map(|trace| trace.clone())
            .map_err(|_| KernelError::Persistence("authority trace lock is poisoned".to_string()))
    }

    pub(crate) fn record_authority_trace(&self, entry: crate::root_runtime::AuthorityTrace) {
        if let Ok(mut trace) = self.inner.authority_trace.lock() {
            trace.push(entry);
        }
    }

    pub(crate) fn active_manifest_digest(&self) -> Result<Option<Sha256Digest>, KernelError> {
        self.selected_manifest_digest(false)
    }

    pub(crate) fn last_known_good_manifest_digest(
        &self,
    ) -> Result<Option<Sha256Digest>, KernelError> {
        self.selected_manifest_digest(true)
    }

    pub(crate) fn restore_last_known_good_manifest(
        &self,
        failed_manifest: Sha256Digest,
    ) -> Result<Sha256Digest, KernelError> {
        self.mutate_state("restore-last-known-good", |state| {
            let active = state
                .active_manifest
                .as_ref()
                .ok_or_else(|| {
                    KernelError::InvalidConfiguration(
                        "there is no active manifest to restore".to_string(),
                    )
                })
                .and_then(|digest| {
                    validate_digest(digest).map_err(|error| KernelError::Persistence(error.message))
                })?;
            if active != failed_manifest {
                return Err(KernelError::InvalidConfiguration(
                    "active manifest changed while recovery was being verified".to_string(),
                ));
            }
            let target = state
                .last_known_good_manifest
                .as_ref()
                .ok_or_else(|| {
                    KernelError::InvalidConfiguration(
                        "there is no last-known-good manifest".to_string(),
                    )
                })
                .and_then(|digest| {
                    validate_digest(digest).map_err(|error| KernelError::Persistence(error.message))
                })?;
            if !state.root_bindings.contains_key(&digest_hex(target)) {
                return Err(KernelError::InvalidConfiguration(
                    "last-known-good manifest has no verified root binding".to_string(),
                ));
            }
            state.active_manifest = Some(digest_value(target));
            state.active_state = state.last_known_good_state.clone();
            state.last_known_good_manifest = None;
            state.last_known_good_state = None;
            Ok(target)
        })
    }

    pub(crate) fn admit_root_binding(
        &self,
        admission: RootBindingAdmission<'_>,
    ) -> Result<(), KernelError> {
        let RootBindingAdmission {
            manifest_digest,
            composed_root_digest,
            source_component_digests,
            execution_bindings,
            r2_principals,
            r2_invocations,
            r2_root_principal_seeds,
            validation_report_digest,
            release_certification_digest,
        } = admission;
        let source_component_digests = source_component_digests
            .iter()
            .map(|digest| digest_hex(*digest))
            .collect::<Vec<_>>();
        let mut stored_execution_bindings = BTreeMap::new();
        for (authority, executable, sources, grants, principal_seeds) in execution_bindings {
            let binding = StoredExecutionBinding {
                executable_digest: digest_hex(*executable),
                source_component_digests: sources
                    .iter()
                    .map(|digest| digest_hex(*digest))
                    .collect(),
                grants: grants
                    .iter()
                    .map(|grant| StoredGrant {
                        capability: grant.capability.clone(),
                        scope: grant.scope.clone(),
                        constraint_digest: digest_hex(grant.constraint_digest),
                    })
                    .collect(),
                principal_seeds: principal_seeds
                    .iter()
                    .map(|digest| digest_hex(*digest))
                    .collect(),
            };
            if stored_execution_bindings
                .insert(digest_hex(*authority), binding)
                .is_some()
            {
                return Err(KernelError::DuplicateNode(authority.to_string()));
            }
        }
        let mut stored_principals = BTreeMap::new();
        for principal in r2_principals {
            let stored = StoredPrincipal {
                consumer: principal.consumer.clone(),
                authority_component_digest: digest_hex(principal.authority_component_digest),
                principal_seed: digest_hex(principal.principal_seed),
                scoped_component_digest: digest_hex(principal.scoped_component_digest),
                host_imports: principal
                    .host_imports
                    .iter()
                    .map(|import| StoredHostImport {
                        alias: import.alias.clone(),
                        source_import: import.source_import.clone(),
                        capability: import.capability.clone(),
                        scope: import.scope.clone(),
                        constraint_digest: digest_hex(import.constraint_digest),
                    })
                    .collect(),
            };
            if stored_principals
                .insert(digest_hex(principal.principal_seed), stored)
                .is_some()
            {
                return Err(KernelError::DuplicateNode(
                    principal.principal_seed.to_string(),
                ));
            }
        }
        let mut invocation_targets = BTreeMap::<String, BTreeSet<String>>::new();
        for (caller, target) in r2_invocations {
            invocation_targets
                .entry(digest_hex(*caller))
                .or_default()
                .insert(digest_hex(*target));
        }
        let mut scoped_component_digests = r2_principals
            .iter()
            .map(|principal| digest_hex(principal.scoped_component_digest))
            .collect::<Vec<_>>();
        scoped_component_digests.sort();
        scoped_component_digests.dedup();
        let binding = StoredRootBinding {
            composed_root_digest: digest_hex(composed_root_digest),
            source_component_digests,
            execution_bindings: stored_execution_bindings,
            scoped_component_digests,
            principals: stored_principals,
            invocation_targets,
            root_principal_seeds: r2_root_principal_seeds
                .iter()
                .map(|digest| digest_hex(*digest))
                .collect(),
            validation_report_digest: digest_hex(validation_report_digest),
            release_certification_digest: digest_hex(release_certification_digest),
        };
        self.mutate_state("root-binding-admission", |state| {
            let manifest_key = digest_hex(manifest_digest);
            for digest in [
                &binding.validation_report_digest,
                &binding.release_certification_digest,
            ] {
                if !state.blobs.contains_key(digest) {
                    return Err(KernelError::InvalidConfiguration(
                        "root certification evidence is not stored".to_string(),
                    ));
                }
            }
            for digest in &binding.source_component_digests {
                if !state.admitted_components.contains_key(digest) {
                    let missing = format!("sha256:{digest}").parse().map_err(|_| {
                        KernelError::Persistence("invalid stored digest".to_string())
                    })?;
                    return Err(KernelError::MissingComponent(missing));
                }
            }
            for digest in &binding.scoped_component_digests {
                if !state.admitted_components.contains_key(digest) {
                    let missing = format!("sha256:{digest}").parse().map_err(|_| {
                        KernelError::Persistence("invalid stored scoped digest".to_string())
                    })?;
                    return Err(KernelError::MissingComponent(missing));
                }
            }
            if !state
                .admitted_components
                .contains_key(&binding.composed_root_digest)
            {
                let missing = format!("sha256:{}", binding.composed_root_digest)
                    .parse()
                    .map_err(|_| KernelError::Persistence("invalid stored digest".to_string()))?;
                return Err(KernelError::MissingComponent(missing));
            }
            for (authority, execution) in &binding.execution_bindings {
                if !binding.source_component_digests.contains(authority) {
                    let extra = format!("sha256:{authority}").parse().map_err(|_| {
                        KernelError::Persistence("invalid stored digest".to_string())
                    })?;
                    return Err(KernelError::UnlistedComponent(extra));
                }
                if !state
                    .admitted_components
                    .contains_key(&execution.executable_digest)
                {
                    let missing = format!("sha256:{}", execution.executable_digest)
                        .parse()
                        .map_err(|_| {
                            KernelError::Persistence("invalid stored digest".to_string())
                        })?;
                    return Err(KernelError::MissingComponent(missing));
                }
                if execution.source_component_digests.is_empty()
                    || !execution.source_component_digests.contains(authority)
                    || execution
                        .source_component_digests
                        .iter()
                        .any(|digest| !binding.source_component_digests.contains(digest))
                {
                    return Err(KernelError::InvalidConfiguration(
                        "derived execution provenance is not a subset of the source graph"
                            .to_string(),
                    ));
                }
                if execution
                    .grants
                    .iter()
                    .any(|grant| !state.blobs.contains_key(&grant.constraint_digest))
                {
                    return Err(KernelError::InvalidConfiguration(
                        "derived execution grant constraint is not stored".to_string(),
                    ));
                }
                if execution
                    .principal_seeds
                    .iter()
                    .any(|seed| !binding.principals.contains_key(seed))
                {
                    return Err(KernelError::InvalidConfiguration(
                        "derived execution names an unknown R2 principal".to_string(),
                    ));
                }
            }
            if binding
                .root_principal_seeds
                .iter()
                .any(|seed| !binding.principals.contains_key(seed))
                || binding.invocation_targets.iter().any(|(caller, targets)| {
                    !binding.principals.contains_key(caller)
                        || targets
                            .iter()
                            .any(|target| !binding.execution_bindings.contains_key(target))
                })
            {
                return Err(KernelError::InvalidConfiguration(
                    "R2 principal or invocation binding is not closed over admitted artifacts"
                        .to_string(),
                ));
            }
            match state.root_bindings.get(&manifest_key) {
                Some(existing) if existing != &binding => {
                    return Err(KernelError::InvalidConfiguration(
                        "manifest digest is already bound to different root artifacts".to_string(),
                    ));
                }
                Some(_) => {}
                None => {
                    state.root_bindings.insert(manifest_key.clone(), binding);
                }
            }
            state.admitted_graphs.insert(manifest_key);
            Ok(())
        })
    }

    /// Returns a handle whose dynamic execution and wake targets are restricted
    /// to one previously admitted source graph.
    pub fn scoped_to_graph(&self, manifest_digest: Sha256Digest) -> Result<Self, KernelError> {
        let state = self.inner.state.lock().map_err(|_| {
            KernelError::Persistence("persistent state lock is poisoned".to_string())
        })?;
        let binding = state
            .root_bindings
            .get(&digest_hex(manifest_digest))
            .cloned()
            .ok_or_else(|| {
                KernelError::InvalidConfiguration(
                    "manifest has no admitted root execution binding".to_string(),
                )
            })?;
        drop(state);
        Ok(Self {
            inner: self.inner.clone(),
            graph_scope: Some(Arc::new(GraphScope {
                manifest_digest,
                source_components: binding.source_component_digests.into_iter().collect(),
                execution_bindings: binding.execution_bindings,
                principals: binding.principals,
                invocation_targets: binding.invocation_targets,
            })),
        })
    }

    /// Returns separately persisted execution provenance for a completed run.
    pub fn execution_provenance(
        &self,
        operation_id: &str,
    ) -> Result<Option<crate::root_runtime::ExecutionProvenance>, KernelError> {
        validate_identifier(operation_id)
            .map_err(|error| KernelError::InvalidConfiguration(error.message))?;
        let state = self.inner.state.lock().map_err(|_| {
            KernelError::Persistence("persistent state lock is poisoned".to_string())
        })?;
        Ok(state
            .operation_runs
            .get(operation_id)
            .and_then(|key| state.runs.get(key))
            .and_then(|run| run.provenance.clone()))
    }

    /// Returns the persisted generic completion for operator evidence.
    ///
    /// This native read-only inspection API is not linked into a component
    /// world. Component callers must continue to use the principal-owned WIT
    /// poll path.
    pub fn execution_completion(
        &self,
        operation_id: &str,
    ) -> Result<Option<component_runner::RunCompletion>, KernelError> {
        validate_identifier(operation_id)
            .map_err(|error| KernelError::InvalidConfiguration(error.message))?;
        let state = self.inner.state.lock().map_err(|_| {
            KernelError::Persistence("persistent state lock is poisoned".to_string())
        })?;
        Ok(state
            .operation_runs
            .get(operation_id)
            .and_then(|key| state.runs.get(key))
            .map(|run| run.completion.clone()))
    }

    /// Creates a persistent Ed25519 key behind a non-exportable handle.
    pub fn create_ed25519_key(&self, handle: impl Into<String>) -> Result<String, KernelError> {
        let handle = handle.into();
        validate_identifier(&handle)
            .map_err(|error| KernelError::InvalidConfiguration(error.message))?;
        let random = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&random)
            .map_err(|_| KernelError::Persistence("Ed25519 key generation failed".to_string()))?;
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).map_err(|_| {
            KernelError::Persistence("generated Ed25519 key was invalid".to_string())
        })?;
        let public_key = pair.public_key().as_ref().to_vec();
        let key_id = Sha256Digest::from_bytes(&public_key).to_string();
        self.mutate_state("key-create", |state| {
            if state.keys.contains_key(&handle) {
                return Err(KernelError::InvalidConfiguration(
                    "key handle already exists".to_string(),
                ));
            }
            state.keys.insert(
                handle,
                StoredKey {
                    key_id: key_id.clone(),
                    pkcs8: pkcs8.as_ref().to_vec(),
                    public_key,
                },
            );
            Ok(())
        })?;
        Ok(key_id)
    }

    pub(crate) fn now_ms(&self) -> u64 {
        self.inner.time.now_ms()
    }

    pub(crate) fn inject_runtime_fault(
        &self,
        point: DurabilityFaultPoint,
        operation: &str,
    ) -> Result<(), foundation::Failure> {
        self.inner
            .faults
            .inject(point, operation)
            .map_err(wit_persistence)
    }

    fn selected_manifest_reference(
        &self,
        previous: bool,
    ) -> Result<Option<foundation::BlobRef>, foundation::Failure> {
        let state = self.lock_state()?;
        let selected = if previous {
            state.last_known_good_manifest.as_ref()
        } else {
            state.active_manifest.as_ref()
        };
        let Some(selected) = selected else {
            return Ok(None);
        };
        let digest = validate_digest(selected)?;
        let size = state
            .blobs
            .get(&digest_hex(digest))
            .copied()
            .ok_or_else(|| failure("integrity-error", "selected manifest bytes are absent"))?;
        drop(state);
        verify_file(&self.blob_path(digest), digest, size).map_err(wit_persistence)?;
        Ok(Some(blob_reference(
            digest,
            size,
            "application/vnd.wasm-biotic.graph+json".to_string(),
        )))
    }

    fn selected_manifest_digest(
        &self,
        previous: bool,
    ) -> Result<Option<Sha256Digest>, KernelError> {
        let state = self.inner.state.lock().map_err(|_| {
            KernelError::Persistence("persistent state lock is poisoned".to_string())
        })?;
        let selected = if previous {
            state.last_known_good_manifest.as_ref()
        } else {
            state.active_manifest.as_ref()
        };
        selected
            .map(|digest| {
                validate_digest(digest).map_err(|error| KernelError::Persistence(error.message))
            })
            .transpose()
    }

    pub(crate) fn component_bytes(
        &self,
        digest: Sha256Digest,
    ) -> Result<Vec<u8>, foundation::Failure> {
        let state = self.lock_state()?;
        let size = state
            .admitted_components
            .get(&digest_hex(digest))
            .copied()
            .ok_or_else(|| failure("not-admitted", "component digest is not admitted"))?;
        drop(state);
        read_verified(&self.component_path(digest), digest, size).map_err(wit_persistence)
    }

    pub(crate) fn blob_bytes(&self, digest: Sha256Digest) -> Result<Vec<u8>, foundation::Failure> {
        let state = self.lock_state()?;
        let size = state
            .blobs
            .get(&digest_hex(digest))
            .copied()
            .ok_or_else(|| failure("not-found", "content digest is not stored"))?;
        drop(state);
        read_verified(&self.blob_path(digest), digest, size).map_err(wit_persistence)
    }

    pub(crate) fn root_executable_digest(
        &self,
        manifest_digest: Sha256Digest,
    ) -> Result<Sha256Digest, KernelError> {
        let state = self.inner.state.lock().map_err(|_| {
            KernelError::Persistence("persistent state lock is poisoned".to_string())
        })?;
        let stored = &state
            .root_bindings
            .get(&digest_hex(manifest_digest))
            .ok_or_else(|| {
                KernelError::InvalidConfiguration(
                    "manifest has no verified root binding".to_string(),
                )
            })?
            .composed_root_digest;
        format!("sha256:{stored}")
            .parse()
            .map_err(|_| KernelError::Persistence("stored root digest is invalid".to_string()))
    }

    pub(crate) fn root_certification_digests(
        &self,
        manifest_digest: Sha256Digest,
    ) -> Result<(Sha256Digest, Sha256Digest), KernelError> {
        let state = self.inner.state.lock().map_err(|_| {
            KernelError::Persistence("persistent state lock is poisoned".to_string())
        })?;
        let binding = state
            .root_bindings
            .get(&digest_hex(manifest_digest))
            .ok_or_else(|| {
                KernelError::InvalidConfiguration(
                    "manifest has no verified root binding".to_string(),
                )
            })?;
        let parse = |value: &str, subject: &str| {
            if value.is_empty() {
                return Err(KernelError::InvalidConfiguration(format!(
                    "stored root binding has no {subject} digest"
                )));
            }
            format!("sha256:{value}").parse().map_err(|_| {
                KernelError::Persistence(format!("stored {subject} digest is invalid"))
            })
        };
        Ok((
            parse(&binding.validation_report_digest, "validation report")?,
            parse(
                &binding.release_certification_digest,
                "release certification",
            )?,
        ))
    }

    pub(crate) fn resolve_execution(
        &self,
        authority_digest: Sha256Digest,
    ) -> Result<(Vec<u8>, crate::root_runtime::ExecutionProvenance), foundation::Failure> {
        let authority_key = digest_hex(authority_digest);
        let (executable_digest, sources, graph_manifest_digest) =
            if let Some(scope) = &self.graph_scope {
                if !scope.source_components.contains(&authority_key) {
                    return Err(failure(
                        "not-admitted",
                        "requested component digest is outside the running graph",
                    ));
                }
                match scope.execution_bindings.get(&authority_key) {
                    Some(binding) => {
                        let executable = format!("sha256:{}", binding.executable_digest)
                            .parse()
                            .map_err(|_| {
                                failure("integrity-error", "stored executable digest is invalid")
                            })?;
                        let sources = binding
                            .source_component_digests
                            .iter()
                            .map(|digest| format!("sha256:{digest}").parse())
                            .collect::<Result<Vec<_>, _>>()
                            .map_err(|_| {
                                failure("integrity-error", "stored source digest is invalid")
                            })?;
                        (executable, sources, Some(scope.manifest_digest))
                    }
                    None => {
                        return Err(failure(
                            "not-admitted",
                            "requested digest has no manifest-bound executable mapping",
                        ));
                    }
                }
            } else {
                (authority_digest, vec![authority_digest], None)
            };
        let bytes = self.component_bytes(executable_digest)?;
        Ok((
            bytes,
            crate::root_runtime::ExecutionProvenance {
                graph_manifest_digest,
                authority_component_digest: authority_digest,
                executable_component_digest: executable_digest,
                source_component_digests: sources,
                caller_principal_seed: None,
            },
        ))
    }

    pub(crate) fn admitted_run_grants(
        &self,
        authority_digest: Sha256Digest,
    ) -> Result<Option<Vec<AdmittedGrant>>, foundation::Failure> {
        let Some(scope) = &self.graph_scope else {
            return Ok(None);
        };
        let binding = scope
            .execution_bindings
            .get(&digest_hex(authority_digest))
            .ok_or_else(|| {
                failure(
                    "not-admitted",
                    "requested digest has no manifest-bound executable mapping",
                )
            })?;
        binding
            .grants
            .iter()
            .map(|grant| {
                Ok(AdmittedGrant {
                    capability: grant.capability.clone(),
                    scope: grant.scope.clone(),
                    constraint_digest: format!("sha256:{}", grant.constraint_digest)
                        .parse()
                        .map_err(|_| {
                            failure("integrity-error", "stored constraint digest is invalid")
                        })?,
                })
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some)
    }

    pub(crate) fn execution_principals(
        &self,
        authority_digest: Sha256Digest,
    ) -> Result<Vec<crate::root_runtime::AdmittedPrincipal>, foundation::Failure> {
        let Some(scope) = &self.graph_scope else {
            return Ok(Vec::new());
        };
        let binding = scope
            .execution_bindings
            .get(&digest_hex(authority_digest))
            .ok_or_else(|| {
                failure(
                    "not-admitted",
                    "requested digest has no manifest-bound executable mapping",
                )
            })?;
        binding
            .principal_seeds
            .iter()
            .map(|seed| {
                scope
                    .principals
                    .get(seed)
                    .ok_or_else(|| failure("integrity-error", "stored principal is absent"))
                    .and_then(stored_principal_to_admitted)
            })
            .collect()
    }

    pub(crate) fn enforce_component_invocation(
        &self,
        caller_principal_seed: Sha256Digest,
        target: Sha256Digest,
    ) -> Result<(), foundation::Failure> {
        let scope = self.graph_scope.as_ref().ok_or_else(|| {
            failure(
                "not-admitted",
                "principal-bound invocation requires an admitted graph scope",
            )
        })?;
        let caller = digest_hex(caller_principal_seed);
        let target = digest_hex(target);
        if !scope
            .invocation_targets
            .get(&caller)
            .is_some_and(|targets| targets.contains(&target))
        {
            return Err(failure(
                "not-granted",
                "component target is outside the caller principal invocation edges",
            ));
        }
        Ok(())
    }

    pub(crate) fn constraint_bytes(
        &self,
        digest: Sha256Digest,
    ) -> Result<Vec<u8>, foundation::Failure> {
        let state = self.lock_state()?;
        let size = state
            .blobs
            .get(&digest_hex(digest))
            .copied()
            .ok_or_else(|| failure("not-found", "grant constraint bytes are not stored"))?;
        drop(state);
        read_verified(&self.blob_path(digest), digest, size).map_err(wit_persistence)
    }

    fn enforce_graph_component_scope(
        &self,
        digest: Sha256Digest,
    ) -> Result<(), foundation::Failure> {
        if self
            .graph_scope
            .as_ref()
            .is_some_and(|scope| !scope.source_components.contains(&digest_hex(digest)))
        {
            return Err(failure(
                "not-admitted",
                "component digest is outside the running graph",
            ));
        }
        Ok(())
    }

    pub(crate) fn existing_run(
        &self,
        operation_scope: &str,
        request_digest: &str,
        graph_manifest_digest: Option<Sha256Digest>,
        caller_principal_seed: Option<Sha256Digest>,
    ) -> Result<Option<StoredRun>, foundation::Failure> {
        let state = self.lock_state()?;
        match state.runs.get(operation_scope) {
            Some(existing)
                if existing.request_digest != request_digest
                    || existing
                        .provenance
                        .as_ref()
                        .map(|provenance| provenance.graph_manifest_digest)
                        .unwrap_or(None)
                        != graph_manifest_digest
                    || existing.caller_principal_seed != caller_principal_seed =>
            {
                Err(failure(
                    "idempotency-conflict",
                    "principal operation key was reused for different bytes or authority",
                ))
            }
            existing => Ok(existing.cloned()),
        }
    }

    fn principal_operation_scope(
        &self,
        capability: &str,
        idempotency_key: &str,
        caller_principal_seed: Option<Sha256Digest>,
    ) -> Result<String, foundation::Failure> {
        let Some(principal_seed) = caller_principal_seed else {
            return Ok(idempotency_key.to_string());
        };
        let graph_manifest_digest = self
            .graph_scope
            .as_ref()
            .map(|scope| scope.manifest_digest)
            .ok_or_else(|| {
                failure(
                    "not-admitted",
                    "principal operation requires an admitted graph scope",
                )
            })?;
        let bytes = crate::canonical_json_bytes(&serde_json::json!({
            "capability": capability,
            "graph_manifest_digest": graph_manifest_digest,
            "idempotency_key": idempotency_key,
            "principal_seed": principal_seed,
            "schema": R2_OPERATION_SCHEMA,
        }))
        .map_err(|_| failure("encoding-error", "could not bind principal operation"))?;
        Ok(Sha256Digest::from_bytes(&bytes).to_string())
    }

    pub(crate) fn component_operation_scope(
        &self,
        idempotency_key: &str,
        caller_principal_seed: Option<Sha256Digest>,
    ) -> Result<String, foundation::Failure> {
        self.principal_operation_scope("component-runner", idempotency_key, caller_principal_seed)
    }

    fn principal_handle_scope(
        &self,
        capability: &str,
        handle: &str,
        caller_principal_seed: Option<Sha256Digest>,
    ) -> Result<String, foundation::Failure> {
        let Some(principal_seed) = caller_principal_seed else {
            return Ok(handle.to_string());
        };
        let graph_manifest_digest = self
            .graph_scope
            .as_ref()
            .map(|scope| scope.manifest_digest)
            .ok_or_else(|| {
                failure(
                    "not-admitted",
                    "principal handle requires an admitted graph scope",
                )
            })?;
        Ok(graph_principal_handle_key(
            graph_manifest_digest,
            principal_seed,
            capability,
            handle,
        ))
    }

    pub(crate) fn record_run(
        &self,
        idempotency: String,
        run: StoredRun,
    ) -> Result<(), foundation::Failure> {
        self.mutate_state_wit("run-receipt", |state| {
            if let Some(existing) = state.runs.get(&idempotency) {
                if existing.request_digest != run.request_digest
                    || existing.caller_principal_seed != run.caller_principal_seed
                    || existing
                        .provenance
                        .as_ref()
                        .map(|value| value.graph_manifest_digest)
                        != run
                            .provenance
                            .as_ref()
                            .map(|value| value.graph_manifest_digest)
                {
                    return Err(failure(
                        "idempotency-conflict",
                        "principal operation key was reused for different bytes or authority",
                    ));
                }
                return Ok(());
            }
            if state
                .operation_runs
                .get(&run.operation_id)
                .is_some_and(|existing| existing != &idempotency)
            {
                return Err(failure(
                    "idempotency-conflict",
                    "operation identifier is already bound to different authority",
                ));
            }
            state
                .operation_runs
                .insert(run.operation_id.clone(), idempotency.clone());
            state.runs.insert(idempotency, run);
            Ok(())
        })
    }

    pub(crate) fn run_by_operation(
        &self,
        operation: &str,
    ) -> Result<Option<StoredRun>, foundation::Failure> {
        let state = self.lock_state()?;
        Ok(state
            .operation_runs
            .get(operation)
            .and_then(|key| state.runs.get(key))
            .cloned())
    }

    pub(crate) fn poll_run_for_principal(
        &self,
        operation: &str,
        caller_principal_seed: Option<Sha256Digest>,
    ) -> Result<Option<StoredRun>, foundation::Failure> {
        validate_identifier(operation)?;
        let run = self.run_by_operation(operation)?;
        if caller_principal_seed.is_some()
            && run.as_ref().map(|stored| stored.caller_principal_seed)
                != Some(caller_principal_seed)
        {
            return Err(failure(
                "not-granted",
                "component operation is not owned by the caller principal",
            ));
        }
        if run
            .as_ref()
            .is_some_and(|stored| stored.caller_principal_seed != caller_principal_seed)
        {
            return Err(failure(
                "not-granted",
                "component operation is not owned by the caller principal",
            ));
        }
        Ok(run)
    }

    pub(crate) fn cancel_run_for_principal(
        &self,
        operation: &str,
        caller_principal_seed: Option<Sha256Digest>,
    ) -> Result<bool, foundation::Failure> {
        let _ = self.poll_run_for_principal(operation, caller_principal_seed)?;
        Ok(false)
    }

    pub(crate) fn poll_http_for_principal(
        &self,
        operation: &str,
        caller_principal_seed: Option<Sha256Digest>,
    ) -> Result<Option<http_transport::Response>, foundation::Failure> {
        validate_identifier(operation)?;
        if caller_principal_seed.is_some() {
            return Err(failure(
                "not-granted",
                "HTTP operation is not owned by the caller principal",
            ));
        }
        Ok(None)
    }

    pub(crate) fn start_http_for_authority(
        &self,
        request: http_transport::Request,
        authority: HttpAuthority,
    ) -> Result<String, foundation::Failure> {
        validate_identifier(&request.request_id)?;
        let idempotency = validate_digest(&request.idempotency_key)?;
        let operator = self.inner.config.http_transport.as_ref().ok_or_else(|| {
            failure(
                "transport-disabled",
                "HTTP transport is disabled by immutable operator capacity",
            )
        })?;
        if request.timeout_ms == 0
            || request.timeout_ms > self.inner.config.max_http_timeout_ms
            || request.timeout_ms > operator.max_timeout_ms
        {
            return Err(failure(
                "limit-exceeded",
                "HTTP timeout exceeds the configured bound",
            ));
        }
        if request.url.len() > MAX_IDENTIFIER_BYTES * 8 {
            return Err(failure("limit-exceeded", "HTTP destination is too long"));
        }
        let constraints = self.http_constraints_for_authority(&authority)?;
        bounded_http::validate_operator_intersection(&constraints, operator)
            .map_err(transport_failure)?;
        let body_size = request.body.as_ref().map_or(0, |body| body.size_bytes);
        if let Some(body) = &request.body {
            validate_blob_ref(
                body,
                constraints
                    .max_request_body_bytes
                    .min(operator.max_request_body_bytes),
            )?;
            self.get_blob(body.clone())?;
        }
        if body_size
            > constraints
                .max_request_body_bytes
                .min(operator.max_request_body_bytes)
        {
            return Err(failure(
                "limit-exceeded",
                "HTTP request body exceeds its byte bound",
            ));
        }
        bounded_http::validate_persistable_request(&request, body_size, &constraints, operator)
            .map_err(transport_failure)?;
        let owner = authority.stored();
        let request_bytes = crate::canonical_json_bytes(&request)
            .map_err(|_| failure("encoding-error", "HTTP request could not be canonicalized"))?;
        let request_digest = Sha256Digest::from_bytes(&request_bytes);
        let identity_bytes = crate::canonical_json_bytes(&serde_json::json!({
            "alias": owner.alias,
            "constraint_digest": owner.constraint_digest,
            "graph_manifest_digest": owner.graph_manifest_digest,
            "idempotency_key": idempotency,
            "principal_seed": owner.principal_seed,
            "schema": "wasm-biotic.http-operation-identity.v1",
        }))
        .map_err(|_| {
            failure(
                "encoding-error",
                "HTTP operation identity could not be encoded",
            )
        })?;
        let identity = Sha256Digest::from_bytes(&identity_bytes).to_string();
        let operation_id = format!(
            "http-{}",
            digest_hex(Sha256Digest::from_bytes(identity.as_bytes()))
        );
        let now = self.inner.time.now_ms();
        let effective_concurrency = constraints.max_concurrency.min(operator.max_concurrency);
        let (operation_id, dispatch) = self.mutate_state_wit("http-prepare", |state| {
            if let Some(existing_id) = state.http_idempotency.get(&identity) {
                let existing = state.http_operations.get(existing_id).ok_or_else(|| {
                    failure(
                        "integrity-error",
                        "HTTP idempotency index refers to a missing operation",
                    )
                })?;
                if existing.owner != owner || existing.request_digest != request_digest {
                    return Err(failure(
                        "idempotency-conflict",
                        "HTTP idempotency key was reused for different authority or bytes",
                    ));
                }
                return Ok((
                    existing_id.clone(),
                    matches!(existing.state, StoredHttpState::Prepared),
                ));
            }
            let active_global = state
                .http_operations
                .values()
                .filter(|operation| {
                    matches!(
                        operation.state,
                        StoredHttpState::Prepared | StoredHttpState::Dispatching { .. }
                    )
                })
                .count();
            let active_alias = state
                .http_operations
                .values()
                .filter(|operation| {
                    operation.owner.constraint_digest == owner.constraint_digest
                        && matches!(
                            operation.state,
                            StoredHttpState::Prepared | StoredHttpState::Dispatching { .. }
                        )
                })
                .count();
            if active_global >= usize::try_from(operator.max_concurrency).unwrap_or(usize::MAX)
                || active_alias >= usize::try_from(effective_concurrency).unwrap_or(usize::MAX)
            {
                return Err(failure(
                    "limit-exceeded",
                    "HTTP concurrency exceeds the signed or operator bound",
                ));
            }
            let operation = StoredHttpOperation {
                owner: owner.clone(),
                request_digest,
                request: request.clone(),
                started_at_ms: now,
                state: StoredHttpState::Prepared,
            };
            if state
                .http_operations
                .insert(operation_id.clone(), operation)
                .is_some()
            {
                return Err(failure(
                    "integrity-error",
                    "HTTP operation identifier collided",
                ));
            }
            state
                .http_idempotency
                .insert(identity.clone(), operation_id.clone());
            Ok((operation_id.clone(), true))
        })?;
        if dispatch {
            self.spawn_http_dispatch(operation_id.clone())?;
        }
        Ok(operation_id)
    }

    pub(crate) fn poll_http_for_authority(
        &self,
        operation: &str,
        authority: &HttpAuthority,
    ) -> Result<Option<http_transport::Response>, foundation::Failure> {
        validate_identifier(operation)?;
        let stored = {
            let state = self.lock_state()?;
            let Some(stored) = state.http_operations.get(operation) else {
                return Ok(None);
            };
            if stored.owner != authority.stored() {
                return Err(failure(
                    "not-granted",
                    "HTTP operation is not owned by the exact caller authority",
                ));
            }
            stored.clone()
        };
        self.http_constraints_for_authority(authority)?;
        match &stored.state {
            StoredHttpState::Prepared | StoredHttpState::Dispatching { .. } => Ok(None),
            StoredHttpState::Completed { response, .. } => Ok(Some(response.clone())),
            StoredHttpState::DefiniteFailure { failure, .. }
            | StoredHttpState::CancelledBeforeDispatch { failure, .. }
            | StoredHttpState::Indeterminate { failure, .. } => Err(failure.clone()),
        }
    }

    pub(crate) fn cancel_http_for_authority(
        &self,
        operation: &str,
        authority: &HttpAuthority,
    ) -> Result<bool, foundation::Failure> {
        validate_identifier(operation)?;
        {
            let state = self.lock_state()?;
            let Some(stored) = state.http_operations.get(operation) else {
                return Ok(false);
            };
            if stored.owner != authority.stored() {
                return Err(failure(
                    "not-granted",
                    "HTTP operation is not owned by the exact caller authority",
                ));
            }
        }
        self.http_constraints_for_authority(authority)?;
        let owner = authority.stored();
        let finished = self.inner.time.now_ms();
        self.mutate_state_wit("http-cancel", |state| {
            let Some(stored) = state.http_operations.get_mut(operation) else {
                return Ok(false);
            };
            if stored.owner != owner {
                return Err(failure(
                    "not-granted",
                    "HTTP operation is not owned by the exact caller authority",
                ));
            }
            if !matches!(stored.state, StoredHttpState::Prepared) {
                return Ok(false);
            }
            let cancelled = failure(
                "cancelled-before-dispatch",
                "HTTP operation was cancelled before native dispatch",
            );
            let receipt = http_transport_receipt(
                operation,
                &stored.owner,
                stored.request_digest,
                None,
                "cancelled-before-dispatch",
                (stored.started_at_ms, finished),
                None,
            );
            stored.state = StoredHttpState::CancelledBeforeDispatch {
                failure: cancelled,
                transport_receipt: receipt,
            };
            Ok(true)
        })
    }

    pub(crate) fn cancel_http_for_principal(
        &self,
        operation: &str,
        caller_principal_seed: Option<Sha256Digest>,
    ) -> Result<bool, foundation::Failure> {
        let _ = self.poll_http_for_principal(operation, caller_principal_seed)?;
        Ok(false)
    }

    /// Returns the canonical, redacted native transport receipt for operator
    /// verification. The receipt contains digests and transport facts only.
    pub fn http_transport_receipt(&self, operation: &str) -> Result<Option<Vec<u8>>, KernelError> {
        validate_identifier(operation)
            .map_err(|error| KernelError::InvalidConfiguration(error.message))?;
        let state = self.inner.state.lock().map_err(|_| {
            KernelError::Persistence("persistent state lock is poisoned".to_string())
        })?;
        let receipt = state
            .http_operations
            .get(operation)
            .and_then(|stored| match &stored.state {
                StoredHttpState::Completed {
                    transport_receipt, ..
                }
                | StoredHttpState::DefiniteFailure {
                    transport_receipt, ..
                }
                | StoredHttpState::CancelledBeforeDispatch {
                    transport_receipt, ..
                }
                | StoredHttpState::Indeterminate {
                    transport_receipt, ..
                } => Some(transport_receipt),
                StoredHttpState::Prepared | StoredHttpState::Dispatching { .. } => None,
            });
        receipt.map(crate::canonical_json_bytes).transpose()
    }

    fn read_blob_digest(&self, digest: Sha256Digest) -> Result<Vec<u8>, foundation::Failure> {
        let state = self.lock_state()?;
        let size = state
            .blobs
            .get(&digest_hex(digest))
            .copied()
            .ok_or_else(|| failure("not-found", "content-addressed HTTP constraint is absent"))?;
        drop(state);
        read_verified(&self.blob_path(digest), digest, size).map_err(wit_persistence)
    }

    fn http_constraints_for_authority(
        &self,
        authority: &HttpAuthority,
    ) -> Result<bounded_http::HttpTransportConstraintsV1, foundation::Failure> {
        let bytes = self.read_blob_digest(authority.constraint_digest)?;
        let schema = serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|value| {
                value
                    .get("schema")
                    .and_then(|value| value.as_str())
                    .map(str::to_string)
            });
        if schema.as_deref() != Some(bounded_http::HTTP_CONSTRAINT_SCHEMA_V1) {
            return Err(failure(
                "transport-disabled",
                "HTTP transport is disabled for this legacy alias profile",
            ));
        }
        bounded_http::parse_constraints(&bytes)
            .map_err(|_| failure("not-granted", "HTTP alias constraint is invalid"))
    }

    fn spawn_http_dispatch(&self, operation_id: String) -> Result<(), foundation::Failure> {
        let dispatcher = self.clone();
        std::thread::Builder::new()
            .name(format!("wasm-biotic-{operation_id}"))
            .spawn(move || {
                let _ = dispatcher.dispatch_http_operation(&operation_id);
            })
            .map(|_| ())
            .map_err(|_| {
                failure(
                    "dispatch-unavailable",
                    "HTTP dispatch thread could not be started; prepared state is retained",
                )
            })
    }

    fn dispatch_http_operation(&self, operation_id: &str) -> Result<(), foundation::Failure> {
        let operation = {
            let state = self.lock_state()?;
            let Some(operation) = state.http_operations.get(operation_id) else {
                return Ok(());
            };
            if !matches!(operation.state, StoredHttpState::Prepared) {
                return Ok(());
            }
            operation.clone()
        };
        let operator = self.inner.config.http_transport.as_ref().ok_or_else(|| {
            failure(
                "transport-disabled",
                "HTTP transport is disabled by immutable operator capacity",
            )
        })?;
        let constraint_bytes = match self.read_blob_digest(operation.owner.constraint_digest) {
            Ok(bytes) => bytes,
            Err(error) => {
                return self.finish_http_failure(operation_id, false, error, None);
            }
        };
        let constraints = match bounded_http::parse_constraints(&constraint_bytes) {
            Ok(constraints) => constraints,
            Err(_) => {
                return self.finish_http_failure(
                    operation_id,
                    false,
                    failure(
                        "not-granted",
                        "HTTP alias constraint failed canonical validation",
                    ),
                    None,
                );
            }
        };
        let body = match operation.request.body.as_ref() {
            Some(reference) => match self.get_blob(reference.clone()) {
                Ok(bytes) => Some(bytes),
                Err(error) => {
                    return self.finish_http_failure(operation_id, false, error, None);
                }
            },
            None => None,
        };
        let body_size = body
            .as_ref()
            .map_or(0, |bytes| u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        let validated = match bounded_http::validate_request(
            &operation.request,
            body_size,
            &constraints,
            operator,
            self.inner.http_material_root.as_deref(),
        ) {
            Ok(validated) => validated,
            Err(error) => {
                return self.finish_http_failure(
                    operation_id,
                    error.dispatch_may_have_occurred,
                    transport_failure(error),
                    None,
                );
            }
        };
        let resolved_address = validated.selected_address.to_string();
        self.inner
            .faults
            .inject(
                DurabilityFaultPoint::BeforeHttpDispatchRecord,
                "http-dispatch",
            )
            .map_err(wit_persistence)?;
        let marked = self.mutate_state_wit("http-dispatch", |state| {
            let Some(stored) = state.http_operations.get_mut(operation_id) else {
                return Ok(false);
            };
            if !matches!(stored.state, StoredHttpState::Prepared) {
                return Ok(false);
            }
            if stored.owner != operation.owner || stored.request_digest != operation.request_digest
            {
                return Err(failure(
                    "integrity-error",
                    "HTTP prepared operation changed before dispatch",
                ));
            }
            stored.state = StoredHttpState::Dispatching {
                resolved_address: resolved_address.clone(),
            };
            Ok(true)
        })?;
        if !marked {
            return Ok(());
        }
        self.inner
            .faults
            .inject(
                DurabilityFaultPoint::AfterHttpDispatchRecord,
                "http-dispatch",
            )
            .map_err(wit_persistence)?;
        self.inner
            .faults
            .inject(
                DurabilityFaultPoint::BeforeHttpSocketDispatch,
                "http-dispatch",
            )
            .map_err(wit_persistence)?;
        match bounded_http::execute_validated(
            &operation.request,
            body,
            &constraints,
            operator,
            self.inner.http_material_root.as_deref(),
            validated,
        ) {
            Ok(success) => {
                self.inner
                    .faults
                    .inject(DurabilityFaultPoint::AfterHttpResponse, "http-dispatch")
                    .map_err(wit_persistence)?;
                self.finish_http_success(operation_id, success)
            }
            Err(error) => {
                self.finish_http_failure(operation_id, true, transport_failure(error), None)
            }
        }
    }

    fn finish_http_success(
        &self,
        operation_id: &str,
        success: bounded_http::TransportSuccess,
    ) -> Result<(), foundation::Failure> {
        let finished = self.inner.time.now_ms();
        let body = if success.body.is_empty() {
            None
        } else {
            match self.put_blob("application/octet-stream".to_string(), success.body) {
                Ok(reference) => Some(reference),
                Err(error) => {
                    return self.finish_http_failure(
                        operation_id,
                        true,
                        failure("transport-outcome-unknown", error.message),
                        Some(success.facts),
                    );
                }
            }
        };
        self.inner
            .faults
            .inject(
                DurabilityFaultPoint::BeforeHttpOutcomeCommit,
                "http-outcome",
            )
            .map_err(wit_persistence)?;
        self.mutate_state_wit("http-outcome", |state| {
            let stored = state.http_operations.get_mut(operation_id).ok_or_else(|| {
                failure(
                    "integrity-error",
                    "HTTP operation disappeared before completion",
                )
            })?;
            if !matches!(stored.state, StoredHttpState::Dispatching { .. }) {
                return Err(failure(
                    "integrity-error",
                    "HTTP operation is not dispatching at completion",
                ));
            }
            let transport_receipt = http_transport_receipt(
                operation_id,
                &stored.owner,
                stored.request_digest,
                match &stored.state {
                    StoredHttpState::Dispatching { resolved_address } => {
                        Some(resolved_address.clone())
                    }
                    _ => None,
                },
                "completed",
                (stored.started_at_ms, finished),
                Some(success.facts.clone()),
            );
            let outcome_bytes = crate::canonical_json_bytes(&transport_receipt)
                .map_err(|_| failure("encoding-error", "HTTP receipt could not be encoded"))?;
            let outcome = Sha256Digest::from_bytes(&outcome_bytes);
            let response = http_transport::Response {
                status: success.status,
                headers: success.headers.clone(),
                body: body.clone(),
                receipt: effect_receipt(
                    stored.request_digest,
                    crate::compiled_native_tcb_inventory_digest(),
                    outcome,
                    stored.started_at_ms,
                    finished,
                    0,
                ),
            };
            stored.state = StoredHttpState::Completed {
                response,
                transport_receipt,
            };
            Ok(())
        })?;
        self.inner
            .faults
            .inject(DurabilityFaultPoint::AfterHttpOutcomeCommit, "http-outcome")
            .map_err(wit_persistence)
    }

    fn finish_http_failure(
        &self,
        operation_id: &str,
        indeterminate: bool,
        failure_value: foundation::Failure,
        facts: Option<bounded_http::TransportFactsV1>,
    ) -> Result<(), foundation::Failure> {
        let finished = self.inner.time.now_ms();
        let persisted_failure = if indeterminate {
            failure(
                "transport-outcome-unknown",
                "HTTP dispatch may have occurred; native replay is forbidden",
            )
        } else {
            failure_value
        };
        self.inner
            .faults
            .inject(
                DurabilityFaultPoint::BeforeHttpOutcomeCommit,
                "http-outcome",
            )
            .map_err(wit_persistence)?;
        self.mutate_state_wit("http-outcome", |state| {
            let Some(stored) = state.http_operations.get_mut(operation_id) else {
                return Ok(());
            };
            if !matches!(
                stored.state,
                StoredHttpState::Prepared | StoredHttpState::Dispatching { .. }
            ) {
                return Ok(());
            }
            let disposition = if indeterminate {
                "indeterminate"
            } else {
                "definite-failure"
            };
            let transport_receipt = http_transport_receipt(
                operation_id,
                &stored.owner,
                stored.request_digest,
                match &stored.state {
                    StoredHttpState::Dispatching { resolved_address } => {
                        Some(resolved_address.clone())
                    }
                    _ => None,
                },
                disposition,
                (stored.started_at_ms, finished),
                facts.clone(),
            );
            stored.state = if indeterminate {
                StoredHttpState::Indeterminate {
                    failure: persisted_failure.clone(),
                    transport_receipt,
                }
            } else {
                StoredHttpState::DefiniteFailure {
                    failure: persisted_failure.clone(),
                    transport_receipt,
                }
            };
            Ok(())
        })?;
        self.inner
            .faults
            .inject(DurabilityFaultPoint::AfterHttpOutcomeCommit, "http-outcome")
            .map_err(wit_persistence)
    }

    pub(crate) fn max_blob_bytes(&self) -> u64 {
        self.inner.config.max_blob_bytes
    }

    pub(crate) fn component_limit_ceiling(&self) -> (u64, u64, u64, u64) {
        (
            self.inner.config.max_component_fuel,
            self.inner.config.max_component_memory_bytes,
            self.inner.config.max_component_output_bytes,
            self.inner.config.max_component_wall_time_ms,
        )
    }

    pub(crate) fn verify_configured_ceiling(
        &self,
        required: &RequiredCapacity,
    ) -> Result<(), KernelError> {
        let configured = &self.inner.config;
        if configured.max_blob_bytes < required.max_blob_bytes
            || configured.max_total_blob_bytes < required.max_total_blob_bytes
            || configured.max_random_bytes < required.max_random_bytes
            || configured.max_wake_delay_ms < required.max_wake_delay_ms
            || configured.max_http_timeout_ms < required.max_http_timeout_ms
            || configured.max_component_fuel < required.max_component_fuel
            || configured.max_component_memory_bytes < required.max_component_memory_bytes
            || configured.max_component_output_bytes < required.max_component_output_bytes
            || configured.max_component_wall_time_ms < required.max_component_wall_time_ms
            || !required
                .transaction_namespaces
                .is_subset(&configured.allowed_namespaces)
        {
            return Err(KernelError::InvalidConfiguration(
                "manifest-bound requirements exceed the immutable operator capacity".to_string(),
            ));
        }
        Ok(())
    }

    fn blob_path(&self, digest: Sha256Digest) -> PathBuf {
        self.inner.root.join(BLOBS_DIR).join(digest_hex(digest))
    }

    fn component_path(&self, digest: Sha256Digest) -> PathBuf {
        self.inner
            .root
            .join(COMPONENTS_DIR)
            .join(format!("{}.wasm", digest_hex(digest)))
    }

    fn lock_state(&self) -> Result<std::sync::MutexGuard<'_, DurableState>, foundation::Failure> {
        self.inner
            .state
            .lock()
            .map_err(|_| failure("synchronization", "persistent state lock is poisoned"))
    }

    fn fence_writer(&self, state: &DurableState) -> Result<StateFileLock, KernelError> {
        let writer_lock = StateFileLock::acquire(&self.inner.root)?;
        let durable = load_state(&self.inner.root, &DurabilityFaultController::default())?;
        if durable.generation != state.generation {
            return Err(KernelError::Persistence(format!(
                "stale writer fenced: in-memory generation {} differs from durable generation {}",
                state.generation, durable.generation
            )));
        }
        Ok(writer_lock)
    }

    fn mutate_state<T>(
        &self,
        operation: &'static str,
        mutation: impl FnOnce(&mut DurableState) -> Result<T, KernelError>,
    ) -> Result<T, KernelError> {
        let mut state = self.inner.state.lock().map_err(|_| {
            KernelError::Persistence("persistent state lock is poisoned".to_string())
        })?;
        let _writer_lock = self.fence_writer(&state)?;
        let previous = state.clone();
        self.inner
            .faults
            .inject(DurabilityFaultPoint::BeforeStateChange, operation)?;
        let output = match mutation(&mut state) {
            Ok(output) => output,
            Err(error) => {
                *state = previous;
                return Err(error);
            }
        };
        state.generation = state.generation.checked_add(1).ok_or_else(|| {
            *state = previous.clone();
            KernelError::Persistence("mechanism-state generation exhausted".to_string())
        })?;
        for point in [
            DurabilityFaultPoint::AfterStateChange,
            DurabilityFaultPoint::BeforeStateCommit,
        ] {
            if let Err(error) = self.inner.faults.inject(point, operation) {
                *state = previous;
                return Err(error);
            }
        }
        if let Err(error) = persist_state(&self.inner.root, &state, &self.inner.faults) {
            *state = previous;
            return Err(error);
        }
        if let Err(error) = self
            .inner
            .faults
            .inject(DurabilityFaultPoint::AfterStateCommit, operation)
        {
            *state = previous;
            return Err(error);
        }
        Ok(output)
    }

    fn mutate_state_wit<T>(
        &self,
        operation: &'static str,
        mutation: impl FnOnce(&mut DurableState) -> Result<T, foundation::Failure>,
    ) -> Result<T, foundation::Failure> {
        let mut state = self.lock_state()?;
        let _writer_lock = self.fence_writer(&state).map_err(wit_persistence)?;
        let previous = state.clone();
        self.inner
            .faults
            .inject(DurabilityFaultPoint::BeforeStateChange, operation)
            .map_err(wit_persistence)?;
        let output = match mutation(&mut state) {
            Ok(output) => output,
            Err(error) => {
                *state = previous;
                return Err(error);
            }
        };
        state.generation = state.generation.checked_add(1).ok_or_else(|| {
            *state = previous.clone();
            failure("version-exhausted", "mechanism-state generation exhausted")
        })?;
        for point in [
            DurabilityFaultPoint::AfterStateChange,
            DurabilityFaultPoint::BeforeStateCommit,
        ] {
            if let Err(error) = self.inner.faults.inject(point, operation) {
                *state = previous;
                return Err(wit_persistence(error));
            }
        }
        if let Err(error) = persist_state(&self.inner.root, &state, &self.inner.faults) {
            *state = previous;
            return Err(wit_persistence(error));
        }
        if let Err(error) = self
            .inner
            .faults
            .inject(DurabilityFaultPoint::AfterStateCommit, operation)
        {
            *state = previous;
            return Err(wit_persistence(error));
        }
        Ok(output)
    }
}

impl foundation::Host for LocalMechanisms {}

impl blob_store::Host for LocalMechanisms {
    fn put(
        &mut self,
        media_type: String,
        content: Vec<u8>,
    ) -> Result<foundation::BlobRef, foundation::Failure> {
        self.put_blob(media_type, content)
    }

    fn get(&mut self, reference: foundation::BlobRef) -> Result<Vec<u8>, foundation::Failure> {
        self.get_blob(reference)
    }

    fn has(&mut self, content_digest: foundation::Digest) -> Result<bool, foundation::Failure> {
        self.has_blob(content_digest)
    }
}

impl transaction_store::Host for LocalMechanisms {
    fn read(
        &mut self,
        namespace: String,
        key: String,
    ) -> Result<Option<transaction_store::VersionedValue>, foundation::Failure> {
        self.validate_namespace_key(&namespace, &key)?;
        let state = self.lock_state()?;
        Ok(state
            .values
            .get(&namespace)
            .and_then(|values| values.get(&key))
            .cloned())
    }

    fn commit(
        &mut self,
        request: transaction_store::CommitRequest,
    ) -> Result<transaction_store::CommitReceipt, foundation::Failure> {
        self.commit_transaction(request)
    }
}

impl clock::Host for LocalMechanisms {
    fn now_ms(&mut self) -> u64 {
        LocalMechanisms::now_ms(self)
    }

    fn schedule_wake(&mut self, request: clock::WakeRequest) -> Result<u64, foundation::Failure> {
        self.schedule(request)
    }

    fn poll_wake(
        &mut self,
        wake_id: String,
    ) -> Result<Option<clock::FiredWake>, foundation::Failure> {
        self.poll_scheduled(wake_id)
    }

    fn cancel_wake(&mut self, wake_id: String) -> Result<bool, foundation::Failure> {
        self.cancel_scheduled(wake_id)
    }
}

impl component_runner::Host for LocalMechanisms {
    fn start(
        &mut self,
        request: component_runner::RunRequest,
    ) -> Result<String, foundation::Failure> {
        crate::root_runtime::start_task(self.clone(), request, None)
    }

    fn poll(
        &mut self,
        operation_id: String,
    ) -> Result<Option<component_runner::RunCompletion>, foundation::Failure> {
        Ok(self
            .poll_run_for_principal(&operation_id, None)?
            .map(|run| run.completion))
    }

    fn cancel(&mut self, operation_id: String) -> Result<bool, foundation::Failure> {
        self.cancel_run_for_principal(&operation_id, None)
    }
}

impl http_transport::Host for LocalMechanisms {
    fn start(&mut self, request: http_transport::Request) -> Result<String, foundation::Failure> {
        validate_identifier(&request.request_id)?;
        validate_digest(&request.idempotency_key)?;
        if request.timeout_ms == 0 || request.timeout_ms > self.inner.config.max_http_timeout_ms {
            return Err(failure(
                "limit-exceeded",
                "HTTP timeout exceeds the configured bound",
            ));
        }
        if request.url.len() > MAX_IDENTIFIER_BYTES * 4 {
            return Err(failure("limit-exceeded", "HTTP destination is too long"));
        }
        Err(failure(
            "transport-disabled",
            "HTTP transport requires an admitted v3 per-consumer alias",
        ))
    }

    fn poll(
        &mut self,
        operation_id: String,
    ) -> Result<Option<http_transport::Response>, foundation::Failure> {
        self.poll_http_for_principal(&operation_id, None)
    }

    fn cancel(&mut self, operation_id: String) -> Result<bool, foundation::Failure> {
        self.cancel_http_for_principal(&operation_id, None)
    }
}

impl key_service::Host for LocalMechanisms {
    fn sign_digest(
        &mut self,
        key_handle: String,
        payload: foundation::Digest,
    ) -> Result<key_service::Signature, foundation::Failure> {
        let digest = validate_digest(&payload)?;
        validate_identifier(&key_handle)?;
        let state = self.lock_state()?;
        let key = state
            .keys
            .get(&key_handle)
            .ok_or_else(|| failure("not-found", "key handle is not present"))?;
        let pair = Ed25519KeyPair::from_pkcs8(&key.pkcs8)
            .map_err(|_| failure("integrity-error", "stored key material is invalid"))?;
        Ok(key_service::Signature {
            key_id: key.key_id.clone(),
            algorithm: key_service::SignatureAlgorithm::Ed25519,
            bytes: pair.sign(digest.as_bytes()).as_ref().to_vec(),
        })
    }

    fn verify_digest(
        &mut self,
        key_id: String,
        payload: foundation::Digest,
        supplied: key_service::Signature,
    ) -> Result<bool, foundation::Failure> {
        let digest = validate_digest(&payload)?;
        validate_identifier(&key_id)?;
        if supplied.key_id != key_id
            || supplied.algorithm != key_service::SignatureAlgorithm::Ed25519
        {
            return Ok(false);
        }
        let state = self.lock_state()?;
        let Some(key) = state.keys.values().find(|key| key.key_id == key_id) else {
            return Ok(false);
        };
        Ok(
            signature::UnparsedPublicKey::new(&signature::ED25519, &key.public_key)
                .verify(digest.as_bytes(), &supplied.bytes)
                .is_ok(),
        )
    }

    fn random_bytes(&mut self, length: u32) -> Result<Vec<u8>, foundation::Failure> {
        if length == 0 || length > self.inner.config.max_random_bytes {
            return Err(failure(
                "limit-exceeded",
                "random response exceeds the configured bound",
            ));
        }
        let mut bytes = vec![0_u8; length as usize];
        SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| failure("entropy-unavailable", "secure entropy source failed"))?;
        Ok(bytes)
    }
}

impl activation::Host for LocalMechanisms {
    fn active_manifest(&mut self) -> Result<Option<foundation::BlobRef>, foundation::Failure> {
        self.active_manifest_reference()
    }

    fn active_state(&mut self) -> Result<Option<foundation::BlobRef>, foundation::Failure> {
        self.active_state_reference()
    }

    fn stage(
        &mut self,
        request: activation::ActivationRequest,
    ) -> Result<activation::ActivationStatus, foundation::Failure> {
        self.stage_activation(request)
    }

    fn commit(
        &mut self,
        activation_id: String,
    ) -> Result<activation::ActivationStatus, foundation::Failure> {
        self.commit_activation(activation_id)
    }

    fn status(
        &mut self,
        activation_id: String,
    ) -> Result<activation::ActivationStatus, foundation::Failure> {
        self.activation_status_for_principal(activation_id, None)
    }

    fn rollback(
        &mut self,
        activation_id: String,
        target_graph: foundation::Digest,
    ) -> Result<activation::ActivationStatus, foundation::Failure> {
        self.rollback_activation(activation_id, target_graph)
    }
}

impl audit_log::Host for LocalMechanisms {
    fn append(
        &mut self,
        entry: audit_log::AuditEntry,
    ) -> Result<audit_log::AuditReceipt, foundation::Failure> {
        self.append_audit(entry)
    }

    fn resolve(
        &mut self,
        sequence: u64,
    ) -> Result<Option<audit_log::AuditEntry>, foundation::Failure> {
        let state = self.lock_state()?;
        Ok(sequence
            .checked_sub(1)
            .and_then(|index| usize::try_from(index).ok())
            .and_then(|index| state.audit.get(index))
            .map(|entry| entry.entry.clone()))
    }
}

impl LocalMechanisms {
    fn validate_namespace_key(
        &self,
        namespace: &str,
        key: &str,
    ) -> Result<(), foundation::Failure> {
        validate_identifier(namespace)?;
        validate_identifier(key)?;
        if !self.inner.config.allowed_namespaces.contains(namespace) {
            return Err(failure(
                "out-of-scope",
                "transaction namespace is not granted",
            ));
        }
        Ok(())
    }

    fn commit_transaction(
        &self,
        request: transaction_store::CommitRequest,
    ) -> Result<transaction_store::CommitReceipt, foundation::Failure> {
        self.commit_transaction_for_principal(request, None)
    }

    pub(crate) fn commit_transaction_for_principal(
        &self,
        request: transaction_store::CommitRequest,
        caller_principal_seed: Option<Sha256Digest>,
    ) -> Result<transaction_store::CommitReceipt, foundation::Failure> {
        validate_identifier(&request.transaction_id)?;
        let idempotency = self.principal_operation_scope(
            "transaction-store",
            &digest_key(&request.idempotency_key)?,
            caller_principal_seed,
        )?;
        let request_digest = canonical_digest(&request)?;
        for assertion in &request.assertions {
            self.validate_namespace_key(&assertion.namespace, &assertion.key)?;
        }
        let mut mutation_keys = BTreeSet::new();
        for mutation in &request.mutations {
            let (namespace, key, value) = match mutation {
                transaction_store::Mutation::Put((namespace, key, value)) => {
                    (namespace, key, Some(value))
                }
                transaction_store::Mutation::Delete((namespace, key)) => (namespace, key, None),
            };
            self.validate_namespace_key(namespace, key)?;
            if !mutation_keys.insert((namespace.clone(), key.clone())) {
                return Err(failure(
                    "invalid-request",
                    "transaction contains duplicate mutations",
                ));
            }
            if let Some(value) = value {
                self.get_blob(value.clone())?;
            }
        }

        self.mutate_state_wit("transaction-commit", |state| {
            if let Some(existing) = state.commits.get(&idempotency) {
                if existing.request_digest != request_digest {
                    return Err(failure(
                        "idempotency-conflict",
                        "idempotency key was reused for different bytes",
                    ));
                }
                return Ok(existing.receipt.clone());
            }
            for assertion in &request.assertions {
                let actual = state
                    .values
                    .get(&assertion.namespace)
                    .and_then(|values| values.get(&assertion.key))
                    .map(|value| value.version);
                if actual != assertion.expected_version {
                    return Err(failure("conflict", "transaction assertion did not match"));
                }
            }
            state.transaction_version = state
                .transaction_version
                .checked_add(1)
                .ok_or_else(|| failure("version-exhausted", "transaction version overflow"))?;
            let version = state.transaction_version;
            for mutation in &request.mutations {
                match mutation {
                    transaction_store::Mutation::Put((namespace, key, value)) => {
                        state.values.entry(namespace.clone()).or_default().insert(
                            key.clone(),
                            transaction_store::VersionedValue {
                                version,
                                value: value.clone(),
                            },
                        );
                    }
                    transaction_store::Mutation::Delete((namespace, key)) => {
                        if let Some(values) = state.values.get_mut(namespace) {
                            values.remove(key);
                        }
                    }
                }
            }
            let committed_value_digest = digest_value(Sha256Digest::from_bytes(
                &serde_json::to_vec(&(version, &state.values))
                    .map_err(|_| failure("encoding-error", "could not encode committed values"))?,
            ));
            let receipt = transaction_store::CommitReceipt {
                transaction_id: request.transaction_id.clone(),
                commit_version: version,
                committed_value_digest,
            };
            state.commits.insert(
                idempotency,
                IdempotentCommit {
                    request_digest,
                    receipt: receipt.clone(),
                },
            );
            Ok(receipt)
        })
    }

    fn schedule(&self, request: clock::WakeRequest) -> Result<u64, foundation::Failure> {
        self.schedule_for_principal(request, None)
    }

    pub(crate) fn schedule_for_principal(
        &self,
        request: clock::WakeRequest,
        caller_principal_seed: Option<Sha256Digest>,
    ) -> Result<u64, foundation::Failure> {
        validate_identifier(&request.wake_id)?;
        let idempotency = self.principal_operation_scope(
            "clock",
            &digest_key(&request.idempotency_key)?,
            caller_principal_seed,
        )?;
        let wake_storage_key =
            self.principal_handle_scope("clock", &request.wake_id, caller_principal_seed)?;
        let target = validate_digest(&request.target_component)?;
        self.enforce_graph_component_scope(target)?;
        validate_digest(&request.payload_digest)?;
        let request_digest = canonical_digest(&request)?;
        let now = self.now_ms();
        if request.not_before_ms.saturating_sub(now) > self.inner.config.max_wake_delay_ms {
            return Err(failure(
                "limit-exceeded",
                "wake time exceeds the configured future horizon",
            ));
        }
        let state = self.lock_state()?;
        if !state.admitted_components.contains_key(&digest_hex(target)) {
            return Err(failure(
                "not-admitted",
                "wake target digest is not admitted",
            ));
        }
        drop(state);
        self.mutate_state_wit("wake-schedule", |state| {
            if let Some(existing_id) = state.wake_idempotency.get(&idempotency) {
                let existing = &state.wakes[existing_id];
                if existing.request_digest != request_digest
                    || existing.caller_principal_seed != caller_principal_seed
                {
                    return Err(failure(
                        "idempotency-conflict",
                        "idempotency key was reused for different bytes",
                    ));
                }
                return Ok(existing.request.not_before_ms);
            }
            if state.wakes.contains_key(&wake_storage_key) {
                return Err(failure("conflict", "wake identifier already exists"));
            }
            state
                .wake_idempotency
                .insert(idempotency, wake_storage_key.clone());
            state.wakes.insert(
                wake_storage_key.clone(),
                WakeRecord {
                    request_digest,
                    request: request.clone(),
                    caller_principal_seed,
                    cancelled: false,
                    fired_at_ms: None,
                },
            );
            Ok(request.not_before_ms)
        })
    }

    fn poll_scheduled(
        &self,
        wake_id: String,
    ) -> Result<Option<clock::FiredWake>, foundation::Failure> {
        self.poll_scheduled_for_principal(wake_id, None)
    }

    pub(crate) fn poll_scheduled_for_principal(
        &self,
        wake_id: String,
        caller_principal_seed: Option<Sha256Digest>,
    ) -> Result<Option<clock::FiredWake>, foundation::Failure> {
        validate_identifier(&wake_id)?;
        let wake_storage_key =
            self.principal_handle_scope("clock", &wake_id, caller_principal_seed)?;
        let now = self.now_ms();
        self.mutate_state_wit("wake-fire", |state| {
            let Some(record) = state.wakes.get_mut(&wake_storage_key) else {
                if caller_principal_seed.is_some() {
                    return Err(failure(
                        "not-granted",
                        "wake handle is not owned by the caller principal",
                    ));
                }
                return Ok(None);
            };
            if record.caller_principal_seed != caller_principal_seed {
                return Err(failure(
                    "not-granted",
                    "wake handle is not owned by the caller principal",
                ));
            }
            if record.cancelled || now < record.request.not_before_ms {
                return Ok(None);
            }
            let fired = *record.fired_at_ms.get_or_insert(now);
            Ok(Some(clock::FiredWake {
                wake_id,
                fired_at_ms: fired,
                payload_digest: record.request.payload_digest.clone(),
            }))
        })
    }

    fn cancel_scheduled(&self, wake_id: String) -> Result<bool, foundation::Failure> {
        self.cancel_scheduled_for_principal(wake_id, None)
    }

    pub(crate) fn cancel_scheduled_for_principal(
        &self,
        wake_id: String,
        caller_principal_seed: Option<Sha256Digest>,
    ) -> Result<bool, foundation::Failure> {
        validate_identifier(&wake_id)?;
        let wake_storage_key =
            self.principal_handle_scope("clock", &wake_id, caller_principal_seed)?;
        self.mutate_state_wit("wake-cancel", |state| {
            let Some(record) = state.wakes.get_mut(&wake_storage_key) else {
                if caller_principal_seed.is_some() {
                    return Err(failure(
                        "not-granted",
                        "wake handle is not owned by the caller principal",
                    ));
                }
                return Ok(false);
            };
            if record.caller_principal_seed != caller_principal_seed {
                return Err(failure(
                    "not-granted",
                    "wake handle is not owned by the caller principal",
                ));
            }
            if record.cancelled || record.fired_at_ms.is_some() {
                return Ok(false);
            }
            record.cancelled = true;
            Ok(true)
        })
    }

    fn stage_activation(
        &self,
        request: activation::ActivationRequest,
    ) -> Result<activation::ActivationStatus, foundation::Failure> {
        self.stage_activation_for_principal(request, None)
    }

    pub(crate) fn stage_activation_for_principal(
        &self,
        request: activation::ActivationRequest,
        caller_principal_seed: Option<Sha256Digest>,
    ) -> Result<activation::ActivationStatus, foundation::Failure> {
        validate_identifier(&request.activation_id)?;
        let idempotency = self.principal_operation_scope(
            "activation",
            &digest_key(&request.idempotency_key)?,
            caller_principal_seed,
        )?;
        let activation_storage_key = self.principal_handle_scope(
            "activation",
            &request.activation_id,
            caller_principal_seed,
        )?;
        let target = validate_blob_ref(&request.graph_manifest, self.inner.config.max_blob_bytes)?;
        self.get_blob(request.graph_manifest.clone())?;
        match (&request.state_migration, &request.migrated_state) {
            (Some(migration), Some(migrated_state)) => {
                let migration = validate_digest(migration)?;
                if !self
                    .lock_state()?
                    .admitted_components
                    .contains_key(&digest_hex(migration))
                {
                    return Err(failure(
                        "not-admitted",
                        "migration component digest is not admitted",
                    ));
                }
                validate_blob_ref(migrated_state, self.inner.config.max_blob_bytes)?;
                self.get_blob(migrated_state.clone())?;
            }
            (None, None) => {}
            _ => {
                return Err(failure(
                    "incomplete-migration-binding",
                    "migration component and migrated state must be supplied together",
                ));
            }
        }
        if let Some(expected_state) = &request.expected_active_state {
            validate_blob_ref(expected_state, self.inner.config.max_blob_bytes)?;
            self.get_blob(expected_state.clone())?;
        }
        let request_digest = canonical_digest(&request)?;
        self.mutate_state_wit("activation-stage", |state| {
            if !state.root_bindings.contains_key(&digest_hex(target)) {
                return Err(failure(
                    "not-admitted",
                    "manifest has no verified root execution binding",
                ));
            }
            if digest_option_key(request.expected_active_graph.as_ref())?
                != digest_option_key(state.active_manifest.as_ref())?
            {
                return Err(failure("conflict", "expected active graph does not match"));
            }
            if blob_option_key(request.expected_active_state.as_ref())?
                != blob_option_key(state.active_state.as_ref())?
            {
                return Err(failure("conflict", "expected active state does not match"));
            }
            if let Some(existing_id) = state.activation_idempotency.get(&idempotency) {
                if existing_id != &activation_storage_key {
                    return Err(failure(
                        "not-granted",
                        "activation ownership has moved to another graph principal",
                    ));
                }
                let existing = &state.activations[existing_id];
                if existing.request_digest != request_digest
                    || existing.caller_principal_seed != caller_principal_seed
                {
                    return Err(failure(
                        "idempotency-conflict",
                        "idempotency key was reused for different bytes",
                    ));
                }
                return Ok(existing.status.clone());
            }
            if state.activations.contains_key(&activation_storage_key) {
                return Err(failure("conflict", "activation identifier already exists"));
            }
            let target_state = request
                .migrated_state
                .clone()
                .or_else(|| state.active_state.clone());
            let status = activation::ActivationStatus {
                activation_id: request.activation_id.clone(),
                state: activation::ActivationState::Staged,
                active_graph: Some(digest_value(target)),
                active_state: target_state.clone(),
                receipt: None,
            };
            state
                .activation_idempotency
                .insert(idempotency, activation_storage_key.clone());
            state.activations.insert(
                activation_storage_key.clone(),
                StoredActivation {
                    request_digest,
                    target_graph: digest_value(target),
                    caller_principal_seed,
                    target_state,
                    status: status.clone(),
                },
            );
            Ok(status)
        })
    }

    fn commit_activation(
        &self,
        activation_id: String,
    ) -> Result<activation::ActivationStatus, foundation::Failure> {
        self.commit_activation_for_principal(activation_id, None)
    }

    pub(crate) fn commit_activation_for_principal(
        &self,
        activation_id: String,
        caller_principal_seed: Option<Sha256Digest>,
    ) -> Result<activation::ActivationStatus, foundation::Failure> {
        validate_identifier(&activation_id)?;
        let activation_storage_key =
            self.principal_handle_scope("activation", &activation_id, caller_principal_seed)?;
        let now = self.now_ms();
        self.mutate_state_wit("activation-commit", |state| {
            let Some(record) = state.activations.get(&activation_storage_key).cloned() else {
                return Err(if caller_principal_seed.is_some() {
                    failure(
                        "not-granted",
                        "activation handle is not owned by the caller principal",
                    )
                } else {
                    failure("not-found", "activation identifier is not present")
                });
            };
            if record.caller_principal_seed != caller_principal_seed {
                return Err(failure(
                    "not-granted",
                    "activation handle is not owned by the caller principal",
                ));
            }
            if matches!(record.status.state, activation::ActivationState::Active) {
                return Ok(record.status);
            }
            if !matches!(record.status.state, activation::ActivationState::Staged) {
                return Err(failure("invalid-state", "activation is not staged"));
            }
            let target = validate_digest(&record.target_graph)?;
            let destination_key = match caller_principal_seed {
                Some(principal_seed) => verified_graph_principal_handle_key(
                    state,
                    target,
                    principal_seed,
                    "activation",
                    "switch",
                    "wasm-biotic:factory/activation@0.1.0",
                    &activation_id,
                )?,
                None => activation_storage_key.clone(),
            };
            state.last_known_good_manifest = state.active_manifest.clone();
            state.last_known_good_state = state.active_state.clone();
            state.active_manifest = Some(record.target_graph.clone());
            state.active_state = record.target_state.clone();
            let receipt = mechanism_receipt(
                Sha256Digest::from_bytes(record.request_digest.as_bytes()),
                target,
                now,
                now,
                0,
            );
            let active_manifest = state.active_manifest.clone();
            let active_state = state.active_state.clone();
            let mut updated = record;
            updated.status.state = activation::ActivationState::Active;
            updated.status.active_graph = active_manifest;
            updated.status.active_state = active_state;
            updated.status.receipt = Some(receipt);
            let status = updated.status.clone();
            rekey_activation_owner(state, &activation_storage_key, destination_key, updated)?;
            Ok(status)
        })
    }

    fn rollback_activation(
        &self,
        activation_id: String,
        target_graph: foundation::Digest,
    ) -> Result<activation::ActivationStatus, foundation::Failure> {
        self.rollback_activation_for_principal(activation_id, target_graph, None)
    }

    pub(crate) fn activation_status_for_principal(
        &self,
        activation_id: String,
        caller_principal_seed: Option<Sha256Digest>,
    ) -> Result<activation::ActivationStatus, foundation::Failure> {
        validate_identifier(&activation_id)?;
        let activation_storage_key =
            self.principal_handle_scope("activation", &activation_id, caller_principal_seed)?;
        let state = self.lock_state()?;
        let Some(record) = state.activations.get(&activation_storage_key) else {
            return Err(if caller_principal_seed.is_some() {
                failure(
                    "not-granted",
                    "activation handle is not owned by the caller principal",
                )
            } else {
                failure("not-found", "activation identifier is not present")
            });
        };
        if record.caller_principal_seed != caller_principal_seed {
            return Err(failure(
                "not-granted",
                "activation handle is not owned by the caller principal",
            ));
        }
        Ok(record.status.clone())
    }

    pub(crate) fn rollback_activation_for_principal(
        &self,
        activation_id: String,
        target_graph: foundation::Digest,
        caller_principal_seed: Option<Sha256Digest>,
    ) -> Result<activation::ActivationStatus, foundation::Failure> {
        validate_identifier(&activation_id)?;
        let activation_storage_key =
            self.principal_handle_scope("activation", &activation_id, caller_principal_seed)?;
        let target = validate_digest(&target_graph)?;
        let now = self.now_ms();
        self.mutate_state_wit("activation-rollback", |state| {
            if !state.root_bindings.contains_key(&digest_hex(target)) {
                return Err(failure(
                    "not-admitted",
                    "rollback manifest has no verified root execution binding",
                ));
            }
            if digest_option_key(state.last_known_good_manifest.as_ref())?
                != Some(target.to_string())
            {
                return Err(failure(
                    "out-of-scope",
                    "rollback target is not last-known-good",
                ));
            }
            let request_digest = Sha256Digest::from_bytes(
                format!("{activation_id}|{}", digest_hex(target)).as_bytes(),
            );
            let Some(record) = state.activations.get(&activation_storage_key) else {
                return Err(if caller_principal_seed.is_some() {
                    failure(
                        "not-granted",
                        "activation handle is not owned by the caller principal",
                    )
                } else {
                    failure("not-found", "activation identifier is not present")
                });
            };
            if record.caller_principal_seed != caller_principal_seed {
                return Err(failure(
                    "not-granted",
                    "activation handle is not owned by the caller principal",
                ));
            }
            let destination_key = match caller_principal_seed {
                Some(principal_seed) => verified_graph_principal_handle_key(
                    state,
                    target,
                    principal_seed,
                    "activation",
                    "switch",
                    "wasm-biotic:factory/activation@0.1.0",
                    &activation_id,
                )?,
                None => activation_storage_key.clone(),
            };
            state.active_manifest = Some(target_graph.clone());
            state.active_state = state.last_known_good_state.clone();
            let active_state = state.active_state.clone();
            let mut updated = record.clone();
            updated.status.state = activation::ActivationState::RolledBack;
            updated.status.active_graph = Some(target_graph);
            updated.status.active_state = active_state;
            updated.status.receipt = Some(mechanism_receipt(request_digest, target, now, now, 0));
            let status = updated.status.clone();
            rekey_activation_owner(state, &activation_storage_key, destination_key, updated)?;
            Ok(status)
        })
    }

    fn append_audit(
        &self,
        entry: audit_log::AuditEntry,
    ) -> Result<audit_log::AuditReceipt, foundation::Failure> {
        validate_identifier(&entry.event_id)?;
        validate_identifier(&entry.actor.id)?;
        require_nonempty(&entry.event_type, "event-type")?;
        validate_digest(&entry.actor.component_digest)?;
        self.get_blob(entry.payload.clone())?;
        let idempotency = digest_key(&entry.idempotency_key)?;
        let request_digest = canonical_digest(&entry)?;
        self.mutate_state_wit("audit-append", |state| {
            if let Some(sequence) = state.audit_idempotency.get(&idempotency) {
                let existing = &state.audit[usize::try_from(sequence - 1).unwrap_or(usize::MAX)];
                if existing.request_digest != request_digest {
                    return Err(failure(
                        "idempotency-conflict",
                        "idempotency key was reused for different bytes",
                    ));
                }
                return Ok(existing.receipt.clone());
            }
            let expected_previous = state
                .audit
                .last()
                .map(|record| record.receipt.entry_digest.clone());
            if digest_option_key(entry.previous_entry.as_ref())?
                != digest_option_key(expected_previous.as_ref())?
            {
                return Err(failure(
                    "conflict",
                    "audit previous digest does not match chain head",
                ));
            }
            let sequence = u64::try_from(state.audit.len())
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or_else(|| failure("version-exhausted", "audit sequence overflow"))?;
            let entry_digest = Sha256Digest::from_bytes(
                &serde_json::to_vec(&(sequence, &entry))
                    .map_err(|_| failure("encoding-error", "could not encode audit entry"))?,
            );
            let receipt = audit_log::AuditReceipt {
                sequence,
                entry_digest: digest_value(entry_digest),
            };
            state.audit.push(StoredAudit {
                request_digest,
                entry,
                receipt: receipt.clone(),
            });
            state.audit_idempotency.insert(idempotency, sequence);
            Ok(receipt)
        })
    }
}

pub(crate) fn validate_digest(
    value: &foundation::Digest,
) -> Result<Sha256Digest, foundation::Failure> {
    match value.algorithm {
        foundation::HashAlgorithm::Sha256 => {}
    }
    if value.hex.len() != 64
        || !value
            .hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(failure(
            "invalid-digest",
            "digest must be 64 lower-case hexadecimal characters",
        ));
    }
    format!("sha256:{}", value.hex)
        .parse()
        .map_err(|_| failure("invalid-digest", "digest could not be parsed"))
}

pub(crate) fn digest_value(value: Sha256Digest) -> foundation::Digest {
    foundation::Digest {
        algorithm: foundation::HashAlgorithm::Sha256,
        hex: digest_hex(value),
    }
}

pub(crate) fn failure(code: impl Into<String>, message: impl Into<String>) -> foundation::Failure {
    foundation::Failure {
        code: code.into(),
        message: message.into(),
        retryable: false,
        evidence: None,
    }
}

fn transport_failure(error: bounded_http::TransportFailure) -> foundation::Failure {
    failure(error.code, error.message)
}

pub(crate) fn canonical_digest<T: Serialize>(value: &T) -> Result<String, foundation::Failure> {
    serde_json::to_vec(value)
        .map(|bytes| Sha256Digest::from_bytes(&bytes).to_string())
        .map_err(|_| failure("encoding-error", "canonical value encoding failed"))
}

pub(crate) fn mechanism_receipt(
    request: Sha256Digest,
    outcome: Sha256Digest,
    started_at_ms: u64,
    finished_at_ms: u64,
    audit_sequence: u64,
) -> foundation::EffectReceipt {
    let executor = Sha256Digest::from_bytes(IMPLEMENTATION_ID);
    effect_receipt(
        request,
        executor,
        outcome,
        started_at_ms,
        finished_at_ms,
        audit_sequence,
    )
}

pub(crate) fn effect_receipt(
    request: Sha256Digest,
    executor: Sha256Digest,
    outcome: Sha256Digest,
    started_at_ms: u64,
    finished_at_ms: u64,
    audit_sequence: u64,
) -> foundation::EffectReceipt {
    let receipt_digest = Sha256Digest::from_bytes(
        format!("{request}|{executor}|{outcome}|{started_at_ms}|{finished_at_ms}|{audit_sequence}")
            .as_bytes(),
    );
    foundation::EffectReceipt {
        receipt_id: format!("receipt-{}", digest_hex(receipt_digest)),
        request_digest: digest_value(request),
        executor_digest: digest_value(executor),
        started_at_ms,
        finished_at_ms,
        outcome_digest: digest_value(outcome),
        audit_sequence,
    }
}

fn validate_blob_ref(
    reference: &foundation::BlobRef,
    max_bytes: u64,
) -> Result<Sha256Digest, foundation::Failure> {
    require_nonempty(&reference.media_type, "media-type")?;
    if reference.size_bytes > max_bytes {
        return Err(failure(
            "limit-exceeded",
            "blob reference exceeds configured bound",
        ));
    }
    validate_digest(&reference.content_digest)
}

fn blob_reference(digest: Sha256Digest, size: u64, media_type: String) -> foundation::BlobRef {
    foundation::BlobRef {
        content_digest: digest_value(digest),
        size_bytes: size,
        media_type,
    }
}

fn digest_key(value: &foundation::Digest) -> Result<String, foundation::Failure> {
    validate_digest(value).map(|digest| digest.to_string())
}

fn digest_option_key(
    value: Option<&foundation::Digest>,
) -> Result<Option<String>, foundation::Failure> {
    value.map(digest_key).transpose()
}

fn blob_option_key(
    value: Option<&foundation::BlobRef>,
) -> Result<Option<(String, u64, String)>, foundation::Failure> {
    value
        .map(|reference| {
            Ok((
                digest_key(&reference.content_digest)?,
                reference.size_bytes,
                reference.media_type.clone(),
            ))
        })
        .transpose()
}

fn digest_hex(value: Sha256Digest) -> String {
    value.to_string().trim_start_matches("sha256:").to_string()
}

fn require_nonempty(value: &str, field: &str) -> Result<(), foundation::Failure> {
    if value.trim().is_empty() || value.len() > MAX_IDENTIFIER_BYTES {
        Err(failure(
            "invalid-request",
            format!("{field} is empty or exceeds its byte bound"),
        ))
    } else {
        Ok(())
    }
}

fn validate_identifier(value: &str) -> Result<(), foundation::Failure> {
    require_nonempty(value, "identifier")?;
    if value.chars().any(char::is_control) {
        return Err(failure(
            "invalid-request",
            "identifier contains control characters",
        ));
    }
    Ok(())
}

fn validate_config(config: &LocalConfig) -> Result<(), KernelError> {
    if config.max_blob_bytes == 0
        || config.max_total_blob_bytes < config.max_blob_bytes
        || config.max_random_bytes == 0
        || config.max_wake_delay_ms == 0
        || config.max_http_timeout_ms == 0
        || config.max_component_fuel == 0
        || config.max_component_memory_bytes == 0
        || config.max_component_output_bytes == 0
        || config.max_component_wall_time_ms == 0
    {
        return Err(KernelError::InvalidConfiguration(
            "all bounds must be positive and total blob quota must cover one blob".to_string(),
        ));
    }
    for namespace in &config.allowed_namespaces {
        validate_identifier(namespace)
            .map_err(|error| KernelError::InvalidConfiguration(error.message))?;
    }
    if let Some(http) = &config.http_transport {
        http.validate()?;
        if http.max_timeout_ms > config.max_http_timeout_ms
            || http.max_request_body_bytes > config.max_blob_bytes
            || http.max_response_body_bytes > config.max_blob_bytes
        {
            return Err(KernelError::InvalidConfiguration(
                "HTTP operator capacity exceeds the enclosing mechanism bounds".to_string(),
            ));
        }
    }
    Ok(())
}

fn write_canonical_config_value(
    value: &serde_json::Value,
    output: &mut Vec<u8>,
) -> Result<(), KernelError> {
    match value {
        serde_json::Value::Null => output.extend_from_slice(b"null"),
        serde_json::Value::Bool(value) => {
            output.extend_from_slice(if *value { b"true" } else { b"false" });
        }
        serde_json::Value::Number(number) => {
            if number.is_f64() {
                return Err(KernelError::InvalidConfiguration(
                    "floating-point operator bounds are not canonical".to_string(),
                ));
            }
            output.extend_from_slice(number.to_string().as_bytes());
        }
        serde_json::Value::String(value) => output.extend_from_slice(
            &serde_json::to_vec(value)
                .map_err(|error| KernelError::InvalidConfiguration(error.to_string()))?,
        ),
        serde_json::Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_config_value(value, output)?;
            }
            output.push(b']');
        }
        serde_json::Value::Object(values) => {
            output.push(b'{');
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_config_value(&serde_json::Value::String(key.clone()), output)?;
                output.push(b':');
                write_canonical_config_value(&values[key], output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn load_state(
    root: &Path,
    faults: &DurabilityFaultController,
) -> Result<DurableState, KernelError> {
    let path = root.join(STATE_FILE);
    if !path.exists() {
        let state = DurableState::default();
        persist_state(root, &state, faults)?;
        return Ok(state);
    }
    let bytes = fs::read(&path).map_err(persistence)?;
    let state: DurableState = serde_json::from_slice(&bytes).map_err(persistence)?;
    if state.schema != STATE_SCHEMA {
        return Err(KernelError::Persistence(format!(
            "unsupported mechanism state schema {}",
            state.schema
        )));
    }
    Ok(state)
}

fn persist_state(
    root: &Path,
    state: &DurableState,
    faults: &DurabilityFaultController,
) -> Result<(), KernelError> {
    let bytes = serde_json::to_vec(state).map_err(persistence)?;
    write_atomic(&root.join(STATE_FILE), &bytes, faults, "mechanism-state")
}

fn write_atomic(
    path: &Path,
    bytes: &[u8],
    faults: &DurabilityFaultController,
    operation: &'static str,
) -> Result<(), KernelError> {
    let temp = if path.file_name().is_some_and(|name| name == STATE_FILE) {
        path.with_file_name(STATE_TEMP_FILE)
    } else {
        path.with_extension("tmp")
    };
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&temp).map_err(persistence)?;
    faults.inject(DurabilityFaultPoint::BeforeTempWrite, operation)?;
    file.write_all(bytes).map_err(persistence)?;
    faults.inject(DurabilityFaultPoint::AfterTempWrite, operation)?;
    faults.inject(DurabilityFaultPoint::BeforeTempSync, operation)?;
    file.sync_all().map_err(persistence)?;
    faults.inject(DurabilityFaultPoint::AfterTempSync, operation)?;
    faults.inject(DurabilityFaultPoint::BeforeRename, operation)?;
    fs::rename(&temp, path).map_err(persistence)?;
    faults.inject(DurabilityFaultPoint::AfterRename, operation)?;
    if let Some(parent) = path.parent() {
        faults.inject(DurabilityFaultPoint::BeforeDirectorySync, operation)?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(persistence)?;
        faults.inject(DurabilityFaultPoint::AfterDirectorySync, operation)?;
    }
    Ok(())
}

fn read_verified(path: &Path, digest: Sha256Digest, size: u64) -> Result<Vec<u8>, KernelError> {
    let mut file = File::open(path).map_err(persistence)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(persistence)?;
    verify_bytes(&bytes, digest, size)?;
    Ok(bytes)
}

fn verify_file(path: &Path, digest: Sha256Digest, size: u64) -> Result<(), KernelError> {
    read_verified(path, digest, size).map(|_| ())
}

fn verify_bytes(bytes: &[u8], digest: Sha256Digest, size: u64) -> Result<(), KernelError> {
    let actual_size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let actual_digest = Sha256Digest::from_bytes(bytes);
    if actual_size != size || actual_digest != digest {
        return Err(KernelError::Persistence(
            "content-addressed bytes failed size or digest verification".to_string(),
        ));
    }
    Ok(())
}

fn persistence(error: impl std::fmt::Display) -> KernelError {
    KernelError::Persistence(error.to_string())
}

fn wit_persistence(error: impl std::fmt::Display) -> foundation::Failure {
    failure("persistence-error", error.to_string())
}

#[cfg(test)]
mod durability_tests;
#[cfg(test)]
mod http_tests;
