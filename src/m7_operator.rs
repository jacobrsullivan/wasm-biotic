//! Operator-facing orchestration for one bounded M7 proof dossier.
//!
//! The M7 foundation and dossier runtime deliberately do not inspect Git,
//! read operator files, or handle command-line concerns.  This module provides
//! that missing edge without weakening the evidence boundary: all signing is
//! detached, private keys are never accepted, source files are read through
//! bounded regular-file checks, and output files are created without replacing
//! different existing bytes.

use crate::execution::ContentDigest;
use crate::m5_provider_execution::M5CompletedProviderInvocationV1;
use crate::m5_runtime::M5PreparedProviderSeedV1;
use crate::m7_closure::{
    FrozenClosureCriteria, LiveProviderQualificationScope, LiveProviderQualificationStatus,
    M7_ACTIVE_SURFACE_CONNECT_TIMEOUT_MS, M7_ACTIVE_SURFACE_READ_TIMEOUT_MS,
    M7_ACTIVE_SURFACE_REQUEST_TIMEOUT_MS, M7_MAX_TRANSCRIPT_CONTENT_BYTES,
    M7ActiveSurfaceCaptureV1, M7ActiveSurfaceObservationV1, M7ActiveSurfaceRoleV1,
    M7ActiveSurfaceSnapshotV1, M7Blocker, M7CargoTestTranscriptV2, M7ClaimBoundarySourceV3,
    M7ClosureDecision, M7Criterion, M7Evaluation, M7EvaluationCaveatV1, M7EvidenceArtifact,
    M7EvidenceFamily, M7EvidenceKind, M7EvidenceLink, M7ExternalEd25519IdentityV1, M7FinalBundle,
    M7LiveProviderSourceV1, M7ProofRunManifest, M7PublicationPolicySourceV3, M7SemanticFailure,
    M7SourceCaptureInventoryFailure, M7SourceIdentity, M7SourceInputV2, M7SourceLinkV2,
    M7SourceRoleV2, M7SourceRootProvenanceV1, M7TruthBoundarySourceV3,
};
use crate::m7_runtime::{M7DossierRuntime, M7IndependentReviewRequest};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fmt::{Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const M7_SOURCE_INSPECTION_SCHEMA: &str = "wasm-biotic.m7-source-inspection.v2";
pub const M7_SOURCE_IDENTITY_RECIPE_SCHEMA: &str = "wasm-biotic.m7-source-identity-recipe.v2";
pub const M7_TRACKED_INVENTORY_SCHEMA: &str = "wasm-biotic.m7-tracked-inventory.v1";
pub const M7_TOOLCHAIN_RECORD_SCHEMA: &str = "wasm-biotic.m7-toolchain-record.v2";
pub const M7_BUILD_ENVIRONMENT_POLICY_SCHEMA: &str = "wasm-biotic.m7-build-environment-policy.v1";
pub const M7_MANIFEST_CREATE_REQUEST_SCHEMA: &str = "wasm-biotic.m7-manifest-create-request.v3";
pub const M7_EXACT_SOURCE_ADMISSION_REQUEST_SCHEMA: &str =
    "wasm-biotic.m7-exact-source-admission-request.v3";
pub const M7_SOURCE_CAPTURE_SIGNING_REQUEST_SCHEMA: &str =
    "wasm-biotic.m7-source-capture-signing-request.v3";
pub const M7_REVIEW_SIGNING_REQUEST_SCHEMA: &str = "wasm-biotic.m7-review-signing-request.v1";
pub const M7_EVALUATION_REPORT_SCHEMA: &str = "wasm-biotic.m7-evaluation-report.v6";

const SOURCE_INVENTORY_DIGEST_DOMAIN: &str = "wasm-biotic:m7-tracked-inventory:v1";
const TOOLCHAIN_RECORD_DIGEST_DOMAIN: &str = "wasm-biotic:m7-toolchain-record:v2";
const BUILD_ENVIRONMENT_POLICY_DIGEST_DOMAIN: &str = "wasm-biotic:m7-build-environment-policy:v1";
const SOURCE_INSPECTION_DIGEST_DOMAIN: &str = "wasm-biotic:m7-source-inspection:v2";
const SOURCE_CAPTURE_REQUEST_DIGEST_DOMAIN: &str =
    "wasm-biotic:m7-source-capture-signing-request:v3";
const REVIEW_SIGNING_REQUEST_DIGEST_DOMAIN: &str = "wasm-biotic:m7-review-signing-request:v1";

pub const MAX_REQUEST_BYTES: usize = 2 * 1_048_576;
pub const MAX_MANIFEST_BYTES: usize = 2 * 1_048_576;
pub const MAX_SOURCE_INSPECTION_BYTES: usize = 32 * 1_048_576;
pub const MAX_PREPARED_PROVIDER_SEED_BYTES: usize = 4 * 1_048_576;
pub const MAX_COMPLETED_PROVIDER_INVOCATION_BYTES: usize = 8 * 1_048_576;
pub const MAX_LIVE_PROVIDER_SOURCE_BYTES: usize = 32 * 1_048_576;
pub const MAX_ACTIVE_SURFACE_INPUT_BYTES: usize = 16 * 1_048_576;
pub const MAX_ACTIVE_SURFACE_INPUT_TOTAL_BYTES: usize = 64 * 1_048_576;
pub const MAX_EXACT_SOURCE_BYTES: usize = 256 * 1_048_576;
pub const MAX_EXACT_SOURCE_TOTAL_BYTES: usize = 384 * 1_048_576;
pub const MAX_TRANSCRIPT_CONTENT_BYTES: usize = M7_MAX_TRANSCRIPT_CONTENT_BYTES;
pub const MAX_TRANSCRIPT_STREAM_BYTES: usize = MAX_TRANSCRIPT_CONTENT_BYTES;
const MAX_TRANSCRIPT_JSON_EXPANSION: usize = 6;
const MAX_TRANSCRIPT_JSON_FIXED_OVERHEAD_BYTES: usize = 64 * 1_024;
pub const MAX_TRANSCRIPT_FILE_BYTES: usize = MAX_TRANSCRIPT_CONTENT_BYTES
    * MAX_TRANSCRIPT_JSON_EXPANSION
    + MAX_TRANSCRIPT_JSON_FIXED_OVERHEAD_BYTES;
pub const MAX_REVIEW_TEXT_BYTES: usize = 1_048_576;
pub const MAX_SIGNATURE_BYTES: usize = 64;
pub const MAX_OUTPUT_BYTES: usize = 256 * 1_048_576;

const MAX_TRACKED_FILES: usize = 100_000;
const MAX_TRACKED_FILE_BYTES: usize = 256 * 1_048_576;
const MAX_TRACKED_TOTAL_BYTES: usize = 1_024 * 1_048_576;
const MAX_GIT_OUTPUT_BYTES: usize = 64 * 1_048_576;
const MAX_PROCESS_DIAGNOSTIC_BYTES: usize = 1_048_576;
const MAX_LOCKFILE_BYTES: usize = 16 * 1_048_576;
const MAX_TOOLCHAIN_PIN_BYTES: usize = 1_048_576;
const MAX_TOOL_EXECUTABLE_BYTES: usize = 256 * 1_048_576;
const MAX_STATEMENT_BYTES: usize = 64 * 1_024;
const ED25519_PUBLIC_KEY_BYTES: usize = 32;
const GIT_PROCESS_TIMEOUT: Duration = Duration::from_secs(120);
const TOOLCHAIN_PROCESS_TIMEOUT: Duration = Duration::from_secs(60);
const CARGO_TEST_PROCESS_TIMEOUT: Duration = Duration::from_secs(2 * 60 * 60);
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(25);
const MAX_LIBTEST_FAILURE_DIAGNOSTIC_NAMES: usize = 16;
const MAX_LIBTEST_FAILURE_DIAGNOSTIC_NAME_BYTES: usize = 240;
const MAX_LIBTEST_FAILURE_DIAGNOSTIC_COMPONENTS: usize = 32;

#[cfg(unix)]
const CANONICAL_BUILD_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";
#[cfg(not(unix))]
const CANONICAL_BUILD_PATH: &str = "";

const BUILD_ENVIRONMENT_INHERITANCE_POLICY: &str = "clear-all-before-allowlist";
const BUILD_RUNTIME_VARIABLE: &str = "CARGO_TARGET_DIR";
const BUILD_ENVIRONMENT_REJECTION_RULES: &[&str] = &[
    "reject compiler/linker wrappers and flags",
    "reject Rust toolchain and target overrides",
    "reject Cargo build/profile/registry/network overrides",
];
const BUILD_ENVIRONMENT_STRIPPING_RULES: &[&str] = &[
    "strip every inherited variable before applying the fixed allowlist",
    "strip proxy and credential variables",
    "strip Git mutation and identity variables",
];

static OUTPUT_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum M7ProcessOutputStream {
    Stdout,
    Stderr,
}

impl Display for M7ProcessOutputStream {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stdout => formatter.write_str("stdout"),
            Self::Stderr => formatter.write_str("stderr"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum M7ProcessOutputLimitKind {
    Stream,
    Combined,
    StreamAndCombined,
}

/// Bounded, untrusted libtest-looking markers observed before an output cap.
///
/// These names are diagnostic hints only. They do not establish that libtest
/// emitted the lines, that Cargo exited, or that any named test failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct M7ObservedLibtestFailureDiagnostic {
    observed_failed_test_names: Vec<String>,
    name_limit_reached: bool,
}

impl M7ObservedLibtestFailureDiagnostic {
    /// Strictly screened names retained in first-observed order.
    pub fn observed_failed_test_names(&self) -> &[String] {
        &self.observed_failed_test_names
    }

    /// Whether another distinct safe-looking name was omitted at the count cap.
    pub fn name_limit_reached(&self) -> bool {
        self.name_limit_reached
    }
}

#[derive(Debug)]
pub enum M7OperatorError {
    InvalidInput(String),
    UnsafePath(PathBuf),
    ResourceExhausted(String),
    Conflict(String),
    Process {
        command: Vec<String>,
        status: Option<i32>,
        stderr: String,
    },
    ProcessTimeout {
        command: Vec<String>,
        timeout: Duration,
    },
    ProcessOutputLimitExceeded {
        program: PathBuf,
        stream: M7ProcessOutputStream,
        kind: M7ProcessOutputLimitKind,
        stream_observed_at_least: usize,
        stream_limit: usize,
        combined_observed_at_least: usize,
        combined_limit: Option<usize>,
        observed_libtest_failures: Option<M7ObservedLibtestFailureDiagnostic>,
    },
    EvaluationNotClosed {
        decision: M7ClosureDecision,
        evidence_complete: bool,
        report_path: PathBuf,
    },
    Foundation(String),
    Dossier(String),
    Serialization(String),
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

impl M7OperatorError {
    fn io(path: &Path, source: std::io::Error) -> Self {
        Self::Io {
            path: path.to_path_buf(),
            source,
        }
    }
}

impl Display for M7OperatorError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidInput(message) => {
                write!(formatter, "invalid M7 operator input: {message}")
            }
            Self::UnsafePath(path) => {
                write!(formatter, "unsafe M7 operator path: {}", path.display())
            }
            Self::ResourceExhausted(message) => {
                write!(formatter, "M7 operator resource bound exceeded: {message}")
            }
            Self::Conflict(message) => write!(formatter, "M7 operator conflict: {message}"),
            Self::Process {
                command,
                status,
                stderr,
            } => write!(
                formatter,
                "operator subprocess {:?} failed with status {:?}: {}",
                command,
                status,
                stderr.trim()
            ),
            Self::ProcessTimeout { command, timeout } => write!(
                formatter,
                "operator subprocess {:?} timed out after {timeout:?}",
                command
            ),
            Self::ProcessOutputLimitExceeded {
                program,
                stream,
                kind,
                stream_observed_at_least,
                stream_limit,
                combined_observed_at_least,
                combined_limit,
                observed_libtest_failures,
            } => {
                let limit_kind = match kind {
                    M7ProcessOutputLimitKind::Stream => "per-stream",
                    M7ProcessOutputLimitKind::Combined => "combined",
                    M7ProcessOutputLimitKind::StreamAndCombined => "per-stream and combined",
                };
                write!(
                    formatter,
                    "operator subprocess '{}' {stream} exceeded its {limit_kind} output limit ({stream} observed at least {stream_observed_at_least} bytes; stream limit {stream_limit} bytes; combined stdout/stderr observed at least {combined_observed_at_least} bytes",
                    program.display()
                )?;
                if let Some(limit) = combined_limit {
                    write!(formatter, "; combined limit {limit} bytes")?;
                }
                formatter.write_str("); captured content omitted")?;
                if let Some(diagnostic) = observed_libtest_failures {
                    write!(
                        formatter,
                        "; untrusted, possibly incomplete libtest-looking FAILED names observed before the cap: [{}]",
                        diagnostic.observed_failed_test_names.join(", ")
                    )?;
                    if diagnostic.name_limit_reached {
                        formatter.write_str(" (additional safe-looking names omitted)")?;
                    }
                    formatter.write_str(
                        "; these markers do not establish a Cargo result, test failure, count, or cause",
                    )?;
                }
                Ok(())
            }
            Self::EvaluationNotClosed {
                decision,
                evidence_complete,
                report_path,
            } => write!(
                formatter,
                "M7 evaluation did not establish closure (decision {decision:?}, evidence_complete {evidence_complete}); report persisted at '{}'",
                report_path.display()
            ),
            Self::Foundation(message) => {
                write!(formatter, "M7 foundation rejected input: {message}")
            }
            Self::Dossier(message) => write!(formatter, "M7 dossier rejected operation: {message}"),
            Self::Serialization(message) => {
                write!(formatter, "M7 operator serialization failed: {message}")
            }
            Self::Io { path, source } => write!(
                formatter,
                "M7 operator I/O failed at '{}': {source}",
                path.display()
            ),
        }
    }
}

impl Error for M7OperatorError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M7SourceIdentityRecipeV1 {
    pub schema: String,
    pub git_environment_rules: Vec<String>,
    pub commit_object_encoding: String,
    pub tree_object_encoding: String,
    pub checkout_inventory_encoding: String,
    pub cleanliness_command: Vec<String>,
    pub inventory_command: Vec<String>,
    pub tracked_content_command: Vec<String>,
    pub rustc_command: Vec<String>,
    pub cargo_command: Vec<String>,
}

impl Default for M7SourceIdentityRecipeV1 {
    fn default() -> Self {
        Self {
            schema: M7_SOURCE_IDENTITY_RECIPE_SCHEMA.to_string(),
            git_environment_rules: vec![
                "remove GIT_DIR, GIT_WORK_TREE, GIT_COMMON_DIR, GIT_OBJECT_DIRECTORY, GIT_ALTERNATE_OBJECT_DIRECTORIES, and GIT_INDEX_FILE"
                    .to_string(),
                "set GIT_NO_REPLACE_OBJECTS=1".to_string(),
            ],
            commit_object_encoding:
                "sha256 over exact `git cat-file commit <commit-oid>` stdout bytes".to_string(),
            tree_object_encoding:
                "sha256 over exact `git cat-file tree <tree-oid>` stdout bytes".to_string(),
            checkout_inventory_encoding: format!(
                "sha256 over compact JSON ({SOURCE_INVENTORY_DIGEST_DOMAIN}, sorted tracked entries); each worktree byte sequence must reproduce its Git blob OID"
            ),
            cleanliness_command: vec![
                "git".to_string(),
                "status".to_string(),
                "--porcelain=v2".to_string(),
                "--untracked-files=all".to_string(),
                "--ignored=matching".to_string(),
                "-z".to_string(),
            ],
            inventory_command: vec![
                "git".to_string(),
                "ls-tree".to_string(),
                "-r".to_string(),
                "-z".to_string(),
                "--full-tree".to_string(),
                "<tree-oid>".to_string(),
            ],
            tracked_content_command: vec![
                "git".to_string(),
                "hash-object".to_string(),
                "--stdin".to_string(),
            ],
            rustc_command: vec![
                "<resolved-rustc-executable>".to_string(),
                "--version".to_string(),
                "--verbose".to_string(),
            ],
            cargo_command: vec![
                "<resolved-cargo-executable>".to_string(),
                "--version".to_string(),
                "--verbose".to_string(),
            ],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M7TrackedSourceEntryV1 {
    pub path: String,
    pub mode: String,
    pub blob_oid: String,
    pub byte_length: u64,
    pub content_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M7TrackedInventoryV1 {
    pub schema: String,
    pub entries: Vec<M7TrackedSourceEntryV1>,
    pub total_byte_length: u64,
    pub inventory_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M7ToolchainCommandRecordV1 {
    pub logical_program: String,
    pub resolver: M7ExecutableIdentityV1,
    pub executable: M7ExecutableIdentityV1,
    pub command: Vec<String>,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M7ExecutableIdentityV1 {
    pub invocation_path: String,
    pub canonical_path: String,
    pub invocation_symlink_target: Option<String>,
    pub byte_length: u64,
    pub content_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M7BuildEnvironmentVariableV1 {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M7BuildEnvironmentPolicyV1 {
    pub schema: String,
    pub inheritance_policy: String,
    pub fixed_environment: Vec<M7BuildEnvironmentVariableV1>,
    pub runtime_variable_names: Vec<String>,
    pub rejection_rules: Vec<String>,
    pub stripping_rules: Vec<String>,
    pub cargo_config_paths_checked_absent: Vec<String>,
    pub cargo_credential_paths_checked_absent: Vec<String>,
    pub policy_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M7ToolchainPinFileV1 {
    pub path: String,
    pub byte_length: u64,
    pub content_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M7ToolchainRecordV1 {
    pub schema: String,
    pub git: M7ToolchainCommandRecordV1,
    pub rustc: M7ToolchainCommandRecordV1,
    pub cargo: M7ToolchainCommandRecordV1,
    pub pin_files: Vec<M7ToolchainPinFileV1>,
    pub build_environment_policy: M7BuildEnvironmentPolicyV1,
    pub record_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M7SourceInspectionV1 {
    pub schema: String,
    pub recipe: M7SourceIdentityRecipeV1,
    pub checkout_root: String,
    pub git_directory: String,
    pub git_common_directory: String,
    pub detached_head: bool,
    pub clean_before_inventory: bool,
    pub clean_after_inventory: bool,
    pub independent_git_directory: bool,
    pub uses_object_alternates: bool,
    pub commit_oid: String,
    pub commit_object_digest: ContentDigest,
    pub tree_oid: String,
    pub tree_digest: ContentDigest,
    pub tracked_inventory: M7TrackedInventoryV1,
    pub cargo_lock_digest: ContentDigest,
    pub toolchain: M7ToolchainRecordV1,
    pub source_identity: M7SourceIdentity,
    pub inspection_digest: ContentDigest,
}

#[derive(Serialize)]
struct InventoryDigestMaterial<'a> {
    domain: &'static str,
    entries: &'a [M7TrackedSourceEntryV1],
    total_byte_length: u64,
}

#[derive(Serialize)]
struct ToolchainDigestMaterial<'a> {
    domain: &'static str,
    git: &'a M7ToolchainCommandRecordV1,
    rustc: &'a M7ToolchainCommandRecordV1,
    cargo: &'a M7ToolchainCommandRecordV1,
    pin_files: &'a [M7ToolchainPinFileV1],
    build_environment_policy: &'a M7BuildEnvironmentPolicyV1,
}

#[derive(Serialize)]
struct BuildEnvironmentPolicyDigestMaterial<'a> {
    domain: &'static str,
    inheritance_policy: &'a str,
    fixed_environment: &'a [M7BuildEnvironmentVariableV1],
    runtime_variable_names: &'a [String],
    rejection_rules: &'a [String],
    stripping_rules: &'a [String],
    cargo_config_paths_checked_absent: &'a [String],
    cargo_credential_paths_checked_absent: &'a [String],
}

#[derive(Serialize)]
struct SourceInspectionDigestMaterial<'a> {
    domain: &'static str,
    recipe: &'a M7SourceIdentityRecipeV1,
    checkout_root: &'a str,
    git_directory: &'a str,
    git_common_directory: &'a str,
    detached_head: bool,
    clean_before_inventory: bool,
    clean_after_inventory: bool,
    independent_git_directory: bool,
    uses_object_alternates: bool,
    commit_oid: &'a str,
    commit_object_digest: &'a ContentDigest,
    tree_oid: &'a str,
    tree_digest: &'a ContentDigest,
    tracked_inventory: &'a M7TrackedInventoryV1,
    cargo_lock_digest: &'a ContentDigest,
    toolchain: &'a M7ToolchainRecordV1,
    source_identity: &'a M7SourceIdentity,
}

impl M7TrackedInventoryV1 {
    fn new(mut entries: Vec<M7TrackedSourceEntryV1>) -> Result<Self, M7OperatorError> {
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        if entries.is_empty() || entries.len() > MAX_TRACKED_FILES {
            return Err(M7OperatorError::ResourceExhausted(format!(
                "tracked inventory must contain 1..={MAX_TRACKED_FILES} files"
            )));
        }
        let mut paths = BTreeSet::new();
        let mut total_byte_length = 0_u64;
        for entry in &entries {
            validate_relative_path(Path::new(&entry.path))?;
            validate_git_oid(&entry.blob_oid, "tracked blob")?;
            if !matches!(entry.mode.as_str(), "100644" | "100755" | "120000") {
                return Err(M7OperatorError::InvalidInput(format!(
                    "unsupported tracked mode '{}' for '{}'",
                    entry.mode, entry.path
                )));
            }
            if entry.byte_length > MAX_TRACKED_FILE_BYTES as u64 {
                return Err(M7OperatorError::ResourceExhausted(format!(
                    "tracked entry '{}' exceeds {MAX_TRACKED_FILE_BYTES} bytes",
                    entry.path
                )));
            }
            if !paths.insert(entry.path.clone()) {
                return Err(M7OperatorError::InvalidInput(format!(
                    "tracked inventory repeats '{}'",
                    entry.path
                )));
            }
            total_byte_length = total_byte_length
                .checked_add(entry.byte_length)
                .ok_or_else(|| {
                    M7OperatorError::ResourceExhausted(
                        "tracked inventory byte length overflowed".to_string(),
                    )
                })?;
        }
        if total_byte_length > MAX_TRACKED_TOTAL_BYTES as u64 {
            return Err(M7OperatorError::ResourceExhausted(format!(
                "tracked inventory exceeds {MAX_TRACKED_TOTAL_BYTES} bytes"
            )));
        }
        let inventory_digest = digest_json(&InventoryDigestMaterial {
            domain: SOURCE_INVENTORY_DIGEST_DOMAIN,
            entries: &entries,
            total_byte_length,
        })?;
        Ok(Self {
            schema: M7_TRACKED_INVENTORY_SCHEMA.to_string(),
            entries,
            total_byte_length,
            inventory_digest,
        })
    }

    fn validate(&self) -> Result<(), M7OperatorError> {
        if self.schema != M7_TRACKED_INVENTORY_SCHEMA {
            return Err(M7OperatorError::InvalidInput(
                "unsupported tracked-inventory schema".to_string(),
            ));
        }
        let expected = Self::new(self.entries.clone())?;
        if &expected != self {
            return Err(M7OperatorError::InvalidInput(
                "tracked inventory is not canonically ordered or has a stale digest".to_string(),
            ));
        }
        Ok(())
    }
}

impl M7ExecutableIdentityV1 {
    fn validate(&self) -> Result<(), M7OperatorError> {
        let invocation = Path::new(&self.invocation_path);
        let canonical = Path::new(&self.canonical_path);
        if !invocation.is_absolute()
            || !canonical.is_absolute()
            || self.byte_length == 0
            || self.byte_length > MAX_TOOL_EXECUTABLE_BYTES as u64
        {
            return Err(M7OperatorError::InvalidInput(
                "executable identity has an invalid path or byte length".to_string(),
            ));
        }
        if self.invocation_symlink_target.is_none() && invocation != canonical {
            return Err(M7OperatorError::InvalidInput(
                "non-symlink executable invocation path is not canonical".to_string(),
            ));
        }
        if self
            .invocation_symlink_target
            .as_ref()
            .is_some_and(|target| target.is_empty())
        {
            return Err(M7OperatorError::InvalidInput(
                "executable symlink target cannot be empty".to_string(),
            ));
        }
        Ok(())
    }

    fn verify_current(&self) -> Result<(), M7OperatorError> {
        self.validate()?;
        let current = executable_identity_from_invocation(Path::new(&self.invocation_path))?;
        if &current != self {
            return Err(M7OperatorError::Conflict(format!(
                "executable identity changed at '{}'",
                self.invocation_path
            )));
        }
        Ok(())
    }
}

impl M7BuildEnvironmentPolicyV1 {
    fn new(
        rustc_path: &str,
        cargo_home: &Path,
        mut cargo_config_paths_checked_absent: Vec<String>,
        mut cargo_credential_paths_checked_absent: Vec<String>,
    ) -> Result<Self, M7OperatorError> {
        if CANONICAL_BUILD_PATH.is_empty() {
            return Err(M7OperatorError::InvalidInput(
                "the canonical M7 build environment is not defined for this platform".to_string(),
            ));
        }
        let cargo_home = cargo_home
            .to_str()
            .ok_or_else(|| M7OperatorError::UnsafePath(cargo_home.to_path_buf()))?;
        let mut fixed_environment = vec![
            M7BuildEnvironmentVariableV1 {
                name: "CARGO_HOME".to_string(),
                value: cargo_home.to_string(),
            },
            M7BuildEnvironmentVariableV1 {
                name: "CARGO_NET_OFFLINE".to_string(),
                value: "true".to_string(),
            },
            M7BuildEnvironmentVariableV1 {
                name: "CARGO_TERM_COLOR".to_string(),
                value: "never".to_string(),
            },
            M7BuildEnvironmentVariableV1 {
                name: "LANG".to_string(),
                value: "C".to_string(),
            },
            M7BuildEnvironmentVariableV1 {
                name: "LC_ALL".to_string(),
                value: "C".to_string(),
            },
            M7BuildEnvironmentVariableV1 {
                name: "PATH".to_string(),
                value: CANONICAL_BUILD_PATH.to_string(),
            },
            M7BuildEnvironmentVariableV1 {
                name: "RUSTC".to_string(),
                value: rustc_path.to_string(),
            },
            M7BuildEnvironmentVariableV1 {
                name: "TZ".to_string(),
                value: "UTC".to_string(),
            },
        ];
        fixed_environment.sort_by(|left, right| left.name.cmp(&right.name));
        cargo_config_paths_checked_absent.sort();
        cargo_config_paths_checked_absent.dedup();
        cargo_credential_paths_checked_absent.sort();
        cargo_credential_paths_checked_absent.dedup();
        let mut policy = Self {
            schema: M7_BUILD_ENVIRONMENT_POLICY_SCHEMA.to_string(),
            inheritance_policy: BUILD_ENVIRONMENT_INHERITANCE_POLICY.to_string(),
            fixed_environment,
            runtime_variable_names: vec![BUILD_RUNTIME_VARIABLE.to_string()],
            rejection_rules: BUILD_ENVIRONMENT_REJECTION_RULES
                .iter()
                .map(|rule| (*rule).to_string())
                .collect(),
            stripping_rules: BUILD_ENVIRONMENT_STRIPPING_RULES
                .iter()
                .map(|rule| (*rule).to_string())
                .collect(),
            cargo_config_paths_checked_absent,
            cargo_credential_paths_checked_absent,
            policy_digest: ContentDigest::from_bytes(&[]),
        };
        policy.policy_digest = policy.expected_digest()?;
        policy.validate(rustc_path)?;
        Ok(policy)
    }

    fn validate(&self, rustc_path: &str) -> Result<(), M7OperatorError> {
        if self.schema != M7_BUILD_ENVIRONMENT_POLICY_SCHEMA
            || self.inheritance_policy != BUILD_ENVIRONMENT_INHERITANCE_POLICY
            || self.runtime_variable_names != [BUILD_RUNTIME_VARIABLE.to_string()]
            || self.rejection_rules
                != BUILD_ENVIRONMENT_REJECTION_RULES
                    .iter()
                    .map(|rule| (*rule).to_string())
                    .collect::<Vec<_>>()
            || self.stripping_rules
                != BUILD_ENVIRONMENT_STRIPPING_RULES
                    .iter()
                    .map(|rule| (*rule).to_string())
                    .collect::<Vec<_>>()
        {
            return Err(M7OperatorError::InvalidInput(
                "build-environment policy differs from the canonical allowlist".to_string(),
            ));
        }
        let cargo_home = self
            .fixed_environment
            .iter()
            .find(|entry| entry.name == "CARGO_HOME")
            .ok_or_else(|| {
                M7OperatorError::InvalidInput(
                    "build-environment policy has no CARGO_HOME".to_string(),
                )
            })?;
        if !Path::new(&cargo_home.value).is_absolute()
            || self
                .cargo_config_paths_checked_absent
                .iter()
                .chain(self.cargo_credential_paths_checked_absent.iter())
                .any(|path| !Path::new(path).is_absolute())
        {
            return Err(M7OperatorError::InvalidInput(
                "build-environment policy paths must be absolute".to_string(),
            ));
        }
        let expected = Self::new_without_validation(
            rustc_path,
            Path::new(&cargo_home.value),
            self.cargo_config_paths_checked_absent.clone(),
            self.cargo_credential_paths_checked_absent.clone(),
        )?;
        if &expected != self {
            return Err(M7OperatorError::InvalidInput(
                "build-environment policy is not canonical or has a stale digest".to_string(),
            ));
        }
        Ok(())
    }

    fn new_without_validation(
        rustc_path: &str,
        cargo_home: &Path,
        cargo_config_paths_checked_absent: Vec<String>,
        cargo_credential_paths_checked_absent: Vec<String>,
    ) -> Result<Self, M7OperatorError> {
        let cargo_home = cargo_home
            .to_str()
            .ok_or_else(|| M7OperatorError::UnsafePath(cargo_home.to_path_buf()))?;
        let mut fixed_environment = vec![
            ("CARGO_HOME", cargo_home),
            ("CARGO_NET_OFFLINE", "true"),
            ("CARGO_TERM_COLOR", "never"),
            ("LANG", "C"),
            ("LC_ALL", "C"),
            ("PATH", CANONICAL_BUILD_PATH),
            ("RUSTC", rustc_path),
            ("TZ", "UTC"),
        ]
        .into_iter()
        .map(|(name, value)| M7BuildEnvironmentVariableV1 {
            name: name.to_string(),
            value: value.to_string(),
        })
        .collect::<Vec<_>>();
        fixed_environment.sort_by(|left, right| left.name.cmp(&right.name));
        let mut config_paths = cargo_config_paths_checked_absent;
        config_paths.sort();
        config_paths.dedup();
        let mut credential_paths = cargo_credential_paths_checked_absent;
        credential_paths.sort();
        credential_paths.dedup();
        let mut policy = Self {
            schema: M7_BUILD_ENVIRONMENT_POLICY_SCHEMA.to_string(),
            inheritance_policy: BUILD_ENVIRONMENT_INHERITANCE_POLICY.to_string(),
            fixed_environment,
            runtime_variable_names: vec![BUILD_RUNTIME_VARIABLE.to_string()],
            rejection_rules: BUILD_ENVIRONMENT_REJECTION_RULES
                .iter()
                .map(|rule| (*rule).to_string())
                .collect(),
            stripping_rules: BUILD_ENVIRONMENT_STRIPPING_RULES
                .iter()
                .map(|rule| (*rule).to_string())
                .collect(),
            cargo_config_paths_checked_absent: config_paths,
            cargo_credential_paths_checked_absent: credential_paths,
            policy_digest: ContentDigest::from_bytes(&[]),
        };
        policy.policy_digest = policy.expected_digest()?;
        Ok(policy)
    }

    fn expected_digest(&self) -> Result<ContentDigest, M7OperatorError> {
        digest_json(&BuildEnvironmentPolicyDigestMaterial {
            domain: BUILD_ENVIRONMENT_POLICY_DIGEST_DOMAIN,
            inheritance_policy: &self.inheritance_policy,
            fixed_environment: &self.fixed_environment,
            runtime_variable_names: &self.runtime_variable_names,
            rejection_rules: &self.rejection_rules,
            stripping_rules: &self.stripping_rules,
            cargo_config_paths_checked_absent: &self.cargo_config_paths_checked_absent,
            cargo_credential_paths_checked_absent: &self.cargo_credential_paths_checked_absent,
        })
    }

    fn process_environment(&self, target_directory: Option<&Path>) -> Vec<(OsString, OsString)> {
        let mut environment = self
            .fixed_environment
            .iter()
            .map(|entry| (OsString::from(&entry.name), OsString::from(&entry.value)))
            .collect::<Vec<_>>();
        if let Some(target_directory) = target_directory {
            environment.push((
                OsString::from(BUILD_RUNTIME_VARIABLE),
                target_directory.as_os_str().to_os_string(),
            ));
        }
        environment
    }
}

impl M7ToolchainRecordV1 {
    fn new(
        git: M7ToolchainCommandRecordV1,
        rustc: M7ToolchainCommandRecordV1,
        cargo: M7ToolchainCommandRecordV1,
        mut pin_files: Vec<M7ToolchainPinFileV1>,
        build_environment_policy: M7BuildEnvironmentPolicyV1,
    ) -> Result<Self, M7OperatorError> {
        pin_files.sort_by(|left, right| left.path.cmp(&right.path));
        if git.exit_code != 0 || rustc.exit_code != 0 || cargo.exit_code != 0 {
            return Err(M7OperatorError::InvalidInput(
                "toolchain commands must have successful exit codes".to_string(),
            ));
        }
        if git.stdout.is_empty() || rustc.stdout.is_empty() || cargo.stdout.is_empty() {
            return Err(M7OperatorError::InvalidInput(
                "toolchain command stdout cannot be empty".to_string(),
            ));
        }
        let recipe = M7SourceIdentityRecipeV1::default();
        if git.logical_program != "git"
            || rustc.logical_program != "rustc"
            || cargo.logical_program != "cargo"
            || git.command
                != [
                    git.executable.canonical_path.clone(),
                    "--version".to_string(),
                ]
            || rustc.command
                != [
                    rustc.executable.canonical_path.clone(),
                    "--version".to_string(),
                    "--verbose".to_string(),
                ]
            || cargo.command
                != [
                    cargo.executable.canonical_path.clone(),
                    "--version".to_string(),
                    "--verbose".to_string(),
                ]
            || recipe.rustc_command[1..] != rustc.command[1..]
            || recipe.cargo_command[1..] != cargo.command[1..]
        {
            return Err(M7OperatorError::InvalidInput(
                "toolchain record command vectors differ from the v2 recipe".to_string(),
            ));
        }
        for command in [&git, &rustc, &cargo] {
            if Path::new(&command.resolver.invocation_path).file_name()
                != Some(OsStr::new(&command.logical_program))
                || Path::new(&command.executable.canonical_path).file_name()
                    != Some(OsStr::new(&command.logical_program))
                || command.resolver != command.executable
                    && (command.resolver.invocation_symlink_target.is_none()
                        || Path::new(&command.resolver.canonical_path).file_name()
                            != Some(OsStr::new("rustup")))
            {
                return Err(M7OperatorError::InvalidInput(format!(
                    "{} resolver does not identify the exact canonical tool executable",
                    command.logical_program
                )));
            }
        }
        git.resolver.validate()?;
        git.executable.validate()?;
        rustc.resolver.validate()?;
        rustc.executable.validate()?;
        cargo.resolver.validate()?;
        cargo.executable.validate()?;
        build_environment_policy.validate(&rustc.executable.canonical_path)?;
        let mut pin_paths = BTreeSet::new();
        for pin in &pin_files {
            validate_relative_path(Path::new(&pin.path))?;
            if !pin_paths.insert(pin.path.clone()) {
                return Err(M7OperatorError::InvalidInput(format!(
                    "toolchain record repeats pin file '{}'",
                    pin.path
                )));
            }
            if pin.byte_length == 0 || pin.byte_length > MAX_TOOLCHAIN_PIN_BYTES as u64 {
                return Err(M7OperatorError::ResourceExhausted(format!(
                    "toolchain pin '{}' must contain 1..={MAX_TOOLCHAIN_PIN_BYTES} bytes",
                    pin.path
                )));
            }
        }
        let record_digest = digest_json(&ToolchainDigestMaterial {
            domain: TOOLCHAIN_RECORD_DIGEST_DOMAIN,
            git: &git,
            rustc: &rustc,
            cargo: &cargo,
            pin_files: &pin_files,
            build_environment_policy: &build_environment_policy,
        })?;
        Ok(Self {
            schema: M7_TOOLCHAIN_RECORD_SCHEMA.to_string(),
            git,
            rustc,
            cargo,
            pin_files,
            build_environment_policy,
            record_digest,
        })
    }

    fn validate(&self) -> Result<(), M7OperatorError> {
        if self.schema != M7_TOOLCHAIN_RECORD_SCHEMA {
            return Err(M7OperatorError::InvalidInput(
                "unsupported toolchain-record schema".to_string(),
            ));
        }
        let expected = Self::new(
            self.git.clone(),
            self.rustc.clone(),
            self.cargo.clone(),
            self.pin_files.clone(),
            self.build_environment_policy.clone(),
        )?;
        if &expected != self {
            return Err(M7OperatorError::InvalidInput(
                "toolchain record is not canonical or has a stale digest".to_string(),
            ));
        }
        Ok(())
    }

    fn verify_executables_current(&self) -> Result<(), M7OperatorError> {
        for command in [&self.git, &self.rustc, &self.cargo] {
            command.resolver.verify_current()?;
            command.executable.verify_current()?;
        }
        Ok(())
    }
}

impl M7SourceInspectionV1 {
    #[allow(clippy::too_many_arguments)]
    fn new(
        recipe: M7SourceIdentityRecipeV1,
        checkout_root: String,
        git_directory: String,
        git_common_directory: String,
        commit_oid: String,
        commit_object_digest: ContentDigest,
        tree_oid: String,
        tree_digest: ContentDigest,
        tracked_inventory: M7TrackedInventoryV1,
        cargo_lock_digest: ContentDigest,
        toolchain: M7ToolchainRecordV1,
    ) -> Result<Self, M7OperatorError> {
        let source_identity = M7SourceIdentity {
            commit_oid: commit_oid.clone(),
            commit_object_digest: commit_object_digest.clone(),
            tree_oid: tree_oid.clone(),
            tree_digest: tree_digest.clone(),
            checkout_root_digest: tracked_inventory.inventory_digest.clone(),
            toolchain_digest: toolchain.record_digest.clone(),
            lockfile_digest: cargo_lock_digest.clone(),
            root_provenance: M7SourceRootProvenanceV1::FreshCleanCheckout,
        };
        let mut inspection = Self {
            schema: M7_SOURCE_INSPECTION_SCHEMA.to_string(),
            recipe,
            checkout_root,
            git_directory,
            git_common_directory,
            detached_head: true,
            clean_before_inventory: true,
            clean_after_inventory: true,
            independent_git_directory: true,
            uses_object_alternates: false,
            commit_oid,
            commit_object_digest,
            tree_oid,
            tree_digest,
            tracked_inventory,
            cargo_lock_digest,
            toolchain,
            source_identity,
            inspection_digest: ContentDigest::from_bytes(&[]),
        };
        inspection.inspection_digest = inspection.expected_digest()?;
        inspection.validate()?;
        Ok(inspection)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, M7OperatorError> {
        self.validate()?;
        canonical_json_bytes(self)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, M7OperatorError> {
        if bytes.is_empty() || bytes.len() > MAX_SOURCE_INSPECTION_BYTES {
            return Err(M7OperatorError::ResourceExhausted(format!(
                "source inspection must contain 1..={MAX_SOURCE_INSPECTION_BYTES} bytes"
            )));
        }
        let inspection: Self = serde_json::from_slice(bytes)
            .map_err(|error| M7OperatorError::Serialization(error.to_string()))?;
        inspection.validate()?;
        if canonical_json_bytes(&inspection)? != bytes {
            return Err(M7OperatorError::InvalidInput(
                "source inspection is not canonical JSON".to_string(),
            ));
        }
        Ok(inspection)
    }

    fn validate(&self) -> Result<(), M7OperatorError> {
        if self.schema != M7_SOURCE_INSPECTION_SCHEMA
            || self.recipe != M7SourceIdentityRecipeV1::default()
            || self.checkout_root.trim().is_empty()
            || self.git_directory.trim().is_empty()
            || self.git_common_directory.trim().is_empty()
            || !self.detached_head
            || !self.clean_before_inventory
            || !self.clean_after_inventory
            || !self.independent_git_directory
            || self.uses_object_alternates
        {
            return Err(M7OperatorError::InvalidInput(
                "source inspection does not prove one detached, clean, independent checkout"
                    .to_string(),
            ));
        }
        let checkout_root = Path::new(&self.checkout_root);
        let git_directory = Path::new(&self.git_directory);
        let git_common_directory = Path::new(&self.git_common_directory);
        let expected_git_directory = checkout_root.join(".git");
        if !checkout_root.is_absolute()
            || !git_directory.is_absolute()
            || git_directory != git_common_directory
            || git_directory != expected_git_directory.as_path()
        {
            return Err(M7OperatorError::InvalidInput(
                "source inspection paths do not describe one canonical independent Git root"
                    .to_string(),
            ));
        }
        validate_git_oid(&self.commit_oid, "commit")?;
        validate_git_oid(&self.tree_oid, "tree")?;
        self.tracked_inventory.validate()?;
        self.toolchain.validate()?;
        let cargo_lock = self
            .tracked_inventory
            .entries
            .iter()
            .find(|entry| entry.path == "Cargo.lock")
            .ok_or_else(|| {
                M7OperatorError::InvalidInput(
                    "source inspection has no tracked Cargo.lock".to_string(),
                )
            })?;
        if cargo_lock.content_digest != self.cargo_lock_digest {
            return Err(M7OperatorError::InvalidInput(
                "Cargo.lock digest differs from the tracked inventory".to_string(),
            ));
        }
        let expected_identity = M7SourceIdentity {
            commit_oid: self.commit_oid.clone(),
            commit_object_digest: self.commit_object_digest.clone(),
            tree_oid: self.tree_oid.clone(),
            tree_digest: self.tree_digest.clone(),
            checkout_root_digest: self.tracked_inventory.inventory_digest.clone(),
            toolchain_digest: self.toolchain.record_digest.clone(),
            lockfile_digest: self.cargo_lock_digest.clone(),
            root_provenance: M7SourceRootProvenanceV1::FreshCleanCheckout,
        };
        if self.source_identity != expected_identity
            || self.inspection_digest != self.expected_digest()?
        {
            return Err(M7OperatorError::InvalidInput(
                "source identity or inspection digest is stale".to_string(),
            ));
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, M7OperatorError> {
        digest_json(&SourceInspectionDigestMaterial {
            domain: SOURCE_INSPECTION_DIGEST_DOMAIN,
            recipe: &self.recipe,
            checkout_root: &self.checkout_root,
            git_directory: &self.git_directory,
            git_common_directory: &self.git_common_directory,
            detached_head: self.detached_head,
            clean_before_inventory: self.clean_before_inventory,
            clean_after_inventory: self.clean_after_inventory,
            independent_git_directory: self.independent_git_directory,
            uses_object_alternates: self.uses_object_alternates,
            commit_oid: &self.commit_oid,
            commit_object_digest: &self.commit_object_digest,
            tree_oid: &self.tree_oid,
            tree_digest: &self.tree_digest,
            tracked_inventory: &self.tracked_inventory,
            cargo_lock_digest: &self.cargo_lock_digest,
            toolchain: &self.toolchain,
            source_identity: &self.source_identity,
        })
    }
}

struct ProcessCapture {
    status: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProcessOutputLimits {
    stdout: usize,
    stderr: usize,
    combined: Option<usize>,
}

impl ProcessOutputLimits {
    const fn separate(stdout: usize, stderr: usize) -> Self {
        Self {
            stdout,
            stderr,
            combined: None,
        }
    }

    const fn with_combined(stdout: usize, stderr: usize, combined: usize) -> Self {
        Self {
            stdout,
            stderr,
            combined: Some(combined),
        }
    }

    const fn stream_limit(self, stream: M7ProcessOutputStream) -> usize {
        match stream {
            M7ProcessOutputStream::Stdout => self.stdout,
            M7ProcessOutputStream::Stderr => self.stderr,
        }
    }
}

#[derive(Debug, Default)]
struct CombinedOutputState {
    observed: usize,
    exceeded: bool,
}

#[derive(Debug)]
struct CombinedOutputBudget {
    limit: Option<usize>,
    state: Mutex<CombinedOutputState>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CombinedOutputObservation {
    observed_before: usize,
    observed: usize,
    first_exceeded: bool,
}

impl CombinedOutputBudget {
    fn new(limit: Option<usize>) -> Self {
        Self {
            limit,
            state: Mutex::new(CombinedOutputState::default()),
        }
    }

    fn observe(&self, count: usize) -> Result<CombinedOutputObservation, M7OperatorError> {
        let mut state = self.state.lock().map_err(|_| {
            M7OperatorError::InvalidInput("subprocess output budget lock was poisoned".to_string())
        })?;
        let observed_before = state.observed;
        state.observed = state.observed.checked_add(count).ok_or_else(|| {
            M7OperatorError::ResourceExhausted(
                "combined subprocess output length overflowed".to_string(),
            )
        })?;
        let first_exceeded = self
            .limit
            .is_some_and(|limit| state.observed > limit && !state.exceeded);
        if first_exceeded {
            state.exceeded = true;
        }
        Ok(CombinedOutputObservation {
            observed_before,
            observed: state.observed,
            first_exceeded,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProcessOutputLimitEvent {
    stream: M7ProcessOutputStream,
    kind: M7ProcessOutputLimitKind,
    stream_observed_at_least: usize,
    stream_limit: usize,
    combined_observed_at_least: usize,
    combined_limit: Option<usize>,
}

impl ProcessOutputLimitEvent {
    fn into_error(
        self,
        program: &str,
        observed_libtest_failures: Option<M7ObservedLibtestFailureDiagnostic>,
    ) -> M7OperatorError {
        M7OperatorError::ProcessOutputLimitExceeded {
            program: PathBuf::from(program),
            stream: self.stream,
            kind: self.kind,
            stream_observed_at_least: self.stream_observed_at_least,
            stream_limit: self.stream_limit,
            combined_observed_at_least: self.combined_observed_at_least,
            combined_limit: self.combined_limit,
            observed_libtest_failures,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProcessOutputDiagnosticPolicy {
    OmitAll,
    CargoLibtestFailureNames,
}

fn is_safe_libtest_failure_name(name: &[u8]) -> bool {
    if name.is_empty()
        || name.len() > MAX_LIBTEST_FAILURE_DIAGNOSTIC_NAME_BYTES
        || !name.is_ascii()
        || contains_secret_shaped_material(name)
    {
        return false;
    }
    let Ok(name) = std::str::from_utf8(name) else {
        return false;
    };
    let mut components = 0_usize;
    for component in name.split("::") {
        components += 1;
        if components > MAX_LIBTEST_FAILURE_DIAGNOSTIC_COMPONENTS || component.is_empty() {
            return false;
        }
        let mut bytes = component.bytes();
        let Some(first) = bytes.next() else {
            return false;
        };
        if !(first.is_ascii_alphabetic() || first == b'_')
            || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return false;
        }
    }
    true
}

fn observed_libtest_failure_diagnostic(
    retained_stdout: &[u8],
) -> Option<M7ObservedLibtestFailureDiagnostic> {
    const PREFIX: &[u8] = b"test ";
    const SUFFIX: &[u8] = b" ... FAILED";

    let mut observed_failed_test_names = Vec::new();
    let mut name_limit_reached = false;
    for raw_line in retained_stdout.split_inclusive(|byte| *byte == b'\n') {
        if raw_line.last() != Some(&b'\n') {
            continue;
        }
        let line = &raw_line[..raw_line.len() - 1];
        let Some(name) = line
            .strip_prefix(PREFIX)
            .and_then(|line| line.strip_suffix(SUFFIX))
        else {
            continue;
        };
        if !is_safe_libtest_failure_name(name) {
            continue;
        }
        let name = std::str::from_utf8(name).expect("safe libtest names are ASCII");
        if observed_failed_test_names
            .iter()
            .any(|existing| existing == name)
        {
            continue;
        }
        if observed_failed_test_names.len() == MAX_LIBTEST_FAILURE_DIAGNOSTIC_NAMES {
            name_limit_reached = true;
            continue;
        }
        observed_failed_test_names.push(name.to_string());
    }
    if observed_failed_test_names.is_empty() && !name_limit_reached {
        None
    } else {
        Some(M7ObservedLibtestFailureDiagnostic {
            observed_failed_test_names,
            name_limit_reached,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProcessReaderEvent {
    OutputLimit(ProcessOutputLimitEvent),
    ReadFailed(M7ProcessOutputStream),
    Finished(M7ProcessOutputStream),
}

fn drain_bounded<R: Read>(
    mut reader: R,
    stream: M7ProcessOutputStream,
    limits: ProcessOutputLimits,
    combined_budget: &CombinedOutputBudget,
    events: mpsc::Sender<ProcessReaderEvent>,
) -> Result<Vec<u8>, M7OperatorError> {
    let stream_limit = limits.stream_limit(stream);
    let mut retained = Vec::new();
    let mut total = 0_usize;
    let mut stream_limit_reported = false;
    let mut chunk = [0_u8; 16 * 1024];
    loop {
        let count = match reader.read(&mut chunk) {
            Ok(count) => count,
            Err(error) => {
                let _ = events.send(ProcessReaderEvent::ReadFailed(stream));
                return Err(M7OperatorError::InvalidInput(format!(
                    "subprocess {stream} pipe failed: {error}"
                )));
            }
        };
        if count == 0 {
            break;
        }
        total = total.checked_add(count).ok_or_else(|| {
            let _ = events.send(ProcessReaderEvent::ReadFailed(stream));
            M7OperatorError::ResourceExhausted(format!(
                "subprocess {stream} output length overflowed"
            ))
        })?;
        let combined = match combined_budget.observe(count) {
            Ok(observation) => observation,
            Err(error) => {
                let _ = events.send(ProcessReaderEvent::ReadFailed(stream));
                return Err(error);
            }
        };
        let stream_exceeded = total > stream_limit && !stream_limit_reported;
        if stream_exceeded || combined.first_exceeded {
            let kind = match (stream_exceeded, combined.first_exceeded) {
                (true, true) => M7ProcessOutputLimitKind::StreamAndCombined,
                (true, false) => M7ProcessOutputLimitKind::Stream,
                (false, true) => M7ProcessOutputLimitKind::Combined,
                (false, false) => unreachable!(),
            };
            let _ = events.send(ProcessReaderEvent::OutputLimit(ProcessOutputLimitEvent {
                stream,
                kind,
                stream_observed_at_least: total,
                stream_limit,
                combined_observed_at_least: combined.observed,
                combined_limit: limits.combined,
            }));
            stream_limit_reported |= stream_exceeded;
        }
        if retained.len() < stream_limit {
            let combined_allowance = limits.combined.map_or(count, |limit| {
                limit.saturating_sub(combined.observed_before).min(count)
            });
            let keep = count
                .min(stream_limit - retained.len())
                .min(combined_allowance);
            retained.extend_from_slice(&chunk[..keep]);
        }
    }
    let _ = events.send(ProcessReaderEvent::Finished(stream));
    Ok(retained)
}

#[cfg(unix)]
type ProcessGroupId = rustix::process::Pid;
#[cfg(not(unix))]
type ProcessGroupId = ();

fn terminate_process_group(
    child: &mut Child,
    process_group: &ProcessGroupId,
) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        match rustix::process::kill_process_group(*process_group, rustix::process::Signal::KILL) {
            Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
            Err(error) => {
                let _ = child.kill();
                Err(std::io::Error::other(format!(
                    "cannot kill subprocess process group: {error}"
                )))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = process_group;
        match child.kill() {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => Ok(()),
            Err(error) => Err(error),
        }
    }
}

fn terminate_and_reap(
    child: &mut Child,
    process_group: &ProcessGroupId,
) -> std::io::Result<ExitStatus> {
    let termination_error = terminate_process_group(child, process_group).err();
    let status = child.wait()?;
    if let Some(error) = termination_error {
        return Err(error);
    }
    Ok(status)
}

fn record_process_reader_event(
    event: ProcessReaderEvent,
    output_limit: &mut Option<ProcessOutputLimitEvent>,
    reader_failed: &mut Option<M7ProcessOutputStream>,
    stdout_finished: &mut bool,
    stderr_finished: &mut bool,
) {
    match event {
        ProcessReaderEvent::OutputLimit(event) => {
            if output_limit.is_none() {
                *output_limit = Some(event);
            }
        }
        ProcessReaderEvent::ReadFailed(stream) => {
            if reader_failed.is_none() {
                *reader_failed = Some(stream);
            }
        }
        ProcessReaderEvent::Finished(M7ProcessOutputStream::Stdout) => *stdout_finished = true,
        ProcessReaderEvent::Finished(M7ProcessOutputStream::Stderr) => *stderr_finished = true,
    }
}

fn run_process(
    program: &str,
    args: &[String],
    cwd: &Path,
    stdin_bytes: Option<&[u8]>,
    output_limits: ProcessOutputLimits,
    timeout: Duration,
    clear_environment: bool,
    clear_git_overrides: bool,
    clear_credential_environment: bool,
    output_diagnostic_policy: ProcessOutputDiagnosticPolicy,
    environment: &[(OsString, OsString)],
) -> Result<ProcessCapture, M7OperatorError> {
    let mut command = Command::new(program);
    command
        .args(args)
        .current_dir(cwd)
        .stdin(if stdin_bytes.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if clear_environment {
        command.env_clear();
    }
    if clear_git_overrides {
        for name in [
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_COMMON_DIR",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_INDEX_FILE",
        ] {
            command.env_remove(name);
        }
        command.env("GIT_NO_REPLACE_OBJECTS", "1");
    }
    if clear_credential_environment {
        for (name, _) in std::env::vars_os() {
            let normalized = name.to_string_lossy().to_ascii_uppercase();
            if normalized.contains("API_KEY")
                || normalized.contains("TOKEN")
                || normalized.contains("SECRET")
                || normalized.contains("PASSWORD")
                || normalized.contains("PASSWD")
                || normalized.contains("PRIVATE_KEY")
                || normalized.contains("ACCESS_KEY")
                || normalized.contains("CREDENTIAL")
                || normalized.contains("AUTH")
                || normalized.contains("COOKIE")
                || normalized == "SSH_AUTH_SOCK"
                || normalized == "DATABASE_URL"
                || normalized == "REDIS_URL"
                || normalized == "HTTP_PROXY"
                || normalized == "HTTPS_PROXY"
                || normalized == "ALL_PROXY"
            {
                command.env_remove(name);
            }
        }
    }
    for (name, value) in environment {
        command.env(name, value);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command.spawn().map_err(|error| {
        M7OperatorError::io(
            cwd,
            std::io::Error::new(error.kind(), format!("cannot start {program}: {error}")),
        )
    })?;
    #[cfg(unix)]
    let process_group = rustix::process::Pid::from_child(&child);
    #[cfg(not(unix))]
    let process_group = ();
    let stdout = child.stdout.take().ok_or_else(|| {
        M7OperatorError::InvalidInput("subprocess stdout pipe was not created".to_string())
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        M7OperatorError::InvalidInput("subprocess stderr pipe was not created".to_string())
    })?;
    let command_vector = std::iter::once(program.to_string())
        .chain(args.iter().cloned())
        .collect::<Vec<_>>();
    let started = Instant::now();
    let combined_budget = CombinedOutputBudget::new(output_limits.combined);
    let (event_sender, event_receiver) = mpsc::channel();
    thread::scope(|scope| {
        let stdout_events = event_sender.clone();
        let stdout_budget = &combined_budget;
        let stdout_reader = scope.spawn(move || {
            drain_bounded(
                stdout,
                M7ProcessOutputStream::Stdout,
                output_limits,
                stdout_budget,
                stdout_events,
            )
        });
        let stderr_events = event_sender.clone();
        let stderr_budget = &combined_budget;
        let stderr_reader = scope.spawn(move || {
            drain_bounded(
                stderr,
                M7ProcessOutputStream::Stderr,
                output_limits,
                stderr_budget,
                stderr_events,
            )
        });
        drop(event_sender);
        let stdin_writer = if let Some(input) = stdin_bytes {
            let mut stdin = child.stdin.take().ok_or_else(|| {
                M7OperatorError::InvalidInput("subprocess stdin pipe was not created".to_string())
            })?;
            Some(scope.spawn(move || stdin.write_all(input)))
        } else {
            None
        };

        let mut timed_out = false;
        let mut wait_error = None;
        let mut output_limit = None;
        let mut reader_failed = None;
        let mut stdout_finished = false;
        let mut stderr_finished = false;
        let status = loop {
            while let Ok(event) = event_receiver.try_recv() {
                record_process_reader_event(
                    event,
                    &mut output_limit,
                    &mut reader_failed,
                    &mut stdout_finished,
                    &mut stderr_finished,
                );
            }
            if output_limit.is_some() || reader_failed.is_some() {
                match terminate_and_reap(&mut child, &process_group) {
                    Ok(status) => break Some(status),
                    Err(error) => {
                        wait_error = Some(error);
                        break None;
                    }
                }
            }
            match child.try_wait() {
                Ok(Some(status)) => {
                    while let Ok(event) = event_receiver.try_recv() {
                        record_process_reader_event(
                            event,
                            &mut output_limit,
                            &mut reader_failed,
                            &mut stdout_finished,
                            &mut stderr_finished,
                        );
                    }
                    if !stdout_finished || !stderr_finished {
                        if let Err(error) = terminate_process_group(&mut child, &process_group) {
                            wait_error = Some(error);
                        }
                    }
                    break Some(status);
                }
                Ok(None) => {}
                Err(error) => {
                    wait_error = Some(error);
                    break terminate_and_reap(&mut child, &process_group).ok();
                }
            }
            let elapsed = started.elapsed();
            if elapsed >= timeout {
                timed_out = true;
                match terminate_and_reap(&mut child, &process_group) {
                    Ok(status) => break Some(status),
                    Err(error) => {
                        wait_error = Some(error);
                        break None;
                    }
                }
            }
            thread::sleep(PROCESS_POLL_INTERVAL.min(timeout.saturating_sub(elapsed)));
        };

        let stdin_result = stdin_writer.map(|writer| writer.join());
        let stdout_result = stdout_reader.join();
        let stderr_result = stderr_reader.join();

        while let Ok(event) = event_receiver.try_recv() {
            record_process_reader_event(
                event,
                &mut output_limit,
                &mut reader_failed,
                &mut stdout_finished,
                &mut stderr_finished,
            );
        }

        if let Some(event) = output_limit {
            let observed_libtest_failures = match output_diagnostic_policy {
                ProcessOutputDiagnosticPolicy::OmitAll => None,
                ProcessOutputDiagnosticPolicy::CargoLibtestFailureNames => stdout_result
                    .as_ref()
                    .ok()
                    .and_then(|result| result.as_ref().ok())
                    .and_then(|stdout| observed_libtest_failure_diagnostic(stdout)),
            };
            return Err(event.into_error(program, observed_libtest_failures));
        }
        if timed_out {
            return Err(M7OperatorError::ProcessTimeout {
                command: command_vector,
                timeout,
            });
        }
        if let Some(error) = wait_error {
            return Err(M7OperatorError::io(cwd, error));
        }
        if let Some(result) = stdin_result {
            result
                .map_err(|_| {
                    M7OperatorError::InvalidInput("subprocess stdin writer panicked".to_string())
                })?
                .map_err(|error| M7OperatorError::io(cwd, error))?;
        }
        let stdout = stdout_result.map_err(|_| {
            M7OperatorError::InvalidInput("subprocess stdout reader panicked".to_string())
        })??;
        let stderr = stderr_result.map_err(|_| {
            M7OperatorError::InvalidInput("subprocess stderr reader panicked".to_string())
        })??;
        let status = status.ok_or_else(|| {
            M7OperatorError::InvalidInput("subprocess ended without a wait status".to_string())
        })?;
        Ok(ProcessCapture {
            status: status.code(),
            stdout,
            stderr,
        })
    })
}

fn run_git(
    cwd: &Path,
    git: &M7ExecutableIdentityV1,
    args: &[&str],
    stdin_bytes: Option<&[u8]>,
    stdout_limit: usize,
) -> Result<ProcessCapture, M7OperatorError> {
    git.verify_current()?;
    let environment = [
        ("GIT_CONFIG_GLOBAL", "/dev/null"),
        ("GIT_CONFIG_NOSYSTEM", "1"),
        ("GIT_NO_REPLACE_OBJECTS", "1"),
        ("GIT_OPTIONAL_LOCKS", "0"),
        ("GIT_TERMINAL_PROMPT", "0"),
        ("LANG", "C"),
        ("LC_ALL", "C"),
        ("PATH", CANONICAL_BUILD_PATH),
        ("TZ", "UTC"),
    ]
    .into_iter()
    .map(|(name, value)| (OsString::from(name), OsString::from(value)))
    .collect::<Vec<_>>();
    let capture = run_process(
        &git.canonical_path,
        &args
            .iter()
            .map(|value| (*value).to_string())
            .collect::<Vec<_>>(),
        cwd,
        stdin_bytes,
        ProcessOutputLimits::separate(stdout_limit, MAX_PROCESS_DIAGNOSTIC_BYTES),
        GIT_PROCESS_TIMEOUT,
        true,
        false,
        false,
        ProcessOutputDiagnosticPolicy::OmitAll,
        &environment,
    )?;
    git.verify_current()?;
    Ok(capture)
}

fn require_process_success(
    program: &str,
    args: &[&str],
    capture: ProcessCapture,
) -> Result<ProcessCapture, M7OperatorError> {
    if capture.status != Some(0) {
        return Err(M7OperatorError::Process {
            command: std::iter::once(program.to_string())
                .chain(args.iter().map(|value| (*value).to_string()))
                .collect(),
            status: capture.status,
            stderr: String::from_utf8_lossy(&capture.stderr).into_owned(),
        });
    }
    Ok(capture)
}

fn one_line_utf8(bytes: &[u8], label: &str) -> Result<String, M7OperatorError> {
    let value = std::str::from_utf8(bytes)
        .map_err(|error| M7OperatorError::InvalidInput(format!("{label} is not UTF-8: {error}")))?;
    let value = value.trim_end_matches(|character| character == '\r' || character == '\n');
    if value.is_empty()
        || value
            .chars()
            .any(|character| character == '\r' || character == '\n')
    {
        return Err(M7OperatorError::InvalidInput(format!(
            "{label} must contain exactly one nonempty line"
        )));
    }
    Ok(value.to_string())
}

fn validate_git_oid(value: &str, label: &str) -> Result<(), M7OperatorError> {
    if !matches!(value.len(), 40 | 64)
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(M7OperatorError::InvalidInput(format!(
            "{label} OID must be 40 or 64 lowercase hexadecimal characters"
        )));
    }
    Ok(())
}

fn validate_relative_path(path: &Path) -> Result<(), M7OperatorError> {
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(M7OperatorError::UnsafePath(path.to_path_buf()));
    }
    Ok(())
}

fn safe_tracked_path(
    root: &Path,
    relative: &Path,
    symlink_leaf: bool,
) -> Result<PathBuf, M7OperatorError> {
    validate_relative_path(relative)?;
    let mut current = root.to_path_buf();
    let component_count = relative.components().count();
    for (index, component) in relative.components().enumerate() {
        let Component::Normal(name) = component else {
            return Err(M7OperatorError::UnsafePath(relative.to_path_buf()));
        };
        current.push(name);
        let metadata =
            fs::symlink_metadata(&current).map_err(|error| M7OperatorError::io(&current, error))?;
        let is_leaf = index + 1 == component_count;
        if metadata.file_type().is_symlink() && !(is_leaf && symlink_leaf) {
            return Err(M7OperatorError::UnsafePath(current));
        }
        if !is_leaf && !metadata.is_dir() {
            return Err(M7OperatorError::UnsafePath(current));
        }
    }
    Ok(current)
}

fn resolve_git_directory(root: &Path, value: &str) -> Result<PathBuf, M7OperatorError> {
    let candidate = Path::new(value);
    let candidate = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        root.join(candidate)
    };
    fs::canonicalize(&candidate).map_err(|error| M7OperatorError::io(&candidate, error))
}

fn parse_ls_tree(bytes: &[u8]) -> Result<Vec<(String, String, String)>, M7OperatorError> {
    let mut records = Vec::new();
    for raw in bytes
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        let tab = raw.iter().position(|byte| *byte == b'\t').ok_or_else(|| {
            M7OperatorError::InvalidInput("git ls-tree record has no path separator".to_string())
        })?;
        let header = std::str::from_utf8(&raw[..tab]).map_err(|error| {
            M7OperatorError::InvalidInput(format!("git ls-tree header is not UTF-8: {error}"))
        })?;
        let path = std::str::from_utf8(&raw[tab + 1..]).map_err(|error| {
            M7OperatorError::InvalidInput(format!("tracked path is not UTF-8: {error}"))
        })?;
        let fields = header.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.len() != 3 {
            return Err(M7OperatorError::InvalidInput(
                "git ls-tree record has an unexpected header".to_string(),
            ));
        }
        let mode = fields[0];
        let object_kind = fields[1];
        let oid = fields[2];
        if object_kind != "blob" {
            return Err(M7OperatorError::InvalidInput(format!(
                "tracked entry '{path}' has unsupported Git object kind '{object_kind}'"
            )));
        }
        validate_git_oid(oid, "tracked blob")?;
        validate_relative_path(Path::new(path))?;
        records.push((mode.to_string(), oid.to_string(), path.to_string()));
    }
    if records.is_empty() || records.len() > MAX_TRACKED_FILES {
        return Err(M7OperatorError::ResourceExhausted(format!(
            "Git tree must contain 1..={MAX_TRACKED_FILES} tracked blobs"
        )));
    }
    Ok(records)
}

#[cfg(unix)]
fn symlink_target_bytes(path: &Path) -> Result<Vec<u8>, M7OperatorError> {
    use std::os::unix::ffi::OsStrExt;
    let target = fs::read_link(path).map_err(|error| M7OperatorError::io(path, error))?;
    Ok(target.as_os_str().as_bytes().to_vec())
}

#[cfg(not(unix))]
fn symlink_target_bytes(path: &Path) -> Result<Vec<u8>, M7OperatorError> {
    let target = fs::read_link(path).map_err(|error| M7OperatorError::io(path, error))?;
    let value = target
        .to_str()
        .ok_or_else(|| M7OperatorError::UnsafePath(path.to_path_buf()))?;
    Ok(value.as_bytes().to_vec())
}

fn build_tracked_inventory(
    root: &Path,
    git: &M7ExecutableIdentityV1,
    tree_oid: &str,
) -> Result<M7TrackedInventoryV1, M7OperatorError> {
    let listing = require_process_success(
        "git",
        &["ls-tree", "-r", "-z", "--full-tree", tree_oid],
        run_git(
            root,
            git,
            &["ls-tree", "-r", "-z", "--full-tree", tree_oid],
            None,
            MAX_GIT_OUTPUT_BYTES,
        )?,
    )?;
    let records = parse_ls_tree(&listing.stdout)?;
    let mut entries = Vec::with_capacity(records.len());
    let mut total = 0_usize;
    for (mode, expected_oid, relative) in records {
        let is_symlink = mode == "120000";
        if !matches!(mode.as_str(), "100644" | "100755" | "120000") {
            return Err(M7OperatorError::InvalidInput(format!(
                "tracked entry '{relative}' has unsupported mode '{mode}'"
            )));
        }
        let path = safe_tracked_path(root, Path::new(&relative), is_symlink)?;
        let bytes = if is_symlink {
            symlink_target_bytes(&path)?
        } else {
            read_regular_bounded(&path, MAX_TRACKED_FILE_BYTES)?
        };
        total = total.checked_add(bytes.len()).ok_or_else(|| {
            M7OperatorError::ResourceExhausted("tracked source byte total overflowed".to_string())
        })?;
        if total > MAX_TRACKED_TOTAL_BYTES {
            return Err(M7OperatorError::ResourceExhausted(format!(
                "tracked source bytes exceed {MAX_TRACKED_TOTAL_BYTES}"
            )));
        }
        let hashed = require_process_success(
            "git",
            &["hash-object", "--stdin"],
            run_git(root, git, &["hash-object", "--stdin"], Some(&bytes), 1_024)?,
        )?;
        let actual_oid = one_line_utf8(&hashed.stdout, "git hash-object output")?;
        if actual_oid != expected_oid {
            return Err(M7OperatorError::InvalidInput(format!(
                "tracked worktree bytes for '{relative}' differ from tree blob {expected_oid}"
            )));
        }
        entries.push(M7TrackedSourceEntryV1 {
            path: relative,
            mode,
            blob_oid: expected_oid,
            byte_length: bytes.len() as u64,
            content_digest: ContentDigest::from_bytes(&bytes),
        });
    }
    M7TrackedInventoryV1::new(entries)
}

fn executable_identity_from_invocation(
    invocation: &Path,
) -> Result<M7ExecutableIdentityV1, M7OperatorError> {
    if !invocation.is_absolute() {
        return Err(M7OperatorError::UnsafePath(invocation.to_path_buf()));
    }
    let parent = invocation
        .parent()
        .ok_or_else(|| M7OperatorError::UnsafePath(invocation.to_path_buf()))?;
    let canonical_parent =
        fs::canonicalize(parent).map_err(|error| M7OperatorError::io(parent, error))?;
    if canonical_parent != parent {
        return Err(M7OperatorError::UnsafePath(invocation.to_path_buf()));
    }
    let metadata =
        fs::symlink_metadata(invocation).map_err(|error| M7OperatorError::io(invocation, error))?;
    let (canonical, invocation_symlink_target) = if metadata.file_type().is_symlink() {
        let target =
            fs::read_link(invocation).map_err(|error| M7OperatorError::io(invocation, error))?;
        let target_text = target
            .to_str()
            .ok_or_else(|| M7OperatorError::UnsafePath(invocation.to_path_buf()))?
            .to_string();
        let resolved = if target.is_absolute() {
            target
        } else {
            parent.join(target)
        };
        let direct_metadata = fs::symlink_metadata(&resolved)
            .map_err(|error| M7OperatorError::io(&resolved, error))?;
        if direct_metadata.file_type().is_symlink() || !direct_metadata.is_file() {
            return Err(M7OperatorError::UnsafePath(invocation.to_path_buf()));
        }
        (
            fs::canonicalize(&resolved).map_err(|error| M7OperatorError::io(&resolved, error))?,
            Some(target_text),
        )
    } else if metadata.is_file() {
        let canonical =
            fs::canonicalize(invocation).map_err(|error| M7OperatorError::io(invocation, error))?;
        if canonical != invocation {
            return Err(M7OperatorError::UnsafePath(invocation.to_path_buf()));
        }
        (canonical, None)
    } else {
        return Err(M7OperatorError::UnsafePath(invocation.to_path_buf()));
    };
    let canonical_metadata =
        fs::symlink_metadata(&canonical).map_err(|error| M7OperatorError::io(&canonical, error))?;
    if !canonical_metadata.is_file() || canonical_metadata.file_type().is_symlink() {
        return Err(M7OperatorError::UnsafePath(invocation.to_path_buf()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if canonical_metadata.permissions().mode() & 0o111 == 0 {
            return Err(M7OperatorError::InvalidInput(format!(
                "tool path '{}' is not executable",
                canonical.display()
            )));
        }
    }
    let bytes = read_regular_bounded(&canonical, MAX_TOOL_EXECUTABLE_BYTES)?;
    if bytes.is_empty() {
        return Err(M7OperatorError::InvalidInput(format!(
            "tool executable '{}' is empty",
            canonical.display()
        )));
    }
    let identity = M7ExecutableIdentityV1 {
        invocation_path: invocation
            .to_str()
            .ok_or_else(|| M7OperatorError::UnsafePath(invocation.to_path_buf()))?
            .to_string(),
        canonical_path: canonical
            .to_str()
            .ok_or_else(|| M7OperatorError::UnsafePath(canonical.clone()))?
            .to_string(),
        invocation_symlink_target,
        byte_length: bytes.len() as u64,
        content_digest: ContentDigest::from_bytes(&bytes),
    };
    identity.validate()?;
    Ok(identity)
}

fn resolve_unambiguous_path_tool(
    program: &str,
    path_value: &OsStr,
) -> Result<M7ExecutableIdentityV1, M7OperatorError> {
    if program.is_empty() || program.contains('/') || program.contains('\\') {
        return Err(M7OperatorError::InvalidInput(
            "tool program name must be one path-free component".to_string(),
        ));
    }
    let mut seen_directories = BTreeSet::new();
    let mut candidates = Vec::new();
    for directory in std::env::split_paths(path_value) {
        if !directory.is_absolute() || !seen_directories.insert(directory.clone()) {
            return Err(M7OperatorError::InvalidInput(format!(
                "PATH contains a relative, empty, or repeated directory while resolving {program}"
            )));
        }
        let metadata = fs::symlink_metadata(&directory)
            .map_err(|error| M7OperatorError::io(&directory, error))?;
        let canonical =
            fs::canonicalize(&directory).map_err(|error| M7OperatorError::io(&directory, error))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() || canonical != directory {
            return Err(M7OperatorError::UnsafePath(directory));
        }
        let candidate = canonical.join(program);
        match fs::symlink_metadata(&candidate) {
            Ok(metadata) => {
                if !metadata.is_file() && !metadata.file_type().is_symlink() {
                    return Err(M7OperatorError::UnsafePath(candidate));
                }
                candidates.push(executable_identity_from_invocation(&candidate)?);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(M7OperatorError::io(&candidate, error)),
        }
    }
    if candidates.len() != 1 {
        return Err(M7OperatorError::InvalidInput(format!(
            "PATH must resolve {program} to exactly one executable; found {}",
            candidates.len()
        )));
    }
    Ok(candidates.remove(0))
}

fn canonical_environment_directory(
    variable: &str,
    default_leaf: &str,
) -> Result<PathBuf, M7OperatorError> {
    let path = if let Some(value) = std::env::var_os(variable) {
        PathBuf::from(value)
    } else {
        let home = std::env::var_os("HOME").ok_or_else(|| {
            M7OperatorError::InvalidInput(format!("{variable} is unset and HOME is unavailable"))
        })?;
        PathBuf::from(home).join(default_leaf)
    };
    if !path.is_absolute() {
        return Err(M7OperatorError::UnsafePath(path));
    }
    let metadata =
        fs::symlink_metadata(&path).map_err(|error| M7OperatorError::io(&path, error))?;
    let canonical = fs::canonicalize(&path).map_err(|error| M7OperatorError::io(&path, error))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || canonical != path {
        return Err(M7OperatorError::UnsafePath(path));
    }
    Ok(canonical)
}

fn environment_name_is_rejected_for_build(name: &str) -> bool {
    let name = name.to_ascii_uppercase();
    matches!(
        name.as_str(),
        "RUSTC_WRAPPER"
            | "RUSTC_WORKSPACE_WRAPPER"
            | "RUSTFLAGS"
            | "RUSTDOCFLAGS"
            | "CARGO_ENCODED_RUSTFLAGS"
            | "CARGO_ENCODED_RUSTDOCFLAGS"
            | "MACOSX_DEPLOYMENT_TARGET"
            | "SDKROOT"
            | "CC"
            | "CXX"
            | "AR"
            | "RANLIB"
            | "LD"
            | "CFLAGS"
            | "CXXFLAGS"
            | "CPPFLAGS"
            | "LDFLAGS"
            | "MAKEFLAGS"
    ) || name.starts_with("CARGO_BUILD_")
        || name.starts_with("CARGO_PROFILE_")
        || name.starts_with("CARGO_REGISTRY_")
        || name.starts_with("CARGO_REGISTRIES_")
        || name.starts_with("CARGO_HTTP_")
        || name.starts_with("CARGO_NET_")
        || name.starts_with("CARGO_TARGET_") && name != "CARGO_TARGET_DIR"
        || name.starts_with("CC_")
        || name.starts_with("CXX_")
        || name.starts_with("AR_")
        || name.starts_with("RANLIB_")
        || name.starts_with("PKG_CONFIG")
}

fn validate_inherited_build_environment<I>(names: I) -> Result<(), M7OperatorError>
where
    I: IntoIterator<Item = OsString>,
{
    for name in names {
        let name = name.into_string().map_err(|_| {
            M7OperatorError::InvalidInput(
                "inherited environment contains a non-UTF-8 variable name".to_string(),
            )
        })?;
        if environment_name_is_rejected_for_build(&name) {
            return Err(M7OperatorError::InvalidInput(format!(
                "inherited build-affecting environment variable {name} is forbidden"
            )));
        }
    }
    Ok(())
}

fn require_absent_path(path: &Path, label: &str) -> Result<String, M7OperatorError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(M7OperatorError::InvalidInput(format!(
            "{label} '{}' is forbidden for an authoritative proof run",
            path.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => path
            .to_str()
            .map(str::to_string)
            .ok_or_else(|| M7OperatorError::UnsafePath(path.to_path_buf())),
        Err(error) => Err(M7OperatorError::io(path, error)),
    }
}

fn inspect_cargo_configuration_absence(
    root: &Path,
    cargo_home: &Path,
) -> Result<(Vec<String>, Vec<String>), M7OperatorError> {
    let mut config_paths = Vec::new();
    for ancestor in root.ancestors() {
        let cargo_directory = ancestor.join(".cargo");
        match fs::symlink_metadata(&cargo_directory) {
            Ok(metadata) => {
                if !metadata.is_dir() || metadata.file_type().is_symlink() {
                    return Err(M7OperatorError::UnsafePath(cargo_directory));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(M7OperatorError::io(&cargo_directory, error)),
        }
        for name in ["config", "config.toml"] {
            config_paths.push(require_absent_path(
                &cargo_directory.join(name),
                "Cargo configuration file",
            )?);
        }
    }
    for name in ["config", "config.toml"] {
        config_paths.push(require_absent_path(
            &cargo_home.join(name),
            "Cargo home configuration file",
        )?);
    }
    let mut credential_paths = Vec::new();
    for name in ["credentials", "credentials.toml"] {
        credential_paths.push(require_absent_path(
            &cargo_home.join(name),
            "Cargo credential file",
        )?);
    }
    Ok((config_paths, credential_paths))
}

fn rustup_resolver_environment(cargo_home: &Path, rustup_home: &Path) -> Vec<(OsString, OsString)> {
    [
        ("CARGO_HOME", cargo_home.as_os_str()),
        ("LANG", OsStr::new("C")),
        ("LC_ALL", OsStr::new("C")),
        ("PATH", OsStr::new(CANONICAL_BUILD_PATH)),
        ("RUSTUP_HOME", rustup_home.as_os_str()),
        ("TZ", OsStr::new("UTC")),
    ]
    .into_iter()
    .map(|(name, value)| (OsString::from(name), value.to_os_string()))
    .collect()
}

fn resolve_rust_tool(
    root: &Path,
    program: &str,
    path_value: &OsStr,
    cargo_home: &Path,
    rustup_home: &Path,
) -> Result<(M7ExecutableIdentityV1, M7ExecutableIdentityV1), M7OperatorError> {
    let resolver = resolve_unambiguous_path_tool(program, path_value)?;
    let is_rustup_proxy = resolver.invocation_symlink_target.is_some()
        && Path::new(&resolver.canonical_path)
            .file_name()
            .is_some_and(|name| name == "rustup");
    if !is_rustup_proxy {
        return Ok((resolver.clone(), resolver));
    }
    let environment = rustup_resolver_environment(cargo_home, rustup_home);
    let args = ["which".to_string(), program.to_string()];
    let capture = require_process_success(
        &resolver.canonical_path,
        &["which", program],
        run_process(
            &resolver.canonical_path,
            &args,
            root,
            None,
            ProcessOutputLimits::separate(
                MAX_PROCESS_DIAGNOSTIC_BYTES,
                MAX_PROCESS_DIAGNOSTIC_BYTES,
            ),
            TOOLCHAIN_PROCESS_TIMEOUT,
            true,
            false,
            false,
            ProcessOutputDiagnosticPolicy::OmitAll,
            &environment,
        )?,
    )?;
    let actual_path = PathBuf::from(one_line_utf8(
        &capture.stdout,
        &format!("rustup which {program} output"),
    )?);
    let actual = executable_identity_from_invocation(&actual_path)?;
    if actual.invocation_symlink_target.is_some()
        || actual.invocation_path != actual.canonical_path
        || Path::new(&actual.canonical_path).file_name() != Some(OsStr::new(program))
    {
        return Err(M7OperatorError::InvalidInput(format!(
            "rustup did not resolve {program} to one canonical direct executable"
        )));
    }
    resolver.verify_current()?;
    Ok((resolver, actual))
}

fn toolchain_command_record(
    root: &Path,
    logical_program: &str,
    resolver: M7ExecutableIdentityV1,
    executable: M7ExecutableIdentityV1,
    args: &[&str],
    environment: &[(OsString, OsString)],
) -> Result<M7ToolchainCommandRecordV1, M7OperatorError> {
    resolver.verify_current()?;
    executable.verify_current()?;
    let capture = require_process_success(
        &executable.canonical_path,
        args,
        run_process(
            &executable.canonical_path,
            &args
                .iter()
                .map(|value| (*value).to_string())
                .collect::<Vec<_>>(),
            root,
            None,
            ProcessOutputLimits::separate(
                MAX_PROCESS_DIAGNOSTIC_BYTES,
                MAX_PROCESS_DIAGNOSTIC_BYTES,
            ),
            TOOLCHAIN_PROCESS_TIMEOUT,
            true,
            false,
            false,
            ProcessOutputDiagnosticPolicy::OmitAll,
            environment,
        )?,
    )?;
    resolver.verify_current()?;
    executable.verify_current()?;
    let stdout = String::from_utf8(capture.stdout).map_err(|error| {
        M7OperatorError::InvalidInput(format!("{logical_program} stdout is not UTF-8: {error}"))
    })?;
    let stderr = String::from_utf8(capture.stderr).map_err(|error| {
        M7OperatorError::InvalidInput(format!("{logical_program} stderr is not UTF-8: {error}"))
    })?;
    Ok(M7ToolchainCommandRecordV1 {
        logical_program: logical_program.to_string(),
        resolver,
        executable: executable.clone(),
        command: std::iter::once(executable.canonical_path)
            .chain(args.iter().map(|value| (*value).to_string()))
            .collect(),
        stdout,
        stderr,
        exit_code: capture.status.unwrap_or(-1),
    })
}

fn inspect_toolchain(root: &Path) -> Result<M7ToolchainRecordV1, M7OperatorError> {
    validate_inherited_build_environment(std::env::vars_os().map(|(name, _)| name))?;
    let path_value = std::env::var_os("PATH").ok_or_else(|| {
        M7OperatorError::InvalidInput("PATH is required to resolve proof tools".to_string())
    })?;
    let cargo_home = canonical_environment_directory("CARGO_HOME", ".cargo")?;
    let rustup_home = canonical_environment_directory("RUSTUP_HOME", ".rustup")?;
    let (config_paths, credential_paths) = inspect_cargo_configuration_absence(root, &cargo_home)?;
    let git_executable = resolve_unambiguous_path_tool("git", &path_value)?;
    let (rustc_resolver, rustc_executable) =
        resolve_rust_tool(root, "rustc", &path_value, &cargo_home, &rustup_home)?;
    let (cargo_resolver, cargo_executable) =
        resolve_rust_tool(root, "cargo", &path_value, &cargo_home, &rustup_home)?;
    let policy = M7BuildEnvironmentPolicyV1::new(
        &rustc_executable.canonical_path,
        &cargo_home,
        config_paths,
        credential_paths,
    )?;
    let build_environment = policy.process_environment(None);
    let mut git_environment = build_environment.clone();
    for (name, value) in [
        ("GIT_CONFIG_GLOBAL", "/dev/null"),
        ("GIT_CONFIG_NOSYSTEM", "1"),
        ("GIT_NO_REPLACE_OBJECTS", "1"),
        ("GIT_OPTIONAL_LOCKS", "0"),
        ("GIT_TERMINAL_PROMPT", "0"),
    ] {
        git_environment.push((OsString::from(name), OsString::from(value)));
    }
    let git = toolchain_command_record(
        root,
        "git",
        git_executable.clone(),
        git_executable,
        &["--version"],
        &git_environment,
    )?;
    let rustc = toolchain_command_record(
        root,
        "rustc",
        rustc_resolver,
        rustc_executable,
        &["--version", "--verbose"],
        &build_environment,
    )?;
    let cargo = toolchain_command_record(
        root,
        "cargo",
        cargo_resolver,
        cargo_executable,
        &["--version", "--verbose"],
        &build_environment,
    )?;
    let mut pin_files = Vec::new();
    for relative in ["rust-toolchain.toml", "rust-toolchain"] {
        let path = root.join(relative);
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if !metadata.is_file() || metadata.file_type().is_symlink() {
                    return Err(M7OperatorError::UnsafePath(path));
                }
                let bytes = read_regular_bounded(&path, MAX_TOOLCHAIN_PIN_BYTES)?;
                pin_files.push(M7ToolchainPinFileV1 {
                    path: relative.to_string(),
                    byte_length: bytes.len() as u64,
                    content_digest: ContentDigest::from_bytes(&bytes),
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(M7OperatorError::io(&path, error)),
        }
    }
    M7ToolchainRecordV1::new(git, rustc, cargo, pin_files, policy)
}

/// Inspect one independent Git metadata root at a detached, clean HEAD.
///
/// This function never creates or mutates the checkout. It rejects linked
/// worktrees, object alternates, symbolic HEADs, dirt, untracked files,
/// unsupported Git tree entries, and any worktree byte sequence that does not
/// reproduce its committed blob OID.
pub fn inspect_source_checkout(checkout: &Path) -> Result<M7SourceInspectionV1, M7OperatorError> {
    let input_metadata =
        fs::symlink_metadata(checkout).map_err(|error| M7OperatorError::io(checkout, error))?;
    if !input_metadata.is_dir() || input_metadata.file_type().is_symlink() {
        return Err(M7OperatorError::UnsafePath(checkout.to_path_buf()));
    }
    let root = fs::canonicalize(checkout).map_err(|error| M7OperatorError::io(checkout, error))?;
    let root_text = root
        .to_str()
        .ok_or_else(|| M7OperatorError::UnsafePath(root.clone()))?
        .to_string();
    let toolchain = inspect_toolchain(&root)?;
    let git = toolchain.git.executable.clone();

    let top_level = require_process_success(
        "git",
        &["rev-parse", "--show-toplevel"],
        run_git(
            &root,
            &git,
            &["rev-parse", "--show-toplevel"],
            None,
            16 * 1_024,
        )?,
    )?;
    let reported_top = PathBuf::from(one_line_utf8(&top_level.stdout, "Git top-level path")?);
    let reported_top = fs::canonicalize(&reported_top)
        .map_err(|error| M7OperatorError::io(&reported_top, error))?;
    if reported_top != root {
        return Err(M7OperatorError::InvalidInput(
            "checkout argument is not the Git top-level directory".to_string(),
        ));
    }

    let dot_git = root.join(".git");
    let dot_git_metadata =
        fs::symlink_metadata(&dot_git).map_err(|error| M7OperatorError::io(&dot_git, error))?;
    if !dot_git_metadata.is_dir() || dot_git_metadata.file_type().is_symlink() {
        return Err(M7OperatorError::InvalidInput(
            "checkout must own an independent .git directory, not a linked worktree".to_string(),
        ));
    }
    let expected_git_directory =
        fs::canonicalize(&dot_git).map_err(|error| M7OperatorError::io(&dot_git, error))?;
    let git_directory_output = require_process_success(
        "git",
        &["rev-parse", "--git-dir"],
        run_git(&root, &git, &["rev-parse", "--git-dir"], None, 16 * 1_024)?,
    )?;
    let git_directory = resolve_git_directory(
        &root,
        &one_line_utf8(&git_directory_output.stdout, "Git directory")?,
    )?;
    let common_directory_output = require_process_success(
        "git",
        &["rev-parse", "--git-common-dir"],
        run_git(
            &root,
            &git,
            &["rev-parse", "--git-common-dir"],
            None,
            16 * 1_024,
        )?,
    )?;
    let git_common_directory = resolve_git_directory(
        &root,
        &one_line_utf8(&common_directory_output.stdout, "Git common directory")?,
    )?;
    if git_directory != expected_git_directory || git_common_directory != expected_git_directory {
        return Err(M7OperatorError::InvalidInput(
            "checkout Git directory is shared with another worktree".to_string(),
        ));
    }

    let alternates = git_directory.join("objects/info/alternates");
    match fs::symlink_metadata(&alternates) {
        Ok(metadata) => {
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || !read_regular_bounded(&alternates, MAX_PROCESS_DIAGNOSTIC_BYTES)?.is_empty()
            {
                return Err(M7OperatorError::InvalidInput(
                    "checkout uses a Git object alternate".to_string(),
                ));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(M7OperatorError::io(&alternates, error)),
    }

    let symbolic = run_git(
        &root,
        &git,
        &["symbolic-ref", "-q", "HEAD"],
        None,
        16 * 1_024,
    )?;
    if symbolic.status != Some(1) || !symbolic.stdout.is_empty() {
        return Err(M7OperatorError::InvalidInput(
            "source checkout HEAD is not detached".to_string(),
        ));
    }

    let status_before = require_process_success(
        "git",
        &[
            "status",
            "--porcelain=v2",
            "--untracked-files=all",
            "--ignored=matching",
            "-z",
        ],
        run_git(
            &root,
            &git,
            &[
                "status",
                "--porcelain=v2",
                "--untracked-files=all",
                "--ignored=matching",
                "-z",
            ],
            None,
            MAX_GIT_OUTPUT_BYTES,
        )?,
    )?;
    if !status_before.stdout.is_empty() {
        return Err(M7OperatorError::InvalidInput(
            "source checkout is modified or has untracked files".to_string(),
        ));
    }

    let commit_output = require_process_success(
        "git",
        &["rev-parse", "--verify", "HEAD^{commit}"],
        run_git(
            &root,
            &git,
            &["rev-parse", "--verify", "HEAD^{commit}"],
            None,
            1_024,
        )?,
    )?;
    let commit_oid = one_line_utf8(&commit_output.stdout, "commit OID")?;
    validate_git_oid(&commit_oid, "commit")?;
    let commit_object = require_process_success(
        "git",
        &["cat-file", "commit", &commit_oid],
        run_git(
            &root,
            &git,
            &["cat-file", "commit", &commit_oid],
            None,
            MAX_GIT_OUTPUT_BYTES,
        )?,
    )?;
    let commit_object_digest = ContentDigest::from_bytes(&commit_object.stdout);

    let commit_tree_revision = format!("{commit_oid}^{{tree}}");
    let tree_output = require_process_success(
        "git",
        &["rev-parse", "--verify", &commit_tree_revision],
        run_git(
            &root,
            &git,
            &["rev-parse", "--verify", &commit_tree_revision],
            None,
            1_024,
        )?,
    )?;
    let tree_oid = one_line_utf8(&tree_output.stdout, "tree OID")?;
    validate_git_oid(&tree_oid, "tree")?;
    let tree_object = require_process_success(
        "git",
        &["cat-file", "tree", &tree_oid],
        run_git(
            &root,
            &git,
            &["cat-file", "tree", &tree_oid],
            None,
            MAX_GIT_OUTPUT_BYTES,
        )?,
    )?;
    let tree_digest = ContentDigest::from_bytes(&tree_object.stdout);
    let tracked_inventory = build_tracked_inventory(&root, &git, &tree_oid)?;
    let cargo_lock_path = safe_tracked_path(&root, Path::new("Cargo.lock"), false)?;
    let cargo_lock = read_regular_bounded(&cargo_lock_path, MAX_LOCKFILE_BYTES)?;
    let cargo_lock_digest = ContentDigest::from_bytes(&cargo_lock);
    toolchain.verify_executables_current()?;

    let status_after = require_process_success(
        "git",
        &[
            "status",
            "--porcelain=v2",
            "--untracked-files=all",
            "--ignored=matching",
            "-z",
        ],
        run_git(
            &root,
            &git,
            &[
                "status",
                "--porcelain=v2",
                "--untracked-files=all",
                "--ignored=matching",
                "-z",
            ],
            None,
            MAX_GIT_OUTPUT_BYTES,
        )?,
    )?;
    if !status_after.stdout.is_empty() {
        return Err(M7OperatorError::InvalidInput(
            "source checkout changed during inspection".to_string(),
        ));
    }
    let final_commit_output = require_process_success(
        "git",
        &["rev-parse", "--verify", "HEAD^{commit}"],
        run_git(
            &root,
            &git,
            &["rev-parse", "--verify", "HEAD^{commit}"],
            None,
            1_024,
        )?,
    )?;
    let final_commit_oid = one_line_utf8(&final_commit_output.stdout, "final commit OID")?;
    if final_commit_oid != commit_oid {
        return Err(M7OperatorError::Conflict(
            "detached HEAD changed during source inspection".to_string(),
        ));
    }
    toolchain.verify_executables_current()?;

    M7SourceInspectionV1::new(
        M7SourceIdentityRecipeV1::default(),
        root_text,
        git_directory
            .to_str()
            .ok_or_else(|| M7OperatorError::UnsafePath(git_directory.clone()))?
            .to_string(),
        git_common_directory
            .to_str()
            .ok_or_else(|| M7OperatorError::UnsafePath(git_common_directory.clone()))?
            .to_string(),
        commit_oid,
        commit_object_digest,
        tree_oid,
        tree_digest,
        tracked_inventory,
        cargo_lock_digest,
        toolchain,
    )
}

pub fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, M7OperatorError> {
    serde_json::to_vec_pretty(value)
        .map_err(|error| M7OperatorError::Serialization(error.to_string()))
}

fn digest_json<T: Serialize>(value: &T) -> Result<ContentDigest, M7OperatorError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| M7OperatorError::Serialization(error.to_string()))?;
    Ok(ContentDigest::from_bytes(&bytes))
}

pub fn read_regular_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, M7OperatorError> {
    let path_metadata =
        fs::symlink_metadata(path).map_err(|error| M7OperatorError::io(path, error))?;
    if !path_metadata.is_file() || path_metadata.file_type().is_symlink() {
        return Err(M7OperatorError::UnsafePath(path.to_path_buf()));
    }
    if path_metadata.len() > limit as u64 {
        return Err(M7OperatorError::ResourceExhausted(format!(
            "'{}' exceeds {limit} bytes",
            path.display()
        )));
    }
    let mut file = File::open(path).map_err(|error| M7OperatorError::io(path, error))?;
    let opened_metadata = file
        .metadata()
        .map_err(|error| M7OperatorError::io(path, error))?;
    if !opened_metadata.is_file()
        || opened_metadata.len() > limit as u64
        || !same_file_snapshot(&path_metadata, &opened_metadata)
    {
        return Err(M7OperatorError::UnsafePath(path.to_path_buf()));
    }
    let mut bytes = Vec::with_capacity(opened_metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| M7OperatorError::io(path, error))?;
    if bytes.len() > limit {
        return Err(M7OperatorError::ResourceExhausted(format!(
            "'{}' changed while being read or exceeds {limit} bytes",
            path.display()
        )));
    }
    let opened_after = file
        .metadata()
        .map_err(|error| M7OperatorError::io(path, error))?;
    let path_after =
        fs::symlink_metadata(path).map_err(|error| M7OperatorError::io(path, error))?;
    if path_after.file_type().is_symlink()
        || !same_file_snapshot(&opened_metadata, &opened_after)
        || !same_file_snapshot(&opened_after, &path_after)
        || opened_after.len() != bytes.len() as u64
    {
        return Err(M7OperatorError::Conflict(format!(
            "'{}' changed identity or contents while being read",
            path.display()
        )));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn same_file_snapshot(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.mode() == right.mode()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
}

#[cfg(not(unix))]
fn same_file_snapshot(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.is_file()
        && right.is_file()
        && left.len() == right.len()
        && left.modified().ok() == right.modified().ok()
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct OperatorPathIdentity {
    location: PathBuf,
    file_id: Option<(u64, u64)>,
}

impl OperatorPathIdentity {
    fn aliases(&self, other: &Self) -> bool {
        self.location == other.location
            || self
                .file_id
                .zip(other.file_id)
                .is_some_and(|(left, right)| left == right)
    }
}

#[cfg(unix)]
fn operator_file_id(metadata: &fs::Metadata) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    Some((metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
fn operator_file_id(_metadata: &fs::Metadata) -> Option<(u64, u64)> {
    None
}

/// Reject symlinks in every existing component, not only at the leaf. The
/// optional missing leaf is used solely for an output that has not yet been
/// published.
fn reject_symlink_components(
    path: &Path,
    allow_missing_leaf: bool,
) -> Result<PathBuf, M7OperatorError> {
    if path.as_os_str().is_empty() {
        return Err(M7OperatorError::UnsafePath(path.to_path_buf()));
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| M7OperatorError::io(Path::new("."), error))?
            .join(path)
    };
    let components = absolute.components().collect::<Vec<_>>();
    let mut current = PathBuf::new();
    for (index, component) in components.iter().enumerate() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(component.as_os_str()),
            Component::Normal(name) => {
                current.push(name);
                let is_leaf = index + 1 == components.len();
                let metadata = match fs::symlink_metadata(&current) {
                    Ok(metadata) => metadata,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::NotFound
                            && allow_missing_leaf
                            && is_leaf =>
                    {
                        return Ok(absolute);
                    }
                    Err(error) => return Err(M7OperatorError::io(&current, error)),
                };
                if metadata.file_type().is_symlink() {
                    return Err(M7OperatorError::UnsafePath(current));
                }
                if !is_leaf && !metadata.is_dir() {
                    return Err(M7OperatorError::UnsafePath(current));
                }
            }
            Component::CurDir | Component::ParentDir => {
                return Err(M7OperatorError::UnsafePath(path.to_path_buf()));
            }
        }
    }
    Ok(absolute)
}

fn existing_input_identity(path: &Path) -> Result<OperatorPathIdentity, M7OperatorError> {
    let absolute = reject_symlink_components(path, false)?;
    let metadata =
        fs::symlink_metadata(&absolute).map_err(|error| M7OperatorError::io(&absolute, error))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(M7OperatorError::UnsafePath(path.to_path_buf()));
    }
    let location =
        fs::canonicalize(&absolute).map_err(|error| M7OperatorError::io(&absolute, error))?;
    Ok(OperatorPathIdentity {
        location,
        file_id: operator_file_id(&metadata),
    })
}

fn output_identity(path: &Path) -> Result<OperatorPathIdentity, M7OperatorError> {
    let absolute = reject_symlink_components(path, true)?;
    if !matches!(absolute.components().last(), Some(Component::Normal(_))) {
        return Err(M7OperatorError::UnsafePath(path.to_path_buf()));
    }
    let parent = absolute
        .parent()
        .ok_or_else(|| M7OperatorError::UnsafePath(path.to_path_buf()))?;
    let parent = fs::canonicalize(parent).map_err(|error| M7OperatorError::io(parent, error))?;
    let name = absolute
        .file_name()
        .ok_or_else(|| M7OperatorError::UnsafePath(path.to_path_buf()))?;
    let location = parent.join(name);
    let file_id = match fs::symlink_metadata(&absolute) {
        Ok(metadata) => {
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(M7OperatorError::UnsafePath(path.to_path_buf()));
            }
            operator_file_id(&metadata)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(M7OperatorError::io(&absolute, error)),
    };
    Ok(OperatorPathIdentity { location, file_id })
}

fn reject_operator_path_aliases(
    paths: &[(&str, OperatorPathIdentity)],
) -> Result<(), M7OperatorError> {
    for (index, (left_label, left)) in paths.iter().enumerate() {
        for (right_label, right) in &paths[index + 1..] {
            if left.aliases(right) {
                return Err(M7OperatorError::Conflict(format!(
                    "operator paths '{left_label}' and '{right_label}' alias the same location or file"
                )));
            }
        }
    }
    Ok(())
}

pub fn read_json_file<T: DeserializeOwned>(
    path: &Path,
    limit: usize,
) -> Result<T, M7OperatorError> {
    let bytes = read_regular_bounded(path, limit)?;
    if bytes.is_empty() {
        return Err(M7OperatorError::InvalidInput(format!(
            "'{}' is empty",
            path.display()
        )));
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| M7OperatorError::Serialization(error.to_string()))
}

fn output_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

/// Create a new output without replacing different existing bytes.
///
/// Publication uses a same-directory temporary file and a no-clobber hard
/// link. An existing byte-identical output is an idempotent success.
pub fn persist_no_clobber_or_identical(
    path: &Path,
    bytes: &[u8],
    limit: usize,
) -> Result<(), M7OperatorError> {
    if bytes.is_empty() || bytes.len() > limit {
        return Err(M7OperatorError::ResourceExhausted(format!(
            "output byte length must be in 1..={limit}"
        )));
    }
    let parent = output_parent(path);
    let parent_metadata =
        fs::symlink_metadata(parent).map_err(|error| M7OperatorError::io(parent, error))?;
    if !parent_metadata.is_dir() || parent_metadata.file_type().is_symlink() {
        return Err(M7OperatorError::UnsafePath(parent.to_path_buf()));
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(M7OperatorError::UnsafePath(path.to_path_buf()));
            }
            let existing = read_regular_bounded(path, limit)?;
            return if existing == bytes {
                Ok(())
            } else {
                Err(M7OperatorError::Conflict(format!(
                    "refusing to replace different existing output '{}'",
                    path.display()
                )))
            };
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(M7OperatorError::io(path, error)),
    }

    let temporary = parent.join(format!(
        ".m7-operator-{}-{}.tmp",
        std::process::id(),
        OUTPUT_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|error| M7OperatorError::io(&temporary, error))?;
    let publish_result = (|| {
        file.write_all(bytes)
            .map_err(|error| M7OperatorError::io(&temporary, error))?;
        file.sync_all()
            .map_err(|error| M7OperatorError::io(&temporary, error))?;
        drop(file);
        match fs::hard_link(&temporary, path) {
            Ok(()) => {
                File::open(parent)
                    .and_then(|directory| directory.sync_all())
                    .map_err(|error| M7OperatorError::io(parent, error))?;
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = read_regular_bounded(path, limit)?;
                if existing == bytes {
                    Ok(())
                } else {
                    Err(M7OperatorError::Conflict(format!(
                        "another writer published different bytes at '{}'",
                        path.display()
                    )))
                }
            }
            Err(error) => Err(M7OperatorError::io(path, error)),
        }
    })();
    let cleanup_result = fs::remove_file(&temporary);
    if let Err(error) = cleanup_result {
        if publish_result.is_ok() {
            return Err(M7OperatorError::io(&temporary, error));
        }
    }
    publish_result
}

pub fn inspect_source_to_file(checkout: &Path, output: &Path) -> Result<(), M7OperatorError> {
    let inspection = inspect_source_checkout(checkout)?;
    ensure_output_outside_checkout(output, Path::new(&inspection.checkout_root))?;
    persist_no_clobber_or_identical(
        output,
        &inspection.canonical_bytes()?,
        MAX_SOURCE_INSPECTION_BYTES,
    )
}

fn ensure_output_outside_checkout(
    output: &Path,
    checkout_root: &Path,
) -> Result<(), M7OperatorError> {
    let file_name = output
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| M7OperatorError::UnsafePath(output.to_path_buf()))?;
    let parent = fs::canonicalize(output_parent(output))
        .map_err(|error| M7OperatorError::io(output_parent(output), error))?;
    let resolved = parent.join(file_name);
    let checkout_root = fs::canonicalize(checkout_root)
        .map_err(|error| M7OperatorError::io(checkout_root, error))?;
    if resolved.starts_with(&checkout_root) {
        return Err(M7OperatorError::UnsafePath(output.to_path_buf()));
    }
    Ok(())
}

fn load_manifest(path: &Path) -> Result<M7ProofRunManifest, M7OperatorError> {
    let bytes = read_regular_bounded(path, MAX_MANIFEST_BYTES)?;
    M7ProofRunManifest::from_canonical_bytes(&bytes)
        .map_err(|error| M7OperatorError::Foundation(error.to_string()))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M7CriterionStatementRequestV1 {
    pub criterion_id: String,
    pub statement: String,
    pub required_families: BTreeSet<M7EvidenceFamily>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M7ExternalPublicKeyPinRequestV1 {
    pub principal_id: String,
    pub public_key_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M7ManifestCreateRequestV1 {
    pub schema: String,
    pub proof_run_id: String,
    pub run_started_at_ms: u64,
    pub criteria_id: String,
    pub criteria_version: String,
    pub criteria_frozen_at_ms: u64,
    pub criteria: Vec<M7CriterionStatementRequestV1>,
    pub source_custodian: M7ExternalPublicKeyPinRequestV1,
    pub independent_reviewer: M7ExternalPublicKeyPinRequestV1,
    pub causal_chain_digest: ContentDigest,
    pub implementation_principal_ids: BTreeSet<String>,
    pub implementation_identity_digests: BTreeSet<ContentDigest>,
    pub prepared_provider_seed_path: Option<PathBuf>,
}

fn decode_lower_hex_exact(
    value: &str,
    expected_bytes: usize,
    label: &str,
) -> Result<Vec<u8>, M7OperatorError> {
    if value.len() != expected_bytes * 2
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(M7OperatorError::InvalidInput(format!(
            "{label} must contain exactly {expected_bytes} bytes as lowercase hexadecimal"
        )));
    }
    let mut bytes = Vec::with_capacity(expected_bytes);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn hex_nibble(byte: u8) -> Result<u8, M7OperatorError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(M7OperatorError::InvalidInput(
            "hexadecimal input contains an invalid character".to_string(),
        )),
    }
}

fn external_identity(
    request: &M7ExternalPublicKeyPinRequestV1,
) -> Result<M7ExternalEd25519IdentityV1, M7OperatorError> {
    let public_key = decode_lower_hex_exact(
        &request.public_key_hex,
        ED25519_PUBLIC_KEY_BYTES,
        "external Ed25519 public key",
    )?;
    M7ExternalEd25519IdentityV1::new(request.principal_id.clone(), &public_key)
        .map_err(|error| M7OperatorError::Foundation(error.to_string()))
}

pub fn create_manifest(
    request: &M7ManifestCreateRequestV1,
    source: &M7SourceInspectionV1,
) -> Result<M7ProofRunManifest, M7OperatorError> {
    if request.schema != M7_MANIFEST_CREATE_REQUEST_SCHEMA {
        return Err(M7OperatorError::InvalidInput(
            "unsupported manifest-create request schema".to_string(),
        ));
    }
    source.validate()?;
    if request.criteria.is_empty() || request.criteria.len() > 128 {
        return Err(M7OperatorError::InvalidInput(
            "manifest request must contain 1..=128 criterion statements".to_string(),
        ));
    }
    let mut criteria = Vec::with_capacity(request.criteria.len());
    for criterion in &request.criteria {
        if criterion.statement.trim().is_empty()
            || criterion.statement.as_bytes().len() > MAX_STATEMENT_BYTES
        {
            return Err(M7OperatorError::InvalidInput(format!(
                "criterion '{}' statement must contain 1..={MAX_STATEMENT_BYTES} bytes",
                criterion.criterion_id
            )));
        }
        criteria.push(M7Criterion {
            criterion_id: criterion.criterion_id.clone(),
            statement: criterion.statement.clone(),
            statement_digest: ContentDigest::from_bytes(criterion.statement.as_bytes()),
            required_families: criterion.required_families.clone(),
        });
    }
    let frozen = FrozenClosureCriteria::new(
        request.criteria_id.clone(),
        request.criteria_version.clone(),
        request.criteria_frozen_at_ms,
        criteria,
    )
    .map_err(|error| M7OperatorError::Foundation(error.to_string()))?;
    let source_custodian = external_identity(&request.source_custodian)?;
    let reviewer = external_identity(&request.independent_reviewer)?;
    let live_provider_scope = request
        .prepared_provider_seed_path
        .as_ref()
        .map(|path| {
            let bytes = read_regular_bounded(path, MAX_PREPARED_PROVIDER_SEED_BYTES)?;
            let prepared = M5PreparedProviderSeedV1::from_canonical_bytes(&bytes)
                .map_err(|error| M7OperatorError::Foundation(error.to_string()))?;
            if prepared.precommit.proof_run_id != request.proof_run_id {
                return Err(M7OperatorError::InvalidInput(
                    "prepared provider seed belongs to a different proof run".to_string(),
                ));
            }
            if prepared.precommit.prepared_at_ms >= request.run_started_at_ms {
                return Err(M7OperatorError::InvalidInput(
                    "prepared provider seed must be created strictly before the proof run starts"
                        .to_string(),
                ));
            }
            LiveProviderQualificationScope::from_prepared(&prepared)
                .map_err(|error| M7OperatorError::Foundation(error.to_string()))
        })
        .transpose()?;
    M7ProofRunManifest::new(
        request.proof_run_id.clone(),
        request.run_started_at_ms,
        frozen,
        source.source_identity.clone(),
        source_custodian,
        reviewer,
        request.causal_chain_digest.clone(),
        request.implementation_principal_ids.clone(),
        request.implementation_identity_digests.clone(),
        live_provider_scope,
    )
    .map_err(|error| M7OperatorError::Foundation(error.to_string()))
}

pub fn create_manifest_to_file(
    request_path: &Path,
    source_inspection_path: &Path,
    output: &Path,
) -> Result<(), M7OperatorError> {
    let mut request: M7ManifestCreateRequestV1 = read_json_file(request_path, MAX_REQUEST_BYTES)?;
    if let Some(relative) = request.prepared_provider_seed_path.as_ref() {
        validate_relative_path(relative)?;
        request.prepared_provider_seed_path = Some(safe_tracked_path(
            output_parent(request_path),
            relative,
            false,
        )?);
    }
    let source_bytes = read_regular_bounded(source_inspection_path, MAX_SOURCE_INSPECTION_BYTES)?;
    let source = M7SourceInspectionV1::from_canonical_bytes(&source_bytes)?;
    let refreshed = inspect_source_checkout(Path::new(&source.checkout_root))?;
    if refreshed != source {
        return Err(M7OperatorError::Conflict(
            "detached source checkout changed after its source inspection was written".to_string(),
        ));
    }
    ensure_output_outside_checkout(output, Path::new(&source.checkout_root))?;
    let manifest = create_manifest(&request, &source)?;
    let bytes = manifest
        .canonical_bytes()
        .map_err(|error| M7OperatorError::Foundation(error.to_string()))?;
    persist_no_clobber_or_identical(output, &bytes, MAX_MANIFEST_BYTES)
}

pub fn initialize_dossier(root: &Path, manifest_path: &Path) -> Result<(), M7OperatorError> {
    match fs::symlink_metadata(root) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(M7OperatorError::UnsafePath(root.to_path_buf()));
            }
            let mut entries =
                fs::read_dir(root).map_err(|error| M7OperatorError::io(root, error))?;
            if entries
                .next()
                .transpose()
                .map_err(|error| M7OperatorError::io(root, error))?
                .is_some()
            {
                return Err(M7OperatorError::Conflict(format!(
                    "dossier root '{}' is not empty",
                    root.display()
                )));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(M7OperatorError::io(root, error)),
    }
    let manifest = load_manifest(manifest_path)?;
    let runtime = M7DossierRuntime::open(root, manifest)
        .map_err(|error| M7OperatorError::Dossier(error.to_string()))?;
    drop(runtime);
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct M7ActiveSurfaceCaptureInputsV1 {
    pub root_readme: PathBuf,
    pub roadmap: PathBuf,
    pub base_url: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct M7ActiveSurfaceOutputPathsV1 {
    pub snapshot: PathBuf,
    pub truth_boundary_source: PathBuf,
    pub claim_boundary_source: PathBuf,
    pub publication_policy_source: PathBuf,
}

fn preflight_no_clobber_output(
    path: &Path,
    expected: &[u8],
    limit: usize,
) -> Result<(), M7OperatorError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(M7OperatorError::UnsafePath(path.to_path_buf()));
            }
            if read_regular_bounded(path, limit)? != expected {
                return Err(M7OperatorError::Conflict(format!(
                    "refusing to replace different existing output '{}'",
                    path.display()
                )));
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(M7OperatorError::io(path, error)),
    }
}

fn validate_loopback_capture_origin(value: &str) -> Result<String, M7OperatorError> {
    let url = reqwest::Url::parse(value).map_err(|_| {
        M7OperatorError::InvalidInput(
            "active-surface base URL must be an explicit loopback HTTP origin".to_string(),
        )
    })?;
    let origin = url.origin().ascii_serialization();
    let supplied_origin = value.strip_suffix('/').unwrap_or(value);
    if url.scheme() != "http"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || url.port().is_none_or(|port| port == 80)
        || !matches!(
            url.host_str(),
            Some("localhost" | "127.0.0.1" | "::1" | "[::1]")
        )
        || supplied_origin != origin
        || (value.ends_with('/') && value.ends_with("//"))
    {
        return Err(M7OperatorError::InvalidInput(
            "active-surface base URL must be canonical http://localhost|127.0.0.1|[::1]:<non-default-port> with origin path / and no userinfo, query, or fragment"
                .to_string(),
        ));
    }
    Ok(origin)
}

fn validate_active_surface_authority_locations(
    readme: &OperatorPathIdentity,
    roadmap: &OperatorPathIdentity,
) -> Result<(), M7OperatorError> {
    let repository_root = readme
        .location
        .parent()
        .ok_or_else(|| M7OperatorError::UnsafePath(readme.location.clone()))?;
    if readme.location.file_name() != Some(OsStr::new("README.md"))
        || roadmap.location != repository_root.join("notes").join("ROADMAP.md")
    {
        return Err(M7OperatorError::InvalidInput(
            "active-surface Markdown authorities must be the canonical <checkout>/README.md and <checkout>/notes/ROADMAP.md files"
                .to_string(),
        ));
    }
    Ok(())
}

fn observed_operator_time_ms(lower_bound_ms: u64) -> Result<u64, M7OperatorError> {
    let observed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| {
            M7OperatorError::InvalidInput(
                "operator clock is before the Unix epoch during active-surface capture".to_string(),
            )
        })?
        .as_millis();
    let observed = u64::try_from(observed).map_err(|_| {
        M7OperatorError::ResourceExhausted(
            "operator clock value exceeds the M7 timestamp bound".to_string(),
        )
    })?;
    if observed < lower_bound_ms {
        return Err(M7OperatorError::Conflict(
            "operator clock moved backwards during sequential active-surface capture".to_string(),
        ));
    }
    Ok(observed)
}

fn add_active_surface_bytes(
    total: &mut usize,
    label: &str,
    bytes: &[u8],
) -> Result<(), M7OperatorError> {
    *total = (*total).checked_add(bytes.len()).ok_or_else(|| {
        M7OperatorError::ResourceExhausted("active-surface input byte total overflowed".to_string())
    })?;
    if *total > MAX_ACTIVE_SURFACE_INPUT_TOTAL_BYTES {
        return Err(M7OperatorError::ResourceExhausted(format!(
            "active-surface bytes exceed {MAX_ACTIVE_SURFACE_INPUT_TOTAL_BYTES} while observing {label}"
        )));
    }
    Ok(())
}

fn validate_active_surface_response(
    role: M7ActiveSurfaceRoleV1,
    requested_url: &reqwest::Url,
    response: &reqwest::Response,
) -> Result<(), M7OperatorError> {
    if response.url() != requested_url {
        return Err(M7OperatorError::InvalidInput(format!(
            "active-surface GET {} changed its final URL",
            role.path()
        )));
    }
    if response.status() != reqwest::StatusCode::OK {
        return Err(M7OperatorError::InvalidInput(format!(
            "active-surface GET {} returned status {} instead of 200",
            role.path(),
            response.status().as_u16()
        )));
    }
    if response.version() != reqwest::Version::HTTP_11 {
        return Err(M7OperatorError::InvalidInput(format!(
            "active-surface GET {} did not use HTTP/1.1",
            role.path()
        )));
    }
    for forbidden in [
        reqwest::header::LOCATION.as_str(),
        reqwest::header::CONTENT_ENCODING.as_str(),
        reqwest::header::SET_COOKIE.as_str(),
        reqwest::header::WWW_AUTHENTICATE.as_str(),
        reqwest::header::PROXY_AUTHENTICATE.as_str(),
        reqwest::header::AUTHORIZATION.as_str(),
        reqwest::header::PROXY_AUTHORIZATION.as_str(),
        reqwest::header::COOKIE.as_str(),
        "authentication-info",
        "proxy-authentication-info",
    ] {
        if response.headers().contains_key(forbidden) {
            return Err(M7OperatorError::InvalidInput(format!(
                "active-surface GET {} returned forbidden response metadata",
                role.path()
            )));
        }
    }
    let mut content_types = response
        .headers()
        .get_all(reqwest::header::CONTENT_TYPE)
        .iter();
    let content_type = content_types.next().ok_or_else(|| {
        M7OperatorError::InvalidInput(format!(
            "active-surface GET {} omitted Content-Type",
            role.path()
        ))
    })?;
    if content_types.next().is_some() || content_type.as_bytes() != b"application/json" {
        return Err(M7OperatorError::InvalidInput(format!(
            "active-surface GET {} must return exactly one application/json Content-Type",
            role.path()
        )));
    }
    Ok(())
}

fn exact_content_length(
    headers: &reqwest::header::HeaderMap,
    role: M7ActiveSurfaceRoleV1,
) -> Result<Option<u64>, M7OperatorError> {
    let mut values = headers.get_all(reqwest::header::CONTENT_LENGTH).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(M7OperatorError::InvalidInput(format!(
            "active-surface GET {} returned duplicate Content-Length values",
            role.path()
        )));
    }
    let value = value.to_str().map_err(|_| {
        M7OperatorError::InvalidInput(format!(
            "active-surface GET {} returned malformed Content-Length",
            role.path()
        ))
    })?;
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(M7OperatorError::InvalidInput(format!(
            "active-surface GET {} returned malformed Content-Length",
            role.path()
        )));
    }
    value.parse::<u64>().map(Some).map_err(|_| {
        M7OperatorError::InvalidInput(format!(
            "active-surface GET {} returned overlimit Content-Length",
            role.path()
        ))
    })
}

fn validate_peer_for_origin(origin: &str, peer: std::net::SocketAddr) -> bool {
    let Ok(url) = reqwest::Url::parse(&format!("{origin}/")) else {
        return false;
    };
    if url.port() != Some(peer.port()) || !peer.ip().is_loopback() {
        return false;
    }
    match url.host_str() {
        Some("localhost") => true,
        Some("127.0.0.1") => peer.ip() == std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        Some("::1" | "[::1]") => peer.ip() == std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        _ => false,
    }
}

/// Observe the exact Markdown authorities and five sequential loopback HTTP
/// endpoints, then publish one provenance-bound snapshot and three M0 records.
/// Every path and output conflict is preflighted before networking begins.
pub async fn capture_active_surface_sources_to_files(
    inputs: &M7ActiveSurfaceCaptureInputsV1,
    outputs: &M7ActiveSurfaceOutputPathsV1,
) -> Result<(), M7OperatorError> {
    let origin = validate_loopback_capture_origin(&inputs.base_url)?;
    let readme_identity = existing_input_identity(&inputs.root_readme)?;
    let roadmap_identity = existing_input_identity(&inputs.roadmap)?;
    validate_active_surface_authority_locations(&readme_identity, &roadmap_identity)?;
    let output_paths = [
        ("snapshot-out", outputs.snapshot.as_path()),
        ("truth-source-out", outputs.truth_boundary_source.as_path()),
        ("claim-source-out", outputs.claim_boundary_source.as_path()),
        (
            "publication-source-out",
            outputs.publication_policy_source.as_path(),
        ),
    ];
    let mut path_identities = vec![
        ("readme", readme_identity.clone()),
        ("roadmap", roadmap_identity.clone()),
    ];
    for (label, path) in output_paths {
        let identity = output_identity(path)?;
        if identity.file_id.is_some() {
            return Err(M7OperatorError::Conflict(format!(
                "active-surface capture output '{label}' already exists"
            )));
        }
        path_identities.push((label, identity));
    }
    reject_operator_path_aliases(&path_identities)?;

    let mut total_input_bytes = 0_usize;

    let mut captures = Vec::with_capacity(7);
    let mut last_observed_at_ms = 0;
    for (role, path, identity) in [
        (
            M7ActiveSurfaceRoleV1::RootReadme,
            inputs.root_readme.as_path(),
            &readme_identity,
        ),
        (
            M7ActiveSurfaceRoleV1::Roadmap,
            inputs.roadmap.as_path(),
            &roadmap_identity,
        ),
    ] {
        let started_at_ms = observed_operator_time_ms(last_observed_at_ms)?;
        let bytes = read_regular_bounded(path, MAX_ACTIVE_SURFACE_INPUT_BYTES)?;
        if existing_input_identity(path)? != *identity {
            return Err(M7OperatorError::Conflict(format!(
                "active-surface authority '{}' changed identity while being observed",
                path.display()
            )));
        }
        add_active_surface_bytes(&mut total_input_bytes, role.path(), &bytes)?;
        let completed_at_ms = observed_operator_time_ms(started_at_ms)?;
        let canonical_path = identity
            .location
            .to_str()
            .ok_or_else(|| M7OperatorError::UnsafePath(identity.location.clone()))?
            .to_string();
        let observation = M7ActiveSurfaceObservationV1::local_authority(
            role,
            canonical_path,
            started_at_ms,
            completed_at_ms,
            &bytes,
        )
        .map_err(|error| M7OperatorError::Foundation(error.to_string()))?;
        captures.push(
            M7ActiveSurfaceCaptureV1::from_observation(role, bytes, observation)
                .map_err(|error| M7OperatorError::Foundation(error.to_string()))?,
        );
        last_observed_at_ms = completed_at_ms;
    }

    let client = reqwest::Client::builder()
        .retry(reqwest::retry::never())
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .referer(false)
        .pool_max_idle_per_host(0)
        .connect_timeout(Duration::from_millis(M7_ACTIVE_SURFACE_CONNECT_TIMEOUT_MS))
        .timeout(Duration::from_millis(M7_ACTIVE_SURFACE_REQUEST_TIMEOUT_MS))
        .read_timeout(Duration::from_millis(M7_ACTIVE_SURFACE_READ_TIMEOUT_MS))
        .http1_only()
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .build()
        .map_err(|error| {
            M7OperatorError::InvalidInput(format!(
                "could not construct bounded active-surface HTTP client: {error}"
            ))
        })?;
    for role in [
        M7ActiveSurfaceRoleV1::SystemOverview,
        M7ActiveSurfaceRoleV1::GeneralAudienceHome,
        M7ActiveSurfaceRoleV1::NorthStar07ClosureReview,
        M7ActiveSurfaceRoleV1::RemediationPhase04FinalClosureRereview,
        M7ActiveSurfaceRoleV1::RemediationPhase04PublicationPolicy,
    ] {
        let started_at_ms = observed_operator_time_ms(last_observed_at_ms)?;
        let request_url =
            reqwest::Url::parse(&format!("{origin}{}", role.path())).map_err(|_| {
                M7OperatorError::InvalidInput("active-surface endpoint URL is invalid".to_string())
            })?;
        let mut response = client
            .get(request_url.clone())
            .header(reqwest::header::ACCEPT, "application/json")
            .header(reqwest::header::ACCEPT_ENCODING, "identity")
            .header(reqwest::header::CONNECTION, "close")
            .send()
            .await
            .map_err(|error| {
                M7OperatorError::InvalidInput(format!(
                    "active-surface GET {} failed: {error}",
                    role.path()
                ))
            })?;
        validate_active_surface_response(role, &request_url, &response)?;
        let peer = response.remote_addr().ok_or_else(|| {
            M7OperatorError::InvalidInput(format!(
                "active-surface GET {} did not expose a remote peer",
                role.path()
            ))
        })?;
        if !validate_peer_for_origin(&origin, peer) {
            return Err(M7OperatorError::InvalidInput(format!(
                "active-surface GET {} reached a peer inconsistent with the loopback origin",
                role.path()
            )));
        }
        let declared_length = exact_content_length(response.headers(), role)?;
        if declared_length.is_some_and(|length| {
            length > MAX_ACTIVE_SURFACE_INPUT_BYTES as u64
                || total_input_bytes
                    .checked_add(length as usize)
                    .is_none_or(|total| total > MAX_ACTIVE_SURFACE_INPUT_TOTAL_BYTES)
        }) {
            return Err(M7OperatorError::ResourceExhausted(format!(
                "active-surface GET {} declares an oversized body",
                role.path()
            )));
        }
        let version = "HTTP/1.1".to_string();
        let mut bytes = Vec::with_capacity(declared_length.unwrap_or(0) as usize);
        while let Some(chunk) = response.chunk().await.map_err(|error| {
            M7OperatorError::InvalidInput(format!(
                "active-surface GET {} body failed: {error}",
                role.path()
            ))
        })? {
            if bytes
                .len()
                .checked_add(chunk.len())
                .is_none_or(|length| length > MAX_ACTIVE_SURFACE_INPUT_BYTES)
            {
                return Err(M7OperatorError::ResourceExhausted(format!(
                    "active-surface GET {} exceeded {MAX_ACTIVE_SURFACE_INPUT_BYTES} bytes",
                    role.path()
                )));
            }
            bytes.extend_from_slice(&chunk);
        }
        if declared_length.is_some_and(|length| length != bytes.len() as u64) {
            return Err(M7OperatorError::InvalidInput(format!(
                "active-surface GET {} body length disagrees with Content-Length",
                role.path()
            )));
        }
        add_active_surface_bytes(&mut total_input_bytes, role.path(), &bytes)?;
        let completed_at_ms = observed_operator_time_ms(started_at_ms)?;
        let observation = M7ActiveSurfaceObservationV1::http_get(
            role,
            origin.clone(),
            peer.to_string(),
            version,
            started_at_ms,
            completed_at_ms,
            &bytes,
        )
        .map_err(|error| M7OperatorError::Foundation(error.to_string()))?;
        captures.push(
            M7ActiveSurfaceCaptureV1::from_observation(role, bytes, observation)
                .map_err(|error| M7OperatorError::Foundation(error.to_string()))?,
        );
        last_observed_at_ms = completed_at_ms;
    }

    let snapshot = M7ActiveSurfaceSnapshotV1::from_observed_surfaces(captures)
        .map_err(|error| M7OperatorError::Foundation(error.to_string()))?;
    let truth_source = M7TruthBoundarySourceV3::new(snapshot.clone())
        .map_err(|error| M7OperatorError::Foundation(error.to_string()))?;
    let claim_source = M7ClaimBoundarySourceV3::new(snapshot.clone())
        .map_err(|error| M7OperatorError::Foundation(error.to_string()))?;
    let publication_source = M7PublicationPolicySourceV3::new(snapshot.clone())
        .map_err(|error| M7OperatorError::Foundation(error.to_string()))?;
    let snapshot_bytes = snapshot
        .canonical_bytes()
        .map_err(|error| M7OperatorError::Foundation(error.to_string()))?;
    let truth_bytes = truth_source
        .canonical_bytes()
        .map_err(|error| M7OperatorError::Foundation(error.to_string()))?;
    let claim_bytes = claim_source
        .canonical_bytes()
        .map_err(|error| M7OperatorError::Foundation(error.to_string()))?;
    let publication_bytes = publication_source
        .canonical_bytes()
        .map_err(|error| M7OperatorError::Foundation(error.to_string()))?;

    let publications = [
        (outputs.snapshot.as_path(), snapshot_bytes.as_slice()),
        (
            outputs.truth_boundary_source.as_path(),
            truth_bytes.as_slice(),
        ),
        (
            outputs.claim_boundary_source.as_path(),
            claim_bytes.as_slice(),
        ),
        (
            outputs.publication_policy_source.as_path(),
            publication_bytes.as_slice(),
        ),
    ];
    for (path, bytes) in publications {
        preflight_no_clobber_output(path, bytes, MAX_OUTPUT_BYTES)?;
    }
    for (path, bytes) in publications {
        persist_no_clobber_or_identical(path, bytes, MAX_OUTPUT_BYTES)?;
    }
    Ok(())
}

/// Assemble the one canonical M7 live-provider source only from M5's opaque,
/// manifest-bound completed invocation. Separable pre-call and post-call
/// records are intentionally not accepted at this authority boundary.
pub fn assemble_live_provider_source(
    completed_invocation_path: &Path,
) -> Result<M7LiveProviderSourceV1, M7OperatorError> {
    let completed_bytes = read_regular_bounded(
        completed_invocation_path,
        MAX_COMPLETED_PROVIDER_INVOCATION_BYTES,
    )?;
    let completed = M5CompletedProviderInvocationV1::from_canonical_bytes(&completed_bytes)
        .map_err(|error| M7OperatorError::Foundation(error.to_string()))?;
    M7LiveProviderSourceV1::from_completed_invocation(completed)
        .map_err(|error| M7OperatorError::Foundation(error.to_string()))
}

pub fn assemble_live_provider_source_to_file(
    completed_invocation_path: &Path,
    output: &Path,
) -> Result<(), M7OperatorError> {
    let source = assemble_live_provider_source(completed_invocation_path)?;
    let bytes = source
        .canonical_bytes()
        .map_err(|error| M7OperatorError::Foundation(error.to_string()))?;
    persist_no_clobber_or_identical(output, &bytes, MAX_LIVE_PROVIDER_SOURCE_BYTES)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M7ExactSourceFileV1 {
    pub role: M7SourceRoleV2,
    pub path: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M7ExactSourceAdmissionRequestV1 {
    pub schema: String,
    pub kind: M7EvidenceKind,
    pub sources: Vec<M7ExactSourceFileV1>,
}

pub fn admit_exact_sources(
    dossier_root: &Path,
    request: &M7ExactSourceAdmissionRequestV1,
    source_base: &Path,
) -> Result<M7EvidenceLink, M7OperatorError> {
    if request.schema != M7_EXACT_SOURCE_ADMISSION_REQUEST_SCHEMA {
        return Err(M7OperatorError::InvalidInput(
            "unsupported exact-source admission request schema".to_string(),
        ));
    }
    if matches!(
        request.kind,
        M7EvidenceKind::DeterministicTestTranscript
            | M7EvidenceKind::IndependentReviewerRecommendation
    ) {
        return Err(M7OperatorError::InvalidInput(
            "capture-backed transcript and independent review must use their detached-signature commands"
                .to_string(),
        ));
    }
    if request.sources.is_empty() || request.sources.len() > 128 {
        return Err(M7OperatorError::InvalidInput(
            "exact-source request must contain 1..=128 source files".to_string(),
        ));
    }
    let source_base =
        fs::canonicalize(source_base).map_err(|error| M7OperatorError::io(source_base, error))?;
    let mut inputs = Vec::with_capacity(request.sources.len());
    let mut total = 0_usize;
    for source in &request.sources {
        validate_relative_path(&source.path)?;
        let path = safe_tracked_path(&source_base, &source.path, false)?;
        let bytes = read_regular_bounded(&path, MAX_EXACT_SOURCE_BYTES)?;
        total = total.checked_add(bytes.len()).ok_or_else(|| {
            M7OperatorError::ResourceExhausted("exact source byte total overflowed".to_string())
        })?;
        if total > MAX_EXACT_SOURCE_TOTAL_BYTES {
            return Err(M7OperatorError::ResourceExhausted(format!(
                "exact source bytes exceed {MAX_EXACT_SOURCE_TOTAL_BYTES}"
            )));
        }
        inputs.push(M7SourceInputV2::new(source.role, bytes));
    }
    let mut runtime = M7DossierRuntime::reopen(dossier_root)
        .map_err(|error| M7OperatorError::Dossier(error.to_string()))?;
    let derived = M7EvidenceArtifact::derive_from_sources(runtime.manifest(), request.kind, inputs)
        .map_err(|error| M7OperatorError::Foundation(error.to_string()))?;
    runtime
        .admit_derived_evidence(&derived)
        .map_err(|error| M7OperatorError::Dossier(error.to_string()))
}

pub fn admit_exact_sources_from_file(
    dossier_root: &Path,
    request_path: &Path,
    output: &Path,
) -> Result<(), M7OperatorError> {
    let request: M7ExactSourceAdmissionRequestV1 = read_json_file(request_path, MAX_REQUEST_BYTES)?;
    let source_base = output_parent(request_path);
    let link = admit_exact_sources(dossier_root, &request, source_base)?;
    persist_no_clobber_or_identical(output, &canonical_json_bytes(&link)?, MAX_OUTPUT_BYTES)
}

fn create_cargo_transcript(
    manifest: &M7ProofRunManifest,
    stdout_bytes: Vec<u8>,
    stderr_bytes: Vec<u8>,
    exit_code: i32,
) -> Result<M7CargoTestTranscriptV2, M7OperatorError> {
    validate_cargo_transcript_lengths(
        stdout_bytes.len(),
        stderr_bytes.len(),
        MAX_TRANSCRIPT_STREAM_BYTES,
        MAX_TRANSCRIPT_CONTENT_BYTES,
    )?;
    let stdout = String::from_utf8(stdout_bytes).map_err(|error| {
        M7OperatorError::InvalidInput(format!("captured Cargo stdout is not UTF-8: {error}"))
    })?;
    let stderr = String::from_utf8(stderr_bytes).map_err(|error| {
        M7OperatorError::InvalidInput(format!("captured Cargo stderr is not UTF-8: {error}"))
    })?;
    reject_secret_shaped_transcript("Cargo stdout", stdout.as_bytes())?;
    reject_secret_shaped_transcript("Cargo stderr", stderr.as_bytes())?;
    M7CargoTestTranscriptV2::new(
        vec![
            "cargo".to_string(),
            "test".to_string(),
            "--locked".to_string(),
            "--all-targets".to_string(),
        ],
        manifest.manifest_digest().clone(),
        stdout,
        stderr,
        exit_code,
    )
    .map_err(|error| M7OperatorError::Foundation(error.to_string()))
}

fn validate_cargo_transcript_lengths(
    stdout_length: usize,
    stderr_length: usize,
    stream_limit: usize,
    combined_limit: usize,
) -> Result<(), M7OperatorError> {
    let total = stdout_length.checked_add(stderr_length).ok_or_else(|| {
        M7OperatorError::ResourceExhausted("Cargo transcript length overflowed".to_string())
    })?;
    if stdout_length > stream_limit {
        return Err(M7OperatorError::ResourceExhausted(format!(
            "Cargo stdout length {stdout_length} exceeds the {stream_limit}-byte stream limit"
        )));
    }
    if stderr_length > stream_limit {
        return Err(M7OperatorError::ResourceExhausted(format!(
            "Cargo stderr length {stderr_length} exceeds the {stream_limit}-byte stream limit"
        )));
    }
    if total == 0 || total > combined_limit {
        return Err(M7OperatorError::ResourceExhausted(format!(
            "combined Cargo stdout/stderr length {total} is outside 1..={combined_limit} bytes"
        )));
    }
    Ok(())
}

fn reject_secret_shaped_transcript(label: &str, bytes: &[u8]) -> Result<(), M7OperatorError> {
    if contains_secret_shaped_material(bytes) {
        return Err(M7OperatorError::InvalidInput(format!(
            "{label} contains credential-shaped material and cannot enter immutable M7 evidence"
        )));
    }
    Ok(())
}

fn contains_secret_shaped_material(bytes: &[u8]) -> bool {
    let lower = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    let fixed_patterns = [
        "-----begin private key-----",
        "-----begin rsa private key-----",
        "-----begin ec private key-----",
        "github_pat_",
        "ghp_",
        "authorization: bearer ",
        "openai_api_key=",
        "openrouter_api_key=",
        "\"api_key\":",
        "api_key=",
        "\"access_token\":",
        "access_token=",
        "\"auth_token\":",
        "auth_token=",
        "\"password\":",
        "password=",
        "\"secret_key\":",
        "secret_key=",
    ];
    let aws_key = bytes.windows(20).any(|window| {
        window.starts_with(b"AKIA")
            && window[4..]
                .iter()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    });
    let openai_key = bytes.windows(12).any(|window| {
        window.starts_with(b"sk-")
            && window[3..]
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-' || *byte == b'_')
    });
    fixed_patterns
        .into_iter()
        .any(|pattern| lower.contains(pattern))
        || aws_key
        || openai_key
}

fn prepare_empty_target_directory(
    target_directory: &Path,
    checkout_root: &Path,
) -> Result<PathBuf, M7OperatorError> {
    if !target_directory.is_absolute() {
        return Err(M7OperatorError::UnsafePath(target_directory.to_path_buf()));
    }
    match fs::symlink_metadata(target_directory) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(M7OperatorError::UnsafePath(target_directory.to_path_buf()));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = target_directory
                .parent()
                .ok_or_else(|| M7OperatorError::UnsafePath(target_directory.to_path_buf()))?;
            let parent =
                fs::canonicalize(parent).map_err(|error| M7OperatorError::io(parent, error))?;
            let leaf = target_directory
                .file_name()
                .filter(|name| !name.is_empty())
                .ok_or_else(|| M7OperatorError::UnsafePath(target_directory.to_path_buf()))?;
            let resolved = parent.join(leaf);
            fs::create_dir(&resolved).map_err(|error| M7OperatorError::io(&resolved, error))?;
        }
        Err(error) => return Err(M7OperatorError::io(target_directory, error)),
    }
    let target_directory = fs::canonicalize(target_directory)
        .map_err(|error| M7OperatorError::io(target_directory, error))?;
    let checkout_root = fs::canonicalize(checkout_root)
        .map_err(|error| M7OperatorError::io(checkout_root, error))?;
    if target_directory.starts_with(&checkout_root) || checkout_root.starts_with(&target_directory)
    {
        return Err(M7OperatorError::UnsafePath(target_directory));
    }
    let mut entries = fs::read_dir(&target_directory)
        .map_err(|error| M7OperatorError::io(&target_directory, error))?;
    if entries
        .next()
        .transpose()
        .map_err(|error| M7OperatorError::io(&target_directory, error))?
        .is_some()
    {
        return Err(M7OperatorError::Conflict(format!(
            "Cargo target directory '{}' is not empty",
            target_directory.display()
        )));
    }
    Ok(target_directory)
}

/// Execute the exact release command from the manifest-pinned checkout.
///
/// The checkout is independently inspected immediately before and after the
/// process, and the target directory must be fresh, empty, absolute, and
/// outside the checkout. A failing Cargo exit is retained as evidence rather
/// than converted into an operator error.
pub fn run_cargo_test_to_file(
    checkout: &Path,
    manifest_path: &Path,
    target_directory: &Path,
    output: &Path,
) -> Result<(), M7OperatorError> {
    let manifest = load_manifest(manifest_path)?;
    let before = inspect_source_checkout(checkout)?;
    if &before.source_identity != manifest.source_identity() {
        return Err(M7OperatorError::Conflict(
            "Cargo checkout identity differs from the proof-run manifest".to_string(),
        ));
    }
    ensure_output_outside_checkout(output, checkout)?;
    let target_directory = prepare_empty_target_directory(target_directory, checkout)?;
    let command = vec![
        "test".to_string(),
        "--locked".to_string(),
        "--all-targets".to_string(),
    ];
    let environment = before
        .toolchain
        .build_environment_policy
        .process_environment(Some(&target_directory));
    before.toolchain.cargo.executable.verify_current()?;
    before.toolchain.rustc.executable.verify_current()?;
    let capture_result = run_process(
        &before.toolchain.cargo.executable.canonical_path,
        &command,
        Path::new(&before.checkout_root),
        None,
        ProcessOutputLimits::with_combined(
            MAX_TRANSCRIPT_STREAM_BYTES,
            MAX_TRANSCRIPT_STREAM_BYTES,
            MAX_TRANSCRIPT_CONTENT_BYTES,
        ),
        CARGO_TEST_PROCESS_TIMEOUT,
        true,
        false,
        false,
        ProcessOutputDiagnosticPolicy::CargoLibtestFailureNames,
        &environment,
    );
    let cargo_verification = before.toolchain.cargo.executable.verify_current();
    let rustc_verification = before.toolchain.rustc.executable.verify_current();
    let after_result = inspect_source_checkout(checkout);
    cargo_verification?;
    rustc_verification?;
    let after = after_result?;
    if after != before {
        return Err(M7OperatorError::Conflict(
            "source checkout or toolchain identity changed during Cargo execution".to_string(),
        ));
    }
    let capture = capture_result?;
    let transcript = create_cargo_transcript(
        &manifest,
        capture.stdout,
        capture.stderr,
        capture.status.unwrap_or(-1),
    )?;
    let bytes = transcript
        .canonical_bytes()
        .map_err(|error| M7OperatorError::Foundation(error.to_string()))?;
    persist_no_clobber_or_identical(output, &bytes, MAX_TRANSCRIPT_FILE_BYTES)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M7SourceCaptureSigningRequestV1 {
    pub schema: String,
    pub manifest_digest: ContentDigest,
    pub transcript_digest: ContentDigest,
    pub transcript_byte_length: u64,
    pub captured_at_ms: u64,
    pub source_links: Vec<M7SourceLinkV2>,
    pub source_inventory_digest: ContentDigest,
    pub signing_preimage_digest: ContentDigest,
    pub request_digest: ContentDigest,
}

#[derive(Serialize)]
struct SourceCaptureSigningRequestDigestMaterial<'a> {
    domain: &'static str,
    manifest_digest: &'a ContentDigest,
    transcript_digest: &'a ContentDigest,
    transcript_byte_length: u64,
    captured_at_ms: u64,
    source_links: &'a [M7SourceLinkV2],
    source_inventory_digest: &'a ContentDigest,
    signing_preimage_digest: &'a ContentDigest,
}

impl M7SourceCaptureSigningRequestV1 {
    fn new(
        manifest_digest: ContentDigest,
        transcript_bytes: &[u8],
        captured_at_ms: u64,
        source_links: Vec<M7SourceLinkV2>,
        preimage: &[u8],
    ) -> Result<Self, M7OperatorError> {
        if captured_at_ms == 0 || source_links.is_empty() {
            return Err(M7OperatorError::InvalidInput(
                "source-capture signing request needs a nonzero time and nonempty inventory"
                    .to_string(),
            ));
        }
        let source_inventory_digest = digest_json(&(
            SOURCE_CAPTURE_REQUEST_DIGEST_DOMAIN,
            "source-inventory",
            &source_links,
        ))?;
        let mut request = Self {
            schema: M7_SOURCE_CAPTURE_SIGNING_REQUEST_SCHEMA.to_string(),
            manifest_digest,
            transcript_digest: ContentDigest::from_bytes(transcript_bytes),
            transcript_byte_length: transcript_bytes.len() as u64,
            captured_at_ms,
            source_links,
            source_inventory_digest,
            signing_preimage_digest: ContentDigest::from_bytes(preimage),
            request_digest: ContentDigest::from_bytes(&[]),
        };
        request.request_digest = request.expected_digest()?;
        request.validate()?;
        Ok(request)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, M7OperatorError> {
        self.validate()?;
        canonical_json_bytes(self)
    }

    fn validate(&self) -> Result<(), M7OperatorError> {
        if self.schema != M7_SOURCE_CAPTURE_SIGNING_REQUEST_SCHEMA
            || self.captured_at_ms == 0
            || self.transcript_byte_length == 0
            || self.source_links.is_empty()
        {
            return Err(M7OperatorError::InvalidInput(
                "invalid source-capture signing request fields".to_string(),
            ));
        }
        let mut sorted = self.source_links.clone();
        sorted.sort_by(|left, right| {
            (left.semantic_role, &left.digest).cmp(&(right.semantic_role, &right.digest))
        });
        if sorted != self.source_links {
            return Err(M7OperatorError::InvalidInput(
                "source-capture inventory is not canonically ordered".to_string(),
            ));
        }
        let expected_inventory = digest_json(&(
            SOURCE_CAPTURE_REQUEST_DIGEST_DOMAIN,
            "source-inventory",
            &self.source_links,
        ))?;
        if self.source_inventory_digest != expected_inventory
            || self.request_digest != self.expected_digest()?
        {
            return Err(M7OperatorError::InvalidInput(
                "source-capture signing request digest is stale".to_string(),
            ));
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, M7OperatorError> {
        digest_json(&SourceCaptureSigningRequestDigestMaterial {
            domain: SOURCE_CAPTURE_REQUEST_DIGEST_DOMAIN,
            manifest_digest: &self.manifest_digest,
            transcript_digest: &self.transcript_digest,
            transcript_byte_length: self.transcript_byte_length,
            captured_at_ms: self.captured_at_ms,
            source_links: &self.source_links,
            source_inventory_digest: &self.source_inventory_digest,
            signing_preimage_digest: &self.signing_preimage_digest,
        })
    }
}

pub fn prepare_source_capture(
    dossier_root: &Path,
    transcript_bytes: &[u8],
    captured_at_ms: u64,
) -> Result<(M7SourceCaptureSigningRequestV1, Vec<u8>), M7OperatorError> {
    let runtime = M7DossierRuntime::reopen(dossier_root)
        .map_err(|error| M7OperatorError::Dossier(error.to_string()))?;
    if captured_at_ms <= runtime.manifest().run_started_at_ms() {
        return Err(M7OperatorError::InvalidInput(
            "source-capture time must be later than the manifest run-start time".to_string(),
        ));
    }
    let source_links = runtime
        .source_capture_inventory(transcript_bytes)
        .map_err(|error| M7OperatorError::Dossier(error.to_string()))?;
    let preimage = runtime
        .source_capture_signing_preimage(transcript_bytes, captured_at_ms)
        .map_err(|error| M7OperatorError::Dossier(error.to_string()))?;
    let request = M7SourceCaptureSigningRequestV1::new(
        runtime.manifest().manifest_digest().clone(),
        transcript_bytes,
        captured_at_ms,
        source_links,
        &preimage,
    )?;
    Ok((request, preimage))
}

pub fn prepare_source_capture_to_files(
    dossier_root: &Path,
    transcript_path: &Path,
    captured_at_ms: u64,
    request_output: &Path,
    preimage_output: &Path,
) -> Result<(), M7OperatorError> {
    let transcript = read_regular_bounded(transcript_path, MAX_TRANSCRIPT_FILE_BYTES)?;
    let (request, preimage) = prepare_source_capture(dossier_root, &transcript, captured_at_ms)?;
    persist_no_clobber_or_identical(
        request_output,
        &request.canonical_bytes()?,
        MAX_REQUEST_BYTES,
    )?;
    persist_no_clobber_or_identical(preimage_output, &preimage, MAX_REQUEST_BYTES)
}

pub fn accept_source_capture(
    dossier_root: &Path,
    request: &M7SourceCaptureSigningRequestV1,
    transcript_bytes: &[u8],
    signature: &[u8],
) -> Result<M7EvidenceLink, M7OperatorError> {
    request.validate()?;
    if signature.len() != MAX_SIGNATURE_BYTES {
        return Err(M7OperatorError::InvalidInput(
            "source-custodian signature must be exactly 64 raw Ed25519 bytes".to_string(),
        ));
    }
    if transcript_bytes.len() as u64 != request.transcript_byte_length
        || ContentDigest::from_bytes(transcript_bytes) != request.transcript_digest
    {
        return Err(M7OperatorError::InvalidInput(
            "Cargo transcript differs from the source-capture signing request".to_string(),
        ));
    }
    let mut runtime = M7DossierRuntime::reopen(dossier_root)
        .map_err(|error| M7OperatorError::Dossier(error.to_string()))?;
    if runtime.manifest().manifest_digest() != &request.manifest_digest {
        return Err(M7OperatorError::InvalidInput(
            "source-capture signing request names another manifest".to_string(),
        ));
    }
    let inventory = runtime
        .source_capture_inventory(transcript_bytes)
        .map_err(|error| M7OperatorError::Dossier(error.to_string()))?;
    if inventory != request.source_links {
        return Err(M7OperatorError::Conflict(
            "dossier source inventory changed after capture preimage export".to_string(),
        ));
    }
    let preimage = runtime
        .source_capture_signing_preimage(transcript_bytes, request.captured_at_ms)
        .map_err(|error| M7OperatorError::Dossier(error.to_string()))?;
    if ContentDigest::from_bytes(&preimage) != request.signing_preimage_digest {
        return Err(M7OperatorError::Conflict(
            "source-capture signing preimage changed after export".to_string(),
        ));
    }
    runtime
        .admit_source_capture_signature(transcript_bytes, request.captured_at_ms, signature)
        .map_err(|error| M7OperatorError::Dossier(error.to_string()))
}

pub fn accept_source_capture_from_files(
    dossier_root: &Path,
    request_path: &Path,
    transcript_path: &Path,
    signature_path: &Path,
    output: &Path,
) -> Result<(), M7OperatorError> {
    let request: M7SourceCaptureSigningRequestV1 = read_json_file(request_path, MAX_REQUEST_BYTES)?;
    let transcript = read_regular_bounded(transcript_path, MAX_TRANSCRIPT_FILE_BYTES)?;
    let signature = read_regular_bounded(signature_path, MAX_SIGNATURE_BYTES)?;
    let link = accept_source_capture(dossier_root, &request, &transcript, &signature)?;
    persist_no_clobber_or_identical(output, &canonical_json_bytes(&link)?, MAX_OUTPUT_BYTES)
}

pub fn begin_independent_review(
    dossier_root: &Path,
) -> Result<M7IndependentReviewRequest, M7OperatorError> {
    let mut runtime = M7DossierRuntime::reopen(dossier_root)
        .map_err(|error| M7OperatorError::Dossier(error.to_string()))?;
    runtime
        .begin_independent_review()
        .map_err(|error| M7OperatorError::Dossier(error.to_string()))
}

pub fn begin_independent_review_to_file(
    dossier_root: &Path,
    output: &Path,
) -> Result<(), M7OperatorError> {
    let request = begin_independent_review(dossier_root)?;
    let bytes = request
        .canonical_bytes()
        .map_err(|error| M7OperatorError::Dossier(error.to_string()))?;
    persist_no_clobber_or_identical(output, &bytes, MAX_REQUEST_BYTES)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M7ReviewSigningRequestV1 {
    pub schema: String,
    pub manifest_digest: ContentDigest,
    pub review_request_digest: ContentDigest,
    pub recommendation: M7ClosureDecision,
    pub rationale_digest: ContentDigest,
    pub rationale_byte_length: u64,
    pub independence_statement_digest: ContentDigest,
    pub independence_statement_byte_length: u64,
    pub signing_preimage_digest: ContentDigest,
    pub request_digest: ContentDigest,
}

#[derive(Serialize)]
struct ReviewSigningRequestDigestMaterial<'a> {
    domain: &'static str,
    manifest_digest: &'a ContentDigest,
    review_request_digest: &'a ContentDigest,
    recommendation: M7ClosureDecision,
    rationale_digest: &'a ContentDigest,
    rationale_byte_length: u64,
    independence_statement_digest: &'a ContentDigest,
    independence_statement_byte_length: u64,
    signing_preimage_digest: &'a ContentDigest,
}

impl M7ReviewSigningRequestV1 {
    #[allow(clippy::too_many_arguments)]
    fn new(
        manifest_digest: ContentDigest,
        review_request_digest: ContentDigest,
        recommendation: M7ClosureDecision,
        rationale: &[u8],
        independence_statement: &[u8],
        preimage: &[u8],
    ) -> Result<Self, M7OperatorError> {
        validate_review_text(rationale, "reviewer rationale")?;
        validate_review_text(independence_statement, "reviewer independence statement")?;
        let mut request = Self {
            schema: M7_REVIEW_SIGNING_REQUEST_SCHEMA.to_string(),
            manifest_digest,
            review_request_digest,
            recommendation,
            rationale_digest: ContentDigest::from_bytes(rationale),
            rationale_byte_length: rationale.len() as u64,
            independence_statement_digest: ContentDigest::from_bytes(independence_statement),
            independence_statement_byte_length: independence_statement.len() as u64,
            signing_preimage_digest: ContentDigest::from_bytes(preimage),
            request_digest: ContentDigest::from_bytes(&[]),
        };
        request.request_digest = request.expected_digest()?;
        request.validate()?;
        Ok(request)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, M7OperatorError> {
        self.validate()?;
        canonical_json_bytes(self)
    }

    fn validate(&self) -> Result<(), M7OperatorError> {
        if self.schema != M7_REVIEW_SIGNING_REQUEST_SCHEMA
            || self.rationale_byte_length == 0
            || self.rationale_byte_length > MAX_REVIEW_TEXT_BYTES as u64
            || self.independence_statement_byte_length == 0
            || self.independence_statement_byte_length > MAX_REVIEW_TEXT_BYTES as u64
            || self.request_digest != self.expected_digest()?
        {
            return Err(M7OperatorError::InvalidInput(
                "invalid or stale independent-review signing request".to_string(),
            ));
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, M7OperatorError> {
        digest_json(&ReviewSigningRequestDigestMaterial {
            domain: REVIEW_SIGNING_REQUEST_DIGEST_DOMAIN,
            manifest_digest: &self.manifest_digest,
            review_request_digest: &self.review_request_digest,
            recommendation: self.recommendation,
            rationale_digest: &self.rationale_digest,
            rationale_byte_length: self.rationale_byte_length,
            independence_statement_digest: &self.independence_statement_digest,
            independence_statement_byte_length: self.independence_statement_byte_length,
            signing_preimage_digest: &self.signing_preimage_digest,
        })
    }
}

fn validate_review_text(bytes: &[u8], label: &str) -> Result<(), M7OperatorError> {
    if bytes.is_empty() || bytes.len() > MAX_REVIEW_TEXT_BYTES {
        return Err(M7OperatorError::ResourceExhausted(format!(
            "{label} must contain 1..={MAX_REVIEW_TEXT_BYTES} bytes"
        )));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|error| M7OperatorError::InvalidInput(format!("{label} is not UTF-8: {error}")))?;
    if text.trim().is_empty() {
        return Err(M7OperatorError::InvalidInput(format!(
            "{label} cannot be blank"
        )));
    }
    Ok(())
}

pub fn prepare_independent_review(
    dossier_root: &Path,
    recommendation: M7ClosureDecision,
    rationale: &[u8],
    independence_statement: &[u8],
) -> Result<(M7ReviewSigningRequestV1, Vec<u8>), M7OperatorError> {
    validate_review_text(rationale, "reviewer rationale")?;
    validate_review_text(independence_statement, "reviewer independence statement")?;
    let runtime = M7DossierRuntime::reopen(dossier_root)
        .map_err(|error| M7OperatorError::Dossier(error.to_string()))?;
    let review_request = runtime.review_request().ok_or_else(|| {
        M7OperatorError::InvalidInput(
            "independent review has not been begun for this dossier".to_string(),
        )
    })?;
    let rationale_digest = ContentDigest::from_bytes(rationale);
    let independence_statement_digest = ContentDigest::from_bytes(independence_statement);
    let preimage = runtime
        .independent_review_signing_preimage(
            recommendation,
            rationale_digest,
            independence_statement_digest,
        )
        .map_err(|error| M7OperatorError::Dossier(error.to_string()))?;
    let signing_request = M7ReviewSigningRequestV1::new(
        runtime.manifest().manifest_digest().clone(),
        review_request.request_digest().clone(),
        recommendation,
        rationale,
        independence_statement,
        &preimage,
    )?;
    Ok((signing_request, preimage))
}

pub fn prepare_independent_review_to_files(
    dossier_root: &Path,
    recommendation: M7ClosureDecision,
    rationale_path: &Path,
    independence_statement_path: &Path,
    request_output: &Path,
    preimage_output: &Path,
) -> Result<(), M7OperatorError> {
    let rationale = read_regular_bounded(rationale_path, MAX_REVIEW_TEXT_BYTES)?;
    let independence = read_regular_bounded(independence_statement_path, MAX_REVIEW_TEXT_BYTES)?;
    let (request, preimage) =
        prepare_independent_review(dossier_root, recommendation, &rationale, &independence)?;
    persist_no_clobber_or_identical(
        request_output,
        &request.canonical_bytes()?,
        MAX_REQUEST_BYTES,
    )?;
    persist_no_clobber_or_identical(preimage_output, &preimage, MAX_REQUEST_BYTES)
}

pub fn accept_independent_review(
    dossier_root: &Path,
    request: &M7ReviewSigningRequestV1,
    signature: &[u8],
) -> Result<M7EvidenceLink, M7OperatorError> {
    request.validate()?;
    if signature.len() != MAX_SIGNATURE_BYTES {
        return Err(M7OperatorError::InvalidInput(
            "reviewer signature must be exactly 64 raw Ed25519 bytes".to_string(),
        ));
    }
    let mut runtime = M7DossierRuntime::reopen(dossier_root)
        .map_err(|error| M7OperatorError::Dossier(error.to_string()))?;
    if runtime.manifest().manifest_digest() != &request.manifest_digest {
        return Err(M7OperatorError::InvalidInput(
            "review signing request names another manifest".to_string(),
        ));
    }
    let review_request = runtime.review_request().ok_or_else(|| {
        M7OperatorError::InvalidInput(
            "dossier has no frozen independent-review request".to_string(),
        )
    })?;
    if review_request.request_digest() != &request.review_request_digest {
        return Err(M7OperatorError::Conflict(
            "dossier review request changed after signing preimage export".to_string(),
        ));
    }
    let preimage = runtime
        .independent_review_signing_preimage(
            request.recommendation,
            request.rationale_digest.clone(),
            request.independence_statement_digest.clone(),
        )
        .map_err(|error| M7OperatorError::Dossier(error.to_string()))?;
    if ContentDigest::from_bytes(&preimage) != request.signing_preimage_digest {
        return Err(M7OperatorError::Conflict(
            "review signing preimage changed after export".to_string(),
        ));
    }
    runtime
        .admit_independent_review_signature(
            request.recommendation,
            request.rationale_digest.clone(),
            request.independence_statement_digest.clone(),
            signature,
        )
        .map_err(|error| M7OperatorError::Dossier(error.to_string()))
}

pub fn accept_independent_review_from_files(
    dossier_root: &Path,
    request_path: &Path,
    signature_path: &Path,
    output: &Path,
) -> Result<(), M7OperatorError> {
    let request: M7ReviewSigningRequestV1 = read_json_file(request_path, MAX_REQUEST_BYTES)?;
    let signature = read_regular_bounded(signature_path, MAX_SIGNATURE_BYTES)?;
    let link = accept_independent_review(dossier_root, &request, &signature)?;
    persist_no_clobber_or_identical(output, &canonical_json_bytes(&link)?, MAX_OUTPUT_BYTES)
}

pub fn finalize_dossier(dossier_root: &Path) -> Result<M7FinalBundle, M7OperatorError> {
    let mut runtime = M7DossierRuntime::reopen(dossier_root)
        .map_err(|error| M7OperatorError::Dossier(error.to_string()))?;
    runtime
        .finalize()
        .map_err(|error| M7OperatorError::Dossier(error.to_string()))
}

pub fn finalize_dossier_to_file(dossier_root: &Path, output: &Path) -> Result<(), M7OperatorError> {
    let bundle = finalize_dossier(dossier_root)?;
    let bytes = bundle
        .canonical_bytes()
        .map_err(|error| M7OperatorError::Foundation(error.to_string()))?;
    persist_no_clobber_or_identical(output, &bytes, MAX_OUTPUT_BYTES)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum M7LiveProviderStatusV1 {
    NotScoped,
    ScopedButNotProvided,
    Qualified,
    Invalid,
}

impl From<LiveProviderQualificationStatus> for M7LiveProviderStatusV1 {
    fn from(value: LiveProviderQualificationStatus) -> Self {
        match value {
            LiveProviderQualificationStatus::NotScoped => Self::NotScoped,
            LiveProviderQualificationStatus::ScopedButNotProvided => Self::ScopedButNotProvided,
            LiveProviderQualificationStatus::Qualified => Self::Qualified,
            LiveProviderQualificationStatus::Invalid => Self::Invalid,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum M7BlockerCodeV1 {
    InvalidBundle,
    MissingEvidenceLink,
    MissingEvidenceBytes,
    ResolverFailure,
    LengthMismatch,
    DigestMismatch,
    MalformedEvidence,
    NonCanonicalEvidence,
    SchemaMismatch,
    OwnerMismatch,
    CrossRunEvidence,
    StaleManifestEvidence,
    CausalMismatch,
    MissingAuthoritativeSource,
    MissingSourceBytes,
    SourceResolverFailure,
    SourceLengthMismatch,
    SourceDigestMismatch,
    InvalidAuthoritativeSource,
    SourcePayloadMismatch,
    ActiveSurfaceSnapshotMismatch,
    M5ExportLineageMismatch,
    M2M4LineageMismatch,
    ClosureChronologyMismatch,
    SourceClosureMismatch,
    SourceSelfReference,
    SemanticFailure,
    ReviewerAbsent,
    ReviewerNotIndependent,
    ReviewerScopeMismatch,
    LiveProviderScopeMismatch,
    LiveProviderCandidateIdentityMismatch,
    LiveProviderQualificationIncomplete,
    SourceCaptureAttestationAbsent,
    SourceCaptureInventoryFailure,
    SourceCaptureIdentityNotIndependent,
    ReviewerCryptographicAttestationAbsent,
    ReviewerCryptographicAttestationInvalid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum M7SourceCaptureInventoryFailureCodeV1 {
    MissingRole,
    UnexpectedRole,
    ForbiddenRole,
    DuplicateRole,
    NonCanonicalOrder,
    RelabeledRole,
    CrossRunRole,
    StaleManifestRole,
    CausalMismatch,
    InvalidLink,
    LinkMismatch,
    AttestationUnavailable,
    AttestationInvalid,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M7BlockerReportV1 {
    pub code: M7BlockerCodeV1,
    pub evidence_kind: Option<M7EvidenceKind>,
    pub source_role: Option<M7SourceRoleV2>,
    pub semantic_failure: Option<M7SemanticFailure>,
    pub source_capture_inventory_failure: Option<M7SourceCaptureInventoryFailureCodeV1>,
    pub live_provider_status: Option<M7LiveProviderStatusV1>,
    pub detail: Option<String>,
    pub m1_incumbent_package_digest: Option<ContentDigest>,
    pub m1_candidate_package_digest: Option<ContentDigest>,
    pub provider_incumbent_package_digest: Option<ContentDigest>,
    pub provider_target_package_digest: Option<ContentDigest>,
}

impl M7BlockerReportV1 {
    fn bare(code: M7BlockerCodeV1) -> Self {
        Self {
            code,
            evidence_kind: None,
            source_role: None,
            semantic_failure: None,
            source_capture_inventory_failure: None,
            live_provider_status: None,
            detail: None,
            m1_incumbent_package_digest: None,
            m1_candidate_package_digest: None,
            provider_incumbent_package_digest: None,
            provider_target_package_digest: None,
        }
    }
}

fn kind_blocker(code: M7BlockerCodeV1, kind: M7EvidenceKind) -> M7BlockerReportV1 {
    let mut report = M7BlockerReportV1::bare(code);
    report.evidence_kind = Some(kind);
    report
}

fn source_blocker(
    code: M7BlockerCodeV1,
    kind: M7EvidenceKind,
    role: M7SourceRoleV2,
) -> M7BlockerReportV1 {
    let mut report = kind_blocker(code, kind);
    report.source_role = Some(role);
    report
}

fn blocker_report(blocker: M7Blocker) -> M7BlockerReportV1 {
    match blocker {
        M7Blocker::InvalidBundle(detail) => {
            let mut report = M7BlockerReportV1::bare(M7BlockerCodeV1::InvalidBundle);
            report.detail = Some(detail);
            report
        }
        M7Blocker::MissingEvidenceLink(kind) => {
            kind_blocker(M7BlockerCodeV1::MissingEvidenceLink, kind)
        }
        M7Blocker::MissingEvidenceBytes(kind) => {
            kind_blocker(M7BlockerCodeV1::MissingEvidenceBytes, kind)
        }
        M7Blocker::ResolverFailure(kind) => kind_blocker(M7BlockerCodeV1::ResolverFailure, kind),
        M7Blocker::LengthMismatch(kind) => kind_blocker(M7BlockerCodeV1::LengthMismatch, kind),
        M7Blocker::DigestMismatch(kind) => kind_blocker(M7BlockerCodeV1::DigestMismatch, kind),
        M7Blocker::MalformedEvidence(kind) => {
            kind_blocker(M7BlockerCodeV1::MalformedEvidence, kind)
        }
        M7Blocker::NonCanonicalEvidence(kind) => {
            kind_blocker(M7BlockerCodeV1::NonCanonicalEvidence, kind)
        }
        M7Blocker::SchemaMismatch(kind) => kind_blocker(M7BlockerCodeV1::SchemaMismatch, kind),
        M7Blocker::OwnerMismatch(kind) => kind_blocker(M7BlockerCodeV1::OwnerMismatch, kind),
        M7Blocker::CrossRunEvidence(kind) => kind_blocker(M7BlockerCodeV1::CrossRunEvidence, kind),
        M7Blocker::StaleManifestEvidence(kind) => {
            kind_blocker(M7BlockerCodeV1::StaleManifestEvidence, kind)
        }
        M7Blocker::CausalMismatch(kind) => kind_blocker(M7BlockerCodeV1::CausalMismatch, kind),
        M7Blocker::MissingAuthoritativeSource(kind) => {
            kind_blocker(M7BlockerCodeV1::MissingAuthoritativeSource, kind)
        }
        M7Blocker::MissingSourceBytes { kind, role } => {
            source_blocker(M7BlockerCodeV1::MissingSourceBytes, kind, role)
        }
        M7Blocker::SourceResolverFailure { kind, role } => {
            source_blocker(M7BlockerCodeV1::SourceResolverFailure, kind, role)
        }
        M7Blocker::SourceLengthMismatch { kind, role } => {
            source_blocker(M7BlockerCodeV1::SourceLengthMismatch, kind, role)
        }
        M7Blocker::SourceDigestMismatch { kind, role } => {
            source_blocker(M7BlockerCodeV1::SourceDigestMismatch, kind, role)
        }
        M7Blocker::InvalidAuthoritativeSource { kind, role } => {
            let mut report = kind_blocker(M7BlockerCodeV1::InvalidAuthoritativeSource, kind);
            report.source_role = role;
            report
        }
        M7Blocker::SourcePayloadMismatch(kind) => {
            kind_blocker(M7BlockerCodeV1::SourcePayloadMismatch, kind)
        }
        M7Blocker::ActiveSurfaceSnapshotMismatch => {
            M7BlockerReportV1::bare(M7BlockerCodeV1::ActiveSurfaceSnapshotMismatch)
        }
        M7Blocker::M5ExportLineageMismatch => {
            M7BlockerReportV1::bare(M7BlockerCodeV1::M5ExportLineageMismatch)
        }
        M7Blocker::M2M4LineageMismatch => {
            M7BlockerReportV1::bare(M7BlockerCodeV1::M2M4LineageMismatch)
        }
        M7Blocker::ClosureChronologyMismatch => {
            M7BlockerReportV1::bare(M7BlockerCodeV1::ClosureChronologyMismatch)
        }
        M7Blocker::SourceClosureMismatch => {
            M7BlockerReportV1::bare(M7BlockerCodeV1::SourceClosureMismatch)
        }
        M7Blocker::SourceSelfReference(kind) => {
            kind_blocker(M7BlockerCodeV1::SourceSelfReference, kind)
        }
        M7Blocker::SemanticFailure { kind, failure } => {
            let mut report = kind_blocker(M7BlockerCodeV1::SemanticFailure, kind);
            report.semantic_failure = Some(failure);
            report
        }
        M7Blocker::ReviewerAbsent => M7BlockerReportV1::bare(M7BlockerCodeV1::ReviewerAbsent),
        M7Blocker::ReviewerNotIndependent => {
            M7BlockerReportV1::bare(M7BlockerCodeV1::ReviewerNotIndependent)
        }
        M7Blocker::ReviewerScopeMismatch => {
            M7BlockerReportV1::bare(M7BlockerCodeV1::ReviewerScopeMismatch)
        }
        M7Blocker::LiveProviderScopeMismatch => {
            M7BlockerReportV1::bare(M7BlockerCodeV1::LiveProviderScopeMismatch)
        }
        M7Blocker::LiveProviderCandidateIdentityMismatch {
            m1_incumbent_package_digest,
            m1_candidate_package_digest,
            provider_incumbent_package_digest,
            provider_target_package_digest,
        } => {
            let mut report =
                M7BlockerReportV1::bare(M7BlockerCodeV1::LiveProviderCandidateIdentityMismatch);
            report.m1_incumbent_package_digest = m1_incumbent_package_digest;
            report.m1_candidate_package_digest = m1_candidate_package_digest;
            report.provider_incumbent_package_digest = Some(provider_incumbent_package_digest);
            report.provider_target_package_digest = Some(provider_target_package_digest);
            report
        }
        M7Blocker::LiveProviderQualificationIncomplete(status) => {
            let mut report =
                M7BlockerReportV1::bare(M7BlockerCodeV1::LiveProviderQualificationIncomplete);
            report.live_provider_status = Some(status.into());
            report
        }
        M7Blocker::SourceCaptureAttestationAbsent => {
            M7BlockerReportV1::bare(M7BlockerCodeV1::SourceCaptureAttestationAbsent)
        }
        M7Blocker::SourceCaptureInventoryFailure(failure) => {
            let mut report =
                M7BlockerReportV1::bare(M7BlockerCodeV1::SourceCaptureInventoryFailure);
            let (code, role) = match failure {
                M7SourceCaptureInventoryFailure::MissingRole(role) => (
                    M7SourceCaptureInventoryFailureCodeV1::MissingRole,
                    Some(role),
                ),
                M7SourceCaptureInventoryFailure::UnexpectedRole(role) => (
                    M7SourceCaptureInventoryFailureCodeV1::UnexpectedRole,
                    Some(role),
                ),
                M7SourceCaptureInventoryFailure::ForbiddenRole(role) => (
                    M7SourceCaptureInventoryFailureCodeV1::ForbiddenRole,
                    Some(role),
                ),
                M7SourceCaptureInventoryFailure::DuplicateRole(role) => (
                    M7SourceCaptureInventoryFailureCodeV1::DuplicateRole,
                    Some(role),
                ),
                M7SourceCaptureInventoryFailure::NonCanonicalOrder => (
                    M7SourceCaptureInventoryFailureCodeV1::NonCanonicalOrder,
                    None,
                ),
                M7SourceCaptureInventoryFailure::RelabeledRole(role) => (
                    M7SourceCaptureInventoryFailureCodeV1::RelabeledRole,
                    Some(role),
                ),
                M7SourceCaptureInventoryFailure::CrossRunRole(role) => (
                    M7SourceCaptureInventoryFailureCodeV1::CrossRunRole,
                    Some(role),
                ),
                M7SourceCaptureInventoryFailure::StaleManifestRole(role) => (
                    M7SourceCaptureInventoryFailureCodeV1::StaleManifestRole,
                    Some(role),
                ),
                M7SourceCaptureInventoryFailure::CausalMismatch(role) => (
                    M7SourceCaptureInventoryFailureCodeV1::CausalMismatch,
                    Some(role),
                ),
                M7SourceCaptureInventoryFailure::InvalidLink(role) => (
                    M7SourceCaptureInventoryFailureCodeV1::InvalidLink,
                    Some(role),
                ),
                M7SourceCaptureInventoryFailure::LinkMismatch(role) => (
                    M7SourceCaptureInventoryFailureCodeV1::LinkMismatch,
                    Some(role),
                ),
                M7SourceCaptureInventoryFailure::AttestationUnavailable => (
                    M7SourceCaptureInventoryFailureCodeV1::AttestationUnavailable,
                    None,
                ),
                M7SourceCaptureInventoryFailure::AttestationInvalid => (
                    M7SourceCaptureInventoryFailureCodeV1::AttestationInvalid,
                    None,
                ),
            };
            report.source_capture_inventory_failure = Some(code);
            report.source_role = role;
            report
        }
        M7Blocker::SourceCaptureIdentityNotIndependent => {
            M7BlockerReportV1::bare(M7BlockerCodeV1::SourceCaptureIdentityNotIndependent)
        }
        M7Blocker::ReviewerCryptographicAttestationAbsent => {
            M7BlockerReportV1::bare(M7BlockerCodeV1::ReviewerCryptographicAttestationAbsent)
        }
        M7Blocker::ReviewerCryptographicAttestationInvalid => {
            M7BlockerReportV1::bare(M7BlockerCodeV1::ReviewerCryptographicAttestationInvalid)
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M7EvaluationReportV1 {
    pub schema: String,
    pub decision: M7ClosureDecision,
    pub evidence_complete: bool,
    pub reviewer_recommendation: Option<M7ClosureDecision>,
    pub caveats: BTreeSet<M7EvaluationCaveatV1>,
    pub verified_kinds: BTreeSet<M7EvidenceKind>,
    pub blockers: Vec<M7BlockerReportV1>,
    pub bundle_digest: ContentDigest,
    pub live_provider_status: M7LiveProviderStatusV1,
}

impl From<M7Evaluation> for M7EvaluationReportV1 {
    fn from(evaluation: M7Evaluation) -> Self {
        Self {
            schema: M7_EVALUATION_REPORT_SCHEMA.to_string(),
            decision: evaluation.decision,
            evidence_complete: evaluation.evidence_complete,
            reviewer_recommendation: evaluation.reviewer_recommendation,
            caveats: evaluation.caveats,
            verified_kinds: evaluation.verified_kinds,
            blockers: evaluation
                .blockers
                .into_iter()
                .map(blocker_report)
                .collect(),
            bundle_digest: evaluation.bundle_digest,
            live_provider_status: evaluation.live_provider_status.into(),
        }
    }
}

/// Reopen from persisted bytes and return the stable operator wire projection.
pub fn reopen_and_evaluate(dossier_root: &Path) -> Result<M7EvaluationReportV1, M7OperatorError> {
    let runtime = M7DossierRuntime::reopen(dossier_root)
        .map_err(|error| M7OperatorError::Dossier(error.to_string()))?;
    let evaluation = runtime
        .evaluate_final()
        .map_err(|error| M7OperatorError::Dossier(error.to_string()))?;
    Ok(evaluation.into())
}

pub fn reopen_and_evaluate_to_file(
    dossier_root: &Path,
    output: &Path,
) -> Result<M7EvaluationReportV1, M7OperatorError> {
    let report = reopen_and_evaluate(dossier_root)?;
    persist_no_clobber_or_identical(output, &canonical_json_bytes(&report)?, MAX_OUTPUT_BYTES)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn executable_fixture(program: &str) -> M7ExecutableIdentityV1 {
        M7ExecutableIdentityV1 {
            invocation_path: format!("/tmp/m7-fixture-tools/{program}"),
            canonical_path: format!("/tmp/m7-fixture-tools/{program}"),
            invocation_symlink_target: None,
            byte_length: 1,
            content_digest: ContentDigest::from_bytes(program.as_bytes()),
        }
    }

    fn command_fixture(program: &str, args: &[&str]) -> M7ToolchainCommandRecordV1 {
        let executable = executable_fixture(program);
        M7ToolchainCommandRecordV1 {
            logical_program: program.to_string(),
            resolver: executable.clone(),
            executable: executable.clone(),
            command: std::iter::once(executable.canonical_path)
                .chain(args.iter().map(|arg| (*arg).to_string()))
                .collect(),
            stdout: format!("{program} 1.fixture\n"),
            stderr: String::new(),
            exit_code: 0,
        }
    }

    fn source_fixture() -> M7SourceInspectionV1 {
        let lock_bytes = b"# fixture Cargo.lock\n";
        let inventory = M7TrackedInventoryV1::new(vec![M7TrackedSourceEntryV1 {
            path: "Cargo.lock".to_string(),
            mode: "100644".to_string(),
            blob_oid: "a".repeat(40),
            byte_length: lock_bytes.len() as u64,
            content_digest: ContentDigest::from_bytes(lock_bytes),
        }])
        .expect("fixture tracked inventory");
        let recipe = M7SourceIdentityRecipeV1::default();
        let rustc = command_fixture("rustc", &["--version", "--verbose"]);
        let policy = M7BuildEnvironmentPolicyV1::new(
            &rustc.executable.canonical_path,
            Path::new("/tmp/m7-fixture-cargo-home"),
            vec!["/tmp/m7-source-fixture/.cargo/config".to_string()],
            vec!["/tmp/m7-fixture-cargo-home/credentials".to_string()],
        )
        .expect("fixture build policy");
        let toolchain = M7ToolchainRecordV1::new(
            command_fixture("git", &["--version"]),
            rustc,
            command_fixture("cargo", &["--version", "--verbose"]),
            Vec::new(),
            policy,
        )
        .expect("fixture toolchain record");
        M7SourceInspectionV1::new(
            recipe,
            "/tmp/m7-source-fixture".to_string(),
            "/tmp/m7-source-fixture/.git".to_string(),
            "/tmp/m7-source-fixture/.git".to_string(),
            "b".repeat(40),
            ContentDigest::from_bytes(b"commit object"),
            "c".repeat(40),
            ContentDigest::from_bytes(b"tree object"),
            inventory,
            ContentDigest::from_bytes(lock_bytes),
            toolchain,
        )
        .expect("fixture source inspection")
    }

    fn manifest_request() -> M7ManifestCreateRequestV1 {
        M7ManifestCreateRequestV1 {
            schema: M7_MANIFEST_CREATE_REQUEST_SCHEMA.to_string(),
            proof_run_id: "proof-run:test".to_string(),
            run_started_at_ms: 20,
            criteria_id: "criteria:test".to_string(),
            criteria_version: "v1".to_string(),
            criteria_frozen_at_ms: 10,
            criteria: vec![M7CriterionStatementRequestV1 {
                criterion_id: "criterion:m0-m6".to_string(),
                statement: "Every bounded M0-M6 family must derive from exact sources.".to_string(),
                required_families: BTreeSet::from([
                    M7EvidenceFamily::M0TruthBaseline,
                    M7EvidenceFamily::M1CandidateLifecycle,
                    M7EvidenceFamily::M2SchedulerWakeRestart,
                    M7EvidenceFamily::M3CapabilityEffects,
                    M7EvidenceFamily::M4WorkerEcology,
                    M7EvidenceFamily::M5ActivationRollback,
                    M7EvidenceFamily::M6FactoryExchange,
                ]),
            }],
            source_custodian: M7ExternalPublicKeyPinRequestV1 {
                principal_id: "custodian:test".to_string(),
                public_key_hex: "11".repeat(ED25519_PUBLIC_KEY_BYTES),
            },
            independent_reviewer: M7ExternalPublicKeyPinRequestV1 {
                principal_id: "reviewer:test".to_string(),
                public_key_hex: "22".repeat(ED25519_PUBLIC_KEY_BYTES),
            },
            causal_chain_digest: ContentDigest::from_bytes(b"causal chain"),
            implementation_principal_ids: BTreeSet::from(["implementation:test".to_string()]),
            implementation_identity_digests: BTreeSet::from([ContentDigest::from_bytes(
                b"implementation identity",
            )]),
            prepared_provider_seed_path: None,
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ActiveSurfaceServerMode {
        Exact,
        Redirect,
        WrongStatus,
        WrongContentType,
        ContentEncoding,
        Oversized,
    }

    struct ActiveSurfaceTestServer {
        base_url: String,
        shutdown: Option<tokio::sync::oneshot::Sender<()>>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl Drop for ActiveSurfaceTestServer {
        fn drop(&mut self) {
            if let Some(shutdown) = self.shutdown.take() {
                let _ = shutdown.send(());
            }
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    fn active_surface_authority_fixture(
        root: &Path,
    ) -> (
        M7ActiveSurfaceCaptureInputsV1,
        M7ActiveSurfaceOutputPathsV1,
        M7ActiveSurfaceSnapshotV1,
    ) {
        let snapshot = crate::m7_closure::tests::exact_active_surface_snapshot();
        let notes = root.join("notes");
        fs::create_dir(&notes).expect("create notes authority directory");
        let readme = root.join("README.md");
        let roadmap = notes.join("ROADMAP.md");
        fs::write(
            &readme,
            snapshot
                .surface(M7ActiveSurfaceRoleV1::RootReadme)
                .expect("README fixture")
                .content_bytes(),
        )
        .expect("write README authority");
        fs::write(
            &roadmap,
            snapshot
                .surface(M7ActiveSurfaceRoleV1::Roadmap)
                .expect("ROADMAP fixture")
                .content_bytes(),
        )
        .expect("write ROADMAP authority");
        (
            M7ActiveSurfaceCaptureInputsV1 {
                root_readme: readme,
                roadmap,
                base_url: "http://127.0.0.1:9".to_string(),
            },
            M7ActiveSurfaceOutputPathsV1 {
                snapshot: root.join("active-surface-snapshot.json"),
                truth_boundary_source: root.join("m0-truth-boundary.json"),
                claim_boundary_source: root.join("m0-claim-boundary.json"),
                publication_policy_source: root.join("m0-publication-policy.json"),
            },
            snapshot,
        )
    }

    fn start_active_surface_server(
        snapshot: &M7ActiveSurfaceSnapshotV1,
        bind_address: &str,
        mode: ActiveSurfaceServerMode,
    ) -> ActiveSurfaceTestServer {
        use axum::Router;
        use axum::body::Body;
        use axum::http::{Request, Response, StatusCode};
        use std::collections::BTreeMap;
        use std::sync::Arc;

        let listener =
            std::net::TcpListener::bind(bind_address).expect("bind active-surface test server");
        listener
            .set_nonblocking(true)
            .expect("set test listener nonblocking");
        let address = listener.local_addr().expect("test server address");
        let host = if address.is_ipv6() {
            format!("[{}]", address.ip())
        } else {
            address.ip().to_string()
        };
        let base_url = format!("http://{host}:{}", address.port());
        let bodies = Arc::new(
            snapshot
                .surfaces()
                .iter()
                .filter(|surface| surface.role().is_http_surface())
                .map(|surface| {
                    (
                        surface.role().path().to_string(),
                        surface.content_bytes().to_vec(),
                    )
                })
                .collect::<BTreeMap<_, _>>(),
        );
        let app = Router::new().fallback(move |request: Request<Body>| {
            let bodies = bodies.clone();
            async move {
                let path = request.uri().path();
                let Some(mut body) = bodies.get(path).cloned() else {
                    return Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(Body::empty())
                        .expect("not-found response");
                };
                let selected = path == M7ActiveSurfaceRoleV1::SystemOverview.path();
                let mut builder = Response::builder().status(
                    if selected && mode == ActiveSurfaceServerMode::WrongStatus {
                        StatusCode::SERVICE_UNAVAILABLE
                    } else if selected && mode == ActiveSurfaceServerMode::Redirect {
                        StatusCode::FOUND
                    } else {
                        StatusCode::OK
                    },
                );
                if selected && mode == ActiveSurfaceServerMode::Redirect {
                    builder = builder.header(reqwest::header::LOCATION, "/redirected");
                }
                builder = builder.header(
                    reqwest::header::CONTENT_TYPE,
                    if selected && mode == ActiveSurfaceServerMode::WrongContentType {
                        "text/plain"
                    } else {
                        "application/json"
                    },
                );
                if selected && mode == ActiveSurfaceServerMode::ContentEncoding {
                    builder = builder.header(reqwest::header::CONTENT_ENCODING, "gzip");
                }
                if selected && mode == ActiveSurfaceServerMode::Oversized {
                    body = vec![b'x'; MAX_ACTIVE_SURFACE_INPUT_BYTES + 1];
                }
                builder
                    .body(Body::from(body))
                    .expect("active-surface response")
            }
        });
        let (shutdown, shutdown_receiver) = tokio::sync::oneshot::channel();
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("active-surface server runtime");
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener)
                    .expect("adopt active-surface listener");
                axum::serve(listener, app)
                    .with_graceful_shutdown(async move {
                        let _ = shutdown_receiver.await;
                    })
                    .await
                    .expect("serve active-surface fixtures");
            });
        });
        ActiveSurfaceTestServer {
            base_url,
            shutdown: Some(shutdown),
            thread: Some(thread),
        }
    }

    fn run_active_surface_capture(
        inputs: &M7ActiveSurfaceCaptureInputsV1,
        outputs: &M7ActiveSurfaceOutputPathsV1,
    ) -> Result<(), M7OperatorError> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("active-surface capture runtime")
            .block_on(capture_active_surface_sources_to_files(inputs, outputs))
    }

    fn active_surface_test_root(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "wasm-biotic-m7-active-surface-operator-{label}-{}-{}",
            std::process::id(),
            OUTPUT_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("create active-surface operator fixture root");
        fs::canonicalize(root).expect("canonical active-surface operator fixture root")
    }

    #[test]
    fn source_inspection_round_trips_only_canonical_bytes() {
        let source = source_fixture();
        let bytes = source.canonical_bytes().expect("canonical inspection");
        let reopened =
            M7SourceInspectionV1::from_canonical_bytes(&bytes).expect("parse canonical inspection");
        assert!(
            reopened == source,
            "reopened source inspection differed from its canonical source"
        );
        let mut noncanonical = bytes;
        noncanonical.push(b'\n');
        assert!(M7SourceInspectionV1::from_canonical_bytes(&noncanonical).is_err());
    }

    #[test]
    fn manifest_creation_hashes_statements_and_reconstructs_public_pins() {
        let source = source_fixture();
        let request = manifest_request();
        let manifest = create_manifest(&request, &source).expect("create manifest");
        assert_eq!(manifest.proof_run_id(), "proof-run:test");
        assert_eq!(
            manifest.frozen_criteria().criteria()[0].statement,
            request.criteria[0].statement
        );
        assert_eq!(
            manifest.frozen_criteria().criteria()[0].statement_digest,
            ContentDigest::from_bytes(request.criteria[0].statement.as_bytes())
        );
        assert_eq!(
            manifest.source_capture_identity().principal_id(),
            "custodian:test"
        );
        assert_eq!(manifest.reviewer_identity().principal_id(), "reviewer:test");
        let bytes = manifest.canonical_bytes().expect("canonical manifest");
        let reopened =
            M7ProofRunManifest::from_canonical_bytes(&bytes).expect("parse canonical manifest");
        assert!(
            reopened == manifest,
            "reopened proof-run manifest differed from its canonical source"
        );
    }

    #[test]
    fn manifest_and_source_assembly_use_exact_prepared_provider_seed() {
        let root = std::env::temp_dir().join(format!(
            "wasm-biotic-m7-operator-provider-{}-{}",
            std::process::id(),
            OUTPUT_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("create provider fixture directory");
        let provider_source =
            crate::m7_closure::tests::live_provider_source_fixture("proof-run:test", 150);
        let completed = provider_source
            .completed_invocation()
            .expect("completed provider invocation");
        let prepared_path = root.join("prepared-provider-seed.json");
        let completed_path = root.join("completed-provider-invocation.json");
        fs::write(
            &prepared_path,
            completed
                .prepared_seed()
                .canonical_bytes()
                .expect("prepared provider bytes"),
        )
        .expect("write prepared provider seed");
        fs::write(
            &completed_path,
            completed
                .canonical_bytes()
                .expect("completed provider invocation bytes"),
        )
        .expect("write completed provider invocation");

        assert_eq!(
            assemble_live_provider_source(&completed_path).expect("assemble exact provider source"),
            provider_source
        );
        let mut request = manifest_request();
        request.criteria_frozen_at_ms = 100;
        request.run_started_at_ms = 200;
        request.prepared_provider_seed_path = Some(prepared_path.clone());
        let manifest = create_manifest(&request, &source_fixture())
            .expect("manifest from exact prepared provider seed");
        let scope = manifest.live_provider_scope().expect("provider scope");
        assert_eq!(scope.proof_run_id(), "proof-run:test");
        assert_eq!(scope.prepared_at_ms(), 150);

        let mut cross_run = request.clone();
        cross_run.proof_run_id = "proof-run:other".to_string();
        assert!(matches!(
            create_manifest(&cross_run, &source_fixture()),
            Err(M7OperatorError::InvalidInput(_))
        ));
        let mut not_pre_run = request.clone();
        not_pre_run.run_started_at_ms = 150;
        assert!(matches!(
            create_manifest(&not_pre_run, &source_fixture()),
            Err(M7OperatorError::InvalidInput(_))
        ));
        let canonical_request = request.clone();
        let mut before_criteria = request;
        before_criteria.criteria_frozen_at_ms = 150;
        assert!(matches!(
            create_manifest(&before_criteria, &source_fixture()),
            Err(M7OperatorError::Foundation(_))
        ));

        let mut noncanonical = completed
            .prepared_seed()
            .canonical_bytes()
            .expect("prepared provider bytes");
        noncanonical.push(b'\n');
        fs::write(&prepared_path, noncanonical).expect("write noncanonical prepared seed");
        assert!(matches!(
            create_manifest(&canonical_request, &source_fixture()),
            Err(M7OperatorError::Foundation(_))
        ));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn manifest_request_rejects_private_key_fields() {
        let mut value = serde_json::to_value(manifest_request()).expect("request JSON");
        value["source_custodian"]["private_key_hex"] = serde_json::Value::String("00".repeat(32));
        assert!(serde_json::from_value::<M7ManifestCreateRequestV1>(value).is_err());
    }

    #[test]
    fn exact_source_request_rejects_legacy_caller_subject_labels() {
        let value = serde_json::json!({
            "schema": M7_EXACT_SOURCE_ADMISSION_REQUEST_SCHEMA,
            "kind": "m0_truth_baseline",
            "subject_digest": ContentDigest::from_bytes(b"caller label"),
            "sources": [{
                "role": "m0_truth_boundary",
                "path": "m0-truth.json"
            }]
        });
        assert!(serde_json::from_value::<M7ExactSourceAdmissionRequestV1>(value).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn subprocess_timeout_kills_and_reaps_process_group() {
        let started = Instant::now();
        let result = run_process(
            "/bin/sh",
            &["-c".to_string(), "/bin/sleep 5 & wait".to_string()],
            Path::new("/"),
            None,
            ProcessOutputLimits::separate(1_024, 1_024),
            Duration::from_millis(25),
            false,
            false,
            false,
            ProcessOutputDiagnosticPolicy::OmitAll,
            &[],
        );
        assert!(matches!(
            result,
            Err(M7OperatorError::ProcessTimeout { .. })
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn bounded_reader_reports_stream_without_echoing_captured_content() {
        let limits = ProcessOutputLimits::separate(4, 4);
        for (stream, content) in [
            (M7ProcessOutputStream::Stdout, b"stdout-secret".as_slice()),
            (M7ProcessOutputStream::Stderr, b"stderr-secret".as_slice()),
        ] {
            let budget = CombinedOutputBudget::new(limits.combined);
            let (events, received) = mpsc::channel();
            let retained = drain_bounded(content, stream, limits, &budget, events)
                .expect("drain bounded fixture");
            assert_eq!(retained.len(), 4);
            let event = received
                .into_iter()
                .find_map(|event| match event {
                    ProcessReaderEvent::OutputLimit(event) => Some(event),
                    ProcessReaderEvent::ReadFailed(_) | ProcessReaderEvent::Finished(_) => None,
                })
                .expect("output-limit event");
            assert_eq!(event.stream, stream);
            assert_eq!(event.kind, M7ProcessOutputLimitKind::Stream);
            assert_eq!(event.stream_observed_at_least, content.len());
            let diagnostic = event.into_error("/fixture/program", None).to_string();
            assert!(diagnostic.contains("/fixture/program"));
            assert!(diagnostic.contains(&stream.to_string()));
            assert!(diagnostic.contains(&content.len().to_string()));
            assert!(!diagnostic.contains("stdout-secret"));
            assert!(!diagnostic.contains("stderr-secret"));
        }
    }

    #[test]
    fn libtest_failure_diagnostic_accepts_only_complete_strict_bounded_names() {
        let mut fixture = Vec::new();
        fixture.extend_from_slice(b"test module::passed ... ok\n");
        fixture.extend_from_slice(b"test module::first_failure ... FAILED\n");
        fixture.extend_from_slice(b"test module::first_failure ... FAILED\n");
        fixture.extend_from_slice(b"test module::second_failure ... FAILED\n");
        fixture.extend_from_slice(b"test module::unfinished ... FAILED");
        let diagnostic =
            observed_libtest_failure_diagnostic(&fixture).expect("safe failure markers");
        assert_eq!(
            diagnostic.observed_failed_test_names,
            vec![
                "module::first_failure".to_string(),
                "module::second_failure".to_string(),
            ]
        );
        assert!(!diagnostic.name_limit_reached);

        for rejected in [
            b" test module::leading_space ... FAILED\n".as_slice(),
            b"test module::carriage_return ... FAILED\r\n".as_slice(),
            b"\x1b[31mtest module::ansi ... FAILED\x1b[0m\n".as_slice(),
            "test module::unicodé ... FAILED\n".as_bytes(),
            b"test module/path ... FAILED\n".as_slice(),
            b"test module.name ... FAILED\n".as_slice(),
            b"test module-name ... FAILED\n".as_slice(),
            b"test module=name ... FAILED\n".as_slice(),
            b"test module\"name ... FAILED\n".as_slice(),
            b"test ghp_credential_shaped_name ... FAILED\n".as_slice(),
            b"test github_pat_credential_shaped_name ... FAILED\n".as_slice(),
            b"test AKIA1234567890123456 ... FAILED\n".as_slice(),
            b"test module::passed ... ok\n".as_slice(),
        ] {
            assert!(
                observed_libtest_failure_diagnostic(rejected).is_none(),
                "rejected marker entered the diagnostic: {}",
                String::from_utf8_lossy(rejected)
            );
        }
    }

    #[test]
    fn libtest_failure_diagnostic_enforces_name_and_count_boundaries() {
        let maximum_name = "a".repeat(MAX_LIBTEST_FAILURE_DIAGNOSTIC_NAME_BYTES);
        let oversized_name = "a".repeat(MAX_LIBTEST_FAILURE_DIAGNOSTIC_NAME_BYTES + 1);
        let boundary_fixture =
            format!("test {maximum_name} ... FAILED\ntest {oversized_name} ... FAILED\n");
        let diagnostic = observed_libtest_failure_diagnostic(boundary_fixture.as_bytes())
            .expect("maximum-length marker");
        assert_eq!(diagnostic.observed_failed_test_names, vec![maximum_name]);
        assert!(!diagnostic.name_limit_reached);

        let maximum_components = vec!["a"; MAX_LIBTEST_FAILURE_DIAGNOSTIC_COMPONENTS].join("::");
        let oversized_components =
            vec!["a"; MAX_LIBTEST_FAILURE_DIAGNOSTIC_COMPONENTS + 1].join("::");
        let component_fixture = format!(
            "test {maximum_components} ... FAILED\ntest {oversized_components} ... FAILED\n"
        );
        let diagnostic = observed_libtest_failure_diagnostic(component_fixture.as_bytes())
            .expect("maximum-component marker");
        assert_eq!(
            diagnostic.observed_failed_test_names,
            vec![maximum_components]
        );

        let mut count_fixture = String::new();
        for index in 0..=MAX_LIBTEST_FAILURE_DIAGNOSTIC_NAMES {
            count_fixture.push_str(&format!("test module::failure_{index} ... FAILED\n"));
        }
        let diagnostic = observed_libtest_failure_diagnostic(count_fixture.as_bytes())
            .expect("bounded marker set");
        assert_eq!(
            diagnostic.observed_failed_test_names.len(),
            MAX_LIBTEST_FAILURE_DIAGNOSTIC_NAMES
        );
        assert!(diagnostic.name_limit_reached);
        assert_eq!(
            diagnostic
                .observed_failed_test_names
                .first()
                .map(String::as_str),
            Some("module::failure_0")
        );
    }

    #[test]
    fn bounded_reader_accepts_exact_cap_without_limit_event() {
        let limits = ProcessOutputLimits::with_combined(4, 4, 4);
        let budget = CombinedOutputBudget::new(limits.combined);
        let (events, received) = mpsc::channel();
        let retained = drain_bounded(
            b"abcd".as_slice(),
            M7ProcessOutputStream::Stdout,
            limits,
            &budget,
            events,
        )
        .expect("drain exact-cap fixture");
        assert_eq!(retained, b"abcd");
        assert!(
            !received
                .into_iter()
                .any(|event| matches!(event, ProcessReaderEvent::OutputLimit(_)))
        );
    }

    #[test]
    fn combined_output_budget_is_exact_across_both_streams() {
        let limits = ProcessOutputLimits::with_combined(16, 16, 6);
        let budget = CombinedOutputBudget::new(limits.combined);
        let (events, received) = mpsc::channel();
        let stdout = drain_bounded(
            b"abcd".as_slice(),
            M7ProcessOutputStream::Stdout,
            limits,
            &budget,
            events.clone(),
        )
        .expect("drain stdout fixture");
        let stderr = drain_bounded(
            b"xyz".as_slice(),
            M7ProcessOutputStream::Stderr,
            limits,
            &budget,
            events,
        )
        .expect("drain stderr fixture");
        assert_eq!(stdout, b"abcd");
        assert_eq!(stderr, b"xy");
        assert_eq!(stdout.len() + stderr.len(), 6);
        let event = received
            .into_iter()
            .find_map(|event| match event {
                ProcessReaderEvent::OutputLimit(event) => Some(event),
                ProcessReaderEvent::ReadFailed(_) | ProcessReaderEvent::Finished(_) => None,
            })
            .expect("combined output-limit event");
        assert_eq!(event.stream, M7ProcessOutputStream::Stderr);
        assert_eq!(event.kind, M7ProcessOutputLimitKind::Combined);
        assert_eq!(event.combined_observed_at_least, 7);
        assert_eq!(event.combined_limit, Some(6));
    }

    #[cfg(unix)]
    #[test]
    fn subprocess_stderr_overflow_is_typed_and_prompt() {
        let started = Instant::now();
        let result = run_process(
            "/bin/sh",
            &["-c".to_string(), "exec /usr/bin/yes >&2".to_string()],
            Path::new("/"),
            None,
            ProcessOutputLimits::with_combined(4_096, 4_096, 4_096),
            Duration::from_secs(5),
            false,
            false,
            false,
            ProcessOutputDiagnosticPolicy::OmitAll,
            &[],
        );
        assert!(matches!(
            result,
            Err(M7OperatorError::ProcessOutputLimitExceeded {
                program,
                stream: M7ProcessOutputStream::Stderr,
                combined_limit: Some(4_096),
                ..
            }) if program == Path::new("/bin/sh")
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[cfg(unix)]
    #[test]
    fn subprocess_output_overflow_notifies_and_terminates_promptly() {
        let started = Instant::now();
        let result = run_process(
            "/bin/sh",
            &["-c".to_string(), "while :; do printf x; done".to_string()],
            Path::new("/"),
            None,
            ProcessOutputLimits::with_combined(4_096, 4_096, 4_096),
            Duration::from_secs(5),
            false,
            false,
            false,
            ProcessOutputDiagnosticPolicy::OmitAll,
            &[],
        );
        assert!(matches!(
            result,
            Err(M7OperatorError::ProcessOutputLimitExceeded {
                stream: M7ProcessOutputStream::Stdout,
                combined_limit: Some(4_096),
                ..
            })
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[cfg(unix)]
    #[test]
    fn subprocess_output_overflow_exposes_markers_only_when_explicitly_opted_in() {
        let command = [
            "printf 'test module::failed_test ... FAILED\\nadjacent-secret\\n'; ",
            "exec /usr/bin/yes noise",
        ]
        .concat();
        let opted_in = run_process(
            "/bin/sh",
            &["-c".to_string(), command.clone()],
            Path::new("/"),
            None,
            ProcessOutputLimits::with_combined(4_096, 4_096, 4_096),
            Duration::from_secs(5),
            false,
            false,
            false,
            ProcessOutputDiagnosticPolicy::CargoLibtestFailureNames,
            &[],
        );
        let Err(M7OperatorError::ProcessOutputLimitExceeded {
            observed_libtest_failures: Some(diagnostic),
            ..
        }) = opted_in
        else {
            panic!("opted-in overflow did not return a bounded libtest diagnostic");
        };
        assert_eq!(
            diagnostic.observed_failed_test_names,
            vec!["module::failed_test".to_string()]
        );
        let display = ProcessOutputLimitEvent {
            stream: M7ProcessOutputStream::Stdout,
            kind: M7ProcessOutputLimitKind::StreamAndCombined,
            stream_observed_at_least: 4_097,
            stream_limit: 4_096,
            combined_observed_at_least: 4_097,
            combined_limit: Some(4_096),
        }
        .into_error("/bin/sh", Some(diagnostic))
        .to_string();
        assert!(display.contains("module::failed_test"));
        assert!(display.contains("untrusted, possibly incomplete"));
        assert!(!display.contains("adjacent-secret"));
        assert!(!display.contains("noise"));

        let opted_out = run_process(
            "/bin/sh",
            &["-c".to_string(), command],
            Path::new("/"),
            None,
            ProcessOutputLimits::with_combined(4_096, 4_096, 4_096),
            Duration::from_secs(5),
            false,
            false,
            false,
            ProcessOutputDiagnosticPolicy::OmitAll,
            &[],
        );
        let Err(
            error @ M7OperatorError::ProcessOutputLimitExceeded {
                observed_libtest_failures: None,
                ..
            },
        ) = opted_out
        else {
            panic!("generic overflow exposed a libtest-looking marker");
        };
        assert!(!error.to_string().contains("module::failed_test"));
    }

    #[test]
    fn cargo_transcript_length_policy_is_bounded_without_large_fixtures() {
        assert!(validate_cargo_transcript_lengths(4, 4, 8, 8).is_ok());
        assert!(matches!(
            validate_cargo_transcript_lengths(5, 4, 4, 9),
            Err(M7OperatorError::ResourceExhausted(_))
        ));
        assert!(matches!(
            validate_cargo_transcript_lengths(4, 4, 8, 7),
            Err(M7OperatorError::ResourceExhausted(_))
        ));
        assert!(matches!(
            validate_cargo_transcript_lengths(0, 0, 8, 8),
            Err(M7OperatorError::ResourceExhausted(_))
        ));
        assert_eq!(
            MAX_TRANSCRIPT_FILE_BYTES,
            MAX_TRANSCRIPT_CONTENT_BYTES * 6 + 64 * 1_024
        );
        assert!(MAX_TRANSCRIPT_FILE_BYTES <= MAX_OUTPUT_BYTES);
    }

    #[test]
    fn cargo_transcript_rejects_credential_shaped_output() {
        let manifest = create_manifest(&manifest_request(), &source_fixture())
            .expect("create fixture manifest");
        let result = create_cargo_transcript(
            &manifest,
            b"test result: ok. 1 passed; 0 failed; OPENAI_API_KEY=secret\n".to_vec(),
            Vec::new(),
            0,
        );
        assert!(matches!(result, Err(M7OperatorError::InvalidInput(_))));
    }

    #[test]
    fn build_environment_rejects_wrappers_flags_and_toolchain_overrides() {
        for forbidden in [
            "RUSTC_WRAPPER",
            "RUSTFLAGS",
            "CARGO_ENCODED_RUSTFLAGS",
            "CARGO_BUILD_TARGET",
            "CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER",
            "CC",
            "PKG_CONFIG_PATH",
        ] {
            assert!(
                validate_inherited_build_environment([OsString::from(forbidden)]).is_err(),
                "{forbidden} must be rejected"
            );
        }
        assert!(
            validate_inherited_build_environment([
                OsString::from("CARGO_TARGET_DIR"),
                OsString::from("CARGO_MANIFEST_DIR"),
                OsString::from("RUSTUP_TOOLCHAIN"),
                OsString::from("RUST_LOG"),
            ])
            .is_ok()
        );
    }

    #[cfg(unix)]
    #[test]
    fn explicit_fixture_tool_resolution_pins_and_reverifies_executable_bytes() {
        use std::os::unix::fs::PermissionsExt;

        let root = active_surface_test_root("explicit-tool-identities");
        for program in ["git", "rustc", "cargo"] {
            let executable = root.join(program);
            fs::write(
                &executable,
                format!("bounded {program} executable fixture").as_bytes(),
            )
            .expect("write executable fixture");
            fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))
                .expect("mark fixture executable");

            let identity = resolve_unambiguous_path_tool(program, root.as_os_str())
                .expect("resolve the explicit fixture executable");
            identity
                .verify_current()
                .expect("reverify the explicit fixture executable");
            assert_eq!(Path::new(&identity.invocation_path), executable);
            assert_eq!(Path::new(&identity.canonical_path), executable);
            assert_eq!(
                Path::new(&identity.canonical_path).file_name(),
                Some(OsStr::new(program))
            );
            assert!(identity.byte_length > 0);
        }
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn path_resolution_rejects_git_and_cargo_wrappers_ahead_of_real_tools() {
        use std::os::unix::fs::PermissionsExt;

        let root = active_surface_test_root("path-wrapper");
        let wrapper = root.join("wrapper");
        let tools = root.join("tools");
        fs::create_dir(&wrapper).expect("create wrapper path");
        fs::create_dir(&tools).expect("create tool path");
        for program in ["git", "cargo"] {
            for directory in [&wrapper, &tools] {
                let path = directory.join(program);
                fs::write(&path, b"fixture executable").expect("write fixture executable");
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                    .expect("mark fixture executable");
            }
            let path_value = std::env::join_paths([&wrapper, &tools]).expect("join fixture PATH");
            assert!(matches!(
                resolve_unambiguous_path_tool(program, &path_value),
                Err(M7OperatorError::InvalidInput(_))
            ));
        }
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn executable_reverification_detects_byte_changes() {
        use std::os::unix::fs::PermissionsExt;

        let root = active_surface_test_root("executable-change");
        let executable = root.join("cargo");
        fs::write(&executable, b"first executable bytes").expect("write executable fixture");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))
            .expect("mark executable fixture");
        let identity =
            executable_identity_from_invocation(&executable).expect("inspect executable fixture");
        fs::write(&executable, b"changed executable bytes").expect("change executable fixture");
        assert!(matches!(
            identity.verify_current(),
            Err(M7OperatorError::Conflict(_))
        ));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn cargo_configuration_is_rejected_in_checkout_or_cache_home() {
        let root = active_surface_test_root("cargo-config");
        let cargo_home = root.join("cargo-home");
        fs::create_dir(&cargo_home).expect("create Cargo home fixture");
        fs::create_dir(root.join(".cargo")).expect("create checkout Cargo config directory");
        fs::write(root.join(".cargo/config.toml"), b"[build]\nrustflags=[]\n")
            .expect("write checkout Cargo config");
        assert!(matches!(
            inspect_cargo_configuration_absence(&root, &cargo_home),
            Err(M7OperatorError::InvalidInput(_))
        ));
        fs::remove_file(root.join(".cargo/config.toml")).expect("remove checkout config");
        fs::write(cargo_home.join("config"), b"[net]\noffline=false\n")
            .expect("write Cargo home config");
        assert!(matches!(
            inspect_cargo_configuration_absence(&root, &cargo_home),
            Err(M7OperatorError::InvalidInput(_))
        ));
        let _ = fs::remove_dir_all(root);
    }

    fn assert_positive_active_surface_capture(bind_address: &str, label: &str) {
        let root = active_surface_test_root(label);
        let (mut inputs, outputs, expected) = active_surface_authority_fixture(&root);
        let server =
            start_active_surface_server(&expected, bind_address, ActiveSurfaceServerMode::Exact);
        inputs.base_url = server.base_url.clone();
        run_active_surface_capture(&inputs, &outputs).expect("capture active surfaces");

        let captured = M7ActiveSurfaceSnapshotV1::from_canonical_bytes(
            &fs::read(&outputs.snapshot).expect("read snapshot output"),
        )
        .expect("canonical captured snapshot");
        assert_eq!(
            captured.capture_policy_digest(),
            &crate::m7_closure::m7_active_surface_capture_policy_digest()
                .expect("capture-policy digest")
        );
        let mut previous_completed = 0;
        for role in [
            M7ActiveSurfaceRoleV1::RootReadme,
            M7ActiveSurfaceRoleV1::Roadmap,
            M7ActiveSurfaceRoleV1::SystemOverview,
            M7ActiveSurfaceRoleV1::GeneralAudienceHome,
            M7ActiveSurfaceRoleV1::NorthStar07ClosureReview,
            M7ActiveSurfaceRoleV1::RemediationPhase04FinalClosureRereview,
            M7ActiveSurfaceRoleV1::RemediationPhase04PublicationPolicy,
        ] {
            let actual = captured.surface(role).expect("captured role");
            let expected_content = expected
                .surface(role)
                .expect("fixture role")
                .content_bytes();
            assert!(
                actual.content_bytes() == expected_content,
                "captured active-surface content differed from the exact fixture (role={role:?}, actual_bytes={}, expected_bytes={})",
                actual.content_bytes().len(),
                expected_content.len()
            );
            assert_eq!(actual.observation().sequence(), role.observation_sequence());
            assert!(actual.observation().observed_started_at_ms() >= previous_completed);
            previous_completed = actual.observation().observed_completed_at_ms();
            match actual.observation().source() {
                crate::m7_closure::M7ActiveSurfaceObservationSourceV1::LocalAuthority {
                    ..
                } => {
                    assert!(!role.is_http_surface())
                }
                crate::m7_closure::M7ActiveSurfaceObservationSourceV1::Http {
                    method,
                    status_code,
                    media_type,
                    peer_addr,
                    ..
                } => {
                    assert!(role.is_http_surface());
                    assert_eq!(method, "GET");
                    assert_eq!(*status_code, 200);
                    assert_eq!(media_type, "application/json");
                    assert!(
                        peer_addr
                            .parse::<std::net::SocketAddr>()
                            .expect("captured peer")
                            .ip()
                            .is_loopback()
                    );
                }
            }
        }
        let truth_output = fs::read(&outputs.truth_boundary_source).expect("read truth output");
        let expected_truth = M7TruthBoundarySourceV3::new(captured.clone())
            .expect("truth source")
            .canonical_bytes()
            .expect("canonical truth source");
        assert!(
            truth_output == expected_truth,
            "truth-boundary output differed from the exact canonical source (actual_bytes={}, expected_bytes={})",
            truth_output.len(),
            expected_truth.len()
        );
        let claim_output = fs::read(&outputs.claim_boundary_source).expect("read claim output");
        let expected_claim = M7ClaimBoundarySourceV3::new(captured.clone())
            .expect("claim source")
            .canonical_bytes()
            .expect("canonical claim source");
        assert!(
            claim_output == expected_claim,
            "claim-boundary output differed from the exact canonical source (actual_bytes={}, expected_bytes={})",
            claim_output.len(),
            expected_claim.len()
        );
        let publication_output =
            fs::read(&outputs.publication_policy_source).expect("read publication output");
        let expected_publication = M7PublicationPolicySourceV3::new(captured)
            .expect("publication source")
            .canonical_bytes()
            .expect("canonical publication source");
        assert!(
            publication_output == expected_publication,
            "publication-policy output differed from the exact canonical source (actual_bytes={}, expected_bytes={})",
            publication_output.len(),
            expected_publication.len()
        );
        drop(server);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn active_surface_capture_observes_real_ipv4_loopback_transport() {
        assert_positive_active_surface_capture("127.0.0.1:0", "positive-ipv4");
    }

    #[test]
    fn active_surface_capture_observes_real_ipv6_loopback_transport() {
        assert_positive_active_surface_capture("[::1]:0", "positive-ipv6");
    }

    #[test]
    fn active_surface_capture_rejects_nonloopback_or_nonorigin_urls_before_network() {
        let root = active_surface_test_root("origin");
        let (mut inputs, outputs, _) = active_surface_authority_fixture(&root);
        for invalid in [
            "https://127.0.0.1:8443",
            "http://192.0.2.1:8080",
            "http://127.0.0.1",
            "http://127.0.0.1:80",
            "http://user@127.0.0.1:8080",
            "http://127.0.0.1:8080/path",
            "http://127.0.0.1:8080?query",
            "http://127.0.0.1:8080#fragment",
        ] {
            inputs.base_url = invalid.to_string();
            assert!(matches!(
                run_active_surface_capture(&inputs, &outputs),
                Err(M7OperatorError::InvalidInput(_))
            ));
        }
        assert!(!outputs.snapshot.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn active_surface_capture_rejects_redirect_status_media_and_encoding() {
        for mode in [
            ActiveSurfaceServerMode::Redirect,
            ActiveSurfaceServerMode::WrongStatus,
            ActiveSurfaceServerMode::WrongContentType,
            ActiveSurfaceServerMode::ContentEncoding,
        ] {
            let root = active_surface_test_root(&format!("response-{mode:?}"));
            let (mut inputs, outputs, expected) = active_surface_authority_fixture(&root);
            let server = start_active_surface_server(&expected, "127.0.0.1:0", mode);
            inputs.base_url = server.base_url.clone();
            assert!(matches!(
                run_active_surface_capture(&inputs, &outputs),
                Err(M7OperatorError::InvalidInput(_))
            ));
            assert!(!outputs.snapshot.exists());
            drop(server);
            let _ = fs::remove_dir_all(root);
        }
    }

    #[test]
    fn active_surface_capture_stream_rejects_an_oversized_body() {
        let root = active_surface_test_root("oversized-http");
        let (mut inputs, outputs, expected) = active_surface_authority_fixture(&root);
        let server = start_active_surface_server(
            &expected,
            "127.0.0.1:0",
            ActiveSurfaceServerMode::Oversized,
        );
        inputs.base_url = server.base_url.clone();
        assert!(matches!(
            run_active_surface_capture(&inputs, &outputs),
            Err(M7OperatorError::ResourceExhausted(_))
        ));
        assert!(!outputs.snapshot.exists());
        drop(server);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn active_surface_capture_preflights_aliases_and_no_clobber_before_network() {
        let root = active_surface_test_root("preflight");
        let (inputs, mut outputs, expected) = active_surface_authority_fixture(&root);
        fs::remove_file(&inputs.roadmap).expect("remove roadmap before hard-link alias");
        fs::hard_link(&inputs.root_readme, &inputs.roadmap).expect("hard-link authority alias");
        assert!(matches!(
            run_active_surface_capture(&inputs, &outputs),
            Err(M7OperatorError::Conflict(_))
        ));
        fs::remove_file(&inputs.roadmap).expect("remove hard-link authority alias");
        fs::write(
            &inputs.roadmap,
            expected
                .surface(M7ActiveSurfaceRoleV1::Roadmap)
                .expect("roadmap fixture")
                .content_bytes(),
        )
        .expect("restore roadmap authority");

        outputs.claim_boundary_source = outputs.snapshot.clone();
        assert!(matches!(
            run_active_surface_capture(&inputs, &outputs),
            Err(M7OperatorError::Conflict(_))
        ));
        outputs.claim_boundary_source = root.join("m0-claim-boundary.json");
        fs::write(&outputs.publication_policy_source, b"existing output")
            .expect("write existing output");
        assert!(matches!(
            run_active_surface_capture(&inputs, &outputs),
            Err(M7OperatorError::Conflict(_))
        ));
        assert!(!outputs.snapshot.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn active_surface_capture_rejects_symlinked_authority_before_network() {
        use std::os::unix::fs::symlink;

        let root = active_surface_test_root("symlink");
        let (mut inputs, outputs, _) = active_surface_authority_fixture(&root);
        let link = root.join("roadmap-link.md");
        symlink(&inputs.roadmap, &link).expect("create roadmap symlink");
        inputs.roadmap = link;
        assert!(matches!(
            run_active_surface_capture(&inputs, &outputs),
            Err(M7OperatorError::UnsafePath(_))
        ));
        assert!(!outputs.snapshot.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn active_surface_capture_rejects_nonloopback_or_wrong_port_peer_provenance() {
        assert!(!validate_peer_for_origin(
            "http://127.0.0.1:8080",
            "192.0.2.1:8080".parse().expect("nonloopback peer")
        ));
        assert!(!validate_peer_for_origin(
            "http://127.0.0.1:8080",
            "127.0.0.1:8081".parse().expect("wrong-port peer")
        ));
        assert!(validate_peer_for_origin(
            "http://localhost:8080",
            "[::1]:8080".parse().expect("localhost IPv6 peer")
        ));
    }
}
