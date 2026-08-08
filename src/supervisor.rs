//! Durable, single-writer supervisor for bounded local jobs.
//!
//! Delivery is explicitly **at least once**. Every logical effect is bound to a
//! globally unique idempotency key and a durable effect receipt. A handler may
//! therefore be invoked again after process death or lease loss, but it must
//! commit its external effect idempotently under the supplied key. The
//! supervisor accepts at most one committed receipt for that key and makes the
//! receipt and terminal job outcome durable in the same atomic state write.

use crate::execution::artifact::{ArtifactError, ContentDigest, digest_json_content};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const SUPERVISOR_STATE_SCHEMA_VERSION: u32 = 2;
pub const LEGACY_SUPERVISOR_STATE_SCHEMA_VERSION: u32 = 1;

const STATE_FILE_NAME: &str = "supervisor-state.json";
const LOCK_FILE_NAME: &str = "supervisor-writer.lock";
const BACKUP_DIRECTORY_NAME: &str = "backups";
const STATE_DOMAIN: &str = "wasm-biotic.supervisor-state.v2";
const MAX_PAYLOAD_BYTES: usize = 1_048_576;
const MAX_RESULT_BYTES: usize = 1_048_576;

static TEMPORARY_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(1);
static IN_PROCESS_SUPERVISOR_ROOTS: OnceLock<Mutex<BTreeSet<PathBuf>>> = OnceLock::new();

#[derive(Debug)]
struct InProcessSupervisorRootOwner {
    root: PathBuf,
}

impl InProcessSupervisorRootOwner {
    fn acquire(root: &Path) -> Result<Self, SupervisorError> {
        let registry = IN_PROCESS_SUPERVISOR_ROOTS.get_or_init(|| Mutex::new(BTreeSet::new()));
        let mut roots = registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !roots.insert(root.to_path_buf()) {
            return Err(SupervisorError::WriterAlreadyActive {
                path: root.join(LOCK_FILE_NAME),
            });
        }
        Ok(Self {
            root: root.to_path_buf(),
        })
    }
}

impl Drop for InProcessSupervisorRootOwner {
    fn drop(&mut self) {
        let Some(registry) = IN_PROCESS_SUPERVISOR_ROOTS.get() else {
            return;
        };
        registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.root);
    }
}

pub trait SupervisorClock: Send + Sync {
    fn now_ms(&self) -> u64;
}

#[derive(Clone, Debug, Default)]
pub struct SystemSupervisorClock;

impl SupervisorClock for SystemSupervisorClock {
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or_default()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub initial_backoff_ms: u64,
    pub max_backoff_ms: u64,
    pub lease_duration_ms: u64,
    pub attempt_timeout_ms: u64,
}

impl RetryPolicy {
    pub fn validate(&self) -> Result<(), SupervisorError> {
        if self.max_attempts == 0 {
            return Err(SupervisorError::InvalidRetryPolicy(
                "max_attempts must be non-zero".to_string(),
            ));
        }
        if self.lease_duration_ms == 0 {
            return Err(SupervisorError::InvalidRetryPolicy(
                "lease_duration_ms must be non-zero".to_string(),
            ));
        }
        if self.attempt_timeout_ms == 0 {
            return Err(SupervisorError::InvalidRetryPolicy(
                "attempt_timeout_ms must be non-zero".to_string(),
            ));
        }
        if self.max_backoff_ms < self.initial_backoff_ms {
            return Err(SupervisorError::InvalidRetryPolicy(
                "max_backoff_ms must be at least initial_backoff_ms".to_string(),
            ));
        }
        Ok(())
    }

    fn backoff_after_attempt(&self, attempt_number: u32) -> u64 {
        if self.initial_backoff_ms == 0 {
            return 0;
        }
        let exponent = attempt_number.saturating_sub(1).min(63);
        self.initial_backoff_ms
            .saturating_mul(1u64 << exponent)
            .min(self.max_backoff_ms)
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_backoff_ms: 1_000,
            max_backoff_ms: 30_000,
            lease_duration_ms: 30_000,
            attempt_timeout_ms: 120_000,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubmitJobRequest {
    pub job_id: String,
    pub job_kind: String,
    pub payload_json: String,
    pub idempotency_key: String,
    pub not_before_ms: u64,
    pub deadline_at_ms: u64,
    pub retry_policy: RetryPolicy,
    pub approval_request_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobPhase {
    Queued,
    WaitingApproval,
    Leased,
    RetryScheduled,
    Succeeded,
    Failed,
    RetryExhausted,
    Denied,
    ApprovalExpired,
    ApprovalEscalated,
    Cancelled,
    DeadlineExceeded,
}

impl JobPhase {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Succeeded
                | Self::Failed
                | Self::RetryExhausted
                | Self::Denied
                | Self::ApprovalExpired
                | Self::ApprovalEscalated
                | Self::Cancelled
                | Self::DeadlineExceeded
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobLease {
    pub owner_id: String,
    pub lease_token: String,
    pub attempt_number: u32,
    pub acquired_at_ms: u64,
    pub expires_at_ms: u64,
    pub attempt_deadline_at_ms: u64,
    pub last_heartbeat_at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttemptOutcome {
    EffectCommitted {
        effect_receipt_id: String,
        result_digest: ContentDigest,
    },
    RetryableFailure {
        failure_class: String,
        detail: String,
    },
    PermanentFailure {
        failure_class: String,
        detail: String,
    },
    ApprovalBlocked {
        approval_request_id: String,
    },
    LeaseLost {
        detail: String,
    },
    TimedOut {
        detail: String,
    },
    Cancelled {
        reason: String,
    },
    DeadlineExceeded,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobAttempt {
    pub attempt_id: String,
    pub attempt_number: u32,
    pub lease_token: String,
    pub started_at_ms: u64,
    pub ended_at_ms: Option<u64>,
    pub outcome: Option<AttemptOutcome>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancellationRecord {
    pub reason: String,
    pub requested_at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobTerminalOutcome {
    EffectCommitted {
        effect_receipt_id: String,
        effect_id: String,
        result_digest: ContentDigest,
        completed_at_ms: u64,
    },
    PermanentFailure {
        failure_class: String,
        detail: String,
        completed_at_ms: u64,
    },
    RetryExhausted {
        last_failure: String,
        completed_at_ms: u64,
    },
    ApprovalDenied {
        approval_request_id: String,
        evidence_ref: String,
        completed_at_ms: u64,
    },
    ApprovalExpired {
        approval_request_id: String,
        evidence_ref: String,
        completed_at_ms: u64,
    },
    ApprovalEscalated {
        approval_request_id: String,
        evidence_ref: String,
        completed_at_ms: u64,
    },
    Cancelled {
        reason: String,
        completed_at_ms: u64,
    },
    DeadlineExceeded {
        completed_at_ms: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableJob {
    pub job_id: String,
    pub job_kind: String,
    pub payload_json: String,
    pub payload_digest: ContentDigest,
    pub request_fingerprint: ContentDigest,
    pub idempotency_key: String,
    pub effect_receipt_id: String,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub not_before_ms: u64,
    pub deadline_at_ms: u64,
    pub next_wake_at_ms: Option<u64>,
    pub retry_policy: RetryPolicy,
    pub approval_request_id: Option<String>,
    pub phase: JobPhase,
    pub lease: Option<JobLease>,
    pub attempts: Vec<JobAttempt>,
    pub cancellation: Option<CancellationRecord>,
    pub terminal_outcome: Option<JobTerminalOutcome>,
}

impl DurableJob {
    pub fn attempt_count(&self) -> u32 {
        u32::try_from(self.attempts.len()).unwrap_or(u32::MAX)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EffectReceiptStatus {
    Pending,
    Dispatching,
    Committed,
    Abandoned,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectCommit {
    pub effect_id: String,
    pub result_digest: ContentDigest,
    pub result_json: String,
}

impl EffectCommit {
    pub fn from_json(
        effect_id: impl Into<String>,
        result: &Value,
    ) -> Result<Self, SupervisorError> {
        let effect_id = effect_id.into();
        require_nonempty("effect_id", &effect_id)?;
        let result_json = serde_json::to_string(result)
            .map_err(|error| SupervisorError::Serialization(error.to_string()))?;
        if result_json.len() > MAX_RESULT_BYTES {
            return Err(SupervisorError::ResultTooLarge {
                limit: MAX_RESULT_BYTES,
                actual: result_json.len(),
            });
        }
        Ok(Self {
            effect_id,
            result_digest: ContentDigest::from_bytes(result_json.as_bytes()),
            result_json,
        })
    }

    fn validate(&self) -> Result<(), SupervisorError> {
        require_nonempty("effect_id", &self.effect_id)?;
        if self.result_json.len() > MAX_RESULT_BYTES {
            return Err(SupervisorError::ResultTooLarge {
                limit: MAX_RESULT_BYTES,
                actual: self.result_json.len(),
            });
        }
        serde_json::from_str::<Value>(&self.result_json)
            .map_err(|error| SupervisorError::InvalidResultJson(error.to_string()))?;
        let actual = ContentDigest::from_bytes(self.result_json.as_bytes());
        if actual != self.result_digest {
            return Err(SupervisorError::ResultDigestMismatch {
                expected: self.result_digest.clone(),
                actual,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectReceipt {
    pub effect_receipt_id: String,
    pub job_id: String,
    pub idempotency_key: String,
    pub status: EffectReceiptStatus,
    pub delivery_count: u32,
    pub first_dispatched_at_ms: Option<u64>,
    pub last_dispatched_at_ms: Option<u64>,
    pub committed_at_ms: Option<u64>,
    pub abandoned_at_ms: Option<u64>,
    pub abandon_reason: Option<String>,
    pub commit: Option<EffectCommit>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalResolutionKind {
    Granted,
    Denied,
    Expired,
    Escalated,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalResolutionRecord {
    pub approval_request_id: String,
    pub resolution: ApprovalResolutionKind,
    pub evidence_ref: String,
    pub resolved_at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WakeKind {
    Submission,
    Retry,
    ApprovalGranted,
    ApprovalDenied,
    ApprovalExpired,
    ApprovalEscalated,
    StartupLeaseReconciliation,
    GracefulShutdownRequeue,
    LeaseExpired,
    AttemptTimedOut,
    Cancellation,
    Deadline,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WakeRecord {
    pub wake_id: String,
    pub job_id: String,
    pub kind: WakeKind,
    pub scheduled_at_ms: u64,
    pub recorded_at_ms: u64,
    pub consumed_at_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SupervisorLifecycleStatus {
    Running,
    Stopping,
    Stopped,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupervisorHeartbeat {
    pub owner_id: String,
    pub started_at_ms: u64,
    pub last_heartbeat_at_ms: u64,
    pub lifecycle: SupervisorLifecycleStatus,
    pub next_due_at_ms: Option<u64>,
    pub active_lease_owner: Option<String>,
    pub active_job_id: Option<String>,
    pub last_attempt_id: Option<String>,
    pub last_terminal_job_id: Option<String>,
    pub last_terminal_outcome: Option<JobTerminalOutcome>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShutdownRecord {
    pub owner_id: String,
    pub requested_at_ms: u64,
    pub completed_at_ms: u64,
    pub active_job_at_request: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationRecord {
    pub from_version: u32,
    pub to_version: u32,
    pub backup_id: String,
    pub source_digest: ContentDigest,
    pub migrated_at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupervisorState {
    pub schema_name: String,
    pub schema_version: u32,
    pub revision: u64,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub jobs: BTreeMap<String, DurableJob>,
    pub idempotency_index: BTreeMap<String, String>,
    pub effect_receipts: BTreeMap<String, EffectReceipt>,
    pub approval_resolutions: BTreeMap<String, ApprovalResolutionRecord>,
    pub wakes: Vec<WakeRecord>,
    pub heartbeat: SupervisorHeartbeat,
    pub shutdowns: Vec<ShutdownRecord>,
    pub migrations: Vec<MigrationRecord>,
}

impl SupervisorState {
    fn empty(owner_id: &str, now_ms: u64) -> Self {
        Self {
            schema_name: STATE_DOMAIN.to_string(),
            schema_version: SUPERVISOR_STATE_SCHEMA_VERSION,
            revision: 0,
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
            jobs: BTreeMap::new(),
            idempotency_index: BTreeMap::new(),
            effect_receipts: BTreeMap::new(),
            approval_resolutions: BTreeMap::new(),
            wakes: Vec::new(),
            heartbeat: SupervisorHeartbeat {
                owner_id: owner_id.to_string(),
                started_at_ms: now_ms,
                last_heartbeat_at_ms: now_ms,
                lifecycle: SupervisorLifecycleStatus::Running,
                next_due_at_ms: None,
                active_lease_owner: None,
                active_job_id: None,
                last_attempt_id: None,
                last_terminal_job_id: None,
                last_terminal_outcome: None,
            },
            shutdowns: Vec::new(),
            migrations: Vec::new(),
        }
    }

    pub fn validate(&self) -> Result<(), SupervisorError> {
        if self.schema_name != STATE_DOMAIN
            || self.schema_version != SUPERVISOR_STATE_SCHEMA_VERSION
        {
            return Err(SupervisorError::UnsupportedSchemaVersion {
                found: self.schema_version,
                supported: SUPERVISOR_STATE_SCHEMA_VERSION,
            });
        }
        require_nonempty("heartbeat.owner_id", &self.heartbeat.owner_id)?;
        if self.updated_at_ms < self.created_at_ms {
            return Err(SupervisorError::StateInvariant(
                "updated_at_ms precedes created_at_ms".to_string(),
            ));
        }
        if self.jobs.len() != self.idempotency_index.len()
            || self.jobs.len() != self.effect_receipts.len()
        {
            return Err(SupervisorError::StateInvariant(
                "job, idempotency, and effect-receipt cardinalities differ".to_string(),
            ));
        }
        let mut approval_ids = BTreeSet::new();
        for (job_id, job) in &self.jobs {
            if job_id != &job.job_id {
                return Err(SupervisorError::StateInvariant(
                    "job map key differs from job id".to_string(),
                ));
            }
            require_nonempty("job_id", &job.job_id)?;
            require_nonempty("job_kind", &job.job_kind)?;
            require_nonempty("idempotency_key", &job.idempotency_key)?;
            job.retry_policy.validate()?;
            if job.deadline_at_ms <= job.not_before_ms {
                return Err(SupervisorError::StateInvariant(format!(
                    "job {} deadline must follow not-before time",
                    job.job_id
                )));
            }
            serde_json::from_str::<Value>(&job.payload_json)
                .map_err(|error| SupervisorError::InvalidPayloadJson(error.to_string()))?;
            if ContentDigest::from_bytes(job.payload_json.as_bytes()) != job.payload_digest {
                return Err(SupervisorError::StateInvariant(format!(
                    "job {} payload digest mismatch",
                    job.job_id
                )));
            }
            let expected_fingerprint = digest_json_content(&(
                &job.job_kind,
                &job.payload_json,
                job.not_before_ms,
                job.deadline_at_ms,
                &job.retry_policy,
                &job.approval_request_id,
            ))?;
            if expected_fingerprint != job.request_fingerprint {
                return Err(SupervisorError::StateInvariant(format!(
                    "job {} request fingerprint mismatch",
                    job.job_id
                )));
            }
            if self.idempotency_index.get(&job.idempotency_key) != Some(job_id) {
                return Err(SupervisorError::StateInvariant(format!(
                    "job {} idempotency index mismatch",
                    job.job_id
                )));
            }
            let receipt = self
                .effect_receipts
                .get(&job.effect_receipt_id)
                .ok_or_else(|| {
                    SupervisorError::StateInvariant(format!(
                        "job {} has no effect receipt",
                        job.job_id
                    ))
                })?;
            if receipt.job_id != job.job_id
                || receipt.idempotency_key != job.idempotency_key
                || receipt.effect_receipt_id != job.effect_receipt_id
            {
                return Err(SupervisorError::StateInvariant(format!(
                    "job {} effect receipt binding mismatch",
                    job.job_id
                )));
            }
            if let Some(approval_id) = &job.approval_request_id {
                require_nonempty("approval_request_id", approval_id)?;
                approval_ids.insert(approval_id.clone());
            }
            if job.phase == JobPhase::Leased && job.lease.is_none() {
                return Err(SupervisorError::StateInvariant(format!(
                    "leased job {} has no lease",
                    job.job_id
                )));
            }
            if job.phase != JobPhase::Leased && job.lease.is_some() {
                return Err(SupervisorError::StateInvariant(format!(
                    "non-leased job {} retains a lease",
                    job.job_id
                )));
            }
            if job.phase.is_terminal() != job.terminal_outcome.is_some() {
                return Err(SupervisorError::StateInvariant(format!(
                    "job {} phase and terminal outcome disagree",
                    job.job_id
                )));
            }
            if job.phase == JobPhase::Succeeded
                && (receipt.status != EffectReceiptStatus::Committed || receipt.commit.is_none())
            {
                return Err(SupervisorError::StateInvariant(format!(
                    "succeeded job {} lacks a committed effect receipt",
                    job.job_id
                )));
            }
            for (index, attempt) in job.attempts.iter().enumerate() {
                if attempt.attempt_number != u32::try_from(index + 1).unwrap_or(u32::MAX) {
                    return Err(SupervisorError::StateInvariant(format!(
                        "job {} has non-contiguous attempts",
                        job.job_id
                    )));
                }
                if attempt.outcome.is_some() != attempt.ended_at_ms.is_some() {
                    return Err(SupervisorError::StateInvariant(format!(
                        "job {} attempt completion fields disagree",
                        job.job_id
                    )));
                }
            }
        }
        for resolution in self.approval_resolutions.values() {
            if !approval_ids.contains(&resolution.approval_request_id) {
                return Err(SupervisorError::StateInvariant(format!(
                    "approval resolution {} has no job",
                    resolution.approval_request_id
                )));
            }
        }
        for (receipt_id, receipt) in &self.effect_receipts {
            if receipt_id != &receipt.effect_receipt_id {
                return Err(SupervisorError::StateInvariant(
                    "effect receipt map key mismatch".to_string(),
                ));
            }
            match receipt.status {
                EffectReceiptStatus::Committed => {
                    let commit = receipt.commit.as_ref().ok_or_else(|| {
                        SupervisorError::StateInvariant(format!(
                            "committed receipt {receipt_id} has no commit"
                        ))
                    })?;
                    commit.validate()?;
                    if receipt.committed_at_ms.is_none() {
                        return Err(SupervisorError::StateInvariant(format!(
                            "committed receipt {receipt_id} has no timestamp"
                        )));
                    }
                }
                EffectReceiptStatus::Pending | EffectReceiptStatus::Dispatching => {
                    if receipt.commit.is_some() || receipt.committed_at_ms.is_some() {
                        return Err(SupervisorError::StateInvariant(format!(
                            "uncommitted receipt {receipt_id} contains a commit"
                        )));
                    }
                }
                EffectReceiptStatus::Abandoned => {
                    if receipt.abandoned_at_ms.is_none() || receipt.abandon_reason.is_none() {
                        return Err(SupervisorError::StateInvariant(format!(
                            "abandoned receipt {receipt_id} lacks reason or timestamp"
                        )));
                    }
                    if receipt.commit.is_some() || receipt.committed_at_ms.is_some() {
                        return Err(SupervisorError::StateInvariant(format!(
                            "abandoned receipt {receipt_id} contains a commit"
                        )));
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubmitJobOutcome {
    Created(DurableJob),
    Existing(DurableJob),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobDispatch {
    pub job_id: String,
    pub job_kind: String,
    pub payload_json: String,
    pub payload_digest: ContentDigest,
    pub idempotency_key: String,
    pub effect_receipt_id: String,
    pub lease_token: String,
    pub attempt_number: u32,
    pub lease_expires_at_ms: u64,
    pub attempt_deadline_at_ms: u64,
    pub job_deadline_at_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JobExecutionResult {
    EffectCommitted(EffectCommit),
    RetryableFailure {
        failure_class: String,
        detail: String,
    },
    PermanentFailure {
        failure_class: String,
        detail: String,
    },
    BlockedOnApproval {
        approval_request_id: String,
    },
}

pub trait IdempotentJobHandler {
    /// Execute the job using `dispatch.idempotency_key` as the logical effect
    /// key. Repeated calls with the same key must return the same committed
    /// effect instead of applying it twice.
    fn execute(&mut self, dispatch: &JobDispatch) -> JobExecutionResult;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompleteJobOutcome {
    Succeeded(JobTerminalOutcome),
    RetryScheduled { next_wake_at_ms: u64 },
    WaitingApproval { approval_request_id: String },
    Terminal(JobTerminalOutcome),
    AlreadyCommitted(JobTerminalOutcome),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunOnceOutcome {
    Idle {
        next_due_at_ms: Option<u64>,
    },
    Completed {
        job_id: String,
        outcome: CompleteJobOutcome,
    },
    Shutdown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupervisorStatus {
    pub schema_version: u32,
    pub revision: u64,
    pub heartbeat: SupervisorHeartbeat,
    pub queued_jobs: usize,
    pub waiting_approval_jobs: usize,
    pub leased_jobs: usize,
    pub terminal_jobs: usize,
}

#[derive(Clone, Debug)]
pub struct RunLoopOptions {
    pub max_idle_sleep: Duration,
}

impl Default for RunLoopOptions {
    fn default() -> Self {
        Self {
            max_idle_sleep: Duration::from_millis(100),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ShutdownToken {
    inner: Arc<ShutdownInner>,
}

#[derive(Debug)]
struct ShutdownInner {
    requested: AtomicBool,
    mutex: Mutex<()>,
    wake: Condvar,
}

impl ShutdownToken {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(ShutdownInner {
                requested: AtomicBool::new(false),
                mutex: Mutex::new(()),
                wake: Condvar::new(),
            }),
        }
    }

    pub fn request_shutdown(&self) {
        self.inner.requested.store(true, Ordering::Release);
        self.inner.wake.notify_all();
    }

    pub fn is_shutdown_requested(&self) -> bool {
        self.inner.requested.load(Ordering::Acquire)
    }

    fn wait(&self, duration: Duration) {
        if self.is_shutdown_requested() {
            return;
        }
        if let Ok(guard) = self.inner.mutex.lock() {
            let _ = self.inner.wake.wait_timeout(guard, duration);
        }
    }
}

impl Default for ShutdownToken {
    fn default() -> Self {
        Self::new()
    }
}

pub struct LocalDurableSupervisor {
    store: DurableSupervisorStore,
    state: SupervisorState,
    owner_id: String,
    clock: Arc<dyn SupervisorClock>,
    stopping: bool,
}

impl LocalDurableSupervisor {
    pub fn open(
        root: impl AsRef<Path>,
        owner_id: impl Into<String>,
        clock: Arc<dyn SupervisorClock>,
    ) -> Result<Self, SupervisorError> {
        let owner_id = owner_id.into();
        require_nonempty("owner_id", &owner_id)?;
        let now_ms = clock.now_ms();
        let store = DurableSupervisorStore::acquire(root.as_ref(), &owner_id, now_ms)?;
        let mut state = if store.state_path().exists() {
            store.read_current_state()?
        } else {
            let state = SupervisorState::empty(&owner_id, now_ms);
            state.validate()?;
            store.write_state(&state)?;
            state
        };
        state.heartbeat.owner_id = owner_id.clone();
        state.heartbeat.started_at_ms = now_ms;
        state.heartbeat.last_heartbeat_at_ms = now_ms;
        state.heartbeat.lifecycle = SupervisorLifecycleStatus::Running;
        reconcile_jobs(&mut state, now_ms, true)?;
        refresh_heartbeat(&mut state, now_ms);
        state.revision = state.revision.saturating_add(1);
        state.updated_at_ms = now_ms;
        state.validate()?;
        store.write_state(&state)?;
        Ok(Self {
            store,
            state,
            owner_id,
            clock,
            stopping: false,
        })
    }

    pub fn state(&self) -> &SupervisorState {
        &self.state
    }

    pub fn job(&self, job_id: &str) -> Option<&DurableJob> {
        self.state.jobs.get(job_id)
    }

    pub fn status(&self) -> SupervisorStatus {
        SupervisorStatus {
            schema_version: self.state.schema_version,
            revision: self.state.revision,
            heartbeat: self.state.heartbeat.clone(),
            queued_jobs: self
                .state
                .jobs
                .values()
                .filter(|job| matches!(job.phase, JobPhase::Queued | JobPhase::RetryScheduled))
                .count(),
            waiting_approval_jobs: self
                .state
                .jobs
                .values()
                .filter(|job| job.phase == JobPhase::WaitingApproval)
                .count(),
            leased_jobs: self
                .state
                .jobs
                .values()
                .filter(|job| job.phase == JobPhase::Leased)
                .count(),
            terminal_jobs: self
                .state
                .jobs
                .values()
                .filter(|job| job.phase.is_terminal())
                .count(),
        }
    }

    pub fn submit_job(
        &mut self,
        request: SubmitJobRequest,
    ) -> Result<SubmitJobOutcome, SupervisorError> {
        validate_submit_request(&request)?;
        if self.stopping {
            return Err(SupervisorError::SupervisorStopping);
        }
        let canonical_payload = canonicalize_json(&request.payload_json)?;
        let payload_digest = ContentDigest::from_bytes(canonical_payload.as_bytes());
        let fingerprint = digest_json_content(&(
            &request.job_kind,
            &canonical_payload,
            request.not_before_ms,
            request.deadline_at_ms,
            &request.retry_policy,
            &request.approval_request_id,
        ))?;
        if let Some(existing) = self.state.jobs.get(&request.job_id) {
            if existing.request_fingerprint == fingerprint
                && existing.idempotency_key == request.idempotency_key
            {
                return Ok(SubmitJobOutcome::Existing(existing.clone()));
            }
            return Err(SupervisorError::JobConflict {
                job_id: request.job_id,
            });
        }
        if let Some(existing_job_id) = self.state.idempotency_index.get(&request.idempotency_key) {
            let existing = self
                .state
                .jobs
                .get(existing_job_id)
                .expect("validated state keeps idempotency index resolvable");
            if existing.request_fingerprint == fingerprint {
                return Ok(SubmitJobOutcome::Existing(existing.clone()));
            }
            return Err(SupervisorError::IdempotencyConflict {
                idempotency_key: request.idempotency_key,
                existing_job_id: existing_job_id.clone(),
            });
        }

        let before = self.state.clone();
        let now_ms = self.clock.now_ms();
        let effect_receipt_id = effect_receipt_id(&request.idempotency_key)?;
        let phase = if request.approval_request_id.is_some() {
            JobPhase::WaitingApproval
        } else {
            JobPhase::Queued
        };
        let next_wake_at_ms = (phase == JobPhase::Queued).then_some(request.not_before_ms);
        let job = DurableJob {
            job_id: request.job_id.clone(),
            job_kind: request.job_kind,
            payload_json: canonical_payload,
            payload_digest,
            request_fingerprint: fingerprint,
            idempotency_key: request.idempotency_key.clone(),
            effect_receipt_id: effect_receipt_id.clone(),
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
            not_before_ms: request.not_before_ms,
            deadline_at_ms: request.deadline_at_ms,
            next_wake_at_ms,
            retry_policy: request.retry_policy,
            approval_request_id: request.approval_request_id,
            phase,
            lease: None,
            attempts: Vec::new(),
            cancellation: None,
            terminal_outcome: None,
        };
        self.state
            .idempotency_index
            .insert(request.idempotency_key.clone(), request.job_id.clone());
        self.state.effect_receipts.insert(
            effect_receipt_id.clone(),
            EffectReceipt {
                effect_receipt_id,
                job_id: request.job_id.clone(),
                idempotency_key: request.idempotency_key,
                status: EffectReceiptStatus::Pending,
                delivery_count: 0,
                first_dispatched_at_ms: None,
                last_dispatched_at_ms: None,
                committed_at_ms: None,
                abandoned_at_ms: None,
                abandon_reason: None,
                commit: None,
            },
        );
        self.state.jobs.insert(request.job_id.clone(), job.clone());
        record_wake(
            &mut self.state,
            &request.job_id,
            WakeKind::Submission,
            request.not_before_ms,
            now_ms,
        );
        self.persist_or_restore(before, now_ms)?;
        Ok(SubmitJobOutcome::Created(job))
    }

    pub fn resolve_approval(
        &mut self,
        resolution: ApprovalResolutionRecord,
    ) -> Result<Vec<String>, SupervisorError> {
        require_nonempty("approval_request_id", &resolution.approval_request_id)?;
        require_nonempty("approval evidence_ref", &resolution.evidence_ref)?;
        let matching_job_ids = self
            .state
            .jobs
            .values()
            .filter(|job| {
                job.approval_request_id.as_deref() == Some(resolution.approval_request_id.as_str())
            })
            .map(|job| job.job_id.clone())
            .collect::<Vec<_>>();
        if matching_job_ids.is_empty() {
            return Err(SupervisorError::ApprovalNotFound {
                approval_request_id: resolution.approval_request_id,
            });
        }
        if let Some(existing) = self
            .state
            .approval_resolutions
            .get(&resolution.approval_request_id)
        {
            if existing.resolution == resolution.resolution
                && existing.evidence_ref == resolution.evidence_ref
            {
                return Ok(matching_job_ids);
            }
            return Err(SupervisorError::ApprovalResolutionConflict {
                approval_request_id: resolution.approval_request_id,
            });
        }

        let before = self.state.clone();
        let now_ms = self.clock.now_ms();
        let normalized = ApprovalResolutionRecord {
            resolved_at_ms: now_ms,
            ..resolution
        };
        self.state
            .approval_resolutions
            .insert(normalized.approval_request_id.clone(), normalized.clone());
        for job_id in &matching_job_ids {
            let job = self
                .state
                .jobs
                .get_mut(job_id)
                .expect("matching job remains present");
            if job.phase != JobPhase::WaitingApproval {
                continue;
            }
            match normalized.resolution {
                ApprovalResolutionKind::Granted => {
                    job.phase = JobPhase::Queued;
                    job.next_wake_at_ms = Some(now_ms);
                    job.updated_at_ms = now_ms;
                    record_wake(
                        &mut self.state,
                        job_id,
                        WakeKind::ApprovalGranted,
                        now_ms,
                        now_ms,
                    );
                }
                ApprovalResolutionKind::Denied => {
                    set_terminal(
                        &mut self.state,
                        job_id,
                        JobPhase::Denied,
                        JobTerminalOutcome::ApprovalDenied {
                            approval_request_id: normalized.approval_request_id.clone(),
                            evidence_ref: normalized.evidence_ref.clone(),
                            completed_at_ms: now_ms,
                        },
                        now_ms,
                    )?;
                    record_wake(
                        &mut self.state,
                        job_id,
                        WakeKind::ApprovalDenied,
                        now_ms,
                        now_ms,
                    );
                }
                ApprovalResolutionKind::Expired => {
                    set_terminal(
                        &mut self.state,
                        job_id,
                        JobPhase::ApprovalExpired,
                        JobTerminalOutcome::ApprovalExpired {
                            approval_request_id: normalized.approval_request_id.clone(),
                            evidence_ref: normalized.evidence_ref.clone(),
                            completed_at_ms: now_ms,
                        },
                        now_ms,
                    )?;
                    record_wake(
                        &mut self.state,
                        job_id,
                        WakeKind::ApprovalExpired,
                        now_ms,
                        now_ms,
                    );
                }
                ApprovalResolutionKind::Escalated => {
                    set_terminal(
                        &mut self.state,
                        job_id,
                        JobPhase::ApprovalEscalated,
                        JobTerminalOutcome::ApprovalEscalated {
                            approval_request_id: normalized.approval_request_id.clone(),
                            evidence_ref: normalized.evidence_ref.clone(),
                            completed_at_ms: now_ms,
                        },
                        now_ms,
                    )?;
                    record_wake(
                        &mut self.state,
                        job_id,
                        WakeKind::ApprovalEscalated,
                        now_ms,
                        now_ms,
                    );
                }
            }
        }
        self.persist_or_restore(before, now_ms)?;
        Ok(matching_job_ids)
    }

    pub fn cancel_job(
        &mut self,
        job_id: &str,
        reason: impl Into<String>,
    ) -> Result<JobTerminalOutcome, SupervisorError> {
        let reason = reason.into();
        require_nonempty("cancellation reason", &reason)?;
        let existing = self
            .state
            .jobs
            .get(job_id)
            .ok_or_else(|| SupervisorError::JobNotFound {
                job_id: job_id.to_string(),
            })?;
        if let Some(outcome) = &existing.terminal_outcome {
            if let JobTerminalOutcome::Cancelled {
                reason: existing_reason,
                ..
            } = outcome
                && existing_reason == &reason
            {
                return Ok(outcome.clone());
            }
            return Err(SupervisorError::JobAlreadyTerminal {
                job_id: job_id.to_string(),
            });
        }
        let before = self.state.clone();
        let now_ms = self.clock.now_ms();
        if let Some(job) = self.state.jobs.get_mut(job_id) {
            job.cancellation = Some(CancellationRecord {
                reason: reason.clone(),
                requested_at_ms: now_ms,
            });
            if let Some(lease) = job.lease.clone() {
                finish_attempt(
                    job,
                    &lease.lease_token,
                    now_ms,
                    AttemptOutcome::Cancelled {
                        reason: reason.clone(),
                    },
                )?;
            }
        }
        let outcome = JobTerminalOutcome::Cancelled {
            reason,
            completed_at_ms: now_ms,
        };
        set_terminal(
            &mut self.state,
            job_id,
            JobPhase::Cancelled,
            outcome.clone(),
            now_ms,
        )?;
        record_wake(
            &mut self.state,
            job_id,
            WakeKind::Cancellation,
            now_ms,
            now_ms,
        );
        self.persist_or_restore(before, now_ms)?;
        Ok(outcome)
    }

    pub fn claim_due_job(&mut self) -> Result<Option<JobDispatch>, SupervisorError> {
        if self.stopping {
            return Ok(None);
        }
        let before = self.state.clone();
        let now_ms = self.clock.now_ms();
        reconcile_jobs(&mut self.state, now_ms, false)?;
        if self
            .state
            .jobs
            .values()
            .any(|job| job.phase == JobPhase::Leased)
        {
            refresh_heartbeat(&mut self.state, now_ms);
            if self.state != before {
                self.persist_or_restore(before, now_ms)?;
            }
            return Ok(None);
        }
        let selected = self
            .state
            .jobs
            .values()
            .filter(|job| {
                matches!(job.phase, JobPhase::Queued | JobPhase::RetryScheduled)
                    && job.next_wake_at_ms.is_some_and(|wake| wake <= now_ms)
                    && now_ms < job.deadline_at_ms
            })
            .min_by_key(|job| {
                (
                    job.next_wake_at_ms.unwrap_or(u64::MAX),
                    job.created_at_ms,
                    job.job_id.clone(),
                )
            })
            .map(|job| job.job_id.clone());
        let Some(job_id) = selected else {
            refresh_heartbeat(&mut self.state, now_ms);
            if self.state != before {
                self.persist_or_restore(before, now_ms)?;
            }
            return Ok(None);
        };

        let job = self
            .state
            .jobs
            .get_mut(&job_id)
            .expect("selected job remains present");
        let attempt_number = job.attempt_count().saturating_add(1);
        if attempt_number > job.retry_policy.max_attempts {
            set_retry_exhausted(
                &mut self.state,
                &job_id,
                "attempt budget exhausted before claim".to_string(),
                now_ms,
            )?;
            self.persist_or_restore(before, now_ms)?;
            return Ok(None);
        }
        let lease_token = format!(
            "lease:{}:{}:{}:{}",
            sanitize_id(&self.owner_id),
            sanitize_id(&job_id),
            attempt_number,
            self.state.revision.saturating_add(1)
        );
        let attempt_deadline_at_ms = now_ms
            .saturating_add(job.retry_policy.attempt_timeout_ms)
            .min(job.deadline_at_ms);
        let lease_expires_at_ms = now_ms
            .saturating_add(job.retry_policy.lease_duration_ms)
            .min(attempt_deadline_at_ms);
        let attempt_id = format!("attempt:{job_id}:{attempt_number}");
        job.phase = JobPhase::Leased;
        job.next_wake_at_ms = None;
        job.lease = Some(JobLease {
            owner_id: self.owner_id.clone(),
            lease_token: lease_token.clone(),
            attempt_number,
            acquired_at_ms: now_ms,
            expires_at_ms: lease_expires_at_ms,
            attempt_deadline_at_ms,
            last_heartbeat_at_ms: now_ms,
        });
        job.attempts.push(JobAttempt {
            attempt_id: attempt_id.clone(),
            attempt_number,
            lease_token: lease_token.clone(),
            started_at_ms: now_ms,
            ended_at_ms: None,
            outcome: None,
        });
        job.updated_at_ms = now_ms;
        let receipt = self
            .state
            .effect_receipts
            .get_mut(&job.effect_receipt_id)
            .expect("selected job has validated receipt");
        receipt.status = EffectReceiptStatus::Dispatching;
        receipt.delivery_count = receipt.delivery_count.saturating_add(1);
        receipt.first_dispatched_at_ms.get_or_insert(now_ms);
        receipt.last_dispatched_at_ms = Some(now_ms);
        for wake in self.state.wakes.iter_mut().filter(|wake| {
            wake.job_id == job_id && wake.consumed_at_ms.is_none() && wake.scheduled_at_ms <= now_ms
        }) {
            wake.consumed_at_ms = Some(now_ms);
        }
        self.state.heartbeat.last_attempt_id = Some(attempt_id);
        let dispatch = JobDispatch {
            job_id: job.job_id.clone(),
            job_kind: job.job_kind.clone(),
            payload_json: job.payload_json.clone(),
            payload_digest: job.payload_digest.clone(),
            idempotency_key: job.idempotency_key.clone(),
            effect_receipt_id: job.effect_receipt_id.clone(),
            lease_token,
            attempt_number,
            lease_expires_at_ms,
            attempt_deadline_at_ms,
            job_deadline_at_ms: job.deadline_at_ms,
        };
        self.persist_or_restore(before, now_ms)?;
        Ok(Some(dispatch))
    }

    pub fn heartbeat_lease(&mut self, dispatch: &JobDispatch) -> Result<u64, SupervisorError> {
        let before = self.state.clone();
        let now_ms = self.clock.now_ms();
        reconcile_jobs(&mut self.state, now_ms, false)?;
        let job = self.state.jobs.get_mut(&dispatch.job_id).ok_or_else(|| {
            SupervisorError::JobNotFound {
                job_id: dispatch.job_id.clone(),
            }
        })?;
        let lease = job
            .lease
            .as_mut()
            .filter(|lease| lease.lease_token == dispatch.lease_token)
            .ok_or_else(|| SupervisorError::StaleLease {
                job_id: dispatch.job_id.clone(),
                lease_token: dispatch.lease_token.clone(),
            })?;
        if now_ms >= lease.attempt_deadline_at_ms || now_ms >= job.deadline_at_ms {
            self.persist_or_restore(before, now_ms)?;
            return Err(SupervisorError::StaleLease {
                job_id: dispatch.job_id.clone(),
                lease_token: dispatch.lease_token.clone(),
            });
        }
        lease.last_heartbeat_at_ms = now_ms;
        lease.expires_at_ms = now_ms
            .saturating_add(job.retry_policy.lease_duration_ms)
            .min(lease.attempt_deadline_at_ms)
            .min(job.deadline_at_ms);
        let expires_at_ms = lease.expires_at_ms;
        job.updated_at_ms = now_ms;
        self.persist_or_restore(before, now_ms)?;
        Ok(expires_at_ms)
    }

    pub fn complete_dispatch(
        &mut self,
        dispatch: &JobDispatch,
        result: JobExecutionResult,
    ) -> Result<CompleteJobOutcome, SupervisorError> {
        let existing =
            self.state
                .jobs
                .get(&dispatch.job_id)
                .ok_or_else(|| SupervisorError::JobNotFound {
                    job_id: dispatch.job_id.clone(),
                })?;
        if let Some(outcome) = &existing.terminal_outcome {
            if matches!(outcome, JobTerminalOutcome::EffectCommitted { .. }) {
                return Ok(CompleteJobOutcome::AlreadyCommitted(outcome.clone()));
            }
            return Err(SupervisorError::JobAlreadyTerminal {
                job_id: dispatch.job_id.clone(),
            });
        }
        let before = self.state.clone();
        let now_ms = self.clock.now_ms();
        reconcile_jobs(&mut self.state, now_ms, false)?;
        let lease = self
            .state
            .jobs
            .get(&dispatch.job_id)
            .and_then(|job| job.lease.as_ref())
            .filter(|lease| lease.lease_token == dispatch.lease_token)
            .cloned()
            .ok_or_else(|| SupervisorError::StaleLease {
                job_id: dispatch.job_id.clone(),
                lease_token: dispatch.lease_token.clone(),
            })?;
        if now_ms >= lease.attempt_deadline_at_ms
            || now_ms >= lease.expires_at_ms
            || now_ms >= dispatch.job_deadline_at_ms
        {
            reconcile_jobs(&mut self.state, now_ms, false)?;
            self.persist_or_restore(before, now_ms)?;
            return Err(SupervisorError::StaleLease {
                job_id: dispatch.job_id.clone(),
                lease_token: dispatch.lease_token.clone(),
            });
        }

        let outcome = match result {
            JobExecutionResult::EffectCommitted(commit) => {
                commit.validate()?;
                let receipt_id = self
                    .state
                    .jobs
                    .get(&dispatch.job_id)
                    .expect("job remains present")
                    .effect_receipt_id
                    .clone();
                let receipt = self
                    .state
                    .effect_receipts
                    .get_mut(&receipt_id)
                    .expect("job receipt remains present");
                if let Some(existing_commit) = &receipt.commit {
                    if existing_commit != &commit {
                        return Err(SupervisorError::EffectReceiptConflict {
                            effect_receipt_id: receipt_id,
                        });
                    }
                } else {
                    receipt.commit = Some(commit.clone());
                }
                receipt.status = EffectReceiptStatus::Committed;
                receipt.committed_at_ms = Some(now_ms);
                let terminal = JobTerminalOutcome::EffectCommitted {
                    effect_receipt_id: receipt.effect_receipt_id.clone(),
                    effect_id: commit.effect_id.clone(),
                    result_digest: commit.result_digest.clone(),
                    completed_at_ms: now_ms,
                };
                if let Some(job) = self.state.jobs.get_mut(&dispatch.job_id) {
                    finish_attempt(
                        job,
                        &dispatch.lease_token,
                        now_ms,
                        AttemptOutcome::EffectCommitted {
                            effect_receipt_id: receipt.effect_receipt_id.clone(),
                            result_digest: commit.result_digest,
                        },
                    )?;
                }
                set_terminal(
                    &mut self.state,
                    &dispatch.job_id,
                    JobPhase::Succeeded,
                    terminal.clone(),
                    now_ms,
                )?;
                CompleteJobOutcome::Succeeded(terminal)
            }
            JobExecutionResult::RetryableFailure {
                failure_class,
                detail,
            } => {
                require_nonempty("failure_class", &failure_class)?;
                require_nonempty("failure detail", &detail)?;
                let attempt_outcome = AttemptOutcome::RetryableFailure {
                    failure_class: failure_class.clone(),
                    detail: detail.clone(),
                };
                finish_and_retry_or_exhaust(
                    &mut self.state,
                    &dispatch.job_id,
                    &dispatch.lease_token,
                    attempt_outcome,
                    format!("{failure_class}: {detail}"),
                    now_ms,
                    false,
                )?
            }
            JobExecutionResult::PermanentFailure {
                failure_class,
                detail,
            } => {
                require_nonempty("failure_class", &failure_class)?;
                require_nonempty("failure detail", &detail)?;
                if let Some(job) = self.state.jobs.get_mut(&dispatch.job_id) {
                    finish_attempt(
                        job,
                        &dispatch.lease_token,
                        now_ms,
                        AttemptOutcome::PermanentFailure {
                            failure_class: failure_class.clone(),
                            detail: detail.clone(),
                        },
                    )?;
                }
                let terminal = JobTerminalOutcome::PermanentFailure {
                    failure_class,
                    detail,
                    completed_at_ms: now_ms,
                };
                set_terminal(
                    &mut self.state,
                    &dispatch.job_id,
                    JobPhase::Failed,
                    terminal.clone(),
                    now_ms,
                )?;
                CompleteJobOutcome::Terminal(terminal)
            }
            JobExecutionResult::BlockedOnApproval {
                approval_request_id,
            } => {
                require_nonempty("approval_request_id", &approval_request_id)?;
                if self
                    .state
                    .approval_resolutions
                    .contains_key(&approval_request_id)
                {
                    return Err(SupervisorError::ApprovalResolutionConflict {
                        approval_request_id,
                    });
                }
                let job = self
                    .state
                    .jobs
                    .get_mut(&dispatch.job_id)
                    .expect("job remains present");
                finish_attempt(
                    job,
                    &dispatch.lease_token,
                    now_ms,
                    AttemptOutcome::ApprovalBlocked {
                        approval_request_id: approval_request_id.clone(),
                    },
                )?;
                job.phase = JobPhase::WaitingApproval;
                job.lease = None;
                job.next_wake_at_ms = None;
                job.approval_request_id = Some(approval_request_id.clone());
                job.updated_at_ms = now_ms;
                CompleteJobOutcome::WaitingApproval {
                    approval_request_id,
                }
            }
        };
        self.persist_or_restore(before, now_ms)?;
        Ok(outcome)
    }

    pub fn reconcile(&mut self) -> Result<bool, SupervisorError> {
        let before = self.state.clone();
        let now_ms = self.clock.now_ms();
        let changed = reconcile_jobs(&mut self.state, now_ms, false)?;
        refresh_heartbeat(&mut self.state, now_ms);
        if self.state != before {
            self.persist_or_restore(before, now_ms)?;
        }
        Ok(changed)
    }

    pub fn run_once<H: IdempotentJobHandler>(
        &mut self,
        handler: &mut H,
    ) -> Result<RunOnceOutcome, SupervisorError> {
        if self.stopping {
            return Ok(RunOnceOutcome::Shutdown);
        }
        let Some(dispatch) = self.claim_due_job()? else {
            return Ok(RunOnceOutcome::Idle {
                next_due_at_ms: self.state.heartbeat.next_due_at_ms,
            });
        };
        let result = handler.execute(&dispatch);
        let job_id = dispatch.job_id.clone();
        let outcome = self.complete_dispatch(&dispatch, result)?;
        Ok(RunOnceOutcome::Completed { job_id, outcome })
    }

    pub fn run_until_shutdown<H: IdempotentJobHandler>(
        &mut self,
        handler: &mut H,
        shutdown: &ShutdownToken,
        options: RunLoopOptions,
    ) -> Result<(), SupervisorError> {
        if options.max_idle_sleep.is_zero() {
            return Err(SupervisorError::InvalidRunLoopOptions(
                "max_idle_sleep must be non-zero".to_string(),
            ));
        }
        while !shutdown.is_shutdown_requested() {
            match self.run_once(handler)? {
                RunOnceOutcome::Completed { .. } => {}
                RunOnceOutcome::Idle { next_due_at_ms } => {
                    let now_ms = self.clock.now_ms();
                    let until_due = next_due_at_ms
                        .map(|due| Duration::from_millis(due.saturating_sub(now_ms)))
                        .unwrap_or(options.max_idle_sleep);
                    let sleep = until_due.min(options.max_idle_sleep);
                    shutdown.wait(sleep.max(Duration::from_millis(1)));
                }
                RunOnceOutcome::Shutdown => break,
            }
        }
        self.graceful_shutdown()
    }

    pub fn graceful_shutdown(&mut self) -> Result<(), SupervisorError> {
        if self.stopping && self.state.heartbeat.lifecycle == SupervisorLifecycleStatus::Stopped {
            return Ok(());
        }
        let before = self.state.clone();
        let now_ms = self.clock.now_ms();
        self.stopping = true;
        self.state.heartbeat.lifecycle = SupervisorLifecycleStatus::Stopping;
        let active_job = self
            .state
            .jobs
            .values()
            .find(|job| job.phase == JobPhase::Leased)
            .map(|job| job.job_id.clone());
        let active_leases = self
            .state
            .jobs
            .values()
            .filter_map(|job| {
                job.lease
                    .as_ref()
                    .map(|lease| (job.job_id.clone(), lease.lease_token.clone()))
            })
            .collect::<Vec<_>>();
        for (job_id, lease_token) in active_leases {
            finish_and_retry_or_exhaust(
                &mut self.state,
                &job_id,
                &lease_token,
                AttemptOutcome::LeaseLost {
                    detail: "graceful shutdown released the in-flight lease".to_string(),
                },
                "graceful shutdown released the in-flight lease".to_string(),
                now_ms,
                true,
            )?;
            let scheduled_at_ms = self.state.jobs[&job_id].next_wake_at_ms.unwrap_or(now_ms);
            record_wake(
                &mut self.state,
                &job_id,
                WakeKind::GracefulShutdownRequeue,
                scheduled_at_ms,
                now_ms,
            );
        }
        self.state.shutdowns.push(ShutdownRecord {
            owner_id: self.owner_id.clone(),
            requested_at_ms: now_ms,
            completed_at_ms: now_ms,
            active_job_at_request: active_job,
        });
        self.state.heartbeat.lifecycle = SupervisorLifecycleStatus::Stopped;
        self.persist_or_restore(before, now_ms)
    }

    fn persist_or_restore(
        &mut self,
        previous: SupervisorState,
        now_ms: u64,
    ) -> Result<(), SupervisorError> {
        self.state.revision = previous.revision.saturating_add(1);
        self.state.updated_at_ms = now_ms;
        refresh_heartbeat(&mut self.state, now_ms);
        if let Err(error) = self
            .state
            .validate()
            .and_then(|_| self.store.write_state(&self.state))
        {
            self.state = self.store.read_current_state().unwrap_or(previous);
            return Err(error);
        }
        Ok(())
    }
}

fn validate_submit_request(request: &SubmitJobRequest) -> Result<(), SupervisorError> {
    require_nonempty("job_id", &request.job_id)?;
    require_nonempty("job_kind", &request.job_kind)?;
    require_nonempty("idempotency_key", &request.idempotency_key)?;
    validate_identifier("job_id", &request.job_id)?;
    if request.payload_json.len() > MAX_PAYLOAD_BYTES {
        return Err(SupervisorError::PayloadTooLarge {
            limit: MAX_PAYLOAD_BYTES,
            actual: request.payload_json.len(),
        });
    }
    canonicalize_json(&request.payload_json)?;
    if request.deadline_at_ms <= request.not_before_ms {
        return Err(SupervisorError::InvalidDeadline {
            not_before_ms: request.not_before_ms,
            deadline_at_ms: request.deadline_at_ms,
        });
    }
    request.retry_policy.validate()?;
    if let Some(approval_request_id) = &request.approval_request_id {
        require_nonempty("approval_request_id", approval_request_id)?;
    }
    Ok(())
}

fn canonicalize_json(payload: &str) -> Result<String, SupervisorError> {
    let value = serde_json::from_str::<Value>(payload)
        .map_err(|error| SupervisorError::InvalidPayloadJson(error.to_string()))?;
    serde_json::to_string(&value).map_err(|error| SupervisorError::Serialization(error.to_string()))
}

fn effect_receipt_id(idempotency_key: &str) -> Result<String, SupervisorError> {
    let digest = digest_json_content(&("effect-receipt-v1", idempotency_key))?;
    Ok(format!("effect-receipt:{}", digest.file_stem()))
}

fn finish_attempt(
    job: &mut DurableJob,
    lease_token: &str,
    now_ms: u64,
    outcome: AttemptOutcome,
) -> Result<(), SupervisorError> {
    let attempt = job
        .attempts
        .iter_mut()
        .rev()
        .find(|attempt| attempt.lease_token == lease_token)
        .ok_or_else(|| SupervisorError::StaleLease {
            job_id: job.job_id.clone(),
            lease_token: lease_token.to_string(),
        })?;
    if attempt.outcome.is_some() {
        return Err(SupervisorError::AttemptAlreadyCompleted {
            attempt_id: attempt.attempt_id.clone(),
        });
    }
    attempt.ended_at_ms = Some(now_ms);
    attempt.outcome = Some(outcome);
    Ok(())
}

fn finish_and_retry_or_exhaust(
    state: &mut SupervisorState,
    job_id: &str,
    lease_token: &str,
    attempt_outcome: AttemptOutcome,
    last_failure: String,
    now_ms: u64,
    immediate_retry: bool,
) -> Result<CompleteJobOutcome, SupervisorError> {
    let job = state
        .jobs
        .get_mut(job_id)
        .ok_or_else(|| SupervisorError::JobNotFound {
            job_id: job_id.to_string(),
        })?;
    finish_attempt(job, lease_token, now_ms, attempt_outcome)?;
    job.lease = None;
    let attempts = job.attempt_count();
    if attempts >= job.retry_policy.max_attempts {
        let terminal = JobTerminalOutcome::RetryExhausted {
            last_failure,
            completed_at_ms: now_ms,
        };
        set_terminal(
            state,
            job_id,
            JobPhase::RetryExhausted,
            terminal.clone(),
            now_ms,
        )?;
        return Ok(CompleteJobOutcome::Terminal(terminal));
    }
    let delay = if immediate_retry {
        0
    } else {
        job.retry_policy.backoff_after_attempt(attempts)
    };
    let next_wake_at_ms = now_ms.saturating_add(delay);
    if next_wake_at_ms >= job.deadline_at_ms {
        let terminal = JobTerminalOutcome::DeadlineExceeded {
            completed_at_ms: now_ms,
        };
        set_terminal(
            state,
            job_id,
            JobPhase::DeadlineExceeded,
            terminal.clone(),
            now_ms,
        )?;
        return Ok(CompleteJobOutcome::Terminal(terminal));
    }
    let job = state.jobs.get_mut(job_id).expect("job remains present");
    job.phase = JobPhase::RetryScheduled;
    job.next_wake_at_ms = Some(next_wake_at_ms);
    job.updated_at_ms = now_ms;
    record_wake(state, job_id, WakeKind::Retry, next_wake_at_ms, now_ms);
    Ok(CompleteJobOutcome::RetryScheduled { next_wake_at_ms })
}

fn set_terminal(
    state: &mut SupervisorState,
    job_id: &str,
    phase: JobPhase,
    outcome: JobTerminalOutcome,
    now_ms: u64,
) -> Result<(), SupervisorError> {
    if !phase.is_terminal() {
        return Err(SupervisorError::StateInvariant(
            "set_terminal received a non-terminal phase".to_string(),
        ));
    }
    let job = state
        .jobs
        .get_mut(job_id)
        .ok_or_else(|| SupervisorError::JobNotFound {
            job_id: job_id.to_string(),
        })?;
    job.phase = phase;
    job.lease = None;
    job.next_wake_at_ms = None;
    job.terminal_outcome = Some(outcome.clone());
    job.updated_at_ms = now_ms;
    if !matches!(outcome, JobTerminalOutcome::EffectCommitted { .. })
        && let Some(receipt) = state.effect_receipts.get_mut(&job.effect_receipt_id)
        && receipt.status != EffectReceiptStatus::Committed
    {
        receipt.status = EffectReceiptStatus::Abandoned;
        receipt.abandoned_at_ms = Some(now_ms);
        receipt.abandon_reason = Some(format!("{:?}", job.phase));
    }
    state.heartbeat.last_terminal_job_id = Some(job_id.to_string());
    state.heartbeat.last_terminal_outcome = Some(outcome);
    Ok(())
}

fn set_retry_exhausted(
    state: &mut SupervisorState,
    job_id: &str,
    last_failure: String,
    now_ms: u64,
) -> Result<(), SupervisorError> {
    set_terminal(
        state,
        job_id,
        JobPhase::RetryExhausted,
        JobTerminalOutcome::RetryExhausted {
            last_failure,
            completed_at_ms: now_ms,
        },
        now_ms,
    )
}

fn reconcile_jobs(
    state: &mut SupervisorState,
    now_ms: u64,
    startup: bool,
) -> Result<bool, SupervisorError> {
    let mut changed = false;
    let job_ids = state.jobs.keys().cloned().collect::<Vec<_>>();
    for job_id in job_ids {
        let phase = state
            .jobs
            .get(&job_id)
            .map(|job| job.phase.clone())
            .expect("job id came from state");
        if phase.is_terminal() {
            continue;
        }
        let deadline_at_ms = state.jobs[&job_id].deadline_at_ms;
        if now_ms >= deadline_at_ms {
            if let Some(lease) = state.jobs[&job_id].lease.clone()
                && let Some(job) = state.jobs.get_mut(&job_id)
            {
                finish_attempt(
                    job,
                    &lease.lease_token,
                    now_ms,
                    AttemptOutcome::DeadlineExceeded,
                )?;
            }
            set_terminal(
                state,
                &job_id,
                JobPhase::DeadlineExceeded,
                JobTerminalOutcome::DeadlineExceeded {
                    completed_at_ms: now_ms,
                },
                now_ms,
            )?;
            record_wake(state, &job_id, WakeKind::Deadline, now_ms, now_ms);
            changed = true;
            continue;
        }
        if phase != JobPhase::Leased {
            continue;
        }
        let lease = state.jobs[&job_id]
            .lease
            .clone()
            .expect("leased job has validated lease");
        let failure = if startup {
            Some((
                AttemptOutcome::LeaseLost {
                    detail: "startup reconciled an abandoned in-flight lease".to_string(),
                },
                "abandoned lease recovered at startup".to_string(),
                WakeKind::StartupLeaseReconciliation,
                true,
            ))
        } else if now_ms >= lease.attempt_deadline_at_ms {
            Some((
                AttemptOutcome::TimedOut {
                    detail: "attempt exceeded its configured timeout".to_string(),
                },
                "attempt timeout".to_string(),
                WakeKind::AttemptTimedOut,
                false,
            ))
        } else if now_ms >= lease.expires_at_ms {
            Some((
                AttemptOutcome::LeaseLost {
                    detail: "lease expired before completion".to_string(),
                },
                "lease expired".to_string(),
                WakeKind::LeaseExpired,
                false,
            ))
        } else {
            None
        };
        if let Some((outcome, detail, wake_kind, immediate)) = failure {
            finish_and_retry_or_exhaust(
                state,
                &job_id,
                &lease.lease_token,
                outcome,
                detail,
                now_ms,
                immediate,
            )?;
            let scheduled = state.jobs[&job_id].next_wake_at_ms.unwrap_or(now_ms);
            record_wake(state, &job_id, wake_kind, scheduled, now_ms);
            changed = true;
        }
    }
    Ok(changed)
}

fn record_wake(
    state: &mut SupervisorState,
    job_id: &str,
    kind: WakeKind,
    scheduled_at_ms: u64,
    recorded_at_ms: u64,
) {
    let wake_id = format!(
        "wake:{}:{}:{}",
        sanitize_id(job_id),
        recorded_at_ms,
        state.wakes.len().saturating_add(1)
    );
    state.wakes.push(WakeRecord {
        wake_id,
        job_id: job_id.to_string(),
        kind,
        scheduled_at_ms,
        recorded_at_ms,
        consumed_at_ms: None,
    });
}

fn refresh_heartbeat(state: &mut SupervisorState, now_ms: u64) {
    state.heartbeat.last_heartbeat_at_ms = now_ms;
    state.heartbeat.next_due_at_ms = next_due_at(state);
    let active = state
        .jobs
        .values()
        .find_map(|job| job.lease.as_ref().map(|lease| (job, lease)));
    state.heartbeat.active_job_id = active.map(|(job, _)| job.job_id.clone());
    state.heartbeat.active_lease_owner = active.map(|(_, lease)| lease.owner_id.clone());
}

fn next_due_at(state: &SupervisorState) -> Option<u64> {
    state
        .jobs
        .values()
        .filter(|job| !job.phase.is_terminal())
        .flat_map(|job| {
            let mut due = vec![job.deadline_at_ms];
            if let Some(next_wake) = job.next_wake_at_ms {
                due.push(next_wake);
            }
            if let Some(lease) = &job.lease {
                due.push(lease.expires_at_ms);
                due.push(lease.attempt_deadline_at_ms);
            }
            due
        })
        .min()
}

#[derive(Debug)]
struct DurableSupervisorStore {
    root: PathBuf,
    backups_root: PathBuf,
    lock_file: File,
    // Declared last so the canonical-root reservation outlives the OS lock
    // file and every other store field during destruction.
    _in_process_owner: InProcessSupervisorRootOwner,
}

impl DurableSupervisorStore {
    fn acquire(root: &Path, owner_id: &str, now_ms: u64) -> Result<Self, SupervisorError> {
        reject_terminal_symlink(root)?;
        fs::create_dir_all(root)
            .map_err(|source| io_error("create supervisor root", root, source))?;
        let root = fs::canonicalize(root)
            .map_err(|source| io_error("canonicalize supervisor root", root, source))?;
        let backups_root = root.join(BACKUP_DIRECTORY_NAME);
        reject_terminal_symlink(&backups_root)?;
        fs::create_dir_all(&backups_root)
            .map_err(|source| io_error("create supervisor backup root", &backups_root, source))?;
        let backups_root = fs::canonicalize(&backups_root).map_err(|source| {
            io_error("canonicalize supervisor backup root", &backups_root, source)
        })?;
        ensure_direct_child(&root, &backups_root)?;

        // Some operating systems key advisory locks to the opened inode. If a
        // same-process actor replaces the lock path, another descriptor could
        // otherwise lock the replacement while the first owner remains live.
        // Reserve the canonical root before opening the lock file so path or
        // inode replacement cannot create two in-process writers.
        let in_process_owner = InProcessSupervisorRootOwner::acquire(&root)?;
        let lock_path = root.join(LOCK_FILE_NAME);
        reject_terminal_symlink(&lock_path)?;
        let mut lock_file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .map_err(|source| io_error("open supervisor writer lock", &lock_path, source))?;
        match lock_file.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(SupervisorError::WriterAlreadyActive { path: lock_path });
            }
            Err(std::fs::TryLockError::Error(source)) => {
                return Err(io_error(
                    "acquire supervisor writer lock",
                    &lock_path,
                    source,
                ));
            }
        }
        cleanup_staged_files(&root)?;
        cleanup_staged_files(&backups_root)?;
        lock_file
            .set_len(0)
            .and_then(|_| lock_file.seek(SeekFrom::Start(0)))
            .and_then(|_| lock_file.write_all(format!("{owner_id}\n{now_ms}\n").as_bytes()))
            .and_then(|_| lock_file.sync_all())
            .map_err(|source| io_error("write supervisor writer lock", &lock_path, source))?;

        Ok(Self {
            root,
            backups_root,
            lock_file,
            _in_process_owner: in_process_owner,
        })
    }

    fn state_path(&self) -> PathBuf {
        self.root.join(STATE_FILE_NAME)
    }

    fn read_raw_state(&self) -> Result<Vec<u8>, SupervisorError> {
        let path = self.state_path();
        reject_non_regular_file(&path, "supervisor state")?;
        let mut bytes = Vec::new();
        File::open(&path)
            .map_err(|source| io_error("open supervisor state", &path, source))?
            .read_to_end(&mut bytes)
            .map_err(|source| io_error("read supervisor state", &path, source))?;
        Ok(bytes)
    }

    fn read_current_state(&self) -> Result<SupervisorState, SupervisorError> {
        let bytes = self.read_raw_state()?;
        let version = schema_version_from_bytes(&bytes)?;
        if version != SUPERVISOR_STATE_SCHEMA_VERSION {
            return Err(SupervisorError::MigrationRequired {
                found: version,
                target: SUPERVISOR_STATE_SCHEMA_VERSION,
            });
        }
        let state = serde_json::from_slice::<SupervisorState>(&bytes)
            .map_err(|error| SupervisorError::CorruptState(error.to_string()))?;
        state.validate()?;
        Ok(state)
    }

    fn write_state(&self, state: &SupervisorState) -> Result<(), SupervisorError> {
        state.validate()?;
        let bytes = serde_json::to_vec_pretty(state)
            .map_err(|error| SupervisorError::Serialization(error.to_string()))?;
        atomic_replace(&self.root, &self.state_path(), &bytes)
    }

    fn write_raw_state(&self, bytes: &[u8]) -> Result<(), SupervisorError> {
        atomic_replace(&self.root, &self.state_path(), bytes)
    }

    fn create_backup(&self, bytes: &[u8]) -> Result<String, SupervisorError> {
        let backup_id = backup_id_for(bytes)?;
        validate_identifier("backup_id", &backup_id)?;
        let path = self.backups_root.join(&backup_id);
        ensure_direct_child(&self.backups_root, &path)?;
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Err(SupervisorError::UnsafePath {
                        path,
                        reason: "existing backup is not a regular file",
                    });
                }
                let existing = fs::read(&path)
                    .map_err(|source| io_error("read existing supervisor backup", &path, source))?;
                if existing != bytes {
                    return Err(SupervisorError::BackupConflict { backup_id });
                }
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                atomic_create(&self.backups_root, &path, bytes)?;
            }
            Err(source) => {
                return Err(io_error("inspect supervisor backup", &path, source));
            }
        }
        Ok(backup_id)
    }

    fn read_backup(&self, backup_id: &str) -> Result<Vec<u8>, SupervisorError> {
        validate_identifier("backup_id", backup_id)?;
        let path = self.backups_root.join(backup_id);
        ensure_direct_child(&self.backups_root, &path)?;
        reject_non_regular_file(&path, "supervisor backup")?;
        fs::read(&path).map_err(|source| io_error("read supervisor backup", &path, source))
    }
}

impl Drop for DurableSupervisorStore {
    fn drop(&mut self) {
        let _ = self.lock_file.unlock();
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacySupervisorJobV1 {
    pub job_id: String,
    pub job_kind: String,
    pub payload_json: String,
    pub idempotency_key: String,
    pub not_before_ms: u64,
    pub deadline_at_ms: u64,
    pub max_attempts: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacySupervisorStateV1 {
    pub schema_version: u32,
    pub revision: u64,
    pub created_at_ms: u64,
    pub jobs: Vec<LegacySupervisorJobV1>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationPlan {
    pub from_version: u32,
    pub to_version: u32,
    pub planned_at_ms: u64,
    pub job_count: usize,
    pub source_digest: ContentDigest,
    pub candidate_digest: ContentDigest,
    pub backup_required: bool,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationOutcome {
    pub plan: MigrationPlan,
    pub backup_id: Option<String>,
}

pub struct SupervisorStoreAdmin {
    store: DurableSupervisorStore,
    owner_id: String,
    clock: Arc<dyn SupervisorClock>,
}

impl SupervisorStoreAdmin {
    pub fn open(
        root: impl AsRef<Path>,
        owner_id: impl Into<String>,
        clock: Arc<dyn SupervisorClock>,
    ) -> Result<Self, SupervisorError> {
        let owner_id = owner_id.into();
        require_nonempty("owner_id", &owner_id)?;
        let store = DurableSupervisorStore::acquire(root.as_ref(), &owner_id, clock.now_ms())?;
        if !store.state_path().exists() {
            return Err(SupervisorError::StateNotFound);
        }
        Ok(Self {
            store,
            owner_id,
            clock,
        })
    }

    pub fn stored_schema_version(&self) -> Result<u32, SupervisorError> {
        schema_version_from_bytes(&self.store.read_raw_state()?)
    }

    pub fn dry_run_migration(&self, target_version: u32) -> Result<MigrationPlan, SupervisorError> {
        if target_version != SUPERVISOR_STATE_SCHEMA_VERSION {
            return Err(SupervisorError::UnsupportedMigrationTarget {
                target: target_version,
            });
        }
        let source = self.store.read_raw_state()?;
        let source_version = schema_version_from_bytes(&source)?;
        let planned_at_ms = self.clock.now_ms();
        if source_version == SUPERVISOR_STATE_SCHEMA_VERSION {
            let state = self.store.read_current_state()?;
            let digest = ContentDigest::from_bytes(&source);
            return Ok(MigrationPlan {
                from_version: source_version,
                to_version: target_version,
                planned_at_ms,
                job_count: state.jobs.len(),
                source_digest: digest.clone(),
                candidate_digest: digest,
                backup_required: false,
                notes: vec!["state already uses the current schema".to_string()],
            });
        }
        if source_version != LEGACY_SUPERVISOR_STATE_SCHEMA_VERSION {
            return Err(SupervisorError::UnsupportedSchemaVersion {
                found: source_version,
                supported: SUPERVISOR_STATE_SCHEMA_VERSION,
            });
        }
        let predicted_backup_id = backup_id_for(&source)?;
        let candidate = migrate_v1_bytes(
            &source,
            &self.owner_id,
            planned_at_ms,
            Some(&predicted_backup_id),
        )?
        .0;
        let candidate_bytes = serde_json::to_vec_pretty(&candidate)
            .map_err(|error| SupervisorError::Serialization(error.to_string()))?;
        Ok(MigrationPlan {
            from_version: source_version,
            to_version: target_version,
            planned_at_ms,
            job_count: candidate.jobs.len(),
            source_digest: ContentDigest::from_bytes(&source),
            candidate_digest: ContentDigest::from_bytes(&candidate_bytes),
            backup_required: true,
            notes: vec![
                "dry-run only; no state or backup bytes were written".to_string(),
                "v1 jobs become queued v2 at-least-once jobs with pending effect receipts"
                    .to_string(),
            ],
        })
    }

    pub fn migrate_to_current(&mut self) -> Result<MigrationOutcome, SupervisorError> {
        self.migrate_to_current_with_validator(|_| Ok(()))
    }

    pub fn migrate_to_current_with_validator<F>(
        &mut self,
        successor_validator: F,
    ) -> Result<MigrationOutcome, SupervisorError>
    where
        F: FnOnce(&SupervisorState) -> Result<(), String>,
    {
        let plan = self.dry_run_migration(SUPERVISOR_STATE_SCHEMA_VERSION)?;
        if !plan.backup_required {
            return Ok(MigrationOutcome {
                plan,
                backup_id: None,
            });
        }
        let source = self.store.read_raw_state()?;
        let backup_id = self.store.create_backup(&source)?;
        let (candidate, _) = migrate_v1_bytes(
            &source,
            &self.owner_id,
            plan.planned_at_ms,
            Some(&backup_id),
        )?;
        let candidate_bytes = serde_json::to_vec_pretty(&candidate)
            .map_err(|error| SupervisorError::Serialization(error.to_string()))?;
        let candidate_digest = ContentDigest::from_bytes(&candidate_bytes);
        if candidate_digest != plan.candidate_digest {
            return Err(SupervisorError::MigrationTransformFailed(format!(
                "dry-run candidate {} changed before commit to {}",
                plan.candidate_digest, candidate_digest
            )));
        }
        successor_validator(&candidate).map_err(|reason| {
            SupervisorError::MigrationValidationFailed {
                backup_id: backup_id.clone(),
                reason,
            }
        })?;
        candidate.validate()?;
        self.store.write_state(&candidate)?;
        match self.store.read_current_state() {
            Ok(_) => Ok(MigrationOutcome {
                plan,
                backup_id: Some(backup_id),
            }),
            Err(error) => {
                self.store.write_raw_state(&source)?;
                Err(SupervisorError::MigrationCommitFailed {
                    backup_id,
                    reason: error.to_string(),
                })
            }
        }
    }

    pub fn restore_backup(&mut self, backup_id: &str) -> Result<u32, SupervisorError> {
        let replacement = self.store.read_backup(backup_id)?;
        let replacement_version = schema_version_from_bytes(&replacement)?;
        validate_supported_state_bytes(&replacement, &self.owner_id, self.clock.now_ms())?;
        let current = self.store.read_raw_state()?;
        self.store.create_backup(&current)?;
        self.store.write_raw_state(&replacement)?;
        let written = self.store.read_raw_state()?;
        if written != replacement {
            self.store.write_raw_state(&current)?;
            return Err(SupervisorError::RestoreVerificationFailed {
                backup_id: backup_id.to_string(),
            });
        }
        Ok(replacement_version)
    }
}

fn migrate_v1_bytes(
    source: &[u8],
    owner_id: &str,
    now_ms: u64,
    backup_id: Option<&str>,
) -> Result<(SupervisorState, LegacySupervisorStateV1), SupervisorError> {
    let legacy = serde_json::from_slice::<LegacySupervisorStateV1>(source)
        .map_err(|error| SupervisorError::CorruptState(error.to_string()))?;
    if legacy.schema_version != LEGACY_SUPERVISOR_STATE_SCHEMA_VERSION {
        return Err(SupervisorError::UnsupportedSchemaVersion {
            found: legacy.schema_version,
            supported: LEGACY_SUPERVISOR_STATE_SCHEMA_VERSION,
        });
    }
    let mut state = SupervisorState::empty(owner_id, now_ms);
    state.created_at_ms = legacy.created_at_ms;
    state.revision = legacy.revision.saturating_add(1);
    for legacy_job in &legacy.jobs {
        validate_identifier("legacy job_id", &legacy_job.job_id)?;
        require_nonempty("legacy job_kind", &legacy_job.job_kind)?;
        require_nonempty("legacy idempotency_key", &legacy_job.idempotency_key)?;
        if legacy_job.deadline_at_ms <= legacy_job.not_before_ms || legacy_job.max_attempts == 0 {
            return Err(SupervisorError::MigrationTransformFailed(format!(
                "legacy job {} has invalid scheduling or retry fields",
                legacy_job.job_id
            )));
        }
        if state.jobs.contains_key(&legacy_job.job_id)
            || state
                .idempotency_index
                .contains_key(&legacy_job.idempotency_key)
        {
            return Err(SupervisorError::MigrationTransformFailed(format!(
                "legacy job {} duplicates a job id or idempotency key",
                legacy_job.job_id
            )));
        }
        let payload_json = canonicalize_json(&legacy_job.payload_json)?;
        let payload_digest = ContentDigest::from_bytes(payload_json.as_bytes());
        let retry_policy = RetryPolicy {
            max_attempts: legacy_job.max_attempts,
            ..RetryPolicy::default()
        };
        let fingerprint = digest_json_content(&(
            &legacy_job.job_kind,
            &payload_json,
            legacy_job.not_before_ms,
            legacy_job.deadline_at_ms,
            &retry_policy,
            Option::<String>::None,
        ))?;
        let receipt_id = effect_receipt_id(&legacy_job.idempotency_key)?;
        state.idempotency_index.insert(
            legacy_job.idempotency_key.clone(),
            legacy_job.job_id.clone(),
        );
        state.effect_receipts.insert(
            receipt_id.clone(),
            EffectReceipt {
                effect_receipt_id: receipt_id.clone(),
                job_id: legacy_job.job_id.clone(),
                idempotency_key: legacy_job.idempotency_key.clone(),
                status: EffectReceiptStatus::Pending,
                delivery_count: 0,
                first_dispatched_at_ms: None,
                last_dispatched_at_ms: None,
                committed_at_ms: None,
                abandoned_at_ms: None,
                abandon_reason: None,
                commit: None,
            },
        );
        state.jobs.insert(
            legacy_job.job_id.clone(),
            DurableJob {
                job_id: legacy_job.job_id.clone(),
                job_kind: legacy_job.job_kind.clone(),
                payload_json,
                payload_digest,
                request_fingerprint: fingerprint,
                idempotency_key: legacy_job.idempotency_key.clone(),
                effect_receipt_id: receipt_id,
                created_at_ms: legacy.created_at_ms,
                updated_at_ms: now_ms,
                not_before_ms: legacy_job.not_before_ms,
                deadline_at_ms: legacy_job.deadline_at_ms,
                next_wake_at_ms: Some(legacy_job.not_before_ms),
                retry_policy,
                approval_request_id: None,
                phase: JobPhase::Queued,
                lease: None,
                attempts: Vec::new(),
                cancellation: None,
                terminal_outcome: None,
            },
        );
        record_wake(
            &mut state,
            &legacy_job.job_id,
            WakeKind::Submission,
            legacy_job.not_before_ms,
            now_ms,
        );
    }
    if let Some(backup_id) = backup_id {
        state.migrations.push(MigrationRecord {
            from_version: LEGACY_SUPERVISOR_STATE_SCHEMA_VERSION,
            to_version: SUPERVISOR_STATE_SCHEMA_VERSION,
            backup_id: backup_id.to_string(),
            source_digest: ContentDigest::from_bytes(source),
            migrated_at_ms: now_ms,
        });
    }
    refresh_heartbeat(&mut state, now_ms);
    state.validate()?;
    Ok((state, legacy))
}

fn backup_id_for(bytes: &[u8]) -> Result<String, SupervisorError> {
    let version = schema_version_from_bytes(bytes)?;
    let digest = ContentDigest::from_bytes(bytes);
    Ok(format!(
        "supervisor-state-v{version}-{}.json",
        digest.file_stem()
    ))
}

fn validate_supported_state_bytes(
    bytes: &[u8],
    owner_id: &str,
    now_ms: u64,
) -> Result<(), SupervisorError> {
    match schema_version_from_bytes(bytes)? {
        SUPERVISOR_STATE_SCHEMA_VERSION => {
            let state = serde_json::from_slice::<SupervisorState>(bytes)
                .map_err(|error| SupervisorError::CorruptState(error.to_string()))?;
            state.validate()
        }
        LEGACY_SUPERVISOR_STATE_SCHEMA_VERSION => {
            migrate_v1_bytes(bytes, owner_id, now_ms, None)?;
            Ok(())
        }
        found => Err(SupervisorError::UnsupportedSchemaVersion {
            found,
            supported: SUPERVISOR_STATE_SCHEMA_VERSION,
        }),
    }
}

fn schema_version_from_bytes(bytes: &[u8]) -> Result<u32, SupervisorError> {
    let value = serde_json::from_slice::<Value>(bytes)
        .map_err(|error| SupervisorError::CorruptState(error.to_string()))?;
    let version = value
        .get("schema_version")
        .and_then(Value::as_u64)
        .and_then(|version| u32::try_from(version).ok())
        .ok_or_else(|| {
            SupervisorError::CorruptState(
                "supervisor state has no valid schema_version".to_string(),
            )
        })?;
    Ok(version)
}

fn atomic_temporary_create_error(
    root: &Path,
    temporary: &Path,
    source: std::io::Error,
    ordinary_operation: &'static str,
    root_present_operation: &'static str,
    root_missing_operation: &'static str,
    root_unknown_operation: &'static str,
) -> SupervisorError {
    if source.kind() != std::io::ErrorKind::NotFound {
        return io_error(ordinary_operation, temporary, source);
    }
    let operation = match fs::symlink_metadata(root) {
        Ok(_) => root_present_operation,
        Err(parent_error) if parent_error.kind() == std::io::ErrorKind::NotFound => {
            root_missing_operation
        }
        Err(_) => root_unknown_operation,
    };
    io_error(operation, temporary, source)
}

fn atomic_replace(root: &Path, target: &Path, bytes: &[u8]) -> Result<(), SupervisorError> {
    ensure_direct_child(root, target)?;
    reject_terminal_symlink(target)?;
    let sequence = TEMPORARY_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = root.join(format!(
        ".{}-{}-{sequence}.tmp",
        target
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("state"),
        std::process::id()
    ));
    ensure_direct_child(root, &temporary)?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .map_err(|source| {
            atomic_temporary_create_error(
                root,
                &temporary,
                source,
                "create atomic supervisor file",
                "create atomic supervisor file (supervisor root present)",
                "create atomic supervisor file (supervisor root missing)",
                "create atomic supervisor file (supervisor root status unknown)",
            )
        })?;
    let result = (|| {
        file.write_all(bytes)
            .map_err(|source| io_error("write atomic supervisor file", &temporary, source))?;
        file.sync_all()
            .map_err(|source| io_error("sync atomic supervisor file", &temporary, source))?;
        drop(file);
        fs::rename(&temporary, target)
            .map_err(|source| io_error("replace durable supervisor file", target, source))?;
        File::open(root)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| io_error("sync supervisor root", root, source))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn atomic_create(root: &Path, target: &Path, bytes: &[u8]) -> Result<(), SupervisorError> {
    ensure_direct_child(root, target)?;
    reject_terminal_symlink(target)?;
    let sequence = TEMPORARY_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = root.join(format!(
        ".{}-{}-{sequence}.tmp",
        target
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("new"),
        std::process::id()
    ));
    ensure_direct_child(root, &temporary)?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .map_err(|source| {
            atomic_temporary_create_error(
                root,
                &temporary,
                source,
                "create staged supervisor file",
                "create staged supervisor file (supervisor root present)",
                "create staged supervisor file (supervisor root missing)",
                "create staged supervisor file (supervisor root status unknown)",
            )
        })?;
    let result = (|| {
        file.write_all(bytes)
            .map_err(|source| io_error("write staged supervisor file", &temporary, source))?;
        file.sync_all()
            .map_err(|source| io_error("sync staged supervisor file", &temporary, source))?;
        drop(file);
        fs::hard_link(&temporary, target)
            .map_err(|source| io_error("publish durable supervisor file", target, source))?;
        fs::remove_file(&temporary)
            .map_err(|source| io_error("remove staged supervisor file", &temporary, source))?;
        File::open(root)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| io_error("sync supervisor directory", root, source))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn reject_terminal_symlink(path: &Path) -> Result<(), SupervisorError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(SupervisorError::UnsafePath {
            path: path.to_path_buf(),
            reason: "symbolic links are forbidden at durable supervisor boundaries",
        }),
        Ok(_) => Ok(()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error("inspect supervisor path", path, source)),
    }
}

fn cleanup_staged_files(directory: &Path) -> Result<(), SupervisorError> {
    let entries = fs::read_dir(directory)
        .map_err(|source| io_error("read supervisor service directory", directory, source))?;
    for entry in entries {
        let entry =
            entry.map_err(|source| io_error("read supervisor staged entry", directory, source))?;
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        if !file_name.starts_with(".supervisor-state") || !file_name.ends_with(".tmp") {
            continue;
        }
        cleanup_staged_file(&entry.path())?;
    }
    Ok(())
}

fn cleanup_staged_file(path: &Path) -> Result<(), SupervisorError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(io_error("inspect supervisor staged file", path, source));
        }
    };
    if metadata.is_file() || metadata.file_type().is_symlink() {
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(io_error("remove abandoned staged file", path, source));
            }
        }
    }
    Ok(())
}

fn reject_non_regular_file(path: &Path, role: &'static str) -> Result<(), SupervisorError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("inspect durable supervisor file", path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(SupervisorError::UnsafePath {
            path: path.to_path_buf(),
            reason: role,
        });
    }
    Ok(())
}

fn ensure_direct_child(root: &Path, child: &Path) -> Result<(), SupervisorError> {
    if child.parent() != Some(root) || !child.starts_with(root) {
        return Err(SupervisorError::UnsafePath {
            path: child.to_path_buf(),
            reason: "path is not a direct child of its configured service root",
        });
    }
    Ok(())
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), SupervisorError> {
    let path = Path::new(value);
    let valid = !value.is_empty()
        && value.len() <= 256
        && !path.is_absolute()
        && path.components().all(|component| {
            matches!(component, Component::Normal(_))
                && !value.contains('/')
                && !value.contains('\\')
        });
    if !valid {
        return Err(SupervisorError::InvalidIdentifier {
            field,
            value: value.to_string(),
        });
    }
    Ok(())
}

fn require_nonempty(field: &'static str, value: &str) -> Result<(), SupervisorError> {
    if value.trim().is_empty() {
        return Err(SupervisorError::MissingField { field });
    }
    Ok(())
}

fn sanitize_id(value: &str) -> String {
    value
        .chars()
        .map(|character| match character {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' => character,
            _ => '-',
        })
        .collect()
}

fn io_error(operation: &'static str, path: &Path, source: std::io::Error) -> SupervisorError {
    SupervisorError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

#[derive(Debug)]
pub enum SupervisorError {
    Io {
        operation: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
    Artifact(ArtifactError),
    Serialization(String),
    CorruptState(String),
    StateNotFound,
    WriterAlreadyActive {
        path: PathBuf,
    },
    UnsafePath {
        path: PathBuf,
        reason: &'static str,
    },
    MissingField {
        field: &'static str,
    },
    InvalidIdentifier {
        field: &'static str,
        value: String,
    },
    InvalidPayloadJson(String),
    InvalidResultJson(String),
    PayloadTooLarge {
        limit: usize,
        actual: usize,
    },
    ResultTooLarge {
        limit: usize,
        actual: usize,
    },
    ResultDigestMismatch {
        expected: ContentDigest,
        actual: ContentDigest,
    },
    InvalidDeadline {
        not_before_ms: u64,
        deadline_at_ms: u64,
    },
    InvalidRetryPolicy(String),
    InvalidRunLoopOptions(String),
    StateInvariant(String),
    JobNotFound {
        job_id: String,
    },
    JobConflict {
        job_id: String,
    },
    IdempotencyConflict {
        idempotency_key: String,
        existing_job_id: String,
    },
    JobAlreadyTerminal {
        job_id: String,
    },
    StaleLease {
        job_id: String,
        lease_token: String,
    },
    AttemptAlreadyCompleted {
        attempt_id: String,
    },
    ApprovalNotFound {
        approval_request_id: String,
    },
    ApprovalResolutionConflict {
        approval_request_id: String,
    },
    EffectReceiptConflict {
        effect_receipt_id: String,
    },
    SupervisorStopping,
    MigrationRequired {
        found: u32,
        target: u32,
    },
    UnsupportedSchemaVersion {
        found: u32,
        supported: u32,
    },
    UnsupportedMigrationTarget {
        target: u32,
    },
    MigrationTransformFailed(String),
    MigrationValidationFailed {
        backup_id: String,
        reason: String,
    },
    MigrationCommitFailed {
        backup_id: String,
        reason: String,
    },
    BackupConflict {
        backup_id: String,
    },
    RestoreVerificationFailed {
        backup_id: String,
    },
}

impl From<ArtifactError> for SupervisorError {
    fn from(value: ArtifactError) -> Self {
        Self::Artifact(value)
    }
}

impl Display for SupervisorError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io {
                operation,
                path,
                source,
            } => write!(
                formatter,
                "{operation} at {} failed: {source}",
                path.display()
            ),
            Self::Artifact(error) => write!(formatter, "supervisor artifact error: {error}"),
            Self::Serialization(error) => {
                write!(formatter, "supervisor serialization failed: {error}")
            }
            Self::CorruptState(error) => write!(formatter, "supervisor state is corrupt: {error}"),
            Self::StateNotFound => write!(formatter, "supervisor state does not exist"),
            Self::WriterAlreadyActive { path } => write!(
                formatter,
                "another supervisor writer already holds {}",
                path.display()
            ),
            Self::UnsafePath { path, reason } => {
                write!(
                    formatter,
                    "unsafe supervisor path {}: {reason}",
                    path.display()
                )
            }
            Self::MissingField { field } => write!(formatter, "{field} must not be blank"),
            Self::InvalidIdentifier { field, value } => {
                write!(formatter, "{field} is not a safe identifier: {value:?}")
            }
            Self::InvalidPayloadJson(error) => {
                write!(formatter, "job payload is not valid JSON: {error}")
            }
            Self::InvalidResultJson(error) => {
                write!(formatter, "job result is not valid JSON: {error}")
            }
            Self::PayloadTooLarge { limit, actual } => {
                write!(formatter, "job payload size {actual} exceeds limit {limit}")
            }
            Self::ResultTooLarge { limit, actual } => {
                write!(formatter, "job result size {actual} exceeds limit {limit}")
            }
            Self::ResultDigestMismatch { expected, actual } => write!(
                formatter,
                "job result digest mismatch: expected {expected}, got {actual}"
            ),
            Self::InvalidDeadline {
                not_before_ms,
                deadline_at_ms,
            } => write!(
                formatter,
                "job deadline {deadline_at_ms} must follow not-before time {not_before_ms}"
            ),
            Self::InvalidRetryPolicy(reason) => {
                write!(formatter, "invalid supervisor retry policy: {reason}")
            }
            Self::InvalidRunLoopOptions(reason) => {
                write!(formatter, "invalid supervisor run-loop options: {reason}")
            }
            Self::StateInvariant(reason) => {
                write!(formatter, "supervisor state invariant failed: {reason}")
            }
            Self::JobNotFound { job_id } => write!(formatter, "job not found: {job_id}"),
            Self::JobConflict { job_id } => {
                write!(
                    formatter,
                    "job id is already bound to different input: {job_id}"
                )
            }
            Self::IdempotencyConflict {
                idempotency_key,
                existing_job_id,
            } => write!(
                formatter,
                "idempotency key {idempotency_key:?} is already bound to job {existing_job_id}"
            ),
            Self::JobAlreadyTerminal { job_id } => {
                write!(formatter, "job is already terminal: {job_id}")
            }
            Self::StaleLease {
                job_id,
                lease_token,
            } => write!(formatter, "lease {lease_token} no longer owns job {job_id}"),
            Self::AttemptAlreadyCompleted { attempt_id } => {
                write!(formatter, "attempt is already complete: {attempt_id}")
            }
            Self::ApprovalNotFound {
                approval_request_id,
            } => write!(
                formatter,
                "no job is blocked on approval {approval_request_id}"
            ),
            Self::ApprovalResolutionConflict {
                approval_request_id,
            } => write!(
                formatter,
                "approval {approval_request_id} already has a different resolution"
            ),
            Self::EffectReceiptConflict { effect_receipt_id } => write!(
                formatter,
                "effect receipt {effect_receipt_id} is already committed to different output"
            ),
            Self::SupervisorStopping => write!(formatter, "supervisor is stopping"),
            Self::MigrationRequired { found, target } => write!(
                formatter,
                "supervisor state schema v{found} requires migration to v{target}"
            ),
            Self::UnsupportedSchemaVersion { found, supported } => write!(
                formatter,
                "unsupported supervisor state schema v{found}; supported current version is v{supported}"
            ),
            Self::UnsupportedMigrationTarget { target } => {
                write!(
                    formatter,
                    "unsupported supervisor migration target v{target}"
                )
            }
            Self::MigrationTransformFailed(reason) => {
                write!(formatter, "supervisor migration transform failed: {reason}")
            }
            Self::MigrationValidationFailed { backup_id, reason } => write!(
                formatter,
                "supervisor migration validation failed after backup {backup_id}: {reason}"
            ),
            Self::MigrationCommitFailed { backup_id, reason } => write!(
                formatter,
                "supervisor migration commit failed and restored backup {backup_id}: {reason}"
            ),
            Self::BackupConflict { backup_id } => {
                write!(
                    formatter,
                    "supervisor backup conflicts with existing {backup_id}"
                )
            }
            Self::RestoreVerificationFailed { backup_id } => write!(
                formatter,
                "restored supervisor backup {backup_id} did not verify"
            ),
        }
    }
}

impl Error for SupervisorError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Artifact(source) => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ApprovalResolutionKind, ApprovalResolutionRecord, CompleteJobOutcome, EffectCommit,
        IdempotentJobHandler, JobExecutionResult, JobPhase, JobTerminalOutcome,
        LEGACY_SUPERVISOR_STATE_SCHEMA_VERSION, LegacySupervisorJobV1, LegacySupervisorStateV1,
        LocalDurableSupervisor, RetryPolicy, RunLoopOptions, RunOnceOutcome, ShutdownToken,
        SubmitJobOutcome, SubmitJobRequest, SupervisorClock, SupervisorError,
        SupervisorLifecycleStatus, SupervisorStoreAdmin, SystemSupervisorClock, atomic_replace,
        cleanup_staged_file,
    };
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::thread;
    use std::time::Duration;

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    #[derive(Debug)]
    struct TestTree {
        root: PathBuf,
    }

    impl TestTree {
        fn new(label: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "wasm-biotic-supervisor-{label}-{}-{}",
                std::process::id(),
                TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).expect("create test root");
            Self { root }
        }
    }

    impl Drop for TestTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[derive(Debug)]
    struct ManualClock {
        now_ms: AtomicU64,
    }

    impl ManualClock {
        fn new(now_ms: u64) -> Arc<Self> {
            Arc::new(Self {
                now_ms: AtomicU64::new(now_ms),
            })
        }

        fn set(&self, now_ms: u64) {
            self.now_ms.store(now_ms, Ordering::Release);
        }

        fn advance(&self, delta_ms: u64) {
            self.now_ms.fetch_add(delta_ms, Ordering::AcqRel);
        }
    }

    impl SupervisorClock for ManualClock {
        fn now_ms(&self) -> u64 {
            self.now_ms.load(Ordering::Acquire)
        }
    }

    fn policy(max_attempts: u32) -> RetryPolicy {
        RetryPolicy {
            max_attempts,
            initial_backoff_ms: 10,
            max_backoff_ms: 100,
            lease_duration_ms: 20,
            attempt_timeout_ms: 50,
        }
    }

    fn request(job_id: &str, now_ms: u64) -> SubmitJobRequest {
        SubmitJobRequest {
            job_id: job_id.to_string(),
            job_kind: "reference-effect".to_string(),
            payload_json: json!({ "job": job_id }).to_string(),
            idempotency_key: format!("effect-key:{job_id}"),
            not_before_ms: now_ms,
            deadline_at_ms: now_ms + 1_000,
            retry_policy: policy(3),
            approval_request_id: None,
        }
    }

    fn committed(effect_id: &str) -> JobExecutionResult {
        JobExecutionResult::EffectCommitted(
            EffectCommit::from_json(effect_id, &json!({ "effect": effect_id }))
                .expect("build effect commit"),
        )
    }

    #[test]
    fn future_job_becomes_claimable_only_after_its_durable_wake() {
        let tree = TestTree::new("future");
        let clock = ManualClock::new(100);
        let mut supervisor =
            LocalDurableSupervisor::open(&tree.root, "owner-a", clock.clone()).unwrap();
        let mut future = request("future", 200);
        future.deadline_at_ms = 500;
        supervisor.submit_job(future).unwrap();

        assert!(supervisor.claim_due_job().unwrap().is_none());
        assert_eq!(supervisor.status().heartbeat.next_due_at_ms, Some(200));
        clock.set(200);
        let dispatch = supervisor
            .claim_due_job()
            .unwrap()
            .expect("future job is due");
        assert_eq!(dispatch.attempt_number, 1);
        assert!(matches!(
            supervisor
                .complete_dispatch(&dispatch, committed("effect:future"))
                .unwrap(),
            CompleteJobOutcome::Succeeded(_)
        ));
    }

    #[test]
    fn restart_reconciles_abandoned_lease_and_preserves_at_least_once_key() {
        let tree = TestTree::new("restart");
        let clock = ManualClock::new(100);
        let first_key;
        {
            let mut first =
                LocalDurableSupervisor::open(&tree.root, "owner-a", clock.clone()).unwrap();
            first.submit_job(request("job", 100)).unwrap();
            let dispatch = first.claim_due_job().unwrap().unwrap();
            first_key = dispatch.idempotency_key;
        }

        clock.set(110);
        let mut reopened =
            LocalDurableSupervisor::open(&tree.root, "owner-b", clock.clone()).unwrap();
        let job = reopened.job("job").unwrap();
        assert_eq!(job.phase, JobPhase::RetryScheduled);
        assert!(matches!(
            job.attempts[0].outcome,
            Some(super::AttemptOutcome::LeaseLost { .. })
        ));
        let retried = reopened.claim_due_job().unwrap().unwrap();
        assert_eq!(retried.idempotency_key, first_key);
        assert_eq!(retried.attempt_number, 2);
    }

    #[test]
    fn duplicate_submission_is_idempotent_and_conflicting_key_is_rejected() {
        let tree = TestTree::new("duplicate");
        let clock = ManualClock::new(0);
        let mut supervisor =
            LocalDurableSupervisor::open(&tree.root, "owner", clock.clone()).unwrap();
        let original_request = request("job", 0);
        assert!(matches!(
            supervisor.submit_job(original_request.clone()).unwrap(),
            SubmitJobOutcome::Created(_)
        ));
        assert!(matches!(
            supervisor.submit_job(original_request.clone()).unwrap(),
            SubmitJobOutcome::Existing(_)
        ));
        let mut conflict = request("other-job", 0);
        conflict.idempotency_key = original_request.idempotency_key;
        conflict.payload_json = json!({ "different": true }).to_string();
        assert!(matches!(
            supervisor.submit_job(conflict),
            Err(SupervisorError::IdempotencyConflict { .. })
        ));
        assert_eq!(supervisor.state().jobs.len(), 1);
    }

    #[test]
    fn lease_loss_requeues_and_rejects_the_stale_completion() {
        let tree = TestTree::new("lease-loss");
        let clock = ManualClock::new(0);
        let mut supervisor =
            LocalDurableSupervisor::open(&tree.root, "owner", clock.clone()).unwrap();
        supervisor.submit_job(request("job", 0)).unwrap();
        let stale = supervisor.claim_due_job().unwrap().unwrap();
        clock.advance(21);
        assert!(supervisor.reconcile().unwrap());
        assert_eq!(
            supervisor.job("job").unwrap().phase,
            JobPhase::RetryScheduled
        );
        assert!(matches!(
            supervisor.complete_dispatch(&stale, committed("too-late")),
            Err(SupervisorError::StaleLease { .. })
        ));
        clock.advance(10);
        assert_eq!(
            supervisor.claim_due_job().unwrap().unwrap().attempt_number,
            2
        );
    }

    #[test]
    fn attempt_timeout_is_visible_and_retry_exhaustion_is_terminal() {
        let tree = TestTree::new("timeout");
        let clock = ManualClock::new(0);
        let mut supervisor =
            LocalDurableSupervisor::open(&tree.root, "owner", clock.clone()).unwrap();
        let mut timed = request("timed", 0);
        timed.retry_policy = RetryPolicy {
            lease_duration_ms: 100,
            attempt_timeout_ms: 20,
            max_attempts: 1,
            ..policy(1)
        };
        supervisor.submit_job(timed).unwrap();
        supervisor.claim_due_job().unwrap().unwrap();
        clock.advance(21);
        supervisor.reconcile().unwrap();

        let job = supervisor.job("timed").unwrap();
        assert_eq!(job.phase, JobPhase::RetryExhausted);
        assert!(matches!(
            job.attempts[0].outcome,
            Some(super::AttemptOutcome::TimedOut { .. })
        ));
        assert!(matches!(
            job.terminal_outcome,
            Some(JobTerminalOutcome::RetryExhausted { .. })
        ));
    }

    struct RetryHandler {
        calls: usize,
    }

    impl IdempotentJobHandler for RetryHandler {
        fn execute(&mut self, _dispatch: &super::JobDispatch) -> JobExecutionResult {
            self.calls += 1;
            JobExecutionResult::RetryableFailure {
                failure_class: "transient".to_string(),
                detail: format!("failure {}", self.calls),
            }
        }
    }

    #[test]
    fn retryable_handler_exhausts_exact_attempt_budget() {
        let tree = TestTree::new("retry-exhaustion");
        let clock = ManualClock::new(0);
        let mut supervisor =
            LocalDurableSupervisor::open(&tree.root, "owner", clock.clone()).unwrap();
        let mut job = request("job", 0);
        job.retry_policy = policy(2);
        supervisor.submit_job(job).unwrap();
        let mut handler = RetryHandler { calls: 0 };

        assert!(matches!(
            supervisor.run_once(&mut handler).unwrap(),
            RunOnceOutcome::Completed {
                outcome: CompleteJobOutcome::RetryScheduled { .. },
                ..
            }
        ));
        clock.advance(10);
        assert!(matches!(
            supervisor.run_once(&mut handler).unwrap(),
            RunOnceOutcome::Completed {
                outcome: CompleteJobOutcome::Terminal(JobTerminalOutcome::RetryExhausted { .. }),
                ..
            }
        ));
        assert_eq!(handler.calls, 2);
    }

    #[test]
    fn approval_grant_wakes_work_while_denial_expiry_and_escalation_are_terminal() {
        let tree = TestTree::new("approvals");
        let clock = ManualClock::new(100);
        let mut supervisor =
            LocalDurableSupervisor::open(&tree.root, "owner", clock.clone()).unwrap();
        for (job_id, approval_id) in [
            ("grant", "approval-grant"),
            ("deny", "approval-deny"),
            ("expire", "approval-expire"),
            ("escalate", "approval-escalate"),
        ] {
            let mut job = request(job_id, 100);
            job.approval_request_id = Some(approval_id.to_string());
            supervisor.submit_job(job).unwrap();
        }
        for (approval_id, resolution) in [
            ("approval-grant", ApprovalResolutionKind::Granted),
            ("approval-deny", ApprovalResolutionKind::Denied),
            ("approval-expire", ApprovalResolutionKind::Expired),
            ("approval-escalate", ApprovalResolutionKind::Escalated),
        ] {
            supervisor
                .resolve_approval(ApprovalResolutionRecord {
                    approval_request_id: approval_id.to_string(),
                    resolution,
                    evidence_ref: format!("evidence:{approval_id}"),
                    resolved_at_ms: 0,
                })
                .unwrap();
        }
        supervisor
            .resolve_approval(ApprovalResolutionRecord {
                approval_request_id: "approval-grant".to_string(),
                resolution: ApprovalResolutionKind::Granted,
                evidence_ref: "evidence:approval-grant".to_string(),
                resolved_at_ms: 0,
            })
            .expect("duplicate identical grant is idempotent");
        assert_eq!(supervisor.job("grant").unwrap().phase, JobPhase::Queued);
        assert_eq!(supervisor.job("deny").unwrap().phase, JobPhase::Denied);
        assert_eq!(
            supervisor.job("expire").unwrap().phase,
            JobPhase::ApprovalExpired
        );
        assert_eq!(
            supervisor.job("escalate").unwrap().phase,
            JobPhase::ApprovalEscalated
        );
        assert_eq!(supervisor.claim_due_job().unwrap().unwrap().job_id, "grant");
    }

    #[test]
    fn cancellation_is_durable_terminal_state_and_prevents_dispatch() {
        let tree = TestTree::new("cancel");
        let clock = ManualClock::new(0);
        let mut supervisor =
            LocalDurableSupervisor::open(&tree.root, "owner", clock.clone()).unwrap();
        supervisor.submit_job(request("job", 0)).unwrap();
        let outcome = supervisor.cancel_job("job", "operator stop").unwrap();
        assert!(matches!(outcome, JobTerminalOutcome::Cancelled { .. }));
        assert_eq!(supervisor.job("job").unwrap().phase, JobPhase::Cancelled);
        assert!(supervisor.claim_due_job().unwrap().is_none());
        drop(supervisor);
        let reopened =
            LocalDurableSupervisor::open(&tree.root, "next-owner", clock.clone()).unwrap();
        assert_eq!(reopened.job("job").unwrap().phase, JobPhase::Cancelled);
    }

    #[test]
    fn graceful_shutdown_releases_an_active_lease_for_restart() {
        let tree = TestTree::new("graceful-active");
        let clock = ManualClock::new(0);
        let mut supervisor =
            LocalDurableSupervisor::open(&tree.root, "owner-a", clock.clone()).unwrap();
        supervisor.submit_job(request("job", 0)).unwrap();
        supervisor.claim_due_job().unwrap().unwrap();
        supervisor.graceful_shutdown().unwrap();

        let job = supervisor.job("job").unwrap();
        assert_eq!(job.phase, JobPhase::RetryScheduled);
        assert!(job.lease.is_none());
        assert!(matches!(
            job.attempts[0].outcome,
            Some(super::AttemptOutcome::LeaseLost { .. })
        ));
        assert_eq!(
            supervisor.status().heartbeat.lifecycle,
            SupervisorLifecycleStatus::Stopped
        );
        drop(supervisor);

        let mut reopened =
            LocalDurableSupervisor::open(&tree.root, "owner-b", clock.clone()).unwrap();
        assert_eq!(reopened.claim_due_job().unwrap().unwrap().attempt_number, 2);
    }

    #[derive(Default)]
    struct ExternalIdempotentEffects {
        commits: BTreeMap<String, EffectCommit>,
        physical_commits: usize,
    }

    impl ExternalIdempotentEffects {
        fn commit(&mut self, key: &str) -> EffectCommit {
            if let Some(existing) = self.commits.get(key) {
                return existing.clone();
            }
            self.physical_commits += 1;
            let commit = EffectCommit::from_json(
                format!("external-effect:{key}"),
                &json!({ "idempotency_key": key }),
            )
            .unwrap();
            self.commits.insert(key.to_string(), commit.clone());
            commit
        }
    }

    #[test]
    fn crash_after_external_effect_replays_but_commits_one_logical_effect() {
        let tree = TestTree::new("effect-receipt");
        let clock = ManualClock::new(0);
        let mut effects = ExternalIdempotentEffects::default();
        let first_dispatch;
        {
            let mut supervisor =
                LocalDurableSupervisor::open(&tree.root, "owner-a", clock.clone()).unwrap();
            supervisor.submit_job(request("job", 0)).unwrap();
            first_dispatch = supervisor.claim_due_job().unwrap().unwrap();
            effects.commit(&first_dispatch.idempotency_key);
            // Simulated process death before the supervisor can persist the
            // handler's committed receipt.
        }
        clock.advance(1);
        let mut reopened =
            LocalDurableSupervisor::open(&tree.root, "owner-b", clock.clone()).unwrap();
        let replay = reopened.claim_due_job().unwrap().unwrap();
        assert_eq!(replay.idempotency_key, first_dispatch.idempotency_key);
        let same_commit = effects.commit(&replay.idempotency_key);
        reopened
            .complete_dispatch(&replay, JobExecutionResult::EffectCommitted(same_commit))
            .unwrap();

        assert_eq!(effects.physical_commits, 1);
        assert_eq!(
            reopened
                .state()
                .effect_receipts
                .get(&replay.effect_receipt_id)
                .unwrap()
                .delivery_count,
            2
        );
        assert_eq!(reopened.job("job").unwrap().phase, JobPhase::Succeeded);
    }

    #[test]
    fn single_writer_lock_releases_on_drop() {
        let tree = TestTree::new("lock");
        let clock = ManualClock::new(0);
        let first = LocalDurableSupervisor::open(&tree.root, "owner-a", clock.clone()).unwrap();
        assert!(matches!(
            LocalDurableSupervisor::open(&tree.root, "owner-b", clock.clone()),
            Err(SupervisorError::WriterAlreadyActive { .. })
        ));
        drop(first);
        LocalDurableSupervisor::open(&tree.root, "owner-b", clock.clone())
            .expect("OS lock releases when writer drops");
    }

    #[test]
    fn same_process_canonical_root_registry_survives_lock_path_replacement_stress() {
        let tree = TestTree::new("same-process-owner-registry");
        let canonical_root = fs::canonicalize(&tree.root).expect("canonical stress root");
        let clock = ManualClock::new(0);

        for iteration in 0..128 {
            let owner_id = format!("owner-{iteration}-active");
            let first = LocalDurableSupervisor::open(&tree.root, owner_id, clock.clone()).unwrap();
            let state_path = canonical_root.join(super::STATE_FILE_NAME);
            let state_before =
                fs::read(&state_path).expect("read state before duplicate same-process open");

            // Replacing an advisory-lock pathname creates a new inode that an
            // OS-only locking scheme may allow another descriptor to lock.
            // The canonical-root registry must still reject the duplicate
            // before it can clean staged files or touch durable state.
            #[cfg(unix)]
            fs::remove_file(canonical_root.join(super::LOCK_FILE_NAME))
                .expect("replace live lock pathname");
            let stale =
                canonical_root.join(format!(".supervisor-state.json-abandoned-{iteration}.tmp"));
            fs::write(&stale, b"abandoned").expect("plant abandoned staged file");
            assert!(matches!(
                LocalDurableSupervisor::open(
                    tree.root.join("."),
                    format!("owner-{iteration}-duplicate"),
                    clock.clone(),
                ),
                Err(SupervisorError::WriterAlreadyActive { .. })
            ));
            assert_eq!(
                fs::read(&state_path).expect("read state after rejected duplicate"),
                state_before,
                "a rejected same-process writer must not change durable state bytes"
            );
            assert!(
                stale.exists(),
                "a rejected duplicate must not run staged-file cleanup"
            );
            drop(first);

            let successor = LocalDurableSupervisor::open(
                &tree.root,
                format!("owner-{iteration}-successor"),
                clock.clone(),
            )
            .expect("canonical-root reservation releases after owner drop");
            assert!(
                !stale.exists(),
                "the next exclusive owner cleans the abandoned staged file"
            );
            drop(successor);
        }
    }

    #[test]
    fn vanished_staged_cleanup_entry_is_idempotent() {
        let tree = TestTree::new("vanished-staged-cleanup");
        let vanished = tree
            .root
            .join(".supervisor-state.json-vanished-before-inspection.tmp");
        cleanup_staged_file(&vanished)
            .expect("a stale entry that vanished before inspection is already clean");

        fs::write(&vanished, b"stale").expect("create staged cleanup control");
        fs::remove_file(&vanished).expect("simulate concurrent stale-entry disappearance");
        cleanup_staged_file(&vanished)
            .expect("a stale entry that vanished before removal is already clean");
    }

    #[test]
    fn atomic_replace_missing_root_reports_exact_create_operation() {
        let tree = TestTree::new("atomic-missing-root");
        let target = tree.root.join(super::STATE_FILE_NAME);
        fs::remove_dir_all(&tree.root).expect("simulate externally vanished supervisor root");
        let error = atomic_replace(&tree.root, &target, b"nonempty")
            .expect_err("atomic write must not recreate or mask a missing supervisor root");
        match error {
            SupervisorError::Io {
                operation,
                path,
                source,
            } => {
                assert_eq!(
                    operation,
                    "create atomic supervisor file (supervisor root missing)"
                );
                assert_eq!(path.parent(), Some(tree.root.as_path()));
                assert_eq!(source.kind(), std::io::ErrorKind::NotFound);
                assert!(!tree.root.exists());
            }
            other => panic!("unexpected missing-root failure: {other}"),
        }
    }

    #[test]
    fn deadline_expiry_survives_restart_without_dispatch() {
        let tree = TestTree::new("deadline");
        let clock = ManualClock::new(0);
        {
            let mut supervisor =
                LocalDurableSupervisor::open(&tree.root, "owner-a", clock.clone()).unwrap();
            let mut job = request("job", 100);
            job.deadline_at_ms = 200;
            supervisor.submit_job(job).unwrap();
        }
        clock.set(250);
        let mut reopened =
            LocalDurableSupervisor::open(&tree.root, "owner-b", clock.clone()).unwrap();
        assert_eq!(
            reopened.job("job").unwrap().phase,
            JobPhase::DeadlineExceeded
        );
        assert!(reopened.claim_due_job().unwrap().is_none());
    }

    #[test]
    fn migration_dry_run_failure_backup_restore_and_success_are_safe() {
        let tree = TestTree::new("migration");
        let clock = ManualClock::new(100);
        let legacy = LegacySupervisorStateV1 {
            schema_version: LEGACY_SUPERVISOR_STATE_SCHEMA_VERSION,
            revision: 7,
            created_at_ms: 10,
            jobs: vec![LegacySupervisorJobV1 {
                job_id: "legacy-job".to_string(),
                job_kind: "legacy-effect".to_string(),
                payload_json: json!({ "legacy": true }).to_string(),
                idempotency_key: "legacy-effect-key".to_string(),
                not_before_ms: 200,
                deadline_at_ms: 1_000,
                max_attempts: 2,
            }],
        };
        fs::write(
            tree.root.join("supervisor-state.json"),
            serde_json::to_vec_pretty(&legacy).unwrap(),
        )
        .unwrap();

        let mut admin =
            SupervisorStoreAdmin::open(&tree.root, "migration-admin", clock.clone()).unwrap();
        let dry_run = admin.dry_run_migration(2).unwrap();
        assert_eq!(dry_run.from_version, 1);
        assert_eq!(dry_run.job_count, 1);
        assert!(dry_run.backup_required);
        assert_eq!(admin.stored_schema_version().unwrap(), 1);

        let failure = admin
            .migrate_to_current_with_validator(|_| Err("injected successor rejection".to_string()))
            .unwrap_err();
        let backup_id = match failure {
            SupervisorError::MigrationValidationFailed { backup_id, .. } => backup_id,
            other => panic!("unexpected migration failure: {other}"),
        };
        assert_eq!(admin.stored_schema_version().unwrap(), 1);
        assert!(tree.root.join("backups").join(&backup_id).is_file());

        let migrated = admin.migrate_to_current().unwrap();
        assert_eq!(migrated.plan.from_version, 1);
        assert_eq!(admin.stored_schema_version().unwrap(), 2);
        assert_eq!(
            super::ContentDigest::from_bytes(&admin.store.read_raw_state().unwrap()),
            migrated.plan.candidate_digest
        );
        assert_eq!(admin.restore_backup(&backup_id).unwrap(), 1);
        assert_eq!(admin.stored_schema_version().unwrap(), 1);
        drop(admin);
        assert!(matches!(
            LocalDurableSupervisor::open(&tree.root, "owner", clock.clone()),
            Err(SupervisorError::MigrationRequired {
                found: 1,
                target: 2
            })
        ));
    }

    struct LiveHandler {
        calls: Arc<AtomicUsize>,
        shutdown: ShutdownToken,
    }

    impl IdempotentJobHandler for LiveHandler {
        fn execute(&mut self, dispatch: &super::JobDispatch) -> JobExecutionResult {
            self.calls.fetch_add(1, Ordering::AcqRel);
            self.shutdown.request_shutdown();
            committed(&format!("live:{}", dispatch.job_id))
        }
    }

    #[test]
    fn wall_clock_loop_claims_future_work_without_another_request_and_stops_gracefully() {
        let tree = TestTree::new("live-loop");
        let clock: Arc<dyn SupervisorClock> = Arc::new(SystemSupervisorClock);
        let mut supervisor =
            LocalDurableSupervisor::open(&tree.root, "live-owner", clock.clone()).unwrap();
        let now = clock.now_ms();
        let mut future = request("future", now + 30);
        future.deadline_at_ms = now + 2_000;
        // This is a wall-clock integration test, so leave enough lease margin
        // for a contended full-suite runner. Lease-expiry behavior is covered
        // deterministically with the injected clock in the tests above.
        future.retry_policy.lease_duration_ms = 500;
        future.retry_policy.attempt_timeout_ms = 1_000;
        supervisor.submit_job(future).unwrap();
        let shutdown = ShutdownToken::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let handler_calls = calls.clone();
        let handler_shutdown = shutdown.clone();

        let join = thread::spawn(move || {
            let mut handler = LiveHandler {
                calls: handler_calls,
                shutdown: handler_shutdown,
            };
            supervisor
                .run_until_shutdown(
                    &mut handler,
                    &shutdown,
                    RunLoopOptions {
                        max_idle_sleep: Duration::from_millis(10),
                    },
                )
                .unwrap();
            supervisor
        });
        let supervisor = join.join().expect("live supervisor thread");
        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_eq!(supervisor.job("future").unwrap().phase, JobPhase::Succeeded);
        assert_eq!(
            supervisor.status().heartbeat.lifecycle,
            SupervisorLifecycleStatus::Stopped
        );
        assert_eq!(supervisor.state().shutdowns.len(), 1);
    }

    #[test]
    fn corrupt_state_is_rejected_without_replacement() {
        let tree = TestTree::new("corrupt");
        let bytes = b"{not-json".to_vec();
        fs::write(tree.root.join("supervisor-state.json"), &bytes).unwrap();
        let clock = ManualClock::new(0);
        assert!(matches!(
            LocalDurableSupervisor::open(&tree.root, "owner", clock),
            Err(SupervisorError::CorruptState(_))
        ));
        assert_eq!(
            fs::read(tree.root.join("supervisor-state.json")).unwrap(),
            bytes
        );
    }
}
