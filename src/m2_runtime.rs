//! Production runtime glue for the durable M2 supervisor and bounded M1 path.
//!
//! Construction is deliberately lazy: [`M2Runtime::new`] performs no file-system
//! work and acquires no writer lock. The first explicit [`M2Runtime::start`] or
//! operational API call opens the durable supervisor as the sole writer, opens
//! the M1 reference service behind that lock, and starts one background owner.
//! The owner holds the supervisor mutex only while claiming, inspecting, or
//! completing a dispatch. M1 effects execute outside that mutex.
//!
//! The worker provides at-least-once delivery. Every supported payload carries
//! exact predecessor identities, and the M1 service persists intent before its
//! physical effects. A replay therefore returns an identical commit derived
//! from the persisted stage record rather than repeating the physical effect.

use crate::execution::artifact::{ContentDigest, digest_json_content};
use crate::m1_reference::{ApprovalDecision, M1ReferenceService, ReferenceLifecycleError};
use crate::supervisor::{
    ApprovalResolutionKind, ApprovalResolutionRecord, DurableJob, EffectCommit,
    IdempotentJobHandler, JobDispatch, JobExecutionResult, JobPhase, JobTerminalOutcome,
    LocalDurableSupervisor, MigrationOutcome, MigrationPlan, RetryPolicy,
    SUPERVISOR_STATE_SCHEMA_VERSION, SubmitJobOutcome, SubmitJobRequest, SupervisorClock,
    SupervisorError, SupervisorHeartbeat, SupervisorStatus, SupervisorStoreAdmin,
    SystemSupervisorClock,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::Duration;

pub const M1_OPEN_WORKSPACE_JOB_KIND: &str = "m1.open_workspace";
pub const M1_MATERIALIZE_JOB_KIND: &str = "m1.materialize";
pub const M1_PACKAGE_JOB_KIND: &str = "m1.package";
pub const M1_PROVE_JOB_KIND: &str = "m1.prove";
pub const M1_COMPARE_JOB_KIND: &str = "m1.compare";
pub const M1_ACTIVATE_JOB_KIND: &str = "m1.activate";
pub const M1_OBSERVE_JOB_KIND: &str = "m1.observe";
pub const M1_ROLLBACK_JOB_KIND: &str = "m1.rollback";

const EFFECT_SCHEMA: &str = "wasm-biotic.m2-lifecycle-effect.v1";

/// Explicit roots and worker timing for one local M2 runtime.
///
/// No path is inferred from the process working directory, environment
/// variables, or the submitted job. `max_idle_wait_ms` bounds how long the
/// worker sleeps before refreshing its durable heartbeat when no prompt wake is
/// received.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M2RuntimeConfig {
    pub supervisor_root: PathBuf,
    pub lifecycle_root: PathBuf,
    pub template_root: PathBuf,
    pub owner_id: String,
    pub max_idle_wait_ms: u64,
}

impl M2RuntimeConfig {
    pub fn validate(&self) -> Result<(), M2RuntimeError> {
        if self.supervisor_root.as_os_str().is_empty() {
            return Err(M2RuntimeError::InvalidConfig(
                "supervisor_root must not be empty".to_string(),
            ));
        }
        if self.lifecycle_root.as_os_str().is_empty() {
            return Err(M2RuntimeError::InvalidConfig(
                "lifecycle_root must not be empty".to_string(),
            ));
        }
        if self.template_root.as_os_str().is_empty() {
            return Err(M2RuntimeError::InvalidConfig(
                "template_root must not be empty".to_string(),
            ));
        }
        if self.owner_id.trim().is_empty() {
            return Err(M2RuntimeError::InvalidConfig(
                "owner_id must not be blank".to_string(),
            ));
        }
        if self.max_idle_wait_ms == 0 {
            return Err(M2RuntimeError::InvalidConfig(
                "max_idle_wait_ms must be non-zero".to_string(),
            ));
        }
        Ok(())
    }
}

/// Closed, typed payload catalog for the bounded local-first M1 lifecycle.
///
/// The enum tag is deliberately repeated inside the supervisor payload. The
/// handler rejects a mismatch between this tag and `DurableJob::job_kind`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "payload")]
pub enum M1LifecycleJob {
    #[serde(rename = "m1.open_workspace")]
    OpenWorkspace(OpenWorkspacePayload),
    #[serde(rename = "m1.materialize")]
    Materialize(MaterializePayload),
    #[serde(rename = "m1.package")]
    Package(PackagePayload),
    #[serde(rename = "m1.prove")]
    Prove(ProvePayload),
    #[serde(rename = "m1.compare")]
    Compare(ComparePayload),
    #[serde(rename = "m1.activate")]
    Activate(ActivatePayload),
    #[serde(rename = "m1.observe")]
    Observe(ObservePayload),
    #[serde(rename = "m1.rollback")]
    Rollback(RollbackPayload),
}

impl M1LifecycleJob {
    pub fn job_kind(&self) -> &'static str {
        match self {
            Self::OpenWorkspace(_) => M1_OPEN_WORKSPACE_JOB_KIND,
            Self::Materialize(_) => M1_MATERIALIZE_JOB_KIND,
            Self::Package(_) => M1_PACKAGE_JOB_KIND,
            Self::Prove(_) => M1_PROVE_JOB_KIND,
            Self::Compare(_) => M1_COMPARE_JOB_KIND,
            Self::Activate(_) => M1_ACTIVATE_JOB_KIND,
            Self::Observe(_) => M1_OBSERVE_JOB_KIND,
            Self::Rollback(_) => M1_ROLLBACK_JOB_KIND,
        }
    }

    pub fn approval_request_id(&self) -> Option<&str> {
        match self {
            Self::Activate(payload) => Some(payload.approval_request_id.as_str()),
            Self::Rollback(payload) => Some(payload.approval_request_id.as_str()),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenWorkspacePayload {
    pub workspace_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaterializePayload {
    pub workspace_id: String,
    pub workspace_snapshot_digest: ContentDigest,
    pub expected_before_digest: ContentDigest,
    pub replacement_wat_bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackagePayload {
    pub workspace_id: String,
    pub patchset_digest: ContentDigest,
    pub expected_source_tree_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvePayload {
    pub package_record_digest: ContentDigest,
    pub package_digest: ContentDigest,
    pub expected_source_tree_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComparePayload {
    pub incumbent_proving_record_digest: ContentDigest,
    pub challenger_proving_record_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivatePayload {
    pub comparison_record_digest: ContentDigest,
    pub approval_request_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservePayload {
    pub activation_operation_id: String,
    pub activated_component_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackPayload {
    pub activation_operation_id: String,
    pub observation_record_digest: ContentDigest,
    pub approval_request_id: String,
    /// Human/machine incident reference. The handler appends a digest of the
    /// exact supervisor approval-resolution record before persisting it.
    pub reason_ref: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M2SubmitJobRequest {
    pub job_id: String,
    pub idempotency_key: String,
    pub not_before_ms: u64,
    pub deadline_at_ms: u64,
    pub retry_policy: RetryPolicy,
    pub lifecycle: M1LifecycleJob,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M2SubmitJobOutcome {
    pub created: bool,
    pub job: DurableJob,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M2RuntimeStatus {
    pub worker_running: bool,
    pub worker_error: Option<String>,
    pub schema_version: u32,
    pub revision: u64,
    pub heartbeat: SupervisorHeartbeat,
    pub queued_jobs: usize,
    pub waiting_approval_jobs: usize,
    pub leased_jobs: usize,
    pub terminal_jobs: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M2MigrationPlan {
    pub from_version: u32,
    pub to_version: u32,
    pub planned_at_ms: u64,
    pub job_count: usize,
    pub source_digest: ContentDigest,
    pub candidate_digest: ContentDigest,
    pub backup_required: bool,
    pub notes: Vec<String>,
}

impl From<MigrationPlan> for M2MigrationPlan {
    fn from(value: MigrationPlan) -> Self {
        Self {
            from_version: value.from_version,
            to_version: value.to_version,
            planned_at_ms: value.planned_at_ms,
            job_count: value.job_count,
            source_digest: value.source_digest,
            candidate_digest: value.candidate_digest,
            backup_required: value.backup_required,
            notes: value.notes,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M2MigrationOutcome {
    pub plan: M2MigrationPlan,
    pub backup_id: Option<String>,
}

impl From<MigrationOutcome> for M2MigrationOutcome {
    fn from(value: MigrationOutcome) -> Self {
        Self {
            plan: value.plan.into(),
            backup_id: value.backup_id,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct LifecycleEffectEnvelope {
    schema: &'static str,
    job_kind: &'static str,
    record: Value,
}

struct RuntimeShared {
    supervisor: Mutex<Option<LocalDurableSupervisor>>,
    execution_gate: Mutex<()>,
    control: Mutex<WorkerControl>,
    wake: Condvar,
}

#[derive(Default)]
struct WorkerControl {
    generation: u64,
    stop_requested: bool,
    running: bool,
    last_error: Option<String>,
}

/// Lazy, single-writer runtime facade intended for `LocalRuntimeService`.
pub struct M2Runtime {
    config: M2RuntimeConfig,
    clock: Arc<dyn SupervisorClock>,
    shared: Arc<RuntimeShared>,
    worker: Mutex<Option<JoinHandle<()>>>,
    lifecycle_gate: Mutex<()>,
}

impl M2Runtime {
    pub fn new(config: M2RuntimeConfig) -> Result<Self, M2RuntimeError> {
        Self::with_clock(config, Arc::new(SystemSupervisorClock))
    }

    pub fn with_clock(
        config: M2RuntimeConfig,
        clock: Arc<dyn SupervisorClock>,
    ) -> Result<Self, M2RuntimeError> {
        config.validate()?;
        Ok(Self {
            config,
            clock,
            shared: Arc::new(RuntimeShared {
                supervisor: Mutex::new(None),
                execution_gate: Mutex::new(()),
                control: Mutex::new(WorkerControl::default()),
                wake: Condvar::new(),
            }),
            worker: Mutex::new(None),
            lifecycle_gate: Mutex::new(()),
        })
    }

    pub fn config(&self) -> &M2RuntimeConfig {
        &self.config
    }

    /// Acquire the sole supervisor writer and start the background owner.
    ///
    /// Repeated calls are idempotent while the same worker remains healthy.
    pub fn start(&self) -> Result<(), M2RuntimeError> {
        let _lifecycle = lock_unpoison(&self.lifecycle_gate);
        let mut worker_slot = lock_unpoison(&self.worker);
        if let Some(worker) = worker_slot.as_ref() {
            let control = lock_unpoison(&self.shared.control);
            if let Some(error) = &control.last_error {
                return Err(M2RuntimeError::WorkerFailed(error.clone()));
            }
            if control.running && !worker.is_finished() {
                return Ok(());
            }
            return Err(M2RuntimeError::WorkerFailed(
                "background worker exited; call stop before restarting".to_string(),
            ));
        }

        let supervisor = LocalDurableSupervisor::open(
            &self.config.supervisor_root,
            self.config.owner_id.clone(),
            Arc::clone(&self.clock),
        )?;
        let service =
            match M1ReferenceService::open(&self.config.lifecycle_root, &self.config.template_root)
            {
                Ok(service) => service,
                Err(error) => {
                    let mut supervisor = supervisor;
                    let _ = supervisor.graceful_shutdown();
                    return Err(error.into());
                }
            };

        {
            let mut supervisor_slot = lock_unpoison(&self.shared.supervisor);
            *supervisor_slot = Some(supervisor);
        }
        {
            let mut control = lock_unpoison(&self.shared.control);
            control.stop_requested = false;
            control.running = true;
            control.last_error = None;
            control.generation = control.generation.saturating_add(1);
        }

        let shared = Arc::clone(&self.shared);
        let clock = Arc::clone(&self.clock);
        let max_idle_wait = Duration::from_millis(self.config.max_idle_wait_ms);
        let thread_name = format!("wasm-biotic-m2-{}", self.config.owner_id);
        match thread::Builder::new().name(thread_name).spawn(move || {
            worker_main(shared, service, clock, max_idle_wait);
        }) {
            Ok(handle) => {
                *worker_slot = Some(handle);
                Ok(())
            }
            Err(error) => {
                let mut supervisor_slot = lock_unpoison(&self.shared.supervisor);
                if let Some(supervisor) = supervisor_slot.as_mut() {
                    let _ = supervisor.graceful_shutdown();
                }
                supervisor_slot.take();
                let mut control = lock_unpoison(&self.shared.control);
                control.running = false;
                Err(M2RuntimeError::ThreadSpawn(error))
            }
        }
    }

    /// Stop the worker, durably release any lease, and drop the writer lock.
    pub fn stop(&self) -> Result<(), M2RuntimeError> {
        let _lifecycle = lock_unpoison(&self.lifecycle_gate);
        {
            let mut control = lock_unpoison(&self.shared.control);
            control.stop_requested = true;
            control.generation = control.generation.saturating_add(1);
            self.shared.wake.notify_all();
        }

        let handle = lock_unpoison(&self.worker).take();
        let join_failed = handle.is_some_and(|handle| handle.join().is_err());
        let shutdown_result = {
            let mut supervisor_slot = lock_unpoison(&self.shared.supervisor);
            let result = supervisor_slot
                .as_mut()
                .map(LocalDurableSupervisor::graceful_shutdown)
                .transpose();
            supervisor_slot.take();
            result
        };
        {
            let mut control = lock_unpoison(&self.shared.control);
            control.running = false;
            control.stop_requested = false;
        }
        shutdown_result?;
        if join_failed {
            return Err(M2RuntimeError::WorkerPanicked);
        }
        Ok(())
    }

    pub fn submit(
        &self,
        request: M2SubmitJobRequest,
    ) -> Result<M2SubmitJobOutcome, M2RuntimeError> {
        self.ensure_healthy_started()?;
        let payload_json = serde_json::to_string(&request.lifecycle)?;
        let job_kind = request.lifecycle.job_kind().to_string();
        let approval_request_id = request
            .lifecycle
            .approval_request_id()
            .map(ToOwned::to_owned);
        let outcome = {
            let mut supervisor_slot = lock_unpoison(&self.shared.supervisor);
            let supervisor = supervisor_slot.as_mut().ok_or(M2RuntimeError::NotRunning)?;
            supervisor.submit_job(SubmitJobRequest {
                job_id: request.job_id,
                job_kind,
                payload_json,
                idempotency_key: request.idempotency_key,
                not_before_ms: request.not_before_ms,
                deadline_at_ms: request.deadline_at_ms,
                retry_policy: request.retry_policy,
                approval_request_id,
            })?
        };
        self.notify_worker();
        Ok(match outcome {
            SubmitJobOutcome::Created(job) => M2SubmitJobOutcome { created: true, job },
            SubmitJobOutcome::Existing(job) => M2SubmitJobOutcome {
                created: false,
                job,
            },
        })
    }

    /// Cancel only at a safe effect boundary.
    ///
    /// The execution gate is not the supervisor mutex: reads and submissions
    /// continue while an M1 effect runs. Cancellation waits for an in-flight
    /// effect to be durably completed, preventing a "cancelled" job from hiding
    /// an already-applied physical effect.
    pub fn cancel(
        &self,
        job_id: &str,
        reason: impl Into<String>,
    ) -> Result<JobTerminalOutcome, M2RuntimeError> {
        self.ensure_healthy_started()?;
        let _effect_boundary = lock_unpoison(&self.shared.execution_gate);
        let outcome = {
            let mut supervisor_slot = lock_unpoison(&self.shared.supervisor);
            let supervisor = supervisor_slot.as_mut().ok_or(M2RuntimeError::NotRunning)?;
            supervisor.cancel_job(job_id, reason)?
        };
        self.notify_worker();
        Ok(outcome)
    }

    pub fn resolve_approval(
        &self,
        resolution: ApprovalResolutionRecord,
    ) -> Result<Vec<String>, M2RuntimeError> {
        self.ensure_healthy_started()?;
        let jobs = {
            let mut supervisor_slot = lock_unpoison(&self.shared.supervisor);
            let supervisor = supervisor_slot.as_mut().ok_or(M2RuntimeError::NotRunning)?;
            supervisor.resolve_approval(resolution)?
        };
        self.notify_worker();
        Ok(jobs)
    }

    pub fn status(&self) -> Result<M2RuntimeStatus, M2RuntimeError> {
        self.start()?;
        let (worker_running, worker_error) = {
            let control = lock_unpoison(&self.shared.control);
            (control.running, control.last_error.clone())
        };
        let status = {
            let supervisor_slot = lock_unpoison(&self.shared.supervisor);
            supervisor_slot
                .as_ref()
                .ok_or(M2RuntimeError::NotRunning)?
                .status()
        };
        Ok(runtime_status(worker_running, worker_error, status))
    }

    pub fn jobs(&self) -> Result<Vec<DurableJob>, M2RuntimeError> {
        self.ensure_healthy_started()?;
        let supervisor_slot = lock_unpoison(&self.shared.supervisor);
        let supervisor = supervisor_slot.as_ref().ok_or(M2RuntimeError::NotRunning)?;
        Ok(supervisor.state().jobs.values().cloned().collect())
    }

    pub fn job(&self, job_id: &str) -> Result<Option<DurableJob>, M2RuntimeError> {
        self.ensure_healthy_started()?;
        let supervisor_slot = lock_unpoison(&self.shared.supervisor);
        let supervisor = supervisor_slot.as_ref().ok_or(M2RuntimeError::NotRunning)?;
        Ok(supervisor.job(job_id).cloned())
    }

    /// Read a migration plan while the runtime is stopped. No bytes are changed.
    pub fn migration_dry_run(&self) -> Result<M2MigrationPlan, M2RuntimeError> {
        let _lifecycle = lock_unpoison(&self.lifecycle_gate);
        self.require_stopped()?;
        let admin = SupervisorStoreAdmin::open(
            &self.config.supervisor_root,
            self.config.owner_id.clone(),
            Arc::clone(&self.clock),
        )?;
        Ok(admin
            .dry_run_migration(SUPERVISOR_STATE_SCHEMA_VERSION)?
            .into())
    }

    /// Migrate the durable supervisor store while the runtime is stopped.
    pub fn migrate(&self) -> Result<M2MigrationOutcome, M2RuntimeError> {
        let _lifecycle = lock_unpoison(&self.lifecycle_gate);
        self.require_stopped()?;
        let mut admin = SupervisorStoreAdmin::open(
            &self.config.supervisor_root,
            self.config.owner_id.clone(),
            Arc::clone(&self.clock),
        )?;
        Ok(admin.migrate_to_current()?.into())
    }

    /// Restore one named supervisor backup while the runtime is stopped.
    pub fn restore(&self, backup_id: &str) -> Result<u32, M2RuntimeError> {
        let _lifecycle = lock_unpoison(&self.lifecycle_gate);
        self.require_stopped()?;
        let mut admin = SupervisorStoreAdmin::open(
            &self.config.supervisor_root,
            self.config.owner_id.clone(),
            Arc::clone(&self.clock),
        )?;
        Ok(admin.restore_backup(backup_id)?)
    }

    pub fn stored_schema_version(&self) -> Result<u32, M2RuntimeError> {
        let _lifecycle = lock_unpoison(&self.lifecycle_gate);
        self.require_stopped()?;
        let admin = SupervisorStoreAdmin::open(
            &self.config.supervisor_root,
            self.config.owner_id.clone(),
            Arc::clone(&self.clock),
        )?;
        Ok(admin.stored_schema_version()?)
    }

    fn ensure_healthy_started(&self) -> Result<(), M2RuntimeError> {
        self.start()?;
        let control = lock_unpoison(&self.shared.control);
        if let Some(error) = &control.last_error {
            return Err(M2RuntimeError::WorkerFailed(error.clone()));
        }
        if !control.running {
            return Err(M2RuntimeError::NotRunning);
        }
        Ok(())
    }

    fn notify_worker(&self) {
        let mut control = lock_unpoison(&self.shared.control);
        control.generation = control.generation.saturating_add(1);
        self.shared.wake.notify_all();
    }

    fn require_stopped(&self) -> Result<(), M2RuntimeError> {
        if lock_unpoison(&self.worker).is_some()
            || lock_unpoison(&self.shared.supervisor).is_some()
            || lock_unpoison(&self.shared.control).running
        {
            return Err(M2RuntimeError::AdminRequiresStoppedRuntime);
        }
        Ok(())
    }
}

impl Drop for M2Runtime {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn runtime_status(
    worker_running: bool,
    worker_error: Option<String>,
    status: SupervisorStatus,
) -> M2RuntimeStatus {
    M2RuntimeStatus {
        worker_running,
        worker_error,
        schema_version: status.schema_version,
        revision: status.revision,
        heartbeat: status.heartbeat,
        queued_jobs: status.queued_jobs,
        waiting_approval_jobs: status.waiting_approval_jobs,
        leased_jobs: status.leased_jobs,
        terminal_jobs: status.terminal_jobs,
    }
}

fn worker_main(
    shared: Arc<RuntimeShared>,
    service: M1ReferenceService,
    clock: Arc<dyn SupervisorClock>,
    max_idle_wait: Duration,
) {
    let loop_result = worker_loop(&shared, &service, &clock, max_idle_wait);
    let shutdown_result = {
        let mut supervisor_slot = lock_unpoison(&shared.supervisor);
        supervisor_slot
            .as_mut()
            .map(LocalDurableSupervisor::graceful_shutdown)
            .transpose()
    };
    let mut control = lock_unpoison(&shared.control);
    control.running = false;
    if let Err(error) = loop_result {
        control.last_error = Some(error.to_string());
    } else if let Err(error) = shutdown_result {
        control.last_error = Some(error.to_string());
    }
    control.generation = control.generation.saturating_add(1);
    shared.wake.notify_all();
}

fn worker_loop(
    shared: &RuntimeShared,
    service: &M1ReferenceService,
    clock: &Arc<dyn SupervisorClock>,
    max_idle_wait: Duration,
) -> Result<(), M2RuntimeError> {
    loop {
        if lock_unpoison(&shared.control).stop_requested {
            return Ok(());
        }

        let (dispatch_context, next_due_at_ms) = {
            let mut supervisor_slot = lock_unpoison(&shared.supervisor);
            let supervisor = supervisor_slot.as_mut().ok_or(M2RuntimeError::NotRunning)?;
            supervisor.reconcile()?;
            let dispatch = supervisor.claim_due_job()?;
            let context = dispatch.map(|dispatch| {
                let job = supervisor
                    .job(&dispatch.job_id)
                    .expect("a claimed dispatch retains its durable job");
                let job_approval_request_id = job.approval_request_id.clone();
                let approval_resolution =
                    job_approval_request_id.as_ref().and_then(|approval_id| {
                        supervisor
                            .state()
                            .approval_resolutions
                            .get(approval_id)
                            .cloned()
                    });
                DispatchContext {
                    dispatch,
                    job_approval_request_id,
                    approval_resolution,
                }
            });
            let next_due = supervisor.status().heartbeat.next_due_at_ms;
            (context, next_due)
        };

        if let Some(context) = dispatch_context {
            let _effect_boundary = lock_unpoison(&shared.execution_gate);
            if lock_unpoison(&shared.control).stop_requested {
                return Ok(());
            }
            let still_owned = {
                let supervisor_slot = lock_unpoison(&shared.supervisor);
                let supervisor = supervisor_slot.as_ref().ok_or(M2RuntimeError::NotRunning)?;
                supervisor
                    .job(&context.dispatch.job_id)
                    .filter(|job| job.phase == JobPhase::Leased)
                    .and_then(|job| job.lease.as_ref())
                    .is_some_and(|lease| lease.lease_token == context.dispatch.lease_token)
            };
            if !still_owned {
                continue;
            }

            let mut handler = M1LifecycleHandler {
                service,
                job_approval_request_id: context.job_approval_request_id,
                approval_resolution: context.approval_resolution,
            };
            let result = handler.execute(&context.dispatch);
            let completion = {
                let mut supervisor_slot = lock_unpoison(&shared.supervisor);
                let supervisor = supervisor_slot.as_mut().ok_or(M2RuntimeError::NotRunning)?;
                supervisor.complete_dispatch(&context.dispatch, result)
            };
            match completion {
                Ok(_) => {}
                Err(SupervisorError::StaleLease { .. })
                | Err(SupervisorError::JobAlreadyTerminal { .. }) => {}
                Err(error) => return Err(error.into()),
            }
            continue;
        }

        let now_ms = clock.now_ms();
        let until_due = next_due_at_ms
            .map(|due| Duration::from_millis(due.saturating_sub(now_ms)))
            .unwrap_or(max_idle_wait)
            .min(max_idle_wait)
            .max(Duration::from_millis(1));
        let control = lock_unpoison(&shared.control);
        if control.stop_requested {
            return Ok(());
        }
        let observed_generation = control.generation;
        let wait_result = shared.wake.wait_timeout_while(control, until_due, |state| {
            !state.stop_requested && state.generation == observed_generation
        });
        match wait_result {
            Ok(_) => {}
            Err(poisoned) => {
                drop(poisoned.into_inner());
            }
        }
    }
}

struct DispatchContext {
    dispatch: JobDispatch,
    job_approval_request_id: Option<String>,
    approval_resolution: Option<ApprovalResolutionRecord>,
}

struct M1LifecycleHandler<'a> {
    service: &'a M1ReferenceService,
    job_approval_request_id: Option<String>,
    approval_resolution: Option<ApprovalResolutionRecord>,
}

impl IdempotentJobHandler for M1LifecycleHandler<'_> {
    fn execute(&mut self, dispatch: &JobDispatch) -> JobExecutionResult {
        let lifecycle = match serde_json::from_str::<M1LifecycleJob>(&dispatch.payload_json) {
            Ok(lifecycle) => lifecycle,
            Err(error) => {
                return permanent_failure(
                    "m1_payload_invalid",
                    format!("closed M1 payload did not decode: {error}"),
                );
            }
        };
        if lifecycle.job_kind() != dispatch.job_kind {
            return permanent_failure(
                "m1_job_kind_mismatch",
                format!(
                    "payload kind {} does not match durable job kind {}",
                    lifecycle.job_kind(),
                    dispatch.job_kind
                ),
            );
        }
        if lifecycle.approval_request_id() != self.job_approval_request_id.as_deref() {
            return permanent_failure(
                "m1_approval_binding_mismatch",
                "payload approval id does not exactly match the durable job approval id",
            );
        }

        let result = match lifecycle {
            M1LifecycleJob::OpenWorkspace(payload) => self.open_workspace(payload),
            M1LifecycleJob::Materialize(payload) => self.materialize(payload),
            M1LifecycleJob::Package(payload) => self.package(payload),
            M1LifecycleJob::Prove(payload) => self.prove(payload),
            M1LifecycleJob::Compare(payload) => self.compare(payload),
            M1LifecycleJob::Activate(payload) => self.activate(payload),
            M1LifecycleJob::Observe(payload) => self.observe(payload),
            M1LifecycleJob::Rollback(payload) => self.rollback(payload),
        };
        match result {
            Ok((job_kind, record)) => effect_commit(job_kind, record),
            Err(HandlerFailure::Retryable { class, detail }) => {
                JobExecutionResult::RetryableFailure {
                    failure_class: class,
                    detail,
                }
            }
            Err(HandlerFailure::Permanent { class, detail }) => permanent_failure(class, detail),
        }
    }
}

impl M1LifecycleHandler<'_> {
    fn open_workspace(
        &self,
        payload: OpenWorkspacePayload,
    ) -> Result<(&'static str, Value), HandlerFailure> {
        self.service
            .initialize_incumbent()
            .map_err(classify_lifecycle_error)?;
        let record = self
            .service
            .open_challenger_workspace(&payload.workspace_id)
            .map_err(classify_lifecycle_error)?;
        encode_record(M1_OPEN_WORKSPACE_JOB_KIND, &record)
    }

    fn materialize(
        &self,
        payload: MaterializePayload,
    ) -> Result<(&'static str, Value), HandlerFailure> {
        let state = self.service.state().map_err(classify_lifecycle_error)?;
        let workspace = state.challenger_workspace.as_ref().ok_or_else(|| {
            reference_mismatch("materialization requires a persisted challenger workspace")
        })?;
        require_reference(
            "workspace snapshot",
            &workspace.snapshot_digest,
            &payload.workspace_snapshot_digest,
        )?;
        let record = self
            .service
            .materialize_challenger_wat(
                &payload.workspace_id,
                &payload.expected_before_digest,
                &payload.replacement_wat_bytes,
            )
            .map_err(classify_lifecycle_error)?;
        encode_record(M1_MATERIALIZE_JOB_KIND, &record)
    }

    fn package(&self, payload: PackagePayload) -> Result<(&'static str, Value), HandlerFailure> {
        let state = self.service.state().map_err(classify_lifecycle_error)?;
        let patchset = state.challenger_patchset.as_ref().ok_or_else(|| {
            reference_mismatch("packaging requires a persisted materialized patchset")
        })?;
        require_reference(
            "patchset",
            &patchset.patchset_digest,
            &payload.patchset_digest,
        )?;
        let record = self
            .service
            .package_challenger(&payload.workspace_id, &payload.expected_source_tree_digest)
            .map_err(classify_lifecycle_error)?;
        encode_record(M1_PACKAGE_JOB_KIND, &record)
    }

    fn prove(&self, payload: ProvePayload) -> Result<(&'static str, Value), HandlerFailure> {
        let state = self.service.state().map_err(classify_lifecycle_error)?;
        let package = state
            .challenger_package
            .as_ref()
            .ok_or_else(|| reference_mismatch("proving requires a persisted challenger package"))?;
        require_reference(
            "package record",
            &package.record_digest,
            &payload.package_record_digest,
        )?;
        let record = self
            .service
            .prove_challenger(
                &payload.package_digest,
                &payload.expected_source_tree_digest,
            )
            .map_err(classify_lifecycle_error)?;
        encode_record(M1_PROVE_JOB_KIND, &record)
    }

    fn compare(&self, payload: ComparePayload) -> Result<(&'static str, Value), HandlerFailure> {
        let state = self.service.state().map_err(classify_lifecycle_error)?;
        let incumbent = state.incumbent.as_ref().ok_or_else(|| {
            reference_mismatch("comparison requires persisted incumbent proving evidence")
        })?;
        let challenger = state.challenger_proving.as_ref().ok_or_else(|| {
            reference_mismatch("comparison requires persisted challenger proving evidence")
        })?;
        require_reference(
            "incumbent proving record",
            &incumbent.artifact.proving.record_digest,
            &payload.incumbent_proving_record_digest,
        )?;
        require_reference(
            "challenger proving record",
            &challenger.record_digest,
            &payload.challenger_proving_record_digest,
        )?;
        let record = self
            .service
            .compare_challenger(
                &payload.incumbent_proving_record_digest,
                &payload.challenger_proving_record_digest,
            )
            .map_err(classify_lifecycle_error)?;
        encode_record(M1_COMPARE_JOB_KIND, &record)
    }

    fn activate(&self, payload: ActivatePayload) -> Result<(&'static str, Value), HandlerFailure> {
        let resolution = self.granted_resolution(&payload.approval_request_id)?;
        let state = self.service.state().map_err(classify_lifecycle_error)?;
        let comparison = state.challenger_comparison.as_ref().ok_or_else(|| {
            reference_mismatch("activation requires persisted comparison evidence")
        })?;
        require_reference(
            "comparison record",
            &comparison.record_digest,
            &payload.comparison_record_digest,
        )?;
        self.service
            .record_approval(
                &resolution.approval_request_id,
                ApprovalDecision::Approve,
                &resolution.evidence_ref,
            )
            .map_err(classify_lifecycle_error)?;
        let record = self
            .service
            .activate_approved()
            .map_err(classify_lifecycle_error)?;
        encode_record(M1_ACTIVATE_JOB_KIND, &record)
    }

    fn observe(&self, payload: ObservePayload) -> Result<(&'static str, Value), HandlerFailure> {
        let state = self.service.state().map_err(classify_lifecycle_error)?;
        let activation = state
            .activation
            .as_ref()
            .ok_or_else(|| reference_mismatch("observation requires a persisted activation"))?;
        require_text_reference(
            "activation operation",
            &activation.operation_id,
            &payload.activation_operation_id,
        )?;
        require_reference(
            "activated component",
            &activation.activated_artifact.digest,
            &payload.activated_component_digest,
        )?;
        let record = self
            .service
            .observe_active()
            .map_err(classify_lifecycle_error)?;
        encode_record(M1_OBSERVE_JOB_KIND, &record)
    }

    fn rollback(&self, payload: RollbackPayload) -> Result<(&'static str, Value), HandlerFailure> {
        let resolution = self.granted_resolution(&payload.approval_request_id)?;
        if payload.reason_ref.trim().is_empty() {
            return Err(reference_mismatch("rollback reason_ref must not be blank"));
        }
        let state = self.service.state().map_err(classify_lifecycle_error)?;
        let activation = state
            .activation
            .as_ref()
            .ok_or_else(|| reference_mismatch("rollback requires a persisted activation"))?;
        let observation = state.active_observation.as_ref().ok_or_else(|| {
            reference_mismatch("rollback requires persisted active observation evidence")
        })?;
        require_text_reference(
            "activation operation",
            &activation.operation_id,
            &payload.activation_operation_id,
        )?;
        require_reference(
            "active observation record",
            &observation.record_digest,
            &payload.observation_record_digest,
        )?;
        let resolution_digest =
            digest_json_content(resolution).map_err(|error| HandlerFailure::Permanent {
                class: "m1_approval_binding_invalid".to_string(),
                detail: error.to_string(),
            })?;
        let bound_reason_ref = format!(
            "{};supervisor-approval={};resolution={}",
            payload.reason_ref, resolution.approval_request_id, resolution_digest
        );
        let record = self
            .service
            .rollback_and_verify(&bound_reason_ref)
            .map_err(classify_lifecycle_error)?;
        encode_record(M1_ROLLBACK_JOB_KIND, &record)
    }

    fn granted_resolution(
        &self,
        payload_approval_id: &str,
    ) -> Result<&ApprovalResolutionRecord, HandlerFailure> {
        let job_approval_id = self.job_approval_request_id.as_deref().ok_or_else(|| {
            reference_mismatch("approval-bound payload has no durable job approval id")
        })?;
        require_text_reference("approval request", job_approval_id, payload_approval_id)?;
        let resolution = self.approval_resolution.as_ref().ok_or_else(|| {
            reference_mismatch("approval-bound job has no durable resolution record")
        })?;
        require_text_reference(
            "approval resolution",
            &resolution.approval_request_id,
            payload_approval_id,
        )?;
        if resolution.resolution != ApprovalResolutionKind::Granted {
            return Err(reference_mismatch(
                "only an exact granted approval resolution authorizes this effect",
            ));
        }
        Ok(resolution)
    }
}

fn encode_record<T: Serialize>(
    job_kind: &'static str,
    record: &T,
) -> Result<(&'static str, Value), HandlerFailure> {
    serde_json::to_value(record)
        .map(|value| (job_kind, value))
        .map_err(|error| HandlerFailure::Permanent {
            class: "m1_result_encoding_failed".to_string(),
            detail: error.to_string(),
        })
}

fn effect_commit(job_kind: &'static str, record: Value) -> JobExecutionResult {
    let envelope = LifecycleEffectEnvelope {
        schema: EFFECT_SCHEMA,
        job_kind,
        record,
    };
    let value = match serde_json::to_value(&envelope) {
        Ok(value) => value,
        Err(error) => {
            return permanent_failure("m1_result_encoding_failed", error.to_string());
        }
    };
    let bytes = match serde_json::to_vec(&value) {
        Ok(bytes) => bytes,
        Err(error) => {
            return permanent_failure("m1_result_encoding_failed", error.to_string());
        }
    };
    let record_digest = ContentDigest::from_bytes(&bytes);
    let effect_id = format!("{job_kind}:{}", record_digest.as_str());
    match EffectCommit::from_json(effect_id, &value) {
        Ok(commit) => JobExecutionResult::EffectCommitted(commit),
        Err(error) => permanent_failure("m1_effect_commit_invalid", error.to_string()),
    }
}

fn permanent_failure(class: impl Into<String>, detail: impl Into<String>) -> JobExecutionResult {
    JobExecutionResult::PermanentFailure {
        failure_class: class.into(),
        detail: detail.into(),
    }
}

fn require_reference(
    role: &str,
    actual: &ContentDigest,
    requested: &ContentDigest,
) -> Result<(), HandlerFailure> {
    if actual == requested {
        return Ok(());
    }
    Err(reference_mismatch(format!(
        "{role} reference mismatch: durable {actual}, requested {requested}"
    )))
}

fn require_text_reference(role: &str, actual: &str, requested: &str) -> Result<(), HandlerFailure> {
    if !actual.is_empty() && actual == requested {
        return Ok(());
    }
    Err(reference_mismatch(format!(
        "{role} reference mismatch: durable {actual:?}, requested {requested:?}"
    )))
}

fn reference_mismatch(detail: impl Into<String>) -> HandlerFailure {
    HandlerFailure::Permanent {
        class: "m1_reference_mismatch".to_string(),
        detail: detail.into(),
    }
}

fn classify_lifecycle_error(error: ReferenceLifecycleError) -> HandlerFailure {
    match error {
        ReferenceLifecycleError::Io { .. }
        | ReferenceLifecycleError::Candidate(_)
        | ReferenceLifecycleError::Deployment(_) => HandlerFailure::Retryable {
            class: "m1_local_effect_transient".to_string(),
            detail: error.to_string(),
        },
        ReferenceLifecycleError::Serialization(_)
        | ReferenceLifecycleError::Artifact(_)
        | ReferenceLifecycleError::Validation(_)
        | ReferenceLifecycleError::InvalidInput(_)
        | ReferenceLifecycleError::InvalidTransition(_)
        | ReferenceLifecycleError::Conflict(_)
        | ReferenceLifecycleError::Invariant(_)
        | ReferenceLifecycleError::UnsafePath { .. }
        | ReferenceLifecycleError::CorruptContent { .. }
        | ReferenceLifecycleError::UnsupportedSchema { .. } => HandlerFailure::Permanent {
            class: "m1_lifecycle_rejected".to_string(),
            detail: error.to_string(),
        },
    }
}

enum HandlerFailure {
    Retryable { class: String, detail: String },
    Permanent { class: String, detail: String },
}

fn lock_unpoison<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[derive(Debug)]
pub enum M2RuntimeError {
    InvalidConfig(String),
    Supervisor(SupervisorError),
    Lifecycle(ReferenceLifecycleError),
    Serialization(serde_json::Error),
    ThreadSpawn(std::io::Error),
    WorkerFailed(String),
    WorkerPanicked,
    NotRunning,
    AdminRequiresStoppedRuntime,
}

impl From<SupervisorError> for M2RuntimeError {
    fn from(value: SupervisorError) -> Self {
        Self::Supervisor(value)
    }
}

impl From<ReferenceLifecycleError> for M2RuntimeError {
    fn from(value: ReferenceLifecycleError) -> Self {
        Self::Lifecycle(value)
    }
}

impl From<serde_json::Error> for M2RuntimeError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialization(value)
    }
}

impl Display for M2RuntimeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(reason) => write!(formatter, "invalid M2 runtime config: {reason}"),
            Self::Supervisor(error) => write!(formatter, "M2 supervisor failed: {error}"),
            Self::Lifecycle(error) => write!(formatter, "M1 lifecycle failed: {error}"),
            Self::Serialization(error) => write!(formatter, "M2 JSON encoding failed: {error}"),
            Self::ThreadSpawn(error) => write!(formatter, "M2 worker could not start: {error}"),
            Self::WorkerFailed(error) => write!(formatter, "M2 worker failed: {error}"),
            Self::WorkerPanicked => write!(formatter, "M2 worker panicked"),
            Self::NotRunning => write!(formatter, "M2 runtime is not running"),
            Self::AdminRequiresStoppedRuntime => {
                write!(
                    formatter,
                    "M2 migration administration requires a stopped runtime"
                )
            }
        }
    }
}

impl Error for M2RuntimeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Supervisor(error) => Some(error),
            Self::Lifecycle(error) => Some(error),
            Self::Serialization(error) => Some(error),
            Self::ThreadSpawn(error) => Some(error),
            Self::InvalidConfig(_)
            | Self::WorkerFailed(_)
            | Self::WorkerPanicked
            | Self::NotRunning
            | Self::AdminRequiresStoppedRuntime => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ActivatePayload, ComparePayload, DispatchContext, M1LifecycleHandler, M1LifecycleJob,
        M2Runtime, M2RuntimeConfig, M2RuntimeError, M2SubmitJobRequest, MaterializePayload,
        ObservePayload, OpenWorkspacePayload, PackagePayload, ProvePayload, RollbackPayload,
    };
    use crate::candidate::COMPONENT_WAT_PATH;
    use crate::execution::artifact::ContentDigest;
    use crate::m1_reference::M1ReferenceService;
    use crate::supervisor::{
        ApprovalResolutionKind, ApprovalResolutionRecord, AttemptOutcome, IdempotentJobHandler,
        JobExecutionResult, JobPhase, LocalDurableSupervisor, RetryPolicy, SubmitJobRequest,
        SupervisorClock, SupervisorError,
    };
    use serde_json::Value;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory {
        root: PathBuf,
    }

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "wasm-biotic-m2-runtime-{label}-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&root).expect("create test root");
            Self { root }
        }

        fn config(&self, owner_id: &str) -> M2RuntimeConfig {
            M2RuntimeConfig {
                supervisor_root: self.root.join("supervisor"),
                lifecycle_root: self.root.join("lifecycle"),
                template_root: template_root(),
                owner_id: owner_id.to_string(),
                max_idle_wait_ms: 20,
            }
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[derive(Debug)]
    struct ManualClock {
        now_ms: AtomicU64,
    }

    impl ManualClock {
        fn new(now_ms: u64) -> Self {
            Self {
                now_ms: AtomicU64::new(now_ms),
            }
        }

        fn advance(&self, delta_ms: u64) {
            self.now_ms.fetch_add(delta_ms, Ordering::SeqCst);
        }
    }

    impl SupervisorClock for ManualClock {
        fn now_ms(&self) -> u64 {
            self.now_ms.load(Ordering::SeqCst)
        }
    }

    fn repository_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    fn fixture_root() -> PathBuf {
        repository_root().join("artifacts/fixtures/m1-reference-component")
    }

    fn template_root() -> PathBuf {
        fixture_root().join("template")
    }

    fn increment_wat() -> Vec<u8> {
        fs::read(fixture_root().join("candidates/increment.wat")).expect("read increment candidate")
    }

    fn wall_now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock follows epoch")
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX)
    }

    fn policy() -> RetryPolicy {
        RetryPolicy {
            max_attempts: 3,
            initial_backoff_ms: 5,
            max_backoff_ms: 20,
            lease_duration_ms: 60_000,
            attempt_timeout_ms: 60_000,
        }
    }

    fn submit(runtime: &M2Runtime, job_id: &str, not_before_ms: u64, lifecycle: M1LifecycleJob) {
        let outcome = runtime
            .submit(M2SubmitJobRequest {
                job_id: job_id.to_string(),
                idempotency_key: format!("effect-{job_id}"),
                not_before_ms,
                deadline_at_ms: not_before_ms.saturating_add(120_000),
                retry_policy: policy(),
                lifecycle,
            })
            .expect("submit lifecycle job");
        assert!(outcome.created);
    }

    fn wait_for_terminal(runtime: &M2Runtime, job_id: &str) -> crate::supervisor::DurableJob {
        let started = Instant::now();
        loop {
            let job = runtime.job(job_id).expect("read job").expect("job exists");
            if job.phase.is_terminal() {
                return job;
            }
            assert!(
                started.elapsed() < Duration::from_secs(20),
                "job {job_id} did not become terminal; last phase {:?}",
                job.phase
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn wait_for_success(runtime: &M2Runtime, job_id: &str) {
        let job = wait_for_terminal(runtime, job_id);
        assert_eq!(job.phase, JobPhase::Succeeded, "{:?}", job.terminal_outcome);
    }

    fn lifecycle_state(test: &TestDirectory) -> crate::m1_reference::ReferenceLineage {
        M1ReferenceService::open(test.root.join("lifecycle"), template_root())
            .expect("open lifecycle observer")
            .state()
            .expect("read lifecycle state")
    }

    #[test]
    fn construction_is_lazy_and_admin_requires_a_released_writer() {
        let test = TestDirectory::new("lazy-writer");
        let first = M2Runtime::new(test.config("owner-a")).expect("construct first runtime");
        let second = M2Runtime::new(test.config("owner-b")).expect("construct second runtime");
        assert!(!test.root.join("supervisor").exists());
        assert!(!test.root.join("lifecycle").exists());

        first.start().expect("start first writer");
        assert!(matches!(
            second.start(),
            Err(M2RuntimeError::Supervisor(
                SupervisorError::WriterAlreadyActive { .. }
            ))
        ));
        assert!(matches!(
            first.migration_dry_run(),
            Err(M2RuntimeError::AdminRequiresStoppedRuntime)
        ));

        first.stop().expect("stop first writer");
        let plan = first.migration_dry_run().expect("plan current migration");
        assert_eq!(plan.from_version, plan.to_version);
        assert!(!plan.backup_required);
        second.start().expect("start successor writer");
        let status = second.status().expect("successor status");
        assert!(status.worker_running);
        serde_json::to_value(&status).expect("status is transport serializable");
        second.stop().expect("stop successor");
    }

    #[test]
    fn rapid_stop_drop_reopen_stress_preserves_owner_lock_and_atomic_state() {
        let test = TestDirectory::new("rapid-stop-drop-reopen");
        let clock = Arc::new(ManualClock::new(10_000));
        let supervisor_root = test.root.join("supervisor");
        let state_path = supervisor_root.join("supervisor-state.json");

        for iteration in 0..128 {
            let runtime = M2Runtime::with_clock(
                test.config(&format!("owner-{iteration}-active")),
                clock.clone(),
            )
            .expect("construct stress runtime");
            runtime.start().unwrap_or_else(|error| {
                panic!("iteration {iteration} start failed with exact operation: {error:#?}")
            });
            let state_before =
                fs::read(&state_path).expect("read state before rejected duplicate owner");

            let duplicate = M2Runtime::with_clock(
                test.config(&format!("owner-{iteration}-duplicate")),
                clock.clone(),
            )
            .expect("construct duplicate stress runtime");
            assert!(matches!(
                duplicate.start(),
                Err(M2RuntimeError::Supervisor(
                    SupervisorError::WriterAlreadyActive { .. }
                ))
            ));
            assert_eq!(
                fs::read(&state_path).expect("read state after rejected duplicate owner"),
                state_before,
                "same-process duplicate acquisition must not change state bytes"
            );
            drop(duplicate);

            if iteration % 2 == 0 {
                runtime.stop().unwrap_or_else(|error| {
                    panic!("iteration {iteration} stop failed with exact operation: {error:#?}")
                });
            }
            drop(runtime);

            let staged = fs::read_dir(&supervisor_root)
                .expect("supervisor root survives stop/drop")
                .map(|entry| entry.expect("read supervisor entry").file_name())
                .filter_map(|name| name.to_str().map(str::to_string))
                .filter(|name| name.starts_with(".supervisor-state") && name.ends_with(".tmp"))
                .collect::<Vec<_>>();
            assert!(
                staged.is_empty(),
                "iteration {iteration} retained supervisor temp files: {staged:?}"
            );
            serde_json::from_slice::<Value>(
                &fs::read(&state_path).expect("state survives rapid stop/drop"),
            )
            .expect("rapid stop/drop leaves valid durable JSON");
        }

        let final_reopen =
            M2Runtime::with_clock(test.config("owner-final-reopen"), clock).expect("final runtime");
        final_reopen
            .start()
            .unwrap_or_else(|error| panic!("final reopen failed with exact operation: {error:#?}"));
        final_reopen
            .stop()
            .unwrap_or_else(|error| panic!("final stop failed with exact operation: {error:#?}"));
    }

    #[test]
    fn background_executes_the_full_typed_lifecycle_and_reopens_cleanly() {
        let test = TestDirectory::new("full-background");
        let runtime = M2Runtime::new(test.config("full-owner")).expect("construct runtime");
        let due_at_ms = wall_now_ms().saturating_add(120);
        submit(
            &runtime,
            "open",
            due_at_ms,
            M1LifecycleJob::OpenWorkspace(OpenWorkspacePayload {
                workspace_id: "m2-candidate".to_string(),
            }),
        );
        let pending = runtime.status().expect("pending status");
        assert!(pending.heartbeat.next_due_at_ms.is_some());
        wait_for_success(&runtime, "open");

        // A clean stop drops the file lock; reopening recovers the durable job
        // and M1 boundaries without resubmission.
        runtime.stop().expect("graceful midpoint stop");
        runtime.start().expect("reopen runtime");
        assert_eq!(
            runtime
                .job("open")
                .expect("read reopened job")
                .unwrap()
                .phase,
            JobPhase::Succeeded
        );

        let state = lifecycle_state(&test);
        let workspace = state
            .challenger_workspace
            .expect("opened workspace boundary");
        let expected_before_digest = workspace
            .snapshot
            .entry(COMPONENT_WAT_PATH)
            .expect("workspace WAT")
            .content_digest
            .clone();
        submit(
            &runtime,
            "materialize",
            wall_now_ms(),
            M1LifecycleJob::Materialize(MaterializePayload {
                workspace_id: workspace.snapshot.workspace_id,
                workspace_snapshot_digest: workspace.snapshot_digest,
                expected_before_digest,
                replacement_wat_bytes: increment_wat(),
            }),
        );
        wait_for_success(&runtime, "materialize");

        let state = lifecycle_state(&test);
        let patchset = state.challenger_patchset.expect("patchset boundary");
        submit(
            &runtime,
            "package",
            wall_now_ms(),
            M1LifecycleJob::Package(PackagePayload {
                workspace_id: patchset.workspace_id,
                patchset_digest: patchset.patchset_digest,
                expected_source_tree_digest: patchset.after.tree_digest,
            }),
        );
        wait_for_success(&runtime, "package");

        let state = lifecycle_state(&test);
        let package = state.challenger_package.expect("package boundary");
        submit(
            &runtime,
            "prove",
            wall_now_ms(),
            M1LifecycleJob::Prove(ProvePayload {
                package_record_digest: package.record_digest,
                package_digest: package.package.digest,
                expected_source_tree_digest: package.build.source_tree_digest,
            }),
        );
        wait_for_success(&runtime, "prove");

        let state = lifecycle_state(&test);
        let incumbent_digest = state
            .incumbent
            .expect("incumbent")
            .artifact
            .proving
            .record_digest;
        let challenger_digest = state
            .challenger_proving
            .expect("challenger proving")
            .record_digest;
        submit(
            &runtime,
            "compare",
            wall_now_ms(),
            M1LifecycleJob::Compare(ComparePayload {
                incumbent_proving_record_digest: incumbent_digest,
                challenger_proving_record_digest: challenger_digest,
            }),
        );
        wait_for_success(&runtime, "compare");

        let comparison_digest = lifecycle_state(&test)
            .challenger_comparison
            .expect("comparison boundary")
            .record_digest;
        submit(
            &runtime,
            "activate",
            wall_now_ms(),
            M1LifecycleJob::Activate(ActivatePayload {
                comparison_record_digest: comparison_digest,
                approval_request_id: "approve-activation".to_string(),
            }),
        );
        assert_eq!(
            runtime
                .job("activate")
                .expect("read activation")
                .unwrap()
                .phase,
            JobPhase::WaitingApproval
        );
        runtime
            .resolve_approval(ApprovalResolutionRecord {
                approval_request_id: "approve-activation".to_string(),
                resolution: ApprovalResolutionKind::Granted,
                evidence_ref: "operator:activation-review-1".to_string(),
                resolved_at_ms: 0,
            })
            .expect("grant activation");
        wait_for_success(&runtime, "activate");

        let activation = lifecycle_state(&test).activation.expect("activation");
        submit(
            &runtime,
            "observe",
            wall_now_ms(),
            M1LifecycleJob::Observe(ObservePayload {
                activation_operation_id: activation.operation_id.clone(),
                activated_component_digest: activation.activated_artifact.digest,
            }),
        );
        wait_for_success(&runtime, "observe");

        let observation = lifecycle_state(&test)
            .active_observation
            .expect("active observation");
        submit(
            &runtime,
            "rollback",
            wall_now_ms(),
            M1LifecycleJob::Rollback(RollbackPayload {
                activation_operation_id: activation.operation_id,
                observation_record_digest: observation.record_digest,
                approval_request_id: "approve-rollback".to_string(),
                reason_ref: "incident:m2-rehearsal".to_string(),
            }),
        );
        runtime
            .resolve_approval(ApprovalResolutionRecord {
                approval_request_id: "approve-rollback".to_string(),
                resolution: ApprovalResolutionKind::Granted,
                evidence_ref: "operator:rollback-review-1".to_string(),
                resolved_at_ms: 0,
            })
            .expect("grant rollback");
        wait_for_success(&runtime, "rollback");

        let completed = lifecycle_state(&test);
        assert!(completed.rollback.is_some());
        assert!(
            completed
                .rollback
                .as_ref()
                .unwrap()
                .deployment
                .reason_ref
                .contains("supervisor-approval=approve-rollback")
        );
        serde_json::to_value(runtime.jobs().expect("list jobs"))
            .expect("job list is transport serializable");
        runtime.stop().expect("final clean stop");
    }

    #[test]
    fn deny_expire_and_escalate_are_terminal_without_calling_an_effect() {
        let test = TestDirectory::new("non-grants");
        let runtime = M2Runtime::new(test.config("non-grant-owner")).expect("construct runtime");
        let fake_comparison = ContentDigest::from_bytes(b"not-a-comparison");
        let cases = [
            ("denied", ApprovalResolutionKind::Denied, JobPhase::Denied),
            (
                "expired",
                ApprovalResolutionKind::Expired,
                JobPhase::ApprovalExpired,
            ),
            (
                "escalated",
                ApprovalResolutionKind::Escalated,
                JobPhase::ApprovalEscalated,
            ),
        ];
        for (id, resolution, terminal_phase) in cases {
            let approval_id = format!("approval-{id}");
            submit(
                &runtime,
                id,
                wall_now_ms(),
                M1LifecycleJob::Activate(ActivatePayload {
                    comparison_record_digest: fake_comparison.clone(),
                    approval_request_id: approval_id.clone(),
                }),
            );
            runtime
                .resolve_approval(ApprovalResolutionRecord {
                    approval_request_id: approval_id,
                    resolution,
                    evidence_ref: format!("operator:{id}"),
                    resolved_at_ms: 0,
                })
                .expect("resolve non-grant");
            let job = wait_for_terminal(&runtime, id);
            assert_eq!(job.phase, terminal_phase);
            assert_eq!(job.attempt_count(), 0);
        }
        assert!(lifecycle_state(&test).activation.is_none());
        runtime.stop().expect("stop runtime");
    }

    #[test]
    fn replay_after_effect_before_receipt_returns_the_same_commit_once() {
        let test = TestDirectory::new("effect-boundary");
        let service = M1ReferenceService::open(test.root.join("lifecycle"), template_root())
            .expect("open lifecycle");
        service
            .initialize_incumbent()
            .expect("initialize incumbent");
        let challenger = service
            .prepare_challenger(&increment_wat())
            .expect("prepare challenger");
        let clock = Arc::new(ManualClock::new(10_000));
        let mut supervisor = LocalDurableSupervisor::open(
            test.root.join("supervisor"),
            "crash-owner",
            clock.clone(),
        )
        .expect("open supervisor");
        let lifecycle = M1LifecycleJob::Activate(ActivatePayload {
            comparison_record_digest: challenger.comparison.record_digest,
            approval_request_id: "crash-boundary-approval".to_string(),
        });
        supervisor
            .submit_job(SubmitJobRequest {
                job_id: "activate".to_string(),
                job_kind: lifecycle.job_kind().to_string(),
                payload_json: serde_json::to_string(&lifecycle).unwrap(),
                idempotency_key: "crash-boundary-effect".to_string(),
                not_before_ms: 10_000,
                deadline_at_ms: 20_000,
                retry_policy: RetryPolicy {
                    max_attempts: 3,
                    initial_backoff_ms: 0,
                    max_backoff_ms: 0,
                    lease_duration_ms: 100,
                    attempt_timeout_ms: 1_000,
                },
                approval_request_id: Some("crash-boundary-approval".to_string()),
            })
            .expect("submit activation");
        supervisor
            .resolve_approval(ApprovalResolutionRecord {
                approval_request_id: "crash-boundary-approval".to_string(),
                resolution: ApprovalResolutionKind::Granted,
                evidence_ref: "operator:crash-boundary".to_string(),
                resolved_at_ms: 0,
            })
            .expect("grant activation");
        let first_dispatch = supervisor
            .claim_due_job()
            .expect("claim first")
            .expect("first dispatch");
        let first_context = dispatch_context(&supervisor, first_dispatch);
        let mut first_handler = M1LifecycleHandler {
            service: &service,
            job_approval_request_id: first_context.job_approval_request_id,
            approval_resolution: first_context.approval_resolution,
        };
        let first_result = first_handler.execute(&first_context.dispatch);
        let first_commit = match first_result {
            JobExecutionResult::EffectCommitted(commit) => commit,
            other => panic!("activation did not commit: {other:?}"),
        };

        // Simulated crash: the M1 effect is durable, but the supervisor never
        // receives complete_dispatch for the first lease.
        drop(supervisor);
        drop(service);
        clock.advance(101);
        let reopened_service =
            M1ReferenceService::open(test.root.join("lifecycle"), template_root())
                .expect("recover M1 service");
        let mut reopened = LocalDurableSupervisor::open(
            test.root.join("supervisor"),
            "restart-owner",
            clock.clone(),
        )
        .expect("reopen supervisor");
        let second_dispatch = reopened
            .claim_due_job()
            .expect("claim replay")
            .expect("replayed dispatch");
        let second_context = dispatch_context(&reopened, second_dispatch);
        let mut second_handler = M1LifecycleHandler {
            service: &reopened_service,
            job_approval_request_id: second_context.job_approval_request_id,
            approval_resolution: second_context.approval_resolution,
        };
        let second_result = second_handler.execute(&second_context.dispatch);
        let second_commit = match &second_result {
            JobExecutionResult::EffectCommitted(commit) => commit.clone(),
            other => panic!("replay did not commit: {other:?}"),
        };
        assert_eq!(second_commit, first_commit);
        reopened
            .complete_dispatch(&second_context.dispatch, second_result)
            .expect("commit replay receipt");
        assert_eq!(reopened.job("activate").unwrap().phase, JobPhase::Succeeded);

        let deployment: Value = serde_json::from_slice(
            &fs::read(test.root.join("lifecycle/deployment/deployment-state.json"))
                .expect("read deployment state"),
        )
        .expect("parse deployment state");
        assert_eq!(
            deployment["activations"].as_array().unwrap().len(),
            1,
            "replay must not repeat the physical activation"
        );
    }

    #[test]
    fn wrong_predecessor_and_future_cancellation_never_apply_an_effect() {
        let wrong_ref_test = TestDirectory::new("wrong-ref");
        let wrong_ref_runtime =
            M2Runtime::new(wrong_ref_test.config("wrong-ref-owner")).expect("construct runtime");
        submit(
            &wrong_ref_runtime,
            "out-of-order",
            wall_now_ms(),
            M1LifecycleJob::Materialize(MaterializePayload {
                workspace_id: "missing".to_string(),
                workspace_snapshot_digest: ContentDigest::from_bytes(b"missing-workspace"),
                expected_before_digest: ContentDigest::from_bytes(b"missing-base"),
                replacement_wat_bytes: increment_wat(),
            }),
        );
        let failed = wait_for_terminal(&wrong_ref_runtime, "out-of-order");
        assert_eq!(failed.phase, JobPhase::Failed);
        assert!(
            lifecycle_state(&wrong_ref_test)
                .challenger_patchset
                .is_none()
        );
        wrong_ref_runtime.stop().expect("stop wrong-ref runtime");

        let cancel_test = TestDirectory::new("cancel");
        let cancel_runtime =
            M2Runtime::new(cancel_test.config("cancel-owner")).expect("construct runtime");
        submit(
            &cancel_runtime,
            "cancelled-open",
            wall_now_ms().saturating_add(5_000),
            M1LifecycleJob::OpenWorkspace(OpenWorkspacePayload {
                workspace_id: "never-opened".to_string(),
            }),
        );
        cancel_runtime
            .cancel("cancelled-open", "operator cancelled before due time")
            .expect("cancel future job");
        assert_eq!(
            cancel_runtime
                .job("cancelled-open")
                .expect("read cancelled job")
                .unwrap()
                .phase,
            JobPhase::Cancelled
        );
        thread::sleep(Duration::from_millis(60));
        assert!(lifecycle_state(&cancel_test).incumbent.is_none());
        cancel_runtime.stop().expect("stop cancellation runtime");
    }

    #[test]
    fn retry_timeout_and_restart_lease_loss_remain_bounded_and_durable() {
        let test = TestDirectory::new("retry-timeout");
        let clock = Arc::new(ManualClock::new(100));
        let mut supervisor = LocalDurableSupervisor::open(
            test.root.join("supervisor"),
            "retry-owner",
            clock.clone(),
        )
        .expect("open supervisor");
        supervisor
            .submit_job(SubmitJobRequest {
                job_id: "retry".to_string(),
                job_kind: "m1.open_workspace".to_string(),
                payload_json: "{}".to_string(),
                idempotency_key: "retry-effect".to_string(),
                not_before_ms: 100,
                deadline_at_ms: 1_000,
                retry_policy: RetryPolicy {
                    max_attempts: 5,
                    initial_backoff_ms: 5,
                    max_backoff_ms: 5,
                    lease_duration_ms: 20,
                    attempt_timeout_ms: 40,
                },
                approval_request_id: None,
            })
            .expect("submit retry job");
        let first = supervisor
            .claim_due_job()
            .expect("claim first")
            .expect("first dispatch");
        supervisor
            .complete_dispatch(
                &first,
                JobExecutionResult::RetryableFailure {
                    failure_class: "test_transient".to_string(),
                    detail: "bounded transient failure".to_string(),
                },
            )
            .expect("schedule retry");
        assert_eq!(
            supervisor.job("retry").unwrap().phase,
            JobPhase::RetryScheduled
        );

        clock.advance(5);
        let second = supervisor
            .claim_due_job()
            .expect("claim second")
            .expect("second dispatch");
        clock.advance(21);
        supervisor.reconcile().expect("reconcile expired lease");
        let after_timeout = supervisor.job("retry").unwrap();
        assert_eq!(after_timeout.phase, JobPhase::RetryScheduled);
        assert!(matches!(
            after_timeout.attempts[1].outcome,
            Some(AttemptOutcome::LeaseLost { .. })
        ));

        clock.advance(5);
        let third = supervisor
            .claim_due_job()
            .expect("claim third")
            .expect("third dispatch");
        assert_ne!(second.lease_token, third.lease_token);
        drop(supervisor);
        let reopened = LocalDurableSupervisor::open(
            test.root.join("supervisor"),
            "retry-restart-owner",
            clock,
        )
        .expect("reopen after lease loss");
        let recovered = reopened.job("retry").unwrap();
        assert_eq!(recovered.phase, JobPhase::RetryScheduled);
        assert!(matches!(
            recovered.attempts[2].outcome,
            Some(AttemptOutcome::LeaseLost { .. })
        ));
    }

    fn dispatch_context(
        supervisor: &LocalDurableSupervisor,
        dispatch: crate::supervisor::JobDispatch,
    ) -> DispatchContext {
        let job = supervisor.job(&dispatch.job_id).expect("dispatch job");
        let job_approval_request_id = job.approval_request_id.clone();
        let approval_resolution = job_approval_request_id.as_ref().and_then(|approval_id| {
            supervisor
                .state()
                .approval_resolutions
                .get(approval_id)
                .cloned()
        });
        DispatchContext {
            dispatch,
            job_approval_request_id,
            approval_resolution,
        }
    }
}
