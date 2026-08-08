//! Live, bounded M3 capability-service runtime.
//!
//! This module closes the gap between the typed service host in
//! [`crate::capability_services`] and the durable executor in
//! [`crate::m2_runtime`]. It deliberately exposes a small local-first surface:
//! seven named service families, one fixed scope, one fixed deployment, a
//! digest-bound schedule registry, and durable operational inspection records.
//!
//! Scheduling is not a success-shaped acknowledgement. A schedule must first
//! be bound to one exact [`M1LifecycleJob`]; the scheduling port then submits
//! that payload to M2 and derives its receipt from the durable job returned by
//! M2. Operations inspection similarly joins an actual deployment snapshot
//! with the actual M2 status and jobs and persists the joined record.

use crate::candidate::CandidateWorkspaceService;
use crate::capability_services::{
    CAPABILITY_ATTESTATION_SCHEMA, CancellationToken, CapabilityHostError, CapabilityInvocation,
    CapabilityOperation, CapabilityRequest, CapabilityServiceDependencies,
    CapabilityServiceDescriptor, CapabilityServiceHost, CapabilitySuccess, ClockPort,
    FactoryEvolutionPort, IdempotencyContract, InvocationOutcome, InvocationProvenance,
    InvocationReceipt, LocalBuildPackagingService, LocalDeploymentRollbackAdapter,
    LocalEvidenceStore, LocalValidationReviewService, M1CandidateWorkspaceAdapter,
    OperationsSnapshot, ScheduleJobRequest, ScheduleReceipt, SchedulingPort, ServiceFailure,
    ServiceFailureKind, ServiceHealth, ServiceInvocationAttestation, SystemClock, TimeoutBehavior,
};
use crate::deployment::LocalDeploymentService;
use crate::execution::{
    ApprovalClass, AuthorityClass, ContentDigest, NativeServiceFamily, digest_json_content,
};
use crate::m2_runtime::{
    M1LifecycleJob, M2Runtime, M2RuntimeError, M2RuntimeStatus, M2SubmitJobRequest,
};
use crate::supervisor::{DurableJob, JobPhase, JobTerminalOutcome, RetryPolicy, SupervisorError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

pub const BUILD_SERVICE_ID: &str = "wasm-biotic.build.local.v1";
pub const VALIDATION_SERVICE_ID: &str = "wasm-biotic.validation.local.v1";
pub const REVIEW_SERVICE_ID: &str = "wasm-biotic.review.local.v1";
pub const PACKAGING_SERVICE_ID: &str = "wasm-biotic.packaging.local.v1";
pub const CONTINUITY_SERVICE_ID: &str = "wasm-biotic.continuity.local.v1";
pub const CONTINUITY_RESOLVE_SERVICE_ID: &str = "wasm-biotic.continuity.resolve.local.v1";
pub const SCHEDULING_SERVICE_ID: &str = "wasm-biotic.scheduling.m2.v1";
pub const OPERATIONS_CONTROL_SERVICE_ID: &str = "wasm-biotic.operations.control.local.v1";
pub const OPERATIONS_INSPECT_SERVICE_ID: &str = "wasm-biotic.operations.inspect.local.v1";
pub const FACTORY_EXECUTION_SERVICE_ID: &str = "wasm-biotic.factory.execution.local.v1";
pub const FACTORY_PROMOTION_SERVICE_ID: &str = "wasm-biotic.factory.promotion.local.v1";
pub const FACTORY_INSPECT_SERVICE_ID: &str = "wasm-biotic.factory.inspect.local.v1";

pub const M3_SCHEDULE_BINDING_SCHEMA: &str = "wasm-biotic.m3-schedule-binding.v1";
pub const M3_OPERATIONS_RECORD_SCHEMA: &str = "wasm-biotic.m3-operations-record.v1";
pub const M3_EVIDENCE_BUNDLE_SCHEMA: &str = "wasm-biotic.m3-evidence-bundle.v1";

const HOST_DIRECTORY: &str = "host";
const CANDIDATE_DIRECTORY: &str = "candidate";
const PACKAGING_DIRECTORY: &str = "packaging";
const VALIDATION_DIRECTORY: &str = "validation";
const CONTINUITY_DIRECTORY: &str = "continuity";
const DEPLOYMENT_DIRECTORY: &str = "deployment";
const DEPLOYMENT_CANDIDATE_DIRECTORY: &str = "deployment-candidates";
const SCHEDULE_DIRECTORY: &str = "schedule-bindings";
const OPERATIONS_DIRECTORY: &str = "operations-records";
const EVIDENCE_BUNDLE_DIRECTORY: &str = "evidence-bundles";
const RUNTIME_OWNER_LOCK_FILE: &str = ".m3-runtime-owner.lock";
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 1_024;
const MAX_SCHEDULE_BINDING_BYTES: usize = 2 * 1_048_576;
const MAX_OPERATIONS_JOB_COUNT: usize = 10_000;
const MAX_OPERATIONS_RECORD_BYTES: usize = 16 * 1_048_576;
const MAX_EVIDENCE_BUNDLE_INVOCATIONS: usize = 64;
const MAX_EVIDENCE_BUNDLE_SCHEDULES: usize = 16;
const MAX_EVIDENCE_BUNDLE_OPERATIONS_RECORDS: usize = 8;
const MAX_EVIDENCE_BUNDLE_BYTES: usize = 32 * 1_048_576;

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Explicit roots and identities for one bounded M3 namespace.
///
/// All service-owned state is created below `root`; the frozen template is the
/// sole read-only input outside that root. No path is inferred from the current
/// directory or environment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M3RuntimeConfig {
    pub root: PathBuf,
    pub template_root: PathBuf,
    pub scope_id: String,
    pub deployment_id: String,
    #[serde(default)]
    pub unavailable_service_ids: BTreeSet<String>,
}

impl M3RuntimeConfig {
    pub fn new(
        root: impl Into<PathBuf>,
        template_root: impl Into<PathBuf>,
        scope_id: impl Into<String>,
        deployment_id: impl Into<String>,
    ) -> Self {
        Self {
            root: root.into(),
            template_root: template_root.into(),
            scope_id: scope_id.into(),
            deployment_id: deployment_id.into(),
            unavailable_service_ids: BTreeSet::new(),
        }
    }

    pub fn with_unavailable_services<I, S>(mut self, service_ids: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.unavailable_service_ids = service_ids.into_iter().map(Into::into).collect();
        self
    }

    pub fn validate(&self) -> Result<(), M3RuntimeError> {
        if self.root.as_os_str().is_empty() {
            return Err(M3RuntimeError::InvalidConfig(
                "root must not be empty".to_string(),
            ));
        }
        if self.template_root.as_os_str().is_empty() {
            return Err(M3RuntimeError::InvalidConfig(
                "template_root must not be empty".to_string(),
            ));
        }
        validate_identifier("scope_id", &self.scope_id)?;
        validate_identifier("deployment_id", &self.deployment_id)?;
        for service_id in &self.unavailable_service_ids {
            validate_identifier("unavailable_service_id", service_id)?;
        }
        Ok(())
    }
}

/// Stable public description of one registered capability service.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M3ServiceRegistration {
    pub service_id: String,
    pub family: NativeServiceFamily,
    pub supported_operations: BTreeSet<CapabilityOperation>,
}

/// Request to bind one capability-level schedule to one exact M2 lifecycle
/// payload. Registration is durable and immutable for `schedule_id`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M3ScheduleRegistration {
    pub scope_id: String,
    pub schedule_id: String,
    pub job_id: String,
    pub idempotency_key: String,
    pub due_at_ms: u64,
    pub deadline_at_ms: u64,
    pub retry_policy: RetryPolicy,
    pub lifecycle: M1LifecycleJob,
}

/// Durable schedule binding returned after registration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M3ScheduleBinding {
    pub schema: String,
    pub registration: M3ScheduleRegistration,
    pub payload_digest: ContentDigest,
    pub binding_digest: ContentDigest,
}

impl M3ScheduleBinding {
    pub fn capability_request(&self) -> ScheduleJobRequest {
        ScheduleJobRequest {
            scope_id: self.registration.scope_id.clone(),
            schedule_id: self.registration.schedule_id.clone(),
            due_at_ms: self.registration.due_at_ms,
            payload_digest: self.payload_digest.clone(),
        }
    }
}

/// Supervisor approval state included in a durable operations record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M3ApprovalState {
    pub job_id: String,
    pub approval_request_id: String,
    pub phase: JobPhase,
}

/// Bounded operational projection of one real M2 job.
///
/// Payload JSON is deliberately excluded: its digest is enough to bind the
/// view to the durable job while avoiding payload amplification in every
/// operations inspection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M3JobOperationsView {
    pub job_id: String,
    pub job_kind: String,
    pub payload_digest: ContentDigest,
    pub request_fingerprint: ContentDigest,
    pub phase: JobPhase,
    pub attempt_count: u32,
    pub not_before_ms: u64,
    pub deadline_at_ms: u64,
    pub next_wake_at_ms: Option<u64>,
    pub approval_request_id: Option<String>,
    pub terminal_outcome: Option<JobTerminalOutcome>,
}

impl From<&DurableJob> for M3JobOperationsView {
    fn from(job: &DurableJob) -> Self {
        Self {
            job_id: job.job_id.clone(),
            job_kind: job.job_kind.clone(),
            payload_digest: job.payload_digest.clone(),
            request_fingerprint: job.request_fingerprint.clone(),
            phase: job.phase.clone(),
            attempt_count: job.attempt_count(),
            not_before_ms: job.not_before_ms,
            deadline_at_ms: job.deadline_at_ms,
            next_wake_at_ms: job.next_wake_at_ms,
            approval_request_id: job.approval_request_id.clone(),
            terminal_outcome: job.terminal_outcome.clone(),
        }
    }
}

/// Durable joined view of deployment and supervisor state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M3OperationsRecord {
    pub schema: String,
    pub inspection_invocation_id: String,
    pub inspection_receipt_digest: ContentDigest,
    pub deployment: OperationsSnapshot,
    pub supervisor: M2RuntimeStatus,
    pub jobs: Vec<M3JobOperationsView>,
    pub approvals: Vec<M3ApprovalState>,
    pub record_digest: ContentDigest,
}

/// Exact durable identities selected for one aggregate M3 proof.
///
/// Publication canonicalizes each vector by identity after rejecting
/// duplicates. This makes the bundle digest independent of caller ordering
/// without weakening the exact-set selection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M3EvidenceBundleRequest {
    pub invocation_ids: Vec<String>,
    pub schedule_ids: Vec<String>,
    pub operations_record_digests: Vec<ContentDigest>,
}

/// One exact capability receipt paired with its independently derived service
/// attestation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M3InvocationEvidence {
    pub receipt: InvocationReceipt,
    pub attestation: ServiceInvocationAttestation,
}

/// One immutable schedule binding paired with the exact terminal M2 job.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M3ScheduleEvidence {
    pub binding: M3ScheduleBinding,
    pub job: DurableJob,
}

/// Derived index from a family to the exact successful receipts that cover it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M3FamilyEvidenceIndex {
    pub family: NativeServiceFamily,
    pub receipt_digests: Vec<ContentDigest>,
}

/// Content-addressed aggregate proof for one clean bounded M3 run.
///
/// The bundle embeds exact receipts, attestations, schedule bindings, terminal
/// jobs, and operations records. Its family index is derived from those
/// constituents and is re-derived during every load; it is never accepted as a
/// success assertion on its own.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M3EvidenceBundle {
    pub schema: String,
    pub scope_id: String,
    pub selection: M3EvidenceBundleRequest,
    pub invocations: Vec<M3InvocationEvidence>,
    pub schedules: Vec<M3ScheduleEvidence>,
    pub operations: Vec<M3OperationsRecord>,
    pub family_index: Vec<M3FamilyEvidenceIndex>,
    pub bundle_digest: ContentDigest,
}

/// Live facade over all seven bounded native service families.
pub struct M3CapabilityRuntime {
    config: M3RuntimeConfig,
    root: PathBuf,
    _owner_lock: File,
    host: CapabilityServiceHost,
    scheduling: Arc<M2SchedulingPort>,
    m2: Arc<M2Runtime>,
    services: Vec<M3ServiceRegistration>,
    operations_root: PathBuf,
    evidence_bundle_root: PathBuf,
}

impl M3CapabilityRuntime {
    pub fn open(config: M3RuntimeConfig, m2: Arc<M2Runtime>) -> Result<Self, M3RuntimeError> {
        Self::with_clock(config, m2, Arc::new(SystemClock))
    }

    /// Open the ordinary M3 runtime plus the opt-in generic factory-evolution
    /// boundary. The default [`Self::open`] catalog remains unchanged.
    pub fn open_with_factory_evolution(
        config: M3RuntimeConfig,
        m2: Arc<M2Runtime>,
        factory_evolution: Arc<dyn FactoryEvolutionPort>,
    ) -> Result<Self, M3RuntimeError> {
        Self::open_internal(config, m2, Arc::new(SystemClock), Some(factory_evolution))
    }

    /// Clock injection is public so deadline behavior can be proven without an
    /// unbounded wall-clock test.
    pub fn with_clock(
        config: M3RuntimeConfig,
        m2: Arc<M2Runtime>,
        clock: Arc<dyn ClockPort>,
    ) -> Result<Self, M3RuntimeError> {
        Self::open_internal(config, m2, clock, None)
    }

    fn open_internal(
        config: M3RuntimeConfig,
        m2: Arc<M2Runtime>,
        clock: Arc<dyn ClockPort>,
        factory_evolution: Option<Arc<dyn FactoryEvolutionPort>>,
    ) -> Result<Self, M3RuntimeError> {
        config.validate()?;
        let root = secure_create_root(&config.root)?;
        let owner_lock = acquire_owner_lock(&root)?;
        let host_root = secure_child_directory(&root, HOST_DIRECTORY)?;
        let candidate_root = secure_child_directory(&root, CANDIDATE_DIRECTORY)?;
        let packaging_root = secure_child_directory(&root, PACKAGING_DIRECTORY)?;
        let validation_root = secure_child_directory(&root, VALIDATION_DIRECTORY)?;
        let continuity_root = secure_child_directory(&root, CONTINUITY_DIRECTORY)?;
        let deployment_root = secure_child_directory(&root, DEPLOYMENT_DIRECTORY)?;
        let deployment_candidate_root =
            secure_child_directory(&root, DEPLOYMENT_CANDIDATE_DIRECTORY)?;
        let schedule_root = secure_child_directory(&root, SCHEDULE_DIRECTORY)?;
        let operations_root = secure_child_directory(&root, OPERATIONS_DIRECTORY)?;
        let evidence_bundle_root = secure_child_directory(&root, EVIDENCE_BUNDLE_DIRECTORY)?;

        let candidate_service = Arc::new(CandidateWorkspaceService::bootstrap(candidate_root)?);
        let workspace = Arc::new(M1CandidateWorkspaceAdapter::new(
            config.scope_id.clone(),
            &config.template_root,
            Arc::clone(&candidate_service),
        )?);
        let packaging = Arc::new(LocalBuildPackagingService::open(
            config.scope_id.clone(),
            packaging_root,
            Arc::clone(&candidate_service),
        )?);
        let validation = Arc::new(LocalValidationReviewService::open(
            config.scope_id.clone(),
            validation_root,
            packaging.clone(),
        )?);
        let evidence = Arc::new(LocalEvidenceStore::open(
            config.scope_id.clone(),
            continuity_root,
        )?);
        let deployment = Arc::new(LocalDeploymentService::open(
            deployment_root,
            deployment_candidate_root,
        )?);
        let deployment_adapter = Arc::new(LocalDeploymentRollbackAdapter::open(
            config.scope_id.clone(),
            config.deployment_id.clone(),
            deployment,
            packaging.clone(),
        )?);
        let scheduling = Arc::new(M2SchedulingPort {
            scope_id: config.scope_id.clone(),
            bindings_root: schedule_root,
            m2: Arc::clone(&m2),
            mutation_gate: Mutex::new(()),
        });

        let (mut descriptors, mut services) = service_catalog(&config.scope_id)?;
        if factory_evolution.is_some() {
            let (factory_descriptors, factory_services) =
                factory_service_catalog(&config.scope_id)?;
            descriptors.extend(factory_descriptors);
            services.extend(factory_services);
        }
        for service_id in &config.unavailable_service_ids {
            if !services
                .iter()
                .any(|service| service.service_id == *service_id)
            {
                return Err(M3RuntimeError::InvalidConfig(format!(
                    "unavailable service id '{service_id}' is not in the M3 catalog"
                )));
            }
        }
        let mut dependencies = CapabilityServiceDependencies::empty();
        dependencies.workspace = Some(workspace);
        dependencies.build_packaging = Some(packaging);
        dependencies.validation_review = Some(validation);
        dependencies.deployment = Some(deployment_adapter);
        dependencies.evidence = Some(evidence);
        dependencies.scheduling = Some(scheduling.clone());
        dependencies.factory_evolution = factory_evolution;
        dependencies.unavailable_service_ids = config.unavailable_service_ids.clone();
        dependencies.clock = clock;
        let host = CapabilityServiceHost::open(host_root, descriptors, dependencies)?;

        Ok(Self {
            config,
            root,
            _owner_lock: owner_lock,
            host,
            scheduling,
            m2,
            services,
            operations_root,
            evidence_bundle_root,
        })
    }

    pub fn config(&self) -> &M3RuntimeConfig {
        &self.config
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn services(&self) -> &[M3ServiceRegistration] {
        &self.services
    }

    pub fn invoke(
        &self,
        invocation: &CapabilityInvocation,
        cancellation: CancellationToken,
    ) -> Result<InvocationReceipt, M3RuntimeError> {
        Ok(self.host.invoke(invocation, cancellation)?)
    }

    pub fn receipt(&self, invocation_id: &str) -> Result<InvocationReceipt, M3RuntimeError> {
        Ok(self.host.receipt(invocation_id)?)
    }

    pub fn invocation_input(
        &self,
        invocation_id: &str,
    ) -> Result<CapabilityInvocation, M3RuntimeError> {
        Ok(self.host.invocation_input(invocation_id)?)
    }

    pub fn attestation(
        &self,
        invocation_id: &str,
    ) -> Result<ServiceInvocationAttestation, M3RuntimeError> {
        Ok(self.host.attest(invocation_id)?)
    }

    pub fn health(&self, service_id: &str) -> Result<ServiceHealth, M3RuntimeError> {
        Ok(self.host.health(service_id)?)
    }

    /// Persist an immutable binding before a scheduling invocation may submit
    /// the work. Re-registering the exact binding is idempotent; changing any
    /// field for the same schedule id is a hard conflict.
    pub fn register_schedule(
        &self,
        registration: M3ScheduleRegistration,
    ) -> Result<M3ScheduleBinding, M3RuntimeError> {
        self.scheduling.register(registration)
    }

    /// Resolve the durable M2 job, including its current phase and terminal
    /// outcome, for a previously registered schedule.
    pub fn scheduled_job(&self, schedule_id: &str) -> Result<Option<DurableJob>, M3RuntimeError> {
        let binding = self.scheduling.load(schedule_id)?;
        Ok(self.m2.job(&binding.registration.job_id)?)
    }

    pub fn schedule_binding(&self, schedule_id: &str) -> Result<M3ScheduleBinding, M3RuntimeError> {
        self.scheduling.load(schedule_id)
    }

    /// Invoke the typed Operations inspection service, join it with actual M2
    /// state, and persist the exact joined view.
    pub fn inspect_operations(
        &self,
        invocation: &CapabilityInvocation,
        cancellation: CancellationToken,
    ) -> Result<M3OperationsRecord, M3RuntimeError> {
        if invocation.identity.service_id != OPERATIONS_INSPECT_SERVICE_ID
            || !matches!(invocation.request, CapabilityRequest::InspectOperations(_))
        {
            return Err(M3RuntimeError::InvalidOperationsInspection(
                "inspection requires the operations-inspect service and InspectOperations request"
                    .to_string(),
            ));
        }
        let receipt = self.host.invoke(invocation, cancellation)?;
        let deployment = match receipt.outcome() {
            InvocationOutcome::Succeeded {
                result: CapabilitySuccess::Operations(snapshot),
            } => snapshot.as_ref().clone(),
            InvocationOutcome::Succeeded { .. } => {
                return Err(M3RuntimeError::InvalidOperationsInspection(
                    "operations service returned a non-operations success".to_string(),
                ));
            }
            InvocationOutcome::Terminal { failure } => {
                return Err(M3RuntimeError::TerminalCapability(failure.clone()));
            }
        };
        let supervisor = self.m2.status()?;
        let mut durable_jobs = self.m2.jobs()?;
        if durable_jobs.len() > MAX_OPERATIONS_JOB_COUNT {
            return Err(M3RuntimeError::ResourceBoundExceeded {
                resource: "operations job count",
                actual: durable_jobs.len(),
                limit: MAX_OPERATIONS_JOB_COUNT,
            });
        }
        durable_jobs.sort_by(|left, right| left.job_id.cmp(&right.job_id));
        let mut approvals = durable_jobs
            .iter()
            .filter_map(|job| {
                job.approval_request_id
                    .as_ref()
                    .map(|approval_request_id| M3ApprovalState {
                        job_id: job.job_id.clone(),
                        approval_request_id: approval_request_id.clone(),
                        phase: job.phase.clone(),
                    })
            })
            .collect::<Vec<_>>();
        approvals.sort_by(|left, right| left.job_id.cmp(&right.job_id));
        let jobs = durable_jobs.iter().map(M3JobOperationsView::from).collect();
        let mut record = M3OperationsRecord {
            schema: M3_OPERATIONS_RECORD_SCHEMA.to_string(),
            inspection_invocation_id: receipt.invocation_id().to_string(),
            inspection_receipt_digest: receipt.receipt_digest().clone(),
            deployment,
            supervisor,
            jobs,
            approvals,
            record_digest: ContentDigest::from_bytes(&[]),
        };
        record.record_digest = operations_record_digest(&record)?;
        let bytes = serde_json::to_vec_pretty(&record)?;
        enforce_byte_bound(
            "operations record",
            bytes.len(),
            MAX_OPERATIONS_RECORD_BYTES,
        )?;
        let path = self.operations_record_path(&record.record_digest);
        persist_immutable_named(&self.operations_root, &path, &bytes)?;
        let loaded = self.operations_record(&record.record_digest)?;
        if loaded != record {
            return Err(M3RuntimeError::CorruptState(
                "persisted operations record differs from the joined snapshot".to_string(),
            ));
        }
        Ok(record)
    }

    pub fn operations_record(
        &self,
        digest: &ContentDigest,
    ) -> Result<M3OperationsRecord, M3RuntimeError> {
        let path = self.operations_record_path(digest);
        let bytes = read_regular_file_bounded(&path, MAX_OPERATIONS_RECORD_BYTES)?;
        let record: M3OperationsRecord = serde_json::from_slice(&bytes)?;
        if record.schema != M3_OPERATIONS_RECORD_SCHEMA
            || &record.record_digest != digest
            || operations_record_digest(&record)? != *digest
        {
            return Err(M3RuntimeError::CorruptState(format!(
                "operations record {digest} failed integrity validation"
            )));
        }
        Ok(record)
    }

    /// Build, persist, and re-read one aggregate proof over exact durable M3
    /// constituents.
    pub fn publish_evidence_bundle(
        &self,
        request: M3EvidenceBundleRequest,
    ) -> Result<M3EvidenceBundle, M3RuntimeError> {
        let selection = normalize_evidence_selection(request)?;
        let mut invocations = Vec::with_capacity(selection.invocation_ids.len());
        for invocation_id in &selection.invocation_ids {
            let evidence = M3InvocationEvidence {
                receipt: self.host.receipt(invocation_id)?,
                attestation: self.host.attest(invocation_id)?,
            };
            validate_invocation_evidence(&evidence, &self.config.scope_id)?;
            invocations.push(evidence);
        }
        let family_index = derive_family_index(&invocations)?;

        let mut schedules = Vec::with_capacity(selection.schedule_ids.len());
        for schedule_id in &selection.schedule_ids {
            let binding = self.scheduling.load(schedule_id)?;
            let job = self.m2.job(&binding.registration.job_id)?.ok_or_else(|| {
                M3RuntimeError::InvalidEvidenceBundle(format!(
                    "schedule '{schedule_id}' has no durable M2 job"
                ))
            })?;
            let evidence = M3ScheduleEvidence { binding, job };
            validate_schedule_evidence(&evidence, &self.config.scope_id)?;
            schedules.push(evidence);
        }

        let mut operations = Vec::with_capacity(selection.operations_record_digests.len());
        for digest in &selection.operations_record_digests {
            operations.push(self.operations_record(digest)?);
        }
        validate_bundle_cohesion(&invocations, &schedules, &operations)?;

        let mut bundle = M3EvidenceBundle {
            schema: M3_EVIDENCE_BUNDLE_SCHEMA.to_string(),
            scope_id: self.config.scope_id.clone(),
            selection,
            invocations,
            schedules,
            operations,
            family_index,
            bundle_digest: ContentDigest::from_bytes(&[]),
        };
        bundle.bundle_digest = evidence_bundle_digest(&bundle)?;
        self.verify_evidence_bundle(&bundle)?;
        let bytes = serde_json::to_vec_pretty(&bundle)?;
        enforce_byte_bound("M3 evidence bundle", bytes.len(), MAX_EVIDENCE_BUNDLE_BYTES)?;
        let path = self.evidence_bundle_path(&bundle.bundle_digest);
        persist_immutable_named(&self.evidence_bundle_root, &path, &bytes)?;
        let reloaded = self.evidence_bundle(&bundle.bundle_digest)?;
        if reloaded != bundle {
            return Err(M3RuntimeError::CorruptState(
                "persisted M3 evidence bundle differs from its verified constituents".to_string(),
            ));
        }
        Ok(bundle)
    }

    /// Load a content-addressed bundle and independently re-resolve every
    /// constituent from its authoritative durable store.
    pub fn evidence_bundle(
        &self,
        digest: &ContentDigest,
    ) -> Result<M3EvidenceBundle, M3RuntimeError> {
        let path = self.evidence_bundle_path(digest);
        let bytes = read_regular_file_bounded(&path, MAX_EVIDENCE_BUNDLE_BYTES)?;
        let bundle: M3EvidenceBundle = serde_json::from_slice(&bytes)?;
        if bundle.schema != M3_EVIDENCE_BUNDLE_SCHEMA
            || &bundle.bundle_digest != digest
            || evidence_bundle_digest(&bundle)? != *digest
        {
            return Err(M3RuntimeError::CorruptState(format!(
                "M3 evidence bundle {digest} failed content-address validation"
            )));
        }
        self.verify_evidence_bundle(&bundle)?;
        Ok(bundle)
    }

    /// Verify both embedded cryptographic identities and equality with current
    /// immutable durable records.
    pub fn verify_evidence_bundle(&self, bundle: &M3EvidenceBundle) -> Result<(), M3RuntimeError> {
        if bundle.schema != M3_EVIDENCE_BUNDLE_SCHEMA
            || bundle.scope_id != self.config.scope_id
            || evidence_bundle_digest(bundle)? != bundle.bundle_digest
        {
            return Err(M3RuntimeError::InvalidEvidenceBundle(
                "bundle schema, scope, or content digest is invalid".to_string(),
            ));
        }
        let normalized = normalize_evidence_selection(bundle.selection.clone())?;
        if normalized != bundle.selection {
            return Err(M3RuntimeError::InvalidEvidenceBundle(
                "bundle selection is not in canonical identity order".to_string(),
            ));
        }
        let invocation_ids = bundle
            .invocations
            .iter()
            .map(|evidence| evidence.receipt.invocation_id().to_string())
            .collect::<Vec<_>>();
        if invocation_ids != bundle.selection.invocation_ids {
            return Err(M3RuntimeError::InvalidEvidenceBundle(
                "embedded invocation evidence does not match the exact selection".to_string(),
            ));
        }
        for evidence in &bundle.invocations {
            validate_invocation_evidence(evidence, &self.config.scope_id)?;
            let invocation_id = evidence.receipt.invocation_id();
            if self.host.receipt(invocation_id)? != evidence.receipt
                || self.host.attest(invocation_id)? != evidence.attestation
            {
                return Err(M3RuntimeError::CorruptState(format!(
                    "bundle invocation '{invocation_id}' differs from durable capability state"
                )));
            }
        }
        if derive_family_index(&bundle.invocations)? != bundle.family_index {
            return Err(M3RuntimeError::InvalidEvidenceBundle(
                "family index is not derived from the embedded successful receipts".to_string(),
            ));
        }

        let schedule_ids = bundle
            .schedules
            .iter()
            .map(|evidence| evidence.binding.registration.schedule_id.clone())
            .collect::<Vec<_>>();
        if schedule_ids != bundle.selection.schedule_ids {
            return Err(M3RuntimeError::InvalidEvidenceBundle(
                "embedded schedule evidence does not match the exact selection".to_string(),
            ));
        }
        for evidence in &bundle.schedules {
            validate_schedule_evidence(evidence, &self.config.scope_id)?;
            let schedule_id = &evidence.binding.registration.schedule_id;
            if self.scheduling.load(schedule_id)? != evidence.binding
                || self.m2.job(&evidence.binding.registration.job_id)?.as_ref()
                    != Some(&evidence.job)
            {
                return Err(M3RuntimeError::CorruptState(format!(
                    "bundle schedule '{schedule_id}' differs from durable M2 state"
                )));
            }
        }

        let operations_digests = bundle
            .operations
            .iter()
            .map(|record| record.record_digest.clone())
            .collect::<Vec<_>>();
        if operations_digests != bundle.selection.operations_record_digests {
            return Err(M3RuntimeError::InvalidEvidenceBundle(
                "embedded operations records do not match the exact selection".to_string(),
            ));
        }
        for record in &bundle.operations {
            if self.operations_record(&record.record_digest)? != *record {
                return Err(M3RuntimeError::CorruptState(format!(
                    "bundle operations record '{}' differs from durable state",
                    record.record_digest
                )));
            }
        }
        validate_bundle_cohesion(&bundle.invocations, &bundle.schedules, &bundle.operations)
    }

    pub fn stop(&self) -> Result<(), M3RuntimeError> {
        Ok(self.host.stop()?)
    }

    fn operations_record_path(&self, digest: &ContentDigest) -> PathBuf {
        self.operations_root
            .join(format!("{}.json", digest.file_stem()))
    }

    fn evidence_bundle_path(&self, digest: &ContentDigest) -> PathBuf {
        self.evidence_bundle_root
            .join(format!("{}.json", digest.file_stem()))
    }
}

impl Drop for M3CapabilityRuntime {
    fn drop(&mut self) {
        let _ = self.host.stop();
    }
}

struct M2SchedulingPort {
    scope_id: String,
    bindings_root: PathBuf,
    m2: Arc<M2Runtime>,
    mutation_gate: Mutex<()>,
}

impl M2SchedulingPort {
    fn register(
        &self,
        registration: M3ScheduleRegistration,
    ) -> Result<M3ScheduleBinding, M3RuntimeError> {
        let _gate = lock_unpoison(&self.mutation_gate);
        if registration.scope_id != self.scope_id {
            return Err(M3RuntimeError::InvalidSchedule(format!(
                "schedule scope '{}' does not match runtime scope '{}'",
                registration.scope_id, self.scope_id
            )));
        }
        validate_identifier("schedule_id", &registration.schedule_id)?;
        validate_identifier("job_id", &registration.job_id)?;
        if registration.idempotency_key.trim().is_empty()
            || registration.idempotency_key.len() > MAX_IDEMPOTENCY_KEY_BYTES
        {
            return Err(M3RuntimeError::InvalidSchedule(format!(
                "idempotency_key must contain 1..={MAX_IDEMPOTENCY_KEY_BYTES} bytes"
            )));
        }
        if registration.deadline_at_ms <= registration.due_at_ms {
            return Err(M3RuntimeError::InvalidSchedule(
                "deadline_at_ms must follow due_at_ms".to_string(),
            ));
        }
        registration
            .retry_policy
            .validate()
            .map_err(|error| M3RuntimeError::InvalidSchedule(error.to_string()))?;
        let payload_digest = lifecycle_payload_digest(&registration.lifecycle)?;
        let mut binding = M3ScheduleBinding {
            schema: M3_SCHEDULE_BINDING_SCHEMA.to_string(),
            registration,
            payload_digest,
            binding_digest: ContentDigest::from_bytes(&[]),
        };
        binding.binding_digest = schedule_binding_digest(&binding)?;
        let path = self.binding_path(&binding.registration.schedule_id);
        let bytes = serde_json::to_vec_pretty(&binding)?;
        enforce_byte_bound("schedule binding", bytes.len(), MAX_SCHEDULE_BINDING_BYTES)?;
        if path.exists() {
            let existing = self.load(&binding.registration.schedule_id)?;
            if existing == binding {
                return Ok(existing);
            }
            return Err(M3RuntimeError::ScheduleConflict {
                schedule_id: binding.registration.schedule_id,
            });
        }
        persist_immutable_named(&self.bindings_root, &path, &bytes)?;
        let loaded = self.load(&binding.registration.schedule_id)?;
        if loaded != binding {
            return Err(M3RuntimeError::CorruptState(
                "persisted schedule binding differs from registration".to_string(),
            ));
        }
        Ok(binding)
    }

    fn load(&self, schedule_id: &str) -> Result<M3ScheduleBinding, M3RuntimeError> {
        validate_identifier("schedule_id", schedule_id)?;
        let path = self.binding_path(schedule_id);
        if !path.exists() {
            return Err(M3RuntimeError::ScheduleNotFound {
                schedule_id: schedule_id.to_string(),
            });
        }
        let bytes = read_regular_file_bounded(&path, MAX_SCHEDULE_BINDING_BYTES)?;
        let binding: M3ScheduleBinding = serde_json::from_slice(&bytes)?;
        if binding.schema != M3_SCHEDULE_BINDING_SCHEMA
            || binding.registration.schedule_id != schedule_id
            || binding.registration.scope_id != self.scope_id
            || lifecycle_payload_digest(&binding.registration.lifecycle)? != binding.payload_digest
            || schedule_binding_digest(&binding)? != binding.binding_digest
        {
            return Err(M3RuntimeError::CorruptState(format!(
                "schedule binding '{schedule_id}' failed integrity validation"
            )));
        }
        Ok(binding)
    }

    fn binding_path(&self, schedule_id: &str) -> PathBuf {
        let identity = ContentDigest::from_bytes(schedule_id.as_bytes());
        self.bindings_root
            .join(format!("{}.json", identity.file_stem()))
    }
}

impl SchedulingPort for M2SchedulingPort {
    fn schedule(
        &self,
        request: &ScheduleJobRequest,
        control: &crate::capability_services::InvocationControl,
    ) -> Result<ScheduleReceipt, ServiceFailure> {
        control.check()?;
        if request.scope_id != self.scope_id {
            return Err(ServiceFailure {
                kind: ServiceFailureKind::ScopeDenied,
                code: "schedule_scope_mismatch".to_string(),
                message: format!(
                    "schedule scope '{}' does not match runtime scope '{}'",
                    request.scope_id, self.scope_id
                ),
                evidence: None,
            });
        }
        let binding = self
            .load(&request.schedule_id)
            .map_err(schedule_store_failure)?;
        if binding.registration.due_at_ms != request.due_at_ms
            || binding.payload_digest != request.payload_digest
        {
            return Err(ServiceFailure::failed(
                "schedule_binding_mismatch",
                "schedule request does not match its immutable lifecycle binding",
            ));
        }
        let outcome = self
            .m2
            .submit(M2SubmitJobRequest {
                job_id: binding.registration.job_id.clone(),
                idempotency_key: binding.registration.idempotency_key.clone(),
                not_before_ms: binding.registration.due_at_ms,
                deadline_at_ms: binding.registration.deadline_at_ms,
                retry_policy: binding.registration.retry_policy.clone(),
                lifecycle: binding.registration.lifecycle.clone(),
            })
            .map_err(m2_schedule_failure)?;
        if outcome.job.job_id != binding.registration.job_id
            || outcome.job.payload_digest != binding.payload_digest
            || outcome.job.not_before_ms != binding.registration.due_at_ms
            || outcome.job.deadline_at_ms != binding.registration.deadline_at_ms
        {
            return Err(ServiceFailure::failed(
                "m2_schedule_receipt_mismatch",
                "M2 returned a durable job that differs from the registered schedule",
            ));
        }
        let scheduler_receipt_digest = digest_json_content(&(
            "wasm-biotic:m3-m2-schedule-receipt:v1",
            request,
            &binding.binding_digest,
            outcome.created,
            &outcome.job.job_id,
            &outcome.job.request_fingerprint,
            &outcome.job.effect_receipt_id,
        ))
        .map_err(|error| {
            ServiceFailure::failed("schedule_receipt_digest_failed", error.to_string())
        })?;
        Ok(ScheduleReceipt {
            schedule_id: request.schedule_id.clone(),
            due_at_ms: request.due_at_ms,
            payload_digest: request.payload_digest.clone(),
            scheduler_receipt_digest,
        })
    }
}

fn service_catalog(
    scope_id: &str,
) -> Result<(Vec<CapabilityServiceDescriptor>, Vec<M3ServiceRegistration>), M3RuntimeError> {
    let specifications = [
        ServiceSpecification {
            service_id: BUILD_SERVICE_ID,
            family: NativeServiceFamily::Build,
            authority: AuthorityClass::LocalMutate,
            approval: ApprovalClass::AutoAllowed,
            operations: &[
                CapabilityOperation::WorkspaceOpen,
                CapabilityOperation::WorkspaceSnapshot,
                CapabilityOperation::WorkspacePatch,
                CapabilityOperation::CandidateBuild,
            ],
            idempotency: IdempotencyContract::SingleAttemptNoAutomaticRetry,
        },
        ServiceSpecification {
            service_id: VALIDATION_SERVICE_ID,
            family: NativeServiceFamily::Validation,
            authority: AuthorityClass::Observe,
            approval: ApprovalClass::AutoAllowed,
            operations: &[
                CapabilityOperation::ValidationProve,
                CapabilityOperation::ValidationCompare,
            ],
            idempotency: IdempotencyContract::IdempotentAtLeastOnce,
        },
        ServiceSpecification {
            service_id: REVIEW_SERVICE_ID,
            family: NativeServiceFamily::Review,
            authority: AuthorityClass::Observe,
            approval: ApprovalClass::AutoAllowed,
            operations: &[CapabilityOperation::ReviewCandidate],
            idempotency: IdempotencyContract::ReadOnlyReplayable,
        },
        ServiceSpecification {
            service_id: PACKAGING_SERVICE_ID,
            family: NativeServiceFamily::Packaging,
            authority: AuthorityClass::LocalMutate,
            approval: ApprovalClass::AutoAllowed,
            operations: &[
                CapabilityOperation::PackagePublish,
                CapabilityOperation::PackageVerify,
            ],
            idempotency: IdempotencyContract::IdempotentAtLeastOnce,
        },
        ServiceSpecification {
            service_id: CONTINUITY_SERVICE_ID,
            family: NativeServiceFamily::Continuity,
            authority: AuthorityClass::LocalMutate,
            approval: ApprovalClass::AutoAllowed,
            operations: &[CapabilityOperation::EvidencePublish],
            idempotency: IdempotencyContract::IdempotentAtLeastOnce,
        },
        ServiceSpecification {
            service_id: CONTINUITY_RESOLVE_SERVICE_ID,
            family: NativeServiceFamily::Continuity,
            authority: AuthorityClass::Observe,
            approval: ApprovalClass::AutoAllowed,
            operations: &[CapabilityOperation::EvidenceResolve],
            idempotency: IdempotencyContract::ReadOnlyReplayable,
        },
        ServiceSpecification {
            service_id: SCHEDULING_SERVICE_ID,
            family: NativeServiceFamily::Scheduling,
            authority: AuthorityClass::AutomationControl,
            approval: ApprovalClass::SupervisorAllowed,
            operations: &[CapabilityOperation::ScheduleJob],
            idempotency: IdempotencyContract::IdempotentAtLeastOnce,
        },
        ServiceSpecification {
            service_id: OPERATIONS_CONTROL_SERVICE_ID,
            family: NativeServiceFamily::Operations,
            authority: AuthorityClass::PromotionControl,
            approval: ApprovalClass::HumanRequired,
            operations: &[
                CapabilityOperation::DeploymentInitialize,
                CapabilityOperation::DeploymentActivate,
                CapabilityOperation::DeploymentObserve,
                CapabilityOperation::DeploymentRollback,
            ],
            idempotency: IdempotencyContract::IdempotentAtLeastOnce,
        },
        ServiceSpecification {
            service_id: OPERATIONS_INSPECT_SERVICE_ID,
            family: NativeServiceFamily::Operations,
            authority: AuthorityClass::Observe,
            approval: ApprovalClass::AutoAllowed,
            operations: &[CapabilityOperation::OperationsInspect],
            idempotency: IdempotencyContract::ReadOnlyReplayable,
        },
    ];
    let mut descriptors = Vec::with_capacity(specifications.len());
    let mut services = Vec::with_capacity(specifications.len());
    for specification in specifications {
        let descriptor = CapabilityServiceDescriptor::new(
            specification.service_id,
            specification.family,
            scope_id,
            specification.authority,
            specification.approval,
            specification.operations.iter().copied(),
            specification.idempotency,
            TimeoutBehavior::Cooperative,
            format!("m3-runtime:{}", specification.service_id),
        )?;
        services.push(M3ServiceRegistration {
            service_id: descriptor.service_id().to_string(),
            family: descriptor.family(),
            supported_operations: descriptor.supported_operations().clone(),
        });
        descriptors.push(descriptor);
    }
    Ok((descriptors, services))
}

fn factory_service_catalog(
    scope_id: &str,
) -> Result<(Vec<CapabilityServiceDescriptor>, Vec<M3ServiceRegistration>), M3RuntimeError> {
    let specifications = [
        ServiceSpecification {
            service_id: FACTORY_EXECUTION_SERVICE_ID,
            family: NativeServiceFamily::Validation,
            authority: AuthorityClass::Observe,
            approval: ApprovalClass::AutoAllowed,
            operations: &[
                CapabilityOperation::FactoryExecute,
                CapabilityOperation::FactoryProviderProposal,
                CapabilityOperation::FactoryShadow,
            ],
            idempotency: IdempotencyContract::IdempotentAtLeastOnce,
        },
        ServiceSpecification {
            service_id: FACTORY_PROMOTION_SERVICE_ID,
            family: NativeServiceFamily::Operations,
            authority: AuthorityClass::PromotionControl,
            approval: ApprovalClass::HumanRequired,
            operations: &[
                CapabilityOperation::FactoryInitialize,
                CapabilityOperation::FactoryStateMigrate,
                CapabilityOperation::FactoryActivate,
                CapabilityOperation::FactoryObserve,
                CapabilityOperation::FactoryRollback,
            ],
            idempotency: IdempotencyContract::IdempotentAtLeastOnce,
        },
        ServiceSpecification {
            service_id: FACTORY_INSPECT_SERVICE_ID,
            family: NativeServiceFamily::Operations,
            authority: AuthorityClass::Observe,
            approval: ApprovalClass::AutoAllowed,
            operations: &[CapabilityOperation::FactoryInspect],
            idempotency: IdempotencyContract::ReadOnlyReplayable,
        },
    ];
    let mut descriptors = Vec::with_capacity(specifications.len());
    let mut services = Vec::with_capacity(specifications.len());
    for specification in specifications {
        let descriptor = CapabilityServiceDescriptor::new(
            specification.service_id,
            specification.family,
            scope_id,
            specification.authority,
            specification.approval,
            specification.operations.iter().copied(),
            specification.idempotency,
            TimeoutBehavior::Cooperative,
            format!("m3-runtime:{}", specification.service_id),
        )?;
        services.push(M3ServiceRegistration {
            service_id: descriptor.service_id().to_string(),
            family: descriptor.family(),
            supported_operations: descriptor.supported_operations().clone(),
        });
        descriptors.push(descriptor);
    }
    Ok((descriptors, services))
}

struct ServiceSpecification {
    service_id: &'static str,
    family: NativeServiceFamily,
    authority: AuthorityClass,
    approval: ApprovalClass,
    operations: &'static [CapabilityOperation],
    idempotency: IdempotencyContract,
}

fn schedule_binding_digest(binding: &M3ScheduleBinding) -> Result<ContentDigest, M3RuntimeError> {
    digest_json_content(&(
        M3_SCHEDULE_BINDING_SCHEMA,
        &binding.registration,
        &binding.payload_digest,
    ))
    .map_err(|error| M3RuntimeError::Artifact(error.to_string()))
}

fn lifecycle_payload_digest(lifecycle: &M1LifecycleJob) -> Result<ContentDigest, M3RuntimeError> {
    // The supervisor canonicalizes JSON through `serde_json::Value` before
    // hashing. Mirror that contract so the capability request binds to the
    // exact digest that M2 will persist, including multi-field payloads.
    let value: Value = serde_json::to_value(lifecycle)?;
    let canonical = serde_json::to_string(&value)?;
    Ok(ContentDigest::from_bytes(canonical.as_bytes()))
}

fn operations_record_digest(record: &M3OperationsRecord) -> Result<ContentDigest, M3RuntimeError> {
    digest_json_content(&(
        M3_OPERATIONS_RECORD_SCHEMA,
        &record.inspection_invocation_id,
        &record.inspection_receipt_digest,
        &record.deployment,
        &record.supervisor,
        &record.jobs,
        &record.approvals,
    ))
    .map_err(|error| M3RuntimeError::Artifact(error.to_string()))
}

fn normalize_evidence_selection(
    mut request: M3EvidenceBundleRequest,
) -> Result<M3EvidenceBundleRequest, M3RuntimeError> {
    if request.invocation_ids.is_empty() {
        return Err(M3RuntimeError::InvalidEvidenceBundle(
            "an evidence bundle must select capability invocations".to_string(),
        ));
    }
    enforce_item_bound(
        "M3 evidence invocation selection",
        request.invocation_ids.len(),
        MAX_EVIDENCE_BUNDLE_INVOCATIONS,
    )?;
    if request.schedule_ids.is_empty() {
        return Err(M3RuntimeError::InvalidEvidenceBundle(
            "an evidence bundle must select at least one real schedule".to_string(),
        ));
    }
    enforce_item_bound(
        "M3 evidence schedule selection",
        request.schedule_ids.len(),
        MAX_EVIDENCE_BUNDLE_SCHEDULES,
    )?;
    if request.operations_record_digests.is_empty() {
        return Err(M3RuntimeError::InvalidEvidenceBundle(
            "an evidence bundle must select at least one operations record".to_string(),
        ));
    }
    enforce_item_bound(
        "M3 evidence operations selection",
        request.operations_record_digests.len(),
        MAX_EVIDENCE_BUNDLE_OPERATIONS_RECORDS,
    )?;
    reject_duplicate_strings("invocation id", &request.invocation_ids)?;
    reject_duplicate_strings("schedule id", &request.schedule_ids)?;
    let unique_operations = request
        .operations_record_digests
        .iter()
        .collect::<BTreeSet<_>>();
    if unique_operations.len() != request.operations_record_digests.len() {
        return Err(M3RuntimeError::InvalidEvidenceBundle(
            "operations record selection contains a duplicate digest".to_string(),
        ));
    }
    for invocation_id in &request.invocation_ids {
        validate_identifier("invocation_id", invocation_id)
            .map_err(|error| M3RuntimeError::InvalidEvidenceBundle(error.to_string()))?;
    }
    for schedule_id in &request.schedule_ids {
        validate_identifier("schedule_id", schedule_id)
            .map_err(|error| M3RuntimeError::InvalidEvidenceBundle(error.to_string()))?;
    }
    request.invocation_ids.sort();
    request.schedule_ids.sort();
    request.operations_record_digests.sort();
    Ok(request)
}

fn reject_duplicate_strings(
    identity: &'static str,
    values: &[String],
) -> Result<(), M3RuntimeError> {
    let unique = values.iter().collect::<BTreeSet<_>>();
    if unique.len() == values.len() {
        Ok(())
    } else {
        Err(M3RuntimeError::InvalidEvidenceBundle(format!(
            "evidence selection contains a duplicate {identity}"
        )))
    }
}

fn validate_invocation_evidence(
    evidence: &M3InvocationEvidence,
    scope_id: &str,
) -> Result<(), M3RuntimeError> {
    evidence.receipt.verify_integrity()?;
    if evidence.receipt.scope_id() != scope_id {
        return Err(M3RuntimeError::InvalidEvidenceBundle(format!(
            "invocation '{}' belongs to scope '{}', expected '{scope_id}'",
            evidence.receipt.invocation_id(),
            evidence.receipt.scope_id()
        )));
    }
    if !matches!(
        evidence.receipt.outcome(),
        InvocationOutcome::Succeeded { .. }
    ) {
        return Err(M3RuntimeError::InvalidEvidenceBundle(format!(
            "invocation '{}' did not terminate successfully",
            evidence.receipt.invocation_id()
        )));
    }
    let attestation = &evidence.attestation;
    let expected_attestation_id = format!(
        "attestation:{}",
        evidence.receipt.receipt_digest().file_stem()
    );
    if attestation.schema != CAPABILITY_ATTESTATION_SCHEMA
        || attestation.attestation_id != expected_attestation_id
        || attestation.invocation_id != evidence.receipt.invocation_id()
        || attestation.service_id != evidence.receipt.service_id()
        || attestation.family != evidence.receipt.family()
        || attestation.operation != evidence.receipt.operation()
        || attestation.scope_id != evidence.receipt.scope_id()
        || &attestation.input_digest != evidence.receipt.input_digest()
        || &attestation.output_digest != evidence.receipt.output_digest()
        || &attestation.receipt_digest != evidence.receipt.receipt_digest()
        || &attestation.provenance != evidence.receipt.provenance()
        || !attestation.terminal_success
        || attestation.failure_kind.is_some()
        || attestation_digest(attestation)? != attestation.attestation_digest
    {
        return Err(M3RuntimeError::InvalidEvidenceBundle(format!(
            "invocation '{}' receipt and attestation identities do not agree",
            evidence.receipt.invocation_id()
        )));
    }
    Ok(())
}

fn validate_schedule_evidence(
    evidence: &M3ScheduleEvidence,
    scope_id: &str,
) -> Result<(), M3RuntimeError> {
    let registration = &evidence.binding.registration;
    let job = &evidence.job;
    if evidence.binding.schema != M3_SCHEDULE_BINDING_SCHEMA
        || registration.scope_id != scope_id
        || schedule_binding_digest(&evidence.binding)? != evidence.binding.binding_digest
        || lifecycle_payload_digest(&registration.lifecycle)? != evidence.binding.payload_digest
        || job.job_id != registration.job_id
        || job.job_kind != registration.lifecycle.job_kind()
        || job.idempotency_key != registration.idempotency_key
        || job.payload_digest != evidence.binding.payload_digest
        || job.not_before_ms != registration.due_at_ms
        || job.deadline_at_ms != registration.deadline_at_ms
        || job.retry_policy != registration.retry_policy
        || job.approval_request_id.as_deref() != registration.lifecycle.approval_request_id()
    {
        return Err(M3RuntimeError::InvalidEvidenceBundle(format!(
            "schedule '{}' binding does not match its durable M2 job",
            registration.schedule_id
        )));
    }
    let decoded: M1LifecycleJob = serde_json::from_str(&job.payload_json)?;
    if decoded != registration.lifecycle {
        return Err(M3RuntimeError::InvalidEvidenceBundle(format!(
            "schedule '{}' job payload cannot reconstruct its lifecycle request",
            registration.schedule_id
        )));
    }
    if job.phase != JobPhase::Succeeded
        || !matches!(
            job.terminal_outcome.as_ref(),
            Some(JobTerminalOutcome::EffectCommitted { .. })
        )
        || job.attempts.is_empty()
    {
        return Err(M3RuntimeError::InvalidEvidenceBundle(format!(
            "schedule '{}' does not resolve to a successfully committed terminal M2 job",
            registration.schedule_id
        )));
    }
    Ok(())
}

fn derive_family_index(
    invocations: &[M3InvocationEvidence],
) -> Result<Vec<M3FamilyEvidenceIndex>, M3RuntimeError> {
    let mut by_family = BTreeMap::<NativeServiceFamily, Vec<ContentDigest>>::new();
    for evidence in invocations {
        validate_invocation_evidence(evidence, evidence.receipt.scope_id())?;
        by_family
            .entry(evidence.receipt.family())
            .or_default()
            .push(evidence.receipt.receipt_digest().clone());
    }
    let required = [
        NativeServiceFamily::Build,
        NativeServiceFamily::Validation,
        NativeServiceFamily::Review,
        NativeServiceFamily::Packaging,
        NativeServiceFamily::Continuity,
        NativeServiceFamily::Scheduling,
        NativeServiceFamily::Operations,
    ];
    let missing = required
        .iter()
        .copied()
        .filter(|family| !by_family.contains_key(family))
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(M3RuntimeError::InvalidEvidenceBundle(format!(
            "evidence bundle is missing successful family coverage: {missing:?}"
        )));
    }
    Ok(required
        .into_iter()
        .map(|family| {
            let mut receipt_digests = by_family.remove(&family).unwrap_or_default();
            receipt_digests.sort();
            M3FamilyEvidenceIndex {
                family,
                receipt_digests,
            }
        })
        .collect())
}

fn validate_bundle_cohesion(
    invocations: &[M3InvocationEvidence],
    schedules: &[M3ScheduleEvidence],
    operations: &[M3OperationsRecord],
) -> Result<(), M3RuntimeError> {
    if schedules.is_empty() || operations.is_empty() {
        return Err(M3RuntimeError::InvalidEvidenceBundle(
            "aggregate evidence requires real scheduling and operations constituents".to_string(),
        ));
    }
    let invocation_by_id = invocations
        .iter()
        .map(|evidence| (evidence.receipt.invocation_id(), evidence))
        .collect::<BTreeMap<_, _>>();

    for schedule in schedules {
        let registration = &schedule.binding.registration;
        let matched = invocations.iter().any(|evidence| {
            if evidence.receipt.family() != NativeServiceFamily::Scheduling {
                return false;
            }
            matches!(
                evidence.receipt.outcome(),
                InvocationOutcome::Succeeded {
                    result: CapabilitySuccess::Scheduled(receipt)
                } if receipt.schedule_id == registration.schedule_id
                    && receipt.due_at_ms == registration.due_at_ms
                    && receipt.payload_digest == schedule.binding.payload_digest
            )
        });
        if !matched {
            return Err(M3RuntimeError::InvalidEvidenceBundle(format!(
                "schedule '{}' has no matching successful Scheduling invocation",
                registration.schedule_id
            )));
        }
    }

    for record in operations {
        if operations_record_digest(record)? != record.record_digest {
            return Err(M3RuntimeError::InvalidEvidenceBundle(format!(
                "operations record '{}' failed its embedded digest",
                record.record_digest
            )));
        }
        let invocation = invocation_by_id
            .get(record.inspection_invocation_id.as_str())
            .ok_or_else(|| {
                M3RuntimeError::InvalidEvidenceBundle(format!(
                    "operations record '{}' has no selected inspection invocation",
                    record.record_digest
                ))
            })?;
        if invocation.receipt.family() != NativeServiceFamily::Operations
            || invocation.receipt.operation() != CapabilityOperation::OperationsInspect
            || invocation.receipt.receipt_digest() != &record.inspection_receipt_digest
            || !matches!(
                invocation.receipt.outcome(),
                InvocationOutcome::Succeeded {
                    result: CapabilitySuccess::Operations(snapshot)
                } if snapshot.as_ref() == &record.deployment
            )
        {
            return Err(M3RuntimeError::InvalidEvidenceBundle(format!(
                "operations record '{}' is not bound to its successful inspection receipt",
                record.record_digest
            )));
        }
        reject_duplicate_job_views(&record.jobs)?;
        validate_operations_approvals(record)?;
    }

    for schedule in schedules {
        let expected = M3JobOperationsView::from(&schedule.job);
        if !operations
            .iter()
            .any(|record| record.jobs.iter().any(|job| job == &expected))
        {
            return Err(M3RuntimeError::InvalidEvidenceBundle(format!(
                "terminal schedule job '{}' is absent from the selected operations records",
                schedule.job.job_id
            )));
        }
    }
    Ok(())
}

fn reject_duplicate_job_views(jobs: &[M3JobOperationsView]) -> Result<(), M3RuntimeError> {
    let unique = jobs
        .iter()
        .map(|job| job.job_id.as_str())
        .collect::<BTreeSet<_>>();
    if unique.len() == jobs.len() {
        Ok(())
    } else {
        Err(M3RuntimeError::InvalidEvidenceBundle(
            "operations record contains duplicate job identities".to_string(),
        ))
    }
}

fn validate_operations_approvals(record: &M3OperationsRecord) -> Result<(), M3RuntimeError> {
    let unique = record
        .approvals
        .iter()
        .map(|approval| approval.job_id.as_str())
        .collect::<BTreeSet<_>>();
    if unique.len() != record.approvals.len() {
        return Err(M3RuntimeError::InvalidEvidenceBundle(
            "operations record contains duplicate approval job identities".to_string(),
        ));
    }
    for approval in &record.approvals {
        if !record.jobs.iter().any(|job| {
            job.job_id == approval.job_id
                && job.approval_request_id.as_deref() == Some(approval.approval_request_id.as_str())
                && job.phase == approval.phase
        }) {
            return Err(M3RuntimeError::InvalidEvidenceBundle(format!(
                "approval '{}' is not an exact projection of its operations job",
                approval.approval_request_id
            )));
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct M3AttestationDigestMaterial<'a> {
    schema: &'a str,
    attestation_id: &'a str,
    invocation_id: &'a str,
    service_id: &'a str,
    family: NativeServiceFamily,
    operation: CapabilityOperation,
    scope_id: &'a str,
    implementation_digest: &'a ContentDigest,
    input_digest: &'a ContentDigest,
    output_digest: &'a ContentDigest,
    receipt_digest: &'a ContentDigest,
    terminal_success: bool,
    failure_kind: Option<ServiceFailureKind>,
    provenance: &'a InvocationProvenance,
}

fn attestation_digest(
    attestation: &ServiceInvocationAttestation,
) -> Result<ContentDigest, M3RuntimeError> {
    digest_json_content(&M3AttestationDigestMaterial {
        schema: &attestation.schema,
        attestation_id: &attestation.attestation_id,
        invocation_id: &attestation.invocation_id,
        service_id: &attestation.service_id,
        family: attestation.family,
        operation: attestation.operation,
        scope_id: &attestation.scope_id,
        implementation_digest: &attestation.implementation_digest,
        input_digest: &attestation.input_digest,
        output_digest: &attestation.output_digest,
        receipt_digest: &attestation.receipt_digest,
        terminal_success: attestation.terminal_success,
        failure_kind: attestation.failure_kind,
        provenance: &attestation.provenance,
    })
    .map_err(|error| M3RuntimeError::Artifact(error.to_string()))
}

fn evidence_bundle_digest(bundle: &M3EvidenceBundle) -> Result<ContentDigest, M3RuntimeError> {
    digest_json_content(&(
        M3_EVIDENCE_BUNDLE_SCHEMA,
        &bundle.scope_id,
        &bundle.selection,
        &bundle.invocations,
        &bundle.schedules,
        &bundle.operations,
        &bundle.family_index,
    ))
    .map_err(|error| M3RuntimeError::Artifact(error.to_string()))
}

fn schedule_store_failure(error: M3RuntimeError) -> ServiceFailure {
    match error {
        M3RuntimeError::ScheduleNotFound { .. } => ServiceFailure::failed(
            "schedule_not_registered",
            "schedule id has no durable lifecycle binding",
        ),
        M3RuntimeError::CorruptState(message) => {
            ServiceFailure::unavailable("schedule_store_corrupt", message)
        }
        other => ServiceFailure::failed("schedule_store_failed", other.to_string()),
    }
}

fn m2_schedule_failure(error: M2RuntimeError) -> ServiceFailure {
    match error {
        M2RuntimeError::Supervisor(
            SupervisorError::JobConflict { .. }
            | SupervisorError::IdempotencyConflict { .. }
            | SupervisorError::InvalidIdentifier { .. }
            | SupervisorError::InvalidDeadline { .. }
            | SupervisorError::InvalidRetryPolicy(_),
        ) => ServiceFailure::failed("m2_schedule_conflict", error.to_string()),
        M2RuntimeError::Serialization(_) => {
            ServiceFailure::failed("m2_schedule_serialization_failed", error.to_string())
        }
        other => ServiceFailure::unavailable("m2_scheduler_unavailable", other.to_string()),
    }
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), M3RuntimeError> {
    let path = Path::new(value);
    let valid = !value.trim().is_empty()
        && value.len() <= 256
        && !path.is_absolute()
        && !value.contains('/')
        && !value.contains('\\')
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)));
    if valid {
        Ok(())
    } else {
        Err(M3RuntimeError::InvalidConfig(format!(
            "{field} is not a safe bounded identifier: {value:?}"
        )))
    }
}

fn secure_create_root(path: &Path) -> Result<PathBuf, M3RuntimeError> {
    reject_symlink_if_present(path)?;
    fs::create_dir_all(path).map_err(|source| M3RuntimeError::io(path, source))?;
    let metadata = fs::symlink_metadata(path).map_err(|source| M3RuntimeError::io(path, source))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(M3RuntimeError::UnsafePath {
            path: path.to_path_buf(),
            reason: "runtime root must be a real directory",
        });
    }
    fs::canonicalize(path).map_err(|source| M3RuntimeError::io(path, source))
}

fn acquire_owner_lock(root: &Path) -> Result<File, M3RuntimeError> {
    let path = root.join(RUNTIME_OWNER_LOCK_FILE);
    reject_symlink_if_present(&path)?;
    if path.exists() {
        let metadata =
            fs::symlink_metadata(&path).map_err(|source| M3RuntimeError::io(&path, source))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(M3RuntimeError::UnsafePath {
                path,
                reason: "runtime owner lock must be a regular file",
            });
        }
    }
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|source| M3RuntimeError::io(&path, source))?;
    file.try_lock().map_err(|source| match source {
        std::fs::TryLockError::WouldBlock => M3RuntimeError::Conflict(format!(
            "M3 runtime root '{}' already has a live owner",
            root.display()
        )),
        std::fs::TryLockError::Error(source) => M3RuntimeError::io(&path, source),
    })?;
    Ok(file)
}

fn secure_child_directory(root: &Path, name: &str) -> Result<PathBuf, M3RuntimeError> {
    let path = root.join(name);
    reject_symlink_if_present(&path)?;
    fs::create_dir_all(&path).map_err(|source| M3RuntimeError::io(&path, source))?;
    let canonical = fs::canonicalize(&path).map_err(|source| M3RuntimeError::io(&path, source))?;
    if canonical.parent() != Some(root) {
        return Err(M3RuntimeError::UnsafePath {
            path,
            reason: "service directory escaped the runtime root",
        });
    }
    Ok(canonical)
}

fn reject_symlink_if_present(path: &Path) -> Result<(), M3RuntimeError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(M3RuntimeError::UnsafePath {
            path: path.to_path_buf(),
            reason: "symbolic links are not accepted",
        }),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(M3RuntimeError::io(path, source)),
    }
}

fn read_regular_file_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, M3RuntimeError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| M3RuntimeError::io(path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(M3RuntimeError::UnsafePath {
            path: path.to_path_buf(),
            reason: "expected a regular non-symlink file",
        });
    }
    let byte_len = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
    enforce_byte_bound("durable M3 file", byte_len, limit)?;
    let mut bytes = Vec::with_capacity(byte_len);
    File::open(path)
        .map_err(|source| M3RuntimeError::io(path, source))?
        .read_to_end(&mut bytes)
        .map_err(|source| M3RuntimeError::io(path, source))?;
    Ok(bytes)
}

fn enforce_byte_bound(
    resource: &'static str,
    actual: usize,
    limit: usize,
) -> Result<(), M3RuntimeError> {
    if actual > limit {
        Err(M3RuntimeError::ResourceBoundExceeded {
            resource,
            actual,
            limit,
        })
    } else {
        Ok(())
    }
}

fn enforce_item_bound(
    resource: &'static str,
    actual: usize,
    limit: usize,
) -> Result<(), M3RuntimeError> {
    if actual > limit {
        Err(M3RuntimeError::ResourceBoundExceeded {
            resource,
            actual,
            limit,
        })
    } else {
        Ok(())
    }
}

/// Publish immutable bytes without ever replacing an existing name.
///
/// A same-filesystem hard link makes publication atomic and no-clobber. The
/// temporary inode is removed after publication or comparison.
fn persist_immutable_named(
    directory: &Path,
    destination: &Path,
    bytes: &[u8],
) -> Result<(), M3RuntimeError> {
    reject_symlink_if_present(destination)?;
    if destination.exists() {
        let existing = read_regular_file_bounded(destination, bytes.len())?;
        return if existing == bytes {
            Ok(())
        } else {
            Err(M3RuntimeError::ImmutableConflict {
                path: destination.to_path_buf(),
            })
        };
    }
    let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = directory.join(format!(".m3-write-{}-{sequence}", std::process::id()));
    let write_result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|source| M3RuntimeError::io(&temporary, source))?;
        file.write_all(bytes)
            .map_err(|source| M3RuntimeError::io(&temporary, source))?;
        file.sync_all()
            .map_err(|source| M3RuntimeError::io(&temporary, source))?;
        match fs::hard_link(&temporary, destination) {
            Ok(()) => Ok(()),
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = read_regular_file_bounded(destination, bytes.len())?;
                if existing == bytes {
                    Ok(())
                } else {
                    Err(M3RuntimeError::ImmutableConflict {
                        path: destination.to_path_buf(),
                    })
                }
            }
            Err(source) => Err(M3RuntimeError::io(destination, source)),
        }
    })();
    let _ = fs::remove_file(&temporary);
    write_result
}

fn lock_unpoison<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[derive(Debug)]
pub enum M3RuntimeError {
    InvalidConfig(String),
    Conflict(String),
    InvalidSchedule(String),
    InvalidOperationsInspection(String),
    InvalidEvidenceBundle(String),
    TerminalCapability(ServiceFailure),
    Capability(CapabilityHostError),
    M2(M2RuntimeError),
    Candidate(crate::candidate::CandidateWorkspaceError),
    Deployment(crate::deployment::DeploymentError),
    Serialization(serde_json::Error),
    Artifact(String),
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    UnsafePath {
        path: PathBuf,
        reason: &'static str,
    },
    ImmutableConflict {
        path: PathBuf,
    },
    ScheduleNotFound {
        schedule_id: String,
    },
    ScheduleConflict {
        schedule_id: String,
    },
    CorruptState(String),
    ResourceBoundExceeded {
        resource: &'static str,
        actual: usize,
        limit: usize,
    },
}

impl M3RuntimeError {
    fn io(path: &Path, source: std::io::Error) -> Self {
        Self::Io {
            path: path.to_path_buf(),
            source,
        }
    }
}

impl From<CapabilityHostError> for M3RuntimeError {
    fn from(value: CapabilityHostError) -> Self {
        Self::Capability(value)
    }
}

impl From<M2RuntimeError> for M3RuntimeError {
    fn from(value: M2RuntimeError) -> Self {
        Self::M2(value)
    }
}

impl From<crate::candidate::CandidateWorkspaceError> for M3RuntimeError {
    fn from(value: crate::candidate::CandidateWorkspaceError) -> Self {
        Self::Candidate(value)
    }
}

impl From<crate::deployment::DeploymentError> for M3RuntimeError {
    fn from(value: crate::deployment::DeploymentError) -> Self {
        Self::Deployment(value)
    }
}

impl From<serde_json::Error> for M3RuntimeError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialization(value)
    }
}

impl Display for M3RuntimeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(reason) => write!(formatter, "invalid M3 runtime config: {reason}"),
            Self::Conflict(reason) => write!(formatter, "M3 conflict: {reason}"),
            Self::InvalidSchedule(reason) => write!(formatter, "invalid M3 schedule: {reason}"),
            Self::InvalidOperationsInspection(reason) => {
                write!(formatter, "invalid M3 operations inspection: {reason}")
            }
            Self::InvalidEvidenceBundle(reason) => {
                write!(formatter, "invalid M3 evidence bundle: {reason}")
            }
            Self::TerminalCapability(failure) => {
                write!(formatter, "capability invocation was terminal: {failure}")
            }
            Self::Capability(error) => write!(formatter, "M3 capability host failed: {error}"),
            Self::M2(error) => write!(formatter, "M3 scheduling supervisor failed: {error}"),
            Self::Candidate(error) => write!(formatter, "M3 candidate service failed: {error}"),
            Self::Deployment(error) => write!(formatter, "M3 deployment service failed: {error}"),
            Self::Serialization(error) => write!(formatter, "M3 JSON encoding failed: {error}"),
            Self::Artifact(error) => write!(formatter, "M3 digest derivation failed: {error}"),
            Self::Io { path, source } => {
                write!(formatter, "M3 I/O at {} failed: {source}", path.display())
            }
            Self::UnsafePath { path, reason } => {
                write!(formatter, "unsafe M3 path {}: {reason}", path.display())
            }
            Self::ImmutableConflict { path } => {
                write!(
                    formatter,
                    "immutable M3 record conflicts at {}",
                    path.display()
                )
            }
            Self::ScheduleNotFound { schedule_id } => {
                write!(formatter, "M3 schedule is not registered: {schedule_id}")
            }
            Self::ScheduleConflict { schedule_id } => {
                write!(formatter, "M3 schedule identity conflicts: {schedule_id}")
            }
            Self::CorruptState(reason) => write!(formatter, "M3 state is corrupt: {reason}"),
            Self::ResourceBoundExceeded {
                resource,
                actual,
                limit,
            } => write!(
                formatter,
                "M3 {resource} uses {actual} items or bytes; limit is {limit}"
            ),
        }
    }
}

impl Error for M3RuntimeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Capability(error) => Some(error),
            Self::M2(error) => Some(error),
            Self::Candidate(error) => Some(error),
            Self::Deployment(error) => Some(error),
            Self::Serialization(error) => Some(error),
            Self::Io { source, .. } => Some(source),
            Self::InvalidConfig(_)
            | Self::Conflict(_)
            | Self::InvalidSchedule(_)
            | Self::InvalidOperationsInspection(_)
            | Self::InvalidEvidenceBundle(_)
            | Self::TerminalCapability(_)
            | Self::Artifact(_)
            | Self::UnsafePath { .. }
            | Self::ImmutableConflict { .. }
            | Self::ScheduleNotFound { .. }
            | Self::ScheduleConflict { .. }
            | Self::CorruptState(_)
            | Self::ResourceBoundExceeded { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability_services::{
        ActivateDeploymentRequest, BuildCandidateRequest, CompareProvingRequest,
        FactoryEffectRequest, FactoryEffectResult, InitializeDeploymentRequest,
        InspectOperationsRequest, InvocationApproval, InvocationBudget, InvocationControl,
        InvocationIdentity, ObserveDeploymentRequest, OpenWorkspaceRequest, PatchWorkspaceRequest,
        ProvePackageRequest, PublishEvidenceRequest, PublishPackageRequest, ResolveEvidenceRequest,
        ReviewCandidateRequest, RollbackDeploymentRequest, ScopedDeploymentRef, ScopedWorkspaceRef,
        ServiceAvailability,
    };
    use crate::deployment::ObservationOutcome;
    use crate::execution::component::ComponentExecutionLimits;
    use crate::m1_validation::{ValidationCase, ValidationSuite};
    use crate::m2_runtime::{ActivatePayload, M2RuntimeConfig, OpenWorkspacePayload};
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::atomic::AtomicU64;
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);
    const SCOPE: &str = "scope-a";
    const DEPLOYMENT: &str = "reference-task";

    struct TestDirectory {
        root: PathBuf,
    }

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "wasm-biotic-m3-{label}-{}-{sequence}",
                std::process::id()
            ));
            if root.exists() {
                fs::remove_dir_all(&root).expect("remove stale M3 test root");
            }
            fs::create_dir(&root).expect("create M3 test root");
            Self { root }
        }

        fn copy_template(&self, name: &str) -> PathBuf {
            let destination = self.root.join(name);
            fs::create_dir(&destination).expect("create isolated template");
            let fixture = fixture_root().join("template");
            for file in ["component.wit", "component.wat"] {
                fs::copy(fixture.join(file), destination.join(file)).expect("copy frozen template");
            }
            destination
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[derive(Default)]
    struct FixtureFactoryEvolutionPort {
        calls: Mutex<Vec<(CapabilityOperation, FactoryEffectRequest)>>,
    }

    impl FactoryEvolutionPort for FixtureFactoryEvolutionPort {
        fn apply_factory_effect(
            &self,
            operation: CapabilityOperation,
            request: &FactoryEffectRequest,
            _control: &InvocationControl,
        ) -> Result<FactoryEffectResult, ServiceFailure> {
            self.calls
                .lock()
                .expect("lock fixture factory calls")
                .push((operation, request.clone()));
            let mut response = format!("{operation:?}:").into_bytes();
            response.extend_from_slice(&request.exact_request_bytes);
            Ok(FactoryEffectResult::new(request, response))
        }
    }

    struct Harness {
        m3_config: M3RuntimeConfig,
        m2_config: M2RuntimeConfig,
        m2: Arc<M2Runtime>,
        runtime: M3CapabilityRuntime,
    }

    fn harness(test: &TestDirectory, label: &str) -> Harness {
        let template = test.copy_template(&format!("{label}-template"));
        let m2_config = M2RuntimeConfig {
            supervisor_root: test.root.join(format!("{label}-supervisor")),
            lifecycle_root: test.root.join(format!("{label}-lifecycle")),
            template_root: template.clone(),
            owner_id: format!("m3-test-{label}"),
            max_idle_wait_ms: 10,
        };
        let m3_config = M3RuntimeConfig::new(
            test.root.join(format!("{label}-m3")),
            template,
            SCOPE,
            DEPLOYMENT,
        );
        let m2 = Arc::new(M2Runtime::new(m2_config.clone()).expect("construct M2"));
        let runtime =
            M3CapabilityRuntime::open(m3_config.clone(), Arc::clone(&m2)).expect("open M3");
        Harness {
            m3_config,
            m2_config,
            m2,
            runtime,
        }
    }

    fn workspace(workspace_id: &str) -> ScopedWorkspaceRef {
        ScopedWorkspaceRef {
            scope_id: SCOPE.to_string(),
            workspace_id: workspace_id.to_string(),
        }
    }

    fn deployment() -> ScopedDeploymentRef {
        ScopedDeploymentRef {
            scope_id: SCOPE.to_string(),
            deployment_id: DEPLOYMENT.to_string(),
        }
    }

    fn invocation(
        service_id: &str,
        invocation_id: &str,
        authority: AuthorityClass,
        approval: InvocationApproval,
        request: CapabilityRequest,
    ) -> CapabilityInvocation {
        CapabilityInvocation {
            identity: InvocationIdentity {
                invocation_id: invocation_id.to_string(),
                idempotency_key: format!("idempotency:{invocation_id}"),
                service_id: service_id.to_string(),
                scope_id: SCOPE.to_string(),
                caller_id: "m3-test-worker".to_string(),
                authority,
                approval,
            },
            budget: InvocationBudget::bounded(30_000),
            request,
        }
    }

    fn automatic(
        service_id: &str,
        invocation_id: &str,
        authority: AuthorityClass,
        request: CapabilityRequest,
    ) -> CapabilityInvocation {
        invocation(
            service_id,
            invocation_id,
            authority,
            InvocationApproval::Automatic,
            request,
        )
    }

    fn approved(
        service_id: &str,
        invocation_id: &str,
        authority: AuthorityClass,
        class: ApprovalClass,
        request: CapabilityRequest,
    ) -> CapabilityInvocation {
        invocation(
            service_id,
            invocation_id,
            authority,
            InvocationApproval::Granted {
                approval_ref: format!("approval:{invocation_id}"),
                class,
            },
            request,
        )
    }

    fn successful_result(receipt: InvocationReceipt) -> CapabilitySuccess {
        match receipt.outcome().clone() {
            InvocationOutcome::Succeeded { result } => result,
            InvocationOutcome::Terminal { failure } => {
                panic!("expected successful capability receipt, got {failure}")
            }
        }
    }

    fn invoke_success(
        runtime: &M3CapabilityRuntime,
        invocation: &CapabilityInvocation,
    ) -> CapabilitySuccess {
        successful_result(
            runtime
                .invoke(invocation, CancellationToken::new())
                .expect("invoke capability"),
        )
    }

    fn snapshot_regular_files(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        fn visit(root: &Path, directory: &Path, snapshot: &mut BTreeMap<PathBuf, Vec<u8>>) {
            let mut entries = fs::read_dir(directory)
                .expect("list M3 snapshot directory")
                .map(|entry| entry.expect("read M3 snapshot entry").path())
                .collect::<Vec<_>>();
            entries.sort();
            for path in entries {
                let metadata = fs::symlink_metadata(&path).expect("inspect M3 snapshot entry");
                if metadata.is_dir() {
                    visit(root, &path, snapshot);
                } else if metadata.is_file() {
                    snapshot.insert(
                        path.strip_prefix(root)
                            .expect("snapshot path is beneath M3 root")
                            .to_path_buf(),
                        fs::read(&path).expect("read M3 snapshot file"),
                    );
                }
            }
        }

        let mut snapshot = BTreeMap::new();
        visit(root, root, &mut snapshot);
        snapshot
    }

    fn suite() -> ValidationSuite {
        ValidationSuite::new(
            "m3-live-reference-transform-v1",
            "transform",
            [(-1, 0), (0, 1), (41, 42)]
                .into_iter()
                .enumerate()
                .map(|(index, (input, output))| {
                    ValidationCase::returns(format!("case-{}", index + 1), input, output)
                })
                .collect(),
            ComponentExecutionLimits {
                fuel: 1_000_000,
                ..ComponentExecutionLimits::default()
            },
        )
        .expect("valid M3 proving suite")
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX)
    }

    fn wait_for_phase(
        runtime: &M3CapabilityRuntime,
        schedule_id: &str,
        expected: JobPhase,
    ) -> DurableJob {
        for _ in 0..500 {
            let job = runtime
                .scheduled_job(schedule_id)
                .expect("observe scheduled job")
                .expect("durable job exists");
            if job.phase == expected {
                return job;
            }
            assert!(
                !job.phase.is_terminal() || job.phase == expected,
                "job reached unexpected terminal phase {:?}",
                job.phase
            );
            thread::sleep(Duration::from_millis(10));
        }
        panic!("job did not reach {expected:?} within the bounded wait")
    }

    #[test]
    fn runtime_exposes_exact_terminal_invocation_input_after_restart() {
        let test = TestDirectory::new("invocation-input-restart");
        let Harness {
            m3_config,
            m2_config,
            m2,
            runtime,
        } = harness(&test, "invocation-input");
        let invocation = automatic(
            BUILD_SERVICE_ID,
            "recover-runtime-input",
            AuthorityClass::LocalMutate,
            CapabilityRequest::OpenWorkspace(OpenWorkspaceRequest {
                workspace: workspace("recover-runtime-workspace"),
            }),
        );
        let receipt = runtime
            .invoke(&invocation, CancellationToken::new())
            .expect("persist terminal capability invocation");
        assert!(receipt.started_at_ms() <= receipt.finished_at_ms());
        assert_eq!(
            runtime
                .invocation_input("recover-runtime-input")
                .expect("load invocation through M3"),
            invocation
        );

        m2.stop().expect("stop first M2 owner");
        drop(runtime);
        drop(m2);

        let restarted_m2 =
            Arc::new(M2Runtime::new(m2_config).expect("construct restarted M2 owner"));
        let restarted =
            M3CapabilityRuntime::open(m3_config, Arc::clone(&restarted_m2)).expect("restart M3");
        assert_eq!(
            restarted
                .invocation_input("recover-runtime-input")
                .expect("load invocation through restarted M3"),
            invocation
        );
        restarted_m2.stop().expect("stop restarted M2 owner");
    }

    #[test]
    fn sole_writer_lock_preserves_state_and_allows_final_owner_handoff() {
        let test = TestDirectory::new("sole-writer-handoff");
        let Harness {
            m3_config,
            m2,
            runtime,
            ..
        } = harness(&test, "sole-writer");
        let runtime = Arc::new(runtime);
        let invocation = automatic(
            BUILD_SERVICE_ID,
            "sole-writer-evidence",
            AuthorityClass::LocalMutate,
            CapabilityRequest::OpenWorkspace(OpenWorkspaceRequest {
                workspace: workspace("sole-writer-workspace"),
            }),
        );
        let expected_receipt = runtime
            .invoke(&invocation, CancellationToken::new())
            .expect("persist evidence before duplicate-owner attempt");
        let state_before_duplicate = snapshot_regular_files(runtime.root());

        let duplicate_result = M3CapabilityRuntime::open(m3_config.clone(), Arc::clone(&m2));
        assert!(matches!(
            duplicate_result,
            Err(M3RuntimeError::Conflict(reason))
                if reason.contains("already has a live owner")
        ));
        assert_eq!(
            snapshot_regular_files(runtime.root()),
            state_before_duplicate,
            "a rejected duplicate owner must not alter any durable M3 bytes"
        );
        assert_eq!(
            runtime
                .receipt("sole-writer-evidence")
                .expect("original owner still resolves prior evidence"),
            expected_receipt
        );

        let retained_owner = Arc::clone(&runtime);
        drop(runtime);
        assert!(matches!(
            M3CapabilityRuntime::open(m3_config.clone(), Arc::clone(&m2)),
            Err(M3RuntimeError::Conflict(_))
        ));
        assert_eq!(
            snapshot_regular_files(retained_owner.root()),
            state_before_duplicate,
            "dropping one runtime clone must neither release ownership nor alter state"
        );
        drop(retained_owner);
        let handed_off = M3CapabilityRuntime::open(m3_config, Arc::clone(&m2))
            .expect("final owner drop releases the M3 root");
        assert_eq!(
            handed_off
                .receipt("sole-writer-evidence")
                .expect("new owner resolves prior evidence"),
            expected_receipt
        );
        assert_eq!(
            handed_off
                .invocation_input("sole-writer-evidence")
                .expect("new owner resolves exact prior input"),
            invocation
        );
        drop(handed_off);
        m2.stop().expect("stop unused M2 owner");
    }

    #[test]
    fn opt_in_factory_boundary_is_exact_approved_idempotent_and_reloadable() {
        let test = TestDirectory::new("factory-extension");
        let template = test.copy_template("factory-extension-template");
        let m2 = Arc::new(
            M2Runtime::new(M2RuntimeConfig {
                supervisor_root: test.root.join("factory-extension-supervisor"),
                lifecycle_root: test.root.join("factory-extension-lifecycle"),
                template_root: template.clone(),
                owner_id: "m3-test-factory-extension".to_string(),
                max_idle_wait_ms: 10,
            })
            .expect("construct factory-extension M2"),
        );

        let (_, ordinary_catalog) = service_catalog(SCOPE).expect("derive ordinary M3 catalog");
        let ordinary = M3CapabilityRuntime::open(
            M3RuntimeConfig::new(
                test.root.join("ordinary-m3"),
                template.clone(),
                SCOPE,
                DEPLOYMENT,
            ),
            Arc::clone(&m2),
        )
        .expect("open ordinary M3 runtime");
        assert_eq!(ordinary.services(), ordinary_catalog.as_slice());
        assert_eq!(
            serde_json::to_vec(ordinary.services()).expect("encode ordinary runtime catalog"),
            serde_json::to_vec(&ordinary_catalog).expect("encode canonical ordinary catalog")
        );
        assert_eq!(
            ordinary
                .services()
                .iter()
                .map(|service| service.service_id.as_str())
                .collect::<Vec<_>>(),
            vec![
                BUILD_SERVICE_ID,
                VALIDATION_SERVICE_ID,
                REVIEW_SERVICE_ID,
                PACKAGING_SERVICE_ID,
                CONTINUITY_SERVICE_ID,
                CONTINUITY_RESOLVE_SERVICE_ID,
                SCHEDULING_SERVICE_ID,
                OPERATIONS_CONTROL_SERVICE_ID,
                OPERATIONS_INSPECT_SERVICE_ID,
            ]
        );
        drop(ordinary);

        let backend = Arc::new(FixtureFactoryEvolutionPort::default());
        let factory_port: Arc<dyn FactoryEvolutionPort> = backend.clone();
        let config =
            M3RuntimeConfig::new(test.root.join("factory-m3"), template, SCOPE, DEPLOYMENT);
        let runtime = M3CapabilityRuntime::open_with_factory_evolution(
            config.clone(),
            Arc::clone(&m2),
            factory_port,
        )
        .expect("open M3 with factory extension");
        assert_eq!(runtime.services().len(), ordinary_catalog.len() + 3);
        let execution = runtime
            .services()
            .iter()
            .find(|service| service.service_id == FACTORY_EXECUTION_SERVICE_ID)
            .expect("factory execution registration");
        assert_eq!(execution.family, NativeServiceFamily::Validation);
        assert_eq!(
            execution.supported_operations,
            BTreeSet::from([
                CapabilityOperation::FactoryExecute,
                CapabilityOperation::FactoryProviderProposal,
                CapabilityOperation::FactoryShadow,
            ])
        );
        let promotion = runtime
            .services()
            .iter()
            .find(|service| service.service_id == FACTORY_PROMOTION_SERVICE_ID)
            .expect("factory promotion registration");
        assert_eq!(promotion.family, NativeServiceFamily::Operations);
        assert_eq!(
            promotion.supported_operations,
            BTreeSet::from([
                CapabilityOperation::FactoryInitialize,
                CapabilityOperation::FactoryStateMigrate,
                CapabilityOperation::FactoryActivate,
                CapabilityOperation::FactoryObserve,
                CapabilityOperation::FactoryRollback,
            ])
        );
        let inspect = runtime
            .services()
            .iter()
            .find(|service| service.service_id == FACTORY_INSPECT_SERVICE_ID)
            .expect("factory inspect registration");
        assert_eq!(inspect.family, NativeServiceFamily::Operations);
        assert_eq!(
            inspect.supported_operations,
            BTreeSet::from([CapabilityOperation::FactoryInspect])
        );

        let exact_request_bytes = b"\0shadow-request\n\xff".to_vec();
        let effect_request = FactoryEffectRequest::new(
            SCOPE,
            "factory-a",
            "logical-effect:shadow:1",
            exact_request_bytes.clone(),
        );
        let shadow = automatic(
            FACTORY_EXECUTION_SERVICE_ID,
            "factory-shadow-1",
            AuthorityClass::Observe,
            CapabilityRequest::FactoryShadow(effect_request.clone()),
        );
        let first = runtime
            .invoke(&shadow, CancellationToken::new())
            .expect("invoke factory shadow");
        let factory_result = match first.outcome() {
            InvocationOutcome::Succeeded {
                result: CapabilitySuccess::FactoryEffect(result),
            } => result,
            other => panic!("unexpected factory shadow outcome: {other:?}"),
        };
        assert_eq!(factory_result.logical_effect_id, "logical-effect:shadow:1");
        assert_eq!(
            factory_result.exact_request_digest,
            effect_request.exact_request_digest
        );
        assert_eq!(
            backend.calls.lock().unwrap().as_slice(),
            &[(CapabilityOperation::FactoryShadow, effect_request.clone())]
        );
        assert_eq!(
            backend.calls.lock().unwrap()[0].1.exact_request_bytes,
            exact_request_bytes
        );
        assert_eq!(
            *first.input_digest(),
            ContentDigest::from_bytes(
                &serde_json::to_vec(&shadow).expect("encode exact factory invocation")
            )
        );

        let repeated = runtime
            .invoke(&shadow, CancellationToken::new())
            .expect("idempotent factory retry");
        assert_eq!(repeated, first);
        assert_eq!(backend.calls.lock().unwrap().len(), 1);

        let blocked = automatic(
            FACTORY_PROMOTION_SERVICE_ID,
            "factory-activate-blocked",
            AuthorityClass::PromotionControl,
            CapabilityRequest::FactoryActivate(FactoryEffectRequest::new(
                SCOPE,
                "factory-a",
                "logical-effect:activate:blocked",
                b"activate-blocked".to_vec(),
            )),
        );
        let blocked_receipt = runtime
            .invoke(&blocked, CancellationToken::new())
            .expect("approval blocking is durably receipted");
        assert_eq!(
            blocked_receipt.outcome().failure_kind(),
            Some(ServiceFailureKind::ApprovalBlocked)
        );
        assert_eq!(backend.calls.lock().unwrap().len(), 1);

        let activate = approved(
            FACTORY_PROMOTION_SERVICE_ID,
            "factory-activate-approved",
            AuthorityClass::PromotionControl,
            ApprovalClass::HumanRequired,
            CapabilityRequest::FactoryActivate(FactoryEffectRequest::new(
                SCOPE,
                "factory-a",
                "logical-effect:activate:1",
                b"activate-approved".to_vec(),
            )),
        );
        assert!(
            runtime
                .invoke(&activate, CancellationToken::new())
                .expect("invoke approved factory activation")
                .outcome()
                .is_success()
        );
        assert_eq!(backend.calls.lock().unwrap().len(), 2);

        let exact_input = runtime
            .invocation_input("factory-shadow-1")
            .expect("reload exact factory input");
        let attestation = runtime
            .attestation("factory-shadow-1")
            .expect("derive factory attestation");
        assert_eq!(exact_input, shadow);
        assert_eq!(attestation.operation, CapabilityOperation::FactoryShadow);
        assert!(attestation.terminal_success);
        drop(runtime);

        let reopened_port: Arc<dyn FactoryEvolutionPort> = backend.clone();
        let reopened = M3CapabilityRuntime::open_with_factory_evolution(
            config,
            Arc::clone(&m2),
            reopened_port,
        )
        .expect("reopen M3 factory extension");
        assert_eq!(
            reopened
                .receipt("factory-shadow-1")
                .expect("reload receipt"),
            first
        );
        assert_eq!(
            reopened
                .invocation_input("factory-shadow-1")
                .expect("reload input after restart"),
            shadow
        );
        assert_eq!(
            reopened
                .attestation("factory-shadow-1")
                .expect("reload attestation after restart"),
            attestation
        );
        assert_eq!(
            reopened
                .invoke(&shadow, CancellationToken::new())
                .expect("idempotent retry after restart"),
            first
        );
        assert_eq!(backend.calls.lock().unwrap().len(), 2);
        drop(reopened);
        m2.stop().expect("stop factory-extension M2");
    }

    #[test]
    fn all_seven_families_execute_real_work_and_reload_durable_state() {
        let test = TestDirectory::new("seven-families");
        let Harness {
            m3_config,
            m2_config,
            m2,
            runtime,
        } = harness(&test, "live");

        let families = runtime
            .services()
            .iter()
            .map(|service| service.family)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            families,
            BTreeSet::from([
                NativeServiceFamily::Build,
                NativeServiceFamily::Validation,
                NativeServiceFamily::Review,
                NativeServiceFamily::Packaging,
                NativeServiceFamily::Continuity,
                NativeServiceFamily::Scheduling,
                NativeServiceFamily::Operations,
            ])
        );
        assert_eq!(runtime.services().len(), 9);
        for service in runtime.services() {
            assert_eq!(
                runtime
                    .health(&service.service_id)
                    .expect("registered service health")
                    .availability,
                ServiceAvailability::Available
            );
        }

        let incumbent_open = automatic(
            BUILD_SERVICE_ID,
            "build-open-incumbent",
            AuthorityClass::LocalMutate,
            CapabilityRequest::OpenWorkspace(OpenWorkspaceRequest {
                workspace: workspace("incumbent"),
            }),
        );
        invoke_success(&runtime, &incumbent_open);
        let challenger_open = automatic(
            BUILD_SERVICE_ID,
            "build-open-challenger",
            AuthorityClass::LocalMutate,
            CapabilityRequest::OpenWorkspace(OpenWorkspaceRequest {
                workspace: workspace("challenger"),
            }),
        );
        let challenger_snapshot = match invoke_success(&runtime, &challenger_open) {
            CapabilitySuccess::Workspace(snapshot) => *snapshot,
            other => panic!("unexpected workspace result: {other:?}"),
        };
        let before_digest = challenger_snapshot
            .entry("component.wat")
            .expect("mutable WAT entry")
            .content_digest
            .clone();
        invoke_success(
            &runtime,
            &automatic(
                BUILD_SERVICE_ID,
                "build-patch-challenger",
                AuthorityClass::LocalMutate,
                CapabilityRequest::PatchWorkspace(PatchWorkspaceRequest {
                    workspace: workspace("challenger"),
                    expected_before_digest: before_digest,
                    replacement_bytes: fs::read(fixture_root().join("candidates/increment.wat"))
                        .expect("read increment candidate"),
                }),
            ),
        );

        let incumbent_build = match invoke_success(
            &runtime,
            &automatic(
                BUILD_SERVICE_ID,
                "build-incumbent",
                AuthorityClass::LocalMutate,
                CapabilityRequest::BuildCandidate(BuildCandidateRequest {
                    workspace: workspace("incumbent"),
                }),
            ),
        ) {
            CapabilitySuccess::Build(build) => *build,
            other => panic!("unexpected build result: {other:?}"),
        };
        let challenger_build = match invoke_success(
            &runtime,
            &automatic(
                BUILD_SERVICE_ID,
                "build-challenger",
                AuthorityClass::LocalMutate,
                CapabilityRequest::BuildCandidate(BuildCandidateRequest {
                    workspace: workspace("challenger"),
                }),
            ),
        ) {
            CapabilitySuccess::Build(build) => *build,
            other => panic!("unexpected build result: {other:?}"),
        };

        let incumbent_package = match invoke_success(
            &runtime,
            &automatic(
                PACKAGING_SERVICE_ID,
                "package-incumbent",
                AuthorityClass::LocalMutate,
                CapabilityRequest::PublishPackage(PublishPackageRequest {
                    workspace: workspace("incumbent"),
                    expected_package_digest: incumbent_build.package_digest.clone(),
                }),
            ),
        ) {
            CapabilitySuccess::Package(package) => *package,
            other => panic!("unexpected package result: {other:?}"),
        };
        let challenger_package = match invoke_success(
            &runtime,
            &automatic(
                PACKAGING_SERVICE_ID,
                "package-challenger",
                AuthorityClass::LocalMutate,
                CapabilityRequest::PublishPackage(PublishPackageRequest {
                    workspace: workspace("challenger"),
                    expected_package_digest: challenger_build.package_digest.clone(),
                }),
            ),
        ) {
            CapabilitySuccess::Package(package) => *package,
            other => panic!("unexpected package result: {other:?}"),
        };

        let suite = suite();
        let incumbent_proving = match invoke_success(
            &runtime,
            &automatic(
                VALIDATION_SERVICE_ID,
                "validate-incumbent",
                AuthorityClass::Observe,
                CapabilityRequest::ProvePackage(ProvePackageRequest {
                    scope_id: SCOPE.to_string(),
                    package_digest: incumbent_package.package_digest.clone(),
                    suite: suite.clone(),
                }),
            ),
        ) {
            CapabilitySuccess::Proving(proving) => *proving,
            other => panic!("unexpected proving result: {other:?}"),
        };
        let challenger_proving = match invoke_success(
            &runtime,
            &automatic(
                VALIDATION_SERVICE_ID,
                "validate-challenger",
                AuthorityClass::Observe,
                CapabilityRequest::ProvePackage(ProvePackageRequest {
                    scope_id: SCOPE.to_string(),
                    package_digest: challenger_package.package_digest.clone(),
                    suite: suite.clone(),
                }),
            ),
        ) {
            CapabilitySuccess::Proving(proving) => *proving,
            other => panic!("unexpected proving result: {other:?}"),
        };
        let comparison = match invoke_success(
            &runtime,
            &automatic(
                VALIDATION_SERVICE_ID,
                "validate-compare",
                AuthorityClass::Observe,
                CapabilityRequest::CompareProving(CompareProvingRequest {
                    scope_id: SCOPE.to_string(),
                    suite: suite.clone(),
                    incumbent_proving_digest: incumbent_proving.record_digest.clone(),
                    challenger_proving_digest: challenger_proving.record_digest.clone(),
                }),
            ),
        ) {
            CapabilitySuccess::Comparison(comparison) => *comparison,
            other => panic!("unexpected comparison result: {other:?}"),
        };
        let review = match invoke_success(
            &runtime,
            &automatic(
                REVIEW_SERVICE_ID,
                "review-challenger",
                AuthorityClass::Observe,
                CapabilityRequest::ReviewCandidate(ReviewCandidateRequest {
                    scope_id: SCOPE.to_string(),
                    suite: suite.clone(),
                    comparison_digest: comparison.record_digest.clone(),
                }),
            ),
        ) {
            CapabilitySuccess::Review(review) => *review,
            other => panic!("unexpected review result: {other:?}"),
        };

        let evidence_payload = serde_json::to_vec(&review).expect("encode review evidence");
        let evidence = match invoke_success(
            &runtime,
            &automatic(
                CONTINUITY_SERVICE_ID,
                "continuity-publish-review",
                AuthorityClass::LocalMutate,
                CapabilityRequest::PublishEvidence(PublishEvidenceRequest {
                    scope_id: SCOPE.to_string(),
                    evidence_id: "review-evidence-1".to_string(),
                    media_type: "application/json".to_string(),
                    subject_refs: vec![format!("review:{}", review.review_digest)],
                    expected_digest: Some(ContentDigest::from_bytes(&evidence_payload)),
                    payload: evidence_payload.clone(),
                }),
            ),
        ) {
            CapabilitySuccess::EvidencePublished(record) => *record,
            other => panic!("unexpected evidence result: {other:?}"),
        };
        let resolved = match invoke_success(
            &runtime,
            &automatic(
                CONTINUITY_RESOLVE_SERVICE_ID,
                "continuity-resolve-review",
                AuthorityClass::Observe,
                CapabilityRequest::ResolveEvidence(ResolveEvidenceRequest {
                    scope_id: SCOPE.to_string(),
                    evidence_id: evidence.evidence_id.clone(),
                    expected_digest: evidence.content_digest.clone(),
                }),
            ),
        ) {
            CapabilitySuccess::EvidenceResolved(resolved) => *resolved,
            other => panic!("unexpected evidence resolution: {other:?}"),
        };
        assert_eq!(resolved.payload, evidence_payload);

        let due_at_ms = now_ms();
        let schedule = runtime
            .register_schedule(M3ScheduleRegistration {
                scope_id: SCOPE.to_string(),
                schedule_id: "schedule-open-workspace".to_string(),
                job_id: "m3-open-workspace-job".to_string(),
                idempotency_key: "m3-open-workspace-effect".to_string(),
                due_at_ms,
                deadline_at_ms: due_at_ms.saturating_add(60_000),
                retry_policy: RetryPolicy::default(),
                lifecycle: M1LifecycleJob::OpenWorkspace(OpenWorkspacePayload {
                    workspace_id: "scheduled-workspace".to_string(),
                }),
            })
            .expect("register real M2 schedule");
        invoke_success(
            &runtime,
            &approved(
                SCHEDULING_SERVICE_ID,
                "schedule-open-workspace",
                AuthorityClass::AutomationControl,
                ApprovalClass::SupervisorAllowed,
                CapabilityRequest::ScheduleJob(schedule.capability_request()),
            ),
        );
        let scheduled = wait_for_phase(&runtime, "schedule-open-workspace", JobPhase::Succeeded);
        assert!(scheduled.terminal_outcome.is_some());

        let approval_due_at_ms = now_ms();
        let approval_schedule = runtime
            .register_schedule(M3ScheduleRegistration {
                scope_id: SCOPE.to_string(),
                schedule_id: "schedule-await-approval".to_string(),
                job_id: "m3-await-approval-job".to_string(),
                idempotency_key: "m3-await-approval-effect".to_string(),
                due_at_ms: approval_due_at_ms,
                deadline_at_ms: approval_due_at_ms.saturating_add(60_000),
                retry_policy: RetryPolicy::default(),
                lifecycle: M1LifecycleJob::Activate(ActivatePayload {
                    comparison_record_digest: ContentDigest::from_bytes(b"pending-comparison"),
                    approval_request_id: "approval:m3-pending".to_string(),
                }),
            })
            .expect("register approval-bound schedule");
        invoke_success(
            &runtime,
            &approved(
                SCHEDULING_SERVICE_ID,
                "schedule-await-approval",
                AuthorityClass::AutomationControl,
                ApprovalClass::SupervisorAllowed,
                CapabilityRequest::ScheduleJob(approval_schedule.capability_request()),
            ),
        );
        wait_for_phase(
            &runtime,
            "schedule-await-approval",
            JobPhase::WaitingApproval,
        );

        invoke_success(
            &runtime,
            &approved(
                OPERATIONS_CONTROL_SERVICE_ID,
                "operations-initialize",
                AuthorityClass::PromotionControl,
                ApprovalClass::HumanRequired,
                CapabilityRequest::InitializeDeployment(InitializeDeploymentRequest {
                    deployment: deployment(),
                    operation_id: "initialize-1".to_string(),
                    incumbent_package_digest: incumbent_package.package_digest.clone(),
                }),
            ),
        );
        let activation = match invoke_success(
            &runtime,
            &approved(
                OPERATIONS_CONTROL_SERVICE_ID,
                "operations-activate",
                AuthorityClass::PromotionControl,
                ApprovalClass::HumanRequired,
                CapabilityRequest::ActivateDeployment(ActivateDeploymentRequest {
                    deployment: deployment(),
                    operation_id: "activation-1".to_string(),
                    package_digest: challenger_package.package_digest.clone(),
                    expected_active_digest: incumbent_package.package_digest.clone(),
                    approval_ref: format!("review:{}", review.review_digest),
                    comparison_ref: comparison.record_digest.to_string(),
                    observation_window_ref: "window:m3-test".to_string(),
                }),
            ),
        ) {
            CapabilitySuccess::DeploymentActivated(activation) => *activation,
            other => panic!("unexpected activation result: {other:?}"),
        };
        invoke_success(
            &runtime,
            &approved(
                OPERATIONS_CONTROL_SERVICE_ID,
                "operations-observe",
                AuthorityClass::PromotionControl,
                ApprovalClass::HumanRequired,
                CapabilityRequest::ObserveDeployment(ObserveDeploymentRequest {
                    deployment: deployment(),
                    observation_id: "observation-1".to_string(),
                    activation_id: activation.operation_id.clone(),
                    expected_active_digest: challenger_package.package_digest.clone(),
                    outcome: ObservationOutcome::Healthy,
                    summary: "bounded reference execution remained healthy".to_string(),
                    evidence_bytes: br#"{"input":41,"output":42}"#.to_vec(),
                }),
            ),
        );
        invoke_success(
            &runtime,
            &approved(
                OPERATIONS_CONTROL_SERVICE_ID,
                "operations-rollback",
                AuthorityClass::PromotionControl,
                ApprovalClass::HumanRequired,
                CapabilityRequest::RollbackDeployment(RollbackDeploymentRequest {
                    deployment: deployment(),
                    operation_id: "rollback-1".to_string(),
                    activation_id: activation.operation_id,
                    reason_ref: "operator:m3-test".to_string(),
                }),
            ),
        );

        let operations_invocation = automatic(
            OPERATIONS_INSPECT_SERVICE_ID,
            "operations-inspect",
            AuthorityClass::Observe,
            CapabilityRequest::InspectOperations(InspectOperationsRequest {
                deployment: deployment(),
            }),
        );
        let operations = runtime
            .inspect_operations(&operations_invocation, CancellationToken::new())
            .expect("persist joined operations inspection");
        assert_eq!(operations.deployment.activation_count, 1);
        assert_eq!(operations.deployment.observation_count, 1);
        assert_eq!(operations.deployment.rollback_count, 1);
        assert!(
            operations.jobs.iter().any(
                |job| job.job_id == "m3-open-workspace-job" && job.phase == JobPhase::Succeeded
            )
        );
        assert!(operations.approvals.iter().any(|approval| {
            approval.job_id == "m3-await-approval-job"
                && approval.approval_request_id == "approval:m3-pending"
                && approval.phase == JobPhase::WaitingApproval
        }));
        assert!(
            !serde_json::to_string(&operations)
                .expect("encode bounded operations projection")
                .contains("payload_json")
        );

        let representative_invocations = [
            ("build-challenger", NativeServiceFamily::Build),
            ("validate-challenger", NativeServiceFamily::Validation),
            ("review-challenger", NativeServiceFamily::Review),
            ("package-challenger", NativeServiceFamily::Packaging),
            ("continuity-publish-review", NativeServiceFamily::Continuity),
            ("schedule-open-workspace", NativeServiceFamily::Scheduling),
            ("operations-inspect", NativeServiceFamily::Operations),
        ];
        for (invocation_id, family) in &representative_invocations {
            let attestation = runtime
                .attestation(invocation_id)
                .expect("resolve invocation attestation");
            assert_eq!(attestation.family, *family);
            assert!(attestation.terminal_success);
            assert_ne!(
                attestation.attestation_digest,
                ContentDigest::from_bytes(&[])
            );
        }
        let operations_digest = operations.record_digest.clone();
        let scheduling_attestation = runtime
            .attestation("schedule-open-workspace")
            .expect("schedule attestation before restart");

        m2.stop().expect("stop first M2 owner");
        drop(runtime);
        drop(m2);

        let restarted_m2 =
            Arc::new(M2Runtime::new(m2_config).expect("construct restarted M2 owner"));
        let restarted =
            M3CapabilityRuntime::open(m3_config, Arc::clone(&restarted_m2)).expect("restart M3");
        let reloaded_evidence = match invoke_success(
            &restarted,
            &automatic(
                CONTINUITY_RESOLVE_SERVICE_ID,
                "continuity-resolve-after-restart",
                AuthorityClass::Observe,
                CapabilityRequest::ResolveEvidence(ResolveEvidenceRequest {
                    scope_id: SCOPE.to_string(),
                    evidence_id: evidence.evidence_id,
                    expected_digest: evidence.content_digest,
                }),
            ),
        ) {
            CapabilitySuccess::EvidenceResolved(resolved) => *resolved,
            other => panic!("unexpected restarted evidence resolution: {other:?}"),
        };
        assert_eq!(reloaded_evidence.payload, evidence_payload);
        assert_eq!(
            restarted
                .schedule_binding("schedule-open-workspace")
                .expect("reload schedule binding"),
            schedule
        );
        assert_eq!(
            restarted
                .scheduled_job("schedule-open-workspace")
                .expect("reload scheduled job")
                .expect("scheduled job remains durable")
                .phase,
            JobPhase::Succeeded
        );
        assert_eq!(
            restarted
                .operations_record(&operations_digest)
                .expect("reload operations record"),
            operations
        );
        assert_eq!(
            restarted
                .attestation("schedule-open-workspace")
                .expect("resolve durable attestation after restart"),
            scheduling_attestation
        );
        let restarted_operations = restarted
            .inspect_operations(
                &automatic(
                    OPERATIONS_INSPECT_SERVICE_ID,
                    "operations-inspect-after-restart",
                    AuthorityClass::Observe,
                    CapabilityRequest::InspectOperations(InspectOperationsRequest {
                        deployment: deployment(),
                    }),
                ),
                CancellationToken::new(),
            )
            .expect("inspect restarted deployment and M2 state");
        assert_eq!(restarted_operations.deployment.rollback_count, 1);
        assert!(
            restarted_operations
                .approvals
                .iter()
                .any(|approval| approval.approval_request_id == "approval:m3-pending")
        );

        let bundle_request = M3EvidenceBundleRequest {
            invocation_ids: representative_invocations
                .iter()
                .map(|(invocation_id, _)| (*invocation_id).to_string())
                .collect(),
            schedule_ids: vec!["schedule-open-workspace".to_string()],
            operations_record_digests: vec![operations_digest],
        };
        let bundle = restarted
            .publish_evidence_bundle(bundle_request.clone())
            .expect("publish aggregate evidence after restart");
        assert_eq!(bundle.invocations.len(), 7);
        assert_eq!(bundle.schedules.len(), 1);
        assert_eq!(bundle.operations.len(), 1);
        assert_eq!(bundle.family_index.len(), 7);
        assert_eq!(
            restarted
                .evidence_bundle(&bundle.bundle_digest)
                .expect("re-read content-addressed evidence bundle"),
            bundle
        );
        restarted
            .verify_evidence_bundle(&bundle)
            .expect("independently re-resolve every aggregate constituent");

        let mut identity_corruption = bundle.clone();
        identity_corruption.invocations[0].attestation.output_digest =
            ContentDigest::from_bytes(b"forged-output");
        identity_corruption.bundle_digest =
            evidence_bundle_digest(&identity_corruption).expect("re-digest forged outer bundle");
        assert!(matches!(
            restarted.verify_evidence_bundle(&identity_corruption),
            Err(M3RuntimeError::InvalidEvidenceBundle(_))
        ));

        let mut missing_family = bundle_request.clone();
        missing_family
            .invocation_ids
            .retain(|invocation_id| invocation_id != "review-challenger");
        assert!(matches!(
            restarted.publish_evidence_bundle(missing_family),
            Err(M3RuntimeError::InvalidEvidenceBundle(_))
        ));

        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let failed_receipt = restarted
            .invoke(
                &automatic(
                    BUILD_SERVICE_ID,
                    "bundle-failed-invocation",
                    AuthorityClass::LocalMutate,
                    CapabilityRequest::OpenWorkspace(OpenWorkspaceRequest {
                        workspace: workspace("bundle-failed"),
                    }),
                ),
                cancellation,
            )
            .expect("persist explicit failed invocation");
        assert!(!failed_receipt.outcome().is_success());
        let mut includes_failure = bundle_request.clone();
        includes_failure
            .invocation_ids
            .push("bundle-failed-invocation".to_string());
        assert!(matches!(
            restarted.publish_evidence_bundle(includes_failure),
            Err(M3RuntimeError::InvalidEvidenceBundle(_))
        ));

        let mut duplicate = bundle_request.clone();
        duplicate
            .invocation_ids
            .push("build-challenger".to_string());
        assert!(matches!(
            restarted.publish_evidence_bundle(duplicate),
            Err(M3RuntimeError::InvalidEvidenceBundle(_))
        ));

        let mut oversized = bundle_request;
        oversized.invocation_ids = (0..=MAX_EVIDENCE_BUNDLE_INVOCATIONS)
            .map(|index| format!("oversized-invocation-{index}"))
            .collect();
        assert!(matches!(
            restarted.publish_evidence_bundle(oversized),
            Err(M3RuntimeError::ResourceBoundExceeded { .. })
        ));

        let bundle_path = restarted.evidence_bundle_path(&bundle.bundle_digest);
        fs::write(&bundle_path, b"{\"tampered\":true}").expect("tamper aggregate evidence bytes");
        assert!(restarted.evidence_bundle(&bundle.bundle_digest).is_err());
        restarted_m2.stop().expect("stop restarted M2 owner");
    }

    #[derive(Default)]
    struct JumpClock {
        now: AtomicU64,
    }

    impl ClockPort for JumpClock {
        fn now_ms(&self) -> u64 {
            self.now.fetch_add(100, Ordering::AcqRel)
        }
    }

    #[test]
    fn terminal_outcomes_are_honest_for_cancel_timeout_unsupported_and_unavailable() {
        let test = TestDirectory::new("terminal-outcomes");
        let Harness { runtime, m2, .. } = harness(&test, "ordinary");

        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let cancelled = runtime
            .invoke(
                &automatic(
                    BUILD_SERVICE_ID,
                    "cancelled-build",
                    AuthorityClass::LocalMutate,
                    CapabilityRequest::OpenWorkspace(OpenWorkspaceRequest {
                        workspace: workspace("cancelled"),
                    }),
                ),
                cancellation,
            )
            .expect("cancelled invocation has a durable receipt");
        assert_eq!(
            cancelled.outcome().failure_kind(),
            Some(ServiceFailureKind::Cancelled)
        );

        let unsupported = runtime
            .invoke(
                &automatic(
                    PACKAGING_SERVICE_ID,
                    "unsupported-packaging-request",
                    AuthorityClass::LocalMutate,
                    CapabilityRequest::ResolveEvidence(ResolveEvidenceRequest {
                        scope_id: SCOPE.to_string(),
                        evidence_id: "not-packaging".to_string(),
                        expected_digest: ContentDigest::from_bytes(b"none"),
                    }),
                ),
                CancellationToken::new(),
            )
            .expect("unsupported invocation has a durable receipt");
        assert_eq!(
            unsupported.outcome().failure_kind(),
            Some(ServiceFailureKind::Unsupported)
        );

        let timeout_template = test.copy_template("timeout-template");
        let timeout_m2 = Arc::new(
            M2Runtime::new(M2RuntimeConfig {
                supervisor_root: test.root.join("timeout-supervisor"),
                lifecycle_root: test.root.join("timeout-lifecycle"),
                template_root: timeout_template.clone(),
                owner_id: "m3-timeout".to_string(),
                max_idle_wait_ms: 10,
            })
            .expect("construct timeout M2"),
        );
        let timeout_runtime = M3CapabilityRuntime::with_clock(
            M3RuntimeConfig::new(
                test.root.join("timeout-m3"),
                timeout_template,
                SCOPE,
                DEPLOYMENT,
            ),
            timeout_m2,
            Arc::new(JumpClock::default()),
        )
        .expect("open timeout runtime");
        let mut timeout_invocation = automatic(
            BUILD_SERVICE_ID,
            "timed-out-build",
            AuthorityClass::LocalMutate,
            CapabilityRequest::OpenWorkspace(OpenWorkspaceRequest {
                workspace: workspace("timed-out"),
            }),
        );
        timeout_invocation.budget = InvocationBudget::bounded(1);
        let timed_out = timeout_runtime
            .invoke(&timeout_invocation, CancellationToken::new())
            .expect("timed out invocation has a durable receipt");
        assert_eq!(
            timed_out.outcome().failure_kind(),
            Some(ServiceFailureKind::TimedOut)
        );

        let unavailable_template = test.copy_template("unavailable-template");
        let unavailable_m2 = Arc::new(
            M2Runtime::new(M2RuntimeConfig {
                supervisor_root: test.root.join("unavailable-supervisor"),
                lifecycle_root: test.root.join("unavailable-lifecycle"),
                template_root: unavailable_template.clone(),
                owner_id: "m3-unavailable".to_string(),
                max_idle_wait_ms: 10,
            })
            .expect("construct unavailable M2"),
        );
        let unavailable_runtime = M3CapabilityRuntime::open(
            M3RuntimeConfig::new(
                test.root.join("unavailable-m3"),
                unavailable_template.clone(),
                SCOPE,
                DEPLOYMENT,
            ),
            unavailable_m2,
        )
        .expect("open runtime before backend becomes unavailable");
        let due_at_ms = now_ms();
        let binding = unavailable_runtime
            .register_schedule(M3ScheduleRegistration {
                scope_id: SCOPE.to_string(),
                schedule_id: "unavailable-schedule".to_string(),
                job_id: "unavailable-job".to_string(),
                idempotency_key: "unavailable-effect".to_string(),
                due_at_ms,
                deadline_at_ms: due_at_ms.saturating_add(60_000),
                retry_policy: RetryPolicy::default(),
                lifecycle: M1LifecycleJob::OpenWorkspace(OpenWorkspacePayload {
                    workspace_id: "never-opened".to_string(),
                }),
            })
            .expect("register schedule before backend loss");
        fs::remove_file(unavailable_template.join("component.wat"))
            .expect("make M2 lifecycle dependency unavailable");
        let unavailable = unavailable_runtime
            .invoke(
                &approved(
                    SCHEDULING_SERVICE_ID,
                    "unavailable-scheduler",
                    AuthorityClass::AutomationControl,
                    ApprovalClass::SupervisorAllowed,
                    CapabilityRequest::ScheduleJob(binding.capability_request()),
                ),
                CancellationToken::new(),
            )
            .expect("unavailable invocation has a durable receipt");
        assert_eq!(
            unavailable.outcome().failure_kind(),
            Some(ServiceFailureKind::Unavailable)
        );
        assert_eq!(
            unavailable_runtime
                .health(SCHEDULING_SERVICE_ID)
                .expect("scheduling health")
                .failed_invocations,
            1
        );
        m2.stop().expect("stop unused ordinary M2");
    }

    #[test]
    fn invalid_configuration_and_schedule_rebinding_are_blocked() {
        let test = TestDirectory::new("misconfiguration");
        let template = test.copy_template("template");
        let m2 = Arc::new(
            M2Runtime::new(M2RuntimeConfig {
                supervisor_root: test.root.join("supervisor"),
                lifecycle_root: test.root.join("lifecycle"),
                template_root: template.clone(),
                owner_id: "m3-misconfiguration".to_string(),
                max_idle_wait_ms: 10,
            })
            .expect("construct M2"),
        );
        assert!(matches!(
            M3CapabilityRuntime::open(
                M3RuntimeConfig::new(test.root.join("bad"), &template, "", DEPLOYMENT),
                Arc::clone(&m2),
            ),
            Err(M3RuntimeError::InvalidConfig(_))
        ));
        assert!(
            M3CapabilityRuntime::open(
                M3RuntimeConfig::new(
                    test.root.join("missing-template-runtime"),
                    test.root.join("missing-template"),
                    SCOPE,
                    DEPLOYMENT,
                ),
                Arc::clone(&m2),
            )
            .is_err()
        );

        let runtime = M3CapabilityRuntime::open(
            M3RuntimeConfig::new(test.root.join("valid"), template, SCOPE, DEPLOYMENT),
            m2,
        )
        .expect("open valid runtime");
        let due_at_ms = now_ms();
        let first = M3ScheduleRegistration {
            scope_id: SCOPE.to_string(),
            schedule_id: "immutable-schedule".to_string(),
            job_id: "immutable-job".to_string(),
            idempotency_key: "immutable-effect".to_string(),
            due_at_ms,
            deadline_at_ms: due_at_ms.saturating_add(60_000),
            retry_policy: RetryPolicy::default(),
            lifecycle: M1LifecycleJob::OpenWorkspace(OpenWorkspacePayload {
                workspace_id: "one".to_string(),
            }),
        };
        assert_eq!(
            runtime
                .register_schedule(first.clone())
                .expect("initial registration"),
            runtime
                .register_schedule(first.clone())
                .expect("idempotent registration")
        );
        let mut conflicting = first;
        conflicting.lifecycle = M1LifecycleJob::OpenWorkspace(OpenWorkspacePayload {
            workspace_id: "two".to_string(),
        });
        assert!(matches!(
            runtime.register_schedule(conflicting),
            Err(M3RuntimeError::ScheduleConflict { .. })
        ));

        let binding_path = runtime.scheduling.binding_path("immutable-schedule");
        fs::write(&binding_path, vec![b'x'; MAX_SCHEDULE_BINDING_BYTES + 1])
            .expect("tamper schedule binding beyond its read bound");
        assert!(matches!(
            runtime.schedule_binding("immutable-schedule"),
            Err(M3RuntimeError::ResourceBoundExceeded { .. })
        ));
    }

    fn fixture_root() -> PathBuf {
        let source = PathBuf::from(file!());
        let absolute = if source.is_absolute() {
            source
        } else {
            std::env::current_dir()
                .expect("current directory")
                .join(source)
        };
        absolute
            .parent()
            .and_then(Path::parent)
            .expect("source file beneath repository root")
            .join("artifacts/fixtures/m1-reference-component")
    }
}
