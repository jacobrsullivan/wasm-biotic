#![cfg_attr(all(target_arch = "wasm32", not(test)), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

//! Pure component-owned supervisor policy.
//!
//! Native code is deliberately absent from this state machine. The host passes
//! state and one event through WIT; this component returns new state and
//! declarative commands. Effect journalling and execution belong to the
//! separately composed component driver and generic substrate.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

extern crate alloc;

#[cfg(all(target_arch = "wasm32", not(test)))]
#[global_allocator]
static ALLOCATOR: dlmalloc::GlobalDlmalloc = dlmalloc::GlobalDlmalloc;

pub const STATE_SCHEMA: &str = "wasm-biotic.supervisor-state.v1";
pub const JSON_MEDIA_TYPE: &str = "application/json";

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage {
    Planner,
    Builder,
    Validator,
    Reviewer,
    Packager,
    ContinuityWorker,
}

impl Stage {
    pub const ALL: [Self; 6] = [
        Self::Planner,
        Self::Builder,
        Self::Validator,
        Self::Reviewer,
        Self::Packager,
        Self::ContinuityWorker,
    ];

    fn next(&self) -> Option<Self> {
        match self {
            Self::Planner => Some(Self::Builder),
            Self::Builder => Some(Self::Validator),
            Self::Validator => Some(Self::Reviewer),
            Self::Reviewer => Some(Self::Packager),
            Self::Packager => Some(Self::ContinuityWorker),
            Self::ContinuityWorker => None,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::Planner => "planner",
            Self::Builder => "builder",
            Self::Validator => "validator",
            Self::Reviewer => "reviewer",
            Self::Packager => "packager",
            Self::ContinuityWorker => "continuity-worker",
        }
    }

    fn service_families(&self) -> &'static [ServiceFamilyValue] {
        const PLANNER: &[ServiceFamilyValue] =
            &[ServiceFamilyValue::Build, ServiceFamilyValue::Scheduling];
        const BUILDER: &[ServiceFamilyValue] = &[ServiceFamilyValue::Build];
        const VALIDATOR: &[ServiceFamilyValue] = &[ServiceFamilyValue::Validation];
        const REVIEWER: &[ServiceFamilyValue] = &[ServiceFamilyValue::Review];
        const PACKAGER: &[ServiceFamilyValue] = &[ServiceFamilyValue::Packaging];
        const CONTINUITY: &[ServiceFamilyValue] = &[ServiceFamilyValue::Continuity];
        match self {
            Self::Planner => PLANNER,
            Self::Builder => BUILDER,
            Self::Validator => VALIDATOR,
            Self::Reviewer => REVIEWER,
            Self::Packager => PACKAGER,
            Self::ContinuityWorker => CONTINUITY,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceFamilyValue {
    Build,
    Packaging,
    Validation,
    Review,
    Continuity,
    Scheduling,
    Operations,
}

impl ServiceFamilyValue {
    pub const ALL: [Self; 7] = [
        Self::Build,
        Self::Packaging,
        Self::Validation,
        Self::Review,
        Self::Continuity,
        Self::Scheduling,
        Self::Operations,
    ];

    fn as_str(self) -> &'static str {
        match self {
            Self::Build => "build",
            Self::Packaging => "packaging",
            Self::Validation => "validation",
            Self::Review => "review",
            Self::Continuity => "continuity",
            Self::Scheduling => "scheduling",
            Self::Operations => "operations",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DigestValue {
    pub algorithm: String,
    pub hex: String,
}

impl DigestValue {
    fn sha256(bytes: &[u8]) -> Self {
        Self {
            algorithm: "sha256".to_string(),
            hex: hex_sha256(bytes),
        }
    }

    fn validate(&self, field: &str) -> Result<(), PolicyError> {
        if self.algorithm != "sha256" {
            return Err(PolicyError::new(
                "unsupported-digest",
                format!("{field} must use sha256"),
            ));
        }
        if self.hex.len() != 64
            || !self
                .hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(PolicyError::new(
                "invalid-digest",
                format!("{field} must be 64 lower-case hexadecimal characters"),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobPointer {
    pub content_digest: DigestValue,
    pub size_bytes: u64,
    pub media_type: String,
}

impl BlobPointer {
    fn validate(&self, field: &str) -> Result<(), PolicyError> {
        self.content_digest
            .validate(&format!("{field}.content_digest"))?;
        if self.media_type.trim().is_empty() {
            return Err(PolicyError::new(
                "invalid-blob",
                format!("{field}.media_type must not be blank"),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum JobStatus {
    Running,
    Blocked,
    Completed,
    Rejected,
    Failed,
    Cancelled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobRecord {
    pub job_id: String,
    pub source: BlobPointer,
    pub current_stage: Stage,
    pub status: JobStatus,
    pub active_execution: Option<String>,
    pub latest_output: Option<BlobPointer>,
    pub checkpoint: Option<BlobPointer>,
    pub terminal_code: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionBinding {
    pub job_id: String,
    pub stage: Stage,
    pub attempt: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceBindingValue {
    pub family: ServiceFamilyValue,
    pub component_digest: DigestValue,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorStateV1 {
    pub schema: String,
    pub graph_digest: DigestValue,
    pub last_event_sequence: u64,
    pub worker_components: BTreeMap<Stage, DigestValue>,
    pub service_components: BTreeMap<ServiceFamilyValue, DigestValue>,
    pub jobs: BTreeMap<String, JobRecord>,
    pub active_executions: BTreeMap<String, ExecutionBinding>,
    pub completed_executions: BTreeMap<String, DigestValue>,
}

impl SupervisorStateV1 {
    pub fn empty(
        graph_digest: DigestValue,
        worker_components: BTreeMap<Stage, DigestValue>,
        service_components: BTreeMap<ServiceFamilyValue, DigestValue>,
    ) -> Result<Self, PolicyError> {
        let state = Self {
            schema: STATE_SCHEMA.to_string(),
            graph_digest,
            last_event_sequence: 0,
            worker_components,
            service_components,
            jobs: BTreeMap::new(),
            active_executions: BTreeMap::new(),
            completed_executions: BTreeMap::new(),
        };
        state.validate()?;
        Ok(state)
    }

    fn validate(&self) -> Result<(), PolicyError> {
        if self.schema != STATE_SCHEMA {
            return Err(PolicyError::new(
                "unsupported-state-schema",
                format!("expected state schema {STATE_SCHEMA}"),
            ));
        }
        self.graph_digest.validate("state.graph_digest")?;

        let actual = self.worker_components.keys().cloned().collect::<BTreeSet<_>>();
        let expected = Stage::ALL.into_iter().collect::<BTreeSet<_>>();
        if actual != expected {
            return Err(PolicyError::new(
                "incomplete-worker-graph",
                "state must bind exactly the six governed worker stages",
            ));
        }
        for (stage, digest) in &self.worker_components {
            digest.validate(&format!("worker_components.{}", stage.as_str()))?;
        }

        let actual = self
            .service_components
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();
        let expected = ServiceFamilyValue::ALL
            .into_iter()
            .collect::<BTreeSet<_>>();
        if actual != expected {
            return Err(PolicyError::new(
                "incomplete-service-graph",
                "state must bind exactly the seven capability-service families",
            ));
        }
        for (family, digest) in &self.service_components {
            digest.validate(&format!("service_components.{}", family.as_str()))?;
        }

        for (job_id, job) in &self.jobs {
            if job_id != &job.job_id
                || job_id != &format!("job-sha256-{}", job.source.content_digest.hex)
            {
                return Err(PolicyError::new(
                    "invalid-job-identity",
                    format!("job map key {job_id} does not match its source digest"),
                ));
            }
            job.source.validate(&format!("jobs.{job_id}.source"))?;
            if let Some(output) = &job.latest_output {
                output.validate(&format!("jobs.{job_id}.latest_output"))?;
            }
            if let Some(checkpoint) = &job.checkpoint {
                checkpoint.validate(&format!("jobs.{job_id}.checkpoint"))?;
            }
            match job.status {
                JobStatus::Running if job.active_execution.is_none() => {
                    return Err(PolicyError::new(
                        "missing-active-execution",
                        format!("running job {job_id} has no active execution"),
                    ));
                }
                JobStatus::Running => {}
                _ if job.active_execution.is_some() => {
                    return Err(PolicyError::new(
                        "terminal-active-execution",
                        format!("non-running job {job_id} retains an active execution"),
                    ));
                }
                _ => {}
            }
        }

        for (execution_id, binding) in &self.active_executions {
            let job = self.jobs.get(&binding.job_id).ok_or_else(|| {
                PolicyError::new(
                    "orphan-execution",
                    format!("execution {execution_id} references an unknown job"),
                )
            })?;
            if job.active_execution.as_deref() != Some(execution_id)
                || job.current_stage != binding.stage
                || job.status != JobStatus::Running
            {
                return Err(PolicyError::new(
                    "inconsistent-execution",
                    format!("execution {execution_id} disagrees with its job record"),
                ));
            }
        }
        for (execution_id, digest) in &self.completed_executions {
            if execution_id.trim().is_empty() {
                return Err(PolicyError::new(
                    "invalid-completed-execution",
                    "completed execution identifier must not be blank",
                ));
            }
            digest.validate(&format!("completed_executions.{execution_id}"))?;
        }
        Ok(())
    }

    pub fn to_json(&self) -> Result<Vec<u8>, PolicyError> {
        serde_json::to_vec(self).map_err(|error| {
            PolicyError::new(
                "state-serialization-failed",
                format!("could not serialize state: {error}"),
            )
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyFailure {
    pub code: String,
    pub message: String,
    pub retryable: bool,
    pub evidence: Option<BlobPointer>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyWorkerOutcome {
    Completed(BlobPointer),
    Blocked(BlobPointer),
    Rejected(PolicyFailure),
    Failed(PolicyFailure),
    Cancelled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyWorkerResponse {
    pub execution_id: String,
    pub worker_component: DigestValue,
    pub outcome: PolicyWorkerOutcome,
    pub checkpoint: Option<BlobPointer>,
    pub proof_digests: Vec<DigestValue>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyEvent {
    JobSubmitted(BlobPointer),
    WorkerFinished(PolicyWorkerResponse),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchSpec {
    pub execution_id: String,
    pub job_id: String,
    pub stage: Stage,
    pub worker_component: DigestValue,
    pub service_bindings: Vec<ServiceBindingValue>,
    pub input: BlobPointer,
    pub checkpoint: Option<BlobPointer>,
    pub lease_digest: DigestValue,
    pub attempt: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyCommand {
    DispatchWorker(DispatchSpec),
    RequireApproval(BlobPointer),
    EmitResponse(BlobPointer),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyReduction {
    pub previous_state_digest: DigestValue,
    pub next_state_json: Vec<u8>,
    pub commands: Vec<PolicyCommand>,
    pub decision_digest: DigestValue,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyError {
    pub code: String,
    pub message: String,
}

impl PolicyError {
    fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

impl core::fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl core::error::Error for PolicyError {}

#[derive(Serialize)]
struct DecisionMaterial<'a> {
    graph_digest: &'a DigestValue,
    previous_state_digest: &'a DigestValue,
    event_sequence: u64,
    event: &'a PolicyEvent,
    next_state_digest: &'a DigestValue,
    commands: &'a [PolicyCommand],
}

pub fn reduce_policy(
    graph_digest: DigestValue,
    state_json: &[u8],
    event_sequence: u64,
    event: PolicyEvent,
) -> Result<PolicyReduction, PolicyError> {
    graph_digest.validate("request.graph_digest")?;
    let previous_state_digest = DigestValue::sha256(state_json);
    let mut state: SupervisorStateV1 = serde_json::from_slice(state_json).map_err(|error| {
        PolicyError::new(
            "invalid-state-json",
            format!("could not parse {STATE_SCHEMA}: {error}"),
        )
    })?;
    state.validate()?;

    if state.graph_digest != graph_digest {
        return Err(PolicyError::new(
            "graph-digest-mismatch",
            "request graph digest does not match the state graph digest",
        ));
    }
    let expected_sequence = state.last_event_sequence.checked_add(1).ok_or_else(|| {
        PolicyError::new("event-sequence-exhausted", "event sequence cannot advance")
    })?;
    if event_sequence != expected_sequence {
        return Err(PolicyError::new(
            "event-sequence-mismatch",
            format!("expected event sequence {expected_sequence}, received {event_sequence}"),
        ));
    }

    let mut commands = match &event {
        PolicyEvent::JobSubmitted(source) => submit_job(&mut state, source.clone())?,
        PolicyEvent::WorkerFinished(response) => {
            finish_worker(&mut state, response.clone())?
        }
    };
    state.last_event_sequence = event_sequence;
    state.validate()?;

    let next_state_json = state.to_json()?;
    let next_state_digest = DigestValue::sha256(&next_state_json);
    let decision_bytes = serde_json::to_vec(&DecisionMaterial {
        graph_digest: &graph_digest,
        previous_state_digest: &previous_state_digest,
        event_sequence,
        event: &event,
        next_state_digest: &next_state_digest,
        commands: &commands,
    })
    .map_err(|error| {
        PolicyError::new(
            "decision-serialization-failed",
            format!("could not serialize decision material: {error}"),
        )
    })?;
    let decision_digest = DigestValue::sha256(&decision_bytes);

    // Make allocation order irrelevant to the returned command order.
    commands.shrink_to_fit();
    Ok(PolicyReduction {
        previous_state_digest,
        next_state_json,
        commands,
        decision_digest,
    })
}

fn submit_job(
    state: &mut SupervisorStateV1,
    source: BlobPointer,
) -> Result<Vec<PolicyCommand>, PolicyError> {
    source.validate("job.source")?;
    let job_id = format!("job-sha256-{}", source.content_digest.hex);
    if let Some(existing) = state.jobs.get(&job_id) {
        if existing.source == source {
            return Ok(Vec::new());
        }
        return Err(PolicyError::new(
            "job-identity-collision",
            "job identifier resolves to different source bytes",
        ));
    }

    state.jobs.insert(
        job_id.clone(),
        JobRecord {
            job_id: job_id.clone(),
            source: source.clone(),
            current_stage: Stage::Planner,
            status: JobStatus::Running,
            active_execution: None,
            latest_output: None,
            checkpoint: None,
            terminal_code: None,
        },
    );
    let dispatch = dispatch_stage(state, &job_id, Stage::Planner, source, None, 1)?;
    Ok(vec![PolicyCommand::DispatchWorker(dispatch)])
}

fn finish_worker(
    state: &mut SupervisorStateV1,
    response: PolicyWorkerResponse,
) -> Result<Vec<PolicyCommand>, PolicyError> {
    response.worker_component.validate("worker_component")?;
    if let Some(checkpoint) = &response.checkpoint {
        checkpoint.validate("worker.checkpoint")?;
    }
    for (index, digest) in response.proof_digests.iter().enumerate() {
        digest.validate(&format!("worker.proof_digests.{index}"))?;
    }
    let response_bytes = serde_json::to_vec(&response).map_err(|error| {
        PolicyError::new(
            "worker-response-serialization-failed",
            format!("could not serialize worker response: {error}"),
        )
    })?;
    let response_digest = DigestValue::sha256(&response_bytes);

    if let Some(committed) = state.completed_executions.get(&response.execution_id) {
        return if committed == &response_digest {
            Ok(Vec::new())
        } else {
            Err(PolicyError::new(
                "conflicting-worker-replay",
                "completed execution was replayed with different response bytes",
            ))
        };
    }

    let binding = state
        .active_executions
        .get(&response.execution_id)
        .cloned()
        .ok_or_else(|| {
            PolicyError::new(
                "unknown-worker-execution",
                format!("execution {} is not active", response.execution_id),
            )
        })?;
    let expected_worker = state
        .worker_components
        .get(&binding.stage)
        .expect("validated states contain every worker stage");
    if expected_worker != &response.worker_component {
        return Err(PolicyError::new(
            "worker-component-mismatch",
            format!(
                "execution {} was not completed by its graph-bound {} component",
                response.execution_id,
                binding.stage.as_str()
            ),
        ));
    }

    let job = state.jobs.get(&binding.job_id).ok_or_else(|| {
        PolicyError::new("unknown-job", "active execution references an unknown job")
    })?;
    if job.active_execution.as_deref() != Some(&response.execution_id) {
        return Err(PolicyError::new(
            "stale-worker-execution",
            "worker completion is not the job's active execution",
        ));
    }

    state.active_executions.remove(&response.execution_id);
    state
        .completed_executions
        .insert(response.execution_id.clone(), response_digest);

    match response.outcome {
        PolicyWorkerOutcome::Completed(output) => {
            output.validate("worker.output")?;
            if let Some(next_stage) = binding.stage.next() {
                {
                    let job = state.jobs.get_mut(&binding.job_id).expect("job was checked");
                    job.current_stage = next_stage.clone();
                    job.status = JobStatus::Running;
                    job.active_execution = None;
                    job.latest_output = Some(output.clone());
                    job.checkpoint = response.checkpoint.clone();
                    job.terminal_code = None;
                }
                let dispatch = dispatch_stage(
                    state,
                    &binding.job_id,
                    next_stage,
                    output,
                    response.checkpoint,
                    1,
                )?;
                Ok(vec![PolicyCommand::DispatchWorker(dispatch)])
            } else {
                let job = state.jobs.get_mut(&binding.job_id).expect("job was checked");
                job.status = JobStatus::Completed;
                job.active_execution = None;
                job.latest_output = Some(output.clone());
                job.checkpoint = response.checkpoint;
                job.terminal_code = None;
                Ok(vec![PolicyCommand::EmitResponse(output)])
            }
        }
        PolicyWorkerOutcome::Blocked(request) => {
            request.validate("worker.blocked")?;
            let job = state.jobs.get_mut(&binding.job_id).expect("job was checked");
            job.status = JobStatus::Blocked;
            job.active_execution = None;
            job.checkpoint = response.checkpoint;
            job.terminal_code = Some("approval-required".to_string());
            Ok(vec![PolicyCommand::RequireApproval(request)])
        }
        PolicyWorkerOutcome::Rejected(failure) => {
            finish_failed_job(state, &binding.job_id, JobStatus::Rejected, failure)?;
            Ok(Vec::new())
        }
        PolicyWorkerOutcome::Failed(failure) => {
            finish_failed_job(state, &binding.job_id, JobStatus::Failed, failure)?;
            Ok(Vec::new())
        }
        PolicyWorkerOutcome::Cancelled => {
            let job = state.jobs.get_mut(&binding.job_id).expect("job was checked");
            job.status = JobStatus::Cancelled;
            job.active_execution = None;
            job.checkpoint = response.checkpoint;
            job.terminal_code = Some("cancelled".to_string());
            Ok(Vec::new())
        }
    }
}

fn finish_failed_job(
    state: &mut SupervisorStateV1,
    job_id: &str,
    status: JobStatus,
    failure: PolicyFailure,
) -> Result<(), PolicyError> {
    if failure.code.trim().is_empty() {
        return Err(PolicyError::new(
            "invalid-worker-failure",
            "worker failure code must not be blank",
        ));
    }
    if let Some(evidence) = &failure.evidence {
        evidence.validate("worker.failure.evidence")?;
    }
    let job = state.jobs.get_mut(job_id).expect("job was checked");
    job.status = status;
    job.active_execution = None;
    job.terminal_code = Some(failure.code);
    Ok(())
}

fn dispatch_stage(
    state: &mut SupervisorStateV1,
    job_id: &str,
    stage: Stage,
    input: BlobPointer,
    checkpoint: Option<BlobPointer>,
    attempt: u32,
) -> Result<DispatchSpec, PolicyError> {
    let worker_component = state
        .worker_components
        .get(&stage)
        .cloned()
        .ok_or_else(|| {
            PolicyError::new(
                "worker-not-bound",
                format!("{} worker is absent from the graph", stage.as_str()),
            )
        })?;
    let service_bindings = stage
        .service_families()
        .iter()
        .map(|family| {
            state
                .service_components
                .get(family)
                .cloned()
                .map(|component_digest| ServiceBindingValue {
                    family: *family,
                    component_digest,
                })
                .ok_or_else(|| {
                    PolicyError::new(
                        "service-not-bound",
                        format!("{} service is absent from the graph", family.as_str()),
                    )
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let execution_id = format!("{job_id}:{}:{attempt}", stage.as_str());
    let lease_digest = DigestValue::sha256(
        format!(
            "lease-v1|{}|{}|{}|{}",
            state.graph_digest.hex,
            job_id,
            stage.as_str(),
            attempt
        )
        .as_bytes(),
    );
    if state.active_executions.contains_key(&execution_id)
        || state.completed_executions.contains_key(&execution_id)
    {
        return Err(PolicyError::new(
            "duplicate-execution-id",
            format!("execution {execution_id} already exists"),
        ));
    }
    state.active_executions.insert(
        execution_id.clone(),
        ExecutionBinding {
            job_id: job_id.to_string(),
            stage: stage.clone(),
            attempt,
        },
    );
    let job = state.jobs.get_mut(job_id).ok_or_else(|| {
        PolicyError::new("unknown-job", "cannot dispatch a worker for an unknown job")
    })?;
    job.active_execution = Some(execution_id.clone());

    Ok(DispatchSpec {
        execution_id,
        job_id: job_id.to_string(),
        stage,
        worker_component,
        service_bindings,
        input,
        checkpoint,
        lease_digest,
        attempt,
    })
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut result = String::with_capacity(64);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in digest {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 0x0f) as usize] as char);
    }
    result
}

#[cfg(all(target_arch = "wasm32", not(test)))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}

// The `wasm32-wasip2` linker normally obtains this Canonical ABI allocator
// from `std`. This component is intentionally no-std, so it exports the same
// ABI over its private dlmalloc allocator without importing WASI.
#[cfg(all(target_arch = "wasm32", not(test)))]
#[unsafe(no_mangle)]
unsafe extern "C" fn cabi_realloc(
    old_pointer: *mut u8,
    old_length: usize,
    alignment: usize,
    new_length: usize,
) -> *mut u8 {
    use alloc::alloc::{Layout, alloc, dealloc, handle_alloc_error, realloc};

    let alignment = alignment.max(1);
    if old_pointer.is_null() {
        if new_length == 0 {
            return core::ptr::null_mut();
        }
        let layout = Layout::from_size_align(new_length, alignment)
            .unwrap_or_else(|_| core::arch::wasm32::unreachable());
        // SAFETY: `layout` is non-zero and valid; allocation failure traps.
        let pointer = unsafe { alloc(layout) };
        if pointer.is_null() {
            handle_alloc_error(layout);
        }
        pointer
    } else {
        let old_layout = Layout::from_size_align(old_length.max(1), alignment)
            .unwrap_or_else(|_| core::arch::wasm32::unreachable());
        if new_length == 0 {
            // SAFETY: the canonical ABI supplies the original pointer, size
            // and alignment from an earlier call to this allocator.
            unsafe { dealloc(old_pointer, old_layout) };
            core::ptr::null_mut()
        } else {
            // SAFETY: same canonical ABI provenance as the deallocation case.
            let pointer = unsafe { realloc(old_pointer, old_layout, new_length) };
            if pointer.is_null() {
                let new_layout = Layout::from_size_align(new_length, alignment)
                    .unwrap_or_else(|_| core::arch::wasm32::unreachable());
                handle_alloc_error(new_layout);
            }
            pointer
        }
    }
}

// `core` lowers slice/byte comparisons to the C ABI symbol on wasm. A no-std
// component supplies it locally so the linker does not pull in WASI libc.
#[cfg(all(target_arch = "wasm32", not(test)))]
#[unsafe(no_mangle)]
unsafe extern "C" fn memcmp(left: *const u8, right: *const u8, length: usize) -> i32 {
    for offset in 0..length {
        // SAFETY: the compiler-generated caller promises both regions are
        // readable for `length` bytes, as required by the C `memcmp` contract.
        let left_byte = unsafe { *left.add(offset) };
        // SAFETY: same precondition as above for the right-hand region.
        let right_byte = unsafe { *right.add(offset) };
        if left_byte != right_byte {
            return i32::from(left_byte) - i32::from(right_byte);
        }
    }
    0
}

#[cfg(target_arch = "wasm32")]
mod component {
    use super::*;

    wit_bindgen::generate!({
        path: "../../wit/wasm-biotic",
        world: "supervisor-reducer-component",
    });

    use exports::wasm_biotic::factory::supervisor_reducer::{
        Guest, Reduction, ReductionRequest, SupervisorCommand, SupervisorEvent,
    };
    use wasm_biotic::factory::capability_contract::{ServiceBinding, ServiceFamily};
    use wasm_biotic::factory::foundation::{
        BlobRef, Digest, Document, Failure, HashAlgorithm, Principal,
    };
    use wasm_biotic::factory::worker_workflow::{
        WorkerOutcome, WorkerRequest, WorkerResponse, WorkerRole,
    };

    struct SupervisorReducerComponent;

    impl Guest for SupervisorReducerComponent {
        fn reduce(request: ReductionRequest) -> Result<Reduction, Failure> {
            if request.state.schema != STATE_SCHEMA {
                return Err(component_failure(
                    "unsupported-state-schema",
                    format!("expected state document schema {STATE_SCHEMA}"),
                ));
            }
            if request.state.media_type != JSON_MEDIA_TYPE {
                return Err(component_failure(
                    "unsupported-state-media-type",
                    format!("expected state media type {JSON_MEDIA_TYPE}"),
                ));
            }

            let graph_digest = digest_from_component(request.graph_digest)?;
            let event = event_from_component(request.event)?;
            let reduction = reduce_policy(
                graph_digest,
                &request.state.body,
                request.event_sequence,
                event,
            )
            .map_err(policy_failure)?;

            Ok(Reduction {
                previous_state_digest: digest_to_component(reduction.previous_state_digest),
                next_state: Document {
                    schema: STATE_SCHEMA.to_string(),
                    media_type: JSON_MEDIA_TYPE.to_string(),
                    body: reduction.next_state_json,
                },
                commands: reduction
                    .commands
                    .into_iter()
                    .map(command_to_component)
                    .collect(),
                decision_digest: digest_to_component(reduction.decision_digest),
            })
        }
    }

    fn event_from_component(event: SupervisorEvent) -> Result<PolicyEvent, Failure> {
        match event {
            SupervisorEvent::JobSubmitted(source) => {
                Ok(PolicyEvent::JobSubmitted(blob_from_component(source)?))
            }
            SupervisorEvent::WorkerFinished(response) => Ok(PolicyEvent::WorkerFinished(
                worker_response_from_component(response)?,
            )),
            _ => Err(component_failure(
                "unsupported-event",
                "this reducer version accepts job-submitted and worker-finished events only",
            )),
        }
    }

    fn worker_response_from_component(
        response: WorkerResponse,
    ) -> Result<PolicyWorkerResponse, Failure> {
        let outcome = match response.outcome {
            WorkerOutcome::Completed(output) => {
                PolicyWorkerOutcome::Completed(blob_from_component(output)?)
            }
            WorkerOutcome::Blocked(request) => {
                PolicyWorkerOutcome::Blocked(blob_from_component(request)?)
            }
            WorkerOutcome::Rejected(failure) => {
                PolicyWorkerOutcome::Rejected(failure_from_component(failure)?)
            }
            WorkerOutcome::Failed(failure) => {
                PolicyWorkerOutcome::Failed(failure_from_component(failure)?)
            }
            WorkerOutcome::Cancelled => PolicyWorkerOutcome::Cancelled,
        };
        let mut proof_digests = Vec::new();
        for receipt in response.receipts {
            proof_digests.push(digest_from_component(receipt.outcome_digest)?);
        }
        for evidence in &response.evidence {
            proof_digests.push(digest_from_component(evidence.content_digest.clone())?);
        }
        Ok(PolicyWorkerResponse {
            execution_id: response.execution_id,
            worker_component: digest_from_component(response.worker_component)?,
            outcome,
            checkpoint: response.checkpoint.map(blob_from_component).transpose()?,
            proof_digests,
        })
    }

    fn failure_from_component(failure: Failure) -> Result<PolicyFailure, Failure> {
        Ok(PolicyFailure {
            code: failure.code,
            message: failure.message,
            retryable: failure.retryable,
            evidence: failure.evidence.map(blob_from_component).transpose()?,
        })
    }

    fn command_to_component(command: PolicyCommand) -> SupervisorCommand {
        match command {
            PolicyCommand::DispatchWorker(dispatch) => {
                SupervisorCommand::DispatchWorker(WorkerRequest {
                    execution_id: dispatch.execution_id,
                    job_id: dispatch.job_id,
                    role: role_to_component(dispatch.stage.clone()),
                    worker: Principal {
                        id: dispatch.stage.as_str().to_string(),
                        component_digest: digest_to_component(dispatch.worker_component),
                    },
                    service_bindings: dispatch
                        .service_bindings
                        .into_iter()
                        .map(service_binding_to_component)
                        .collect(),
                    input: blob_to_component(dispatch.input),
                    checkpoint: dispatch.checkpoint.map(blob_to_component),
                    lease_digest: digest_to_component(dispatch.lease_digest),
                    attempt: dispatch.attempt,
                    deadline_ms: None,
                })
            }
            PolicyCommand::RequireApproval(request) => {
                SupervisorCommand::RequireApproval(blob_to_component(request))
            }
            PolicyCommand::EmitResponse(response) => {
                SupervisorCommand::EmitResponse(blob_to_component(response))
            }
        }
    }

    fn role_to_component(stage: Stage) -> WorkerRole {
        match stage {
            Stage::Planner => WorkerRole::Planner,
            Stage::Builder => WorkerRole::Builder,
            Stage::Validator => WorkerRole::Validator,
            Stage::Reviewer => WorkerRole::Reviewer,
            Stage::Packager => WorkerRole::Packager,
            Stage::ContinuityWorker => WorkerRole::ContinuityWorker,
        }
    }

    fn service_binding_to_component(binding: ServiceBindingValue) -> ServiceBinding {
        ServiceBinding {
            family: match binding.family {
                ServiceFamilyValue::Build => ServiceFamily::Build,
                ServiceFamilyValue::Packaging => ServiceFamily::Packaging,
                ServiceFamilyValue::Validation => ServiceFamily::Validation,
                ServiceFamilyValue::Review => ServiceFamily::Review,
                ServiceFamilyValue::Continuity => ServiceFamily::Continuity,
                ServiceFamilyValue::Scheduling => ServiceFamily::Scheduling,
                ServiceFamilyValue::Operations => ServiceFamily::Operations,
            },
            component_digest: digest_to_component(binding.component_digest),
        }
    }

    fn digest_from_component(digest: Digest) -> Result<DigestValue, Failure> {
        let value = DigestValue {
            algorithm: match digest.algorithm {
                HashAlgorithm::Sha256 => "sha256".to_string(),
            },
            hex: digest.hex,
        };
        value
            .validate("component.digest")
            .map_err(policy_failure)?;
        Ok(value)
    }

    fn digest_to_component(digest: DigestValue) -> Digest {
        Digest {
            algorithm: HashAlgorithm::Sha256,
            hex: digest.hex,
        }
    }

    fn blob_from_component(reference: BlobRef) -> Result<BlobPointer, Failure> {
        let pointer = BlobPointer {
            content_digest: digest_from_component(reference.content_digest)?,
            size_bytes: reference.size_bytes,
            media_type: reference.media_type,
        };
        pointer.validate("component.blob").map_err(policy_failure)?;
        Ok(pointer)
    }

    fn blob_to_component(pointer: BlobPointer) -> BlobRef {
        BlobRef {
            content_digest: digest_to_component(pointer.content_digest),
            size_bytes: pointer.size_bytes,
            media_type: pointer.media_type,
        }
    }

    fn policy_failure(error: PolicyError) -> Failure {
        component_failure(error.code, error.message)
    }

    fn component_failure(code: impl Into<String>, message: impl Into<String>) -> Failure {
        Failure {
            code: code.into(),
            message: message.into(),
            retryable: false,
            evidence: None,
        }
    }

    export!(SupervisorReducerComponent);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(character: char) -> DigestValue {
        DigestValue {
            algorithm: "sha256".to_string(),
            hex: std::iter::repeat_n(character, 64).collect(),
        }
    }

    fn blob(character: char) -> BlobPointer {
        BlobPointer {
            content_digest: digest(character),
            size_bytes: 16,
            media_type: "application/octet-stream".to_string(),
        }
    }

    fn state() -> SupervisorStateV1 {
        let worker_components = Stage::ALL
            .into_iter()
            .zip(['1', '2', '3', '4', '5', '6'].into_iter().map(digest))
            .collect();
        let service_components = ServiceFamilyValue::ALL
            .into_iter()
            .zip(['7', '8', '9', '0', 'a', 'b', 'c'].into_iter().map(digest))
            .collect();
        SupervisorStateV1::empty(digest('a'), worker_components, service_components).unwrap()
    }

    fn dispatch(command: &PolicyCommand) -> &DispatchSpec {
        match command {
            PolicyCommand::DispatchWorker(dispatch) => dispatch,
            other => panic!("expected dispatch command, received {other:?}"),
        }
    }

    #[test]
    fn submission_is_deterministic_and_dispatches_exact_planner_digest() {
        let initial = state();
        let state_json = initial.to_json().unwrap();
        let source = blob('b');
        let first = reduce_policy(
            initial.graph_digest.clone(),
            &state_json,
            1,
            PolicyEvent::JobSubmitted(source.clone()),
        )
        .unwrap();
        let second = reduce_policy(
            initial.graph_digest.clone(),
            &state_json,
            1,
            PolicyEvent::JobSubmitted(source),
        )
        .unwrap();

        assert_eq!(first.next_state_json, second.next_state_json);
        assert_eq!(first.decision_digest, second.decision_digest);
        assert_eq!(first.commands, second.commands);
        let planner = dispatch(&first.commands[0]);
        assert_eq!(planner.stage, Stage::Planner);
        assert_eq!(planner.worker_component, digest('1'));
        assert_eq!(
            planner
                .service_bindings
                .iter()
                .map(|binding| binding.family)
                .collect::<Vec<_>>(),
            vec![ServiceFamilyValue::Build, ServiceFamilyValue::Scheduling]
        );
    }

    #[test]
    fn worker_completion_advances_to_builder_and_replay_is_a_noop() {
        let initial = state();
        let submitted = reduce_policy(
            initial.graph_digest.clone(),
            &initial.to_json().unwrap(),
            1,
            PolicyEvent::JobSubmitted(blob('b')),
        )
        .unwrap();
        let planner = dispatch(&submitted.commands[0]).clone();
        let response = PolicyWorkerResponse {
            execution_id: planner.execution_id,
            worker_component: planner.worker_component,
            outcome: PolicyWorkerOutcome::Completed(blob('c')),
            checkpoint: Some(blob('d')),
            proof_digests: vec![digest('e')],
        };
        let completed = reduce_policy(
            initial.graph_digest.clone(),
            &submitted.next_state_json,
            2,
            PolicyEvent::WorkerFinished(response.clone()),
        )
        .unwrap();
        assert_eq!(dispatch(&completed.commands[0]).stage, Stage::Builder);
        assert_eq!(dispatch(&completed.commands[0]).worker_component, digest('2'));

        let replay = reduce_policy(
            initial.graph_digest,
            &completed.next_state_json,
            3,
            PolicyEvent::WorkerFinished(response),
        )
        .unwrap();
        assert!(replay.commands.is_empty());
    }

    #[test]
    fn skipped_sequence_and_wrong_worker_digest_fail_closed() {
        let initial = state();
        let source = blob('b');
        let skipped = reduce_policy(
            initial.graph_digest.clone(),
            &initial.to_json().unwrap(),
            2,
            PolicyEvent::JobSubmitted(source.clone()),
        )
        .unwrap_err();
        assert_eq!(skipped.code, "event-sequence-mismatch");

        let submitted = reduce_policy(
            initial.graph_digest.clone(),
            &initial.to_json().unwrap(),
            1,
            PolicyEvent::JobSubmitted(source),
        )
        .unwrap();
        let planner = dispatch(&submitted.commands[0]);
        let mismatch = reduce_policy(
            initial.graph_digest,
            &submitted.next_state_json,
            2,
            PolicyEvent::WorkerFinished(PolicyWorkerResponse {
                execution_id: planner.execution_id.clone(),
                worker_component: digest('f'),
                outcome: PolicyWorkerOutcome::Completed(blob('c')),
                checkpoint: None,
                proof_digests: Vec::new(),
            }),
        )
        .unwrap_err();
        assert_eq!(mismatch.code, "worker-component-mismatch");
    }
}
