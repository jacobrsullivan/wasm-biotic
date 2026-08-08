//! Effect-free durable-record and byte-contract policy for the factory root.

extern crate alloc;

use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    string::{String, ToString},
    vec::Vec,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

pub const JSON_MEDIA_TYPE: &str = "application/json";
pub const SUPERVISOR_STATE_SCHEMA: &str = "wasm-biotic.supervisor-state.v1";
pub const SUBMIT_SCHEMA: &str = "wasm-biotic.factory-submit.v1";
pub const RECOVERY_SCHEMA: &str = "wasm-biotic.factory-recovery.v1";
pub const CONTROL_RECORD_SCHEMA: &str = "wasm-biotic.factory-control-record.v1";
pub const CONTROL_RECORD_MEDIA_TYPE: &str =
    "application/vnd.wasm-biotic.factory-control-record.v1+json";
pub const JOB_RESULT_SCHEMA: &str = "wasm-biotic.factory-job-result.v1";
pub const JOB_RESULT_MEDIA_TYPE: &str = "application/vnd.wasm-biotic.factory-job-result.v1+json";
pub const CAPABILITY_ROUTE_SCHEMA: &str = "wasm-biotic.capability-route.v1";
pub const ACTIVATION_STAGE_SCHEMA: &str = "wasm-biotic.activation-stage.v1";
pub const ACTIVATION_ROLLBACK_SCHEMA: &str = "wasm-biotic.activation-rollback.v1";
pub const AUDIT_APPEND_SCHEMA: &str = "wasm-biotic.audit-append.v1";
pub const MIGRATION_REQUEST_SCHEMA: &str = "wasm-biotic.migration-request.v1";
pub const FACTORY_UPGRADE_SCHEMA: &str = "wasm-biotic.factory-upgrade.v1";
pub const FACTORY_UPGRADE_RESULT_SCHEMA: &str = "wasm-biotic.factory-upgrade-result.v1";
pub const FACTORY_OBSERVATION_SCHEMA: &str = "wasm-biotic.factory-observation.v1";
pub const FACTORY_OBSERVATION_REQUEST_SCHEMA: &str = "wasm-biotic.factory-observation-request.v1";
pub const FACTORY_OBSERVATION_RESULT_SCHEMA: &str = "wasm-biotic.factory-observation-result.v1";
pub const API_VALUE_SCHEMA: &str = "wasm-biotic.factory-api-value.v1";
pub const NAMESPACE: &str = "wasm-biotic.factory-control.v1";
pub const FACTORY_GRAPH_SCHEMA: &str = "wasm-biotic.factory-graph.v1";
pub const FACTORY_WIT_PACKAGE: &str = "wasm-biotic:factory@0.1.0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyError {
    pub code: String,
    pub message: String,
}

impl PolicyError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DigestValue {
    pub algorithm: String,
    pub hex: String,
}

impl DigestValue {
    pub fn sha256(bytes: &[u8]) -> Self {
        let digest = Sha256::digest(bytes);
        let mut hex = String::with_capacity(64);
        const ALPHABET: &[u8; 16] = b"0123456789abcdef";
        for byte in digest {
            hex.push(ALPHABET[(byte >> 4) as usize] as char);
            hex.push(ALPHABET[(byte & 0x0f) as usize] as char);
        }
        Self {
            algorithm: "sha256".to_string(),
            hex,
        }
    }

    pub fn validate(&self, field: &str) -> Result<(), PolicyError> {
        if self.algorithm != "sha256"
            || self.hex.len() != 64
            || !self
                .hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(PolicyError::new(
                "invalid-digest",
                format!("{field} must be a lower-case SHA-256 digest"),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobValue {
    pub content_digest: DigestValue,
    pub size_bytes: u64,
    pub media_type: String,
}

impl BlobValue {
    pub fn validate(&self, field: &str) -> Result<(), PolicyError> {
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

    pub fn for_bytes(media_type: impl Into<String>, bytes: &[u8]) -> Self {
        Self {
            content_digest: DigestValue::sha256(bytes),
            size_bytes: bytes.len() as u64,
            media_type: media_type.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateDocumentRef {
    pub schema: String,
    pub blob: BlobValue,
}

impl StateDocumentRef {
    pub fn validate(&self, field: &str) -> Result<(), PolicyError> {
        if self.schema.trim().is_empty() {
            return Err(PolicyError::new(
                "invalid-document-schema",
                format!("{field}.schema must not be blank"),
            ));
        }
        self.blob.validate(&format!("{field}.blob"))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitEnvelopeV1 {
    pub schema: String,
    pub graph_digest: DigestValue,
    pub initial_state: StateDocumentRef,
    pub source: BlobValue,
}

impl SubmitEnvelopeV1 {
    pub fn decode(bytes: &[u8]) -> Result<Self, PolicyError> {
        let value: Self = decode_json(bytes, "invalid-submit-json")?;
        if value.schema != SUBMIT_SCHEMA {
            return Err(PolicyError::new(
                "unsupported-submit-schema",
                format!("expected {SUBMIT_SCHEMA}"),
            ));
        }
        value.graph_digest.validate("submit.graph_digest")?;
        value.initial_state.validate("submit.initial_state")?;
        if value.initial_state.schema != SUPERVISOR_STATE_SCHEMA
            || value.initial_state.blob.media_type != JSON_MEDIA_TYPE
        {
            return Err(PolicyError::new(
                "invalid-initial-state-document",
                "initial state must be a wasm-biotic.supervisor-state.v1 JSON document",
            ));
        }
        value.source.validate("submit.source")?;
        Ok(value)
    }

    pub fn job_id(&self) -> String {
        format!("job-sha256-{}", self.source.content_digest.hex)
    }
}

/// The exact graph identity material the factory-control component is allowed
/// to interpret. The substrate supplies only the content-addressed bytes; all
/// role and service meaning remains here in Wasm-owned policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum FactoryComponentKindValue {
    Root,
    SupervisorReducer,
    WorkerRouter,
    CapabilityRouter,
    PlannerWorker,
    BuilderWorker,
    ValidatorWorker,
    ReviewerWorker,
    PackagerWorker,
    ContinuityWorker,
    BuildService,
    PackagingService,
    ValidationService,
    ReviewService,
    ContinuityService,
    SchedulingService,
    OperationsService,
    ExchangeService,
    FactoryEvolution,
    StateMigration,
    ClosureEvaluator,
    AdmittedTool,
}

const REQUIRED_FACTORY_KINDS: [FactoryComponentKindValue; 21] = [
    FactoryComponentKindValue::Root,
    FactoryComponentKindValue::SupervisorReducer,
    FactoryComponentKindValue::WorkerRouter,
    FactoryComponentKindValue::CapabilityRouter,
    FactoryComponentKindValue::PlannerWorker,
    FactoryComponentKindValue::BuilderWorker,
    FactoryComponentKindValue::ValidatorWorker,
    FactoryComponentKindValue::ReviewerWorker,
    FactoryComponentKindValue::PackagerWorker,
    FactoryComponentKindValue::ContinuityWorker,
    FactoryComponentKindValue::BuildService,
    FactoryComponentKindValue::PackagingService,
    FactoryComponentKindValue::ValidationService,
    FactoryComponentKindValue::ReviewService,
    FactoryComponentKindValue::ContinuityService,
    FactoryComponentKindValue::SchedulingService,
    FactoryComponentKindValue::OperationsService,
    FactoryComponentKindValue::ExchangeService,
    FactoryComponentKindValue::FactoryEvolution,
    FactoryComponentKindValue::StateMigration,
    FactoryComponentKindValue::ClosureEvaluator,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum SubstratePrimitiveValue {
    BlobStore,
    TransactionStore,
    Clock,
    ComponentRunner,
    HttpTransport,
    KeyService,
    Activation,
    AuditLog,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActiveGraphGrantV1 {
    capability: SubstratePrimitiveValue,
    scope: String,
    constraints: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActiveGraphNodeV1 {
    id: String,
    kind: FactoryComponentKindValue,
    component_digest: String,
    world: String,
    exports: Vec<String>,
    grants: Vec<ActiveGraphGrantV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    state_schema: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
enum ActiveGraphBindingProviderV1 {
    Component { node: String, export: String },
    Host { capability: SubstratePrimitiveValue },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActiveGraphBindingV1 {
    consumer: String,
    #[serde(rename = "import")]
    import_name: String,
    provider: ActiveGraphBindingProviderV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActiveGraphInvocationV1 {
    consumer: String,
    target: String,
    export: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActiveGraphManifestV1 {
    schema: String,
    wit_package: String,
    root_node: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    previous_graph: Option<String>,
    state_schema: String,
    nodes: Vec<ActiveGraphNodeV1>,
    bindings: Vec<ActiveGraphBindingV1>,
    invocations: Vec<ActiveGraphInvocationV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    metadata: Option<String>,
}

impl ActiveGraphManifestV1 {
    fn decode(bytes: &[u8]) -> Result<Self, PolicyError> {
        let value: Value = serde_json::from_slice(bytes).map_err(|error| {
            PolicyError::new(
                "invalid-active-manifest-json",
                format!("active graph manifest is not JSON: {error}"),
            )
        })?;
        let mut canonical = Vec::new();
        write_canonical_value(&value, &mut canonical)?;
        if canonical != bytes {
            return Err(PolicyError::new(
                "noncanonical-active-manifest",
                "active graph manifest must use canonical JSON bytes",
            ));
        }
        let manifest: Self = serde_json::from_value(value).map_err(|error| {
            PolicyError::new(
                "invalid-active-manifest-schema",
                format!("active graph manifest has the wrong schema: {error}"),
            )
        })?;
        manifest.validate()?;
        Ok(manifest)
    }

    fn validate(&self) -> Result<(), PolicyError> {
        if self.schema != FACTORY_GRAPH_SCHEMA
            || self.wit_package != FACTORY_WIT_PACKAGE
            || self.state_schema != SUPERVISOR_STATE_SCHEMA
        {
            return Err(PolicyError::new(
                "unsupported-active-manifest",
                "active manifest must be the frozen factory-graph.v1 / factory@0.1.0 supervisor graph",
            ));
        }
        if let Some(previous) = &self.previous_graph {
            parse_content_digest(previous, "active_manifest.previous_graph")?;
        }
        if let Some(metadata) = &self.metadata {
            parse_content_digest(metadata, "active_manifest.metadata")?;
        }

        let mut ids = BTreeSet::new();
        let mut kinds = BTreeMap::<FactoryComponentKindValue, usize>::new();
        for node in &self.nodes {
            if node.id.trim().is_empty() || !ids.insert(node.id.as_str()) {
                return Err(PolicyError::new(
                    "invalid-active-manifest-node",
                    "active manifest node ids must be non-blank and unique",
                ));
            }
            parse_content_digest(
                &node.component_digest,
                &format!("active_manifest.nodes.{}.component_digest", node.id),
            )?;
            if node.world.trim().is_empty()
                || node.exports.iter().any(|export| export.trim().is_empty())
            {
                return Err(PolicyError::new(
                    "invalid-active-manifest-node",
                    format!(
                        "active manifest node {} has a blank world or export",
                        node.id
                    ),
                ));
            }
            for grant in &node.grants {
                if grant.scope.trim().is_empty() {
                    return Err(PolicyError::new(
                        "invalid-active-manifest-grant",
                        format!("active manifest node {} has a blank grant scope", node.id),
                    ));
                }
                parse_content_digest(
                    &grant.constraints,
                    &format!("active_manifest.nodes.{}.grant.constraints", node.id),
                )?;
            }
            *kinds.entry(node.kind).or_insert(0) += 1;
        }
        for kind in REQUIRED_FACTORY_KINDS {
            if kinds.get(&kind) != Some(&1) {
                return Err(PolicyError::new(
                    "incomplete-active-factory-graph",
                    "active manifest must contain exactly one of every required factory component kind",
                ));
            }
        }
        let root = self
            .nodes
            .iter()
            .find(|node| node.id == self.root_node)
            .ok_or_else(|| {
                PolicyError::new(
                    "invalid-active-manifest-root",
                    "active manifest root_node does not name a node",
                )
            })?;
        if root.kind != FactoryComponentKindValue::Root {
            return Err(PolicyError::new(
                "invalid-active-manifest-root",
                "active manifest root_node must name the root component",
            ));
        }
        Ok(())
    }

    fn digest_for_kind(&self, kind: FactoryComponentKindValue) -> Result<DigestValue, PolicyError> {
        let node = self
            .nodes
            .iter()
            .find(|node| node.kind == kind)
            .ok_or_else(|| {
                PolicyError::new(
                    "incomplete-active-factory-graph",
                    "active manifest omitted a required factory component kind",
                )
            })?;
        parse_content_digest(
            &node.component_digest,
            "active_manifest.node.component_digest",
        )
    }
}

/// Verifies that an upgrade is bound to the exact active graph, one exact
/// candidate graph and the active graph's declared migration component.
/// Native code supplies content-addressed bytes but does not interpret any of
/// these factory meanings.
pub fn validate_upgrade_manifests(
    active_manifest_bytes: &[u8],
    active_graph: &DigestValue,
    candidate_manifest_bytes: &[u8],
    candidate_graph: &DigestValue,
    migration_component: &DigestValue,
) -> Result<(), PolicyError> {
    active_graph.validate("upgrade.active_graph")?;
    candidate_graph.validate("upgrade.candidate_graph")?;
    migration_component.validate("upgrade.migration_component")?;
    if DigestValue::sha256(active_manifest_bytes) != *active_graph {
        return Err(PolicyError::new(
            "active-manifest-digest-mismatch",
            "active manifest bytes do not match the selected graph digest",
        ));
    }
    if DigestValue::sha256(candidate_manifest_bytes) != *candidate_graph {
        return Err(PolicyError::new(
            "candidate-manifest-digest-mismatch",
            "candidate manifest bytes do not match the requested graph digest",
        ));
    }
    let active = ActiveGraphManifestV1::decode(active_manifest_bytes)?;
    let candidate = ActiveGraphManifestV1::decode(candidate_manifest_bytes)?;
    if candidate_graph != active_graph
        && candidate.previous_graph.as_deref()
            != Some(format!("sha256:{}", active_graph.hex).as_str())
    {
        return Err(PolicyError::new(
            "successor-lineage-mismatch",
            "candidate manifest must name the exact active graph as its predecessor",
        ));
    }
    if active.digest_for_kind(FactoryComponentKindValue::StateMigration)? != *migration_component {
        return Err(PolicyError::new(
            "migration-component-mismatch",
            "upgrade must execute the state-migration component declared by the active graph",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InitialSupervisorStateV1 {
    schema: String,
    graph_digest: DigestValue,
    last_event_sequence: u64,
    worker_components: BTreeMap<String, DigestValue>,
    service_components: BTreeMap<String, DigestValue>,
    jobs: BTreeMap<String, Value>,
    active_executions: BTreeMap<String, Value>,
    completed_executions: BTreeMap<String, DigestValue>,
}

/// Proves that a new job and its caller-supplied initial state are bound to
/// the exact graph selected by the substrate. The host exposes identity only;
/// this Wasm-owned policy assigns worker and service meaning to manifest kinds.
pub fn validate_active_submission(
    active_manifest_bytes: &[u8],
    active_manifest_digest: &DigestValue,
    initial_state_bytes: &[u8],
    submit: &SubmitEnvelopeV1,
) -> Result<(), PolicyError> {
    active_manifest_digest.validate("active_manifest.content_digest")?;
    let actual_manifest_digest = DigestValue::sha256(active_manifest_bytes);
    if &actual_manifest_digest != active_manifest_digest {
        return Err(PolicyError::new(
            "active-manifest-digest-mismatch",
            "active manifest bytes do not match the substrate's content address",
        ));
    }
    if submit.graph_digest != *active_manifest_digest {
        return Err(PolicyError::new(
            "inactive-submit-graph",
            "submitted graph digest is not the graph currently selected by the substrate",
        ));
    }

    let manifest = ActiveGraphManifestV1::decode(active_manifest_bytes)?;
    let state: InitialSupervisorStateV1 =
        decode_json(initial_state_bytes, "invalid-initial-state-json")?;
    if state.schema != SUPERVISOR_STATE_SCHEMA
        || state.last_event_sequence != 0
        || !state.jobs.is_empty()
        || !state.active_executions.is_empty()
        || !state.completed_executions.is_empty()
    {
        return Err(PolicyError::new(
            "noninitial-supervisor-state",
            "job submission requires an empty sequence-zero supervisor state",
        ));
    }
    state.graph_digest.validate("initial_state.graph_digest")?;
    if state.graph_digest != submit.graph_digest {
        return Err(PolicyError::new(
            "initial-state-graph-mismatch",
            "initial supervisor state is not bound to the submitted active graph",
        ));
    }

    validate_component_map(
        &state.worker_components,
        &[
            ("planner", FactoryComponentKindValue::PlannerWorker),
            ("builder", FactoryComponentKindValue::BuilderWorker),
            ("validator", FactoryComponentKindValue::ValidatorWorker),
            ("reviewer", FactoryComponentKindValue::ReviewerWorker),
            ("packager", FactoryComponentKindValue::PackagerWorker),
            (
                "continuity-worker",
                FactoryComponentKindValue::ContinuityWorker,
            ),
        ],
        &manifest,
        "worker",
    )?;
    validate_component_map(
        &state.service_components,
        &[
            ("build", FactoryComponentKindValue::BuildService),
            ("packaging", FactoryComponentKindValue::PackagingService),
            ("validation", FactoryComponentKindValue::ValidationService),
            ("review", FactoryComponentKindValue::ReviewService),
            ("continuity", FactoryComponentKindValue::ContinuityService),
            ("scheduling", FactoryComponentKindValue::SchedulingService),
            ("operations", FactoryComponentKindValue::OperationsService),
        ],
        &manifest,
        "service",
    )
}

fn validate_component_map(
    actual: &BTreeMap<String, DigestValue>,
    expected: &[(&str, FactoryComponentKindValue)],
    manifest: &ActiveGraphManifestV1,
    class: &str,
) -> Result<(), PolicyError> {
    if actual.len() != expected.len() {
        return Err(PolicyError::new(
            format!("initial-state-{class}-binding-mismatch"),
            format!("initial state must bind exactly the active graph's {class} components"),
        ));
    }
    for (name, kind) in expected {
        let value = actual.get(*name).ok_or_else(|| {
            PolicyError::new(
                format!("initial-state-{class}-binding-mismatch"),
                format!("initial state omitted the {name} {class} binding"),
            )
        })?;
        value.validate(&format!("initial_state.{class}_components.{name}"))?;
        if value != &manifest.digest_for_kind(*kind)? {
            return Err(PolicyError::new(
                format!("initial-state-{class}-binding-mismatch"),
                format!("initial state {name} binding is not the active manifest component"),
            ));
        }
    }
    Ok(())
}

fn parse_content_digest(value: &str, field: &str) -> Result<DigestValue, PolicyError> {
    let hex = value.strip_prefix("sha256:").ok_or_else(|| {
        PolicyError::new(
            "invalid-content-digest",
            format!("{field} must use the sha256:<hex> content-address form"),
        )
    })?;
    let digest = DigestValue {
        algorithm: "sha256".to_string(),
        hex: hex.to_string(),
    };
    digest.validate(field)?;
    Ok(digest)
}

fn write_canonical_value(value: &Value, output: &mut Vec<u8>) -> Result<(), PolicyError> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(value) => output.extend_from_slice(if *value { b"true" } else { b"false" }),
        Value::Number(number) => output.extend_from_slice(number.to_string().as_bytes()),
        Value::String(string) => {
            let encoded = serde_json::to_vec(string).map_err(|error| {
                PolicyError::new(
                    "active-manifest-canonicalization-failed",
                    format!("could not encode manifest string: {error}"),
                )
            })?;
            output.extend_from_slice(&encoded);
        }
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_value(value, output)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            output.push(b'{');
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort();
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_value(&Value::String(key.clone()), output)?;
                output.push(b':');
                write_canonical_value(&values[key], output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryEnvelopeV1 {
    pub schema: String,
    pub job_id: String,
}

impl RecoveryEnvelopeV1 {
    pub fn decode(bytes: &[u8]) -> Result<Self, PolicyError> {
        let value: Self = decode_json(bytes, "invalid-recovery-json")?;
        if value.schema != RECOVERY_SCHEMA || value.job_id.trim().is_empty() {
            return Err(PolicyError::new(
                "invalid-recovery-request",
                format!("expected {RECOVERY_SCHEMA} and a non-blank job_id"),
            ));
        }
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WorkerRoleValue {
    Planner,
    Builder,
    Validator,
    Reviewer,
    Packager,
    ContinuityWorker,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalValue {
    pub id: String,
    pub component_digest: DigestValue,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceBindingValue {
    pub family: ServiceFamilyValue,
    pub component_digest: DigestValue,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerRequestValue {
    pub execution_id: String,
    pub job_id: String,
    pub role: WorkerRoleValue,
    pub worker: PrincipalValue,
    pub service_bindings: Vec<ServiceBindingValue>,
    pub input: BlobValue,
    pub checkpoint: Option<BlobValue>,
    pub lease_digest: DigestValue,
    pub attempt: u32,
    pub deadline_ms: Option<u64>,
}

impl WorkerRequestValue {
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.execution_id.trim().is_empty()
            || self.job_id.trim().is_empty()
            || self.worker.id.trim().is_empty()
            || self.attempt == 0
        {
            return Err(PolicyError::new(
                "invalid-worker-request",
                "execution, job, worker and non-zero attempt are required",
            ));
        }
        self.worker
            .component_digest
            .validate("worker.component_digest")?;
        self.lease_digest.validate("worker.lease_digest")?;
        self.input.validate("worker.input")?;
        if let Some(checkpoint) = &self.checkpoint {
            checkpoint.validate("worker.checkpoint")?;
        }
        for (index, binding) in self.service_bindings.iter().enumerate() {
            binding
                .component_digest
                .validate(&format!("worker.service_bindings.{index}"))?;
        }
        let actual = self
            .service_bindings
            .iter()
            .map(|binding| binding.family)
            .collect::<Vec<_>>();
        let expected: &[ServiceFamilyValue] = match self.role {
            WorkerRoleValue::Planner => {
                &[ServiceFamilyValue::Build, ServiceFamilyValue::Scheduling]
            }
            WorkerRoleValue::Builder => &[ServiceFamilyValue::Build],
            WorkerRoleValue::Validator => &[ServiceFamilyValue::Validation],
            WorkerRoleValue::Reviewer => &[ServiceFamilyValue::Review],
            WorkerRoleValue::Packager => &[ServiceFamilyValue::Packaging],
            WorkerRoleValue::ContinuityWorker => &[ServiceFamilyValue::Continuity],
        };
        if actual != expected {
            return Err(PolicyError::new(
                "service-binding-mismatch",
                "dispatch must contain exactly the role's ordered graph service bindings",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailureValue {
    pub code: String,
    pub message: String,
    pub retryable: bool,
    pub evidence: Option<BlobValue>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectReceiptValue {
    pub receipt_id: String,
    pub request_digest: DigestValue,
    pub executor_digest: DigestValue,
    pub started_at_ms: u64,
    pub finished_at_ms: u64,
    pub outcome_digest: DigestValue,
    pub audit_sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WorkerOutcomeValue {
    Completed(BlobValue),
    Blocked(BlobValue),
    Rejected(FailureValue),
    Failed(FailureValue),
    Cancelled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerResponseValue {
    pub execution_id: String,
    pub worker_component: DigestValue,
    pub outcome: WorkerOutcomeValue,
    pub checkpoint: Option<BlobValue>,
    pub receipts: Vec<EffectReceiptValue>,
    pub evidence: Vec<BlobValue>,
}

impl WorkerResponseValue {
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.execution_id.trim().is_empty() {
            return Err(PolicyError::new(
                "invalid-worker-response",
                "worker response execution_id must not be blank",
            ));
        }
        self.worker_component
            .validate("response.worker_component")?;
        match &self.outcome {
            WorkerOutcomeValue::Completed(blob) | WorkerOutcomeValue::Blocked(blob) => {
                blob.validate("response.outcome")?;
            }
            WorkerOutcomeValue::Rejected(failure) | WorkerOutcomeValue::Failed(failure) => {
                if failure.code.trim().is_empty() {
                    return Err(PolicyError::new(
                        "invalid-worker-failure",
                        "worker failure code must not be blank",
                    ));
                }
                if let Some(evidence) = &failure.evidence {
                    evidence.validate("response.failure.evidence")?;
                }
            }
            WorkerOutcomeValue::Cancelled => {}
        }
        if let Some(checkpoint) = &self.checkpoint {
            checkpoint.validate("response.checkpoint")?;
        }
        for (index, receipt) in self.receipts.iter().enumerate() {
            receipt
                .request_digest
                .validate(&format!("response.receipts.{index}.request_digest"))?;
            receipt
                .executor_digest
                .validate(&format!("response.receipts.{index}.executor_digest"))?;
            receipt
                .outcome_digest
                .validate(&format!("response.receipts.{index}.outcome_digest"))?;
        }
        for (index, evidence) in self.evidence.iter().enumerate() {
            evidence.validate(&format!("response.evidence.{index}"))?;
        }
        Ok(())
    }

    pub fn validate_for(&self, request: &WorkerRequestValue) -> Result<(), PolicyError> {
        request.validate()?;
        self.validate()?;
        if self.execution_id != request.execution_id
            || self.worker_component != request.worker.component_digest
        {
            return Err(PolicyError::new(
                "worker-router-identity-violation",
                "worker response does not match its graph-bound dispatch",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
// The value mirrors the closed WIT command union. Boxing only one variant
// would add a heap-shaped implementation detail to this component ABI model.
#[allow(clippy::large_enum_variant)]
pub enum SupervisorCommandValue {
    DispatchWorker(WorkerRequestValue),
    EmitResponse(BlobValue),
    RequireApproval(BlobValue),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutboxValue {
    DispatchPending(WorkerRequestValue),
    WorkerReturned(WorkerResponseValue),
    EmitPending(BlobValue),
    ApprovalPending(BlobValue),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ControlStatus {
    Running,
    Blocked,
    Completed,
    Rejected,
    Failed,
    Cancelled,
}

impl ControlStatus {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Rejected | Self::Failed | Self::Cancelled
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlRecordV1 {
    pub schema: String,
    pub job_id: String,
    pub graph_digest: DigestValue,
    pub source: BlobValue,
    pub supervisor_state: StateDocumentRef,
    pub event_sequence: u64,
    pub decision_digest: Option<DigestValue>,
    pub outbox: Option<OutboxValue>,
    pub status: ControlStatus,
    pub result: Option<BlobValue>,
}

impl ControlRecordV1 {
    pub fn initial(submit: &SubmitEnvelopeV1) -> Self {
        Self {
            schema: CONTROL_RECORD_SCHEMA.to_string(),
            job_id: submit.job_id(),
            graph_digest: submit.graph_digest.clone(),
            source: submit.source.clone(),
            supervisor_state: submit.initial_state.clone(),
            event_sequence: 0,
            decision_digest: None,
            outbox: None,
            status: ControlStatus::Running,
            result: None,
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PolicyError> {
        let value: Self = decode_json(bytes, "invalid-control-record-json")?;
        value.validate()?;
        Ok(value)
    }

    pub fn encode(&self) -> Result<Vec<u8>, PolicyError> {
        self.validate()?;
        encode_json(self, "control-record-serialization-failed")
    }

    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.schema != CONTROL_RECORD_SCHEMA
            || self.job_id != format!("job-sha256-{}", self.source.content_digest.hex)
        {
            return Err(PolicyError::new(
                "invalid-control-record",
                "record schema or content-derived job identity is invalid",
            ));
        }
        self.graph_digest.validate("record.graph_digest")?;
        self.source.validate("record.source")?;
        self.supervisor_state.validate("record.supervisor_state")?;
        if let Some(digest) = &self.decision_digest {
            digest.validate("record.decision_digest")?;
        }
        if let Some(result) = &self.result {
            result.validate("record.result")?;
        }
        match &self.outbox {
            Some(OutboxValue::DispatchPending(request)) => request.validate()?,
            Some(OutboxValue::WorkerReturned(response)) => response.validate()?,
            Some(OutboxValue::EmitPending(blob)) | Some(OutboxValue::ApprovalPending(blob)) => {
                blob.validate("record.outbox")?;
            }
            None => {}
        }
        if self.status.is_terminal() && self.result.is_none() {
            return Err(PolicyError::new(
                "terminal-result-missing",
                "terminal job record must reference an inspectable result",
            ));
        }
        Ok(())
    }

    pub fn journal_reduction(
        &mut self,
        next_state: StateDocumentRef,
        next_sequence: u64,
        decision_digest: DigestValue,
        command: Option<SupervisorCommandValue>,
    ) -> Result<(), PolicyError> {
        if self.outbox.is_some() {
            return Err(PolicyError::new(
                "outbox-not-drained",
                "cannot apply a reducer transition over an undrained outbox",
            ));
        }
        if next_sequence
            != self.event_sequence.checked_add(1).ok_or_else(|| {
                PolicyError::new("event-sequence-exhausted", "event sequence cannot advance")
            })?
        {
            return Err(PolicyError::new(
                "event-sequence-mismatch",
                "reducer transition must advance exactly one event",
            ));
        }
        next_state.validate("reduction.next_state")?;
        decision_digest.validate("reduction.decision_digest")?;
        self.supervisor_state = next_state;
        self.event_sequence = next_sequence;
        self.decision_digest = Some(decision_digest);
        self.outbox = command.map(|command| match command {
            SupervisorCommandValue::DispatchWorker(request) => {
                OutboxValue::DispatchPending(request)
            }
            SupervisorCommandValue::EmitResponse(output) => OutboxValue::EmitPending(output),
            SupervisorCommandValue::RequireApproval(request) => {
                OutboxValue::ApprovalPending(request)
            }
        });
        Ok(())
    }

    pub fn record_worker_return(
        &mut self,
        response: WorkerResponseValue,
    ) -> Result<(), PolicyError> {
        let request = match &self.outbox {
            Some(OutboxValue::DispatchPending(request)) => request,
            _ => {
                return Err(PolicyError::new(
                    "dispatch-not-pending",
                    "worker return can only replace a journalled pending dispatch",
                ));
            }
        };
        response.validate_for(request)?;
        self.outbox = Some(OutboxValue::WorkerReturned(response));
        Ok(())
    }

    pub fn cancellation_response(
        &self,
        reason: BlobValue,
    ) -> Result<WorkerResponseValue, PolicyError> {
        reason.validate("cancel.reason")?;
        let request = match &self.outbox {
            Some(OutboxValue::DispatchPending(request)) => request,
            _ => {
                return Err(PolicyError::new(
                    "cancel-not-pending",
                    "bounded v1 cancellation requires a journalled pending dispatch",
                ));
            }
        };
        Ok(WorkerResponseValue {
            execution_id: request.execution_id.clone(),
            worker_component: request.worker.component_digest.clone(),
            outcome: WorkerOutcomeValue::Cancelled,
            checkpoint: request.checkpoint.clone(),
            receipts: Vec::new(),
            evidence: alloc::vec![reason],
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobResultV1 {
    pub schema: String,
    pub job_id: String,
    pub status: ControlStatus,
    pub output: Option<BlobValue>,
    pub failure: Option<FailureValue>,
    pub supervisor_state: StateDocumentRef,
    pub event_sequence: u64,
}

impl JobResultV1 {
    pub fn from_worker(
        record: &ControlRecordV1,
        response: &WorkerResponseValue,
    ) -> Result<Option<Self>, PolicyError> {
        let (status, output, failure) = match &response.outcome {
            WorkerOutcomeValue::Completed(output) => match &record.outbox {
                Some(OutboxValue::DispatchPending(_)) => return Ok(None),
                Some(OutboxValue::EmitPending(emitted)) if emitted == output => {
                    (ControlStatus::Completed, Some(output.clone()), None)
                }
                _ => {
                    return Err(PolicyError::new(
                        "invalid-completed-reduction",
                        "completed worker must dispatch the next stage or emit that exact output",
                    ));
                }
            },
            WorkerOutcomeValue::Blocked(request) => {
                if !matches!(&record.outbox, Some(OutboxValue::ApprovalPending(value)) if value == request)
                {
                    return Err(PolicyError::new(
                        "invalid-blocked-reduction",
                        "blocked worker must journal an approval request for the exact blocking blob",
                    ));
                }
                (ControlStatus::Blocked, Some(request.clone()), None)
            }
            WorkerOutcomeValue::Rejected(failure) => {
                if record.outbox.is_some() {
                    return Err(PolicyError::new(
                        "invalid-rejected-reduction",
                        "rejected worker must not emit an effect command",
                    ));
                }
                (ControlStatus::Rejected, None, Some(failure.clone()))
            }
            WorkerOutcomeValue::Failed(failure) => {
                if record.outbox.is_some() {
                    return Err(PolicyError::new(
                        "invalid-failed-reduction",
                        "failed worker must not emit an effect command",
                    ));
                }
                (ControlStatus::Failed, None, Some(failure.clone()))
            }
            WorkerOutcomeValue::Cancelled => {
                if record.outbox.is_some() {
                    return Err(PolicyError::new(
                        "invalid-cancelled-reduction",
                        "cancelled worker must not emit an effect command",
                    ));
                }
                (ControlStatus::Cancelled, None, None)
            }
        };
        Ok(Some(Self {
            schema: JOB_RESULT_SCHEMA.to_string(),
            job_id: record.job_id.clone(),
            status,
            output,
            failure,
            supervisor_state: record.supervisor_state.clone(),
            event_sequence: record.event_sequence,
        }))
    }

    pub fn encode(&self) -> Result<Vec<u8>, PolicyError> {
        encode_json(self, "job-result-serialization-failed")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthorityValue {
    Observe,
    LocalMutate,
    AutomationControl,
    PromotionControl,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OperationValue {
    WorkspaceOpen,
    WorkspaceSnapshot,
    WorkspacePatch,
    CandidateBuild,
    CommandExecute,
    PackagePublish,
    PackageVerify,
    ValidationProve,
    ValidationCompare,
    ReviewCandidate,
    EvidencePublish,
    EvidenceResolve,
    ScheduleJob,
    DeploymentInitialize,
    DeploymentActivate,
    DeploymentObserve,
    DeploymentRollback,
    OperationsInspect,
    FactoryExecute,
    FactoryProviderProposal,
    FactoryShadow,
    FactoryInitialize,
    FactoryStateMigrate,
    FactoryActivate,
    FactoryObserve,
    FactoryRollback,
    FactoryInspect,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalProofValue {
    pub approval_id: String,
    pub decision_digest: DigestValue,
    pub approver: String,
    pub recorded_at_ms: u64,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRequestValue {
    pub request_id: String,
    pub job_id: String,
    pub caller: PrincipalValue,
    pub service_component: DigestValue,
    pub family: ServiceFamilyValue,
    pub operation: OperationValue,
    pub input: BlobValue,
    pub authority: AuthorityValue,
    pub approval: Option<ApprovalProofValue>,
    pub deadline_ms: Option<u64>,
    pub idempotency_key: DigestValue,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRouteEnvelopeV1 {
    pub schema: String,
    pub request: CapabilityRequestValue,
}

impl CapabilityRouteEnvelopeV1 {
    pub fn decode(bytes: &[u8]) -> Result<Self, PolicyError> {
        let value: Self = decode_json(bytes, "invalid-capability-route-json")?;
        if value.schema != CAPABILITY_ROUTE_SCHEMA {
            return Err(PolicyError::new(
                "unsupported-capability-route-schema",
                format!("expected {CAPABILITY_ROUTE_SCHEMA}"),
            ));
        }
        value
            .request
            .service_component
            .validate("capability.service_component")?;
        value
            .request
            .caller
            .component_digest
            .validate("capability.caller.component_digest")?;
        value.request.input.validate("capability.input")?;
        value
            .request
            .idempotency_key
            .validate("capability.idempotency_key")?;
        Ok(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceOutcomeValue {
    Succeeded(BlobValue),
    Rejected(FailureValue),
    Failed(FailureValue),
    Cancelled,
    Exhausted(FailureValue),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityResponseValue {
    pub request_id: String,
    pub service_component: DigestValue,
    pub outcome: ServiceOutcomeValue,
    pub effect_receipts: Vec<EffectReceiptValue>,
    pub evidence: Vec<BlobValue>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationRequestValue {
    pub activation_id: String,
    pub graph_manifest: BlobValue,
    pub expected_active_graph: Option<DigestValue>,
    pub expected_active_state: Option<BlobValue>,
    pub state_migration: Option<DigestValue>,
    pub migrated_state: Option<BlobValue>,
    pub idempotency_key: DigestValue,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationStageEnvelopeV1 {
    pub schema: String,
    pub request: ActivationRequestValue,
}

impl ActivationStageEnvelopeV1 {
    pub fn decode(bytes: &[u8]) -> Result<Self, PolicyError> {
        let value: Self = decode_json(bytes, "invalid-activation-stage-json")?;
        if value.schema != ACTIVATION_STAGE_SCHEMA {
            return Err(PolicyError::new(
                "unsupported-activation-stage-schema",
                format!("expected {ACTIVATION_STAGE_SCHEMA}"),
            ));
        }
        value
            .request
            .graph_manifest
            .validate("activation.graph_manifest")?;
        value
            .request
            .idempotency_key
            .validate("activation.idempotency_key")?;
        if let Some(digest) = &value.request.expected_active_graph {
            digest.validate("activation.expected_active_graph")?;
        }
        if let Some(digest) = &value.request.state_migration {
            digest.validate("activation.state_migration")?;
        }
        if let Some(reference) = &value.request.expected_active_state {
            reference.validate("activation.expected_active_state")?;
        }
        if let Some(reference) = &value.request.migrated_state {
            reference.validate("activation.migrated_state")?;
        }
        if value.request.state_migration.is_some() != value.request.migrated_state.is_some() {
            return Err(PolicyError::new(
                "incomplete-migration-binding",
                "state_migration and migrated_state must be supplied together",
            ));
        }
        Ok(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationRollbackEnvelopeV1 {
    pub schema: String,
    pub target_graph: DigestValue,
}

impl ActivationRollbackEnvelopeV1 {
    pub fn decode(bytes: &[u8]) -> Result<Self, PolicyError> {
        let value: Self = decode_json(bytes, "invalid-activation-rollback-json")?;
        if value.schema != ACTIVATION_ROLLBACK_SCHEMA {
            return Err(PolicyError::new(
                "unsupported-activation-rollback-schema",
                format!("expected {ACTIVATION_ROLLBACK_SCHEMA}"),
            ));
        }
        value.target_graph.validate("activation.target_graph")?;
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ActivationStateValue {
    Staged,
    Active,
    RolledBack,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationStatusValue {
    pub activation_id: String,
    pub state: ActivationStateValue,
    pub active_graph: Option<DigestValue>,
    pub active_state: Option<BlobValue>,
    pub receipt: Option<EffectReceiptValue>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEntryValue {
    pub event_id: String,
    pub actor: PrincipalValue,
    pub event_type: String,
    pub payload: BlobValue,
    pub previous_entry: Option<DigestValue>,
    pub occurred_at_ms: u64,
    pub idempotency_key: DigestValue,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditAppendEnvelopeV1 {
    pub schema: String,
    pub entry: AuditEntryValue,
}

impl AuditAppendEnvelopeV1 {
    pub fn decode(bytes: &[u8]) -> Result<Self, PolicyError> {
        let value: Self = decode_json(bytes, "invalid-audit-append-json")?;
        if value.schema != AUDIT_APPEND_SCHEMA {
            return Err(PolicyError::new(
                "unsupported-audit-append-schema",
                format!("expected {AUDIT_APPEND_SCHEMA}"),
            ));
        }
        value
            .entry
            .actor
            .component_digest
            .validate("audit.actor.component_digest")?;
        value.entry.payload.validate("audit.payload")?;
        value
            .entry
            .idempotency_key
            .validate("audit.idempotency_key")?;
        if let Some(digest) = &value.entry.previous_entry {
            digest.validate("audit.previous_entry")?;
        }
        Ok(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditReceiptValue {
    pub sequence: u64,
    pub entry_digest: DigestValue,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationRequestEnvelopeV1 {
    pub schema: String,
    pub previous_state: StateDocumentRef,
    pub target_graph: DigestValue,
    pub target_manifest: BlobValue,
}

impl MigrationRequestEnvelopeV1 {
    pub fn decode(bytes: &[u8]) -> Result<Self, PolicyError> {
        let value: Self = decode_json(bytes, "invalid-migration-request-json")?;
        if value.schema != MIGRATION_REQUEST_SCHEMA {
            return Err(PolicyError::new(
                "unsupported-migration-request-schema",
                format!("expected {MIGRATION_REQUEST_SCHEMA}"),
            ));
        }
        value.previous_state.validate("migration.previous_state")?;
        value.target_graph.validate("migration.target_graph")?;
        value
            .target_manifest
            .validate("migration.target_manifest")?;
        Ok(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactoryUpgradeEnvelopeV1 {
    pub schema: String,
    pub activation_id: String,
    pub candidate_graph: BlobValue,
    pub expected_active_graph: DigestValue,
    pub expected_active_state: Option<BlobValue>,
    pub previous_state: StateDocumentRef,
    pub migration_component: DigestValue,
    pub idempotency_key: DigestValue,
}

impl FactoryUpgradeEnvelopeV1 {
    pub fn decode(bytes: &[u8]) -> Result<Self, PolicyError> {
        let value: Self = decode_json(bytes, "invalid-factory-upgrade-json")?;
        if value.schema != FACTORY_UPGRADE_SCHEMA || value.activation_id.trim().is_empty() {
            return Err(PolicyError::new(
                "unsupported-factory-upgrade",
                "upgrade schema and activation identity must be exact",
            ));
        }
        value.candidate_graph.validate("upgrade.candidate_graph")?;
        value
            .expected_active_graph
            .validate("upgrade.expected_active_graph")?;
        if let Some(reference) = &value.expected_active_state {
            reference.validate("upgrade.expected_active_state")?;
        }
        value.previous_state.validate("upgrade.previous_state")?;
        value
            .migration_component
            .validate("upgrade.migration_component")?;
        value.idempotency_key.validate("upgrade.idempotency_key")?;
        let material = encode_json(
            &(
                value.schema.as_str(),
                value.activation_id.as_str(),
                &value.candidate_graph,
                &value.expected_active_graph,
                &value.expected_active_state,
                &value.previous_state,
                &value.migration_component,
            ),
            "factory-upgrade-decision-serialization-failed",
        )?;
        if value.idempotency_key != DigestValue::sha256(&material) {
            return Err(PolicyError::new(
                "factory-upgrade-idempotency-mismatch",
                "upgrade idempotency key must bind every decision field",
            ));
        }
        Ok(value)
    }

    pub fn computed_idempotency_key(&self) -> Result<DigestValue, PolicyError> {
        let material = encode_json(
            &(
                self.schema.as_str(),
                self.activation_id.as_str(),
                &self.candidate_graph,
                &self.expected_active_graph,
                &self.expected_active_state,
                &self.previous_state,
                &self.migration_component,
            ),
            "factory-upgrade-decision-serialization-failed",
        )?;
        Ok(DigestValue::sha256(&material))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactoryUpgradeResultV1 {
    pub schema: String,
    pub activation_id: String,
    pub previous_graph: DigestValue,
    pub target_graph: DigestValue,
    pub previous_state: Option<BlobValue>,
    pub migrated_state: BlobValue,
    pub migration_component: DigestValue,
    pub staged: ActivationStatusValue,
    pub committed: ActivationStatusValue,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FactoryHealth {
    Healthy,
    Unhealthy,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactoryObservationV1 {
    pub schema: String,
    pub graph_digest: DigestValue,
    pub health: FactoryHealth,
    pub evidence: Vec<BlobValue>,
}

impl FactoryObservationV1 {
    pub fn decode(bytes: &[u8]) -> Result<Self, PolicyError> {
        let value: Self = decode_json(bytes, "invalid-factory-observation-json")?;
        if value.schema != FACTORY_OBSERVATION_SCHEMA {
            return Err(PolicyError::new(
                "unsupported-factory-observation",
                format!("expected {FACTORY_OBSERVATION_SCHEMA}"),
            ));
        }
        value.graph_digest.validate("observation.graph_digest")?;
        for evidence in &value.evidence {
            evidence.validate("observation.evidence")?;
        }
        Ok(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactoryObservationRequestV1 {
    pub schema: String,
    pub activation_id: String,
    pub expected_active_graph: DigestValue,
    pub incumbent_graph: DigestValue,
    pub observation: BlobValue,
}

impl FactoryObservationRequestV1 {
    pub fn decode(bytes: &[u8]) -> Result<Self, PolicyError> {
        let value: Self = decode_json(bytes, "invalid-factory-observation-request-json")?;
        if value.schema != FACTORY_OBSERVATION_REQUEST_SCHEMA
            || value.activation_id.trim().is_empty()
        {
            return Err(PolicyError::new(
                "unsupported-factory-observation-request",
                "observation request schema and activation identity must be exact",
            ));
        }
        value
            .expected_active_graph
            .validate("observation.expected_active_graph")?;
        value
            .incumbent_graph
            .validate("observation.incumbent_graph")?;
        value.observation.validate("observation.document")?;
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FactoryObservationAction {
    Retained,
    RolledBack,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactoryObservationResultV1 {
    pub schema: String,
    pub activation_id: String,
    pub observed_graph: DigestValue,
    pub action: FactoryObservationAction,
    pub status: ActivationStatusValue,
    pub observation: BlobValue,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiValue<T> {
    pub schema: String,
    pub value: T,
}

pub fn encode_api_value<T: Serialize>(value: T) -> Result<Vec<u8>, PolicyError> {
    encode_json(
        &ApiValue {
            schema: API_VALUE_SCHEMA.to_string(),
            value,
        },
        "api-value-serialization-failed",
    )
}

pub fn decode_json<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
    code: &'static str,
) -> Result<T, PolicyError> {
    serde_json::from_slice(bytes)
        .map_err(|error| PolicyError::new(code, format!("JSON decode failed: {error}")))
}

pub fn encode_json<T: Serialize>(value: &T, code: &'static str) -> Result<Vec<u8>, PolicyError> {
    serde_json::to_vec(value)
        .map_err(|error| PolicyError::new(code, format!("JSON encode failed: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(character: char) -> DigestValue {
        DigestValue {
            algorithm: "sha256".to_string(),
            hex: core::iter::repeat_n(character, 64).collect(),
        }
    }

    fn blob(character: char) -> BlobValue {
        BlobValue {
            content_digest: digest(character),
            size_bytes: 8,
            media_type: "application/octet-stream".to_string(),
        }
    }

    fn submit() -> SubmitEnvelopeV1 {
        SubmitEnvelopeV1 {
            schema: SUBMIT_SCHEMA.to_string(),
            graph_digest: digest('a'),
            initial_state: StateDocumentRef {
                schema: SUPERVISOR_STATE_SCHEMA.to_string(),
                blob: BlobValue {
                    content_digest: digest('b'),
                    size_bytes: 20,
                    media_type: JSON_MEDIA_TYPE.to_string(),
                },
            },
            source: blob('c'),
        }
    }

    fn request() -> WorkerRequestValue {
        WorkerRequestValue {
            execution_id: "execution-1".to_string(),
            job_id: submit().job_id(),
            role: WorkerRoleValue::Planner,
            worker: PrincipalValue {
                id: "planner".to_string(),
                component_digest: digest('d'),
            },
            service_bindings: alloc::vec![
                ServiceBindingValue {
                    family: ServiceFamilyValue::Build,
                    component_digest: digest('e')
                },
                ServiceBindingValue {
                    family: ServiceFamilyValue::Scheduling,
                    component_digest: digest('8')
                },
            ],
            input: blob('c'),
            checkpoint: None,
            lease_digest: digest('f'),
            attempt: 1,
            deadline_ms: None,
        }
    }

    fn active_manifest() -> (ActiveGraphManifestV1, Vec<u8>, DigestValue) {
        let nodes = REQUIRED_FACTORY_KINDS
            .into_iter()
            .enumerate()
            .map(|(index, kind)| ActiveGraphNodeV1 {
                id: if kind == FactoryComponentKindValue::Root {
                    "factory-control".to_string()
                } else {
                    format!("node-{index}")
                },
                kind,
                component_digest: format!(
                    "sha256:{}",
                    DigestValue::sha256(format!("component-{kind:?}").as_bytes()).hex
                ),
                world: format!("wasm-biotic:factory/test-{index}@0.1.0"),
                exports: alloc::vec![format!("export-{index}")],
                grants: Vec::new(),
                state_schema: (kind == FactoryComponentKindValue::Root)
                    .then(|| SUPERVISOR_STATE_SCHEMA.to_string()),
            })
            .collect::<Vec<_>>();
        let manifest = ActiveGraphManifestV1 {
            schema: FACTORY_GRAPH_SCHEMA.to_string(),
            wit_package: FACTORY_WIT_PACKAGE.to_string(),
            root_node: "factory-control".to_string(),
            previous_graph: None,
            state_schema: SUPERVISOR_STATE_SCHEMA.to_string(),
            nodes,
            bindings: alloc::vec![ActiveGraphBindingV1 {
                consumer: "factory-control".to_string(),
                import_name: "supervisor-reducer".to_string(),
                provider: ActiveGraphBindingProviderV1::Component {
                    node: "node-1".to_string(),
                    export: "export-1".to_string(),
                },
            }],
            invocations: Vec::new(),
            metadata: Some(format!("sha256:{}", DigestValue::sha256(b"metadata").hex)),
        };
        let value = serde_json::to_value(&manifest).unwrap();
        let mut bytes = Vec::new();
        write_canonical_value(&value, &mut bytes).unwrap();
        let digest = DigestValue::sha256(&bytes);
        (manifest, bytes, digest)
    }

    fn initial_state_for(manifest: &ActiveGraphManifestV1, graph_digest: &DigestValue) -> Vec<u8> {
        let component = |kind| manifest.digest_for_kind(kind).unwrap();
        let workers = BTreeMap::from([
            (
                "planner".to_string(),
                component(FactoryComponentKindValue::PlannerWorker),
            ),
            (
                "builder".to_string(),
                component(FactoryComponentKindValue::BuilderWorker),
            ),
            (
                "validator".to_string(),
                component(FactoryComponentKindValue::ValidatorWorker),
            ),
            (
                "reviewer".to_string(),
                component(FactoryComponentKindValue::ReviewerWorker),
            ),
            (
                "packager".to_string(),
                component(FactoryComponentKindValue::PackagerWorker),
            ),
            (
                "continuity-worker".to_string(),
                component(FactoryComponentKindValue::ContinuityWorker),
            ),
        ]);
        let services = BTreeMap::from([
            (
                "build".to_string(),
                component(FactoryComponentKindValue::BuildService),
            ),
            (
                "packaging".to_string(),
                component(FactoryComponentKindValue::PackagingService),
            ),
            (
                "validation".to_string(),
                component(FactoryComponentKindValue::ValidationService),
            ),
            (
                "review".to_string(),
                component(FactoryComponentKindValue::ReviewService),
            ),
            (
                "continuity".to_string(),
                component(FactoryComponentKindValue::ContinuityService),
            ),
            (
                "scheduling".to_string(),
                component(FactoryComponentKindValue::SchedulingService),
            ),
            (
                "operations".to_string(),
                component(FactoryComponentKindValue::OperationsService),
            ),
        ]);
        serde_json::to_vec(&serde_json::json!({
            "schema": SUPERVISOR_STATE_SCHEMA,
            "graph_digest": graph_digest,
            "last_event_sequence": 0,
            "worker_components": workers,
            "service_components": services,
            "jobs": {},
            "active_executions": {},
            "completed_executions": {},
        }))
        .unwrap()
    }

    fn submit_for(graph_digest: DigestValue, initial_state_bytes: &[u8]) -> SubmitEnvelopeV1 {
        SubmitEnvelopeV1 {
            schema: SUBMIT_SCHEMA.to_string(),
            graph_digest,
            initial_state: StateDocumentRef {
                schema: SUPERVISOR_STATE_SCHEMA.to_string(),
                blob: BlobValue::for_bytes(JSON_MEDIA_TYPE, initial_state_bytes),
            },
            source: BlobValue::for_bytes("application/octet-stream", b"source"),
        }
    }

    #[test]
    fn submit_schema_and_content_derived_identity_are_strict() {
        let submit = submit();
        let bytes = encode_json(&submit, "encode").unwrap();
        assert_eq!(
            SubmitEnvelopeV1::decode(&bytes).unwrap().job_id(),
            submit.job_id()
        );
        let mut unknown = bytes;
        unknown.pop();
        unknown.extend_from_slice(br#",\"native_role\":true}"#);
        assert!(SubmitEnvelopeV1::decode(&unknown).is_err());
    }

    #[test]
    fn active_manifest_binds_submit_and_all_initial_component_identities() {
        let (manifest, manifest_bytes, graph_digest) = active_manifest();
        let initial_state = initial_state_for(&manifest, &graph_digest);
        let submit = submit_for(graph_digest.clone(), &initial_state);
        validate_active_submission(&manifest_bytes, &graph_digest, &initial_state, &submit)
            .unwrap();
    }

    #[test]
    fn inactive_submit_graph_is_rejected_before_workflow_execution() {
        let (manifest, manifest_bytes, active_digest) = active_manifest();
        let inactive_digest = digest('f');
        let initial_state = initial_state_for(&manifest, &inactive_digest);
        let submit = submit_for(inactive_digest, &initial_state);
        let error =
            validate_active_submission(&manifest_bytes, &active_digest, &initial_state, &submit)
                .unwrap_err();
        assert_eq!(error.code, "inactive-submit-graph");
    }

    #[test]
    fn caller_cannot_replace_an_active_worker_or_service_digest() {
        let (manifest, manifest_bytes, graph_digest) = active_manifest();
        let initial_state = initial_state_for(&manifest, &graph_digest);
        let submit = submit_for(graph_digest.clone(), &initial_state);

        let mut worker_state: Value = serde_json::from_slice(&initial_state).unwrap();
        worker_state["worker_components"]["builder"] = serde_json::to_value(digest('f')).unwrap();
        let worker_bytes = serde_json::to_vec(&worker_state).unwrap();
        let worker_error =
            validate_active_submission(&manifest_bytes, &graph_digest, &worker_bytes, &submit)
                .unwrap_err();
        assert_eq!(worker_error.code, "initial-state-worker-binding-mismatch");

        let mut service_state: Value = serde_json::from_slice(&initial_state).unwrap();
        service_state["service_components"]["review"] = serde_json::to_value(digest('e')).unwrap();
        let service_bytes = serde_json::to_vec(&service_state).unwrap();
        let service_error =
            validate_active_submission(&manifest_bytes, &graph_digest, &service_bytes, &submit)
                .unwrap_err();
        assert_eq!(service_error.code, "initial-state-service-binding-mismatch");
    }

    #[test]
    fn active_manifest_parser_rejects_noncanonical_or_extended_schema() {
        let (manifest, canonical, _) = active_manifest();
        let noncanonical = serde_json::to_vec(&manifest).unwrap();
        assert_ne!(noncanonical, canonical);
        assert_eq!(
            ActiveGraphManifestV1::decode(&noncanonical)
                .unwrap_err()
                .code,
            "noncanonical-active-manifest"
        );

        let mut extended: Value = serde_json::from_slice(&canonical).unwrap();
        extended["native_policy"] = Value::Bool(true);
        let mut extended_bytes = Vec::new();
        write_canonical_value(&extended, &mut extended_bytes).unwrap();
        assert_eq!(
            ActiveGraphManifestV1::decode(&extended_bytes)
                .unwrap_err()
                .code,
            "invalid-active-manifest-schema"
        );
    }

    #[test]
    fn upgrade_policy_binds_lineage_migration_identity_and_every_idempotent_field() {
        let (active, active_bytes, active_digest) = active_manifest();
        let migration = active
            .digest_for_kind(FactoryComponentKindValue::StateMigration)
            .unwrap();
        let mut successor = active.clone();
        successor.previous_graph = Some(format!("sha256:{}", active_digest.hex));
        let successor_value = serde_json::to_value(&successor).unwrap();
        let mut successor_bytes = Vec::new();
        write_canonical_value(&successor_value, &mut successor_bytes).unwrap();
        let successor_digest = DigestValue::sha256(&successor_bytes);
        validate_upgrade_manifests(
            &active_bytes,
            &active_digest,
            &successor_bytes,
            &successor_digest,
            &migration,
        )
        .unwrap();
        assert_eq!(
            validate_upgrade_manifests(
                &active_bytes,
                &active_digest,
                &successor_bytes,
                &successor_digest,
                &digest('f'),
            )
            .unwrap_err()
            .code,
            "migration-component-mismatch"
        );

        let mut envelope = FactoryUpgradeEnvelopeV1 {
            schema: FACTORY_UPGRADE_SCHEMA.to_string(),
            activation_id: "upgrade-1".to_string(),
            candidate_graph: BlobValue::for_bytes(
                "application/vnd.wasm-biotic.graph+json",
                &successor_bytes,
            ),
            expected_active_graph: active_digest,
            expected_active_state: Some(blob('1')),
            previous_state: StateDocumentRef {
                schema: SUPERVISOR_STATE_SCHEMA.to_string(),
                blob: blob('1'),
            },
            migration_component: migration,
            idempotency_key: digest('0'),
        };
        envelope.idempotency_key = envelope.computed_idempotency_key().unwrap();
        let encoded = serde_json::to_vec(&envelope).unwrap();
        assert_eq!(
            FactoryUpgradeEnvelopeV1::decode(&encoded).unwrap(),
            envelope
        );

        let mut changed: Value = serde_json::from_slice(&encoded).unwrap();
        changed["activation_id"] = Value::String("upgrade-2".to_string());
        assert_eq!(
            FactoryUpgradeEnvelopeV1::decode(&serde_json::to_vec(&changed).unwrap())
                .unwrap_err()
                .code,
            "factory-upgrade-idempotency-mismatch"
        );
    }

    #[test]
    fn observation_policy_makes_health_and_graph_binding_explicit() {
        let observation = FactoryObservationV1 {
            schema: FACTORY_OBSERVATION_SCHEMA.to_string(),
            graph_digest: digest('a'),
            health: FactoryHealth::Unhealthy,
            evidence: alloc::vec![blob('b')],
        };
        let bytes = serde_json::to_vec(&observation).unwrap();
        assert_eq!(FactoryObservationV1::decode(&bytes).unwrap(), observation);
        let mut wrong: Value = serde_json::from_slice(&bytes).unwrap();
        wrong["schema"] = Value::String("wasm-biotic.factory-observation.v2".to_string());
        assert_eq!(
            FactoryObservationV1::decode(&serde_json::to_vec(&wrong).unwrap())
                .unwrap_err()
                .code,
            "unsupported-factory-observation"
        );
    }

    #[test]
    fn reduction_is_journalled_before_dispatch_and_sequence_is_monotonic() {
        let submit = submit();
        let mut record = ControlRecordV1::initial(&submit);
        let next_state = StateDocumentRef {
            schema: SUPERVISOR_STATE_SCHEMA.to_string(),
            blob: BlobValue {
                content_digest: digest('1'),
                size_bytes: 21,
                media_type: JSON_MEDIA_TYPE.to_string(),
            },
        };
        record
            .journal_reduction(
                next_state,
                1,
                digest('2'),
                Some(SupervisorCommandValue::DispatchWorker(request())),
            )
            .unwrap();
        assert!(matches!(
            record.outbox,
            Some(OutboxValue::DispatchPending(_))
        ));
        assert_eq!(record.event_sequence, 1);
        assert!(
            record
                .journal_reduction(record.supervisor_state.clone(), 2, digest('3'), None)
                .is_err()
        );
    }

    #[test]
    fn worker_return_replaces_outbox_without_erasing_durable_state() {
        let submit = submit();
        let mut record = ControlRecordV1::initial(&submit);
        let state = StateDocumentRef {
            schema: SUPERVISOR_STATE_SCHEMA.to_string(),
            blob: BlobValue {
                content_digest: digest('1'),
                size_bytes: 21,
                media_type: JSON_MEDIA_TYPE.to_string(),
            },
        };
        let request = request();
        record
            .journal_reduction(
                state.clone(),
                1,
                digest('2'),
                Some(SupervisorCommandValue::DispatchWorker(request.clone())),
            )
            .unwrap();
        let response = WorkerResponseValue {
            execution_id: request.execution_id,
            worker_component: request.worker.component_digest,
            outcome: WorkerOutcomeValue::Completed(blob('9')),
            checkpoint: None,
            receipts: Vec::new(),
            evidence: Vec::new(),
        };
        record.record_worker_return(response).unwrap();
        assert!(matches!(
            record.outbox,
            Some(OutboxValue::WorkerReturned(_))
        ));
        assert_eq!(record.supervisor_state, state);
        assert_eq!(record.event_sequence, 1);
    }

    #[test]
    fn cancellation_is_a_supervisor_event_not_native_state_mutation() {
        let submit = submit();
        let mut record = ControlRecordV1::initial(&submit);
        let state = StateDocumentRef {
            schema: SUPERVISOR_STATE_SCHEMA.to_string(),
            blob: BlobValue {
                content_digest: digest('1'),
                size_bytes: 21,
                media_type: JSON_MEDIA_TYPE.to_string(),
            },
        };
        record
            .journal_reduction(
                state,
                1,
                digest('2'),
                Some(SupervisorCommandValue::DispatchWorker(request())),
            )
            .unwrap();
        let cancelled = record.cancellation_response(blob('7')).unwrap();
        assert!(matches!(cancelled.outcome, WorkerOutcomeValue::Cancelled));
        assert_eq!(cancelled.evidence, alloc::vec![blob('7')]);
        assert!(matches!(
            record.outbox,
            Some(OutboxValue::DispatchPending(_))
        ));
    }

    #[test]
    fn reducer_cannot_emit_a_different_terminal_output() {
        let submit = submit();
        let mut record = ControlRecordV1::initial(&submit);
        record.event_sequence = 7;
        record.supervisor_state = StateDocumentRef {
            schema: SUPERVISOR_STATE_SCHEMA.to_string(),
            blob: BlobValue {
                content_digest: digest('1'),
                size_bytes: 21,
                media_type: JSON_MEDIA_TYPE.to_string(),
            },
        };
        record.outbox = Some(OutboxValue::EmitPending(blob('8')));
        let response = WorkerResponseValue {
            execution_id: "continuity-execution".to_string(),
            worker_component: digest('6'),
            outcome: WorkerOutcomeValue::Completed(blob('9')),
            checkpoint: None,
            receipts: Vec::new(),
            evidence: Vec::new(),
        };
        assert!(matches!(
            JobResultV1::from_worker(&record, &response),
            Err(PolicyError { code, .. }) if code == "invalid-completed-reduction"
        ));
    }
}
