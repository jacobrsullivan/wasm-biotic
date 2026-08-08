#![cfg_attr(all(target_arch = "wasm32", not(test)), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

//! Component-owned factory evolution and shadow policy.

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

pub const CHANGE_SCHEMA: &str = "wasm-biotic.factory-change.v1";
pub const PROPOSAL_SCHEMA: &str = "wasm-biotic.factory-proposal.v1";
pub const SHADOW_REQUEST_SCHEMA: &str = "wasm-biotic.shadow-request.v1";
pub const SHADOW_EVIDENCE_SCHEMA: &str = "wasm-biotic.shadow-evidence.v1";
pub const ASSESSMENT_SCHEMA: &str = "wasm-biotic.factory-assessment.v1";
pub const JSON_MEDIA_TYPE: &str = "application/json";
pub const FACTORY_GRAPH_SCHEMA: &str = "wasm-biotic.factory-graph.v1";
pub const FACTORY_WIT_PACKAGE: &str = "wasm-biotic:factory@0.1.0";
pub const COMPONENT_TASK_EXPORT: &str = "wasm-biotic:factory/component-task@0.1.0";
pub const EVOLUTION_NODE_ID: &str = "factory-evolution";

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Replacement {
    pub node_id: String,
    pub component_digest: String,
    pub expected_world: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChangeRequest {
    schema: String,
    base_graph_digest: String,
    replacements: Vec<Replacement>,
    rationale: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proposal {
    pub schema: String,
    pub base_graph_digest: String,
    pub replacements: Vec<Replacement>,
    pub rationale: String,
    pub requires_shadow: bool,
    pub requires_operator_approval: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
struct BlobPointer {
    digest: String,
    size_bytes: u64,
    media_type: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
struct ShadowRequest {
    schema: String,
    run_id: String,
    candidate_component_digest: String,
    input: BlobPointer,
    expected_output_digest: String,
    idempotency_key: String,
    fuel: u64,
    memory_bytes: u64,
    output_bytes: u64,
    wall_time_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
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

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ActiveGraphGrantV1 {
    capability: SubstratePrimitiveValue,
    scope: String,
    constraints: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
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

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
enum ActiveGraphBindingProviderV1 {
    Component { node: String, export: String },
    Host { capability: SubstratePrimitiveValue },
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ActiveGraphBindingV1 {
    consumer: String,
    #[serde(rename = "import")]
    import_name: String,
    provider: ActiveGraphBindingProviderV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ActiveGraphInvocationV1 {
    consumer: String,
    target: String,
    export: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
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
    fn decode(bytes: &[u8]) -> Result<Self, EvolutionError> {
        let value: Value = serde_json::from_slice(bytes).map_err(|error| {
            EvolutionError::new(
                "invalid-active-manifest-json",
                format!("active graph manifest is not JSON: {error}"),
            )
        })?;
        let mut canonical = Vec::new();
        write_canonical_value(&value, &mut canonical)?;
        if canonical != bytes {
            return Err(EvolutionError::new(
                "noncanonical-active-manifest",
                "active graph manifest must use canonical JSON bytes",
            ));
        }
        let manifest: Self = serde_json::from_value(value).map_err(|error| {
            EvolutionError::new(
                "invalid-active-manifest-schema",
                format!("active graph manifest has the wrong schema: {error}"),
            )
        })?;
        manifest.validate()?;
        Ok(manifest)
    }

    fn validate(&self) -> Result<(), EvolutionError> {
        if self.schema != FACTORY_GRAPH_SCHEMA
            || self.wit_package != FACTORY_WIT_PACKAGE
            || self.state_schema.trim().is_empty()
        {
            return Err(EvolutionError::new(
                "unsupported-active-manifest",
                "active manifest must be the frozen factory-graph.v1 / factory@0.1.0 graph",
            ));
        }
        if let Some(previous) = &self.previous_graph {
            validate_content_digest("active_manifest.previous_graph", previous)?;
        }
        if let Some(metadata) = &self.metadata {
            validate_content_digest("active_manifest.metadata", metadata)?;
        }

        let mut nodes = BTreeMap::new();
        let mut evolution_nodes = 0;
        for node in &self.nodes {
            if node.id.trim().is_empty() || nodes.insert(node.id.as_str(), node).is_some() {
                return Err(EvolutionError::new(
                    "invalid-active-manifest-node",
                    "active manifest node ids must be non-blank and unique",
                ));
            }
            validate_content_digest(
                &format!("active_manifest.nodes.{}.component_digest", node.id),
                &node.component_digest,
            )?;
            if node.world.trim().is_empty()
                || node.exports.iter().any(|export| export.trim().is_empty())
            {
                return Err(EvolutionError::new(
                    "invalid-active-manifest-node",
                    format!(
                        "active manifest node {} has a blank world or export",
                        node.id
                    ),
                ));
            }
            for grant in &node.grants {
                if grant.scope.trim().is_empty() {
                    return Err(EvolutionError::new(
                        "invalid-active-manifest-grant",
                        format!("active manifest node {} has a blank grant scope", node.id),
                    ));
                }
                validate_content_digest(
                    &format!("active_manifest.nodes.{}.grant.constraints", node.id),
                    &grant.constraints,
                )?;
            }
            if node.id == EVOLUTION_NODE_ID
                && node.kind == FactoryComponentKindValue::FactoryEvolution
            {
                evolution_nodes += 1;
            }
        }
        if evolution_nodes != 1 {
            return Err(EvolutionError::new(
                "invalid-active-evolution-node",
                "active manifest must bind factory-evolution to exactly one factory-evolution component",
            ));
        }
        let root = nodes.get(self.root_node.as_str()).ok_or_else(|| {
            EvolutionError::new(
                "invalid-active-manifest-root",
                "active manifest root_node does not name a node",
            )
        })?;
        if root.kind != FactoryComponentKindValue::Root {
            return Err(EvolutionError::new(
                "invalid-active-manifest-root",
                "active manifest root_node must name the root component",
            ));
        }
        for invocation in &self.invocations {
            if invocation.consumer.trim().is_empty()
                || invocation.export.trim().is_empty()
                || !nodes.contains_key(invocation.target.as_str())
            {
                return Err(EvolutionError::new(
                    "invalid-active-manifest-invocation",
                    "active manifest invocation must name a consumer, target node and export",
                ));
            }
        }
        Ok(())
    }
}

/// Accepts candidate authority only from an exact invocation edge in the
/// substrate-selected canonical graph. The substrate supplies identity and
/// bytes; this component owns the meaning of the factory-evolution edge.
pub fn validate_active_candidates(
    active_manifest_bytes: &[u8],
    active_manifest_digest: &str,
    active_manifest_size: u64,
    candidates: &[String],
) -> Result<(), EvolutionError> {
    validate_digest("active_manifest.content_digest", active_manifest_digest)?;
    if active_manifest_size != active_manifest_bytes.len() as u64
        || sha256_hex(active_manifest_bytes) != active_manifest_digest
    {
        return Err(EvolutionError::new(
            "active-manifest-digest-mismatch",
            "active manifest bytes do not match the substrate's content address",
        ));
    }
    let manifest = ActiveGraphManifestV1::decode(active_manifest_bytes)?;
    let nodes = manifest
        .nodes
        .iter()
        .map(|node| (node.id.as_str(), node))
        .collect::<BTreeMap<_, _>>();
    let declared = manifest
        .invocations
        .iter()
        .filter(|edge| edge.consumer == EVOLUTION_NODE_ID && edge.export == COMPONENT_TASK_EXPORT)
        .filter_map(|edge| nodes.get(edge.target.as_str()))
        .map(|node| {
            node.component_digest
                .strip_prefix("sha256:")
                .unwrap_or_default()
        })
        .collect::<BTreeSet<_>>();

    for candidate in candidates {
        validate_digest("candidate_component_digest", candidate)?;
        if !declared.contains(candidate.as_str()) {
            return Err(EvolutionError::new(
                "undeclared-evolution-candidate",
                "candidate digest is not an active component-task invocation target declared for factory-evolution",
            ));
        }
    }
    Ok(())
}

fn validate_content_digest(field: &str, digest: &str) -> Result<(), EvolutionError> {
    let hex = digest.strip_prefix("sha256:").ok_or_else(|| {
        EvolutionError::new(
            "invalid-content-digest",
            format!("{field} must use the sha256:<hex> content-address form"),
        )
    })?;
    validate_digest(field, hex)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    for byte in digest {
        hex.push(ALPHABET[(byte >> 4) as usize] as char);
        hex.push(ALPHABET[(byte & 0x0f) as usize] as char);
    }
    hex
}

fn write_canonical_value(value: &Value, output: &mut Vec<u8>) -> Result<(), EvolutionError> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(value) => output.extend_from_slice(if *value { b"true" } else { b"false" }),
        Value::Number(number) => output.extend_from_slice(number.to_string().as_bytes()),
        Value::String(string) => {
            let encoded = serde_json::to_vec(string).map_err(|error| {
                EvolutionError::new(
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
pub struct ShadowEvidence {
    pub schema: String,
    pub run_id: String,
    pub candidate_component_digest: String,
    pub expected_output_digest: String,
    pub actual_output_digest: String,
    pub receipt_outcome_digest: String,
    pub matched: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Recommendation {
    Promote,
    Reject,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assessment {
    pub schema: String,
    pub candidate_component_digest: String,
    pub recommendation: Recommendation,
    pub reason: String,
    pub requires_operator_approval: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvolutionError {
    pub code: String,
    pub message: String,
}

impl EvolutionError {
    fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

pub fn propose_policy(bytes: &[u8]) -> Result<Vec<u8>, EvolutionError> {
    let mut request: ChangeRequest = serde_json::from_slice(bytes).map_err(|error| {
        EvolutionError::new(
            "invalid-change-request",
            format!("cannot parse change request: {error}"),
        )
    })?;
    if request.schema != CHANGE_SCHEMA {
        return Err(EvolutionError::new(
            "unsupported-change-schema",
            format!("expected {CHANGE_SCHEMA}"),
        ));
    }
    validate_digest("base_graph_digest", &request.base_graph_digest)?;
    if request.rationale.trim().is_empty() || request.replacements.is_empty() {
        return Err(EvolutionError::new(
            "empty-change",
            "rationale and at least one replacement are required",
        ));
    }
    request
        .replacements
        .sort_by(|left, right| left.node_id.cmp(&right.node_id));
    let mut nodes = BTreeSet::new();
    for replacement in &request.replacements {
        if replacement.node_id.trim().is_empty() || replacement.expected_world.trim().is_empty() {
            return Err(EvolutionError::new(
                "invalid-replacement",
                "node id and expected world must not be blank",
            ));
        }
        if !nodes.insert(replacement.node_id.as_str()) {
            return Err(EvolutionError::new(
                "duplicate-replacement",
                format!("{} is replaced more than once", replacement.node_id),
            ));
        }
        validate_digest(
            "replacement.component_digest",
            &replacement.component_digest,
        )?;
    }
    encode(&Proposal {
        schema: PROPOSAL_SCHEMA.to_string(),
        base_graph_digest: request.base_graph_digest,
        replacements: request.replacements,
        rationale: request.rationale,
        requires_shadow: true,
        requires_operator_approval: true,
    })
}

pub fn assess_policy(bytes: &[u8]) -> Result<Vec<u8>, EvolutionError> {
    let evidence: ShadowEvidence = serde_json::from_slice(bytes).map_err(|error| {
        EvolutionError::new(
            "invalid-shadow-evidence",
            format!("cannot parse shadow evidence: {error}"),
        )
    })?;
    if evidence.schema != SHADOW_EVIDENCE_SCHEMA {
        return Err(EvolutionError::new(
            "unsupported-shadow-schema",
            format!("expected {SHADOW_EVIDENCE_SCHEMA}"),
        ));
    }
    for (field, digest) in [
        (
            "candidate_component_digest",
            &evidence.candidate_component_digest,
        ),
        ("expected_output_digest", &evidence.expected_output_digest),
        ("actual_output_digest", &evidence.actual_output_digest),
        ("receipt_outcome_digest", &evidence.receipt_outcome_digest),
    ] {
        validate_digest(field, digest)?;
    }
    let verified_match =
        evidence.matched && evidence.expected_output_digest == evidence.actual_output_digest;
    encode(&Assessment {
        schema: ASSESSMENT_SCHEMA.to_string(),
        candidate_component_digest: evidence.candidate_component_digest,
        recommendation: if verified_match {
            Recommendation::Promote
        } else {
            Recommendation::Reject
        },
        reason: if verified_match {
            "shadow-output-matched"
        } else {
            "shadow-output-diverged"
        }
        .to_string(),
        requires_operator_approval: verified_match,
    })
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, EvolutionError> {
    serde_json::to_vec(value).map_err(|error| {
        EvolutionError::new(
            "serialization-failed",
            format!("cannot encode policy result: {error}"),
        )
    })
}

fn validate_digest(field: &str, digest: &str) -> Result<(), EvolutionError> {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(EvolutionError::new(
            "invalid-digest",
            format!("{field} must be lower-case SHA-256 hex"),
        ));
    }
    Ok(())
}

#[cfg(all(target_arch = "wasm32", not(test)))]
#[global_allocator]
static ALLOCATOR: dlmalloc::GlobalDlmalloc = dlmalloc::GlobalDlmalloc;

#[cfg(all(target_arch = "wasm32", not(test)))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}

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
        let pointer = unsafe { alloc(layout) };
        if pointer.is_null() {
            handle_alloc_error(layout);
        }
        pointer
    } else {
        let old_layout = Layout::from_size_align(old_length.max(1), alignment)
            .unwrap_or_else(|_| core::arch::wasm32::unreachable());
        if new_length == 0 {
            unsafe { dealloc(old_pointer, old_layout) };
            core::ptr::null_mut()
        } else {
            let pointer = unsafe { realloc(old_pointer, old_layout, new_length) };
            if pointer.is_null() {
                let layout = Layout::from_size_align(new_length, alignment)
                    .unwrap_or_else(|_| core::arch::wasm32::unreachable());
                handle_alloc_error(layout);
            }
            pointer
        }
    }
}

#[cfg(all(target_arch = "wasm32", not(test)))]
#[unsafe(no_mangle)]
unsafe extern "C" fn memcmp(left: *const u8, right: *const u8, length: usize) -> i32 {
    for offset in 0..length {
        let left_byte = unsafe { *left.add(offset) };
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

    wit_bindgen::generate!({ path: "../../wit/wasm-biotic", world: "factory-evolution-component" });

    use exports::wasm_biotic::factory::component_task::Guest as TaskGuest;
    use exports::wasm_biotic::factory::factory_evolution::Guest as EvolutionGuest;
    use wasm_biotic::factory::component_runner::{RunCompletion, RunRequest};
    use wasm_biotic::factory::foundation::{
        BlobRef, CapabilityGrant, Digest, Failure, HashAlgorithm, ResourceLimits, TerminalOutcome,
    };

    struct FactoryEvolutionComponent;

    impl EvolutionGuest for FactoryEvolutionComponent {
        fn propose(change_request: BlobRef) -> Result<BlobRef, Failure> {
            propose(change_request)
        }

        fn shadow(candidate_graph: BlobRef) -> Result<BlobRef, Failure> {
            let bytes = wasm_biotic::factory::blob_store::get(&candidate_graph)?;
            let request: ShadowRequest = serde_json::from_slice(&bytes).map_err(|error| {
                failure(
                    "invalid-shadow-request",
                    format!("cannot parse shadow request: {error}"),
                )
            })?;
            validate_shadow_request(&request).map_err(policy_failure)?;
            require_active_candidates(core::slice::from_ref(&request.candidate_component_digest))?;
            let run_request = RunRequest {
                run_id: request.run_id.clone(),
                component_digest: digest(&request.candidate_component_digest),
                input: BlobRef {
                    content_digest: digest(&request.input.digest),
                    size_bytes: request.input.size_bytes,
                    media_type: request.input.media_type.clone(),
                },
                // The candidate is still constrained by its manifest-bound
                // ceiling in the native runner. Omitting the optional
                // constraint reference selects those exact sealed bytes; it
                // does not create an ambient grant.
                grants: alloc::vec![CapabilityGrant {
                    capability: "blob-store".to_string(),
                    scope: "read-write".to_string(),
                    constraints: None,
                }],
                limits: ResourceLimits {
                    fuel: request.fuel,
                    memory_bytes: request.memory_bytes,
                    output_bytes: request.output_bytes,
                    wall_time_ms: request.wall_time_ms,
                },
                idempotency_key: digest(&request.idempotency_key),
            };
            let operation_id = wasm_biotic::factory::component_runner::start(&run_request)?;
            let completion = wasm_biotic::factory::component_runner::poll(&operation_id)?
                .ok_or_else(|| {
                    failure(
                        "shadow-pending",
                        "bounded v1 shadow must complete in its first poll",
                    )
                })?;
            finish_shadow(request, completion)
        }

        fn assess(evidence: BlobRef) -> Result<BlobRef, Failure> {
            let bytes = wasm_biotic::factory::blob_store::get(&evidence)?;
            let assessment = assess_policy(&bytes).map_err(policy_failure)?;
            Ok(wasm_biotic::factory::blob_store::put(
                JSON_MEDIA_TYPE,
                &assessment,
            )?)
        }
    }

    impl TaskGuest for FactoryEvolutionComponent {
        fn run(input: BlobRef) -> Result<BlobRef, Failure> {
            propose(input)
        }
    }

    fn propose(input: BlobRef) -> Result<BlobRef, Failure> {
        let bytes = wasm_biotic::factory::blob_store::get(&input)?;
        let proposal = propose_policy(&bytes).map_err(policy_failure)?;
        let decoded: Proposal = serde_json::from_slice(&proposal).map_err(|error| {
            failure(
                "invalid-generated-proposal",
                format!("could not parse generated proposal: {error}"),
            )
        })?;
        let candidates = decoded
            .replacements
            .iter()
            .map(|replacement| replacement.component_digest.clone())
            .collect::<Vec<_>>();
        require_active_candidates(&candidates)?;
        Ok(wasm_biotic::factory::blob_store::put(
            JSON_MEDIA_TYPE,
            &proposal,
        )?)
    }

    fn require_active_candidates(candidates: &[String]) -> Result<(), Failure> {
        let reference = wasm_biotic::factory::activation::active_manifest()?.ok_or_else(|| {
            failure(
                "no-active-factory-graph",
                "the substrate has not selected a verified active graph manifest",
            )
        })?;
        let bytes = wasm_biotic::factory::blob_store::get(&reference)?;
        validate_active_candidates(
            &bytes,
            &reference.content_digest.hex,
            reference.size_bytes,
            candidates,
        )
        .map_err(policy_failure)
    }

    fn validate_shadow_request(request: &ShadowRequest) -> Result<(), EvolutionError> {
        if request.schema != SHADOW_REQUEST_SCHEMA {
            return Err(EvolutionError::new(
                "unsupported-shadow-request-schema",
                format!("expected {SHADOW_REQUEST_SCHEMA}"),
            ));
        }
        if request.run_id.trim().is_empty() {
            return Err(EvolutionError::new(
                "invalid-run-id",
                "run id must not be blank",
            ));
        }
        for (field, value) in [
            (
                "candidate_component_digest",
                request.candidate_component_digest.as_str(),
            ),
            ("input.digest", request.input.digest.as_str()),
            (
                "expected_output_digest",
                request.expected_output_digest.as_str(),
            ),
            ("idempotency_key", request.idempotency_key.as_str()),
        ] {
            validate_digest(field, value)?;
        }
        if request.fuel == 0
            || request.memory_bytes == 0
            || request.output_bytes == 0
            || request.wall_time_ms == 0
        {
            return Err(EvolutionError::new(
                "invalid-shadow-limits",
                "all shadow resource limits must be non-zero",
            ));
        }
        Ok(())
    }

    fn finish_shadow(
        request: ShadowRequest,
        completion: RunCompletion,
    ) -> Result<BlobRef, Failure> {
        if completion.run_id != request.run_id {
            return Err(failure(
                "shadow-run-mismatch",
                "runner returned a different run id",
            ));
        }
        let actual = match completion.outcome {
            TerminalOutcome::Succeeded(output) => output.content_digest.hex,
            TerminalOutcome::Rejected(error)
            | TerminalOutcome::Failed(error)
            | TerminalOutcome::Exhausted(error) => return Err(error),
            TerminalOutcome::Cancelled => {
                return Err(failure(
                    "shadow-cancelled",
                    "candidate shadow was cancelled",
                ));
            }
        };
        let evidence = ShadowEvidence {
            schema: SHADOW_EVIDENCE_SCHEMA.to_string(),
            run_id: request.run_id,
            candidate_component_digest: request.candidate_component_digest,
            expected_output_digest: request.expected_output_digest.clone(),
            actual_output_digest: actual.clone(),
            receipt_outcome_digest: completion.receipt.outcome_digest.hex,
            matched: actual == request.expected_output_digest,
        };
        let bytes = encode(&evidence).map_err(policy_failure)?;
        Ok(wasm_biotic::factory::blob_store::put(
            JSON_MEDIA_TYPE,
            &bytes,
        )?)
    }

    fn digest(hex: &str) -> Digest {
        Digest {
            algorithm: HashAlgorithm::Sha256,
            hex: hex.to_string(),
        }
    }
    fn policy_failure(error: EvolutionError) -> Failure {
        failure(error.code, error.message)
    }
    fn failure(code: impl Into<String>, message: impl Into<String>) -> Failure {
        Failure {
            code: code.into(),
            message: message.into(),
            retryable: false,
            evidence: None,
        }
    }

    export!(FactoryEvolutionComponent);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(c: char) -> String {
        core::iter::repeat_n(c, 64).collect()
    }

    fn active_manifest(edge_consumer: &str) -> (ActiveGraphManifestV1, Vec<u8>, String, String) {
        let candidate = digest('c');
        let node = |id: &str, kind, component_digest: &str| ActiveGraphNodeV1 {
            id: id.to_string(),
            kind,
            component_digest: format!("sha256:{component_digest}"),
            world: format!("wasm-biotic:factory/{id}-component@0.1.0"),
            exports: alloc::vec![COMPONENT_TASK_EXPORT.to_string()],
            grants: Vec::new(),
            state_schema: None,
        };
        let manifest = ActiveGraphManifestV1 {
            schema: FACTORY_GRAPH_SCHEMA.to_string(),
            wit_package: FACTORY_WIT_PACKAGE.to_string(),
            root_node: "factory-control".to_string(),
            previous_graph: None,
            state_schema: "wasm-biotic.supervisor-state.v1".to_string(),
            nodes: alloc::vec![
                node(
                    "factory-control",
                    FactoryComponentKindValue::Root,
                    &digest('a'),
                ),
                node(
                    EVOLUTION_NODE_ID,
                    FactoryComponentKindValue::FactoryEvolution,
                    &digest('b'),
                ),
                node(
                    "admitted-tool-probe",
                    FactoryComponentKindValue::AdmittedTool,
                    &candidate,
                ),
            ],
            bindings: alloc::vec![ActiveGraphBindingV1 {
                consumer: EVOLUTION_NODE_ID.to_string(),
                import_name: "wasm-biotic:factory/component-runner@0.1.0".to_string(),
                provider: ActiveGraphBindingProviderV1::Host {
                    capability: SubstratePrimitiveValue::ComponentRunner,
                },
            }],
            invocations: alloc::vec![ActiveGraphInvocationV1 {
                consumer: edge_consumer.to_string(),
                target: "admitted-tool-probe".to_string(),
                export: COMPONENT_TASK_EXPORT.to_string(),
            }],
            metadata: Some(format!("sha256:{}", digest('d'))),
        };
        let value = serde_json::to_value(&manifest).unwrap();
        let mut bytes = Vec::new();
        write_canonical_value(&value, &mut bytes).unwrap();
        let reference_digest = sha256_hex(&bytes);
        (manifest, bytes, reference_digest, candidate)
    }

    #[test]
    fn proposal_sorts_replacements_and_requires_shadow_and_approval() {
        let bytes = serde_json::to_vec(&serde_json::json!({
            "schema": CHANGE_SCHEMA, "base_graph_digest": digest('a'), "rationale": "upgrade validation",
            "replacements": [
                {"node_id":"validator","component_digest":digest('c'),"expected_world":"world-c"},
                {"node_id":"builder","component_digest":digest('b'),"expected_world":"world-b"}
            ]
        })).unwrap();
        let proposal: Proposal = serde_json::from_slice(&propose_policy(&bytes).unwrap()).unwrap();
        assert_eq!(proposal.replacements[0].node_id, "builder");
        assert!(proposal.requires_shadow && proposal.requires_operator_approval);
    }

    #[test]
    fn assessment_recommends_only_a_verified_exact_match() {
        let evidence = ShadowEvidence {
            schema: SHADOW_EVIDENCE_SCHEMA.to_string(),
            run_id: "run-1".to_string(),
            candidate_component_digest: digest('a'),
            expected_output_digest: digest('b'),
            actual_output_digest: digest('b'),
            receipt_outcome_digest: digest('c'),
            matched: true,
        };
        let result: Assessment = serde_json::from_slice(
            &assess_policy(&serde_json::to_vec(&evidence).unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(result.recommendation, Recommendation::Promote);
        assert!(result.requires_operator_approval);
    }

    #[test]
    fn duplicate_replacements_and_false_match_fail_or_reject() {
        let bytes = serde_json::to_vec(&serde_json::json!({
            "schema": CHANGE_SCHEMA, "base_graph_digest": digest('a'), "rationale": "bad",
            "replacements": [
                {"node_id":"same","component_digest":digest('b'),"expected_world":"w"},
                {"node_id":"same","component_digest":digest('c'),"expected_world":"w"}
            ]
        }))
        .unwrap();
        assert_eq!(
            propose_policy(&bytes).unwrap_err().code,
            "duplicate-replacement"
        );
        let evidence = ShadowEvidence {
            schema: SHADOW_EVIDENCE_SCHEMA.to_string(),
            run_id: "run".to_string(),
            candidate_component_digest: digest('a'),
            expected_output_digest: digest('b'),
            actual_output_digest: digest('c'),
            receipt_outcome_digest: digest('d'),
            matched: true,
        };
        let result: Assessment = serde_json::from_slice(
            &assess_policy(&serde_json::to_vec(&evidence).unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(result.recommendation, Recommendation::Reject);
    }

    #[test]
    fn active_manifest_edge_admits_exact_evolution_candidate() {
        let (_, bytes, reference_digest, candidate) = active_manifest(EVOLUTION_NODE_ID);
        validate_active_candidates(&bytes, &reference_digest, bytes.len() as u64, &[candidate])
            .unwrap();
    }

    #[test]
    fn undeclared_or_other_consumer_candidate_is_rejected() {
        let (_, bytes, reference_digest, _) = active_manifest(EVOLUTION_NODE_ID);
        let error = validate_active_candidates(
            &bytes,
            &reference_digest,
            bytes.len() as u64,
            &[digest('e')],
        )
        .unwrap_err();
        assert_eq!(error.code, "undeclared-evolution-candidate");

        let (_, other_bytes, other_reference, candidate) = active_manifest("worker-router");
        let error = validate_active_candidates(
            &other_bytes,
            &other_reference,
            other_bytes.len() as u64,
            &[candidate],
        )
        .unwrap_err();
        assert_eq!(error.code, "undeclared-evolution-candidate");
    }

    #[test]
    fn evolution_rejects_false_or_noncanonical_active_manifest_reference() {
        let (manifest, bytes, reference_digest, candidate) = active_manifest(EVOLUTION_NODE_ID);
        let false_reference = validate_active_candidates(
            &bytes,
            &digest('f'),
            bytes.len() as u64,
            core::slice::from_ref(&candidate),
        )
        .unwrap_err();
        assert_eq!(false_reference.code, "active-manifest-digest-mismatch");

        let noncanonical = serde_json::to_vec(&manifest).unwrap();
        assert_ne!(noncanonical, bytes);
        let error = validate_active_candidates(
            &noncanonical,
            &sha256_hex(&noncanonical),
            noncanonical.len() as u64,
            &[candidate],
        )
        .unwrap_err();
        assert_eq!(error.code, "noncanonical-active-manifest");

        // A true digest with a false size is still a false BlobRef.
        let error = validate_active_candidates(
            &bytes,
            &reference_digest,
            bytes.len() as u64 + 1,
            &[digest('c')],
        )
        .unwrap_err();
        assert_eq!(error.code, "active-manifest-digest-mismatch");
    }
}
