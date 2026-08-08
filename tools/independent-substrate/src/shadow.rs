//! Isolated pre-activation shadow comparison for two signed component graphs.

use crate::bindings::root;
use crate::bindings::root::exports::wasm_biotic::factory::factory_api::IngressRequest;
use crate::model::{AnyError, Digest, Result, canonical_json};
use crate::package::LoadedRelease;
use crate::reproduce::{current_binary_digest, source_tree_digest};
use crate::substrate::{
    CoreBlob, CoreFailure, HostState, InMemorySubstrate, MechanismSnapshot, Provenance,
    WakeSnapshot, add_release_to_linker, root_engine, root_store,
};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::rc::Rc;
use wasm_biotic_service_policy_core::r1::{self, ResolvedWorkSummary};
use wasmtime::component::{Component, Linker};

const R1_CORPUS_LABEL: &str = "candidate-shadow";
const PROFILE_V2: &str = "wasm-biotic.factory-substrate-profile.v2";
const PROFILE_V3: &str = "wasm-biotic.factory-substrate-profile.v3";
const OPERATIONS_PROBE_INPUT: &[u8] = b"bounded operations compatibility probe v1";
const CAPABILITY_MAGIC: &[u8] = b"WASM-BIOTIC-CAPABILITY-RESULT\0\x01";
const WORKER_SEQUENCE: [&str; 6] = [
    "planner",
    "builder",
    "validator",
    "reviewer",
    "packager",
    "continuity-worker",
];
const EXPECTED_SERVICE_OPERATIONS: [&str; 12] = [
    "workspace-open",
    "workspace-snapshot",
    "workspace-patch",
    "schedule-job",
    "candidate-build",
    "factory-provider-proposal",
    "validation-prove",
    "review-candidate",
    "package-publish",
    "package-verify",
    "evidence-publish",
    "evidence-resolve",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct ServiceLayer {
    caller_component_digest: Digest,
    family: String,
    input_digest: Digest,
    operation: String,
    service_component_digest: Digest,
    transformation: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct NormalizedProvenance {
    authority_component_digest: Digest,
    executable_component_digest: Digest,
    source_component_digests: Vec<Digest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    caller_principal_seed: Option<Digest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct MechanismBehavior {
    activation_count: usize,
    audit_entry_count: usize,
    blob_count: usize,
    clock_ms: u64,
    commit_count: usize,
    transaction_entries_by_namespace: BTreeMap<String, usize>,
    wakes: Vec<WakeSnapshot>,
}

#[derive(Serialize)]
struct GraphIdentity {
    certification_digest: Digest,
    #[serde(skip_serializing_if = "Option::is_none")]
    derivation_descriptor_digest: Option<Digest>,
    graph_manifest_digest: Digest,
    #[serde(skip_serializing_if = "Option::is_none")]
    principal_inventory_digest: Option<Digest>,
    previous_graph: Option<Digest>,
    root_authority_digest: Digest,
    root_executable_digest: Digest,
    #[serde(skip_serializing_if = "Option::is_none")]
    substrate_profile_digest: Option<Digest>,
    validation_report_digest: Digest,
    wit_package_digest: Digest,
}

#[derive(Serialize)]
struct GraphObservation {
    active_pair_after_corpus: ActivePair,
    active_pair_before_corpus: ActivePair,
    boundary_probe_status: u16,
    composed_root_source_nodes: Vec<String>,
    declared_capability_service_families: Vec<String>,
    event_sequence: u64,
    exercised_capability_service_families: Vec<String>,
    job_id: String,
    mechanism_behavior: MechanismBehavior,
    normalized_dynamic_provenance: BTreeMap<String, NormalizedProvenance>,
    normalized_supervisor_state_digest: Digest,
    operations_probe_layer: ServiceLayer,
    operations_route_request_digest: Digest,
    raw_supervisor_state_digest: Digest,
    raw_terminal_result_digest: Digest,
    resolved_output: CoreBlob,
    resolved_work_summary: ResolvedWorkSummary,
    service_operations_in_execution_order: Vec<String>,
    status: String,
    terminal_failure: serde_json::Value,
    worker_sequence: [&'static str; 6],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct ActivePair {
    graph: Digest,
    manifest: CoreBlob,
    state: Option<CoreBlob>,
}

#[derive(Serialize)]
struct CorpusEvidence {
    canonical_corpus_digest: Digest,
    capability_route: &'static str,
    operations_probe_digest: Digest,
    operations_probe_media_type: &'static str,
    source_digest: Digest,
    source_label: &'static str,
    source_media_type: &'static str,
    source_size_bytes: usize,
    submit_event: &'static str,
}

#[derive(Serialize)]
struct IsolationEvidence {
    candidate_active_pair_unchanged: bool,
    candidate_activation_count_after: usize,
    candidate_had_incumbent_mechanism_handle: bool,
    incumbent_active_pair_unchanged_during_candidate: bool,
    incumbent_mechanism_snapshot_after_candidate: MechanismSnapshot,
    incumbent_mechanism_snapshot_before_candidate: MechanismSnapshot,
    mechanism_roots_distinct: bool,
}

#[derive(Serialize)]
struct ComparisonEvidence {
    all_seven_capability_service_families_executed: bool,
    all_six_worker_roles_executed: bool,
    candidate_previous_graph_is_incumbent: bool,
    composed_root_source_closure_equal: bool,
    graph_bound_fields_normalized: Vec<&'static str>,
    mechanism_behavior_equal: bool,
    normalized_dynamic_provenance_equal: bool,
    normalized_supervisor_state_equal: bool,
    operations_probe_equal: bool,
    operations_route_request_equal: bool,
    resolved_work_summary_equal: bool,
    service_operation_sequence_equal: bool,
    supervisor_terminal_semantics_equal: bool,
    resolved_output_exactly_equal: bool,
}

#[derive(Serialize)]
struct ToolIdentity {
    binary_digest: Digest,
    native_tcb_inventory_digest: Digest,
    source_tree_digest: Digest,
}

#[derive(Serialize)]
struct ShadowReport {
    candidate: GraphIdentity,
    candidate_observation: GraphObservation,
    comparison: ComparisonEvidence,
    component_complete_claim: bool,
    corpus: CorpusEvidence,
    incumbent: GraphIdentity,
    incumbent_observation: GraphObservation,
    isolation: IsolationEvidence,
    outcome: &'static str,
    remaining_conformance_gaps: Vec<String>,
    schema: &'static str,
    scope_limitations: Vec<&'static str>,
    tool: ToolIdentity,
}

struct CompletedGraphRun {
    observation: GraphObservation,
    release: Rc<LoadedRelease>,
    substrate: InMemorySubstrate,
}

struct CapabilityDecisionMaterial<'a> {
    authority: &'a str,
    caller: Digest,
    caller_id: &'a str,
    family: &'a str,
    input: &'a CoreBlob,
    job_id: &'a str,
    operation: &'a str,
    request_id: &'a str,
    service: Digest,
}

pub fn run(
    incumbent_directory: impl AsRef<Path>,
    candidate_directory: impl AsRef<Path>,
    certifier_public_key_hex: &str,
    report_path: impl AsRef<Path>,
) -> Result<Digest> {
    let incumbent_release = Rc::new(
        LoadedRelease::load(incumbent_directory, certifier_public_key_hex)
            .map_err(|error| format!("incumbent package admission failed: {error}"))?,
    );
    let candidate_release = Rc::new(
        LoadedRelease::load(candidate_directory, certifier_public_key_hex)
            .map_err(|error| format!("candidate package admission failed: {error}"))?,
    );
    let source_bytes = r1::canonical_positive_fixture_bytes(R1_CORPUS_LABEL);
    let incumbent = execute_graph(incumbent_release, &source_bytes)
        .map_err(|error| format!("incumbent shadow execution failed: {error}"))?;
    let incumbent_snapshot_before_candidate = incumbent.substrate.mechanism_snapshot();
    let candidate = execute_graph(candidate_release, &source_bytes)
        .map_err(|error| format!("candidate shadow execution failed: {error}"))?;
    let incumbent_snapshot_after_candidate = incumbent.substrate.mechanism_snapshot();

    let mechanism_roots_distinct = !incumbent
        .substrate
        .shares_mechanism_root_with(&candidate.substrate);
    let candidate_previous_graph_is_incumbent = candidate.release.manifest.previous_graph
        == Some(incumbent.release.index.graph_manifest_digest);
    let incumbent_active_pair_unchanged_during_candidate =
        incumbent_snapshot_before_candidate == incumbent_snapshot_after_candidate;
    let candidate_active_pair_unchanged = candidate.observation.active_pair_before_corpus
        == candidate.observation.active_pair_after_corpus;

    let incumbent_semantics = &incumbent.observation;
    let candidate_semantics = &candidate.observation;
    let expected_workers = WORKER_SEQUENCE
        .iter()
        .map(|role| (*role).to_string())
        .collect::<BTreeSet<_>>();
    let all_six_worker_roles_executed = incumbent_semantics
        .normalized_dynamic_provenance
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>()
        == expected_workers
        && candidate_semantics
            .normalized_dynamic_provenance
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>()
            == expected_workers;
    let expected_families = BTreeSet::from([
        "build".to_string(),
        "packaging".to_string(),
        "validation".to_string(),
        "review".to_string(),
        "continuity".to_string(),
        "scheduling".to_string(),
        "operations".to_string(),
    ]);
    let all_seven_capability_service_families_executed = incumbent_semantics
        .exercised_capability_service_families
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        == expected_families
        && candidate_semantics
            .exercised_capability_service_families
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            == expected_families;

    let comparison = ComparisonEvidence {
        all_seven_capability_service_families_executed,
        all_six_worker_roles_executed,
        candidate_previous_graph_is_incumbent,
        composed_root_source_closure_equal: incumbent_semantics.composed_root_source_nodes
            == candidate_semantics.composed_root_source_nodes,
        graph_bound_fields_normalized: vec![
            "graph-digest",
            "provenance.graph-manifest-digest",
            "supervisor-state.lease-digest",
            "supervisor-state.decision-digest",
            "component-run-receipt.request-digest",
            "component-run-receipt.receipt-id",
        ],
        mechanism_behavior_equal: incumbent_semantics.mechanism_behavior
            == candidate_semantics.mechanism_behavior,
        normalized_dynamic_provenance_equal: incumbent_semantics.normalized_dynamic_provenance
            == candidate_semantics.normalized_dynamic_provenance,
        normalized_supervisor_state_equal: incumbent_semantics.normalized_supervisor_state_digest
            == candidate_semantics.normalized_supervisor_state_digest,
        operations_probe_equal: incumbent_semantics.operations_probe_layer
            == candidate_semantics.operations_probe_layer,
        operations_route_request_equal: incumbent_semantics.operations_route_request_digest
            == candidate_semantics.operations_route_request_digest,
        resolved_work_summary_equal: incumbent_semantics.resolved_work_summary
            == candidate_semantics.resolved_work_summary,
        service_operation_sequence_equal: incumbent_semantics.service_operations_in_execution_order
            == candidate_semantics.service_operations_in_execution_order,
        supervisor_terminal_semantics_equal: incumbent_semantics.status
            == candidate_semantics.status
            && incumbent_semantics.event_sequence == candidate_semantics.event_sequence
            && incumbent_semantics.terminal_failure == candidate_semantics.terminal_failure,
        resolved_output_exactly_equal: incumbent_semantics.resolved_output
            == candidate_semantics.resolved_output,
    };
    let comparison_pass = comparison.all_seven_capability_service_families_executed
        && comparison.all_six_worker_roles_executed
        && comparison.candidate_previous_graph_is_incumbent
        && comparison.composed_root_source_closure_equal
        && comparison.mechanism_behavior_equal
        && comparison.normalized_dynamic_provenance_equal
        && comparison.normalized_supervisor_state_equal
        && comparison.operations_probe_equal
        && comparison.operations_route_request_equal
        && comparison.resolved_work_summary_equal
        && comparison.service_operation_sequence_equal
        && comparison.supervisor_terminal_semantics_equal
        && comparison.resolved_output_exactly_equal;
    let isolation_pass = mechanism_roots_distinct
        && incumbent_active_pair_unchanged_during_candidate
        && candidate_active_pair_unchanged
        && candidate.observation.active_pair_after_corpus.graph
            == candidate.release.index.graph_manifest_digest
        && candidate
            .observation
            .active_pair_after_corpus
            .state
            .is_none()
        && candidate.observation.mechanism_behavior.activation_count == 0;
    let outcome = if comparison_pass && isolation_pass {
        "pass"
    } else {
        "fail"
    };
    let remaining_conformance_gaps = if outcome == "pass" {
        Vec::new()
    } else {
        vec!["candidate graph shadow comparison or isolation assertion failed".to_string()]
    };
    let corpus_value = serde_json::json!({
        "schema": "wasm-biotic.candidate-shadow-corpus.v2",
        "source": {
            "digest": Digest::of(&source_bytes),
            "label": R1_CORPUS_LABEL,
            "media_type": r1::CHANGE_REQUEST_MEDIA_TYPE,
        },
        "events": [
            {"kind": "job-submitted", "source_digest": Digest::of(&source_bytes)},
            {
                "kind": "capability-route",
                "family": "operations",
                "operation": "operations-inspect",
                "input_digest": Digest::of(OPERATIONS_PROBE_INPUT),
                "input_media_type": "application/octet-stream",
            },
        ],
    });
    let r2 = matches!(
        incumbent.release.profile.schema.as_str(),
        PROFILE_V2 | PROFILE_V3
    ) || matches!(
        candidate.release.profile.schema.as_str(),
        PROFILE_V2 | PROFILE_V3
    );
    let report = ShadowReport {
        candidate: graph_identity(&candidate.release)?,
        candidate_observation: candidate.observation,
        comparison,
        component_complete_claim: false,
        corpus: CorpusEvidence {
            canonical_corpus_digest: Digest::of(&canonical_json(&corpus_value)?),
            capability_route: "operations-inspect",
            operations_probe_digest: Digest::of(OPERATIONS_PROBE_INPUT),
            operations_probe_media_type: "application/octet-stream",
            source_digest: Digest::of(&source_bytes),
            source_label: R1_CORPUS_LABEL,
            source_media_type: r1::CHANGE_REQUEST_MEDIA_TYPE,
            source_size_bytes: source_bytes.len(),
            submit_event: "job-submitted",
        },
        incumbent: graph_identity(&incumbent.release)?,
        incumbent_observation: incumbent.observation,
        isolation: IsolationEvidence {
            candidate_active_pair_unchanged,
            candidate_activation_count_after: candidate
                .substrate
                .mechanism_snapshot()
                .activation_count,
            candidate_had_incumbent_mechanism_handle: false,
            incumbent_active_pair_unchanged_during_candidate,
            incumbent_mechanism_snapshot_after_candidate: incumbent_snapshot_after_candidate,
            incumbent_mechanism_snapshot_before_candidate: incumbent_snapshot_before_candidate,
            mechanism_roots_distinct,
        },
        outcome,
        remaining_conformance_gaps,
        schema: if r2 {
            "wasm-biotic.candidate-graph-shadow.v3"
        } else {
            "wasm-biotic.candidate-graph-shadow.v2"
        },
        scope_limitations: vec![
            "comparison covers the exact bounded canonical R1 change-request/event corpus, not every possible future event",
            "graph-derived identities are normalized only in the explicitly listed fields",
            "the operations-family probe deliberately uses the legacy octet-stream compatibility path and is not part of the R1 work-state output",
        ],
        tool: ToolIdentity {
            binary_digest: current_binary_digest()?,
            native_tcb_inventory_digest: Digest::of(include_bytes!("../native-tcb.json")),
            source_tree_digest: source_tree_digest(),
        },
    };
    let bytes = canonical_json(&report)?;
    let digest = Digest::of(&bytes);
    if let Some(parent) = report_path.as_ref().parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(report_path, bytes)?;
    if outcome != "pass" {
        return Err("candidate graph shadow report failed".into());
    }
    Ok(digest)
}

fn execute_graph(release: Rc<LoadedRelease>, source_bytes: &[u8]) -> Result<CompletedGraphRun> {
    let substrate = InMemorySubstrate::new(release.clone())?;
    let active_before = active_pair(&substrate.mechanism_snapshot());
    let engine = root_engine()?;
    let component = Component::new(&engine, &release.root_bytes)?;
    let mut linker = Linker::<HostState>::new(&engine);
    add_release_to_linker(&mut linker, &release)?;
    let mut store = root_store(&engine, HostState::root(substrate.clone())?);
    store.set_fuel(release.profile.ceilings.max_component_fuel)?;
    store.set_epoch_deadline(1);
    let instance = root::FactoryRoot::instantiate(&mut store, &component, &linker)?;
    let probe = instance
        .wasm_biotic_factory_factory_api()
        .call_handle(
            &mut store,
            &IngressRequest {
                request_id: "candidate-shadow-boundary-probe".to_string(),
                method: "GET".to_string(),
                path: "/__wasm-biotic/component-boundary-probe".to_string(),
                headers: Vec::new(),
                body: None,
            },
        )?
        .map_err(component_failure)?;
    require(probe.status == 200, "shadow root boundary probe failed")?;

    let initial_state = substrate
        .put("application/json".to_string(), initial_state(&release)?)
        .map_err(core_failure)?;
    let source = substrate
        .put(
            r1::CHANGE_REQUEST_MEDIA_TYPE.to_string(),
            source_bytes.to_vec(),
        )
        .map_err(core_failure)?;
    let submit_bytes = serde_json::to_vec(&serde_json::json!({
        "schema": "wasm-biotic.factory-submit.v1",
        "graph_digest": {"algorithm": "sha256", "hex": release.index.graph_manifest_digest.hex()},
        "initial_state": {"schema": "wasm-biotic.supervisor-state.v1", "blob": blob_json(&initial_state)},
        "source": blob_json(&source),
    }))?;
    let submit = substrate
        .put("application/json".to_string(), submit_bytes)
        .map_err(core_failure)?;
    store.set_fuel(release.profile.ceilings.max_component_fuel)?;
    let job_id = instance
        .wasm_biotic_factory_factory_control()
        .call_submit(&mut store, &root_blob(submit))?
        .map_err(component_failure)?;
    let result_ref = instance
        .wasm_biotic_factory_factory_control()
        .call_inspect(&mut store, &job_id)?
        .map_err(component_failure)?;
    let result_blob = core_blob(result_ref)?;
    let result_bytes = substrate.get(&result_blob).map_err(core_failure)?;
    let result: serde_json::Value = serde_json::from_slice(&result_bytes)?;
    let status = string_field(&result, "status")?;
    if status != "completed" {
        let failure = result
            .get("failure")
            .map_or_else(|| "null".to_string(), serde_json::Value::to_string);
        return Err(format!(
            "shadow factory cycle did not complete: status={status} failure={failure}"
        )
        .into());
    }
    let event_sequence = result
        .get("event_sequence")
        .and_then(serde_json::Value::as_u64)
        .ok_or("terminal result has no event_sequence")?;
    let terminal_output = blob_from_json(result.get("output").ok_or("terminal output missing")?)?;
    require(
        terminal_output.media_type == r1::WORK_STATE_MEDIA_TYPE,
        "shadow factory cycle did not resolve to the strict R1 work-state media type",
    )?;
    let terminal_output_bytes = substrate.get(&terminal_output).map_err(core_failure)?;
    let resolved_work_summary =
        r1::verify_resolved_work_state(&terminal_output_bytes).map_err(policy_failure)?;
    let supervisor_state_ref = result
        .pointer("/supervisor_state/blob")
        .ok_or("terminal supervisor state is absent")?;
    let supervisor_state_blob = blob_from_json(supervisor_state_ref)?;
    let supervisor_state_bytes = substrate
        .get(&supervisor_state_blob)
        .map_err(core_failure)?;
    let raw_supervisor_state_digest = Digest::of(&supervisor_state_bytes);
    let normalized_supervisor_state_digest =
        normalize_supervisor_state(&supervisor_state_bytes, release.index.graph_manifest_digest)?;

    store.set_fuel(release.profile.ceilings.max_component_fuel)?;
    let operations_probe_input = substrate
        .put(
            "application/octet-stream".to_string(),
            OPERATIONS_PROBE_INPUT.to_vec(),
        )
        .map_err(core_failure)?;
    let (operations_route_request_digest, operations_probe_layer) = run_operations_probe(
        &release,
        &substrate,
        &instance,
        &mut store,
        &job_id,
        &operations_probe_input,
    )?;
    let provenance = store.data().provenance();
    let normalized_dynamic_provenance = normalize_provenance(&release, &job_id, provenance)?;
    let snapshot_after = substrate.mechanism_snapshot();
    require_schedule_evidence(&release, &snapshot_after)?;
    let mechanism_behavior = mechanism_behavior(&snapshot_after);
    let service_operations_in_execution_order = resolved_work_summary.operation_history.clone();
    require(
        service_operations_in_execution_order == EXPECTED_SERVICE_OPERATIONS,
        "R1 service operation sequence differs from the exact 12-call corpus",
    )?;
    let mut exercised_capability_service_families = BTreeSet::new();
    for operation in &service_operations_in_execution_order {
        exercised_capability_service_families.insert(r1_operation_family(operation)?.to_string());
    }
    exercised_capability_service_families.insert(operations_probe_layer.family.clone());

    let composed_root_source_nodes = root_source_nodes(&release)?;
    let declared_capability_service_families = declared_service_families(&release);
    require(
        composed_root_source_nodes
            .iter()
            .any(|node| node == "supervisor-reducer"),
        "composed root closure omits the supervisor reducer",
    )?;
    require(
        declared_capability_service_families
            == exercised_capability_service_families
                .iter()
                .cloned()
                .collect::<Vec<_>>(),
        "not every declared capability service family executed",
    )?;

    Ok(CompletedGraphRun {
        observation: GraphObservation {
            active_pair_after_corpus: active_pair(&snapshot_after),
            active_pair_before_corpus: active_before,
            boundary_probe_status: probe.status,
            composed_root_source_nodes,
            declared_capability_service_families,
            event_sequence,
            exercised_capability_service_families: exercised_capability_service_families
                .into_iter()
                .collect(),
            job_id,
            mechanism_behavior,
            normalized_dynamic_provenance,
            normalized_supervisor_state_digest,
            operations_probe_layer,
            operations_route_request_digest,
            raw_supervisor_state_digest,
            raw_terminal_result_digest: Digest::of(&result_bytes),
            resolved_output: terminal_output,
            resolved_work_summary,
            service_operations_in_execution_order,
            status,
            terminal_failure: result
                .get("failure")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
            worker_sequence: WORKER_SEQUENCE,
        },
        release,
        substrate,
    })
}

fn run_operations_probe(
    release: &LoadedRelease,
    substrate: &InMemorySubstrate,
    instance: &root::FactoryRoot,
    store: &mut wasmtime::Store<HostState>,
    job_id: &str,
    input: &CoreBlob,
) -> Result<(Digest, ServiceLayer)> {
    require(
        input.media_type == "application/octet-stream"
            && input.digest == Digest::of(OPERATIONS_PROBE_INPUT),
        "operations compatibility probe did not receive its isolated octet-stream corpus",
    )?;
    let caller = release.node_digest("factory-control")?;
    let service = release.node_digest("operations-service")?;
    let request_id = "candidate-shadow:operations-inspect";
    let idempotency = capability_decision_digest(&CapabilityDecisionMaterial {
        authority: "observe",
        caller,
        caller_id: "candidate-shadow-observer",
        family: "operations",
        input,
        job_id,
        operation: "operations-inspect",
        request_id,
        service,
    });
    let request_bytes = serde_json::to_vec(&serde_json::json!({
        "schema": "wasm-biotic.capability-route.v1",
        "request": {
            "request_id": request_id,
            "job_id": job_id,
            "caller": {
                "id": "candidate-shadow-observer",
                "component_digest": {"algorithm": "sha256", "hex": caller.hex()},
            },
            "service_component": {"algorithm": "sha256", "hex": service.hex()},
            "family": "operations",
            "operation": "operations-inspect",
            "input": blob_json(input),
            "authority": "observe",
            "approval": null,
            "deadline_ms": null,
            "idempotency_key": {"algorithm": "sha256", "hex": idempotency.hex()},
        },
    }))?;
    let request_digest = Digest::of(&request_bytes);
    let body = substrate
        .put("application/json".to_string(), request_bytes)
        .map_err(core_failure)?;
    let response = instance
        .wasm_biotic_factory_factory_api()
        .call_handle(
            store,
            &IngressRequest {
                request_id: "candidate-shadow-operations-route".to_string(),
                method: "POST".to_string(),
                path: "/v1/capabilities/route".to_string(),
                headers: Vec::new(),
                body: Some(root_blob(body)),
            },
        )?
        .map_err(component_failure)?;
    require(response.status == 200, "operations capability route failed")?;
    let response_body = core_blob(response.body.ok_or("operations response body missing")?)?;
    let response_bytes = substrate.get(&response_body).map_err(core_failure)?;
    let response_value: serde_json::Value = serde_json::from_slice(&response_bytes)?;
    let output = response_value
        .pointer("/value/outcome/succeeded")
        .ok_or_else(|| {
            format!(
                "operations service did not succeed: {}",
                serde_json::to_string(&response_value)
                    .unwrap_or_else(|_| "<unencodable>".to_string())
            )
        })?;
    let output = blob_from_json(output)?;
    let output_bytes = substrate.get(&output).map_err(core_failure)?;
    let mut layers = decode_legacy_service_chain(&output_bytes)?;
    require(
        layers.len() == 1,
        "operations probe produced an unexpected envelope chain",
    )?;
    let layer = layers.remove(0);
    require(
        layer.family == "operations" && layer.operation == "operations-inspect",
        "operations probe was handled by the wrong component policy",
    )?;
    Ok((request_digest, layer))
}

fn r1_operation_family(operation: &str) -> Result<&'static str> {
    match operation {
        "workspace-open" | "workspace-snapshot" | "workspace-patch" | "candidate-build" => {
            Ok("build")
        }
        "schedule-job" => Ok("scheduling"),
        "factory-provider-proposal" | "validation-prove" => Ok("validation"),
        "review-candidate" => Ok("review"),
        "package-publish" | "package-verify" => Ok("packaging"),
        "evidence-publish" | "evidence-resolve" => Ok("continuity"),
        other => Err(format!("unexpected operation in verified R1 history: {other}").into()),
    }
}

fn require_schedule_evidence(release: &LoadedRelease, snapshot: &MechanismSnapshot) -> Result<()> {
    require(
        snapshot
            .transaction_entries_by_namespace
            .get("wasm-biotic.schedule.v1")
            == Some(&1),
        "R1 planner did not persist exactly one durable schedule intent",
    )?;
    require(
        snapshot.wakes.len() == 1,
        "R1 planner did not create exactly one durable wake",
    )?;
    let wake = &snapshot.wakes[0];
    require(
        wake.not_before_ms == 0
            && wake.target_component == release.node_digest("planner-worker")?
            && wake.wake_id.ends_with(":3:scheduling:schedule-job"),
        "R1 durable wake is not the planner's replay-stable schedule-job call",
    )
}

fn capability_decision_digest(material: &CapabilityDecisionMaterial<'_>) -> Digest {
    let caller_hex = material.caller.hex();
    let service_hex = material.service.hex();
    let input_hex = material.input.digest.hex();
    let mut hash = Sha256::new();
    hash.update(b"wasm-biotic:capability-decision:v1\0");
    for field in [
        material.request_id,
        material.job_id,
        material.caller_id,
        &caller_hex,
        &service_hex,
        material.family,
        material.operation,
        &input_hex,
        &material.input.media_type,
        material.authority,
    ] {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field.as_bytes());
    }
    hash.update(material.input.size_bytes.to_be_bytes());
    hash.update([0]);
    Digest(hash.finalize().into())
}

/// Decode only the deliberate operations-service R0 compatibility probe. R1
/// terminal output is verified through `r1::verify_resolved_work_state` and
/// must never enter this parser.
fn decode_legacy_service_chain(bytes: &[u8]) -> Result<Vec<ServiceLayer>> {
    let mut layers = Vec::new();
    let mut current = bytes;
    while current.starts_with(CAPABILITY_MAGIC) {
        let mut cursor = &current[CAPABILITY_MAGIC.len()..];
        let family = text_field(&mut cursor)?;
        let operation = text_field(&mut cursor)?;
        let transformation = text_field(&mut cursor)?;
        let _request_id = text_field(&mut cursor)?;
        let _job_id = text_field(&mut cursor)?;
        let _caller_id = text_field(&mut cursor)?;
        let caller_component_digest = digest_field(&mut cursor)?;
        let service_component_digest = digest_field(&mut cursor)?;
        let _idempotency = digest_field(&mut cursor)?;
        let input_digest = digest_field(&mut cursor)?;
        let _input_media_type = text_field(&mut cursor)?;
        let input_bytes = bytes_field(&mut cursor)?;
        require(cursor.is_empty(), "capability envelope has trailing bytes")?;
        require(
            Digest::of(input_bytes) == input_digest,
            "capability envelope input digest is false",
        )?;
        layers.push(ServiceLayer {
            caller_component_digest,
            family,
            input_digest,
            operation,
            service_component_digest,
            transformation,
        });
        current = input_bytes;
    }
    layers.reverse();
    Ok(layers)
}

fn bytes_field<'a>(cursor: &mut &'a [u8]) -> Result<&'a [u8]> {
    if cursor.len() < 4 {
        return Err("truncated capability envelope length".into());
    }
    let length = u32::from_be_bytes(cursor[..4].try_into()?) as usize;
    *cursor = &cursor[4..];
    if cursor.len() < length {
        return Err("truncated capability envelope field".into());
    }
    let value = &cursor[..length];
    *cursor = &cursor[length..];
    Ok(value)
}

fn text_field(cursor: &mut &[u8]) -> Result<String> {
    Ok(std::str::from_utf8(bytes_field(cursor)?)?.to_string())
}

fn digest_field(cursor: &mut &[u8]) -> Result<Digest> {
    format!("sha256:{}", text_field(cursor)?).parse()
}

fn normalize_supervisor_state(bytes: &[u8], graph: Digest) -> Result<Digest> {
    let mut value: serde_json::Value = serde_json::from_slice(bytes)?;
    normalize_value(&mut value, None, &graph.hex());
    Ok(Digest::of(&canonical_json(&value)?))
}

fn normalize_value(value: &mut serde_json::Value, key: Option<&str>, graph_hex: &str) {
    if matches!(
        key,
        Some("lease_digest" | "decision_digest" | "request_digest")
    ) {
        *value = serde_json::json!({"algorithm": "sha256", "hex": "<graph-bound-digest>"});
        return;
    }
    if key == Some("receipt_id") {
        *value = serde_json::Value::String("<graph-bound-receipt>".to_string());
        return;
    }
    match value {
        serde_json::Value::String(text)
            if text == graph_hex || text == &format!("sha256:{graph_hex}") =>
        {
            *text = "<graph-digest>".to_string();
        }
        serde_json::Value::Array(values) => {
            for value in values {
                normalize_value(value, None, graph_hex);
            }
        }
        serde_json::Value::Object(values) => {
            for (key, value) in values {
                normalize_value(value, Some(key), graph_hex);
            }
        }
        _ => {}
    }
}

fn normalize_provenance(
    release: &LoadedRelease,
    job_id: &str,
    provenance: BTreeMap<String, Provenance>,
) -> Result<BTreeMap<String, NormalizedProvenance>> {
    let mut output = BTreeMap::new();
    for (label, node) in [
        ("planner", "planner-worker"),
        ("builder", "builder-worker"),
        ("validator", "validator-worker"),
        ("reviewer", "reviewer-worker"),
        ("packager", "packager-worker"),
        ("continuity-worker", "continuity-worker"),
    ] {
        let lease = Digest::of(
            format!(
                "lease-v1|{}|{job_id}|{label}|1",
                release.index.graph_manifest_digest.hex()
            )
            .as_bytes(),
        );
        let item = provenance
            .get(&format!("operation-{}", lease.hex()))
            .ok_or_else(|| format!("missing {label} shadow provenance"))?;
        let authority = release.node_digest(node)?;
        let executable = release
            .executables
            .get(&authority)
            .ok_or_else(|| format!("missing {node} executable"))?;
        require(
            item.graph_manifest_digest == release.index.graph_manifest_digest
                && item.authority_component_digest == authority
                && item.executable_component_digest == executable.descriptor.executable_digest
                && item.source_component_digests == executable.descriptor.source_digests
                && item.caller_principal_seed == expected_caller_seed(release, node)?,
            &format!("{label} provenance is not descriptor exact"),
        )?;
        output.insert(
            label.to_string(),
            NormalizedProvenance {
                authority_component_digest: item.authority_component_digest,
                executable_component_digest: item.executable_component_digest,
                source_component_digests: item.source_component_digests.clone(),
                caller_principal_seed: item.caller_principal_seed,
            },
        );
    }
    require(
        output.len() == provenance.len(),
        "unexpected dynamic execution in shadow corpus",
    )?;
    Ok(output)
}

fn expected_caller_seed(release: &LoadedRelease, target: &str) -> Result<Option<Digest>> {
    if !matches!(release.profile.schema.as_str(), PROFILE_V2 | PROFILE_V3) {
        return Ok(None);
    }
    let caller = release
        .manifest
        .invocations
        .iter()
        .find(|edge| edge.target == target)
        .ok_or_else(|| format!("{target} has no invocation caller"))?
        .consumer
        .as_str();
    Ok(Some(
        release
            .profile
            .principals
            .iter()
            .find(|principal| principal.consumer == caller)
            .ok_or_else(|| format!("{caller} has no R2 principal"))?
            .principal_seed,
    ))
}

fn initial_state(release: &LoadedRelease) -> Result<Vec<u8>> {
    let digest = |id: &str| -> Result<serde_json::Value> {
        Ok(serde_json::json!({"algorithm": "sha256", "hex": release.node_digest(id)?.hex()}))
    };
    Ok(serde_json::to_vec(&serde_json::json!({
        "schema": "wasm-biotic.supervisor-state.v1",
        "graph_digest": {"algorithm": "sha256", "hex": release.index.graph_manifest_digest.hex()},
        "last_event_sequence": 0,
        "worker_components": {
            "planner": digest("planner-worker")?, "builder": digest("builder-worker")?,
            "validator": digest("validator-worker")?, "reviewer": digest("reviewer-worker")?,
            "packager": digest("packager-worker")?, "continuity-worker": digest("continuity-worker")?,
        },
        "service_components": {
            "build": digest("build-service")?, "packaging": digest("packaging-service")?,
            "validation": digest("validation-service")?, "review": digest("review-service")?,
            "continuity": digest("continuity-service")?, "scheduling": digest("scheduling-service")?,
            "operations": digest("operations-service")?,
        },
        "jobs": {}, "active_executions": {}, "completed_executions": {},
    }))?)
}

fn graph_identity(release: &LoadedRelease) -> Result<GraphIdentity> {
    let r2 = matches!(release.profile.schema.as_str(), PROFILE_V2 | PROFILE_V3);
    Ok(GraphIdentity {
        certification_digest: release.index.certification_digest,
        derivation_descriptor_digest: r2.then_some(release.metadata.derivation_descriptor_digest),
        graph_manifest_digest: release.index.graph_manifest_digest,
        principal_inventory_digest: if r2 {
            Some(release.principal_inventory_digest()?)
        } else {
            None
        },
        previous_graph: release.manifest.previous_graph,
        root_authority_digest: release.index.root_authority_digest,
        root_executable_digest: release.index.root_executable_digest,
        substrate_profile_digest: r2.then_some(release.metadata.substrate_profile_digest),
        validation_report_digest: release.index.validation_report_digest,
        wit_package_digest: release.metadata.wit_package_digest,
    })
}

fn root_source_nodes(release: &LoadedRelease) -> Result<Vec<String>> {
    let root = release
        .executables
        .get(&release.index.root_authority_digest)
        .ok_or("root executable descriptor is absent")?;
    let by_digest = release
        .descriptor
        .sources
        .iter()
        .map(|source| (source.component_digest, source.node_id.clone()))
        .collect::<BTreeMap<_, _>>();
    root.descriptor
        .source_digests
        .iter()
        .map(|digest| {
            by_digest
                .get(digest)
                .cloned()
                .ok_or_else(|| format!("root source {digest} is absent").into())
        })
        .collect()
}

fn declared_service_families(release: &LoadedRelease) -> Vec<String> {
    let kinds = [
        ("build-service", "build"),
        ("packaging-service", "packaging"),
        ("validation-service", "validation"),
        ("review-service", "review"),
        ("continuity-service", "continuity"),
        ("scheduling-service", "scheduling"),
        ("operations-service", "operations"),
    ];
    let present = release
        .manifest
        .nodes
        .iter()
        .map(|node| node.kind.as_str())
        .collect::<BTreeSet<_>>();
    kinds
        .into_iter()
        .filter(|(kind, _)| present.contains(kind))
        .map(|(_, family)| family.to_string())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn mechanism_behavior(snapshot: &MechanismSnapshot) -> MechanismBehavior {
    MechanismBehavior {
        activation_count: snapshot.activation_count,
        audit_entry_count: snapshot.audit_entry_count,
        blob_count: snapshot.blob_count,
        clock_ms: snapshot.clock_ms,
        commit_count: snapshot.commit_count,
        transaction_entries_by_namespace: snapshot.transaction_entries_by_namespace.clone(),
        wakes: snapshot.wakes.clone(),
    }
}

fn active_pair(snapshot: &MechanismSnapshot) -> ActivePair {
    ActivePair {
        graph: snapshot.active_graph,
        manifest: snapshot.active_manifest.clone(),
        state: snapshot.active_state.clone(),
    }
}

fn blob_json(reference: &CoreBlob) -> serde_json::Value {
    serde_json::json!({
        "content_digest": {"algorithm": "sha256", "hex": reference.digest.hex()},
        "size_bytes": reference.size_bytes,
        "media_type": reference.media_type,
    })
}

fn blob_from_json(value: &serde_json::Value) -> Result<CoreBlob> {
    let hex = value
        .pointer("/content_digest/hex")
        .and_then(serde_json::Value::as_str)
        .ok_or("blob JSON has no digest")?;
    Ok(CoreBlob {
        digest: format!("sha256:{hex}").parse()?,
        size_bytes: value
            .get("size_bytes")
            .and_then(serde_json::Value::as_u64)
            .ok_or("blob JSON has no size")?,
        media_type: value
            .get("media_type")
            .and_then(serde_json::Value::as_str)
            .ok_or("blob JSON has no media type")?
            .to_string(),
    })
}

fn core_blob(reference: root::wasm_biotic::factory::foundation::BlobRef) -> Result<CoreBlob> {
    Ok(CoreBlob {
        digest: format!("sha256:{}", reference.content_digest.hex).parse()?,
        size_bytes: reference.size_bytes,
        media_type: reference.media_type,
    })
}

fn root_blob(reference: CoreBlob) -> root::wasm_biotic::factory::foundation::BlobRef {
    root::wasm_biotic::factory::foundation::BlobRef {
        content_digest: root::wasm_biotic::factory::foundation::Digest {
            algorithm: root::wasm_biotic::factory::foundation::HashAlgorithm::Sha256,
            hex: reference.digest.hex(),
        },
        size_bytes: reference.size_bytes,
        media_type: reference.media_type,
    }
}

fn string_field(value: &serde_json::Value, key: &str) -> Result<String> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("terminal result has no {key}").into())
}

fn component_failure(failure: root::wasm_biotic::factory::foundation::Failure) -> AnyError {
    format!("{}: {}", failure.code, failure.message).into()
}

fn core_failure(failure: CoreFailure) -> AnyError {
    format!("{}: {}", failure.code, failure.message).into()
}

fn policy_failure(failure: wasm_biotic_service_policy_core::PolicyError) -> AnyError {
    format!("{}: {}", failure.code, failure.message).into()
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn r1_source_and_legacy_operations_probe_are_distinct_corpora() {
        let first = r1::canonical_positive_fixture_bytes(R1_CORPUS_LABEL);
        let replay = r1::canonical_positive_fixture_bytes(R1_CORPUS_LABEL);
        assert_eq!(first, replay);
        assert_ne!(Digest::of(&first), Digest::of(OPERATIONS_PROBE_INPUT));
        assert!(r1::owns_media_type(r1::CHANGE_REQUEST_MEDIA_TYPE));
        assert!(!r1::owns_media_type("application/octet-stream"));
    }

    #[test]
    fn operations_compatibility_decoder_is_explicitly_legacy_and_isolated() {
        let input = b"opaque";
        let mut bytes = CAPABILITY_MAGIC.to_vec();
        for field in [
            b"operations".as_slice(),
            b"operations-inspect",
            b"operations-inspection-record",
            b"request",
            b"job",
            b"caller",
            b"0000000000000000000000000000000000000000000000000000000000000000",
            b"1111111111111111111111111111111111111111111111111111111111111111",
            b"2222222222222222222222222222222222222222222222222222222222222222",
            Digest::of(input).hex().as_bytes(),
            b"application/octet-stream",
            input,
        ] {
            bytes.extend_from_slice(&(field.len() as u32).to_be_bytes());
            bytes.extend_from_slice(field);
        }
        let layers = decode_legacy_service_chain(&bytes).unwrap();
        assert_eq!(layers.len(), 1);
        assert_eq!(layers[0].family, "operations");
        assert_eq!(layers[0].operation, "operations-inspect");
        assert_eq!(layers[0].transformation, "operations-inspection-record");
    }

    #[test]
    fn r1_operation_history_is_the_exact_twelve_call_workflow() {
        assert_eq!(
            EXPECTED_SERVICE_OPERATIONS,
            [
                "workspace-open",
                "workspace-snapshot",
                "workspace-patch",
                "schedule-job",
                "candidate-build",
                "factory-provider-proposal",
                "validation-prove",
                "review-candidate",
                "package-publish",
                "package-verify",
                "evidence-publish",
                "evidence-resolve",
            ]
        );
    }
}
