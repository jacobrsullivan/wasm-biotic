//! External reproduction client and canonical attestation emission.
//!
//! Unlike `substrate`, this test client knows the frozen bounded-cycle fixture.
//! It is not linked into component execution and implements no host interface.

use crate::bindings::root;
use crate::bindings::root::exports::wasm_biotic::factory::factory_api::IngressRequest;
use crate::model::{AnyError, Digest, Result, canonical_json};
use crate::package::LoadedRelease;
use crate::substrate::{
    CoreBlob, HostState, InMemorySubstrate, MechanismSnapshot, Provenance, add_release_to_linker,
    root_engine, root_store,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::rc::Rc;
use wasm_biotic_service_policy_core::r1::{self, ResolvedWorkSummary};
use wasmtime::component::{Component, Linker};

const R1_FIXTURE_LABEL: &str = "kernel-probe";
const PROFILE_V2: &str = "wasm-biotic.factory-substrate-profile.v2";
const PROFILE_V3: &str = "wasm-biotic.factory-substrate-profile.v3";
const EXPECTED_R1_OPERATIONS: [&str; 12] = [
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

const MECHANISMS: [&str; 8] = [
    "blob-store",
    "transaction-store",
    "clock",
    "component-runner",
    "http-transport",
    "key-service",
    "activation",
    "audit-log",
];

#[derive(Serialize)]
struct IndependentIdentity {
    binary_digest: Digest,
    crate_name: &'static str,
    crate_version: &'static str,
    dependencies_on_forbidden_native_implementations: bool,
    mechanism_interfaces: [&'static str; 8],
    native_tcb_inventory_digest: Digest,
    source_tree_digest: Digest,
}

#[derive(Serialize)]
struct ReleaseIdentity {
    certification_digest: Digest,
    certified_kernel_tcb_inventory_digest: Digest,
    certifier_key_id: Digest,
    graph_manifest_digest: Digest,
    root_authority_digest: Digest,
    root_executable_digest: Digest,
    validation_report_digest: Digest,
    wit_package_digest: Digest,
}

#[derive(Serialize)]
struct ReproductionResult {
    admitted_dynamic_authorities: usize,
    boundary_probe_component_root: bool,
    boundary_probe_status: u16,
    complete_six_worker_cycle: bool,
    dynamic_execution_provenance: BTreeMap<String, Provenance>,
    evolution_shadow_matched: bool,
    exact_replay: ExactReplayVerification,
    final_output_digest: Digest,
    final_output_media_type: String,
    job_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    caller_principals_exact: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    observed_caller_principals: Option<BTreeMap<String, Digest>>,
    r1_semantics: R1SemanticVerification,
    r1_semantics_verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reference_execution_evidence_digest: Option<Digest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reference_exact_replay_claim_complete: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reference_final_output_exact_match: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reference_provenance_exact_match: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reference_r1_semantics_exact_match: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reference_terminal_result_exact_match: Option<bool>,
    source_digest: Digest,
    source_label: &'static str,
    source_media_type: &'static str,
    terminal_result_digest: Digest,
    terminal_status: String,
}

#[derive(Serialize)]
struct PrincipalEnforcementEvidence {
    alias_count: usize,
    caller_identity_source: &'static str,
    caller_owned_operations_enforced: bool,
    caller_target_edges_enforced: bool,
    canonical_host_imports_absent: bool,
    descriptor_schema: String,
    fixed_linker_alias_contexts: bool,
    import_alias_scheme: String,
    principal_count: usize,
    principal_id_scheme: String,
    principal_inventory_digest: Digest,
    profile_schema: String,
    pure_principal_count: usize,
    result: &'static str,
}

#[derive(Deserialize)]
struct ReferenceExecution {
    #[serde(default)]
    exact_replay: Option<ReferenceExactReplay>,
    #[serde(default)]
    final_output_digest: Option<Digest>,
    provenance: BTreeMap<String, Provenance>,
    #[serde(default)]
    r1_semantics: Option<R1SemanticVerification>,
    terminal_result_digest: Digest,
}

#[derive(Deserialize)]
struct ReferenceExactReplay {
    inspect_blob_equal: bool,
    inspect_bytes_equal: bool,
    job_id_equal: bool,
    mechanism_counters_unchanged: bool,
    mechanism_state_unchanged: bool,
    output_blob_equal: bool,
    output_bytes_equal: bool,
    resubmitted_exact_submit_blob: bool,
}

impl ReferenceExactReplay {
    fn is_exact(&self) -> bool {
        self.inspect_blob_equal
            && self.inspect_bytes_equal
            && self.job_id_equal
            && self.mechanism_counters_unchanged
            && self.mechanism_state_unchanged
            && self.output_blob_equal
            && self.output_bytes_equal
            && self.resubmitted_exact_submit_blob
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct R1SemanticVerification {
    artifact_digest_hex: String,
    base_tree_digest_hex: String,
    bytecode_size_bytes: u64,
    evidence_digest_hex: String,
    evidence_resolved: bool,
    fixture_label: String,
    input_digest: Digest,
    input_media_type: String,
    operation_history: Vec<String>,
    output_digest: Digest,
    output_media_type: String,
    package_digest_hex: String,
    package_verified: bool,
    passed_tests: u32,
    patched_tree_digest_hex: String,
    provider_policy: String,
    request_digest_hex: String,
    resolved_digest_hex: String,
    review_approved: bool,
    review_digest_hex: String,
    source_changed: bool,
    tests_discovered: u32,
    total_tests: u32,
    validation_digest_hex: String,
    verification_digest_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct ExactReplayVerification {
    inspect_blob_equal: bool,
    inspect_bytes_equal: bool,
    job_id_equal: bool,
    mechanism_snapshot_after_digest: Digest,
    mechanism_snapshot_before_digest: Digest,
    mechanism_snapshot_unchanged: bool,
    output_blob_equal: bool,
    output_bytes_equal: bool,
    provenance_unchanged: bool,
    resubmitted_exact_submit_blob: bool,
}

impl ExactReplayVerification {
    fn is_exact(&self) -> bool {
        self.inspect_blob_equal
            && self.inspect_bytes_equal
            && self.job_id_equal
            && self.mechanism_snapshot_unchanged
            && self.output_blob_equal
            && self.output_bytes_equal
            && self.provenance_unchanged
            && self.resubmitted_exact_submit_blob
    }
}

struct CompletedJob {
    inspect_bytes: Vec<u8>,
    inspect_reference: CoreBlob,
    output: CoreBlob,
    output_bytes: Vec<u8>,
    status: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ReferenceComparison {
    exact_replay_claim_complete: bool,
    final_output_exact_match: bool,
    provenance_exact_match: bool,
    r1_semantics_exact_match: bool,
    terminal_result_exact_match: bool,
}

impl ReferenceComparison {
    fn is_exact(self) -> bool {
        self.exact_replay_claim_complete
            && self.final_output_exact_match
            && self.provenance_exact_match
            && self.r1_semantics_exact_match
            && self.terminal_result_exact_match
    }
}

#[derive(Serialize)]
struct Attestation {
    artifact_closure_verified: bool,
    certificate_signature_verified: bool,
    component_complete_claim: bool,
    independent_substrate: IndependentIdentity,
    #[serde(skip_serializing_if = "Option::is_none")]
    principal_enforcement: Option<PrincipalEnforcementEvidence>,
    release: ReleaseIdentity,
    reproduction: ReproductionResult,
    schema: &'static str,
}

pub fn run(
    release_directory: impl AsRef<Path>,
    certifier_public_key_hex: &str,
    attestation_path: impl AsRef<Path>,
) -> Result<Digest> {
    let release = Rc::new(LoadedRelease::load(
        release_directory,
        certifier_public_key_hex,
    )?);
    let substrate = InMemorySubstrate::new(release.clone())?;
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
                request_id: "independent-component-boundary-probe".to_string(),
                method: "GET".to_string(),
                path: "/__wasm-biotic/component-boundary-probe".to_string(),
                headers: Vec::new(),
                body: None,
            },
        )?
        .map_err(component_failure)?;
    let boundary_probe_component_root = probe
        .headers
        .iter()
        .any(|(name, value)| name == "x-wasm-biotic-component-root" && value == b"ok");
    require(
        probe.status == 200 && boundary_probe_component_root,
        "component boundary probe did not prove the composed component root",
    )?;

    store.set_fuel(release.profile.ceilings.max_component_fuel)?;
    let initial_state_bytes = initial_state(&release)?;
    let initial_state = substrate
        .put("application/json".to_string(), initial_state_bytes)
        .map_err(core_failure)?;
    let source_bytes = r1::canonical_positive_fixture_bytes(R1_FIXTURE_LABEL);
    let source_digest = Digest::of(&source_bytes);
    let source = substrate
        .put(
            r1::CHANGE_REQUEST_MEDIA_TYPE.to_string(),
            source_bytes.clone(),
        )
        .map_err(core_failure)?;
    let graph_hex = release.index.graph_manifest_digest.hex();
    let submit_bytes = serde_json::to_vec(&serde_json::json!({
        "schema": "wasm-biotic.factory-submit.v1",
        "graph_digest": {"algorithm": "sha256", "hex": graph_hex},
        "initial_state": {
            "schema": "wasm-biotic.supervisor-state.v1",
            "blob": blob_json(&initial_state),
        },
        "source": blob_json(&source),
    }))?;
    let submit = substrate
        .put("application/json".to_string(), submit_bytes)
        .map_err(core_failure)?;
    let job_id = instance
        .wasm_biotic_factory_factory_control()
        .call_submit(&mut store, &root_blob(submit.clone()))?
        .map_err(component_failure)?;
    let result_ref = instance
        .wasm_biotic_factory_factory_control()
        .call_inspect(&mut store, &job_id)?
        .map_err(component_failure)?;
    let completed = completed_job(&substrate, result_ref)?;
    let terminal_status = completed.status.clone();
    require(
        terminal_status == "completed",
        "factory cycle did not complete",
    )?;
    let terminal_result_digest = Digest::of(&completed.inspect_bytes);
    let final_output_digest = Digest::of(&completed.output_bytes);
    let summary =
        r1::verify_resolved_work_state(&completed.output_bytes).map_err(policy_failure)?;
    let r1_semantics =
        verify_r1_semantics(R1_FIXTURE_LABEL, &source_bytes, &completed.output, summary)?;

    let mechanism_snapshot_before_replay = substrate.mechanism_snapshot();
    require_schedule_evidence(&release, &mechanism_snapshot_before_replay)?;
    let provenance_before_replay = store.data().provenance();
    require(
        provenance_before_replay.len() == 6,
        "initial R1 execution did not run exactly the six worker authorities",
    )?;
    store.set_fuel(release.profile.ceilings.max_component_fuel)?;
    let replay_job_id = instance
        .wasm_biotic_factory_factory_control()
        .call_submit(&mut store, &root_blob(submit.clone()))?
        .map_err(component_failure)?;
    let replay_result_ref = instance
        .wasm_biotic_factory_factory_control()
        .call_inspect(&mut store, &replay_job_id)?
        .map_err(component_failure)?;
    let replay = completed_job(&substrate, replay_result_ref)?;
    let mechanism_snapshot_after_replay = substrate.mechanism_snapshot();
    let provenance_after_replay = store.data().provenance();
    let exact_replay = ExactReplayVerification {
        inspect_blob_equal: replay.inspect_reference == completed.inspect_reference,
        inspect_bytes_equal: replay.inspect_bytes == completed.inspect_bytes,
        job_id_equal: replay_job_id == job_id,
        mechanism_snapshot_after_digest: mechanism_snapshot_digest(
            &mechanism_snapshot_after_replay,
        )?,
        mechanism_snapshot_before_digest: mechanism_snapshot_digest(
            &mechanism_snapshot_before_replay,
        )?,
        mechanism_snapshot_unchanged: mechanism_snapshot_after_replay
            == mechanism_snapshot_before_replay,
        output_blob_equal: replay.output == completed.output,
        output_bytes_equal: replay.output_bytes == completed.output_bytes,
        provenance_unchanged: provenance_after_replay == provenance_before_replay,
        resubmitted_exact_submit_blob: true,
    };
    require(
        exact_replay.is_exact(),
        "exact R1 submit replay changed identity, bytes, provenance, or mechanism state",
    )?;

    store.set_fuel(release.profile.ceilings.max_component_fuel)?;
    let tool_input_bytes = b"admitted tool shadow input".to_vec();
    let tool_input = substrate
        .put(
            "application/octet-stream".to_string(),
            tool_input_bytes.clone(),
        )
        .map_err(core_failure)?;
    let expected_payload = format!(
        "{{\"ok\":true,\"schema\":\"wasm-biotic.admitted-tool-probe.v1\",\"source_digest\":\"{}\",\"source_size_bytes\":{}}}",
        tool_input.digest.hex(),
        tool_input_bytes.len()
    )
    .into_bytes();
    let expected_tool_output = Digest::of(&expected_payload);
    let tool_digest = release.node_digest("admitted-tool-probe")?;
    let shadow_idempotency = Digest::of(b"component-graph-shadow-v1");
    let shadow_request = serde_json::to_vec(&serde_json::json!({
        "schema": "wasm-biotic.shadow-request.v1",
        "run_id": "component-graph-shadow-v1",
        "candidate_component_digest": tool_digest.hex(),
        "input": {
            "digest": tool_input.digest.hex(),
            "size_bytes": tool_input.size_bytes,
            "media_type": tool_input.media_type,
        },
        "expected_output_digest": expected_tool_output.hex(),
        "idempotency_key": shadow_idempotency.hex(),
        "fuel": 1_000_000_u64,
        "memory_bytes": 8 * 1024 * 1024_u64,
        "output_bytes": 1024 * 1024_u64,
        "wall_time_ms": 5_000_u64,
    }))?;
    let shadow_body = substrate
        .put("application/json".to_string(), shadow_request)
        .map_err(core_failure)?;
    let shadow_response = instance
        .wasm_biotic_factory_factory_api()
        .call_handle(
            &mut store,
            &IngressRequest {
                request_id: "independent-evolution-shadow".to_string(),
                method: "POST".to_string(),
                path: "/v1/evolution/shadow".to_string(),
                headers: Vec::new(),
                body: Some(root_blob(shadow_body)),
            },
        )?
        .map_err(component_failure)?;
    require(
        shadow_response.status == 200,
        "tool shadow did not return 200",
    )?;
    let shadow_ref = shadow_response.body.ok_or("tool shadow returned no body")?;
    let shadow_bytes = substrate
        .get(&crate::substrate::CoreBlob {
            digest: format!("sha256:{}", shadow_ref.content_digest.hex).parse()?,
            size_bytes: shadow_ref.size_bytes,
            media_type: shadow_ref.media_type,
        })
        .map_err(core_failure)?;
    let shadow_value: serde_json::Value = serde_json::from_slice(&shadow_bytes)?;
    let evolution_shadow_matched = shadow_value
        .get("matched")
        .and_then(serde_json::Value::as_bool)
        == Some(true);
    require(
        evolution_shadow_matched,
        "admitted tool output digest did not match",
    )?;

    let operations = store.data().provenance();
    let mut dynamic_execution_provenance = BTreeMap::new();
    for (label, node_id) in [
        ("planner", "planner-worker"),
        ("builder", "builder-worker"),
        ("validator", "validator-worker"),
        ("reviewer", "reviewer-worker"),
        ("packager", "packager-worker"),
        ("continuity-worker", "continuity-worker"),
    ] {
        let lease = Digest::of(format!("lease-v1|{graph_hex}|{job_id}|{label}|1").as_bytes());
        let operation = format!("operation-{}", lease.hex());
        let provenance = operations
            .get(&operation)
            .ok_or_else(|| format!("missing execution provenance for {label}"))?;
        validate_provenance(&release, node_id, provenance)?;
        dynamic_execution_provenance.insert(label.to_string(), provenance.clone());
    }
    let tool_operation = format!("operation-{}", shadow_idempotency.hex());
    let tool_provenance = operations
        .get(&tool_operation)
        .ok_or("missing admitted tool provenance")?;
    validate_provenance(&release, "admitted-tool-probe", tool_provenance)?;
    dynamic_execution_provenance.insert("admitted-tool-probe".to_string(), tool_provenance.clone());
    require(
        dynamic_execution_provenance.len() == 7,
        "reproduction did not execute exactly seven admitted dynamic authorities",
    )?;
    let reference_path = release.directory.join("evidence/kernel-execution.json");
    let (
        reference_execution_evidence_digest,
        reference_exact_replay_claim_complete,
        reference_final_output_exact_match,
        reference_provenance_exact_match,
        reference_r1_semantics_exact_match,
        reference_terminal_result_exact_match,
    ) = if reference_path.is_file() {
        let bytes = fs::read(reference_path)?;
        let reference: ReferenceExecution = serde_json::from_slice(&bytes)?;
        let comparison = compare_reference(
            &reference,
            &dynamic_execution_provenance,
            final_output_digest,
            &r1_semantics,
            terminal_result_digest,
        );
        require(
            comparison.is_exact(),
            &format!(
                "independent R1 execution differs from reference: replay={} final-output={} provenance={} semantics={} terminal={}",
                comparison.exact_replay_claim_complete,
                comparison.final_output_exact_match,
                comparison.provenance_exact_match,
                comparison.r1_semantics_exact_match,
                comparison.terminal_result_exact_match,
            ),
        )?;
        (
            Some(Digest::of(&bytes)),
            Some(comparison.exact_replay_claim_complete),
            Some(comparison.final_output_exact_match),
            Some(comparison.provenance_exact_match),
            Some(comparison.r1_semantics_exact_match),
            Some(comparison.terminal_result_exact_match),
        )
    } else {
        return Err("release has no kernel execution evidence to strict-compare".into());
    };

    let r2 = matches!(release.profile.schema.as_str(), PROFILE_V2 | PROFILE_V3);
    let observed_caller_principals = if r2 {
        let mut observed = BTreeMap::new();
        for (label, target) in [
            ("planner", "planner-worker"),
            ("builder", "builder-worker"),
            ("validator", "validator-worker"),
            ("reviewer", "reviewer-worker"),
            ("packager", "packager-worker"),
            ("continuity-worker", "continuity-worker"),
            ("admitted-tool-probe", "admitted-tool-probe"),
        ] {
            let edge = release
                .manifest
                .invocations
                .iter()
                .find(|edge| edge.target == target)
                .ok_or_else(|| format!("{target} has no invocation caller"))?;
            let expected_seed = release
                .profile
                .principals
                .iter()
                .find(|principal| principal.consumer == edge.consumer)
                .ok_or_else(|| format!("{} has no R2 principal", edge.consumer))?
                .principal_seed;
            let observed_seed = dynamic_execution_provenance
                .get(label)
                .and_then(|provenance| provenance.caller_principal_seed)
                .ok_or_else(|| format!("{target} has no observed R2 caller principal"))?;
            require(
                observed_seed == expected_seed,
                &format!("{target} observed the wrong R2 caller principal"),
            )?;
            if let Some(prior) = observed.insert(edge.consumer.clone(), observed_seed) {
                require(
                    prior == observed_seed,
                    "one R2 caller was observed with inconsistent principal seeds",
                )?;
            }
        }
        Some(observed)
    } else {
        None
    };
    let principal_enforcement = if r2 {
        Some(PrincipalEnforcementEvidence {
            alias_count: release
                .profile
                .principals
                .iter()
                .map(|principal| principal.host_imports.len())
                .sum(),
            caller_identity_source: "validated-linker-alias-bound-to-signed-principal-seed-v1",
            caller_owned_operations_enforced: true,
            caller_target_edges_enforced: true,
            canonical_host_imports_absent: true,
            descriptor_schema: release.descriptor.schema.clone(),
            fixed_linker_alias_contexts: true,
            import_alias_scheme: release
                .profile
                .import_alias_scheme
                .clone()
                .ok_or("R2 profile has no import alias scheme")?,
            principal_count: release.profile.principals.len(),
            principal_id_scheme: release
                .profile
                .principal_id_scheme
                .clone()
                .ok_or("R2 profile has no principal identity scheme")?,
            principal_inventory_digest: release.principal_inventory_digest()?,
            profile_schema: release.profile.schema.clone(),
            pure_principal_count: release
                .profile
                .principals
                .iter()
                .filter(|principal| principal.host_imports.is_empty())
                .count(),
            result: "pass",
        })
    } else {
        None
    };
    let attestation = Attestation {
        artifact_closure_verified: true,
        certificate_signature_verified: true,
        component_complete_claim: false,
        independent_substrate: IndependentIdentity {
            binary_digest: current_binary_digest()?,
            crate_name: env!("CARGO_PKG_NAME"),
            crate_version: env!("CARGO_PKG_VERSION"),
            dependencies_on_forbidden_native_implementations: false,
            mechanism_interfaces: MECHANISMS,
            native_tcb_inventory_digest: Digest::of(include_bytes!("../native-tcb.json")),
            source_tree_digest: source_tree_digest(),
        },
        principal_enforcement,
        release: ReleaseIdentity {
            certification_digest: release.index.certification_digest,
            certified_kernel_tcb_inventory_digest: release
                .index
                .certified_kernel_tcb_inventory_digest,
            certifier_key_id: release.certificate.certifier_key_id,
            graph_manifest_digest: release.index.graph_manifest_digest,
            root_authority_digest: release.index.root_authority_digest,
            root_executable_digest: release.index.root_executable_digest,
            validation_report_digest: release.index.validation_report_digest,
            wit_package_digest: release.metadata.wit_package_digest,
        },
        reproduction: ReproductionResult {
            admitted_dynamic_authorities: dynamic_execution_provenance.len(),
            boundary_probe_component_root,
            boundary_probe_status: probe.status,
            complete_six_worker_cycle: true,
            dynamic_execution_provenance,
            evolution_shadow_matched,
            exact_replay,
            final_output_digest,
            final_output_media_type: completed.output.media_type.clone(),
            job_id,
            caller_principals_exact: r2.then_some(true),
            observed_caller_principals,
            r1_semantics,
            r1_semantics_verified: true,
            reference_execution_evidence_digest,
            reference_exact_replay_claim_complete,
            reference_final_output_exact_match,
            reference_provenance_exact_match,
            reference_r1_semantics_exact_match,
            reference_terminal_result_exact_match,
            source_digest,
            source_label: R1_FIXTURE_LABEL,
            source_media_type: r1::CHANGE_REQUEST_MEDIA_TYPE,
            terminal_result_digest,
            terminal_status,
        },
        schema: if r2 {
            "wasm-biotic.independent-substrate-reproduction.v2"
        } else {
            "wasm-biotic.independent-substrate-reproduction.v1"
        },
    };
    let bytes = canonical_json(&attestation)?;
    let digest = Digest::of(&bytes);
    if let Some(parent) = attestation_path.as_ref().parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(attestation_path, bytes)?;
    Ok(digest)
}

fn completed_job(
    substrate: &InMemorySubstrate,
    inspect_reference: root::wasm_biotic::factory::foundation::BlobRef,
) -> Result<CompletedJob> {
    let inspect_reference = core_blob(inspect_reference)?;
    let inspect_bytes = substrate.get(&inspect_reference).map_err(core_failure)?;
    let value: serde_json::Value = serde_json::from_slice(&inspect_bytes)?;
    require(
        value.get("schema").and_then(serde_json::Value::as_str)
            == Some("wasm-biotic.factory-job-result.v1"),
        "terminal inspect document has the wrong schema",
    )?;
    let status = value
        .get("status")
        .and_then(serde_json::Value::as_str)
        .ok_or("terminal result has no status")?
        .to_string();
    let output = blob_from_json(value.get("output").ok_or("terminal result has no output")?)?;
    let output_bytes = substrate.get(&output).map_err(core_failure)?;
    Ok(CompletedJob {
        inspect_bytes,
        inspect_reference,
        output,
        output_bytes,
        status,
    })
}

fn core_blob(reference: root::wasm_biotic::factory::foundation::BlobRef) -> Result<CoreBlob> {
    Ok(CoreBlob {
        digest: format!("sha256:{}", reference.content_digest.hex).parse()?,
        size_bytes: reference.size_bytes,
        media_type: reference.media_type,
    })
}

fn blob_from_json(value: &serde_json::Value) -> Result<CoreBlob> {
    require(
        value
            .pointer("/content_digest/algorithm")
            .and_then(serde_json::Value::as_str)
            == Some("sha256"),
        "blob reference does not use SHA-256",
    )?;
    let digest = value
        .pointer("/content_digest/hex")
        .and_then(serde_json::Value::as_str)
        .ok_or("blob reference has no digest")?;
    let size_bytes = value
        .get("size_bytes")
        .and_then(serde_json::Value::as_u64)
        .ok_or("blob reference has no size")?;
    let media_type = value
        .get("media_type")
        .and_then(serde_json::Value::as_str)
        .ok_or("blob reference has no media type")?
        .to_string();
    Ok(CoreBlob {
        digest: format!("sha256:{digest}").parse()?,
        size_bytes,
        media_type,
    })
}

fn verify_r1_semantics(
    fixture_label: &str,
    input_bytes: &[u8],
    output: &CoreBlob,
    summary: ResolvedWorkSummary,
) -> Result<R1SemanticVerification> {
    require(
        output.media_type == r1::WORK_STATE_MEDIA_TYPE,
        "terminal output did not use the strict R1 work-state media type",
    )?;
    verify_useful_r1_summary(&summary, input_bytes, &output.digest)?;
    Ok(R1SemanticVerification {
        artifact_digest_hex: summary.artifact_digest_hex,
        base_tree_digest_hex: summary.base_tree_digest_hex,
        bytecode_size_bytes: summary.bytecode_size_bytes,
        evidence_digest_hex: summary.evidence_digest_hex,
        evidence_resolved: summary.evidence_resolved,
        fixture_label: fixture_label.to_string(),
        input_digest: Digest::of(input_bytes),
        input_media_type: r1::CHANGE_REQUEST_MEDIA_TYPE.to_string(),
        operation_history: summary.operation_history,
        output_digest: output.digest,
        output_media_type: output.media_type.clone(),
        package_digest_hex: summary.package_digest_hex,
        package_verified: summary.package_verified,
        passed_tests: summary.passed_tests,
        patched_tree_digest_hex: summary.patched_tree_digest_hex,
        provider_policy: summary.provider_policy,
        request_digest_hex: summary.request_digest_hex,
        resolved_digest_hex: summary.resolved_digest_hex,
        review_approved: summary.review_approved,
        review_digest_hex: summary.review_digest_hex,
        source_changed: summary.source_changed,
        tests_discovered: summary.tests_discovered,
        total_tests: summary.total_tests,
        validation_digest_hex: summary.validation_digest_hex,
        verification_digest_hex: summary.verification_digest_hex,
    })
}

fn verify_useful_r1_summary(
    summary: &ResolvedWorkSummary,
    input_bytes: &[u8],
    output_digest: &Digest,
) -> Result<()> {
    let input_digest = Digest::of(input_bytes);
    require(
        summary.request_digest_hex == input_digest.hex(),
        "R1 summary is not bound to the submitted source bytes",
    )?;
    require(
        summary.resolved_digest_hex == output_digest.hex(),
        "R1 summary is not bound to the terminal output bytes",
    )?;
    require(
        summary.operation_history
            == EXPECTED_R1_OPERATIONS
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>(),
        "R1 summary does not contain the exact 12-call workflow",
    )?;
    require(
        summary.source_changed
            && summary.base_tree_digest_hex != summary.patched_tree_digest_hex
            && summary.bytecode_size_bytes > 0
            && summary.provider_policy == "local-fixture"
            && summary.tests_discovered > 0
            && summary.total_tests > 0
            && summary.tests_discovered == summary.total_tests
            && summary.passed_tests == summary.total_tests
            && summary.review_approved
            && summary.package_verified
            && summary.evidence_resolved,
        "R1 summary does not prove the complete bounded useful-work slice",
    )
}

fn mechanism_snapshot_digest(snapshot: &MechanismSnapshot) -> Result<Digest> {
    Ok(Digest::of(&canonical_json(snapshot)?))
}

fn require_schedule_evidence(release: &LoadedRelease, snapshot: &MechanismSnapshot) -> Result<()> {
    require(
        snapshot.commit_count == 15
            && snapshot
                .transaction_entries_by_namespace
                .get("wasm-biotic.factory-control.v1")
                == Some(&1)
            && snapshot
                .transaction_entries_by_namespace
                .get("wasm-biotic.schedule.v1")
                == Some(&1),
        "R1 execution did not persist the exact control and schedule transaction closure",
    )?;
    require(
        snapshot.wakes.len() == 1,
        "R1 execution did not create exactly one durable wake",
    )?;
    let wake = &snapshot.wakes[0];
    require(
        wake.not_before_ms == 0
            && wake.target_component == release.node_digest("planner-worker")?
            && wake.wake_id.ends_with(":3:scheduling:schedule-job"),
        "R1 durable wake is not the planner's replay-stable schedule-job call",
    )
}

fn compare_reference(
    reference: &ReferenceExecution,
    provenance: &BTreeMap<String, Provenance>,
    final_output_digest: Digest,
    semantics: &R1SemanticVerification,
    terminal_result_digest: Digest,
) -> ReferenceComparison {
    ReferenceComparison {
        exact_replay_claim_complete: reference
            .exact_replay
            .as_ref()
            .is_some_and(ReferenceExactReplay::is_exact),
        final_output_exact_match: reference.final_output_digest == Some(final_output_digest),
        provenance_exact_match: reference.provenance == *provenance,
        r1_semantics_exact_match: reference.r1_semantics.as_ref() == Some(semantics),
        terminal_result_exact_match: reference.terminal_result_digest == terminal_result_digest,
    }
}

fn initial_state(release: &LoadedRelease) -> Result<Vec<u8>> {
    let digest = |id: &str| -> Result<serde_json::Value> {
        Ok(serde_json::json!({
            "algorithm": "sha256",
            "hex": release.node_digest(id)?.hex(),
        }))
    };
    Ok(serde_json::to_vec(&serde_json::json!({
        "schema": "wasm-biotic.supervisor-state.v1",
        "graph_digest": {
            "algorithm": "sha256",
            "hex": release.index.graph_manifest_digest.hex(),
        },
        "last_event_sequence": 0,
        "worker_components": {
            "planner": digest("planner-worker")?,
            "builder": digest("builder-worker")?,
            "validator": digest("validator-worker")?,
            "reviewer": digest("reviewer-worker")?,
            "packager": digest("packager-worker")?,
            "continuity-worker": digest("continuity-worker")?,
        },
        "service_components": {
            "build": digest("build-service")?,
            "packaging": digest("packaging-service")?,
            "validation": digest("validation-service")?,
            "review": digest("review-service")?,
            "continuity": digest("continuity-service")?,
            "scheduling": digest("scheduling-service")?,
            "operations": digest("operations-service")?,
        },
        "jobs": {},
        "active_executions": {},
        "completed_executions": {},
    }))?)
}

fn validate_provenance(
    release: &LoadedRelease,
    node_id: &str,
    provenance: &Provenance,
) -> Result<()> {
    let authority = release.node_digest(node_id)?;
    require(
        provenance.graph_manifest_digest == release.index.graph_manifest_digest,
        "provenance graph mismatch",
    )?;
    require(
        provenance.authority_component_digest == authority,
        &format!("{node_id} authority provenance mismatch"),
    )?;
    let executable = release
        .executables
        .get(&authority)
        .ok_or_else(|| format!("{node_id} has no executable descriptor"))?;
    require(
        provenance.executable_component_digest == executable.descriptor.executable_digest
            && provenance.source_component_digests == executable.descriptor.source_digests,
        &format!("{node_id} executable provenance mismatch"),
    )?;
    let expected_caller = if matches!(release.profile.schema.as_str(), PROFILE_V2 | PROFILE_V3) {
        let edge = release
            .manifest
            .invocations
            .iter()
            .find(|edge| edge.target == node_id)
            .ok_or_else(|| format!("{node_id} has no invocation caller"))?;
        Some(
            release
                .profile
                .principals
                .iter()
                .find(|principal| principal.consumer == edge.consumer)
                .ok_or_else(|| format!("{} has no R2 principal", edge.consumer))?
                .principal_seed,
        )
    } else {
        None
    };
    require(
        provenance.caller_principal_seed == expected_caller,
        &format!("{node_id} caller principal provenance mismatch"),
    )
}

fn blob_json(reference: &crate::substrate::CoreBlob) -> serde_json::Value {
    serde_json::json!({
        "content_digest": {"algorithm": "sha256", "hex": reference.digest.hex()},
        "size_bytes": reference.size_bytes,
        "media_type": reference.media_type,
    })
}

fn root_blob(
    reference: crate::substrate::CoreBlob,
) -> root::wasm_biotic::factory::foundation::BlobRef {
    root::wasm_biotic::factory::foundation::BlobRef {
        content_digest: root::wasm_biotic::factory::foundation::Digest {
            algorithm: root::wasm_biotic::factory::foundation::HashAlgorithm::Sha256,
            hex: reference.digest.hex(),
        },
        size_bytes: reference.size_bytes,
        media_type: reference.media_type,
    }
}

fn component_failure(failure: root::wasm_biotic::factory::foundation::Failure) -> AnyError {
    format!("{}: {}", failure.code, failure.message).into()
}

fn core_failure(failure: crate::substrate::CoreFailure) -> AnyError {
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

pub(crate) fn current_binary_digest() -> Result<Digest> {
    let path = std::env::current_exe()
        .map_err(|error| format!("cannot resolve independent tool executable: {error}"))?;
    let bytes = fs::read(&path).map_err(|error| {
        format!(
            "cannot read independent tool executable {}: {error}",
            path.display()
        )
    })?;
    Ok(Digest::of(&bytes))
}

pub(crate) fn source_tree_digest() -> Digest {
    let files: [(&str, &[u8]); 15] = [
        ("Cargo.toml", include_bytes!("../Cargo.toml")),
        ("Cargo.lock", include_bytes!("../Cargo.lock")),
        ("native-tcb.json", include_bytes!("../native-tcb.json")),
        (
            "src/bin/candidate-graph-shadow.rs",
            include_bytes!("bin/candidate-graph-shadow.rs"),
        ),
        (
            "src/bin/principal-isolation.rs",
            include_bytes!("bin/principal-isolation.rs"),
        ),
        ("src/bindings.rs", include_bytes!("bindings.rs")),
        ("src/isolation.rs", include_bytes!("isolation.rs")),
        ("src/lib.rs", include_bytes!("lib.rs")),
        ("src/main.rs", include_bytes!("main.rs")),
        ("src/model.rs", include_bytes!("model.rs")),
        ("src/package.rs", include_bytes!("package.rs")),
        ("src/reproduce.rs", include_bytes!("reproduce.rs")),
        ("src/shadow.rs", include_bytes!("shadow.rs")),
        ("src/substrate.rs", include_bytes!("substrate.rs")),
        ("src/transport.rs", include_bytes!("transport.rs")),
    ];
    let mut hasher = Sha256::new();
    hasher.update(b"wasm-biotic.independent-substrate-source-tree.v1");
    for (path, bytes) in files {
        hasher.update((path.len() as u64).to_be_bytes());
        hasher.update(path.as_bytes());
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    Digest(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolved_summary(input: &[u8], output: Digest) -> ResolvedWorkSummary {
        ResolvedWorkSummary {
            request_digest_hex: Digest::of(input).hex(),
            base_tree_digest_hex: "11".repeat(32),
            patched_tree_digest_hex: "22".repeat(32),
            artifact_digest_hex: "33".repeat(32),
            validation_digest_hex: "44".repeat(32),
            review_digest_hex: "55".repeat(32),
            package_digest_hex: "66".repeat(32),
            verification_digest_hex: "77".repeat(32),
            evidence_digest_hex: "88".repeat(32),
            resolved_digest_hex: output.hex(),
            source_changed: true,
            bytecode_size_bytes: 29,
            provider_policy: "local-fixture".to_string(),
            tests_discovered: 1,
            passed_tests: 1,
            total_tests: 1,
            review_approved: true,
            package_verified: true,
            evidence_resolved: true,
            operation_history: EXPECTED_R1_OPERATIONS
                .into_iter()
                .map(str::to_string)
                .collect(),
        }
    }

    fn semantic_verification(input: &[u8], output: Digest) -> R1SemanticVerification {
        let summary = resolved_summary(input, output);
        R1SemanticVerification {
            artifact_digest_hex: summary.artifact_digest_hex,
            base_tree_digest_hex: summary.base_tree_digest_hex,
            bytecode_size_bytes: summary.bytecode_size_bytes,
            evidence_digest_hex: summary.evidence_digest_hex,
            evidence_resolved: summary.evidence_resolved,
            fixture_label: R1_FIXTURE_LABEL.to_string(),
            input_digest: Digest::of(input),
            input_media_type: r1::CHANGE_REQUEST_MEDIA_TYPE.to_string(),
            operation_history: summary.operation_history,
            output_digest: output,
            output_media_type: r1::WORK_STATE_MEDIA_TYPE.to_string(),
            package_digest_hex: summary.package_digest_hex,
            package_verified: summary.package_verified,
            passed_tests: summary.passed_tests,
            patched_tree_digest_hex: summary.patched_tree_digest_hex,
            provider_policy: summary.provider_policy,
            request_digest_hex: summary.request_digest_hex,
            resolved_digest_hex: summary.resolved_digest_hex,
            review_approved: summary.review_approved,
            review_digest_hex: summary.review_digest_hex,
            source_changed: summary.source_changed,
            tests_discovered: summary.tests_discovered,
            total_tests: summary.total_tests,
            validation_digest_hex: summary.validation_digest_hex,
            verification_digest_hex: summary.verification_digest_hex,
        }
    }

    fn exact_reference_replay() -> ReferenceExactReplay {
        ReferenceExactReplay {
            inspect_blob_equal: true,
            inspect_bytes_equal: true,
            job_id_equal: true,
            mechanism_counters_unchanged: true,
            mechanism_state_unchanged: true,
            output_blob_equal: true,
            output_bytes_equal: true,
            resubmitted_exact_submit_blob: true,
        }
    }

    #[test]
    fn useful_r1_summary_requires_the_exact_twelve_call_history() {
        let input = b"canonical-r1-input";
        let output = Digest::of(b"resolved-r1-output");
        let mut summary = resolved_summary(input, output);
        verify_useful_r1_summary(&summary, input, &output).unwrap();

        summary.operation_history.remove(3);
        let failure = verify_useful_r1_summary(&summary, input, &output).unwrap_err();
        assert!(failure.to_string().contains("exact 12-call workflow"));
    }

    #[test]
    fn useful_r1_summary_rejects_unbound_output_and_legacy_provider() {
        let input = b"canonical-r1-input";
        let output = Digest::of(b"resolved-r1-output");
        let mut summary = resolved_summary(input, output);
        assert!(verify_useful_r1_summary(&summary, input, &Digest::of(b"other-output")).is_err());

        summary.provider_policy = "remote".to_string();
        let failure = verify_useful_r1_summary(&summary, input, &output).unwrap_err();
        assert!(failure.to_string().contains("bounded useful-work slice"));
    }

    #[test]
    fn reference_comparison_fails_closed_on_semantic_or_provenance_drift() {
        let input = b"canonical-r1-input";
        let output = Digest::of(b"resolved-r1-output");
        let terminal = Digest::of(b"terminal-result");
        let semantics = semantic_verification(input, output);
        let provenance = BTreeMap::from([(
            "planner".to_string(),
            Provenance {
                graph_manifest_digest: Digest::of(b"graph"),
                authority_component_digest: Digest::of(b"planner"),
                executable_component_digest: Digest::of(b"planner-executable"),
                source_component_digests: vec![Digest::of(b"planner-source")],
                caller_principal_seed: None,
            },
        )]);
        let mut reference = ReferenceExecution {
            exact_replay: Some(exact_reference_replay()),
            final_output_digest: Some(output),
            provenance: provenance.clone(),
            r1_semantics: Some(semantics.clone()),
            terminal_result_digest: terminal,
        };
        assert!(
            compare_reference(&reference, &provenance, output, &semantics, terminal).is_exact()
        );

        reference.r1_semantics.as_mut().unwrap().provider_policy = "remote".to_string();
        assert!(
            !compare_reference(&reference, &provenance, output, &semantics, terminal).is_exact()
        );

        reference.r1_semantics = Some(semantics.clone());
        reference
            .provenance
            .get_mut("planner")
            .unwrap()
            .authority_component_digest = Digest::of(b"wrong-authority");
        assert!(
            !compare_reference(&reference, &provenance, output, &semantics, terminal).is_exact()
        );
    }

    #[test]
    fn replay_claim_requires_every_identity_and_state_check() {
        let mut replay = exact_reference_replay();
        assert!(replay.is_exact());
        replay.mechanism_state_unchanged = false;
        assert!(!replay.is_exact());
    }
}
