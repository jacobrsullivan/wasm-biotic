//! Production operator boundary for one precommitted M5 live-provider proof.
//!
//! `prepare` is deliberately network-free: it opens M5 without a live port,
//! constructs (but does not invoke) the governed provider adapter, freezes the
//! exact proof-run/provider/seed tuple, and publishes its canonical record.
//! `run` revalidates those exact inputs, installs the governed port, performs
//! the precommitted cycle, publishes the opaque completed invocation first,
//! and then emits its compatibility binding, receipt, and result projections.

use aiaf_v1::execution::ContentDigest;
use aiaf_v1::factory_reproduction::{
    CycleStatus, M5ProviderEndpointClassV1, ProviderQualificationStatus,
};
use aiaf_v1::m5_provider_binding::ProviderCandidateBinding;
use aiaf_v1::m5_provider_execution::{
    M5CompletedProviderInvocationV1, M5ProviderExecutionReceiptV1, M5ProviderTerminalOutcomeV1,
};
use aiaf_v1::m5_runtime::{
    GovernedLiveProviderConfig, GovernedLiveProviderPort, M5PreparedProviderSeedV1, M5Runtime,
    M5RuntimeConfig, M5SeedCyclePlan,
};
use aiaf_v1::m7_closure::{LiveProviderQualificationScope, M7ProofRunManifest};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

const MAX_RUNTIME_CONFIG_BYTES: usize = 64 * 1024;
const MAX_PROVIDER_CONFIG_BYTES: usize = 256 * 1024;
const MAX_SEED_PLAN_BYTES: usize = 4 * 1024 * 1024;
const MAX_PREPARED_BYTES: usize = 4 * 1024 * 1024;
const MAX_MANIFEST_BYTES: usize = 32 * 1024 * 1024;
const MAX_BINDING_BYTES: usize = 4 * 1024 * 1024;
const MAX_EXECUTION_RECEIPT_BYTES: usize = 64 * 1024;
const MAX_COMPLETED_INVOCATION_BYTES: usize = 8 * 1024 * 1024;
const MAX_RESULT_BYTES: usize = 64 * 1024;
const RESULT_SCHEMA: &str = "wasm-biotic.m5-provider-proof-result.v3";
const RESULT_DIGEST_DOMAIN: &str = "wasm-biotic:m5-provider-proof-result:v3";
const TEMPORARY_ATTEMPTS: usize = 32;

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(1);

fn main() {
    if let Err(error) = run(std::env::args().collect()) {
        // Operator errors intentionally never include credential values,
        // provider prompts, provider responses, or live transport bodies.
        eprintln!("aiaf-m5-provider-proof: {error}");
        std::process::exit(1);
    }
}

fn run(args: Vec<String>) -> Result<(), OperatorError> {
    if args.len() == 2 && matches!(args[1].as_str(), "help" | "--help" | "-h") {
        println!("{}", usage());
        return Ok(());
    }
    if args.len() < 2 {
        return Err(OperatorError::Usage(usage()));
    }
    let mut flags = Flags::parse(&args[2..])?;
    match args[1].as_str() {
        "prepare" => {
            let runtime_config_path = flags.path("--runtime-config")?;
            let provider_config_path = flags.path("--provider-config")?;
            let seed_plan_path = flags.path("--seed-plan")?;
            let proof_run_id = flags.text("--proof-run-id")?;
            let qualification_id = flags.text("--qualification-id")?;
            let prepared_at_ms = flags.u64("--prepared-at-ms")?;
            let output = flags.path("--out")?;
            flags.finish()?;
            prepare(
                &runtime_config_path,
                &provider_config_path,
                &seed_plan_path,
                proof_run_id,
                qualification_id,
                prepared_at_ms,
                &output,
            )?;
            println!("prepared provider seed written: {}", output.display());
        }
        "run" => {
            let runtime_config_path = flags.path("--runtime-config")?;
            let provider_config_path = flags.path("--provider-config")?;
            let prepared_path = flags.path("--prepared")?;
            let manifest_path = flags.path("--manifest")?;
            let binding_output = flags.path("--binding-out")?;
            let execution_output = flags.path("--execution-out")?;
            let completed_output = flags.path("--completed-out")?;
            let result_output = flags.path("--result-out")?;
            flags.finish()?;
            execute(
                &runtime_config_path,
                &provider_config_path,
                &prepared_path,
                &manifest_path,
                &binding_output,
                &execution_output,
                &completed_output,
                &result_output,
            )?;
            println!("provider binding written: {}", binding_output.display());
            println!(
                "provider execution receipt written: {}",
                execution_output.display()
            );
            println!(
                "completed provider invocation written: {}",
                completed_output.display()
            );
            println!("redacted result written: {}", result_output.display());
        }
        _ => return Err(OperatorError::Usage(usage())),
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn prepare(
    runtime_config_path: &Path,
    provider_config_path: &Path,
    seed_plan_path: &Path,
    proof_run_id: String,
    qualification_id: String,
    prepared_at_ms: u64,
    output: &Path,
) -> Result<(), OperatorError> {
    let runtime_config_input = require_existing_path_without_symlinks(runtime_config_path)?;
    let provider_config_input = require_existing_path_without_symlinks(provider_config_path)?;
    let seed_plan_input = require_existing_path_without_symlinks(seed_plan_path)?;
    let runtime_config: M5RuntimeConfig =
        read_canonical_json(&runtime_config_input, MAX_RUNTIME_CONFIG_BYTES)?;
    let provider_config: GovernedLiveProviderConfig =
        read_canonical_json(&provider_config_input, MAX_PROVIDER_CONFIG_BYTES)?;
    let seed_plan: M5SeedCyclePlan = read_canonical_json(&seed_plan_input, MAX_SEED_PLAN_BYTES)?;
    let runtime_root = require_existing_directory_without_symlinks(&runtime_config.root)?;
    let output = resolve_output_path(output)?;
    ensure_output_separation(
        &output,
        &runtime_root,
        &[runtime_config_input, provider_config_input, seed_plan_input],
    )?;

    // The absence of a live port is the preparation-side network boundary.
    let runtime = M5Runtime::open(runtime_config, None)
        .map_err(|_| OperatorError::Operation("cannot open the exact M5 runtime"))?;
    // Construction validates public configuration only. The credential value
    // is not resolved until the port's live-call trait method is invoked.
    let provider = GovernedLiveProviderPort::new(provider_config)
        .map_err(|_| OperatorError::Operation("governed provider configuration is invalid"))?;
    let prepared = runtime
        .prepare_provider_backed_seed_cycle(
            proof_run_id,
            qualification_id,
            prepared_at_ms,
            &provider,
            seed_plan,
        )
        .map_err(|_| OperatorError::Operation("cannot prepare the exact provider-backed seed"))?;
    let bytes = prepared
        .canonical_bytes()
        .map_err(|_| OperatorError::Operation("cannot encode the prepared provider seed"))?;
    drop(runtime);
    persist_no_clobber_or_identical(&output, &bytes, MAX_PREPARED_BYTES)
}

fn execute(
    runtime_config_path: &Path,
    provider_config_path: &Path,
    prepared_path: &Path,
    manifest_path: &Path,
    binding_output: &Path,
    execution_output: &Path,
    completed_output: &Path,
    result_output: &Path,
) -> Result<(), OperatorError> {
    execute_with_provider_factory(
        runtime_config_path,
        provider_config_path,
        prepared_path,
        manifest_path,
        binding_output,
        execution_output,
        completed_output,
        result_output,
        |provider_config| {
            GovernedLiveProviderPort::new(provider_config)
                .map_err(|_| OperatorError::Operation("governed provider configuration is invalid"))
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn execute_with_provider_factory<F>(
    runtime_config_path: &Path,
    provider_config_path: &Path,
    prepared_path: &Path,
    manifest_path: &Path,
    binding_output: &Path,
    execution_output: &Path,
    completed_output: &Path,
    result_output: &Path,
    create_provider: F,
) -> Result<(), OperatorError>
where
    F: FnOnce(GovernedLiveProviderConfig) -> Result<GovernedLiveProviderPort, OperatorError>,
{
    let runtime_config_input = require_existing_path_without_symlinks(runtime_config_path)?;
    let provider_config_input = require_existing_path_without_symlinks(provider_config_path)?;
    let prepared_input = require_existing_path_without_symlinks(prepared_path)?;
    let manifest_input = require_existing_path_without_symlinks(manifest_path)?;
    let runtime_config: M5RuntimeConfig =
        read_canonical_json(&runtime_config_input, MAX_RUNTIME_CONFIG_BYTES)?;
    let provider_config: GovernedLiveProviderConfig =
        read_canonical_json(&provider_config_input, MAX_PROVIDER_CONFIG_BYTES)?;
    let prepared = read_prepared(&prepared_input)?;
    let manifest = read_manifest(&manifest_input)?;
    let runtime_root = require_existing_directory_without_symlinks(&runtime_config.root)?;
    require_proof_input_outside_runtime(&prepared_input, &runtime_root)?;
    require_proof_input_outside_runtime(&manifest_input, &runtime_root)?;

    // The immutable proof-run manifest must already exist and must have
    // frozen precisely this pre-call scope. This check precedes even provider
    // construction, keeping the live qualification causally downstream.
    let prepared_scope = LiveProviderQualificationScope::from_prepared(&prepared)
        .map_err(|_| OperatorError::ManifestScopeMismatch)?;
    if manifest.live_provider_scope() != Some(&prepared_scope) {
        return Err(OperatorError::ManifestScopeMismatch);
    }
    let binding_destination = resolve_output_path(binding_output)?;
    let execution_destination = resolve_output_path(execution_output)?;
    let completed_destination = resolve_output_path(completed_output)?;
    let result_destination = resolve_output_path(result_output)?;
    let output_destinations = [
        &binding_destination,
        &execution_destination,
        &completed_destination,
        &result_destination,
    ];
    for (index, left) in output_destinations.iter().enumerate() {
        for right in output_destinations.iter().skip(index + 1) {
            if left == right {
                return Err(OperatorError::InvalidInput(
                    "binding, execution-receipt, completed-invocation, and result outputs must be different files",
                ));
            }
        }
    }
    let exact_inputs = [
        runtime_config_input,
        provider_config_input,
        prepared_input,
        manifest_input,
    ];
    ensure_output_separation(&binding_destination, &runtime_root, &exact_inputs)?;
    ensure_output_separation(&execution_destination, &runtime_root, &exact_inputs)?;
    ensure_output_separation(&completed_destination, &runtime_root, &exact_inputs)?;
    ensure_output_separation(&result_destination, &runtime_root, &exact_inputs)?;
    for (index, left) in output_destinations.iter().enumerate() {
        for right in output_destinations.iter().skip(index + 1) {
            ensure_distinct_existing_files(left, right)?;
        }
    }
    preflight_existing_binding(&binding_destination, &prepared)?;
    preflight_existing_execution(&execution_destination, &prepared, &manifest)?;
    preflight_completed_destination(&completed_destination)?;
    preflight_existing_result(&result_destination, &prepared, &manifest, &prepared_scope)?;

    // Open without any live provider first. This read-only durable-state pass
    // prevents M5's legitimate terminal idempotency replay from being
    // misrepresented as proof of a provider call made by this invocation.
    let preflight_runtime = M5Runtime::open(runtime_config.clone(), None)
        .map_err(|_| OperatorError::Operation("cannot inspect the exact M5 runtime"))?;
    preflight_runtime_terminal_evidence(&preflight_runtime, &prepared)?;
    drop(preflight_runtime);

    let provider = create_provider(provider_config)?;
    if provider.provider_configuration() != &prepared.precommit.provider_configuration
        || provider.provider_configuration() != &prepared.qualification_request.configuration
    {
        return Err(OperatorError::ExactProviderConfigurationMismatch);
    }
    let runtime = M5Runtime::open_with_governed_live_provider(runtime_config, Arc::new(provider))
        .map_err(|_| {
        OperatorError::Operation("cannot open M5 with the governed provider port")
    })?;
    // Provider construction is deliberately outside the durable runtime lock.
    // Recheck after acquiring the live runtime so a terminal cycle completed
    // in that gap cannot be mistaken for a provider call made by this run.
    preflight_runtime_terminal_evidence(&runtime, &prepared)?;
    let completed = runtime
        .run_current_manifest_provider_invocation(&manifest, prepared.clone())
        .map_err(|_| {
            OperatorError::SensitiveOperation(
                "provider-backed cycle failed; inspect the redacted durable M5 records",
            )
        })?;
    let binding = completed.provider_binding();
    let execution_receipt = completed.execution_receipt();
    let result = M5ProviderProofResultV1::new(&manifest, &prepared_scope, &completed)?;
    let binding_bytes = binding
        .canonical_bytes()
        .map_err(|_| OperatorError::Operation("cannot encode the exact provider binding"))?;
    let execution_bytes = execution_receipt
        .canonical_bytes()
        .map_err(|_| OperatorError::Operation("cannot encode the provider execution receipt"))?;
    let completed_bytes = completed
        .canonical_bytes()
        .map_err(|_| OperatorError::Operation("cannot encode the completed provider invocation"))?;
    let result_bytes = result.canonical_bytes()?;
    drop(runtime);

    // Publish the sole authoritative provider-source artifact first. A crash
    // before this point abandons the exact run; once this publication succeeds,
    // the remaining files are only non-authoritative compatibility projections.
    persist_no_clobber_or_identical(
        &completed_destination,
        &completed_bytes,
        MAX_COMPLETED_INVOCATION_BYTES,
    )?;
    persist_no_clobber_or_identical(&binding_destination, &binding_bytes, MAX_BINDING_BYTES)?;
    persist_no_clobber_or_identical(
        &execution_destination,
        &execution_bytes,
        MAX_EXECUTION_RECEIPT_BYTES,
    )?;
    persist_no_clobber_or_identical(&result_destination, &result_bytes, MAX_RESULT_BYTES)?;
    if let Some(status) = result.cycle_outcome.non_adopted_status() {
        return Err(OperatorError::NonAdoptedOutcome {
            status,
            binding_path: binding_destination,
            execution_path: execution_destination,
            completed_path: completed_destination,
            result_path: result_destination,
        });
    }
    Ok(())
}

fn read_prepared(path: &Path) -> Result<M5PreparedProviderSeedV1, OperatorError> {
    let bytes = read_regular_bounded(path, MAX_PREPARED_BYTES)?;
    M5PreparedProviderSeedV1::from_canonical_bytes(&bytes).map_err(|_| {
        OperatorError::NonCanonicalInput {
            path: path.to_path_buf(),
            kind: "prepared provider seed",
        }
    })
}

fn read_manifest(path: &Path) -> Result<M7ProofRunManifest, OperatorError> {
    let bytes = read_regular_bounded(path, MAX_MANIFEST_BYTES)?;
    M7ProofRunManifest::from_canonical_bytes(&bytes).map_err(|_| OperatorError::NonCanonicalInput {
        path: path.to_path_buf(),
        kind: "M7 proof-run manifest",
    })
}

fn preflight_existing_binding(
    path: &Path,
    prepared: &M5PreparedProviderSeedV1,
) -> Result<(), OperatorError> {
    if !path_exists_without_following(path)? {
        return Ok(());
    }
    let bytes = read_regular_bounded(path, MAX_BINDING_BYTES)?;
    let binding = ProviderCandidateBinding::from_canonical_bytes(&bytes)
        .map_err(|_| OperatorError::DivergentOutput(path.to_path_buf()))?;
    if binding.target != prepared.target
        || binding.qualification.request_digest != prepared.qualification_request.request_digest
        || binding.qualification.configuration_fingerprint
            != prepared.precommit.configuration_fingerprint
    {
        return Err(OperatorError::DivergentOutput(path.to_path_buf()));
    }
    Err(OperatorError::TerminalReplayDetected(
        "the exact detached provider binding already exists",
    ))
}

fn preflight_existing_execution(
    path: &Path,
    prepared: &M5PreparedProviderSeedV1,
    manifest: &M7ProofRunManifest,
) -> Result<(), OperatorError> {
    if !path_exists_without_following(path)? {
        return Ok(());
    }
    let bytes = read_regular_bounded(path, MAX_EXECUTION_RECEIPT_BYTES)?;
    let receipt = M5ProviderExecutionReceiptV1::from_canonical_bytes(&bytes)
        .map_err(|_| OperatorError::DivergentOutput(path.to_path_buf()))?;
    if receipt.proof_run_id != prepared.precommit.proof_run_id
        || &receipt.manifest_digest != manifest.manifest_digest()
        || receipt.prepared_digest != prepared.prepared_digest
        || receipt.precommit_digest != prepared.precommit.precommit_digest
        || receipt.qualification_request_digest != prepared.qualification_request.request_digest
        || receipt.target_digest != prepared.target.target_digest
    {
        return Err(OperatorError::DivergentOutput(path.to_path_buf()));
    }
    Err(OperatorError::TerminalReplayDetected(
        "the exact provider execution receipt already exists",
    ))
}

fn preflight_completed_destination(path: &Path) -> Result<(), OperatorError> {
    if !path_exists_without_following(path)? {
        return Ok(());
    }
    // The completed invocation deliberately has no public decoder or public
    // assembler.  The operator therefore treats every pre-existing completed
    // destination as a fail-closed conflict before entering the live boundary.
    Err(OperatorError::TerminalReplayDetected(
        "a completed provider invocation destination already exists",
    ))
}

fn preflight_existing_result(
    path: &Path,
    prepared: &M5PreparedProviderSeedV1,
    manifest: &M7ProofRunManifest,
    prepared_scope: &LiveProviderQualificationScope,
) -> Result<(), OperatorError> {
    if !path_exists_without_following(path)? {
        return Ok(());
    }
    let bytes = read_regular_bounded(path, MAX_RESULT_BYTES)?;
    let result = M5ProviderProofResultV1::from_canonical_bytes(&bytes)
        .map_err(|_| OperatorError::DivergentOutput(path.to_path_buf()))?;
    if &result.manifest_digest != manifest.manifest_digest()
        || &result.live_provider_scope_digest != prepared_scope.scope_digest()
        || result.prepared_digest != prepared.prepared_digest
        || result.precommit_digest != prepared.precommit.precommit_digest
        || result.provider_configuration_fingerprint != prepared.precommit.configuration_fingerprint
        || result.base_qualification_request_digest != prepared.qualification_request.request_digest
        || result.target_digest != prepared.target.target_digest
    {
        return Err(OperatorError::DivergentOutput(path.to_path_buf()));
    }
    Err(OperatorError::TerminalReplayDetected(
        "the exact terminal provider result already exists",
    ))
}

fn preflight_runtime_terminal_evidence(
    runtime: &M5Runtime,
    prepared: &M5PreparedProviderSeedV1,
) -> Result<(), OperatorError> {
    let expected_fingerprint = prepared
        .qualification_request
        .configuration
        .fingerprint()
        .map_err(|_| OperatorError::Operation("cannot fingerprint the prepared provider config"))?;
    let exact_binding_exists = runtime
        .provider_candidate_bindings()
        .map_err(|_| OperatorError::Operation("cannot inspect durable provider bindings"))?
        .iter()
        .any(|binding| {
            binding.target == prepared.target
                && binding.qualification.qualification_id
                    == prepared.qualification_request.qualification_id
                && binding.qualification.request_digest
                    == prepared.qualification_request.request_digest
                && binding.qualification.target_digest == prepared.target.target_digest
                && binding.qualification.configuration_fingerprint == expected_fingerprint
        });
    if exact_binding_exists {
        return Err(OperatorError::TerminalReplayDetected(
            "the exact durable provider binding already exists in M5",
        ));
    }

    let state = runtime
        .state_snapshot()
        .map_err(|_| OperatorError::Operation("cannot inspect durable M5 reproduction state"))?;
    let exact_qualification_exists = state.provider_qualifications.iter().any(|qualification| {
        qualification.qualification_id == prepared.qualification_request.qualification_id
            && qualification.request_digest == prepared.qualification_request.request_digest
            && qualification.package_digest == prepared.qualification_request.package_digest
            && qualification.target_digest == prepared.target.target_digest
            && qualification.configuration_fingerprint == expected_fingerprint
    });
    if exact_qualification_exists {
        return Err(OperatorError::TerminalReplayDetected(
            "the exact durable provider qualification already exists in M5",
        ));
    }

    let exact_terminal_cycle_exists = state.cycles.iter().any(|cycle| {
        cycle.cycle_id == prepared.plan.cycle_id
            && cycle.parent_package_digest == prepared.target.incumbent_package_digest
            && cycle.challenger_package_digest == prepared.target.candidate_package_digest
            && cycle.challenger_package_bytes_digest
                == prepared.target.candidate_package_bytes_digest
            && cycle.gate_digest == prepared.target.release_gate_digest
            && state.cycle_intents.iter().any(|intent| {
                intent.cycle_id == cycle.cycle_id
                    && intent.expected_active_package_digest
                        == prepared.target.incumbent_package_digest
                    && intent.expected_gate_digest == prepared.target.release_gate_digest
                    && intent.operator_context_digest == prepared.precommit.precommit_digest
                    && intent.seed_genome.as_ref().is_some_and(|genome| {
                        genome.genome_digest == prepared.target.target_genome_digest
                    })
            })
            && !matches!(
                cycle.status,
                CycleStatus::Evaluating | CycleStatus::Approved
            )
    });
    if exact_terminal_cycle_exists {
        return Err(OperatorError::TerminalReplayDetected(
            "the exact terminal provider target already exists in M5",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct M5ProviderProofResultV1 {
    schema: String,
    manifest_digest: ContentDigest,
    live_provider_scope_digest: ContentDigest,
    prepared_digest: ContentDigest,
    precommit_digest: ContentDigest,
    provider_configuration_fingerprint: ContentDigest,
    base_qualification_request_digest: ContentDigest,
    qualification_request_digest: ContentDigest,
    challenged_seed_digest: ContentDigest,
    invocation_challenge_digest: ContentDigest,
    wire_request_digest: ContentDigest,
    request_body_digest: ContentDigest,
    target_digest: ContentDigest,
    qualification_record_digest: ContentDigest,
    qualification_status: ProviderQualificationStatus,
    binding_digest: ContentDigest,
    execution_receipt_digest: ContentDigest,
    terminal_cycle_record_digest: ContentDigest,
    completed_invocation_digest: ContentDigest,
    api_base_url: String,
    endpoint_class: M5ProviderEndpointClassV1,
    cycle_outcome: M5ProviderTerminalOutcomeV1,
    result_digest: ContentDigest,
}

#[derive(Serialize)]
struct ResultDigestMaterial<'a> {
    domain: &'static str,
    manifest_digest: &'a ContentDigest,
    live_provider_scope_digest: &'a ContentDigest,
    prepared_digest: &'a ContentDigest,
    precommit_digest: &'a ContentDigest,
    provider_configuration_fingerprint: &'a ContentDigest,
    base_qualification_request_digest: &'a ContentDigest,
    qualification_request_digest: &'a ContentDigest,
    challenged_seed_digest: &'a ContentDigest,
    invocation_challenge_digest: &'a ContentDigest,
    wire_request_digest: &'a ContentDigest,
    request_body_digest: &'a ContentDigest,
    target_digest: &'a ContentDigest,
    qualification_record_digest: &'a ContentDigest,
    qualification_status: ProviderQualificationStatus,
    binding_digest: &'a ContentDigest,
    execution_receipt_digest: &'a ContentDigest,
    terminal_cycle_record_digest: &'a ContentDigest,
    completed_invocation_digest: &'a ContentDigest,
    api_base_url: &'a str,
    endpoint_class: M5ProviderEndpointClassV1,
    cycle_outcome: &'a M5ProviderTerminalOutcomeV1,
}

impl M5ProviderProofResultV1 {
    fn new(
        manifest: &M7ProofRunManifest,
        prepared_scope: &LiveProviderQualificationScope,
        completed: &M5CompletedProviderInvocationV1,
    ) -> Result<Self, OperatorError> {
        completed.validate().map_err(|_| {
            OperatorError::Operation("completed provider invocation failed validation")
        })?;
        let prepared = completed.prepared_seed();
        let challenged = completed.challenged_seed();
        let binding = completed.provider_binding();
        let outcome = completed.terminal_outcome();
        let execution_receipt = completed.execution_receipt();
        let observed_scope = LiveProviderQualificationScope::from_prepared(prepared)
            .map_err(|_| OperatorError::ManifestScopeMismatch)?;
        execution_receipt
            .validate_for_manifest(manifest, prepared, challenged, binding)
            .map_err(|_| {
                OperatorError::Operation(
                    "completed provider invocation is outside the exact manifest/provider scope",
                )
            })?;
        if &observed_scope != prepared_scope
            || manifest.live_provider_scope() != Some(prepared_scope)
            || binding.target != prepared.target
            || execution_receipt.base_qualification_request_digest
                != prepared.qualification_request.request_digest
            || binding.qualification.request_digest
                != execution_receipt.qualification_request_digest
            || execution_receipt.manifest_digest != *manifest.manifest_digest()
            || execution_receipt.prepared_digest != prepared.prepared_digest
            || execution_receipt.binding_digest != binding.binding_digest
            || &execution_receipt.terminal_outcome != outcome
            || execution_receipt.terminal_cycle_record_digest
                != *completed.terminal_cycle_record_digest()
        {
            return Err(OperatorError::Operation(
                "cannot summarize records outside the exact manifest/provider scope",
            ));
        }
        let mut result = Self {
            schema: RESULT_SCHEMA.to_string(),
            manifest_digest: manifest.manifest_digest().clone(),
            live_provider_scope_digest: prepared_scope.scope_digest().clone(),
            prepared_digest: prepared.prepared_digest.clone(),
            precommit_digest: prepared.precommit.precommit_digest.clone(),
            provider_configuration_fingerprint: prepared
                .precommit
                .configuration_fingerprint
                .clone(),
            base_qualification_request_digest: prepared
                .qualification_request
                .request_digest
                .clone(),
            qualification_request_digest: execution_receipt.qualification_request_digest.clone(),
            challenged_seed_digest: challenged.challenged_digest().clone(),
            invocation_challenge_digest: challenged
                .challenge()
                .invocation_challenge_digest()
                .clone(),
            wire_request_digest: challenged
                .provider_wire_request()
                .wire_request_digest()
                .clone(),
            request_body_digest: challenged
                .provider_wire_request()
                .request_body_digest()
                .clone(),
            target_digest: prepared.target.target_digest.clone(),
            qualification_record_digest: binding.qualification_record_digest.clone(),
            qualification_status: binding.qualification.status,
            binding_digest: binding.binding_digest.clone(),
            execution_receipt_digest: execution_receipt.receipt_digest.clone(),
            terminal_cycle_record_digest: completed.terminal_cycle_record_digest().clone(),
            completed_invocation_digest: completed.completed_invocation_digest().clone(),
            api_base_url: completed.api_base_url().to_string(),
            endpoint_class: completed.endpoint_class(),
            cycle_outcome: execution_receipt.terminal_outcome.clone(),
            result_digest: ContentDigest::from_bytes(&[]),
        };
        result.result_digest = result.expected_digest()?;
        result.validate()?;
        Ok(result)
    }

    fn validate(&self) -> Result<(), OperatorError> {
        if self.schema != RESULT_SCHEMA || self.result_digest != self.expected_digest()? {
            return Err(OperatorError::Operation(
                "redacted provider result failed its content checks",
            ));
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, OperatorError> {
        let bytes = serde_json::to_vec(&ResultDigestMaterial {
            domain: RESULT_DIGEST_DOMAIN,
            manifest_digest: &self.manifest_digest,
            live_provider_scope_digest: &self.live_provider_scope_digest,
            prepared_digest: &self.prepared_digest,
            precommit_digest: &self.precommit_digest,
            provider_configuration_fingerprint: &self.provider_configuration_fingerprint,
            base_qualification_request_digest: &self.base_qualification_request_digest,
            qualification_request_digest: &self.qualification_request_digest,
            challenged_seed_digest: &self.challenged_seed_digest,
            invocation_challenge_digest: &self.invocation_challenge_digest,
            wire_request_digest: &self.wire_request_digest,
            request_body_digest: &self.request_body_digest,
            target_digest: &self.target_digest,
            qualification_record_digest: &self.qualification_record_digest,
            qualification_status: self.qualification_status,
            binding_digest: &self.binding_digest,
            execution_receipt_digest: &self.execution_receipt_digest,
            terminal_cycle_record_digest: &self.terminal_cycle_record_digest,
            completed_invocation_digest: &self.completed_invocation_digest,
            api_base_url: &self.api_base_url,
            endpoint_class: self.endpoint_class,
            cycle_outcome: &self.cycle_outcome,
        })
        .map_err(|_| OperatorError::Operation("cannot derive the redacted result digest"))?;
        Ok(ContentDigest::from_bytes(&bytes))
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, OperatorError> {
        self.validate()?;
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|_| OperatorError::Operation("cannot encode the redacted result"))?;
        if bytes.is_empty() || bytes.len() > MAX_RESULT_BYTES {
            return Err(OperatorError::ResourceBound(
                "redacted result",
                MAX_RESULT_BYTES,
            ));
        }
        Ok(bytes)
    }

    fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, OperatorError> {
        if bytes.is_empty() || bytes.len() > MAX_RESULT_BYTES {
            return Err(OperatorError::ResourceBound(
                "redacted result",
                MAX_RESULT_BYTES,
            ));
        }
        let result: Self = serde_json::from_slice(bytes)
            .map_err(|_| OperatorError::Operation("redacted result is invalid JSON"))?;
        result.validate()?;
        if serde_json::to_vec_pretty(&result)
            .map_err(|_| OperatorError::Operation("cannot re-encode the redacted result"))?
            != bytes
        {
            return Err(OperatorError::Operation(
                "redacted result is not canonical JSON",
            ));
        }
        Ok(result)
    }
}

fn read_canonical_json<T>(path: &Path, limit: usize) -> Result<T, OperatorError>
where
    T: DeserializeOwned + Serialize,
{
    let bytes = read_regular_bounded(path, limit)?;
    if bytes.is_empty() {
        return Err(OperatorError::NonCanonicalInput {
            path: path.to_path_buf(),
            kind: "JSON input",
        });
    }
    let value: T =
        serde_json::from_slice(&bytes).map_err(|_| OperatorError::NonCanonicalInput {
            path: path.to_path_buf(),
            kind: "JSON input",
        })?;
    let canonical =
        serde_json::to_vec_pretty(&value).map_err(|_| OperatorError::NonCanonicalInput {
            path: path.to_path_buf(),
            kind: "JSON input",
        })?;
    if canonical != bytes {
        return Err(OperatorError::NonCanonicalInput {
            path: path.to_path_buf(),
            kind: "JSON input",
        });
    }
    Ok(value)
}

fn read_regular_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, OperatorError> {
    let path = require_existing_path_without_symlinks(path)?;
    let path_metadata = fs::symlink_metadata(&path).map_err(|source| OperatorError::Io {
        path: path.clone(),
        source,
    })?;
    if !path_metadata.is_file()
        || path_metadata.file_type().is_symlink()
        || path_metadata.len() > limit as u64
    {
        return Err(OperatorError::UnsafePath(path));
    }
    let mut file = File::open(&path).map_err(|source| OperatorError::Io {
        path: path.clone(),
        source,
    })?;
    let opened_metadata = file.metadata().map_err(|source| OperatorError::Io {
        path: path.clone(),
        source,
    })?;
    if !opened_metadata.is_file()
        || opened_metadata.len() > limit as u64
        || !same_file_snapshot(&path_metadata, &opened_metadata)
    {
        return Err(OperatorError::UnsafePath(path));
    }
    let mut bytes = Vec::with_capacity(opened_metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| OperatorError::Io {
            path: path.clone(),
            source,
        })?;
    if bytes.len() > limit {
        return Err(OperatorError::ResourceBound("input file", limit));
    }
    let opened_after = file.metadata().map_err(|source| OperatorError::Io {
        path: path.clone(),
        source,
    })?;
    let path_after = fs::symlink_metadata(&path).map_err(|source| OperatorError::Io {
        path: path.clone(),
        source,
    })?;
    if path_after.file_type().is_symlink()
        || !same_file_snapshot(&opened_metadata, &opened_after)
        || !same_file_snapshot(&opened_after, &path_after)
        || opened_after.len() != bytes.len() as u64
    {
        return Err(OperatorError::ChangedDuringRead(path));
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

fn lexical_absolute(path: &Path) -> Result<PathBuf, OperatorError> {
    if path.as_os_str().is_empty()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(OperatorError::UnsafePath(path.to_path_buf()));
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|source| OperatorError::Io {
                path: PathBuf::from("."),
                source,
            })?
            .join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => return Err(OperatorError::UnsafePath(path.to_path_buf())),
            _ => normalized.push(component.as_os_str()),
        }
    }
    Ok(normalized)
}

fn inspect_path_components(
    path: &Path,
    missing_leaf_allowed: bool,
) -> Result<PathBuf, OperatorError> {
    let path = lexical_absolute(path)?;
    let component_count = path.components().count();
    let mut current = PathBuf::new();
    for (index, component) in path.components().enumerate() {
        current.push(component.as_os_str());
        if matches!(component, Component::RootDir | Component::Prefix(_)) {
            continue;
        }
        let is_leaf = index + 1 == component_count;
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(source)
                if source.kind() == std::io::ErrorKind::NotFound
                    && is_leaf
                    && missing_leaf_allowed =>
            {
                return Ok(path);
            }
            Err(source) => {
                return Err(OperatorError::Io {
                    path: current,
                    source,
                });
            }
        };
        if metadata.file_type().is_symlink() || (!is_leaf && !metadata.is_dir()) {
            return Err(OperatorError::UnsafePath(current));
        }
    }
    Ok(path)
}

fn require_existing_path_without_symlinks(path: &Path) -> Result<PathBuf, OperatorError> {
    let inspected = inspect_path_components(path, false)?;
    fs::canonicalize(&inspected).map_err(|source| OperatorError::Io {
        path: inspected,
        source,
    })
}

fn require_existing_directory_without_symlinks(path: &Path) -> Result<PathBuf, OperatorError> {
    let path = require_existing_path_without_symlinks(path)?;
    let metadata = fs::symlink_metadata(&path).map_err(|source| OperatorError::Io {
        path: path.clone(),
        source,
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(OperatorError::UnsafePath(path));
    }
    Ok(path)
}

fn resolve_output_path(path: &Path) -> Result<PathBuf, OperatorError> {
    let path = inspect_path_components(path, true)?;
    let file_name = match path.file_name() {
        Some(name) if !name.is_empty() => name.to_os_string(),
        _ => return Err(OperatorError::UnsafePath(path)),
    };
    let parent = path
        .parent()
        .ok_or_else(|| OperatorError::UnsafePath(path.clone()))?;
    let metadata = fs::symlink_metadata(parent).map_err(|source| OperatorError::Io {
        path: parent.to_path_buf(),
        source,
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(OperatorError::UnsafePath(parent.to_path_buf()));
    }
    let canonical_parent = fs::canonicalize(parent).map_err(|source| OperatorError::Io {
        path: parent.to_path_buf(),
        source,
    })?;
    if canonical_parent.as_os_str().is_empty() {
        return Err(OperatorError::UnsafePath(path));
    }
    Ok(canonical_parent.join(file_name))
}

fn require_proof_input_outside_runtime(
    input: &Path,
    runtime_root: &Path,
) -> Result<(), OperatorError> {
    if input.starts_with(runtime_root) {
        return Err(OperatorError::ArtifactInsideRuntime(input.to_path_buf()));
    }
    Ok(())
}

fn ensure_output_separation(
    output: &Path,
    runtime_root: &Path,
    inputs: &[PathBuf],
) -> Result<(), OperatorError> {
    if output.starts_with(runtime_root) {
        return Err(OperatorError::ArtifactInsideRuntime(output.to_path_buf()));
    }
    for input in inputs {
        if output == input {
            return Err(OperatorError::OutputAliasesInput {
                output: output.to_path_buf(),
                input: input.clone(),
            });
        }
        ensure_distinct_existing_files(output, input)?;
    }
    Ok(())
}

fn ensure_distinct_existing_files(left: &Path, right: &Path) -> Result<(), OperatorError> {
    let left_metadata = match fs::symlink_metadata(left) {
        Ok(metadata) => Some(metadata),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => None,
        Err(source) => {
            return Err(OperatorError::Io {
                path: left.to_path_buf(),
                source,
            });
        }
    };
    let right_metadata = match fs::symlink_metadata(right) {
        Ok(metadata) => Some(metadata),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => None,
        Err(source) => {
            return Err(OperatorError::Io {
                path: right.to_path_buf(),
                source,
            });
        }
    };
    if let (Some(left_metadata), Some(right_metadata)) = (left_metadata, right_metadata) {
        if left_metadata.file_type().is_symlink()
            || right_metadata.file_type().is_symlink()
            || !left_metadata.is_file()
            || !right_metadata.is_file()
        {
            return Err(OperatorError::UnsafePath(
                if !left_metadata.is_file() || left_metadata.file_type().is_symlink() {
                    left.to_path_buf()
                } else {
                    right.to_path_buf()
                },
            ));
        }
        if same_file_identity(&left_metadata, &right_metadata) {
            return Err(OperatorError::OutputAliasesInput {
                output: left.to_path_buf(),
                input: right.to_path_buf(),
            });
        }
    }
    Ok(())
}

#[cfg(unix)]
fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file_identity(_left: &fs::Metadata, _right: &fs::Metadata) -> bool {
    false
}

fn path_exists_without_following(path: &Path) -> Result<bool, OperatorError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                Err(OperatorError::UnsafePath(path.to_path_buf()))
            } else {
                Ok(true)
            }
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(OperatorError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn persist_no_clobber_or_identical(
    path: &Path,
    bytes: &[u8],
    limit: usize,
) -> Result<(), OperatorError> {
    if bytes.is_empty() || bytes.len() > limit {
        return Err(OperatorError::ResourceBound("output file", limit));
    }
    let path = resolve_output_path(path)?;
    if path_exists_without_following(&path)? {
        return if read_regular_bounded(&path, limit)? == bytes {
            Ok(())
        } else {
            Err(OperatorError::DivergentOutput(path))
        };
    }
    let parent = path
        .parent()
        .ok_or_else(|| OperatorError::UnsafePath(path.clone()))?;
    let (temporary, mut file) = create_temporary_file(parent)?;
    let publication = (|| {
        file.write_all(bytes).map_err(|source| OperatorError::Io {
            path: temporary.clone(),
            source,
        })?;
        file.sync_all().map_err(|source| OperatorError::Io {
            path: temporary.clone(),
            source,
        })?;
        drop(file);
        match fs::hard_link(&temporary, &path) {
            Ok(()) => {
                File::open(parent)
                    .and_then(|directory| directory.sync_all())
                    .map_err(|source| OperatorError::Io {
                        path: parent.to_path_buf(),
                        source,
                    })?;
                Ok(())
            }
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
                if read_regular_bounded(&path, limit)? == bytes {
                    Ok(())
                } else {
                    Err(OperatorError::DivergentOutput(path.clone()))
                }
            }
            Err(source) => Err(OperatorError::Io {
                path: path.clone(),
                source,
            }),
        }
    })();
    let cleanup = fs::remove_file(&temporary);
    match (publication, cleanup) {
        (Err(primary), _) => Err(primary),
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(source)) => Err(OperatorError::Io {
            path: temporary,
            source,
        }),
    }
}

fn create_temporary_file(parent: &Path) -> Result<(PathBuf, File), OperatorError> {
    for _ in 0..TEMPORARY_ATTEMPTS {
        let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!(
            ".aiaf-m5-provider-proof-{}-{sequence}.tmp",
            std::process::id()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(source) => return Err(OperatorError::Io { path, source }),
        }
    }
    Err(OperatorError::Operation(
        "cannot allocate a unique same-directory temporary output",
    ))
}

struct Flags {
    values: BTreeMap<String, String>,
}

impl Flags {
    fn parse(args: &[String]) -> Result<Self, OperatorError> {
        let mut values = BTreeMap::new();
        let mut index = 0;
        while index < args.len() {
            let name = &args[index];
            if !name.starts_with("--") || name.len() <= 2 {
                return Err(OperatorError::Usage(usage()));
            }
            let value = args
                .get(index + 1)
                .ok_or_else(|| OperatorError::InvalidFlag(name.clone()))?;
            if values.insert(name.clone(), value.clone()).is_some() {
                return Err(OperatorError::DuplicateFlag(name.clone()));
            }
            index += 2;
        }
        Ok(Self { values })
    }

    fn take(&mut self, name: &str) -> Result<String, OperatorError> {
        self.values
            .remove(name)
            .ok_or_else(|| OperatorError::MissingFlag(name.to_string()))
    }

    fn path(&mut self, name: &str) -> Result<PathBuf, OperatorError> {
        let value = self.take(name)?;
        if value.is_empty() {
            return Err(OperatorError::InvalidFlag(name.to_string()));
        }
        Ok(PathBuf::from(value))
    }

    fn text(&mut self, name: &str) -> Result<String, OperatorError> {
        let value = self.take(name)?;
        if value.trim().is_empty() {
            return Err(OperatorError::InvalidFlag(name.to_string()));
        }
        Ok(value)
    }

    fn u64(&mut self, name: &str) -> Result<u64, OperatorError> {
        self.take(name)?
            .parse::<u64>()
            .map_err(|_| OperatorError::InvalidFlag(name.to_string()))
    }

    fn finish(self) -> Result<(), OperatorError> {
        if let Some(name) = self.values.keys().next() {
            Err(OperatorError::UnknownFlag(name.clone()))
        } else {
            Ok(())
        }
    }
}

#[derive(Debug)]
enum OperatorError {
    Usage(String),
    MissingFlag(String),
    InvalidFlag(String),
    DuplicateFlag(String),
    UnknownFlag(String),
    InvalidInput(&'static str),
    NonCanonicalInput {
        path: PathBuf,
        kind: &'static str,
    },
    UnsafePath(PathBuf),
    ChangedDuringRead(PathBuf),
    ResourceBound(&'static str, usize),
    DivergentOutput(PathBuf),
    ArtifactInsideRuntime(PathBuf),
    OutputAliasesInput {
        output: PathBuf,
        input: PathBuf,
    },
    ExactProviderConfigurationMismatch,
    ManifestScopeMismatch,
    TerminalReplayDetected(&'static str),
    NonAdoptedOutcome {
        status: &'static str,
        binding_path: PathBuf,
        execution_path: PathBuf,
        completed_path: PathBuf,
        result_path: PathBuf,
    },
    Operation(&'static str),
    SensitiveOperation(&'static str),
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

impl Display for OperatorError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage(message) => formatter.write_str(message),
            Self::MissingFlag(name) => write!(formatter, "missing required flag '{name}'"),
            Self::InvalidFlag(name) => write!(formatter, "invalid value for flag '{name}'"),
            Self::DuplicateFlag(name) => write!(formatter, "duplicate flag '{name}'"),
            Self::UnknownFlag(name) => write!(formatter, "unknown flag '{name}'"),
            Self::InvalidInput(message) => formatter.write_str(message),
            Self::NonCanonicalInput { path, kind } => write!(
                formatter,
                "{kind} '{}' is invalid or not in its exact canonical encoding",
                path.display()
            ),
            Self::UnsafePath(path) => write!(
                formatter,
                "path '{}' is a symlink, has a symlink component, or has the wrong file type",
                path.display()
            ),
            Self::ChangedDuringRead(path) => {
                write!(formatter, "input '{}' changed while it was read", path.display())
            }
            Self::ResourceBound(resource, limit) => {
                write!(formatter, "{resource} is empty or exceeds {limit} bytes")
            }
            Self::DivergentOutput(path) => write!(
                formatter,
                "refusing to replace divergent output '{}'",
                path.display()
            ),
            Self::ArtifactInsideRuntime(path) => write!(
                formatter,
                "proof artifact '{}' must be outside the canonical M5 runtime root",
                path.display()
            ),
            Self::OutputAliasesInput { output, input } => write!(
                formatter,
                "output '{}' aliases input '{}'",
                output.display(),
                input.display()
            ),
            Self::ExactProviderConfigurationMismatch => formatter.write_str(
                "provider config does not derive the exact configuration frozen in the prepared seed",
            ),
            Self::ManifestScopeMismatch => formatter.write_str(
                "M7 manifest does not freeze the exact live-provider scope derived from the prepared seed",
            ),
            Self::TerminalReplayDetected(message) => write!(
                formatter,
                "refusing provider call because current-call proof is impossible: {message}"
            ),
            Self::NonAdoptedOutcome {
                status,
                binding_path,
                execution_path,
                completed_path,
                result_path,
            } => write!(
                formatter,
                "provider qualification was recorded, but cycle outcome was {status}; immutable binding '{}', execution receipt '{}', completed invocation '{}', and redacted result '{}' were persisted",
                binding_path.display(),
                execution_path.display(),
                completed_path.display(),
                result_path.display()
            ),
            Self::Operation(message) | Self::SensitiveOperation(message) => {
                formatter.write_str(message)
            }
            Self::Io { path, source } => {
                write!(formatter, "I/O failure at '{}': {source}", path.display())
            }
        }
    }
}

impl Error for OperatorError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            // Sensitive live-operation failures are intentionally not chained.
            _ => None,
        }
    }
}

fn usage() -> String {
    "Usage:\n\
  aiaf-m5-provider-proof prepare --runtime-config <runtime.json> --provider-config <provider.json> --seed-plan <seed-plan.json> --proof-run-id <id> --qualification-id <id> --prepared-at-ms <u64> --out <prepared.json>\n\
  aiaf-m5-provider-proof run --runtime-config <runtime.json> --provider-config <provider.json> --prepared <prepared.json> --manifest <m7-manifest.json> --binding-out <binding.json> --execution-out <execution.json> --completed-out <completed.json> --result-out <result.json>\n\n\
Inputs must be bounded exact pretty-JSON encodings with no symlinks. Run outputs are immutable current-call proof: any prior binding, receipt, completed-invocation destination, result, qualification, or terminal cycle is rejected before the provider boundary. The completed invocation is the authoritative provider-source artifact; binding and receipt files are compatibility projections. The provider configuration names a credential environment variable; this program never accepts or prints credential values, raw provider prompts, or raw provider responses."
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aiaf_v1::execution::component::ComponentExecutionLimits;
    use aiaf_v1::execution::inference::{
        InferenceGenerationPolicy, InferenceProviderMode, InferenceProviderModelEntry,
        InferenceProviderRegistryEntry,
    };
    use aiaf_v1::factory_reproduction::{
        ApprovalDecision, BenchmarkSpec, InvariantKind, InvariantSpec, MutableFactoryPolicy,
        RecursionBudgets, ReleaseGate, ReleaseThresholds, StateCompatibility,
    };
    use aiaf_v1::m1_validation::{ValidationCase, ValidationSuite};
    use aiaf_v1::m5_runtime::M5InitializationAuthority;
    use aiaf_v1::m7_closure::{
        FrozenClosureCriteria, M7Criterion, M7EvidenceFamily, M7ExternalEd25519IdentityV1,
        M7SourceIdentity, M7SourceRootProvenanceV1,
    };
    use std::cell::Cell;
    use std::collections::BTreeSet;

    fn test_root(label: &str) -> PathBuf {
        let temporary_root =
            fs::canonicalize(std::env::temp_dir()).expect("canonical temporary root");
        let root = temporary_root.join(format!(
            "aiaf-m5-provider-proof-{label}-{}-{}",
            std::process::id(),
            TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("create isolated test root");
        root
    }

    fn provider_config() -> GovernedLiveProviderConfig {
        GovernedLiveProviderConfig {
            provider: InferenceProviderRegistryEntry {
                provider_id: "provider-proof-test".to_string(),
                provider_mode: InferenceProviderMode::OpenAiResponses,
                models: vec![InferenceProviderModelEntry {
                    model_ref: "model-proof-test".to_string(),
                    input_cost_per_million_microunits: 1,
                    output_cost_per_million_microunits: 1,
                    supports_json_schema: true,
                    supports_function_tools: true,
                }],
                capability_summary: "bounded JSON and one function tool".to_string(),
                policy_summary: "test construction only".to_string(),
                active: true,
                api_base_url: "https://example.invalid/v1".to_string(),
                api_key_env_var: "AIAF_M5_TEST_KEY_THAT_IS_NEVER_READ".to_string(),
                organization_env_var: None,
                project_env_var: None,
                request_timeout_ms: 1,
            },
            generation_policy: InferenceGenerationPolicy {
                generation_policy_id: "m5-proof-test-policy".to_string(),
                max_output_tokens: 64,
                max_retries: 0,
                summary: "bounded construction-only policy".to_string(),
            },
        }
    }

    struct ExecuteFixture {
        root: PathBuf,
        runtime_config_path: PathBuf,
        provider_config_path: PathBuf,
        prepared_path: PathBuf,
        manifest_path: PathBuf,
        binding_output: PathBuf,
        execution_output: PathBuf,
        completed_output: PathBuf,
        result_output: PathBuf,
        prepared: M5PreparedProviderSeedV1,
    }

    impl Drop for ExecuteFixture {
        fn drop(&mut self) {
            if self.root.exists() {
                fs::remove_dir_all(&self.root).expect("remove execute fixture root");
            }
        }
    }

    impl ExecuteFixture {
        fn new(label: &str, retain_exact_terminal_cycle: bool) -> Self {
            let root = test_root(label);
            let runtime_root = root.join("runtime");
            fs::create_dir(&runtime_root).expect("create M5 runtime root");
            let runtime_config = M5RuntimeConfig {
                root: runtime_root,
                factory_id: "factory:provider-proof-command-test".to_string(),
                scope_id: "scope:provider-proof-command-test".to_string(),
                deployment_id: "deployment-provider-proof-command-test".to_string(),
                worker_max_concurrency: 1,
            };
            let runtime = M5Runtime::initialize(
                runtime_config.clone(),
                incumbent_wat(),
                validation_suite(),
                release_gate(),
                1,
                M5InitializationAuthority {
                    operator_ref: "operator:provider-proof-command-test".to_string(),
                    rationale: "initialize an isolated provider-proof command fixture".to_string(),
                },
                None,
            )
            .expect("initialize real M5 command fixture");
            let provider_config = provider_config();
            let provider = GovernedLiveProviderPort::new(provider_config.clone())
                .expect("construct preparation-only provider");
            let prepared = runtime
                .prepare_provider_backed_seed_cycle(
                    "proof-run:provider-proof-command-test",
                    "qualification:provider-proof-command-test",
                    200,
                    &provider,
                    seed_plan(),
                )
                .expect("prepare exact provider-backed command fixture");
            if retain_exact_terminal_cycle {
                runtime
                    .run_seeded_cycle(prepared.plan.clone())
                    .expect("retain exact terminal cycle without a provider call");
                let state = runtime
                    .state_snapshot()
                    .expect("inspect retained terminal cycle");
                let retained = state
                    .cycles
                    .iter()
                    .find(|cycle| cycle.cycle_id == prepared.plan.cycle_id)
                    .expect("find retained exact cycle");
                assert!(
                    !matches!(
                        retained.status,
                        CycleStatus::Evaluating | CycleStatus::Approved
                    ),
                    "fixture cycle must be terminal"
                );
            }
            drop(runtime);

            let runtime_config_path = root.join("runtime-config.json");
            let provider_config_path = root.join("provider-config.json");
            let prepared_path = root.join("prepared.json");
            let manifest_path = root.join("manifest.json");
            fs::write(
                &runtime_config_path,
                serde_json::to_vec_pretty(&runtime_config).expect("encode runtime config"),
            )
            .expect("write runtime config");
            fs::write(
                &provider_config_path,
                serde_json::to_vec_pretty(&provider_config).expect("encode provider config"),
            )
            .expect("write provider config");
            fs::write(
                &prepared_path,
                prepared.canonical_bytes().expect("encode prepared seed"),
            )
            .expect("write prepared seed");
            fs::write(
                &manifest_path,
                manifest_for(&prepared, true)
                    .canonical_bytes()
                    .expect("encode exact manifest"),
            )
            .expect("write exact manifest");

            Self {
                runtime_config_path,
                provider_config_path,
                prepared_path,
                manifest_path,
                binding_output: root.join("binding.json"),
                execution_output: root.join("execution.json"),
                completed_output: root.join("completed.json"),
                result_output: root.join("result.json"),
                root,
                prepared,
            }
        }

        fn execute_with_observed_provider_factory(
            &self,
            manifest_path: &Path,
            provider_constructions: &Cell<u64>,
        ) -> Result<(), OperatorError> {
            execute_with_provider_factory(
                &self.runtime_config_path,
                &self.provider_config_path,
                &self.prepared_path,
                manifest_path,
                &self.binding_output,
                &self.execution_output,
                &self.completed_output,
                &self.result_output,
                |_| {
                    provider_constructions.set(provider_constructions.get() + 1);
                    Err(OperatorError::Operation(
                        "test observed provider construction boundary",
                    ))
                },
            )
        }

        fn assert_no_outputs(&self) {
            assert!(!self.binding_output.exists());
            assert!(!self.execution_output.exists());
            assert!(!self.completed_output.exists());
            assert!(!self.result_output.exists());
        }
    }

    fn component_wat(body: &str) -> Vec<u8> {
        format!(
            r#"(component
                (core module $implementation
                    (func (export "transform") (param i32) (result i32)
                        {body}))
                (core instance $instance (instantiate $implementation))
                (func (export "transform") (param "input" s32) (result s32)
                    (canon lift (core func $instance "transform"))))"#
        )
        .into_bytes()
    }

    fn incumbent_wat() -> Vec<u8> {
        component_wat("local.get 0")
    }

    fn challenger_wat() -> Vec<u8> {
        component_wat(
            r#"local.get 0
               i32.const -2147483648
               i32.eq
               if (result i32)
                   i32.const 1
               else
                   local.get 0
                   i32.const 1
                   i32.add
               end"#,
        )
    }

    fn validation_suite() -> ValidationSuite {
        ValidationSuite::new(
            "provider-proof-command-suite",
            "transform",
            vec![
                ValidationCase::returns("case:one", 1, 2),
                ValidationCase::returns("case:seven", 7, 8),
            ],
            ComponentExecutionLimits::default(),
        )
        .expect("construct provider-proof command validation suite")
    }

    fn release_gate() -> ReleaseGate {
        let benchmarks = [(1_i32, 2_i32), (7_i32, 8_i32)]
            .into_iter()
            .enumerate()
            .map(|(index, (input, output))| BenchmarkSpec {
                benchmark_id: format!("benchmark:{index}"),
                request_bytes: input.to_le_bytes().to_vec(),
                expected_output_digest: ContentDigest::from_bytes(&output.to_le_bytes()),
                max_duration_ms: 10_000,
                required: true,
            })
            .collect();
        let invariants = [
            InvariantKind::StableInterface,
            InvariantKind::RunnableComponent,
            InvariantKind::ExactPackageIdentity,
            InvariantKind::BoundedCapabilities,
            InvariantKind::DurableRollback,
        ]
        .into_iter()
        .enumerate()
        .map(|(index, kind)| InvariantSpec {
            invariant_id: format!("invariant:{index}"),
            kind,
            required: true,
        })
        .collect();
        ReleaseGate::new(
            "provider-proof-command-gate",
            benchmarks,
            invariants,
            RecursionBudgets {
                max_generation_depth: 4,
                max_total_cycles: 8,
                max_shadow_tasks: 4,
                max_component_bytes: 1_048_576,
                max_state_bytes: 4_096,
                max_provider_turns: 4,
            },
            ReleaseThresholds {
                minimum_passed_benchmarks: 2,
                minimum_success_basis_points: 10_000,
                maximum_regressions: 0,
                require_all_required_invariants: true,
                minimum_post_activation_successes: 2,
            },
        )
        .expect("construct provider-proof command release gate")
    }

    fn seed_plan() -> M5SeedCyclePlan {
        M5SeedCyclePlan {
            cycle_id: "cycle:provider-proof-command-test".to_string(),
            challenger_wat_bytes: challenger_wat(),
            challenger_policy: MutableFactoryPolicy::terminal(2, 2),
            state_compatibility: StateCompatibility {
                readable_schema_min: 1,
                readable_schema_max: 2,
                written_schema: 1,
                incumbent_rollback_readable_through: 2,
            },
            migration_plan: None,
            migration_artifacts: None,
            operator_context_digest: ContentDigest::from_bytes(b"unbound-command-test-context"),
            approval_decision: ApprovalDecision::Approved,
            approver_ref: "operator:provider-proof-command-test".to_string(),
            approval_rationale: "approve isolated provider-proof command fixture".to_string(),
        }
    }

    fn frozen_criteria() -> FrozenClosureCriteria {
        let statement = "M0-M6 must be proven from their exact bounded authoritative sources.";
        FrozenClosureCriteria::new(
            "criteria:provider-proof-command-test",
            "1.0.0",
            100,
            vec![M7Criterion {
                criterion_id: "criterion:m0-m6".to_string(),
                statement: statement.to_string(),
                statement_digest: ContentDigest::from_bytes(statement.as_bytes()),
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
        )
        .expect("freeze command-test closure criteria")
    }

    fn manifest_for(prepared: &M5PreparedProviderSeedV1, exact_scope: bool) -> M7ProofRunManifest {
        let scope = exact_scope.then(|| {
            LiveProviderQualificationScope::from_prepared(prepared)
                .expect("derive exact live-provider scope")
        });
        M7ProofRunManifest::new(
            prepared.precommit.proof_run_id.clone(),
            300,
            frozen_criteria(),
            M7SourceIdentity {
                commit_oid: "0123456789abcdef0123456789abcdef01234567".to_string(),
                commit_object_digest: ContentDigest::from_bytes(b"command-test-commit-object"),
                tree_oid: "89abcdef0123456789abcdef0123456789abcdef".to_string(),
                tree_digest: ContentDigest::from_bytes(b"command-test-tree-object"),
                checkout_root_digest: ContentDigest::from_bytes(b"command-test-checkout-root"),
                toolchain_digest: ContentDigest::from_bytes(b"command-test-toolchain"),
                lockfile_digest: ContentDigest::from_bytes(b"command-test-lockfile"),
                root_provenance: M7SourceRootProvenanceV1::FreshCleanCheckout,
            },
            M7ExternalEd25519IdentityV1::new("attestor:command-test", &[0x41; 32])
                .expect("construct source-capture identity"),
            M7ExternalEd25519IdentityV1::new("reviewer:command-test", &[0x42; 32])
                .expect("construct reviewer identity"),
            ContentDigest::from_bytes(b"command-test-causal-chain"),
            BTreeSet::from(["implementer:command-test".to_string()]),
            BTreeSet::from([ContentDigest::from_bytes(
                b"command-test-implementation-identity",
            )]),
            scope,
        )
        .expect("construct command-test proof-run manifest")
    }

    #[test]
    fn governed_provider_config_is_canonical_and_constructs_without_a_live_call() {
        let root = test_root("provider-config");
        let path = root.join("provider.json");
        let config = provider_config();
        fs::write(&path, serde_json::to_vec_pretty(&config).expect("encode"))
            .expect("write config");
        let decoded: GovernedLiveProviderConfig =
            read_canonical_json(&path, MAX_PROVIDER_CONFIG_BYTES).expect("read canonical config");
        assert_eq!(decoded, config);
        // `new` validates public inputs and builds exact schemas; it neither
        // reads the named environment variable nor performs network I/O.
        let port = GovernedLiveProviderPort::new(decoded).expect("construct governed port");
        assert_eq!(
            port.provider_configuration().provider_id,
            "provider-proof-test"
        );
        fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn run_rejects_missing_manifest_before_provider_construction() {
        let fixture = ExecuteFixture::new("missing-manifest-boundary", false);
        let missing_manifest = fixture.root.join("missing-manifest.json");
        let provider_constructions = Cell::new(0);

        let error = fixture
            .execute_with_observed_provider_factory(&missing_manifest, &provider_constructions)
            .expect_err("missing manifest must fail closed");

        assert!(matches!(
            error,
            OperatorError::Io { source, .. }
                if source.kind() == std::io::ErrorKind::NotFound
        ));
        assert_eq!(provider_constructions.get(), 0);
        fixture.assert_no_outputs();
    }

    #[test]
    fn run_rejects_scope_mismatched_manifest_before_provider_construction() {
        let fixture = ExecuteFixture::new("manifest-scope-boundary", false);
        let mismatched_manifest_path = fixture.root.join("scope-mismatched-manifest.json");
        fs::write(
            &mismatched_manifest_path,
            manifest_for(&fixture.prepared, false)
                .canonical_bytes()
                .expect("encode scope-mismatched manifest"),
        )
        .expect("write scope-mismatched manifest");
        let provider_constructions = Cell::new(0);

        let error = fixture
            .execute_with_observed_provider_factory(
                &mismatched_manifest_path,
                &provider_constructions,
            )
            .expect_err("scope-mismatched manifest must fail closed");

        assert!(matches!(error, OperatorError::ManifestScopeMismatch));
        assert_eq!(provider_constructions.get(), 0);
        fixture.assert_no_outputs();
    }

    #[test]
    fn run_rejects_exact_durable_terminal_replay_before_provider_construction() {
        let fixture = ExecuteFixture::new("durable-terminal-replay-boundary", true);
        let provider_constructions = Cell::new(0);

        let error = fixture
            .execute_with_observed_provider_factory(&fixture.manifest_path, &provider_constructions)
            .expect_err("exact durable terminal replay must fail closed");

        assert!(matches!(
            error,
            OperatorError::TerminalReplayDetected(
                "the exact terminal provider target already exists in M5"
            )
        ));
        assert_eq!(provider_constructions.get(), 0);
        fixture.assert_no_outputs();
    }

    #[test]
    fn run_rechecks_terminal_replay_under_the_live_runtime_lock() {
        let fixture = ExecuteFixture::new("terminal-replay-lock-gap", false);
        let runtime_config: M5RuntimeConfig =
            read_canonical_json(&fixture.runtime_config_path, MAX_RUNTIME_CONFIG_BYTES)
                .expect("read exact runtime config");
        let prepared = fixture.prepared.clone();
        let provider_constructions = Cell::new(0);

        let error = execute_with_provider_factory(
            &fixture.runtime_config_path,
            &fixture.provider_config_path,
            &fixture.prepared_path,
            &fixture.manifest_path,
            &fixture.binding_output,
            &fixture.execution_output,
            &fixture.completed_output,
            &fixture.result_output,
            |provider_config| {
                provider_constructions.set(provider_constructions.get() + 1);
                let competing_runtime = M5Runtime::open(runtime_config.clone(), None)
                    .expect("open competing runtime in the preflight gap");
                competing_runtime
                    .run_seeded_cycle(prepared.plan.clone())
                    .expect("complete the exact cycle in the preflight gap");
                drop(competing_runtime);
                GovernedLiveProviderPort::new(provider_config)
                    .map_err(|_| OperatorError::Operation("construct governed test provider"))
            },
        )
        .expect_err("locked terminal replay recheck must fail closed");

        assert!(matches!(
            error,
            OperatorError::TerminalReplayDetected(
                "the exact terminal provider target already exists in M5"
            )
        ));
        assert_eq!(provider_constructions.get(), 1);
        fixture.assert_no_outputs();
    }

    #[test]
    fn canonical_reader_rejects_format_drift() {
        let root = test_root("canonical");
        let path = root.join("runtime.json");
        let config = M5RuntimeConfig {
            root: root.clone(),
            factory_id: "factory-proof-test".to_string(),
            scope_id: "scope-proof-test".to_string(),
            deployment_id: "deployment-proof-test".to_string(),
            worker_max_concurrency: 1,
        };
        let mut noncanonical = serde_json::to_vec_pretty(&config).expect("encode");
        noncanonical.push(b'\n');
        fs::write(&path, noncanonical).expect("write input");
        assert!(read_canonical_json::<M5RuntimeConfig>(&path, MAX_RUNTIME_CONFIG_BYTES).is_err());
        fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn immutable_publication_accepts_only_identical_replay() {
        let root = test_root("publication");
        let path = root.join("record.json");
        persist_no_clobber_or_identical(&path, b"{\"proof\":1}", 64).expect("first publish");
        persist_no_clobber_or_identical(&path, b"{\"proof\":1}", 64).expect("identical replay");
        assert!(persist_no_clobber_or_identical(&path, b"{\"proof\":2}", 64).is_err());
        assert_eq!(fs::read(&path).expect("read result"), b"{\"proof\":1}");
        fs::remove_dir_all(root).expect("remove test root");
    }

    #[cfg(unix)]
    #[test]
    fn input_symlink_is_rejected() {
        use std::os::unix::fs::symlink;

        let root = test_root("symlink");
        let target = root.join("target.json");
        let link = root.join("link.json");
        fs::write(&target, b"{}").expect("write target");
        symlink(&target, &link).expect("create link");
        assert!(read_regular_bounded(&link, 64).is_err());
        fs::remove_dir_all(root).expect("remove test root");
    }
}
