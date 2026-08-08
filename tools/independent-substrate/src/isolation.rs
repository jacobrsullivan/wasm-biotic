//! Independent adversarial proof for R2 principal isolation.
//!
//! This is a release test client, not part of the substrate boundary. It
//! selects principals only from signed profile data and exercises generic WIT
//! mechanisms without branching on factory roles, services or policy.

use crate::bindings::root;
use crate::model::{Digest, Result, canonical_json};
use crate::package::LoadedRelease;
use crate::reproduce::{current_binary_digest, source_tree_digest};
use crate::substrate::{HostState, InMemorySubstrate};
use serde::Serialize;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::rc::Rc;

const REPORT_SCHEMA: &str = "wasm-biotic.independent-principal-isolation.v1";
const PROFILE_V2: &str = "wasm-biotic.factory-substrate-profile.v2";
const PROFILE_V3: &str = "wasm-biotic.factory-substrate-profile.v3";

#[derive(Clone)]
struct AliasIdentity {
    alias: String,
    capability: String,
    consumer: String,
    principal_seed: Digest,
}

#[derive(Serialize)]
struct IsolationCase {
    action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    atomic_commit_owner_handoff: Option<bool>,
    attacker_consumer: String,
    attacker_principal_seed: Digest,
    capability: String,
    expected_failure: String,
    id: String,
    mechanism_state_after_digest: Digest,
    mechanism_state_before_digest: Digest,
    mechanism_state_unchanged: bool,
    observed_failure: String,
    protected_operation_retained: Option<bool>,
    result: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    restart_persistence_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rollback_owner_handback: Option<bool>,
    victim_consumer: Option<String>,
    victim_principal_seed: Option<Digest>,
}

#[derive(Serialize)]
struct CampaignSummary {
    caller_owned_idempotency_enforced: bool,
    caller_owned_poll_cancel_enforced: bool,
    caller_target_edges_enforced: bool,
    cases_passed: usize,
    cases_total: usize,
    cross_capability_escalation_rejected: bool,
    forged_alias_rejected: bool,
    graph_qualified_activation_owner_handoff_enforced: bool,
    mechanism_state_unchanged_on_every_rejection: bool,
    two_distinct_principals_exercised: bool,
}

#[derive(Serialize)]
struct ReleaseIdentity {
    certification_digest: Digest,
    derivation_descriptor_digest: Digest,
    graph_manifest_digest: Digest,
    import_alias_scheme: String,
    principal_count: usize,
    principal_id_scheme: String,
    principal_inventory_digest: Digest,
    substrate_profile_digest: Digest,
}

#[derive(Serialize)]
struct ToolIdentity {
    binary_digest: Digest,
    native_tcb_inventory_digest: Digest,
    source_tree_digest: Digest,
}

#[derive(Serialize)]
struct IsolationReport {
    caller_identity_source: &'static str,
    cases: Vec<IsolationCase>,
    component_complete_claim: bool,
    outcome: &'static str,
    release: ReleaseIdentity,
    schema: &'static str,
    substrate: &'static str,
    successor_release: ReleaseIdentity,
    summary: CampaignSummary,
    tool: ToolIdentity,
}

pub fn run(
    incumbent_directory: impl AsRef<Path>,
    successor_directory: impl AsRef<Path>,
    certifier_public_key_hex: &str,
    report_path: impl AsRef<Path>,
) -> Result<Digest> {
    let release = Rc::new(LoadedRelease::load(
        incumbent_directory,
        certifier_public_key_hex,
    )?);
    let successor = Rc::new(LoadedRelease::load(
        successor_directory,
        certifier_public_key_hex,
    )?);
    require(
        matches!(release.profile.schema.as_str(), PROFILE_V2 | PROFILE_V3)
            && successor.profile.schema == release.profile.schema,
        "isolation campaign requires a same-version scoped profile pair",
    )?;
    let successor_release = release_identity(&successor)?;
    let substrate = InMemorySubstrate::new(release.clone())?;
    let mut state = HostState::root(substrate.clone())?;
    let aliases = aliases(&release);
    let cases = vec![
        forged_alias_case(&substrate, &mut state, &release)?,
        cross_capability_case(&substrate, &mut state, &aliases)?,
        clock_ownership_case(&substrate, &mut state, &aliases, &release)?,
        transaction_ownership_case(&substrate, &mut state, &aliases)?,
        caller_target_case(&substrate, &mut state, &aliases, &release)?,
        runner_ownership_case(&substrate, &mut state, &aliases, &release)?,
        activation_owner_handoff_case(&substrate, &mut state, &aliases, &release, successor)?,
    ];

    let cases_passed = cases.iter().filter(|case| case.result == "pass").count();
    let exercised = cases
        .iter()
        .flat_map(|case| {
            [
                Some(case.attacker_principal_seed),
                case.victim_principal_seed,
            ]
        })
        .flatten()
        .collect::<BTreeSet<_>>();
    let summary = CampaignSummary {
        caller_owned_idempotency_enforced: passed(&cases, "cross-principal-idempotency"),
        caller_owned_poll_cancel_enforced: passed(&cases, "cross-principal-clock-operation")
            && passed(&cases, "cross-principal-run-operation"),
        caller_target_edges_enforced: passed(&cases, "caller-target-edge"),
        cases_passed,
        cases_total: cases.len(),
        cross_capability_escalation_rejected: passed(&cases, "cross-capability-escalation"),
        forged_alias_rejected: passed(&cases, "forged-alias"),
        graph_qualified_activation_owner_handoff_enforced: passed(
            &cases,
            "graph-qualified-activation-owner-handoff",
        ),
        mechanism_state_unchanged_on_every_rejection: cases
            .iter()
            .all(|case| case.mechanism_state_unchanged),
        two_distinct_principals_exercised: exercised.len() >= 2,
    };
    let outcome = if summary.cases_passed == summary.cases_total
        && summary.caller_owned_idempotency_enforced
        && summary.caller_owned_poll_cancel_enforced
        && summary.caller_target_edges_enforced
        && summary.cross_capability_escalation_rejected
        && summary.forged_alias_rejected
        && summary.graph_qualified_activation_owner_handoff_enforced
        && summary.mechanism_state_unchanged_on_every_rejection
        && summary.two_distinct_principals_exercised
    {
        "pass"
    } else {
        "fail"
    };
    let report = IsolationReport {
        caller_identity_source: "validated-linker-alias-not-component-input",
        cases,
        component_complete_claim: false,
        outcome,
        release: release_identity(&release)?,
        schema: REPORT_SCHEMA,
        substrate: "independent-in-memory",
        successor_release,
        summary,
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
    require(
        outcome == "pass",
        "independent principal isolation campaign failed",
    )?;
    Ok(digest)
}

fn release_identity(release: &LoadedRelease) -> Result<ReleaseIdentity> {
    Ok(ReleaseIdentity {
        certification_digest: release.index.certification_digest,
        derivation_descriptor_digest: release.metadata.derivation_descriptor_digest,
        graph_manifest_digest: release.index.graph_manifest_digest,
        import_alias_scheme: release
            .profile
            .import_alias_scheme
            .clone()
            .ok_or("R2 profile has no alias scheme")?,
        principal_count: release.profile.principals.len(),
        principal_id_scheme: release
            .profile
            .principal_id_scheme
            .clone()
            .ok_or("R2 profile has no principal scheme")?,
        principal_inventory_digest: release.principal_inventory_digest()?,
        substrate_profile_digest: release.metadata.substrate_profile_digest,
    })
}

fn aliases(release: &LoadedRelease) -> Vec<AliasIdentity> {
    release
        .profile
        .principals
        .iter()
        .flat_map(|principal| {
            principal.host_imports.iter().map(|import| AliasIdentity {
                alias: import.alias.clone(),
                capability: import.capability.clone(),
                consumer: principal.consumer.clone(),
                principal_seed: principal.principal_seed,
            })
        })
        .collect()
}

fn forged_alias_case(
    substrate: &InMemorySubstrate,
    state: &mut HostState,
    release: &LoadedRelease,
) -> Result<IsolationCase> {
    let pure = release
        .profile
        .principals
        .iter()
        .find(|principal| principal.host_imports.is_empty())
        .ok_or("R2 profile has no pure principal")?;
    let before = snapshot_digest(substrate)?;
    let error = state
        .with_alias(
            "wasm-biotic:factory/host-0000000000000000000000000000000000000000000000000000000000000000@0.1.0",
            |_| (),
        )
        .expect_err("forged alias must be rejected");
    let after = snapshot_digest(substrate)?;
    Ok(case(
        "forged-alias",
        "select-undeclared-linker-alias",
        pure.consumer.clone(),
        pure.principal_seed,
        None,
        None,
        "linker-alias",
        "undeclared-alias",
        if error.to_string().contains("undeclared") {
            "undeclared-alias"
        } else {
            "unexpected"
        },
        before,
        after,
        None,
    ))
}

fn cross_capability_case(
    substrate: &InMemorySubstrate,
    state: &mut HostState,
    aliases: &[AliasIdentity],
) -> Result<IsolationCase> {
    let attacker = aliases
        .iter()
        .find(|alias| alias.capability != "blob-store")
        .ok_or("R2 profile has no non-blob alias")?;
    let victim = aliases
        .iter()
        .find(|alias| alias.capability == "blob-store" && alias.consumer != attacker.consumer);
    let before = snapshot_digest(substrate)?;
    let error = state
        .with_alias(&attacker.alias, |state| {
            <HostState as root::wasm_biotic::factory::blob_store::Host>::put(
                state,
                "application/octet-stream".to_string(),
                b"cross-capability".to_vec(),
            )
        })?
        .expect_err("cross-capability call must be rejected");
    let after = snapshot_digest(substrate)?;
    Ok(case(
        "cross-capability-escalation",
        "invoke-blob-through-non-blob-alias",
        attacker.consumer.clone(),
        attacker.principal_seed,
        victim.map(|alias| alias.consumer.clone()),
        victim.map(|alias| alias.principal_seed),
        "blob-store",
        "not-granted",
        &error.code,
        before,
        after,
        None,
    ))
}

fn clock_ownership_case(
    substrate: &InMemorySubstrate,
    state: &mut HostState,
    aliases: &[AliasIdentity],
    release: &LoadedRelease,
) -> Result<IsolationCase> {
    let pair = distinct_pair(aliases, "clock")?;
    let wake_id = "independent-isolation-wake".to_string();
    let request = root::wasm_biotic::factory::clock::WakeRequest {
        wake_id: wake_id.clone(),
        not_before_ms: substrate.now(),
        target_component: wit_digest(release.index.root_authority_digest),
        payload_digest: wit_digest(Digest::of(b"isolation-wake-payload")),
        idempotency_key: wit_digest(Digest::of(b"isolation-wake-key")),
    };
    state.with_alias(&pair.0.alias, |state| {
        <HostState as root::wasm_biotic::factory::clock::Host>::schedule_wake(state, request)
    })??;
    let before = snapshot_digest(substrate)?;
    let poll = state.with_alias(&pair.1.alias, |state| {
        <HostState as root::wasm_biotic::factory::clock::Host>::poll_wake(state, wake_id.clone())
    })?;
    let cancel = state.with_alias(&pair.1.alias, |state| {
        <HostState as root::wasm_biotic::factory::clock::Host>::cancel_wake(state, wake_id)
    })?;
    let observed = match (poll, cancel) {
        (Err(left), Err(right)) if left.code == "not-owned" && right.code == "not-owned" => {
            "not-owned"
        }
        _ => "unexpected",
    };
    let after = snapshot_digest(substrate)?;
    Ok(case(
        "cross-principal-clock-operation",
        "poll-and-cancel-another-principal-wake",
        pair.1.consumer.clone(),
        pair.1.principal_seed,
        Some(pair.0.consumer.clone()),
        Some(pair.0.principal_seed),
        "clock",
        "not-owned",
        observed,
        before,
        after,
        Some(
            substrate
                .mechanism_snapshot()
                .wakes
                .iter()
                .any(|wake| wake.wake_id == "independent-isolation-wake"),
        ),
    ))
}

fn transaction_ownership_case(
    substrate: &InMemorySubstrate,
    state: &mut HostState,
    aliases: &[AliasIdentity],
) -> Result<IsolationCase> {
    let pair = distinct_pair(aliases, "transaction-store")?;
    let request = root::wasm_biotic::factory::transaction_store::CommitRequest {
        transaction_id: "independent-isolation-transaction".to_string(),
        assertions: Vec::new(),
        mutations: Vec::new(),
        idempotency_key: wit_digest(Digest::of(b"isolation-transaction-key")),
    };
    state.with_alias(&pair.0.alias, |state| {
        <HostState as root::wasm_biotic::factory::transaction_store::Host>::commit(
            state,
            request.clone(),
        )
    })??;
    let before = snapshot_digest(substrate)?;
    let error = state
        .with_alias(&pair.1.alias, |state| {
            <HostState as root::wasm_biotic::factory::transaction_store::Host>::commit(
                state, request,
            )
        })?
        .expect_err("cross-principal idempotency replay must be rejected");
    let after = snapshot_digest(substrate)?;
    Ok(case(
        "cross-principal-idempotency",
        "reuse-another-principal-transaction-key",
        pair.1.consumer.clone(),
        pair.1.principal_seed,
        Some(pair.0.consumer.clone()),
        Some(pair.0.principal_seed),
        "transaction-store",
        "not-owned",
        &error.code,
        before,
        after,
        None,
    ))
}

fn caller_target_case(
    substrate: &InMemorySubstrate,
    state: &mut HostState,
    aliases: &[AliasIdentity],
    release: &LoadedRelease,
) -> Result<IsolationCase> {
    let attacker = aliases
        .iter()
        .find(|alias| alias.capability == "component-runner")
        .ok_or("R2 profile has no component-runner alias")?;
    let allowed = release
        .manifest
        .invocations
        .iter()
        .filter(|edge| edge.consumer == attacker.consumer)
        .map(|edge| edge.target.as_str())
        .collect::<BTreeSet<_>>();
    let victim = release
        .manifest
        .invocations
        .iter()
        .find(|edge| !allowed.contains(edge.target.as_str()))
        .ok_or("R2 topology has no cross-caller target negative control")?;
    let input = substrate
        .put(
            "application/octet-stream".to_string(),
            b"isolation-target".to_vec(),
        )
        .map_err(|failure| format!("{}: {}", failure.code, failure.message))?;
    let request = run_request(
        "isolation-forbidden-target",
        release.node_digest(&victim.target)?,
        &input,
        Digest::of(b"isolation-forbidden-target-key"),
        release,
    );
    let before = snapshot_digest(substrate)?;
    let error = state
        .with_alias(&attacker.alias, |state| {
            <HostState as root::wasm_biotic::factory::component_runner::Host>::start(state, request)
        })?
        .expect_err("cross-caller target must be rejected");
    let after = snapshot_digest(substrate)?;
    let victim_principal = release
        .profile
        .principals
        .iter()
        .find(|principal| principal.consumer == victim.target)
        .ok_or("target has no R2 principal")?;
    Ok(case(
        "caller-target-edge",
        "start-component-outside-caller-invocation-edges",
        attacker.consumer.clone(),
        attacker.principal_seed,
        Some(victim.target.clone()),
        Some(victim_principal.principal_seed),
        "component-runner",
        "not-granted",
        &error.code,
        before,
        after,
        None,
    ))
}

fn runner_ownership_case(
    substrate: &InMemorySubstrate,
    state: &mut HostState,
    aliases: &[AliasIdentity],
    release: &LoadedRelease,
) -> Result<IsolationCase> {
    let runners = aliases
        .iter()
        .filter(|alias| alias.capability == "component-runner")
        .collect::<Vec<_>>();
    require(
        runners.len() >= 2,
        "R2 profile has fewer than two runner principals",
    )?;
    let (owner, edge) = runners
        .iter()
        .filter_map(|runner| {
            release
                .manifest
                .invocations
                .iter()
                .filter(|edge| edge.consumer == runner.consumer)
                .map(|edge| (*runner, edge))
                .min_by_key(|(_, edge)| {
                    release
                        .node_digest(&edge.target)
                        .ok()
                        .and_then(|digest| release.executables.get(&digest))
                        .map_or(usize::MAX, |artifact| {
                            artifact.descriptor.source_digests.len()
                        })
                })
        })
        .min_by_key(|(_, edge)| {
            release
                .node_digest(&edge.target)
                .ok()
                .and_then(|digest| release.executables.get(&digest))
                .map_or(usize::MAX, |artifact| {
                    artifact.descriptor.source_digests.len()
                })
        })
        .ok_or("runner principals have no invocation edges")?;
    let attacker = runners
        .into_iter()
        .find(|runner| runner.consumer != owner.consumer)
        .ok_or("runner ownership campaign has no distinct attacker")?;
    let input = substrate
        .put(
            "application/octet-stream".to_string(),
            b"isolation-run".to_vec(),
        )
        .map_err(|failure| format!("{}: {}", failure.code, failure.message))?;
    let request = run_request(
        "isolation-owned-run",
        release.node_digest(&edge.target)?,
        &input,
        Digest::of(b"isolation-owned-run-key"),
        release,
    );
    let operation = state.with_alias(&owner.alias, |state| {
        <HostState as root::wasm_biotic::factory::component_runner::Host>::start(state, request)
    })??;
    let before = snapshot_digest(substrate)?;
    let poll = state.with_alias(&attacker.alias, |state| {
        <HostState as root::wasm_biotic::factory::component_runner::Host>::poll(
            state,
            operation.clone(),
        )
    })?;
    let cancel = state.with_alias(&attacker.alias, |state| {
        <HostState as root::wasm_biotic::factory::component_runner::Host>::cancel(
            state,
            operation.clone(),
        )
    })?;
    let observed = match (poll, cancel) {
        (Err(left), Err(right)) if left.code == "not-owned" && right.code == "not-owned" => {
            "not-owned"
        }
        _ => "unexpected",
    };
    let retained = state
        .with_alias(&owner.alias, |state| {
            <HostState as root::wasm_biotic::factory::component_runner::Host>::poll(
                state, operation,
            )
        })??
        .is_some();
    let after = snapshot_digest(substrate)?;
    Ok(case(
        "cross-principal-run-operation",
        "poll-and-cancel-another-principal-run",
        attacker.consumer.clone(),
        attacker.principal_seed,
        Some(owner.consumer.clone()),
        Some(owner.principal_seed),
        "component-runner",
        "not-owned",
        observed,
        before,
        after,
        Some(retained),
    ))
}

fn activation_owner_handoff_case(
    substrate: &InMemorySubstrate,
    source_state: &mut HostState,
    aliases: &[AliasIdentity],
    release: &LoadedRelease,
    successor: Rc<LoadedRelease>,
) -> Result<IsolationCase> {
    let (owner, attacker) = distinct_pair(aliases, "activation")?;
    let target_owner = successor
        .profile
        .principals
        .iter()
        .find(|principal| principal.consumer == owner.consumer)
        .ok_or("successor omits the activation owner principal")?;
    require(
        target_owner.principal_seed == owner.principal_seed,
        "successor activation owner changes principal seed",
    )?;
    let target_owner_alias = target_owner
        .host_imports
        .iter()
        .find(|import| import.capability == "activation" && import.scope == "switch")
        .ok_or("successor activation owner has no switch import")?
        .alias
        .clone();
    let target_attacker = successor
        .profile
        .principals
        .iter()
        .find(|principal| principal.consumer == attacker.consumer)
        .ok_or("successor omits the activation attacker principal")?;
    let target_attacker_alias = target_attacker
        .host_imports
        .iter()
        .find(|import| import.capability == "activation" && import.scope == "switch")
        .ok_or("successor has no second activation principal")?
        .alias
        .clone();

    let target_graph = successor.index.graph_manifest_digest;
    let target_substrate = substrate.admit_release(successor)?;
    let target_manifest = target_substrate
        .admitted_manifest(target_graph)
        .ok_or("successor manifest was not admitted")?;
    let active = substrate.mechanism_snapshot();
    let activation_id = "independent-graph-qualified-handoff".to_string();
    let request = root::wasm_biotic::factory::activation::ActivationRequest {
        activation_id: activation_id.clone(),
        graph_manifest: root::wasm_biotic::factory::foundation::BlobRef {
            content_digest: wit_digest(target_manifest.digest),
            size_bytes: target_manifest.size_bytes,
            media_type: target_manifest.media_type,
        },
        expected_active_graph: Some(wit_digest(active.active_graph)),
        expected_active_state: active.active_state.map(|state| {
            root::wasm_biotic::factory::foundation::BlobRef {
                content_digest: wit_digest(state.digest),
                size_bytes: state.size_bytes,
                media_type: state.media_type,
            }
        }),
        state_migration: None,
        migrated_state: None,
        idempotency_key: wit_digest(Digest::of(b"independent-graph-qualified-handoff")),
    };
    source_state.with_alias(&owner.alias, |state| {
        <HostState as root::wasm_biotic::factory::activation::Host>::stage(state, request)
    })??;
    source_state.with_alias(&owner.alias, |state| {
        <HostState as root::wasm_biotic::factory::activation::Host>::commit(
            state,
            activation_id.clone(),
        )
    })??;
    let atomic_commit_owner_handoff = substrate.mechanism_snapshot().active_graph == target_graph
        && substrate.activation_owner(&activation_id) == Some((target_graph, owner.principal_seed));

    let mut target_state = HostState::root(target_substrate.clone())?;
    let rejection_before = snapshot_digest(substrate)?;
    let stale_source = source_state.with_alias(&owner.alias, |state| {
        <HostState as root::wasm_biotic::factory::activation::Host>::status(
            state,
            activation_id.clone(),
        )
    })?;
    let wrong_seed = target_state.with_alias(&target_attacker_alias, |state| {
        <HostState as root::wasm_biotic::factory::activation::Host>::status(
            state,
            activation_id.clone(),
        )
    })?;
    let wrong_graph = target_state.with_alias(&target_owner_alias, |state| {
        <HostState as root::wasm_biotic::factory::activation::Host>::rollback(
            state,
            activation_id.clone(),
            wit_digest(target_graph),
        )
    })?;
    let protected = target_state
        .with_alias(&target_owner_alias, |state| {
            <HostState as root::wasm_biotic::factory::activation::Host>::status(
                state,
                activation_id.clone(),
            )
        })?
        .is_ok();
    let rejection_after = snapshot_digest(substrate)?;

    drop(target_state);
    let mut restarted_target = HostState::root(target_substrate)?;
    let restart_persistence_verified = restarted_target
        .with_alias(&target_owner_alias, |state| {
            <HostState as root::wasm_biotic::factory::activation::Host>::status(
                state,
                activation_id.clone(),
            )
        })?
        .is_ok();
    restarted_target.with_alias(&target_owner_alias, |state| {
        <HostState as root::wasm_biotic::factory::activation::Host>::rollback(
            state,
            activation_id.clone(),
            wit_digest(release.index.graph_manifest_digest),
        )
    })??;
    let rollback_owner_handback = substrate.mechanism_snapshot().active_graph
        == release.index.graph_manifest_digest
        && substrate.activation_owner(&activation_id)
            == Some((release.index.graph_manifest_digest, owner.principal_seed));
    let handback_rejection_before = snapshot_digest(substrate)?;
    let stale_target = restarted_target.with_alias(&target_owner_alias, |state| {
        <HostState as root::wasm_biotic::factory::activation::Host>::status(
            state,
            activation_id.clone(),
        )
    })?;
    let mut restarted_source = HostState::root(substrate.clone())?;
    let source_recovered = restarted_source
        .with_alias(&owner.alias, |state| {
            <HostState as root::wasm_biotic::factory::activation::Host>::status(
                state,
                activation_id.clone(),
            )
        })?
        .is_ok();
    let handback_rejection_after = snapshot_digest(substrate)?;

    let rejection_codes_match = matches!(stale_source, Err(ref failure) if failure.code == "not-owned")
        && matches!(wrong_seed, Err(ref failure) if failure.code == "not-owned")
        && matches!(wrong_graph, Err(ref failure) if failure.code == "rollback-target-mismatch")
        && matches!(stale_target, Err(ref failure) if failure.code == "not-owned");
    let all_invariants = atomic_commit_owner_handoff
        && restart_persistence_verified
        && rollback_owner_handback
        && source_recovered
        && rejection_codes_match
        && rejection_before == rejection_after
        && handback_rejection_before == handback_rejection_after;
    let observed = if all_invariants {
        "graph-qualified-handoff-enforced"
    } else {
        "unexpected"
    };
    let mut evidence = case(
        "graph-qualified-activation-owner-handoff",
        "commit-owner-to-target-reject-stale-and-wrong-rollback-owner-to-lkg-after-restart",
        attacker.consumer.clone(),
        attacker.principal_seed,
        Some(owner.consumer.clone()),
        Some(owner.principal_seed),
        "activation",
        "graph-qualified-handoff-enforced",
        observed,
        rejection_before,
        rejection_after,
        Some(protected),
    );
    evidence.atomic_commit_owner_handoff = Some(atomic_commit_owner_handoff);
    evidence.restart_persistence_verified = Some(restart_persistence_verified);
    evidence.rollback_owner_handback = Some(rollback_owner_handback);
    Ok(evidence)
}

#[allow(clippy::too_many_arguments)]
fn case(
    id: &str,
    action: &str,
    attacker_consumer: String,
    attacker_principal_seed: Digest,
    victim_consumer: Option<String>,
    victim_principal_seed: Option<Digest>,
    capability: &str,
    expected: &str,
    observed: &str,
    before: Digest,
    after: Digest,
    protected_operation_retained: Option<bool>,
) -> IsolationCase {
    let pass = expected == observed
        && before == after
        && protected_operation_retained.is_none_or(|retained| retained);
    IsolationCase {
        action: action.to_string(),
        atomic_commit_owner_handoff: None,
        attacker_consumer,
        attacker_principal_seed,
        capability: capability.to_string(),
        expected_failure: expected.to_string(),
        id: id.to_string(),
        mechanism_state_after_digest: after,
        mechanism_state_before_digest: before,
        mechanism_state_unchanged: before == after,
        observed_failure: observed.to_string(),
        protected_operation_retained,
        result: if pass { "pass" } else { "fail" },
        restart_persistence_verified: None,
        rollback_owner_handback: None,
        victim_consumer,
        victim_principal_seed,
    }
}

fn distinct_pair<'a>(
    aliases: &'a [AliasIdentity],
    capability: &str,
) -> Result<(&'a AliasIdentity, &'a AliasIdentity)> {
    let first = aliases
        .iter()
        .find(|alias| alias.capability == capability)
        .ok_or_else(|| format!("R2 profile has no {capability} alias"))?;
    let second = aliases
        .iter()
        .find(|alias| alias.capability == capability && alias.consumer != first.consumer)
        .ok_or_else(|| format!("R2 profile has no second {capability} principal"))?;
    Ok((first, second))
}

fn run_request(
    run_id: &str,
    component_digest: Digest,
    input: &crate::substrate::CoreBlob,
    idempotency_key: Digest,
    release: &LoadedRelease,
) -> root::wasm_biotic::factory::component_runner::RunRequest {
    root::wasm_biotic::factory::component_runner::RunRequest {
        run_id: run_id.to_string(),
        component_digest: wit_digest(component_digest),
        input: root::wasm_biotic::factory::foundation::BlobRef {
            content_digest: wit_digest(input.digest),
            size_bytes: input.size_bytes,
            media_type: input.media_type.clone(),
        },
        grants: Vec::new(),
        limits: root::wasm_biotic::factory::foundation::ResourceLimits {
            fuel: release
                .profile
                .ceilings
                .max_component_fuel
                .clamp(1, 1_000_000),
            memory_bytes: release
                .profile
                .ceilings
                .max_component_memory_bytes
                .clamp(1, 8 * 1024 * 1024),
            output_bytes: release
                .profile
                .ceilings
                .max_component_output_bytes
                .clamp(1, 1024 * 1024),
            wall_time_ms: release
                .profile
                .ceilings
                .max_component_wall_time_ms
                .clamp(1, 5_000),
        },
        idempotency_key: wit_digest(idempotency_key),
    }
}

fn wit_digest(digest: Digest) -> root::wasm_biotic::factory::foundation::Digest {
    root::wasm_biotic::factory::foundation::Digest {
        algorithm: root::wasm_biotic::factory::foundation::HashAlgorithm::Sha256,
        hex: digest.hex(),
    }
}

fn snapshot_digest(substrate: &InMemorySubstrate) -> Result<Digest> {
    Ok(Digest::of(&canonical_json(
        &substrate.mechanism_snapshot(),
    )?))
}

fn passed(cases: &[IsolationCase], id: &str) -> bool {
    cases
        .iter()
        .find(|case| case.id == id)
        .is_some_and(|case| case.result == "pass")
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string().into())
    }
}
