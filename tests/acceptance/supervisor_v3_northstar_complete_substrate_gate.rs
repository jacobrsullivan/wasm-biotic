use aiaf_v1::execution::{
    ActivationEnvelope, ActiveGenerationState, ApprovalClass, ArtifactDigest,
    ArtifactLineageRecord, AuthorityClass, CapabilityEnvelope, CapabilityWorld,
    CapabilityWorldGrant, ComponentBuildOutput, ComponentBuildRequest, ComponentExecutionContext,
    ComponentImportBinding, DurableArtifactStore, GenerationArtifactBundle, GenerationManifest,
    IsolationProfile, V3SubstrateCompletionEvidence, V3SubstrateCompletionStatus,
    ValidationScenario, activate_generation, build_component_package,
    compare_packages_with_execution_context, evaluate_v3_substrate_completion_gate,
    execute_validation_plan_with_context, expected_output_ref, inspect_component_bytes,
    record_successor_production, rollback_generation, start_adopted_generation_campaign,
};
use std::env;
use std::process;

fn build_generation_bundle(
    artifact_id: &str,
    parent_digest: Option<ArtifactDigest>,
    produced_by_generation_digest: Option<ArtifactDigest>,
) -> (GenerationArtifactBundle, ComponentBuildOutput) {
    let manifest = GenerationManifest::new(
        format!("generation-{artifact_id}"),
        parent_digest.clone(),
        "package:aiaf/supervisor@v3",
        "aiaf-supervisor-v3",
        vec![format!("src:{artifact_id}")],
        vec!["policy:bounded-single-factory".to_string()],
        vec![format!("input:{artifact_id}")],
        format!("generation {artifact_id} manifest"),
    )
    .unwrap();
    let build = build_component_package(ComponentBuildRequest {
        build_id: format!("build-{artifact_id}"),
        manifest: manifest.clone(),
        wit_source:
            r#"world aiaf-supervisor-v3 { import host-pulse: func(); export run: func(); }"#
                .to_string(),
        component_source: component_run_wat(),
        required_capability_world_refs: vec![
            "world:artifact-packaging".to_string(),
            "world:semantic-validation".to_string(),
            "world:native-supervisor-challenger".to_string(),
        ],
    })
    .unwrap();
    let activation = ActivationEnvelope::new(
        format!("activation-{artifact_id}"),
        manifest.artifact_id.clone(),
        build.package_manifest.bundle_digest.clone(),
        build.package_manifest.capability_world_refs.clone(),
        parent_digest.clone(),
        format!("observation-window-{artifact_id}"),
        true,
    )
    .unwrap();
    let lineage = ArtifactLineageRecord::new(
        format!("lineage-{artifact_id}"),
        manifest.artifact_id.clone(),
        parent_digest,
        manifest.manifest_digest().unwrap(),
        build.package_manifest.bundle_digest.clone(),
        produced_by_generation_digest,
        vec![
            build.build_id.clone(),
            build.package_manifest.package_id.clone(),
        ],
    )
    .unwrap();
    let bundle = GenerationArtifactBundle::new(
        manifest,
        build.build_closure.clone(),
        build.package_manifest.clone(),
        activation,
        lineage,
    )
    .unwrap();
    (bundle, build)
}

fn component_run_wat() -> String {
    r#"
        (component
            (import "host-pulse" (func $host-pulse))
            (core func $host-pulse-core (canon lower (func $host-pulse)))
            (core module $m
                (import "" "host-pulse" (func $host-pulse))
                (func (export "run")
                    call $host-pulse))
            (core instance $i (instantiate $m
                (with "" (instance
                    (export "host-pulse" (func $host-pulse-core))))))
            (func $run (canon lift (core func $i "run")))
            (export "run" (func $run)))
    "#
    .to_string()
}

fn component_execution_context(envelope_id: &str) -> ComponentExecutionContext {
    ComponentExecutionContext {
        capability_envelope: CapabilityEnvelope {
            envelope_id: envelope_id.to_string(),
            actor_scope: "v3-substrate-component".to_string(),
            world_grants: vec![CapabilityWorldGrant {
                world: CapabilityWorld::ServiceOrganelle,
                allowed_operations: vec!["pulse".to_string()],
                default_authority_class: AuthorityClass::Observe,
                default_approval_class: ApprovalClass::AutoAllowed,
                operation_approval_overrides: Vec::new(),
            }],
            authority_ceiling: AuthorityClass::Observe,
            isolation_profile: IsolationProfile::ArtifactSandbox,
            allowed_resource_scopes: vec!["scope:host-pulse".to_string()],
            approval_overrides: Vec::new(),
            quota_policy: None,
            campaign_scope: None,
            epoch_scope: None,
        },
        import_bindings: vec![ComponentImportBinding {
            import_name: "host-pulse".to_string(),
            world: CapabilityWorld::ServiceOrganelle,
            operation: "pulse".to_string(),
            resource_scope: "scope:host-pulse".to_string(),
            required_authority_class: AuthorityClass::Observe,
        }],
    }
}

#[test]
fn northstar_complete_v3_substrate_gate_is_kernel_owned_and_replayable() {
    let root = env::temp_dir().join(format!(
        "aiaf-v3-northstar-complete-substrate-{}",
        process::id()
    ));
    let store = DurableArtifactStore::bootstrap(root).unwrap();

    let (incumbent_bundle, incumbent_build) = build_generation_bundle("incumbent", None, None);
    let incumbent_context = component_execution_context("envelope-v3-incumbent");
    let (challenger_bundle, challenger_build) = build_generation_bundle(
        "challenger",
        Some(incumbent_bundle.package.bundle_digest.clone()),
        None,
    );
    let challenger_context = component_execution_context("envelope-v3-challenger");

    store
        .persist_generation_artifact_bundle(&challenger_bundle)
        .unwrap();
    store
        .persist_component_build_output(&challenger_build)
        .unwrap();
    assert_eq!(
        store
            .load_component_build_output(&challenger_build.build_id)
            .unwrap()
            .component_digest,
        challenger_build.component_digest
    );
    assert_eq!(
        challenger_build.package_manifest.interface_imports,
        vec!["host-pulse".to_string()]
    );
    let reloaded = store
        .load_generation_artifact_bundle(challenger_bundle.package_digest())
        .unwrap();
    assert_eq!(
        reloaded.package.bundle_digest,
        challenger_bundle.package.bundle_digest
    );
    assert!(
        inspect_component_bytes(
            &challenger_build.component_bytes,
            "aiaf-supervisor-v3",
            challenger_build
                .package_manifest
                .capability_world_refs
                .clone()
        )
        .unwrap()
        .executable
    );

    let validation = execute_validation_plan_with_context(
        "validation-challenger",
        &challenger_bundle.package,
        &challenger_build.component_bytes,
        &challenger_context,
        vec![ValidationScenario {
            scenario_id: "scenario-shared-1".to_string(),
            input_ref: "shared-input-1".to_string(),
            export_name: "run".to_string(),
            expected_result_ref: expected_output_ref(&challenger_bundle.package, "run"),
        }],
        vec!["event-validation-challenger".to_string()],
    )
    .unwrap();
    assert!(validation.passed);
    assert_eq!(validation.import_link_audits.len(), 1);
    store
        .persist_execution_validation_record(&validation)
        .unwrap();
    let reloaded_validation = store
        .load_execution_validation_record(&validation.trace_ref)
        .unwrap();
    assert_eq!(reloaded_validation.output_refs, validation.output_refs);
    assert_eq!(
        reloaded_validation.import_link_audits,
        validation.import_link_audits
    );

    let comparison = compare_packages_with_execution_context(
        "comparison-v3-execution-backed",
        &incumbent_bundle.package,
        &incumbent_build.component_bytes,
        &incumbent_context,
        &challenger_bundle.package,
        &challenger_build.component_bytes,
        &challenger_context,
        vec!["shared-input-1".to_string()],
    )
    .unwrap();
    assert!(comparison.comparison_record.matched);
    assert!(!comparison.incumbent_trace.trace_ref.is_empty());
    assert!(!comparison.challenger_trace.trace_ref.is_empty());
    assert_eq!(comparison.challenger_trace.import_link_audits.len(), 1);
    store
        .persist_execution_comparison_bundle(&comparison)
        .unwrap();
    assert_eq!(
        store
            .load_execution_comparison_bundle(&comparison.comparison_record.comparison_id)
            .unwrap()
            .comparison_record
            .matched,
        comparison.comparison_record.matched
    );

    let mut active_state = ActiveGenerationState::initial(
        "single-factory-v3",
        incumbent_bundle.package.bundle_digest.clone(),
    )
    .unwrap();
    let activation = activate_generation(
        &mut active_state,
        &challenger_bundle.activation,
        &challenger_bundle.package,
    )
    .unwrap();
    assert_eq!(
        active_state.active_generation_digest,
        challenger_bundle.package.bundle_digest
    );

    let mut rollback_probe = active_state.clone();
    let rollback = rollback_generation(&mut rollback_probe, "rollback-v3").unwrap();
    assert_eq!(
        rollback.restored_generation_digest,
        incumbent_bundle.package.bundle_digest
    );
    store
        .persist_active_generation_state(&active_state)
        .unwrap();
    assert_eq!(
        store
            .load_active_generation_state(&active_state.state_id)
            .unwrap()
            .active_generation_digest,
        active_state.active_generation_digest
    );

    let mut campaign = start_adopted_generation_campaign(
        "campaign-successor-v3",
        &active_state,
        "successor-request-v3",
    )
    .unwrap();
    let (successor_bundle, successor_build) = build_generation_bundle(
        "successor",
        Some(active_state.active_generation_digest.clone()),
        Some(active_state.active_generation_digest.clone()),
    );
    let successor_context = component_execution_context("envelope-v3-successor");
    store
        .persist_generation_artifact_bundle(&successor_bundle)
        .unwrap();
    store
        .persist_component_build_output(&successor_build)
        .unwrap();
    assert_eq!(
        store
            .load_generation_artifact_bundle(successor_bundle.package_digest())
            .unwrap()
            .package
            .bundle_digest,
        successor_bundle.package.bundle_digest
    );
    assert_eq!(
        store
            .load_component_build_output(&successor_build.build_id)
            .unwrap()
            .component_digest,
        successor_build.component_digest
    );
    let successor_validation = execute_validation_plan_with_context(
        "validation-successor",
        &successor_bundle.package,
        &successor_build.component_bytes,
        &successor_context,
        vec![ValidationScenario {
            scenario_id: "scenario-successor-1".to_string(),
            input_ref: "successor-input-1".to_string(),
            export_name: "run".to_string(),
            expected_result_ref: expected_output_ref(&successor_bundle.package, "run"),
        }],
        vec!["event-validation-successor".to_string()],
    )
    .unwrap();
    let successor_record = record_successor_production(
        "record-successor-v3",
        &mut campaign,
        &successor_bundle,
        &successor_validation,
    )
    .unwrap();
    store.persist_self_production_campaign(&campaign).unwrap();
    store
        .persist_successor_production_record(&successor_record)
        .unwrap();
    assert_eq!(
        store
            .load_self_production_campaign(&campaign.campaign_id)
            .unwrap()
            .status,
        campaign.status
    );
    assert_eq!(
        store
            .load_successor_production_record(&successor_record.record_id)
            .unwrap()
            .successor_package_digest,
        successor_record.successor_package_digest
    );

    let gate = evaluate_v3_substrate_completion_gate(
        "gate-v3-northstar-complete-substrate",
        V3SubstrateCompletionEvidence {
            artifact_digest: challenger_bundle.lineage.generation_digest.clone(),
            package_digest: challenger_bundle.package.bundle_digest.clone(),
            component_build_ref: challenger_build.build_id.clone(),
            validation_trace_ref: validation.trace_ref.clone(),
            comparison_ref: comparison.comparison_record.comparison_id.clone(),
            activation_ref: activation.activation_id,
            rollback_ref: rollback.rollback_id,
            successor_campaign_ref: campaign.campaign_id,
            successor_digest: successor_bundle.package.bundle_digest.clone(),
        },
    );

    assert_eq!(gate.status, V3SubstrateCompletionStatus::Satisfied);
    assert!(
        gate.anti_overclaim_boundary
            .contains("does not claim federation")
    );
    store.persist_v3_substrate_completion_gate(&gate).unwrap();
    assert_eq!(
        store
            .load_v3_substrate_completion_gate("gate-v3-northstar-complete-substrate")
            .unwrap()
            .status,
        V3SubstrateCompletionStatus::Satisfied
    );

    assert_eq!(
        incumbent_build.package_manifest.generation_id.to_string(),
        "generation-incumbent"
    );
}
