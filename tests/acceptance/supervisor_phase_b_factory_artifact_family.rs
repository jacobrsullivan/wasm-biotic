use aiaf_v1::execution::{
    ActiveFactoryState, DurableArtifactStore, FactoryActivationBundle, FactoryComparisonDimension,
    FactoryComparisonOutcome, FactoryComparisonRecord, FactoryDimensionScore,
    FactoryDimensionVerdict, FactoryEvidencePacket, FactoryGenomeArtifact, FactoryGovernanceState,
    FactoryLineageRecord, FactoryPhenotypeArtifact, FactoryValidationProfile, activate_factory,
    build_factory_rollback_envelope, evaluate_factory_candidate, observe_active_factory,
    quarantine_factory_candidate, record_factory_governance_transition, rollback_factory,
};
use std::env;
use std::fs;
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_store_root(name: &str) -> std::path::PathBuf {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should remain after unix epoch")
        .as_nanos();
    env::temp_dir().join(format!("aiaf-phase-b-{name}-{}-{timestamp}", process::id()))
}

#[test]
fn supervisor_phase_b_factory_artifact_family_acceptance() {
    let root = temp_store_root("factory-artifact-family");
    let store = DurableArtifactStore::bootstrap(root.join("store")).unwrap();

    let incumbent_genome = FactoryGenomeArtifact {
        factory_genome_id: "factory-genome-incumbent".to_string(),
        parent_factory_ref: None,
        stable_contract_refs: vec!["contract:v1".to_string()],
        worker_topology_refs: vec!["topology:bounded-supervisor".to_string()],
        service_closure_refs: vec!["service:v4-shell".to_string()],
        governance_policy_refs: vec!["governance:bounded-adoption".to_string()],
        shell_profile_refs: vec!["shell-profile:v4".to_string()],
        summary: "bounded incumbent factory genome".to_string(),
    };
    let challenger_genome = FactoryGenomeArtifact {
        factory_genome_id: "factory-genome-challenger".to_string(),
        parent_factory_ref: Some(incumbent_genome.factory_genome_id.clone()),
        stable_contract_refs: vec!["contract:v1".to_string()],
        worker_topology_refs: vec![
            "topology:bounded-supervisor".to_string(),
            "topology:review-worker".to_string(),
        ],
        service_closure_refs: vec![
            "service:v4-shell".to_string(),
            "service:factory-validation".to_string(),
        ],
        governance_policy_refs: vec!["governance:bounded-adoption".to_string()],
        shell_profile_refs: vec!["shell-profile:v4".to_string()],
        summary: "challenger factory genome with explicit validation closure".to_string(),
    };

    let incumbent_phenotype = FactoryPhenotypeArtifact {
        factory_phenotype_id: "factory-phenotype-incumbent".to_string(),
        factory_genome_ref: incumbent_genome.factory_genome_id.clone(),
        package_refs: vec!["pkg:incumbent".to_string()],
        entrypoint_refs: vec!["entry:runner".to_string()],
        boundary_refs: vec!["boundary:v1".to_string()],
        validation_profile_refs: vec!["factory-validation-profile-1".to_string()],
        summary: "incumbent bounded factory package".to_string(),
    };
    let challenger_phenotype = FactoryPhenotypeArtifact {
        factory_phenotype_id: "factory-phenotype-challenger".to_string(),
        factory_genome_ref: challenger_genome.factory_genome_id.clone(),
        package_refs: vec!["pkg:challenger".to_string()],
        entrypoint_refs: vec!["entry:runner".to_string(), "entry:review".to_string()],
        boundary_refs: vec!["boundary:v1".to_string()],
        validation_profile_refs: vec!["factory-validation-profile-1".to_string()],
        summary: "challenger bounded factory package".to_string(),
    };

    let lineage = FactoryLineageRecord {
        lineage_id: "factory-lineage-1".to_string(),
        factory_genome_ref: challenger_genome.factory_genome_id.clone(),
        ancestor_refs: vec![incumbent_genome.factory_genome_id.clone()],
        preserved_constraint_refs: vec![
            "constraint:fixed-interface".to_string(),
            "constraint:bounded-governance".to_string(),
        ],
        claim_boundary: "bounded single-factory improvement only".to_string(),
    };

    let validation_profile = FactoryValidationProfile {
        validation_profile_id: "factory-validation-profile-1".to_string(),
        factory_candidate_ref: challenger_phenotype.factory_phenotype_id.clone(),
        scenario_refs: vec![
            "scenario:phase-a-live-shell".to_string(),
            "scenario:factory-artifact-review".to_string(),
        ],
        required_dimension_refs: vec![
            FactoryComparisonDimension::SemanticCorrectness,
            FactoryComparisonDimension::GovernanceFidelity,
            FactoryComparisonDimension::Replayability,
            FactoryComparisonDimension::ReplacementSafety,
        ],
        required_evidence_refs: vec![
            "shell:bundle-1".to_string(),
            "governance:audit-1".to_string(),
            "continuity:memory-1".to_string(),
            "replay:checkpoint-1".to_string(),
            "review:packet-1".to_string(),
        ],
        failure_policy_refs: vec!["failure-policy:rollback-on-regression".to_string()],
    };

    let validation_evidence = aiaf_v1::execution::FactoryValidationEvidence {
        evidence_id: "factory-validation-evidence-1".to_string(),
        factory_candidate_ref: challenger_phenotype.factory_phenotype_id.clone(),
        shell_evidence_refs: vec!["shell:bundle-1".to_string()],
        governance_refs: vec!["governance:audit-1".to_string()],
        continuity_refs: vec!["continuity:memory-1".to_string()],
        replay_refs: vec!["replay:checkpoint-1".to_string()],
        operator_review_refs: vec!["review:packet-1".to_string()],
        failure_refs: Vec::new(),
        summary: "challenger factory remained replayable under bounded review".to_string(),
    };

    let validation_record = evaluate_factory_candidate(
        "factory-validation-record-1",
        &validation_profile,
        &validation_evidence,
        "challenger factory satisfied the bounded validation profile",
    )
    .unwrap();

    let comparison = FactoryComparisonRecord {
        comparison_id: "factory-comparison-1".to_string(),
        incumbent_factory_ref: incumbent_phenotype.factory_phenotype_id.clone(),
        challenger_factory_ref: challenger_phenotype.factory_phenotype_id.clone(),
        dimension_scores: vec![
            FactoryDimensionScore {
                dimension: FactoryComparisonDimension::SemanticCorrectness,
                verdict: FactoryDimensionVerdict::Equivalent,
                incumbent_summary: "incumbent stayed semantically correct".to_string(),
                challenger_summary: "challenger stayed semantically correct".to_string(),
            },
            FactoryDimensionScore {
                dimension: FactoryComparisonDimension::GovernanceFidelity,
                verdict: FactoryDimensionVerdict::Equivalent,
                incumbent_summary: "incumbent stayed within governance boundaries".to_string(),
                challenger_summary: "challenger preserved governance boundaries".to_string(),
            },
            FactoryDimensionScore {
                dimension: FactoryComparisonDimension::Replayability,
                verdict: FactoryDimensionVerdict::ChallengerBetter,
                incumbent_summary: "incumbent replay remained adequate".to_string(),
                challenger_summary: "challenger replay evidence remained more explicit".to_string(),
            },
            FactoryDimensionScore {
                dimension: FactoryComparisonDimension::ReplacementSafety,
                verdict: FactoryDimensionVerdict::ChallengerBetter,
                incumbent_summary: "incumbent rollback remained bounded".to_string(),
                challenger_summary: "challenger adoption evidence improved rollback clarity"
                    .to_string(),
            },
        ],
        shared_input_refs: vec![
            "shared-input:scenario-pack".to_string(),
            "shared-input:contract-map".to_string(),
        ],
        evidence_refs: vec![
            validation_record.validation_id.clone(),
            validation_evidence.evidence_id.clone(),
        ],
        outcome: FactoryComparisonOutcome::AdoptChallenger,
        summary: "challenger factory improved replayability and replacement safety".to_string(),
    };

    let activation_bundle = FactoryActivationBundle {
        activation_id: "factory-activation-1".to_string(),
        comparison_ref: comparison.comparison_id.clone(),
        adopted_factory_ref: challenger_phenotype.factory_phenotype_id.clone(),
        retained_incumbent_ref: incumbent_phenotype.factory_phenotype_id.clone(),
        observation_window_ref: "factory-observation-window-1".to_string(),
        rollback_handle_ref: "factory-rollback-handle-1".to_string(),
    };

    let mut factory_state = ActiveFactoryState::initial(
        "factory-state-1",
        incumbent_phenotype.factory_phenotype_id.clone(),
    )
    .unwrap();
    let activation_record = activate_factory(&mut factory_state, &activation_bundle).unwrap();
    let observation_report = observe_active_factory(
        activation_bundle.observation_window_ref.clone(),
        &factory_state,
        vec![
            "event:factory-adopted".to_string(),
            "event:factory-shell-replay".to_string(),
        ],
        "challenger factory stayed stable through the bounded observation window",
    )
    .unwrap();
    let rollback_record = rollback_factory(&mut factory_state, "factory-rollback-1").unwrap();
    let governance_transition_validated = record_factory_governance_transition(
        "factory-governance-transition-validated-1",
        challenger_phenotype.factory_phenotype_id.clone(),
        FactoryGovernanceState::CandidatePrepared,
        FactoryGovernanceState::CandidateValidated,
        vec![
            validation_profile.validation_profile_id.clone(),
            validation_record.validation_id.clone(),
        ],
        vec![activation_bundle.rollback_handle_ref.clone()],
    )
    .unwrap();
    let governance_transition_adopted = record_factory_governance_transition(
        "factory-governance-transition-adopted-1",
        challenger_phenotype.factory_phenotype_id.clone(),
        FactoryGovernanceState::CandidateValidated,
        FactoryGovernanceState::Adopted,
        vec![
            comparison.comparison_id.clone(),
            activation_bundle.activation_id.clone(),
        ],
        vec![
            activation_bundle.rollback_handle_ref.clone(),
            rollback_record.rollback_id.clone(),
        ],
    )
    .unwrap();
    let rollback_envelope = build_factory_rollback_envelope(
        "factory-rollback-envelope-1",
        &rollback_record,
        vec![
            factory_state.state_id.clone(),
            activation_bundle.activation_id.clone(),
        ],
        vec![
            validation_record.validation_id.clone(),
            validation_evidence.evidence_id.clone(),
            observation_report.observation_window_ref.clone(),
        ],
        "rollback envelope preserves runtime and evidence symmetry for the retained incumbent",
    )
    .unwrap();
    let quarantine_record = quarantine_factory_candidate(
        "factory-quarantine-record-1",
        challenger_phenotype.factory_phenotype_id.clone(),
        vec![
            rollback_record.rollback_id.clone(),
            observation_report.observation_window_ref.clone(),
        ],
        vec![
            lineage.lineage_id.clone(),
            challenger_genome.factory_genome_id.clone(),
        ],
        vec![
            rollback_record.rollback_id.clone(),
            rollback_envelope.rollback_id.clone(),
        ],
        "challenger factory remains inspectable after bounded rollback and quarantine closure",
    )
    .unwrap();

    let evidence_packet = FactoryEvidencePacket {
        packet_id: "factory-evidence-packet-1".to_string(),
        genome_ref: challenger_genome.factory_genome_id.clone(),
        phenotype_ref: challenger_phenotype.factory_phenotype_id.clone(),
        lineage_ref: lineage.lineage_id.clone(),
        comparison_ref: comparison.comparison_id.clone(),
        activation_ref: activation_bundle.activation_id.clone(),
        rollback_ref: rollback_record.rollback_id.clone(),
        claim_boundary: "bounded single-factory adoption with rollback retained".to_string(),
    };

    store
        .persist_factory_genome_artifact(&incumbent_genome)
        .unwrap();
    store
        .persist_factory_genome_artifact(&challenger_genome)
        .unwrap();
    store
        .persist_factory_phenotype_artifact(&incumbent_phenotype)
        .unwrap();
    store
        .persist_factory_phenotype_artifact(&challenger_phenotype)
        .unwrap();
    store.persist_factory_lineage_record(&lineage).unwrap();
    store
        .persist_factory_validation_profile(&validation_profile)
        .unwrap();
    store
        .persist_factory_validation_evidence(&validation_evidence)
        .unwrap();
    store
        .persist_factory_validation_record(&validation_record)
        .unwrap();
    store
        .persist_factory_comparison_record(&comparison)
        .unwrap();
    store
        .persist_factory_activation_bundle(&activation_bundle)
        .unwrap();
    store.persist_active_factory_state(&factory_state).unwrap();
    store
        .persist_factory_governance_transition(&governance_transition_validated)
        .unwrap();
    store
        .persist_factory_governance_transition(&governance_transition_adopted)
        .unwrap();
    store
        .persist_factory_rollback_envelope(&rollback_envelope)
        .unwrap();
    store
        .persist_factory_quarantine_record(&quarantine_record)
        .unwrap();
    store
        .persist_factory_evidence_packet(&evidence_packet)
        .unwrap();

    assert_eq!(
        activation_record.to_factory_ref,
        challenger_phenotype.factory_phenotype_id
    );
    assert_eq!(
        observation_report.active_factory_ref,
        challenger_phenotype.factory_phenotype_id
    );
    assert!(observation_report.passed);
    assert_eq!(
        rollback_record.restored_factory_ref,
        incumbent_phenotype.factory_phenotype_id
    );
    assert_eq!(
        factory_state.active_factory_ref,
        incumbent_phenotype.factory_phenotype_id
    );

    assert_eq!(
        store
            .load_factory_genome_artifact(&challenger_genome.factory_genome_id)
            .unwrap(),
        challenger_genome
    );
    assert_eq!(
        store
            .load_factory_phenotype_artifact(&challenger_phenotype.factory_phenotype_id)
            .unwrap(),
        challenger_phenotype
    );
    assert_eq!(
        store
            .load_factory_lineage_record(&lineage.lineage_id)
            .unwrap(),
        lineage
    );
    assert_eq!(
        store
            .load_factory_validation_profile(&validation_profile.validation_profile_id)
            .unwrap(),
        validation_profile
    );
    assert_eq!(
        store
            .load_factory_validation_evidence(&validation_evidence.evidence_id)
            .unwrap(),
        validation_evidence
    );
    assert_eq!(
        store
            .load_factory_validation_record(&validation_record.validation_id)
            .unwrap(),
        validation_record
    );
    assert_eq!(
        store
            .load_factory_comparison_record(&comparison.comparison_id)
            .unwrap(),
        comparison
    );
    assert_eq!(
        store
            .load_factory_activation_bundle(&activation_bundle.activation_id)
            .unwrap(),
        activation_bundle
    );
    assert_eq!(
        store
            .load_factory_governance_transition(&governance_transition_validated.transition_id)
            .unwrap(),
        governance_transition_validated
    );
    assert_eq!(
        store
            .load_factory_governance_transition(&governance_transition_adopted.transition_id)
            .unwrap(),
        governance_transition_adopted
    );
    assert_eq!(
        store
            .load_factory_rollback_envelope(&rollback_envelope.rollback_id)
            .unwrap(),
        rollback_envelope
    );
    assert_eq!(
        store
            .load_factory_quarantine_record(&quarantine_record.quarantine_id)
            .unwrap(),
        quarantine_record
    );
    assert_eq!(
        store
            .load_factory_evidence_packet(&evidence_packet.packet_id)
            .unwrap(),
        evidence_packet
    );

    let loaded_state = store
        .load_active_factory_state(&factory_state.state_id)
        .unwrap();
    assert_eq!(
        loaded_state.active_factory_ref,
        factory_state.active_factory_ref
    );
    assert_eq!(loaded_state.activation_history.len(), 1);
    assert_eq!(loaded_state.rollback_history.len(), 1);
    assert_eq!(
        loaded_state.activation_history[0].comparison_ref,
        comparison.comparison_id
    );
    assert_eq!(
        loaded_state.rollback_history[0].rollback_handle_ref,
        activation_bundle.rollback_handle_ref
    );

    fs::remove_dir_all(root).unwrap();
}
