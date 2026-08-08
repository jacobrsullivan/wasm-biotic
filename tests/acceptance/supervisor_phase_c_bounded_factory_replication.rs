use aiaf_v1::execution::{
    ChildFactoryDispositionKind, DurableArtifactStore, FactoryGenomeArtifact,
    FactoryPhenotypeArtifact, FactoryReplicationDecisionKind, FactoryReplicationStage,
    assemble_factory_replication_evidence_packet, finalize_factory_replication_decision,
    issue_child_factory_disposition, issue_child_factory_quarantine_protocol,
    materialize_later_factory_candidate, open_child_factory_observation_window,
    record_factory_proving_run, start_factory_replication_campaign,
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
    env::temp_dir().join(format!("aiaf-phase-c-{name}-{}-{timestamp}", process::id()))
}

#[test]
fn supervisor_phase_c_bounded_factory_replication_acceptance() {
    let root = temp_store_root("bounded-factory-replication");
    let store = DurableArtifactStore::bootstrap(root.join("store")).unwrap();

    let parent_genome = FactoryGenomeArtifact {
        factory_genome_id: "factory-genome-parent".to_string(),
        parent_factory_ref: None,
        stable_contract_refs: vec!["contract:v1".to_string()],
        worker_topology_refs: vec!["topology:bounded-supervisor".to_string()],
        service_closure_refs: vec!["service:v4-shell".to_string()],
        governance_policy_refs: vec!["governance:bounded-adoption".to_string()],
        shell_profile_refs: vec!["shell-profile:v4".to_string()],
        summary: "adopted parent factory genome".to_string(),
    };
    let parent_phenotype = FactoryPhenotypeArtifact {
        factory_phenotype_id: "factory-phenotype-parent".to_string(),
        factory_genome_ref: parent_genome.factory_genome_id.clone(),
        package_refs: vec!["pkg:parent".to_string()],
        entrypoint_refs: vec!["entry:runner".to_string()],
        boundary_refs: vec!["boundary:v1".to_string()],
        validation_profile_refs: vec!["factory-validation-profile-parent".to_string()],
        summary: "adopted parent factory package".to_string(),
    };
    let child_genome = FactoryGenomeArtifact {
        factory_genome_id: "factory-genome-child".to_string(),
        parent_factory_ref: Some(parent_genome.factory_genome_id.clone()),
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
        summary: "produced child factory genome".to_string(),
    };
    let child_phenotype = FactoryPhenotypeArtifact {
        factory_phenotype_id: "factory-phenotype-child".to_string(),
        factory_genome_ref: child_genome.factory_genome_id.clone(),
        package_refs: vec!["pkg:child".to_string()],
        entrypoint_refs: vec!["entry:runner".to_string(), "entry:review".to_string()],
        boundary_refs: vec!["boundary:v1".to_string()],
        validation_profile_refs: vec!["factory-validation-profile-child".to_string()],
        summary: "produced child factory package".to_string(),
    };

    let mut campaign = start_factory_replication_campaign(
        "factory-replication-campaign-1",
        parent_phenotype.factory_phenotype_id.clone(),
        "later-factory-request-1",
        vec![
            "governance:adoption-record-1".to_string(),
            "governance:rollback-law-1".to_string(),
        ],
        vec![
            "replay:checkpoint-1".to_string(),
            "replay:session-1".to_string(),
        ],
    )
    .unwrap();
    let child_candidate = materialize_later_factory_candidate(
        &mut campaign,
        "later-factory-candidate-1",
        vec![
            "production:trace-shell-1".to_string(),
            "production:trace-governance-1".to_string(),
        ],
        child_genome.factory_genome_id.clone(),
        child_phenotype.factory_phenotype_id.clone(),
        "one bounded later factory candidate inside one governed single-factory pipeline",
        "produced child factory candidate with explicit parent trace",
    )
    .unwrap();
    let proving_run = record_factory_proving_run(
        &mut campaign,
        "factory-proving-run-1",
        &child_candidate,
        vec![
            "scenario:phase-a-live-shell".to_string(),
            "scenario:phase-b-factory-artifact".to_string(),
        ],
        vec![
            "shell:session-1".to_string(),
            "shell:evidence-packet-1".to_string(),
        ],
        vec![
            "governance:approval-1".to_string(),
            "governance:rollback-ready-1".to_string(),
        ],
        true,
        "child factory completed its bounded proving run",
    )
    .unwrap();
    let decision = finalize_factory_replication_decision(
        &mut campaign,
        "factory-replication-decision-1",
        &child_candidate,
        &proving_run,
        FactoryReplicationDecisionKind::AdoptChildForObservation,
        vec!["rollback:child-factory-1".to_string()],
        "child factory is admitted for bounded observation only",
    )
    .unwrap();
    let evidence_packet = assemble_factory_replication_evidence_packet(
        "factory-replication-packet-1",
        &campaign,
        &child_candidate,
        &proving_run,
        &decision,
        "first bounded later-factory creation only",
    )
    .unwrap();
    let observation = open_child_factory_observation_window(
        &campaign,
        &child_candidate,
        &decision,
        "child-observation-1",
        vec![
            "observation:event-shell-stable-1".to_string(),
            "observation:event-governance-stable-1".to_string(),
        ],
        vec!["rollback:child-factory-1".to_string()],
        "child factory remains under bounded observation",
    )
    .unwrap();
    let quarantine_protocol = issue_child_factory_quarantine_protocol(
        &observation,
        "child-quarantine-protocol-1",
        vec![
            "trigger:regression-1".to_string(),
            "trigger:governance-drift-1".to_string(),
        ],
        vec!["rollback:child-factory-1".to_string()],
        "quarantine the child if bounded observation regresses",
    )
    .unwrap();
    let disposition = issue_child_factory_disposition(
        &decision,
        child_candidate.later_factory_candidate_id.clone(),
        "child-disposition-1",
        ChildFactoryDispositionKind::RetainForReview,
        vec![
            "rollback:child-factory-1".to_string(),
            quarantine_protocol.protocol_id.clone(),
        ],
        "child remains reviewable and rollback-ready after observation admission",
    )
    .unwrap();

    store
        .persist_factory_genome_artifact(&parent_genome)
        .unwrap();
    store
        .persist_factory_phenotype_artifact(&parent_phenotype)
        .unwrap();
    store
        .persist_factory_genome_artifact(&child_genome)
        .unwrap();
    store
        .persist_factory_phenotype_artifact(&child_phenotype)
        .unwrap();
    store
        .persist_factory_replication_campaign(&campaign)
        .unwrap();
    store
        .persist_later_factory_candidate(&child_candidate)
        .unwrap();
    store
        .persist_factory_proving_run_record(&proving_run)
        .unwrap();
    store
        .persist_child_factory_observation_window(&observation)
        .unwrap();
    store
        .persist_child_factory_quarantine_protocol(&quarantine_protocol)
        .unwrap();
    store
        .persist_child_factory_disposition(&disposition)
        .unwrap();
    store
        .persist_factory_replication_decision(&decision)
        .unwrap();
    store
        .persist_factory_replication_evidence_packet(&evidence_packet)
        .unwrap();

    assert_eq!(campaign.runtime_stage, FactoryReplicationStage::Decide);
    assert_eq!(
        child_candidate.parent_factory_ref,
        parent_phenotype.factory_phenotype_id
    );
    assert_eq!(
        proving_run.factory_candidate_ref,
        child_candidate.later_factory_candidate_id
    );
    assert!(proving_run.passed);
    assert_eq!(
        observation.child_factory_ref,
        child_candidate.later_factory_candidate_id
    );
    assert_eq!(
        quarantine_protocol.observation_window_ref,
        observation.observation_window_id
    );
    assert_eq!(disposition.decision_ref, decision.decision_id);
    assert_eq!(
        decision.decision,
        FactoryReplicationDecisionKind::AdoptChildForObservation
    );
    assert_eq!(
        evidence_packet.child_factory_ref,
        child_candidate.later_factory_candidate_id
    );

    assert_eq!(
        store
            .load_factory_replication_campaign(&campaign.replication_campaign_id)
            .unwrap(),
        campaign
    );
    assert_eq!(
        store
            .load_later_factory_candidate(&child_candidate.later_factory_candidate_id)
            .unwrap(),
        child_candidate
    );
    assert_eq!(
        store
            .load_factory_proving_run_record(&proving_run.proving_run_id)
            .unwrap(),
        proving_run
    );
    assert_eq!(
        store
            .load_child_factory_observation_window(&observation.observation_window_id)
            .unwrap(),
        observation
    );
    assert_eq!(
        store
            .load_child_factory_quarantine_protocol(&quarantine_protocol.protocol_id)
            .unwrap(),
        quarantine_protocol
    );
    assert_eq!(
        store
            .load_child_factory_disposition(&disposition.disposition_id)
            .unwrap(),
        disposition
    );
    assert_eq!(
        store
            .load_factory_replication_decision(&decision.decision_id)
            .unwrap(),
        decision
    );
    assert_eq!(
        store
            .load_factory_replication_evidence_packet(&evidence_packet.packet_id)
            .unwrap(),
        evidence_packet
    );

    fs::remove_dir_all(root).unwrap();
}
