use aiaf_v1::execution::DurableArtifactStore;
use aiaf_v1::local_runtime::LocalRunStatus;

use crate::local_runtime_support::service;

fn output_ref_suffix<'a>(output_refs: &'a [String], prefix: &str) -> Option<&'a str> {
    output_refs
        .iter()
        .find_map(|reference| reference.strip_prefix(prefix))
}

#[tokio::test]
async fn supervisor_phase_b_live_factory_artifact_runner_path_acceptance() {
    let service = service("phase-b-live-runner").await;
    let run = service
        .run_headless("supervisor-phase-b-live-factory-artifact-family")
        .await
        .unwrap();

    assert_eq!(run.summary.status, LocalRunStatus::Completed);
    assert!(
        run.summary
            .output_refs
            .iter()
            .any(|reference| reference.starts_with("factory-evidence-packet:"))
    );
    assert!(
        run.summary
            .output_refs
            .iter()
            .any(|reference| reference.starts_with("factory-state:"))
    );
    assert!(
        run.summary
            .output_refs
            .iter()
            .any(|reference| reference.starts_with("factory-governance-transition:"))
    );
    assert!(
        run.summary
            .output_refs
            .iter()
            .any(|reference| reference.starts_with("factory-rollback-envelope:"))
    );
    assert!(
        run.summary
            .output_refs
            .iter()
            .any(|reference| reference.starts_with("factory-quarantine-record:"))
    );

    let packet_id =
        output_ref_suffix(&run.summary.output_refs, "factory-evidence-packet:").unwrap();
    let state_id = output_ref_suffix(&run.summary.output_refs, "factory-state:").unwrap();
    let run_root = service
        .workspace()
        .root()
        .join("runs")
        .join(&run.summary.run_id);
    let store = DurableArtifactStore::bootstrap(run_root.join("store")).unwrap();
    let packet = store.load_factory_evidence_packet(packet_id).unwrap();
    let state = store.load_active_factory_state(state_id).unwrap();
    let transition_id =
        output_ref_suffix(&run.summary.output_refs, "factory-governance-transition:").unwrap();
    let rollback_envelope_id =
        output_ref_suffix(&run.summary.output_refs, "factory-rollback-envelope:").unwrap();
    let quarantine_id =
        output_ref_suffix(&run.summary.output_refs, "factory-quarantine-record:").unwrap();
    let transition = store
        .load_factory_governance_transition(transition_id)
        .unwrap();
    let rollback_envelope = store
        .load_factory_rollback_envelope(rollback_envelope_id)
        .unwrap();
    let quarantine = store.load_factory_quarantine_record(quarantine_id).unwrap();

    assert_eq!(packet.packet_id, packet_id);
    assert_eq!(state.activation_history.len(), 1);
    assert_eq!(state.rollback_history.len(), 1);
    assert_eq!(transition.transition_id, transition_id);
    assert_eq!(rollback_envelope.rollback_id, rollback_envelope_id);
    assert_eq!(quarantine.quarantine_id, quarantine_id);

    let drilldown = service
        .evidence_drilldown(&run.summary.run_id)
        .await
        .unwrap();
    assert!(
        drilldown
            .sections
            .iter()
            .any(|section| section.section_id == "factory-artifacts")
    );

    let export_root = service.export_run(&run.summary.run_id).await.unwrap();
    assert!(export_root.join("snapshots/factory-genomes.json").exists());
    assert!(
        export_root
            .join("snapshots/factory-phenotypes.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/factory-comparisons.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/factory-governance-transitions.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/factory-rollback-envelopes.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/factory-quarantine-records.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/factory-evidence-packets.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/northstar-01-launch-assemblies.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/northstar-03-service-manifests.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/northstar-03-service-closure-dossiers.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/northstar-03-workflow-sufficiency.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/northstar-03-workflow-closure-dossiers.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/remediation-phase-02-service-workspaces.json")
            .exists()
    );
}

#[tokio::test]
async fn supervisor_phase_c_live_factory_replication_runner_path_acceptance() {
    let service = service("phase-c-live-runner").await;
    let run = service
        .run_headless("supervisor-phase-c-live-bounded-factory-replication")
        .await
        .unwrap();

    assert_eq!(run.summary.status, LocalRunStatus::Completed);
    assert!(
        run.summary
            .output_refs
            .iter()
            .any(|reference| reference.starts_with("factory-replication-packet:"))
    );
    assert!(
        run.summary
            .output_refs
            .iter()
            .any(|reference| reference.starts_with("factory-replication-campaign:"))
    );
    assert!(
        run.summary
            .output_refs
            .iter()
            .any(|reference| reference.starts_with("child-factory-observation:"))
    );
    assert!(
        run.summary
            .output_refs
            .iter()
            .any(|reference| reference.starts_with("child-factory-disposition:"))
    );

    let campaign_id =
        output_ref_suffix(&run.summary.output_refs, "factory-replication-campaign:").unwrap();
    let packet_id =
        output_ref_suffix(&run.summary.output_refs, "factory-replication-packet:").unwrap();
    let run_root = service
        .workspace()
        .root()
        .join("runs")
        .join(&run.summary.run_id);
    let store = DurableArtifactStore::bootstrap(run_root.join("store")).unwrap();
    let campaign = store
        .load_factory_replication_campaign(campaign_id)
        .unwrap();
    let packet = store
        .load_factory_replication_evidence_packet(packet_id)
        .unwrap();
    let disposition_id =
        output_ref_suffix(&run.summary.output_refs, "child-factory-disposition:").unwrap();
    let disposition = store
        .load_child_factory_disposition(disposition_id)
        .unwrap();

    assert_eq!(campaign.replication_campaign_id, campaign_id);
    assert_eq!(packet.packet_id, packet_id);
    assert_eq!(disposition.disposition_id, disposition_id);

    let drilldown = service
        .evidence_drilldown(&run.summary.run_id)
        .await
        .unwrap();
    assert!(
        drilldown
            .sections
            .iter()
            .any(|section| section.section_id == "factory-replication")
    );

    let export_root = service.export_run(&run.summary.run_id).await.unwrap();
    assert!(
        export_root
            .join("snapshots/factory-replication-campaigns.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/later-factory-candidates.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/factory-proving-runs.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/child-factory-observation-windows.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/child-factory-quarantine-protocols.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/child-factory-dispositions.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/factory-replication-evidence-packets.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/northstar-01-launch-assemblies.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/northstar-04-worker-cards.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/northstar-04-routing-packets.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/northstar-04-recovery-records.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/remediation-phase-02-ecology-workspaces.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/northstar-05-improvement-programs.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/northstar-05-generation-agendas.json")
            .exists()
    );
}

#[tokio::test]
async fn supervisor_phase_d_live_factory_exchange_runner_path_acceptance() {
    let service = service("phase-d-live-runner").await;
    let run = service
        .run_headless("supervisor-phase-d-live-prefederation-exchange-contracts")
        .await
        .unwrap();

    assert_eq!(run.summary.status, LocalRunStatus::Completed);
    assert!(
        run.summary
            .output_refs
            .iter()
            .any(|reference| reference.starts_with("factory-exchange-envelope:"))
    );
    assert!(
        run.summary
            .output_refs
            .iter()
            .any(|reference| reference.starts_with("factory-compatibility-decision:"))
    );
    assert!(
        run.summary
            .output_refs
            .iter()
            .any(|reference| reference.starts_with("factory-import-state:"))
    );
    assert!(
        run.summary
            .output_refs
            .iter()
            .any(|reference| reference.starts_with("factory-import-disposition:"))
    );

    let envelope_id =
        output_ref_suffix(&run.summary.output_refs, "factory-exchange-envelope:").unwrap();
    let decision_id =
        output_ref_suffix(&run.summary.output_refs, "factory-compatibility-decision:").unwrap();
    let run_root = service
        .workspace()
        .root()
        .join("runs")
        .join(&run.summary.run_id);
    let store = DurableArtifactStore::bootstrap(run_root.join("store")).unwrap();
    let envelope = store.load_factory_exchange_envelope(envelope_id).unwrap();
    let decision = store
        .load_factory_compatibility_decision(decision_id)
        .unwrap();
    let import_state_id =
        output_ref_suffix(&run.summary.output_refs, "factory-import-state:").unwrap();
    let import_disposition_id =
        output_ref_suffix(&run.summary.output_refs, "factory-import-disposition:").unwrap();
    let import_state = store
        .load_quarantine_first_import_state(import_state_id)
        .unwrap();
    let import_disposition = store
        .load_import_disposition(import_disposition_id)
        .unwrap();

    assert_eq!(envelope.exchange_id, envelope_id);
    assert_eq!(decision.decision_id, decision_id);
    assert_eq!(import_state.import_state_id, import_state_id);
    assert_eq!(import_disposition.disposition_id, import_disposition_id);

    let drilldown = service
        .evidence_drilldown(&run.summary.run_id)
        .await
        .unwrap();
    assert!(
        drilldown
            .sections
            .iter()
            .any(|section| section.section_id == "factory-exchange")
    );

    let export_root = service.export_run(&run.summary.run_id).await.unwrap();
    assert!(
        export_root
            .join("snapshots/factory-identities.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/factory-exchange-envelopes.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/factory-quarantine-packets.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/factory-import-states.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/factory-import-dispositions.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/factory-memory-exchange-packets.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/northstar-01-launch-assemblies.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/northstar-06-trust-profiles.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/northstar-06-exchange-routes.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/northstar-06-health-snapshots.json")
            .exists()
    );
}
