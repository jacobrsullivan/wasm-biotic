use serde_json::json;

use aiaf_v1::execution::{DurableArtifactStore, PathSupportClass};
use aiaf_v1::local_runtime::{
    LocalRunStatus, NorthStar01UniversalShellView, NorthStar02PersistentShellView,
    NorthStar03NativeServicesView, NorthStar04WorkerEcologyView, NorthStar05FactoryProgramsView,
    NorthStar06EcosystemView, RunViewModel,
};

use crate::local_runtime_support::{get_json, post_empty, post_json, router, service};

fn output_ref_suffix<'a>(output_refs: &'a [String], prefix: &str) -> Option<&'a str> {
    output_refs
        .iter()
        .find_map(|reference| reference.strip_prefix(prefix))
}

#[tokio::test]
async fn supervisor_northstar_01_06_operator_views_acceptance() {
    let service = service("northstar-01-06-operator-views").await;
    let router = router(service.clone());
    for scenario_id in [
        "supervisor-v4-live-shell-runner-path",
        "supervisor-northstar-live-persistent-shell-program",
        "supervisor-phase-b-live-factory-artifact-family",
        "supervisor-phase-c-live-bounded-factory-replication",
        "supervisor-phase-d-live-prefederation-exchange-contracts",
    ] {
        let _ = service.run_headless(scenario_id).await.unwrap();
    }

    let expired: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({
            "scenario_id": "supervisor-durable-fixed-interface-continuous-self-hosting-program"
        }),
    )
    .await;
    assert_eq!(expired.summary.status, LocalRunStatus::AwaitingApproval);
    let expired: RunViewModel = post_empty(
        &router,
        &format!("/api/runs/{}/approval/expire", expired.summary.run_id),
    )
    .await;
    assert_eq!(expired.summary.status, LocalRunStatus::Failed);

    let escalated: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({
            "scenario_id": "supervisor-durable-fixed-interface-continuous-self-hosting-program"
        }),
    )
    .await;
    assert_eq!(escalated.summary.status, LocalRunStatus::AwaitingApproval);
    let escalated: RunViewModel = post_empty(
        &router,
        &format!("/api/runs/{}/approval/escalate", escalated.summary.run_id),
    )
    .await;
    assert_eq!(escalated.summary.status, LocalRunStatus::Paused);

    let rollback_ready: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({
            "scenario_id": "supervisor-background-quarantine-rollback-control-loop"
        }),
    )
    .await;
    assert_eq!(
        rollback_ready.summary.status,
        LocalRunStatus::AwaitingRollback
    );

    let northstar01: NorthStar01UniversalShellView =
        get_json(&router, "/api/northstar/01/universal-shell").await;
    assert!(northstar01.summary.contains("NorthStar 01"));
    assert!(northstar01.support.iter().any(|item| {
        item.path_ref == "supervisor-northstar-live-persistent-shell-program"
            && item.support_class == PathSupportClass::ShellFirst
    }));
    assert!(northstar01.support.iter().any(|item| {
        item.path_ref == "supervisor-phase-d-live-prefederation-exchange-contracts"
            && item.support_class == PathSupportClass::ShellFirst
    }));
    assert!(!northstar01.launches.is_empty());
    assert!(!northstar01.admissions.is_empty());
    assert!(!northstar01.lifecycle_transitions.is_empty());
    assert!(!northstar01.export_bundles.is_empty());
    assert!(!northstar01.program_mappings.is_empty());
    assert!(!northstar01.migration_gates.is_empty());

    let northstar02: NorthStar02PersistentShellView =
        get_json(&router, "/api/northstar/02/persistent-shell").await;
    assert!(northstar02.summary.contains("NorthStar 02"));
    assert!(!northstar02.run_refs.is_empty());
    assert!(!northstar02.ticks.is_empty());
    assert!(!northstar02.wakes.is_empty());
    assert!(!northstar02.leases.is_empty());
    assert!(!northstar02.approval_inboxes.is_empty());
    assert!(!northstar02.deferred_decision_bundles.is_empty());
    assert!(!northstar02.lease_expiries.is_empty());
    assert!(!northstar02.escalations.is_empty());
    assert!(!northstar02.consolidation_jobs.is_empty());
    assert!(!northstar02.continuity_classes.is_empty());
    assert!(!northstar02.continuity_jobs.is_empty());
    assert!(!northstar02.audit_packets.is_empty());
    assert!(!northstar02.operations_dossiers.is_empty());

    let northstar03: NorthStar03NativeServicesView =
        get_json(&router, "/api/northstar/03/native-services").await;
    assert!(northstar03.summary.contains("NorthStar 03"));
    assert!(!northstar03.run_refs.is_empty());
    assert!(!northstar03.manifests.is_empty());
    assert!(!northstar03.handles.is_empty());
    assert!(!northstar03.attestations.is_empty());
    assert!(!northstar03.closure_dossiers.is_empty());
    assert!(!northstar03.workflow_sufficiency_records.is_empty());
    assert!(!northstar03.workflow_closure_dossiers.is_empty());
    assert!(!northstar03.closure_grade_workflow_refs.is_empty());

    let northstar04: NorthStar04WorkerEcologyView =
        get_json(&router, "/api/northstar/04/worker-ecology").await;
    assert!(northstar04.summary.contains("NorthStar 04"));
    assert!(!northstar04.run_refs.is_empty());
    assert!(!northstar04.worker_cards.is_empty());
    assert!(!northstar04.ecology_snapshots.is_empty());
    assert!(!northstar04.planning_records.is_empty());
    assert!(!northstar04.work_leases.is_empty());
    assert!(!northstar04.synthesis_dossiers.is_empty());
    assert!(!northstar04.health_records.is_empty());
    assert!(!northstar04.routing_packets.is_empty());
    assert!(!northstar04.recovery_records.is_empty());

    let northstar05: NorthStar05FactoryProgramsView =
        get_json(&router, "/api/northstar/05/factory-programs").await;
    assert!(northstar05.summary.contains("NorthStar 05"));
    assert!(!northstar05.run_refs.is_empty());
    assert!(!northstar05.improvement_programs.is_empty());
    assert!(!northstar05.recursion_budgets.is_empty());
    assert!(!northstar05.generation_agendas.is_empty());
    assert!(!northstar05.adoption_windows.is_empty());
    assert!(!northstar05.lineage_health_dossiers.is_empty());
    assert!(!northstar05.stop_conditions.is_empty());
    assert!(!northstar05.recurring_factory_programs.is_empty());
    assert!(!northstar05.continuity_windows.is_empty());
    assert!(!northstar05.budget_histories.is_empty());
    assert!(!northstar05.policy_compliance_records.is_empty());
    assert!(northstar05.cycle_dossiers.len() >= 2);
    assert!(!northstar05.lineage_ledgers.is_empty());
    assert!(!northstar05.regression_packets.is_empty());
    assert!(!northstar05.longitudinal_lineage_dossiers.is_empty());
    assert!(!northstar05.closure_grade_program_refs.is_empty());

    let northstar06: NorthStar06EcosystemView =
        get_json(&router, "/api/northstar/06/ecosystem").await;
    assert!(northstar06.summary.contains("NorthStar 06"));
    assert!(!northstar06.run_refs.is_empty());
    assert!(!northstar06.trust_profiles.is_empty());
    assert!(!northstar06.admissions.is_empty());
    assert!(!northstar06.routes.is_empty());
    assert!(!northstar06.route_cycles.is_empty());
    assert!(!northstar06.adoption_dossiers.is_empty());
    assert!(!northstar06.rollback_choreography.is_empty());
    assert!(!northstar06.workspace_snapshots.is_empty());
    assert!(!northstar06.health_snapshots.is_empty());
    assert!(northstar06.admission_profiles.len() >= 2);
    assert!(!northstar06.route_history_records.is_empty());
    assert!(!northstar06.route_ledgers.is_empty());
    assert!(!northstar06.continuity_windows.is_empty());
    assert!(!northstar06.rollback_symmetry_records.is_empty());
    assert!(!northstar06.compatibility_persistence_records.is_empty());
    assert!(!northstar06.health_ledgers.is_empty());
    assert!(!northstar06.closure_grade_ecosystem_refs.is_empty());
}

#[tokio::test]
async fn supervisor_northstar_persistent_shell_program_export_acceptance() {
    let service = service("northstar-persistent-shell-program").await;
    let run = service
        .run_headless("supervisor-northstar-live-persistent-shell-program")
        .await
        .unwrap();

    assert_eq!(run.summary.status, LocalRunStatus::Completed);
    assert!(
        run.summary
            .output_refs
            .iter()
            .any(|reference| reference.starts_with("northstar-01-launch:"))
    );
    assert!(
        run.summary
            .output_refs
            .iter()
            .any(|reference| reference.starts_with("northstar-02-tick:"))
    );
    assert!(
        run.summary
            .output_refs
            .iter()
            .any(|reference| reference.starts_with("northstar-02-wake:"))
    );
    assert!(
        run.summary
            .output_refs
            .iter()
            .any(|reference| reference.starts_with("northstar-02-consolidation:"))
    );
    assert!(
        run.summary
            .output_refs
            .iter()
            .any(|reference| reference.starts_with("northstar-02-continuity-job:"))
    );
    assert!(
        run.summary
            .output_refs
            .iter()
            .any(|reference| reference.starts_with("northstar-02-audit-packet:"))
    );
    assert!(
        run.summary
            .output_refs
            .iter()
            .any(|reference| reference.starts_with("northstar-02-operations-dossier:"))
    );

    let run_root = service
        .workspace()
        .root()
        .join("runs")
        .join(&run.summary.run_id);
    let store = DurableArtifactStore::bootstrap(run_root.join("store")).unwrap();
    let launch_id = output_ref_suffix(&run.summary.output_refs, "northstar-01-launch:").unwrap();
    let tick_id = output_ref_suffix(&run.summary.output_refs, "northstar-02-tick:").unwrap();
    let wake_id = output_ref_suffix(&run.summary.output_refs, "northstar-02-wake:").unwrap();
    let lease_id = output_ref_suffix(&run.summary.output_refs, "northstar-02-lease:").unwrap();
    let consolidation_id =
        output_ref_suffix(&run.summary.output_refs, "northstar-02-consolidation:").unwrap();
    let continuity_job_id =
        output_ref_suffix(&run.summary.output_refs, "northstar-02-continuity-job:").unwrap();
    let audit_packet_id =
        output_ref_suffix(&run.summary.output_refs, "northstar-02-audit-packet:").unwrap();
    let operations_dossier_id =
        output_ref_suffix(&run.summary.output_refs, "northstar-02-operations-dossier:").unwrap();

    let launch = store
        .load_universal_shell_launch_assembly(launch_id)
        .unwrap();
    let tick = store.load_scheduler_tick_record(tick_id).unwrap();
    let wake = store.load_scheduled_wake_record(wake_id).unwrap();
    let lease = store.load_persistent_job_lease(lease_id).unwrap();
    let consolidation = store
        .load_consolidation_job_record(consolidation_id)
        .unwrap();
    let continuity_job = store.load_continuity_job_record(continuity_job_id).unwrap();
    let audit_packet = store
        .load_persistent_shell_audit_packet(audit_packet_id)
        .unwrap();
    let operations_dossier = store
        .load_persistent_shell_operations_dossier(operations_dossier_id)
        .unwrap();

    assert_eq!(launch.launch_id, launch_id);
    assert_eq!(tick.tick_id, tick_id);
    assert_eq!(wake.wake_record_id, wake_id);
    assert_eq!(lease.lease_id, lease_id);
    assert_eq!(consolidation.consolidation_id, consolidation_id);
    assert_eq!(continuity_job.job_record_id, continuity_job_id);
    assert_eq!(audit_packet.audit_packet_id, audit_packet_id);
    assert_eq!(
        operations_dossier.operations_dossier_id,
        operations_dossier_id
    );
    assert_eq!(wake.lease_ref, lease.lease_id);
    assert!(
        operations_dossier
            .wake_refs
            .iter()
            .any(|reference| reference == wake_id)
    );
    assert!(
        operations_dossier
            .continuity_job_refs
            .iter()
            .any(|reference| reference == continuity_job_id)
    );
    assert!(
        operations_dossier
            .audit_refs
            .iter()
            .any(|reference| reference == audit_packet_id)
    );
    assert!(
        audit_packet
            .job_refs
            .iter()
            .any(|reference| reference == continuity_job_id)
    );

    let export_root = service.export_run(&run.summary.run_id).await.unwrap();
    assert!(
        export_root
            .join("snapshots/northstar-01-launch-assemblies.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/northstar-01-program-mappings.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/northstar-02-scheduler-ticks.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/northstar-02-scheduled-wakes.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/northstar-02-persistent-leases.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/northstar-02-approval-inboxes.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/northstar-02-consolidation-jobs.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/northstar-02-continuity-jobs.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/northstar-02-audit-packets.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/northstar-02-operations-dossiers.json")
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
}
