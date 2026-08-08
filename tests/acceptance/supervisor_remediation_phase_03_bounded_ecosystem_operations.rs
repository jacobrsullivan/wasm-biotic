use aiaf_v1::local_runtime::NorthStar06EcosystemView;

use crate::local_runtime_support::{get_json, router, service};

#[tokio::test]
async fn supervisor_remediation_phase_03_bounded_ecosystem_operations_acceptance() {
    let service = service("remediation-phase-03-bounded-ecosystem-operations").await;
    let router = router(service.clone());

    let _ = service
        .run_headless("supervisor-phase-d-live-prefederation-exchange-contracts")
        .await
        .unwrap();
    let rollback_run = service
        .run_headless("supervisor-background-quarantine-rollback-control-loop")
        .await
        .unwrap();

    let northstar06: NorthStar06EcosystemView =
        get_json(&router, "/api/northstar/06/ecosystem").await;
    assert!(northstar06.admission_profiles.len() >= 2);
    assert!(!northstar06.route_history_records.is_empty());
    assert!(!northstar06.route_ledgers.is_empty());
    assert!(!northstar06.continuity_windows.is_empty());
    assert!(!northstar06.rollback_symmetry_records.is_empty());
    assert!(!northstar06.compatibility_persistence_records.is_empty());
    assert!(!northstar06.health_ledgers.is_empty());
    assert!(!northstar06.closure_grade_ecosystem_refs.is_empty());

    let route_ledger = &northstar06.route_ledgers[0];
    assert!(route_ledger.route_history_refs.len() >= 2);
    assert!(!route_ledger.adoption_refs.is_empty());
    assert!(!route_ledger.quarantine_refs.is_empty());
    assert!(!route_ledger.rollback_refs.is_empty());
    assert!(!route_ledger.continuity_window_refs.is_empty());

    assert!(northstar06.route_history_records.iter().all(|record| {
        !record.adoption_ref.trim().is_empty()
            && !record.quarantine_ref.trim().is_empty()
            && !record.rollback_ref.trim().is_empty()
    }));

    let health_ledger = northstar06
        .health_ledgers
        .iter()
        .find(|item| {
            northstar06
                .closure_grade_ecosystem_refs
                .contains(&item.ecosystem_health_id)
        })
        .unwrap();
    assert!(!health_ledger.continuity_refs.is_empty());
    assert!(!health_ledger.failure_refs.is_empty());
    assert!(!health_ledger.recovery_refs.is_empty());
    assert!(!health_ledger.rollback_symmetry_refs.is_empty());
    assert!(!health_ledger.compatibility_persistence_refs.is_empty());
    assert!(
        health_ledger
            .recovery_refs
            .iter()
            .any(|reference| reference == &format!("run:{}", rollback_run.summary.run_id))
    );
}
