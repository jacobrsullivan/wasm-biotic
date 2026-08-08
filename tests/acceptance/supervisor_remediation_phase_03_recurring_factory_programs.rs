use aiaf_v1::local_runtime::NorthStar05FactoryProgramsView;

use crate::local_runtime_support::{get_json, router, service};

#[tokio::test]
async fn supervisor_remediation_phase_03_recurring_factory_programs_acceptance() {
    let service = service("remediation-phase-03-recurring-factory-programs").await;
    let router = router(service.clone());

    let _ = service
        .run_headless("supervisor-phase-b-live-factory-artifact-family")
        .await
        .unwrap();
    let _ = service
        .run_headless("supervisor-phase-c-live-bounded-factory-replication")
        .await
        .unwrap();

    let northstar05: NorthStar05FactoryProgramsView =
        get_json(&router, "/api/northstar/05/factory-programs").await;
    assert!(!northstar05.recurring_factory_programs.is_empty());
    assert!(!northstar05.continuity_windows.is_empty());
    assert!(!northstar05.budget_histories.is_empty());
    assert!(!northstar05.policy_compliance_records.is_empty());
    assert!(northstar05.cycle_dossiers.len() >= 2);
    assert!(!northstar05.closure_grade_program_refs.is_empty());

    let recurring = northstar05
        .recurring_factory_programs
        .iter()
        .find(|item| {
            northstar05
                .closure_grade_program_refs
                .contains(&item.factory_program_id)
        })
        .unwrap();
    assert!(
        northstar05
            .recursion_budgets
            .iter()
            .any(|item| item.recursion_budget_id == recurring.budget_ref)
    );
    assert!(
        northstar05
            .budget_histories
            .iter()
            .any(|item| item.budget_history_id == recurring.budget_history_ref)
    );
    assert!(
        northstar05
            .policy_compliance_records
            .iter()
            .any(|item| item.policy_compliance_id == recurring.policy_compliance_ref)
    );
    assert!(recurring.cycle_refs.len() >= 2);
    assert_eq!(
        recurring.continuity_window_refs.len(),
        recurring.cycle_refs.len()
    );
    assert!(!recurring.restart_resume_refs.is_empty());
    assert!(recurring.cycle_refs.iter().all(|reference| {
        northstar05.cycle_dossiers.iter().any(|item| {
            item.cycle_dossier_id == *reference
                && !item.rollback_posture_refs.is_empty()
                && recurring
                    .continuity_window_refs
                    .contains(&item.continuity_ref)
        })
    }));
    assert!(northstar05.stop_conditions.iter().any(|item| {
        item.stop_condition_id == recurring.policy_ref
            || recurring.bounded_program_refs.contains(&item.program_ref)
    }));
}
