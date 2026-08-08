use aiaf_v1::execution::{Phase03ClosureReviewPacket, RecurringFactoryWorkspacePacket};
use aiaf_v1::local_runtime::{
    NorthStar05FactoryProgramsView, RemediationPhase03ReproductionEcosystemClosureView,
};

use crate::local_runtime_support::{
    get_json, reloaded_service_from_existing_workspace, router, seed_positive_closure_corpus,
    service,
};

#[tokio::test]
async fn supervisor_remediation_phase_03_sustained_factory_program_continuity_acceptance() {
    let service = service("remediation-phase-03-sustained-factory-program-continuity").await;
    let app = router(service.clone());
    let seeded = seed_positive_closure_corpus(&service, &app).await;

    let northstar05: NorthStar05FactoryProgramsView =
        get_json(&app, "/api/northstar/05/factory-programs").await;
    let factory_workspace: RecurringFactoryWorkspacePacket =
        get_json(&app, "/api/remediation/phase-03/factory-workspace").await;
    let closure_packet: Phase03ClosureReviewPacket =
        get_json(&app, "/api/remediation/phase-03/closure-review-packet").await;
    let phase03: RemediationPhase03ReproductionEcosystemClosureView = get_json(
        &app,
        "/api/remediation/phase-03/reproduction-ecosystem-closure",
    )
    .await;

    assert!(!northstar05.recurring_factory_programs.is_empty());
    assert!(!northstar05.continuity_windows.is_empty());
    assert!(!northstar05.budget_histories.is_empty());
    assert!(!northstar05.policy_compliance_records.is_empty());
    assert_eq!(phase03.phase_status, "closure_grade");

    let recurring = northstar05
        .recurring_factory_programs
        .iter()
        .find(|item| {
            northstar05
                .closure_grade_program_refs
                .contains(&item.factory_program_id)
        })
        .unwrap();

    assert_eq!(
        recurring.continuity_window_refs.len(),
        recurring.cycle_refs.len()
    );
    assert!(recurring.restart_resume_refs.len() >= recurring.cycle_refs.len());
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
    assert!(northstar05.cycle_dossiers.iter().all(|item| {
        !item.rollback_posture_refs.is_empty()
            && !item.continuity_ref.is_empty()
            && recurring
                .continuity_window_refs
                .contains(&item.continuity_ref)
    }));
    assert!(northstar05.continuity_windows.iter().all(|item| {
        item.program_ref == recurring.factory_program_id
            && !item.carry_forward_refs.is_empty()
            && !item.restart_resume_refs.is_empty()
    }));

    assert_eq!(factory_workspace.program_ref, recurring.factory_program_id);
    assert!(
        factory_workspace
            .continuity_refs
            .contains(&recurring.budget_history_ref)
    );
    assert!(
        factory_workspace
            .continuity_refs
            .contains(&recurring.policy_compliance_ref)
    );
    assert_eq!(
        factory_workspace.stability_refs,
        vec![
            recurring.budget_history_ref.clone(),
            recurring.policy_compliance_ref.clone()
        ]
    );

    assert!(
        closure_packet
            .continuity_refs
            .iter()
            .all(|reference| factory_workspace.continuity_refs.contains(reference))
    );
    assert!(
        !closure_packet
            .risk_refs
            .contains(&"risk:phase03:bounded-recursion".to_string())
    );
    assert!(
        closure_packet
            .risk_refs
            .contains(&"risk:phase03:recurring-program-publication-caveat".to_string())
    );

    let _ = service.export_run(&seeded.phase_d_run_id).await.unwrap();
    let reloaded_service = reloaded_service_from_existing_workspace(
        &service,
        "remediation-phase-03-sustained-factory-program-continuity-reloaded",
    )
    .await;
    let reloaded_router = router(reloaded_service);
    let reloaded_northstar05: NorthStar05FactoryProgramsView =
        get_json(&reloaded_router, "/api/northstar/05/factory-programs").await;
    let reloaded_factory_workspace: RecurringFactoryWorkspacePacket = get_json(
        &reloaded_router,
        "/api/remediation/phase-03/factory-workspace",
    )
    .await;
    let reloaded_closure_packet: Phase03ClosureReviewPacket = get_json(
        &reloaded_router,
        "/api/remediation/phase-03/closure-review-packet",
    )
    .await;
    let reloaded_phase03: RemediationPhase03ReproductionEcosystemClosureView = get_json(
        &reloaded_router,
        "/api/remediation/phase-03/reproduction-ecosystem-closure",
    )
    .await;

    assert_eq!(reloaded_phase03.phase_status, "closure_grade");
    assert_eq!(
        reloaded_northstar05.closure_grade_program_refs,
        northstar05.closure_grade_program_refs
    );
    assert_eq!(
        reloaded_factory_workspace.program_ref,
        factory_workspace.program_ref
    );
    assert_eq!(
        reloaded_factory_workspace.continuity_refs,
        factory_workspace.continuity_refs
    );
    assert_eq!(
        reloaded_factory_workspace.stability_refs,
        factory_workspace.stability_refs
    );
    assert_eq!(
        reloaded_closure_packet.acceptable_caveat_refs,
        closure_packet.acceptable_caveat_refs
    );
    assert_eq!(
        reloaded_closure_packet.blocking_risk_refs,
        closure_packet.blocking_risk_refs
    );
}
