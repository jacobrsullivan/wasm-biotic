use aiaf_v1::execution::Phase03ClosureReviewPacket;
use aiaf_v1::local_runtime::{
    NorthStar06EcosystemView, RemediationPhase03ReproductionEcosystemClosureView,
};

use crate::local_runtime_support::{
    get_json, reloaded_service_from_existing_workspace, router, seed_positive_closure_corpus,
    service,
};

#[tokio::test]
async fn supervisor_remediation_phase_03_sustained_bounded_ecosystem_continuity_acceptance() {
    let service = service("remediation-phase-03-sustained-bounded-ecosystem").await;
    let app = router(service.clone());
    let seeded = seed_positive_closure_corpus(&service, &app).await;

    let northstar06: NorthStar06EcosystemView = get_json(&app, "/api/northstar/06/ecosystem").await;
    let phase03: RemediationPhase03ReproductionEcosystemClosureView = get_json(
        &app,
        "/api/remediation/phase-03/reproduction-ecosystem-closure",
    )
    .await;
    let workspace: aiaf_v1::execution::EcosystemClosureWorkspacePacket =
        get_json(&app, "/api/remediation/phase-03/ecosystem-workspace").await;
    let closure_packet: Phase03ClosureReviewPacket =
        get_json(&app, "/api/remediation/phase-03/closure-review-packet").await;

    assert_eq!(phase03.phase_status, "closure_grade");
    assert!(!phase03.closure_grade_ecosystem_refs.is_empty());

    let health_ledger = northstar06
        .health_ledgers
        .iter()
        .find(|item| {
            phase03
                .closure_grade_ecosystem_refs
                .contains(&item.ecosystem_health_id)
        })
        .unwrap();
    let route_ledgers = northstar06
        .route_ledgers
        .iter()
        .filter(|item| {
            health_ledger
                .route_refs
                .contains(&item.exchange_route_ledger_id)
        })
        .collect::<Vec<_>>();
    assert!(!route_ledgers.is_empty());
    assert!(
        route_ledgers
            .iter()
            .any(|ledger| ledger.route_history_refs.len() >= 2)
    );
    assert!(route_ledgers.iter().all(|ledger| {
        !ledger.adoption_refs.is_empty()
            && !ledger.quarantine_refs.is_empty()
            && !ledger.rollback_refs.is_empty()
    }));

    assert!(!northstar06.continuity_windows.is_empty());
    assert!(!northstar06.rollback_symmetry_records.is_empty());
    assert!(!northstar06.compatibility_persistence_records.is_empty());
    assert!(
        health_ledger
            .recovery_refs
            .iter()
            .any(|reference| reference == &format!("run:{}", seeded.rollback_ready_run_id))
    );

    assert!(!workspace.continuity_refs.is_empty());
    assert!(!workspace.stability_refs.is_empty());
    assert!(
        workspace
            .route_refs
            .iter()
            .all(|reference| { closure_packet.ecosystem_refs.contains(reference) })
    );
    assert!(
        workspace
            .health_refs
            .iter()
            .all(|reference| { closure_packet.ecosystem_refs.contains(reference) })
    );
    assert!(
        workspace
            .continuity_refs
            .iter()
            .all(|reference| { closure_packet.ecosystem_refs.contains(reference) })
    );
    assert!(
        workspace
            .stability_refs
            .iter()
            .all(|reference| { closure_packet.ecosystem_refs.contains(reference) })
    );
    assert!(
        closure_packet
            .risk_refs
            .contains(&"risk:phase03:bounded-ecosystem-publication-caveat".to_string())
    );
    assert!(
        !closure_packet
            .risk_refs
            .contains(&"risk:phase03:bounded-ecosystem".to_string())
    );

    let _ = service.export_run(&seeded.phase_d_run_id).await.unwrap();
    let reloaded_service = reloaded_service_from_existing_workspace(
        &service,
        "remediation-phase-03-sustained-bounded-ecosystem-reloaded",
    )
    .await;
    let reloaded_router = router(reloaded_service);
    let reloaded_northstar06: NorthStar06EcosystemView =
        get_json(&reloaded_router, "/api/northstar/06/ecosystem").await;
    let reloaded_phase03: RemediationPhase03ReproductionEcosystemClosureView = get_json(
        &reloaded_router,
        "/api/remediation/phase-03/reproduction-ecosystem-closure",
    )
    .await;
    let reloaded_workspace: aiaf_v1::execution::EcosystemClosureWorkspacePacket = get_json(
        &reloaded_router,
        "/api/remediation/phase-03/ecosystem-workspace",
    )
    .await;
    let reloaded_closure_packet: Phase03ClosureReviewPacket = get_json(
        &reloaded_router,
        "/api/remediation/phase-03/closure-review-packet",
    )
    .await;

    assert_eq!(reloaded_phase03.phase_status, "closure_grade");
    assert_eq!(
        reloaded_northstar06.closure_grade_ecosystem_refs,
        northstar06.closure_grade_ecosystem_refs
    );
    assert_eq!(reloaded_workspace.route_refs, workspace.route_refs);
    assert_eq!(reloaded_workspace.health_refs, workspace.health_refs);
    assert_eq!(
        reloaded_workspace.continuity_refs,
        workspace.continuity_refs
    );
    assert_eq!(reloaded_workspace.stability_refs, workspace.stability_refs);
    assert_eq!(
        reloaded_closure_packet.acceptable_caveat_refs,
        closure_packet.acceptable_caveat_refs
    );
    assert_eq!(
        reloaded_closure_packet.blocking_risk_refs,
        closure_packet.blocking_risk_refs
    );
}
