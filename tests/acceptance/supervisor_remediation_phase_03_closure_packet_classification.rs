use std::collections::BTreeSet;

use aiaf_v1::local_runtime::RemediationPhase03ReproductionEcosystemClosureView;

use crate::local_runtime_support::{
    get_json, reloaded_service_from_existing_workspace, router, seed_positive_closure_corpus,
    service,
};

#[tokio::test]
async fn supervisor_remediation_phase_03_closure_packet_classification_acceptance() {
    let service = service("remediation-phase-03-closure-packet-classification").await;
    let app = router(service.clone());
    let seeded = seed_positive_closure_corpus(&service, &app).await;

    let packet: aiaf_v1::execution::Phase03ClosureReviewPacket =
        get_json(&app, "/api/remediation/phase-03/closure-review-packet").await;
    let phase03: RemediationPhase03ReproductionEcosystemClosureView = get_json(
        &app,
        "/api/remediation/phase-03/reproduction-ecosystem-closure",
    )
    .await;

    assert_eq!(phase03.phase_status, "closure_grade");
    assert_eq!(
        packet.acceptable_caveat_refs,
        vec![
            "risk:phase03:recurring-program-publication-caveat".to_string(),
            "risk:phase03:bounded-ecosystem-publication-caveat".to_string(),
        ]
    );
    assert!(packet.blocking_risk_refs.is_empty());
    assert_eq!(packet.risk_refs.len(), packet.acceptable_caveat_refs.len());
    assert!(
        packet
            .acceptable_caveat_refs
            .iter()
            .all(|reference| packet.risk_refs.contains(reference))
    );
    assert!(
        !packet
            .risk_refs
            .contains(&"risk:phase03:final-claim-remains-not-yet".to_string())
    );
    assert_eq!(
        phase03.acceptable_caveat_refs,
        packet.acceptable_caveat_refs
    );
    assert_eq!(phase03.blocking_claim_risk_refs, packet.blocking_risk_refs);
    assert_eq!(
        packet.risk_refs.iter().cloned().collect::<BTreeSet<_>>(),
        packet
            .acceptable_caveat_refs
            .iter()
            .cloned()
            .chain(packet.blocking_risk_refs.iter().cloned())
            .collect::<BTreeSet<_>>()
    );

    let _ = service.export_run(&seeded.phase_d_run_id).await.unwrap();
    let reloaded_service = reloaded_service_from_existing_workspace(
        &service,
        "remediation-phase-03-closure-packet-classification-reloaded",
    )
    .await;
    let reloaded_router = router(reloaded_service);
    let reloaded_packet: aiaf_v1::execution::Phase03ClosureReviewPacket = get_json(
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
        reloaded_packet.acceptable_caveat_refs,
        packet.acceptable_caveat_refs
    );
    assert_eq!(
        reloaded_packet.blocking_risk_refs,
        packet.blocking_risk_refs
    );
    assert_eq!(reloaded_packet.risk_refs, packet.risk_refs);
}
