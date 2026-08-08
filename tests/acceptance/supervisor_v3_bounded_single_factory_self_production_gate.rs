use aiaf_v1::local_runtime::{
    V3BoundedSingleFactorySelfProductionGateView, V3GenerationArtifact,
    V3GenerationArtifactExportRequest, V3SelfProductionEvidencePacket,
    V3SelfProductionEvidencePacketExportRequest,
};

use crate::local_runtime_support::{get_json, post_json, router, service};

#[tokio::test]
async fn supervisor_v3_bounded_single_factory_self_production_gate_acceptance() {
    let service = service("v30-gate").await;
    let approval = service
        .run_headless("supervisor-approval-resume-worker-complete")
        .await
        .unwrap();
    let self_hosting = service
        .run_headless("supervisor-durable-fixed-interface-continuous-self-hosting-program")
        .await
        .unwrap();
    let second_cycle = service
        .run_headless("supervisor-second-cycle-v1-completion")
        .await
        .unwrap();
    let router = router(service.clone());

    let artifact: V3GenerationArtifact = post_json(
        &router,
        "/api/v3/generation/artifact/export",
        &V3GenerationArtifactExportRequest {
            run_ids: vec![
                approval.summary.run_id.clone(),
                self_hosting.summary.run_id.clone(),
                second_cycle.summary.run_id.clone(),
            ],
            title: Some("v30 gate artifact".to_string()),
            summary: None,
            coexistence_mode: None,
            operator_constraints: Vec::new(),
        },
    )
    .await;
    let packet: V3SelfProductionEvidencePacket = post_json(
        &router,
        "/api/v3/workspace/evidence/export",
        &V3SelfProductionEvidencePacketExportRequest {
            run_ids: vec![
                approval.summary.run_id.clone(),
                self_hosting.summary.run_id.clone(),
                second_cycle.summary.run_id.clone(),
            ],
            title: Some("v30 gate packet".to_string()),
            summary: None,
            claim_boundary: None,
        },
    )
    .await;

    let gate: V3BoundedSingleFactorySelfProductionGateView =
        get_json(&router, "/api/v3/gate").await;
    assert!(gate.summary.contains("single-factory self-production"));
    assert_eq!(gate.milestone_ladder.len(), 5);
    assert!(gate.boundary_statement.contains("later-factory creation"));
    assert!(gate.claim.is_some());
    assert_eq!(
        gate.claim
            .as_ref()
            .map(|claim| claim.adopted_generation_ref.as_str()),
        Some(artifact.generation_id.as_str())
    );
    assert!(!packet.governance_refs.is_empty());
}
