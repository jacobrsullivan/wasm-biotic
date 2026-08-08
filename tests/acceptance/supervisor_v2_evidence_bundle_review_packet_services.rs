use aiaf_v1::local_runtime::{
    OperatorReviewPacket, OperatorReviewPacketExportRequest, V2EvidenceReviewServiceView,
};

use crate::local_runtime_support::{get_json, post_json, router, service};

#[tokio::test]
async fn supervisor_v2_evidence_bundle_review_packet_services_acceptance() {
    let service = service("v22-evidence-services").await;
    let first = service
        .run_headless("supervisor-promote-activate-successor-campaign")
        .await
        .unwrap();
    let second = service
        .run_headless("supervisor-durable-fixed-interface-self-hosting-loop")
        .await
        .unwrap();

    let router = router(service.clone());
    let packet: OperatorReviewPacket = post_json(
        &router,
        "/api/operator/review-packets/export",
        &OperatorReviewPacketExportRequest {
            run_ids: vec![first.summary.run_id.clone(), second.summary.run_id.clone()],
            run_set_id: Some("runset-v22-evidence".to_string()),
            hypothesis_id: Some("hypothesis-v22-evidence".to_string()),
            title: Some("v22 continuity review".to_string()),
            summary: Some("Review packet exposed as a continuity service product.".to_string()),
            verdict: Some("carry-forward".to_string()),
            next_actions: vec!["Keep the packet evidence-linked.".to_string()],
        },
    )
    .await;

    let evidence: V2EvidenceReviewServiceView =
        get_json(&router, "/api/v2/continuity/evidence").await;
    assert!(evidence.summary.contains("evidence/review service"));
    assert!(!evidence.evidence_bundles.is_empty());
    assert!(
        evidence
            .review_packets
            .iter()
            .any(|item| item.packet_id == packet.packet_id)
    );
    assert!(
        evidence
            .evidence_bundles
            .iter()
            .all(|bundle| !bundle.evidence_refs.is_empty())
    );
}
