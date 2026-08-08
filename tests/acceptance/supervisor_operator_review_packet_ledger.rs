use aiaf_v1::local_runtime::{
    OperatorReviewPacket, OperatorReviewPacketExportRequest, ReviewPacketLedgerView,
};

use crate::local_runtime_support::{get_json, post_json, router, service};

#[tokio::test]
async fn supervisor_operator_review_packet_ledger_acceptance() {
    let service = service("review-packets").await;
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
            run_set_id: Some("runset-agent-self-hosting-program".to_string()),
            hypothesis_id: Some("hypothesis-self-hosting-review".to_string()),
            title: Some("Self-hosting comparative review".to_string()),
            summary: Some("Review packet for bounded self-hosting evidence.".to_string()),
            verdict: Some("carry-forward".to_string()),
            next_actions: vec!["Compare the replay branches before rerunning.".to_string()],
        },
    )
    .await;

    assert_eq!(
        packet.run_set_id.as_deref(),
        Some("runset-agent-self-hosting-program")
    );

    let review: ReviewPacketLedgerView = get_json(&router, "/api/operator/review-packets").await;
    assert!(review.summary.contains("review packet"));
    assert!(!review.packets.is_empty());
    assert!(!review.experiment_ledger.is_empty());
}
