use aiaf_v1::local_runtime::{
    OperatorReviewPacket, OperatorReviewPacketExportRequest, ReviewPacketLedgerView,
};

use crate::local_runtime_support::{get_json, post_json, router, service};

#[tokio::test]
async fn supervisor_experiment_ledger_import_export_acceptance() {
    let service = service("review-packet-import").await;
    let run = service
        .run_headless("supervisor-durable-fixed-interface-self-hosting-loop")
        .await
        .unwrap();

    let router = router(service.clone());
    let exported: OperatorReviewPacket = post_json(
        &router,
        "/api/operator/review-packets/export",
        &OperatorReviewPacketExportRequest {
            run_ids: vec![run.summary.run_id.clone()],
            run_set_id: Some("runset-agent-self-hosting-program".to_string()),
            hypothesis_id: Some("hypothesis-self-hosting-proof".to_string()),
            title: Some("Self-hosting export".to_string()),
            summary: Some("Carry review context forward.".to_string()),
            verdict: Some("retain-with-caution".to_string()),
            next_actions: vec!["Inspect continuous review before adoption.".to_string()],
        },
    )
    .await;

    let mut imported = exported.clone();
    imported.packet_id = "review-packet:imported:acceptance".to_string();
    imported.title = "Imported self-hosting review".to_string();

    let imported_response: OperatorReviewPacket =
        post_json(&router, "/api/operator/review-packets/import", &imported).await;
    assert!(imported_response.imported);

    let review: ReviewPacketLedgerView = get_json(&router, "/api/operator/review-packets").await;
    assert!(review.packets.iter().any(|packet| packet.imported));
    assert!(review.experiment_ledger.len() >= 2);
}
