use aiaf_v1::local_runtime::{
    ConvergenceScorecardView, OperatorReviewPacket, OperatorReviewPacketExportRequest,
};

use crate::local_runtime_support::{get_json, post_json, router, service};

#[tokio::test]
async fn supervisor_convergence_scorecard_adoption_evidence_acceptance() {
    let service = service("convergence-scorecard").await;
    let promoted = service
        .run_headless("supervisor-promote-activate-successor-campaign")
        .await
        .unwrap();
    let self_hosting = service
        .run_headless("supervisor-durable-fixed-interface-continuous-self-hosting-program")
        .await
        .unwrap();

    let router = router(service.clone());
    let _: OperatorReviewPacket = post_json(
        &router,
        "/api/operator/review-packets/export",
        &OperatorReviewPacketExportRequest {
            run_ids: vec![
                promoted.summary.run_id.clone(),
                self_hosting.summary.run_id.clone(),
            ],
            run_set_id: Some("runset-agent-self-hosting-program".to_string()),
            hypothesis_id: Some("hypothesis:v19-convergence".to_string()),
            title: Some("v1.9 convergence review".to_string()),
            summary: Some("Review packet for final v1 convergence evidence.".to_string()),
            verdict: Some("carry-forward".to_string()),
            next_actions: vec!["Export the v2 transition packet.".to_string()],
        },
    )
    .await;

    let scorecard: ConvergenceScorecardView = get_json(&router, "/api/convergence/scorecard").await;

    assert!(scorecard.summary.contains("convergence"));
    assert!(!scorecard.scorecards.is_empty());
    assert!(!scorecard.adoption_evidence.is_empty());
    assert!(!scorecard.unresolved_risks.is_empty());
    assert!(
        scorecard
            .scorecards
            .iter()
            .any(|item| item.scorecard_id == "scorecard:self-hosting-line")
    );
}
