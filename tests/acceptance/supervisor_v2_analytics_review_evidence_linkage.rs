use aiaf_v1::local_runtime::{OperatorReviewPacketExportRequest, V2AnalyticsEvidenceLinkageView};

use crate::local_runtime_support::{get_json, post_json, router, service};

#[tokio::test]
async fn supervisor_v2_analytics_review_evidence_linkage_acceptance() {
    let service = service("v22-analytics-linkage").await;
    let first = service
        .run_headless("supervisor-promote-activate-successor-campaign")
        .await
        .unwrap();
    let second = service
        .run_headless("supervisor-durable-fixed-interface-self-hosting-loop")
        .await
        .unwrap();

    let router = router(service.clone());
    let _: aiaf_v1::local_runtime::OperatorReviewPacket = post_json(
        &router,
        "/api/operator/review-packets/export",
        &OperatorReviewPacketExportRequest {
            run_ids: vec![first.summary.run_id.clone(), second.summary.run_id.clone()],
            run_set_id: None,
            hypothesis_id: None,
            title: Some("v22 analytics packet".to_string()),
            summary: Some("Evidence-linked review answer for analytics continuity.".to_string()),
            verdict: None,
            next_actions: vec![],
        },
    )
    .await;

    let linkage: V2AnalyticsEvidenceLinkageView =
        get_json(&router, "/api/v2/continuity/analytics").await;
    assert!(linkage.summary.contains("analytics/review linkage"));
    assert!(!linkage.answers.is_empty());
    assert!(
        linkage
            .answers
            .iter()
            .all(|answer| !answer.evidence_refs.is_empty())
    );
}
