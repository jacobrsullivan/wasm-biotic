use aiaf_v1::local_runtime::PortfolioAnalyticsView;

use crate::local_runtime_support::{get_json, router, service};

#[tokio::test]
async fn supervisor_longitudinal_analytics_comparative_review_acceptance() {
    let service = service("longitudinal-analytics").await;
    service
        .start_run("supervisor-approval-resume-worker-complete")
        .await
        .unwrap();
    service
        .run_headless("supervisor-promote-activate-successor-campaign")
        .await
        .unwrap();
    service
        .run_headless("supervisor-durable-fixed-interface-self-hosting-loop")
        .await
        .unwrap();

    let router = router(service);
    let analytics: PortfolioAnalyticsView = get_json(&router, "/api/analytics/portfolio").await;

    assert!(!analytics.longitudinal_findings.is_empty());
    assert!(!analytics.structured_diffs.is_empty());
    assert!(!analytics.trend_metrics.is_empty());
}
