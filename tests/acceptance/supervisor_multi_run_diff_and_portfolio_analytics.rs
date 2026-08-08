use aiaf_v1::local_runtime::PortfolioAnalyticsView;

use crate::local_runtime_support::{get_json, router, service};

#[tokio::test]
async fn supervisor_multi_run_diff_and_portfolio_analytics_acceptance() {
    let service = service("portfolio-analytics").await;
    service
        .start_run("supervisor-approval-resume-worker-complete")
        .await
        .unwrap();
    service
        .run_headless("supervisor-durable-fixed-interface-self-hosting-loop")
        .await
        .unwrap();

    let router = router(service.clone());
    let analytics: PortfolioAnalyticsView = get_json(&router, "/api/analytics/portfolio").await;

    assert!(analytics.analytics_summary.contains("Structured analytics"));
    assert!(!analytics.trend_metrics.is_empty());
    assert!(!analytics.structured_diffs.is_empty());
    assert!(!analytics.highlighted_risks.is_empty());
}
