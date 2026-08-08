use aiaf_v1::local_runtime::PortfolioAnalyticsView;

use crate::local_runtime_support::{get_json, router, service};

#[tokio::test]
async fn supervisor_campaign_trend_regression_detection_acceptance() {
    let service = service("campaign-trend-regression").await;
    service
        .start_run("supervisor-approval-resume-worker-complete")
        .await
        .unwrap();
    service
        .start_run("supervisor-background-quarantine-rollback-control-loop")
        .await
        .unwrap();

    let router = router(service);
    let analytics: PortfolioAnalyticsView = get_json(&router, "/api/analytics/portfolio").await;

    assert!(!analytics.regression_signals.is_empty());
    assert!(
        analytics
            .regression_signals
            .iter()
            .any(|signal| signal.contains("Approval") || signal.contains("Rollback"))
    );
}
