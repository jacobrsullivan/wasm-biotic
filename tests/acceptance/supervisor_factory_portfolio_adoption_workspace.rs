use aiaf_v1::local_runtime::FactoryPortfolioView;

use crate::local_runtime_support::{get_json, router, service};

#[tokio::test]
async fn supervisor_factory_portfolio_adoption_workspace_acceptance() {
    let service = service("factory-portfolio").await;
    let promoted = service
        .start_run("supervisor-promote-activate-successor-campaign")
        .await
        .unwrap();
    let quarantined = service
        .start_run("supervisor-background-quarantine-rollback-control-loop")
        .await
        .unwrap();

    let router = router(service.clone());
    let portfolio: FactoryPortfolioView = get_json(&router, "/api/factory/portfolio").await;

    assert!(
        portfolio
            .current_factory_summary
            .contains("Latest local factory context")
    );
    assert_eq!(portfolio.timeline.len(), 2);
    assert_eq!(portfolio.timeline[0].run_id, quarantined.summary.run_id);
    assert_eq!(portfolio.timeline[1].run_id, promoted.summary.run_id);
    assert!(portfolio.timeline[0].risk_state.contains("quarantine"));
    assert!(!portfolio.adoption_queue.is_empty());
}
