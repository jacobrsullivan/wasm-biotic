use aiaf_v1::local_runtime::FactoryView;

use crate::local_runtime_support::{get_json, router, service};

#[tokio::test]
async fn supervisor_observer_factory_generation_view_acceptance() {
    let service = service("observer-factory-view").await;
    let run = service
        .start_run("supervisor-promote-activate-successor-campaign")
        .await
        .unwrap();
    let router = router(service.clone());

    let factory: FactoryView = get_json(
        &router,
        &format!("/api/runs/{}/factory", run.summary.run_id),
    )
    .await;

    assert_eq!(factory.run_id, run.summary.run_id);
    assert_eq!(factory.campaign_id, run.summary.campaign_id);
    assert_eq!(factory.epoch_id, run.summary.epoch_id);
    assert!(factory.challenger_ref.is_some());
    assert!(factory.comparison_state.contains("evidence"));
    assert!(factory.promotion_state.contains("evidence"));
    assert!(factory.canary_release_state.contains("release"));
    assert!(factory.attention_queue.len() >= 1);
}
