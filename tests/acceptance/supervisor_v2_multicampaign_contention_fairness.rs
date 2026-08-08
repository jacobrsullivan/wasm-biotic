use aiaf_v1::local_runtime::V2ContentionFairnessView;

use crate::local_runtime_support::{get_json, router, service};

#[tokio::test]
async fn supervisor_v2_multicampaign_contention_fairness_acceptance() {
    let service = service("v23-fairness").await;
    let _ = service
        .run_headless("supervisor-background-quarantine-rollback-control-loop")
        .await
        .unwrap();
    let _ = service
        .run_headless("supervisor-durable-fixed-interface-continuous-self-hosting-program")
        .await
        .unwrap();

    let router = router(service.clone());
    let fairness: V2ContentionFairnessView = get_json(&router, "/api/v2/topology/contention").await;

    assert!(fairness.summary.contains("pressure"));
    assert_eq!(fairness.entries.len(), 3);
    assert!(
        fairness
            .entries
            .iter()
            .all(|entry| !entry.fairness_rule.is_empty())
    );
}
