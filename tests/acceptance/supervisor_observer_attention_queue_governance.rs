use aiaf_v1::local_runtime::{AttentionItem, AttentionSeverity};

use crate::local_runtime_support::{get_json, router, service};

#[tokio::test]
async fn supervisor_observer_attention_queue_governance_acceptance() {
    let service = service("observer-attention-queue").await;
    let run = service
        .start_run("supervisor-background-quarantine-rollback-control-loop")
        .await
        .unwrap();
    let router = router(service.clone());

    let attention: Vec<AttentionItem> = get_json(
        &router,
        &format!("/api/runs/{}/attention", run.summary.run_id),
    )
    .await;

    assert!(attention.len() >= 2);
    assert_eq!(attention[0].severity, AttentionSeverity::Critical);
    assert_eq!(attention[0].title, "Quarantine constrains this run");
    assert!(!attention[0].related_refs.is_empty());
    assert_eq!(attention[1].severity, AttentionSeverity::Critical);
    assert_eq!(attention[1].title, "Rollback available");
    assert!(!attention[1].recommended_action.is_empty());
}
