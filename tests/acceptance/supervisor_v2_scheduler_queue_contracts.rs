use aiaf_v1::local_runtime::V2SchedulerQueueContractView;

use crate::local_runtime_support::{get_json, router, service};

#[tokio::test]
async fn supervisor_v2_scheduler_queue_contracts_acceptance() {
    let service = service("v23-scheduler-queue").await;
    let _ = service
        .run_headless("supervisor-approval-resume-worker-complete")
        .await
        .unwrap();
    let _ = service
        .run_headless("supervisor-promote-activate-successor-campaign")
        .await
        .unwrap();

    let router = router(service.clone());
    let contracts: V2SchedulerQueueContractView =
        get_json(&router, "/api/v2/topology/scheduler-queue").await;

    assert!(contracts.summary.contains("scheduler/queue"));
    assert!(!contracts.scheduler_rules.is_empty());
    assert!(!contracts.queue_rules.is_empty());
    assert!(!contracts.guardrails.is_empty());
}
