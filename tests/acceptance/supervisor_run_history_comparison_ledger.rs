use aiaf_v1::local_runtime::RunHistoryView;

use crate::local_runtime_support::{get_json, router, service};

#[tokio::test]
async fn supervisor_run_history_comparison_ledger_acceptance() {
    let service = service("run-history-ledger").await;
    let first = service
        .start_run("supervisor-promote-activate-successor-campaign")
        .await
        .unwrap();
    let second = service
        .run_headless("supervisor-durable-fixed-interface-self-hosting-loop")
        .await
        .unwrap();

    let router = router(service.clone());
    let history: RunHistoryView = get_json(&router, "/api/history").await;

    assert_eq!(history.recent_runs.len(), 2);
    assert_eq!(history.comparison_ledger.len(), 2);
    assert_eq!(history.recent_runs[0].run_id, second.summary.run_id);
    assert_eq!(history.recent_runs[1].run_id, first.summary.run_id);
    assert_eq!(
        history.comparison_ledger[0].baseline_run_id,
        Some(first.summary.run_id)
    );
    assert!(!history.comparison_ledger[0].evidence_refs.is_empty());
}
