use aiaf_v1::local_runtime::V2ContractDecisionLedgerView;

use crate::local_runtime_support::{get_json, router, service};

#[tokio::test]
async fn supervisor_v2_migration_rollback_decision_record_acceptance() {
    let service = service("v20-decision-ledger").await;
    let _ = service
        .run_headless("supervisor-background-quarantine-rollback-control-loop")
        .await
        .unwrap();
    let _ = service
        .run_headless("supervisor-promote-activate-successor-campaign")
        .await
        .unwrap();

    let router = router(service.clone());
    let ledger: V2ContractDecisionLedgerView =
        get_json(&router, "/api/v2/contracts/decisions").await;

    assert!(ledger.summary.contains("migration"));
    assert!(!ledger.records.is_empty());
    assert!(
        ledger
            .records
            .iter()
            .all(|record| !record.migration_path.is_empty())
    );
    assert!(
        ledger
            .records
            .iter()
            .all(|record| !record.rollback_requirements.is_empty())
    );
    assert!(
        ledger
            .records
            .iter()
            .all(|record| !record.evidence_refs.is_empty())
    );
}
