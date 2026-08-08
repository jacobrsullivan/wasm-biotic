use serde_json::json;

use aiaf_v1::local_runtime::{RunViewModel, V2GovernanceProtocolRecordView};

use crate::local_runtime_support::{get_json, post_empty, post_json, router, service};

#[tokio::test]
async fn supervisor_v2_governance_protocol_records_acceptance() {
    let service = service("v24-governance-protocol").await;
    let router = router(service.clone());

    let approval: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({ "scenario_id": "supervisor-approval-resume-worker-complete" }),
    )
    .await;
    let _: RunViewModel = post_empty(
        &router,
        &format!("/api/runs/{}/approval/grant", approval.summary.run_id),
    )
    .await;

    let rollback: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({ "scenario_id": "supervisor-background-quarantine-rollback-control-loop" }),
    )
    .await;
    let _: RunViewModel = post_empty(
        &router,
        &format!("/api/runs/{}/rollback", rollback.summary.run_id),
    )
    .await;

    let protocol: V2GovernanceProtocolRecordView =
        get_json(&router, "/api/v2/governance/protocol").await;

    assert!(protocol.summary.contains("governance protocol"));
    assert!(
        protocol
            .records
            .iter()
            .any(|record| record.action_class == "approval-grant")
    );
    assert!(
        protocol
            .records
            .iter()
            .any(|record| record.action_class == "rollback")
    );
}
