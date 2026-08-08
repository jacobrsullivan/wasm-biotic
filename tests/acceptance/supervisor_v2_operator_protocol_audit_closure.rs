use serde_json::json;

use aiaf_v1::local_runtime::{RunViewModel, V2OperatorProtocolAuditView};

use crate::local_runtime_support::{get_json, post_empty, post_json, router, service};

#[tokio::test]
async fn supervisor_v2_operator_protocol_audit_closure_acceptance() {
    let service = service("v24-governance-operator").await;
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

    let awaiting_approval: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({ "scenario_id": "supervisor-durable-fixed-interface-continuous-self-hosting-program" }),
    )
    .await;
    let paused: RunViewModel = post_empty(
        &router,
        &format!(
            "/api/runs/{}/approval/escalate",
            awaiting_approval.summary.run_id
        ),
    )
    .await;
    let _: RunViewModel = post_empty(
        &router,
        &format!("/api/runs/{}/resume", paused.summary.run_id),
    )
    .await;

    let operator: V2OperatorProtocolAuditView =
        get_json(&router, "/api/v2/governance/operator").await;

    assert!(operator.summary.contains("operator-protocol audit"));
    assert!(
        operator
            .actions
            .iter()
            .any(|action| action.action_kind == "approval-grant")
    );
    assert!(
        operator
            .actions
            .iter()
            .any(|action| action.action_kind == "resume")
    );
}
