use serde_json::json;

use aiaf_v1::local_runtime::{RunViewModel, V2CapabilityPressureApprovalLoadView};

use crate::local_runtime_support::{get_json, post_json, router, service};

#[tokio::test]
async fn supervisor_v2_capability_pressure_approval_load_acceptance() {
    let service = service("v27-pressure-approval").await;
    let router = router(service.clone());

    let _: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({ "scenario_id": "supervisor-approval-resume-worker-complete" }),
    )
    .await;
    let _: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({ "scenario_id": "supervisor-background-quarantine-rollback-control-loop" }),
    )
    .await;

    let pressure: V2CapabilityPressureApprovalLoadView =
        get_json(&router, "/api/v2/operations/pressure").await;

    assert!(pressure.summary.contains("capability and approval"));
    assert!(pressure.total_pending_approvals >= 1);
    assert_eq!(pressure.entries.len(), 2);
}
