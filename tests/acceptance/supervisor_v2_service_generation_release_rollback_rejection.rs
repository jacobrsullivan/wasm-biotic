use serde_json::json;

use aiaf_v1::local_runtime::{RunViewModel, V2ServiceGenerationReleaseRollbackView};

use crate::local_runtime_support::{get_json, post_json, router, service};

#[tokio::test]
async fn supervisor_v2_service_generation_release_rollback_rejection_acceptance() {
    let service = service("v26-release-rollback").await;
    let router = router(service.clone());

    let _: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({ "scenario_id": "supervisor-background-quarantine-rollback-control-loop" }),
    )
    .await;

    let release: V2ServiceGenerationReleaseRollbackView =
        get_json(&router, "/api/v2/service-generation/release").await;

    assert!(release.summary.contains("release/rollback layer"));
    assert!(release.release_posture.contains("release"));
    assert!(!release.rejection_paths.is_empty());
}
