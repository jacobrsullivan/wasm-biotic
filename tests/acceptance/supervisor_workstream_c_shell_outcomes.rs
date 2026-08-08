use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode};
use serde_json::json;
use tower::util::ServiceExt;

use aiaf_v1::local_runtime::{LocalRunStatus, NorthStar02PersistentShellView, RunViewModel};

use crate::local_runtime_support::{get_json, post_empty, post_json, router, service};

#[tokio::test]
async fn supervisor_workstream_c_shell_outcomes_acceptance() {
    let service = service("workstream-c-shell-outcomes").await;
    let router = router(service.clone());

    let awaiting: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({
            "scenario_id": "supervisor-durable-fixed-interface-continuous-self-hosting-program"
        }),
    )
    .await;
    assert_eq!(awaiting.summary.status, LocalRunStatus::AwaitingApproval);

    let invalid_resume = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/api/runs/{}/resume", awaiting.summary.run_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let invalid_resume_status = invalid_resume.status();
    let invalid_resume_body = to_bytes(invalid_resume.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(invalid_resume_status, StatusCode::BAD_REQUEST);
    assert!(String::from_utf8_lossy(&invalid_resume_body).contains("run is not paused"));

    let expired: RunViewModel = post_empty(
        &router,
        &format!("/api/runs/{}/approval/expire", awaiting.summary.run_id),
    )
    .await;
    assert_eq!(expired.summary.status, LocalRunStatus::Failed);
    assert!(
        expired
            .summary
            .output_refs
            .iter()
            .any(|reference| reference.starts_with("northstar-02-expiry:"))
    );

    let escalated_created: RunViewModel = post_json(
        &router,
        "/api/runs",
        &json!({
            "scenario_id": "supervisor-durable-fixed-interface-continuous-self-hosting-program"
        }),
    )
    .await;
    assert_eq!(
        escalated_created.summary.status,
        LocalRunStatus::AwaitingApproval
    );

    let escalated: RunViewModel = post_empty(
        &router,
        &format!(
            "/api/runs/{}/approval/escalate",
            escalated_created.summary.run_id
        ),
    )
    .await;
    assert_eq!(escalated.summary.status, LocalRunStatus::Paused);
    assert!(
        escalated
            .summary
            .output_refs
            .iter()
            .any(|reference| reference.starts_with("northstar-02-escalation:"))
    );

    let northstar02: NorthStar02PersistentShellView =
        get_json(&router, "/api/northstar/02/persistent-shell").await;
    assert!(!northstar02.lease_expiries.is_empty());
    assert!(!northstar02.escalations.is_empty());

    let expired_export = service.export_run(&expired.summary.run_id).await.unwrap();
    assert!(
        expired_export
            .join("snapshots/northstar-02-lease-expiries.json")
            .exists()
    );
    let escalated_export = service.export_run(&escalated.summary.run_id).await.unwrap();
    assert!(
        escalated_export
            .join("snapshots/northstar-02-shell-escalations.json")
            .exists()
    );
}
