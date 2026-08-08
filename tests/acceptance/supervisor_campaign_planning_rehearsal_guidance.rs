use aiaf_v1::local_runtime::PlanningGuidanceView;

use crate::local_runtime_support::{get_json, router, service};

#[tokio::test]
async fn supervisor_campaign_planning_rehearsal_guidance_acceptance() {
    let service = service("planning-guidance").await;
    service
        .start_run("supervisor-approval-resume-worker-complete")
        .await
        .unwrap();

    let router = router(service.clone());
    let planning: PlanningGuidanceView = get_json(&router, "/api/operator/planning").await;

    assert!(planning.planning_summary.contains("Planning guidance"));
    assert!(!planning.recommendations.is_empty());
    assert_eq!(
        planning.recommendations[0].title,
        "Resolve pending approval"
    );
    assert!(!planning.guardrails.is_empty());
}
