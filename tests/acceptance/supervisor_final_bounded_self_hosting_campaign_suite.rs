use aiaf_v1::local_runtime::FinalSelfHostingSuiteView;

use crate::local_runtime_support::{get_json, router, service};

#[tokio::test]
async fn supervisor_final_bounded_self_hosting_campaign_suite_acceptance() {
    let service = service("final-self-hosting-suite").await;
    let scenarios = [
        "supervisor-promote-activate-successor-campaign",
        "supervisor-second-cycle-v1-completion",
        "supervisor-durable-fixed-interface-self-hosting-loop",
        "supervisor-durable-fixed-interface-continuous-self-hosting-program",
    ];
    for scenario_id in scenarios {
        let _ = service.run_headless(scenario_id).await.unwrap();
    }

    let router = router(service.clone());
    let suite: FinalSelfHostingSuiteView = get_json(&router, "/api/convergence/final-suite").await;

    assert_eq!(suite.suite_id, "suite:final-bounded-self-hosting-campaign");
    assert!(
        suite
            .scenario_ids
            .contains(&"supervisor-durable-fixed-interface-self-hosting-loop".to_string())
    );
    assert!(!suite.latest_supporting_runs.is_empty());
    assert!(suite.readiness_signal.contains("supporting run"));
    assert!(!suite.release_rehearsal.is_empty());
    assert!(!suite.evidence_refs.is_empty());
}
