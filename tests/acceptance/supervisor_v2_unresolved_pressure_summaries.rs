use aiaf_v1::local_runtime::V2UnresolvedPressureSummaryView;

use crate::local_runtime_support::{get_json, router, service};

#[tokio::test]
async fn supervisor_v2_unresolved_pressure_summaries_acceptance() {
    let service = service("v29-pressure").await;
    service
        .run_headless("supervisor-approval-resume-worker-complete")
        .await
        .unwrap();
    service
        .run_headless("supervisor-durable-fixed-interface-continuous-self-hosting-program")
        .await
        .unwrap();

    let router = router(service);
    let pressure: V2UnresolvedPressureSummaryView =
        get_json(&router, "/api/v2/convergence/pressure").await;

    assert!(pressure.summary.contains("unresolved-pressure"));
    assert!(pressure.pressures.len() >= 3);
    assert!(!pressure.achieved_structure.is_empty());
    assert!(
        pressure
            .pressures
            .iter()
            .any(|item| item.severity == "deferred")
    );
}
