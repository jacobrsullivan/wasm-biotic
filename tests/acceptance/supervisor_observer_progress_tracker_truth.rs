use std::collections::BTreeMap;

use aiaf_v1::local_runtime::{ConsoleProgressStatus, SystemOverviewView};

use crate::local_runtime_support::{get_json, router, service};

#[tokio::test]
async fn supervisor_observer_progress_tracker_truth_acceptance() {
    let service = service("observer-progress-tracker").await;
    let router = router(service.clone());

    let overview: SystemOverviewView = get_json(&router, "/api/system/overview").await;
    let tracker = overview
        .progress_tracker
        .into_iter()
        .map(|item| (item.area, item.status))
        .collect::<BTreeMap<_, _>>();

    assert_eq!(
        tracker.get("Wasm-Biotic substrate"),
        Some(&ConsoleProgressStatus::NativeNow)
    );
    assert_eq!(
        tracker.get("Skeptical memory"),
        Some(&ConsoleProgressStatus::NativeNow)
    );
    assert_eq!(
        tracker.get("Execution harness"),
        Some(&ConsoleProgressStatus::LiveButBounded)
    );
    assert_eq!(
        tracker.get("Runnable local system"),
        Some(&ConsoleProgressStatus::LiveButBounded)
    );
    assert_eq!(
        tracker.get("Later factory creation"),
        Some(&ConsoleProgressStatus::NativeNow)
    );
    assert_eq!(
        tracker.get("Pre-federation ecosystem contracts"),
        Some(&ConsoleProgressStatus::LiveButBounded)
    );
    assert_eq!(
        tracker.get("Broader native services"),
        Some(&ConsoleProgressStatus::NativeNow)
    );
    assert_eq!(
        tracker.get("Orchestration"),
        Some(&ConsoleProgressStatus::NativeNow)
    );
    assert_eq!(
        tracker.get("Multi-factory ecosystem"),
        Some(&ConsoleProgressStatus::NativeNow)
    );
}
