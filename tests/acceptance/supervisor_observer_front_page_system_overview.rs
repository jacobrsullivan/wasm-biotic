use std::collections::BTreeMap;

use aiaf_v1::local_runtime::{ConsoleProgressStatus, SystemOverviewView};

use crate::local_runtime_support::{get_json, router, service};

#[tokio::test]
async fn supervisor_observer_front_page_system_overview_acceptance() {
    let service = service("observer-front-page").await;
    service
        .start_run("supervisor-approval-resume-worker-complete")
        .await
        .unwrap();

    let router = router(service.clone());
    let overview: SystemOverviewView = get_json(&router, "/api/system/overview").await;

    assert_eq!(overview.current_status.stored_run_count, 1);
    assert_eq!(overview.current_status.active_run_count, 1);
    assert_eq!(overview.current_status.pending_approval_count, 1);

    let nodes = overview
        .north_star_nodes
        .into_iter()
        .map(|node| (node.label, (node.band, node.status)))
        .collect::<BTreeMap<_, _>>();

    assert_eq!(
        nodes.get("Observer Console"),
        Some(&("surface".to_string(), ConsoleProgressStatus::LiveButBounded))
    );
    assert_eq!(
        nodes.get("Wasm-Biotic substrate"),
        Some(&("substrate".to_string(), ConsoleProgressStatus::NativeNow))
    );
    assert_eq!(
        nodes.get("Continuous factory program"),
        Some(&("factory".to_string(), ConsoleProgressStatus::LiveButBounded))
    );
    assert_eq!(
        nodes.get("Later factory creation"),
        Some(&("ecosystem".to_string(), ConsoleProgressStatus::NativeNow))
    );
    assert_eq!(
        nodes.get("Pre-federation ecosystem contracts"),
        Some(&(
            "ecosystem".to_string(),
            ConsoleProgressStatus::LiveButBounded
        ))
    );
    assert_eq!(
        nodes.get("Multi-factory ecosystem"),
        Some(&("ecosystem".to_string(), ConsoleProgressStatus::NativeNow))
    );
}
