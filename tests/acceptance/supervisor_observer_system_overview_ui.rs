use crate::local_runtime_support::{get_text, router, service};

#[tokio::test]
async fn supervisor_observer_system_overview_ui_acceptance() {
    let service = service("observer-system-overview-ui").await;
    let router = router(service.clone());

    let html = get_text(&router, "/").await;
    assert!(html.contains("General-Audience Ecosystem Home"));
    assert!(html.contains("What AIAF Is Now"));
    assert!(html.contains("AIAF is an AI system built on the idea that software should improve by growing new, tested parts"));
    assert!(html.contains("In its current form, AIAF acts as a local supervisory system for controlled upgrade experiments."));
    assert!(html.contains("AIAF is building workspace services for reading and changing code in controlled environments"));
    assert!(html.contains("Past / Current / Next"));
    assert!(html.contains("Live Ecosystem State"));
    assert!(html.contains("Active Factory Capabilities"));
    assert!(html.contains("Capabilities Being Actively Processed"));
    assert!(html.contains("Recommended Runs"));
    assert!(html.contains("Advanced Controls"));
    assert!(html.contains("Open expert console"));

    let console_html = get_text(&router, "/console").await;
    assert!(console_html.contains("AIAF v1.9 Final Convergence"));
    assert!(console_html.contains("System Overview"));
    assert!(console_html.contains("Scenario Studio"));
    assert!(console_html.contains("Convergence"));
    assert!(console_html.contains("Post-v4"));
    assert!(console_html.contains("Phase A Launch Truth"));
    assert!(console_html.contains("Phase B Adoption Workspace"));
    assert!(console_html.contains("Phase C Observation Workspace"));
    assert!(console_html.contains("Phase D Import Workspace"));
    assert!(console_html.contains("NorthStar 01 Universal Shell"));
    assert!(console_html.contains("NorthStar 02 Persistent Shell"));
    assert!(console_html.contains("NorthStar 03 Native Services"));
    assert!(console_html.contains("NorthStar 04 Worker Ecology"));
    assert!(console_html.contains("NorthStar 05 Factory Programs"));
    assert!(console_html.contains("NorthStar 06 Ecosystem"));
    assert!(console_html.contains("NorthStar 07 Closure Review"));
    assert!(console_html.contains("Remediation Phase 01 Lifecycle Closure"));
    assert!(console_html.contains("Remediation Phase 02 Service And Ecology Closure"));
    assert!(console_html.contains("Remediation Phase 03 Reproduction And Ecosystem Closure"));
    assert!(console_html.contains("Remediation Phase 04 Final Closure Re-Review"));
    assert!(console_html.contains("Export Phase B Review Packet"));
    assert!(console_html.contains("Export Phase C Review Packet"));
    assert!(console_html.contains("Export Phase D Review Packet"));
    assert!(console_html.contains("Export Phase D Contract Manifest"));
    assert!(console_html.contains("Transition"));
    assert!(console_html.contains("Replay"));
    assert!(console_html.contains("Analytics"));
    assert!(console_html.contains("History"));
    assert!(console_html.contains("Portfolio"));
    assert!(console_html.contains("Evidence"));
    assert!(console_html.contains("Operator"));
    assert!(console_html.contains("Scenario Catalog"));
    assert!(console_html.contains("Recent Runs"));
    assert!(console_html.contains("Progress Tracker"));
    assert!(console_html.contains("Factory"));
    assert!(console_html.contains("Agent"));
    assert!(console_html.contains("Run Evidence"));
    assert!(console_html.contains("North Star map, progress tracker"));
    assert!(console_html.contains("Post-v4 Factory Evolution"));
    assert!(console_html.contains("Bounded Ecosystem Bridge"));
    assert!(console_html.contains("Remediation"));
}
