use aiaf_v1::local_runtime::V2CheckpointReplayRecoveryView;

use crate::local_runtime_support::{get_json, router, service};

#[tokio::test]
async fn supervisor_v2_checkpoint_replay_recovery_surfaces_acceptance() {
    let service = service("v23-replay-recovery").await;
    let _ = service
        .run_headless("supervisor-background-quarantine-rollback-control-loop")
        .await
        .unwrap();
    let _ = service
        .run_headless("supervisor-promote-activate-successor-campaign")
        .await
        .unwrap();

    let router = router(service.clone());
    let replay: V2CheckpointReplayRecoveryView =
        get_json(&router, "/api/v2/topology/replay-recovery").await;

    assert!(replay.summary.contains("replay/recovery"));
    assert!(!replay.surfaces.is_empty());
    assert!(
        replay
            .surfaces
            .iter()
            .any(|surface| surface.surface_kind == "checkpoint")
    );
    assert!(
        replay
            .surfaces
            .iter()
            .any(|surface| surface.surface_kind == "replay")
    );
    assert!(
        replay
            .surfaces
            .iter()
            .any(|surface| surface.surface_kind == "recovery")
    );
}
