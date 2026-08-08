use aiaf_v1::execution::{DurableArtifactStore, V4SupervisoryShellCompletionStatus};
use aiaf_v1::local_runtime::LocalRunStatus;

use crate::local_runtime_support::service;

fn output_ref_suffix<'a>(output_refs: &'a [String], prefix: &str) -> Option<&'a str> {
    output_refs
        .iter()
        .find_map(|reference| reference.strip_prefix(prefix))
}

#[tokio::test]
async fn supervisor_phase_a_live_runner_shell_path_acceptance() {
    let service = service("phase-a-live-shell").await;
    let run = service
        .run_headless("supervisor-v4-live-shell-runner-path")
        .await
        .unwrap();

    assert_eq!(run.summary.status, LocalRunStatus::Completed);
    assert_eq!(run.summary.pending_approval_count, 0);
    assert!(
        run.summary
            .output_refs
            .iter()
            .any(|reference| reference.starts_with("v4-shell-session:"))
    );
    assert!(
        run.summary
            .output_refs
            .iter()
            .any(|reference| reference.starts_with("v4-shell-packet:"))
    );
    assert!(
        run.summary
            .output_refs
            .iter()
            .any(|reference| reference.starts_with("v4-shell-gate:"))
    );

    let shell_session_id =
        output_ref_suffix(&run.summary.output_refs, "v4-shell-session:").unwrap();
    let packet_id = output_ref_suffix(&run.summary.output_refs, "v4-shell-packet:").unwrap();
    let gate_id = output_ref_suffix(&run.summary.output_refs, "v4-shell-gate:").unwrap();

    let run_root = service
        .workspace()
        .root()
        .join("runs")
        .join(&run.summary.run_id);
    let store = DurableArtifactStore::bootstrap(run_root.join("store")).unwrap();
    let shell_bundle = store.load_shell_session_bundle(shell_session_id).unwrap();
    let evidence_bundle = store.load_v4_shell_evidence_bundle(packet_id).unwrap();
    let supervisory_bundle = store.load_v4_supervisory_shell_bundle(gate_id).unwrap();

    assert_eq!(
        shell_bundle.shell_session.shell_session_id,
        shell_session_id
    );
    assert_eq!(evidence_bundle.shell_evidence_packet.packet_id, packet_id);
    assert_eq!(
        supervisory_bundle.completion_gate.status,
        V4SupervisoryShellCompletionStatus::Satisfied
    );

    let export_root = service.export_run(&run.summary.run_id).await.unwrap();
    assert!(export_root.join("snapshots/v4-shell-session.json").exists());
    assert!(
        export_root
            .join("snapshots/v4-shell-evidence.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/v4-shell-workspace.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/v4-shell-completion-gate.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/northstar-01-launch-assemblies.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/northstar-01-admissions.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/northstar-01-lifecycle-transitions.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/northstar-01-export-bundles.json")
            .exists()
    );
}
