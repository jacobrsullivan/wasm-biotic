use super::supervisor_v4_support::{run_full_v4_flow, temp_store_root};
use aiaf_v1::execution::ShellEvidenceCompletenessStatus;
use aiaf_v1::local_runtime::render_shell_workspace_view;

#[test]
fn supervisor_v4_shell_evidence_workspace_acceptance() {
    let artifacts = run_full_v4_flow(temp_store_root("shell-evidence-workspace"));

    assert_eq!(
        artifacts.packet.completeness_status,
        ShellEvidenceCompletenessStatus::Complete
    );
    assert_eq!(artifacts.workspace.packet_id, artifacts.packet.packet_id);
    let workspace = render_shell_workspace_view(&artifacts.packet, &artifacts.bundle);
    assert_eq!(workspace.turn_count, 3);
    assert_eq!(workspace.approval_pause_count, 1);
    assert_eq!(workspace.memory_trace_count, 1);
    assert_eq!(workspace.verified_memory_count, 1);
    assert_eq!(workspace.orchestration_count, 2);
}
