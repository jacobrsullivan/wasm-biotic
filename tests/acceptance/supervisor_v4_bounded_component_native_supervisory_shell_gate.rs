use super::supervisor_v4_support::{run_full_v4_flow, temp_store_root};
use aiaf_v1::execution::V4SupervisoryShellCompletionStatus;

#[test]
fn supervisor_v4_bounded_component_native_supervisory_shell_gate_acceptance() {
    let artifacts = run_full_v4_flow(temp_store_root("bounded-supervisory-shell-gate"));

    assert_eq!(
        artifacts.gate.status,
        V4SupervisoryShellCompletionStatus::Satisfied
    );
    assert_eq!(
        artifacts.evidence_bundle.shell_evidence_packet.packet_id,
        artifacts.packet.packet_id
    );
    assert_eq!(
        artifacts.final_bundle.completion_gate.status,
        V4SupervisoryShellCompletionStatus::Satisfied
    );
    assert_eq!(
        artifacts
            .store
            .load_shell_session_bundle(&artifacts.bundle.shell_session.shell_session_id)
            .unwrap()
            .shell_session
            .shell_session_id,
        artifacts.bundle.shell_session.shell_session_id
    );
    assert_eq!(
        artifacts
            .store
            .load_v4_shell_evidence_bundle(&artifacts.packet.packet_id)
            .unwrap()
            .shell_evidence_packet
            .packet_id,
        artifacts.packet.packet_id
    );
    assert_eq!(
        artifacts
            .store
            .load_v4_supervisory_shell_bundle(&artifacts.gate.gate_id)
            .unwrap()
            .completion_gate
            .status,
        V4SupervisoryShellCompletionStatus::Satisfied
    );
}
