use super::supervisor_v4_support::{
    denied_component, run_full_v4_flow, runtime_state, temp_store_root,
};
use aiaf_v1::execution::{
    FailureBudget, ShellSessionState, execute_active_shell_turn, open_shell_session_bundle,
    start_shell_turn,
};

#[test]
fn supervisor_v4_approval_resume_retry_orchestration_acceptance() {
    let flow = run_full_v4_flow(temp_store_root("approval-resume-orchestration"));

    assert_eq!(flow.bundle.approval_pause_records.len(), 1);
    assert!(
        flow.bundle
            .resume_anchors
            .iter()
            .all(|anchor| !anchor.active)
    );
    assert_eq!(flow.bundle.orchestration_records.len(), 2);
    assert_eq!(
        flow.bundle.shell_session.state,
        ShellSessionState::Completed
    );

    let denied = denied_component();
    let mut denied_bundle = open_shell_session_bundle(
        "shell-session-v4-retry",
        "worker-component-v4",
        Some("agenda-v4-1".to_string()),
        runtime_state(),
        &FailureBudget::default(),
    )
    .unwrap();
    start_shell_turn(&mut denied_bundle, "shell-turn-v4-retry", "denied-memory").unwrap();
    let mut denied_budget = FailureBudget::default();
    let denied_execution = execute_active_shell_turn(
        &mut denied_bundle,
        &denied.build.component_bytes,
        &denied.context,
        &mut denied_budget,
    )
    .unwrap();

    assert!(denied_execution.denial_packet.is_some());
    assert_eq!(denied_bundle.retry_records.len(), 1);
    assert!(denied_bundle.retry_records[0].stop_condition.is_some());
}
