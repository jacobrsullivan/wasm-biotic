use super::supervisor_v4_support::{approval_component, runtime_state, temp_store_root};
use aiaf_v1::execution::{
    FailureBudget, ShellSessionState, dispatch_shell_session, execute_active_shell_turn,
    open_shell_session_bundle, start_shell_turn,
};

#[test]
fn supervisor_v4_shell_session_turn_law_acceptance() {
    let _root = temp_store_root("shell-session-turn-law");
    let approval = approval_component();
    let mut failure_budget = FailureBudget::default();
    let mut bundle = open_shell_session_bundle(
        "shell-session-v4-1",
        "worker-component-v4",
        Some("agenda-v4-1".to_string()),
        runtime_state(),
        &failure_budget,
    )
    .unwrap();

    dispatch_shell_session(&mut bundle, "agenda-v4-1").unwrap();
    let turn = start_shell_turn(&mut bundle, "shell-turn-v4-approval", "request-approval").unwrap();
    assert_eq!(turn.turn_index, 1);
    assert_eq!(bundle.shell_session.state, ShellSessionState::RunningTurn);

    let execution = execute_active_shell_turn(
        &mut bundle,
        &approval.build.component_bytes,
        &approval.context,
        &mut failure_budget,
    )
    .unwrap();

    assert!(execution.approval_request.is_some());
    assert_eq!(bundle.shell_turns.len(), 1);
    assert_eq!(bundle.shell_checkpoints.len(), 1);
    assert_eq!(bundle.resume_anchors.len(), 1);
    assert_eq!(
        bundle.shell_session.state,
        ShellSessionState::PausedForApproval
    );
}
