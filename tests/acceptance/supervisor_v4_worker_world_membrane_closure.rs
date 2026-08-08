use super::supervisor_v4_support::{
    denied_component, memory_component, runtime_state, temp_store_root,
};
use aiaf_v1::execution::{
    FailureBudget, ShellActionDecisionStatus, ShellSessionState, execute_active_shell_turn,
    open_shell_session_bundle, start_shell_turn,
};

#[test]
fn supervisor_v4_worker_world_membrane_closure_acceptance() {
    let _root = temp_store_root("worker-world-membrane");
    let memory = memory_component();
    let denied = denied_component();

    let mut allowed_bundle = open_shell_session_bundle(
        "shell-session-v4-allowed",
        "worker-component-v4",
        Some("agenda-v4-1".to_string()),
        runtime_state(),
        &FailureBudget::default(),
    )
    .unwrap();
    start_shell_turn(
        &mut allowed_bundle,
        "shell-turn-v4-memory",
        "retrieve-memory",
    )
    .unwrap();
    let mut allowed_budget = FailureBudget::default();
    let allowed_execution = execute_active_shell_turn(
        &mut allowed_bundle,
        &memory.build.component_bytes,
        &memory.context,
        &mut allowed_budget,
    )
    .unwrap();

    assert!(allowed_execution.denial_packet.is_none());
    assert_eq!(allowed_bundle.action_traces.len(), 1);
    assert_eq!(
        allowed_bundle.action_traces[0].decision.status,
        ShellActionDecisionStatus::Allowed
    );
    assert_eq!(allowed_bundle.shell_session.state, ShellSessionState::Ready);

    let mut denied_bundle = open_shell_session_bundle(
        "shell-session-v4-denied",
        "worker-component-v4",
        Some("agenda-v4-1".to_string()),
        runtime_state(),
        &FailureBudget::default(),
    )
    .unwrap();
    start_shell_turn(&mut denied_bundle, "shell-turn-v4-denied", "denied-memory").unwrap();
    let mut denied_budget = FailureBudget::default();
    let denied_execution = execute_active_shell_turn(
        &mut denied_bundle,
        &denied.build.component_bytes,
        &denied.context,
        &mut denied_budget,
    )
    .unwrap();

    assert!(denied_execution.denial_packet.is_some());
    assert_eq!(denied_bundle.denial_packets.len(), 1);
    assert_eq!(denied_bundle.retry_records.len(), 1);
    assert_eq!(denied_bundle.shell_session.state, ShellSessionState::Denied);
}
