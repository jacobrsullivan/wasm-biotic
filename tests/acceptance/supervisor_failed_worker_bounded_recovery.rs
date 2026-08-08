use std::fs;

use aiaf_v1::execution::{
    AgendaItem, AgendaStatus, DurableArtifactStore, FailureBudget, ReplayableRuntimeState,
    RetryClass, StopCondition, SynthesisClosureDecision, SynthesisHandoff, TaskGraph,
};

use crate::hardening_support::{
    checkpoint, persist_checkpoint_lineage, ready_session, root_pointer_index, root_task,
    temp_store_root,
};

#[test]
fn supervisor_failed_worker_bounded_recovery_acceptance() {
    let session = ready_session("session-1", "campaign-1", "epoch-1", "envelope-1");
    let task = root_task(
        "task-1",
        "bound failed worker recovery under the failure budget",
    );
    let mut failure_budget = FailureBudget {
        max_session_failures: 2,
        max_task_failures: 2,
        max_no_progress_turns: 2,
        ..FailureBudget::default()
    };

    assert_eq!(
        failure_budget.record_failure(RetryClass::TransientWorker),
        None
    );
    let retry_checkpoint = checkpoint(
        "checkpoint-failure-retry-1",
        &session,
        Some(&task),
        vec!["pointer-index-1".to_string()],
        Vec::new(),
    );
    assert_eq!(retry_checkpoint.failure_budget.session_failures, 0);

    let stop_condition = failure_budget.record_failure(RetryClass::TransientWorker);
    assert_eq!(stop_condition, Some(StopCondition::FailureBudgetExhausted));
    assert_eq!(
        failure_budget.record_failure(RetryClass::PolicyNonRetryable),
        Some(StopCondition::GovernanceHardStop)
    );
    assert_eq!(
        failure_budget.record_failure(RetryClass::StructuralNonRetryable),
        Some(StopCondition::StructuralValidationFailure)
    );

    let mut task_graph = TaskGraph::new(
        "task-1",
        vec![AgendaItem::new(
            "agenda-failed",
            "task-1",
            "bounded-analysis",
            Vec::new(),
            aiaf_v1::execution::OwnershipBoundary {
                boundary_id: "boundary-root".to_string(),
                resource_scope: "workspace-root".to_string(),
                mode: aiaf_v1::execution::OwnershipMode::ExclusiveMutable,
                owner_actor_ref: "supervisor-alpha".to_string(),
            },
        )],
    );
    task_graph
        .mark_dispatched("agenda-failed", "worker-1")
        .unwrap();
    task_graph
        .apply_synthesis_handoff(
            "agenda-failed",
            &SynthesisHandoff {
                handoff_id: "handoff-failed-1".to_string(),
                task_id: "task-1".to_string(),
                worker_output_refs: vec!["partial-worker-output-1".to_string()],
                supervisor_summary: "partial output could not be accepted".to_string(),
                next_action: "contain".to_string(),
                closure_decision: SynthesisClosureDecision::Fail,
            },
        )
        .unwrap();
    assert_eq!(
        task_graph.agenda_item("agenda-failed").unwrap().status,
        AgendaStatus::Failed
    );

    let mut memory_store = aiaf_v1::execution::MemoryStore::default();
    memory_store.insert_pointer_index(root_pointer_index(
        "pointer-index-1",
        &session.header.campaign_id,
        &task.task_id,
    ));
    persist_checkpoint_lineage(
        &mut memory_store,
        &aiaf_v1::execution::RunCheckpoint::capture(
            "checkpoint-failure-stop-1",
            &session,
            Some(&task),
            Vec::new(),
            vec!["pointer-index-1".to_string()],
            failure_budget.snapshot(),
            Vec::new(),
        ),
        "failed-worker",
        "failure budget stop remained reconstructable",
    );

    let root = temp_store_root("failed-worker-recovery");
    let _ = fs::remove_dir_all(&root);
    let store = DurableArtifactStore::bootstrap(&root).unwrap();
    let mut persisted_session = session.clone();
    persisted_session.latest_checkpoint_ref = Some("checkpoint-failure-stop-1".to_string());
    store
        .persist_runtime_state(&ReplayableRuntimeState::new(
            persisted_session,
            task.clone(),
            task_graph.clone(),
            memory_store.clone(),
            Some(aiaf_v1::execution::RunCheckpoint::capture(
                "checkpoint-failure-stop-1",
                &session,
                Some(&task),
                Vec::new(),
                vec!["pointer-index-1".to_string()],
                failure_budget.snapshot(),
                Vec::new(),
            )),
            vec![aiaf_v1::execution::ExecutionEvent::new(
                "event-failure-1",
                aiaf_v1::execution::EventFamily::WorkerDispatchEvent,
                "campaign-1",
                "epoch-1",
                "session-1",
                Some("worker-1".to_string()),
                Some("task-1".to_string()),
                "worker failure entered bounded recovery",
            )],
        ))
        .unwrap();

    let reloaded = store.load_runtime_state().unwrap();
    assert_eq!(
        reloaded
            .latest_checkpoint
            .expect("checkpoint should persist")
            .failure_budget
            .session_failures,
        2
    );
    assert_eq!(
        reloaded
            .memory_store
            .checkpoint_lineage("checkpoint-failure-stop-1")
            .len(),
        2
    );
}
