use std::fs;

use aiaf_v1::execution::{
    AgendaItem, AgendaStatus, DurableArtifactStore, ExecutionSessionState, FailureBudget,
    OwnershipBoundary, OwnershipMode, ReplayableRuntimeState, SynthesisClosureDecision,
    SynthesisHandoff, TaskGraph, TaskState,
};

use crate::hardening_support::{
    checkpoint, persist_checkpoint_lineage, ready_session, root_pointer_index, root_task,
    temp_store_root,
};

#[test]
fn supervisor_stalled_worker_bounded_recovery_acceptance() {
    let mut session = ready_session("session-1", "campaign-1", "epoch-1", "envelope-1");
    let mut task = root_task("task-1", "recover a stalled worker without hidden repair");
    session.state = ExecutionSessionState::AwaitingWorkerResult;
    session.active_task_id = Some(task.task_id.clone());
    session.outstanding_worker_refs.push("worker-1".to_string());
    session.blocked_reason = Some(aiaf_v1::execution::BlockedReason::new(
        aiaf_v1::execution::BlockedReasonKind::Worker,
        "worker-1 stalled before returning a result",
    ));
    task.state = TaskState::BlockedOnWorker;
    task.owner_session_id = Some(session.header.session_id.clone());
    task.blocked_reason = session.blocked_reason.clone();

    let mut task_graph = TaskGraph::new(
        "task-1",
        vec![AgendaItem::new(
            "agenda-stalled",
            "task-1",
            "bounded-analysis",
            Vec::new(),
            OwnershipBoundary {
                boundary_id: "boundary-root".to_string(),
                resource_scope: "workspace-root".to_string(),
                mode: OwnershipMode::ExclusiveMutable,
                owner_actor_ref: "supervisor-alpha".to_string(),
            },
        )],
    );
    task_graph
        .mark_dispatched("agenda-stalled", "worker-1")
        .unwrap();

    let mut memory_store = aiaf_v1::execution::MemoryStore::default();
    memory_store.insert_pointer_index(root_pointer_index(
        "pointer-index-1",
        &session.header.campaign_id,
        &task.task_id,
    ));
    let stalled_checkpoint = aiaf_v1::execution::RunCheckpoint::capture(
        "checkpoint-stalled-1",
        &session,
        Some(&task),
        Vec::new(),
        vec!["pointer-index-1".to_string()],
        FailureBudget::default().snapshot(),
        vec!["worker-1".to_string()],
    );
    session.latest_checkpoint_ref = Some(stalled_checkpoint.checkpoint_id.clone());
    persist_checkpoint_lineage(
        &mut memory_store,
        &stalled_checkpoint,
        "stalled",
        "stalled worker checkpoint remained replayable",
    );

    let root = temp_store_root("stalled-worker-recovery");
    let _ = fs::remove_dir_all(&root);
    let store = DurableArtifactStore::bootstrap(&root).unwrap();
    store
        .persist_runtime_state(&ReplayableRuntimeState::new(
            session.clone(),
            task.clone(),
            task_graph.clone(),
            memory_store.clone(),
            Some(stalled_checkpoint.clone()),
            vec![aiaf_v1::execution::ExecutionEvent::new(
                "event-stalled-1",
                aiaf_v1::execution::EventFamily::WorkerDispatchEvent,
                "campaign-1",
                "epoch-1",
                "session-1",
                Some("worker-1".to_string()),
                Some("task-1".to_string()),
                "worker dispatch stalled after checkpoint",
            )],
        ))
        .unwrap();

    let mut reloaded = store.load_runtime_state().unwrap();
    let recovered = reloaded.task_graph.recover_orphaned_dispatches(&[]);

    assert_eq!(recovered, vec!["agenda-stalled".to_string()]);
    assert_eq!(
        reloaded
            .task_graph
            .agenda_item("agenda-stalled")
            .unwrap()
            .status,
        AgendaStatus::Ready
    );
    assert_eq!(
        reloaded
            .memory_store
            .checkpoint_lineage("checkpoint-stalled-1")
            .len(),
        2
    );

    let mut synthesis_graph = TaskGraph::new(
        "task-1",
        vec![AgendaItem::new(
            "agenda-awaiting-synthesis",
            "task-1",
            "bounded-analysis",
            Vec::new(),
            OwnershipBoundary {
                boundary_id: "boundary-synthesis".to_string(),
                resource_scope: "workspace-root".to_string(),
                mode: OwnershipMode::ExclusiveMutable,
                owner_actor_ref: "supervisor-alpha".to_string(),
            },
        )],
    );
    synthesis_graph
        .mark_dispatched("agenda-awaiting-synthesis", "worker-1")
        .unwrap();
    synthesis_graph
        .apply_synthesis_handoff(
            "agenda-awaiting-synthesis",
            &SynthesisHandoff {
                handoff_id: "handoff-1".to_string(),
                task_id: "task-1".to_string(),
                worker_output_refs: vec!["worker-output-1".to_string()],
                supervisor_summary: "partial output preserved".to_string(),
                next_action: "review".to_string(),
                closure_decision: SynthesisClosureDecision::Continue,
            },
        )
        .unwrap();
    synthesis_graph
        .agenda_items
        .iter_mut()
        .find(|agenda_item| agenda_item.agenda_item_id == "agenda-awaiting-synthesis")
        .expect("agenda item should exist")
        .status = AgendaStatus::AwaitingSynthesis;

    let awaiting_recovery = synthesis_graph.recover_orphaned_dispatches(&[]);
    assert_eq!(
        awaiting_recovery,
        vec!["agenda-awaiting-synthesis".to_string()]
    );
    let awaiting_item = synthesis_graph
        .agenda_item("agenda-awaiting-synthesis")
        .unwrap();
    assert_eq!(awaiting_item.status, AgendaStatus::AwaitingSynthesis);
    assert_eq!(
        awaiting_item.output_refs,
        vec!["worker-output-1".to_string()]
    );

    let repaired_checkpoint = checkpoint(
        "checkpoint-stalled-2",
        &session,
        Some(&task),
        vec!["pointer-index-1".to_string()],
        vec!["agenda-stalled".to_string()],
    );
    assert_eq!(
        repaired_checkpoint.failure_budget.no_progress_turns,
        FailureBudget::default().snapshot().no_progress_turns
    );
}
