use aiaf_v1::execution::{
    AgendaItem, AgendaStatus, AuditRecordClass, ExecutionSessionState, FailureBudget,
    MemoryArtifactClass, MemoryStore, OwnershipBoundary, OwnershipMode, SynthesisClosureDecision,
    SynthesisHandoff, TaskGraph, TaskState, WorkerDispatchCheckpointOutcome, WorkerResult,
    accept_worker_result, checkpointed_dispatch_to_worker, start_turn,
};

use crate::hardening_support::{
    append_audit, ready_session, root_pointer_index, root_task, worker_card, worker_dispatch,
    worker_envelope,
};

#[test]
fn supervisor_native_orchestration_capability_operation_acceptance() {
    let mut session = ready_session("session-1", "campaign-1", "epoch-1", "envelope-1");
    let mut task = root_task(
        "task-1",
        "route bounded worker capability operation natively",
    );
    let mut memory_store = MemoryStore::default();
    memory_store.insert_pointer_index(root_pointer_index(
        "pointer-index-1",
        &session.header.campaign_id,
        &task.task_id,
    ));

    start_turn(&mut session, &mut task, "turn-1").unwrap();

    let worker = worker_card("worker-1");
    let envelope = worker_envelope(
        "envelope-1",
        &session.header.campaign_id,
        &session.header.epoch_id,
        aiaf_v1::execution::ApprovalClass::SupervisorAllowed,
    );
    let dispatch = worker_dispatch(
        "dispatch-1",
        &session,
        &task.task_id,
        &worker.worker_id,
        &envelope.envelope_id,
    );

    let WorkerDispatchCheckpointOutcome::Dispatched(dispatch_checkpoint) =
        checkpointed_dispatch_to_worker(
            &mut session,
            &mut task,
            &worker,
            &envelope,
            &dispatch,
            "checkpoint-orchestration-1",
            Vec::new(),
            vec!["pointer-index-1".to_string()],
            FailureBudget::default().snapshot(),
            vec![dispatch.dispatch_id.clone()],
        )
        .unwrap()
    else {
        panic!("bounded capability dispatch should proceed without extra approval");
    };

    append_audit(
        &mut memory_store,
        "memory-audit-capability-operation-1",
        "audit-capability-operation-1",
        AuditRecordClass::CapabilityAuditRecord,
        &session,
        Some(&task.task_id),
        "capability:dispatch-1:WorkspaceObserve:search:workspace-root",
        "native routing admitted the bounded capability operation",
    );

    let mut task_graph = TaskGraph::new(
        &task.task_id,
        vec![AgendaItem::new(
            "agenda-root",
            &task.task_id,
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
        .mark_dispatched("agenda-root", worker.worker_id.clone())
        .unwrap();

    let worker_result = WorkerResult {
        dispatch_id: dispatch.dispatch_id.clone(),
        worker_id: worker.worker_id.clone(),
        worker_task_ref: dispatch.worker_task_ref.clone(),
        result_ref: "worker-result-1".to_string(),
        summary: "bounded analysis completed".to_string(),
        result_message: aiaf_v1::execution::MessageArtifact {
            message_id: "worker-result-message-1".to_string(),
            campaign_id: session.header.campaign_id.clone(),
            epoch_id: session.header.epoch_id.clone(),
            task_id: task.task_id.clone(),
            sender_actor_ref: worker.worker_id.clone(),
            receiver_actor_ref: session.header.session_id.clone(),
            message_class: aiaf_v1::execution::MessageArtifactClass::ResultMessage,
            payload_summary: "bounded analysis completed".to_string(),
            referenced_artifacts: vec![dispatch_checkpoint.checkpoint_id.clone()],
            status: aiaf_v1::execution::MessageArtifactStatus::Received,
        },
    };
    accept_worker_result(&mut session, &mut task, &worker_result).unwrap();
    task_graph
        .apply_synthesis_handoff(
            "agenda-root",
            &SynthesisHandoff {
                handoff_id: "handoff-1".to_string(),
                task_id: task.task_id.clone(),
                worker_output_refs: vec![worker_result.result_ref.clone()],
                supervisor_summary: "native routing accepted the bounded worker output".to_string(),
                next_action: "complete".to_string(),
                closure_decision: SynthesisClosureDecision::Complete,
            },
        )
        .unwrap();

    assert_eq!(session.state, ExecutionSessionState::Ready);
    assert_eq!(task.state, TaskState::Ready);
    assert_eq!(
        task_graph.agenda_item("agenda-root").unwrap().status,
        AgendaStatus::Completed
    );
    assert!(
        memory_store
            .artifacts_for_related_ref(
                "capability:dispatch-1:WorkspaceObserve:search:workspace-root"
            )
            .iter()
            .any(|artifact| artifact.class == MemoryArtifactClass::AuditRecordArtifact)
    );
}
