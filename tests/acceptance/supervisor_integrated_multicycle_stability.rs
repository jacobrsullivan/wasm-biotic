use std::fs;

use aiaf_v1::execution::{
    AgendaItem, AgendaStatus, ApprovalClass, AuditRecordClass, DurableArtifactStore, FailureBudget,
    MemoryStore, MemoryUpdateProposal, MemoryUpdateStatus, ReplayableRuntimeState,
    SynthesisClosureDecision, SynthesisHandoff, TaskGraph, TopicBundleClass,
    create_rollback_handle, execute_rollback, persist_approval_decision_bundle,
    persist_approval_request_bundle, validate_background_resume_with_runtime_state,
};

use crate::hardening_support::{
    append_audit, approval_blocked_runtime_state, background_campaign, checkpoint,
    granted_dispatch_decision, persist_checkpoint_lineage, ready_session, request_for_dispatch,
    root_pointer_index, root_task, temp_store_root, worker_card, worker_dispatch, worker_envelope,
};

#[test]
fn supervisor_integrated_multicycle_stability_acceptance() {
    let mut session = ready_session("session-1", "campaign-1", "epoch-1", "envelope-1");
    let mut task = root_task(
        "task-1",
        "run an integrated hardening slice without interface drift",
    );
    let mut memory_store = MemoryStore::default();
    memory_store.insert_pointer_index(root_pointer_index(
        "pointer-index-1",
        &session.header.campaign_id,
        &task.task_id,
    ));

    let checkpoint_1 = checkpoint(
        "checkpoint-cycle-1",
        &session,
        Some(&task),
        vec!["pointer-index-1".to_string()],
        Vec::new(),
    );
    persist_checkpoint_lineage(
        &mut memory_store,
        &checkpoint_1,
        "cycle-1",
        "cycle 1 checkpoint remained reconstructable",
    );

    let approval_request = request_for_dispatch("approval-1", &session, &task.task_id);
    persist_approval_request_bundle(&mut memory_store, &approval_request, &checkpoint_1);
    let granted = granted_dispatch_decision("approval-1", &session, &task.task_id);
    persist_approval_decision_bundle(&mut memory_store, &granted, &[]);
    append_audit(
        &mut memory_store,
        "memory-audit-background-cycle-1",
        "audit-background-cycle-1",
        AuditRecordClass::GovernanceAuditRecord,
        &session,
        Some(&task.task_id),
        "background:campaign-1:ApprovalResponse:checkpoint-cycle-1",
        "background approval response completed cycle 1 safely",
    );

    let approval_runtime_state = approval_blocked_runtime_state(
        memory_store.clone(),
        &approval_request.approval_request_id,
        &checkpoint_1.checkpoint_id,
        &task.task_id,
    );
    validate_background_resume_with_runtime_state(
        &background_campaign("campaign-1"),
        &aiaf_v1::execution::TickSource::ApprovalResponse,
        &approval_runtime_state,
        std::slice::from_ref(&granted),
        &[],
        &task.task_id,
    )
    .unwrap();

    session.state = aiaf_v1::execution::ExecutionSessionState::ExecutingTurn;
    task.state = aiaf_v1::execution::TaskState::Running;
    let envelope = worker_envelope(
        "envelope-1",
        "campaign-1",
        "epoch-1",
        ApprovalClass::SupervisorAllowed,
    );
    let card = worker_card("worker-1");
    let dispatch = worker_dispatch(
        "dispatch-1",
        &session,
        &task.task_id,
        &card.worker_id,
        "envelope-1",
    );
    let dispatch_outcome = aiaf_v1::execution::checkpointed_dispatch_to_worker(
        &mut session,
        &mut task,
        &card,
        &envelope,
        &dispatch,
        "checkpoint-cycle-2",
        Vec::new(),
        vec!["pointer-index-1".to_string()],
        FailureBudget::default().snapshot(),
        vec![dispatch.dispatch_id.clone()],
    )
    .unwrap();
    let checkpoint_2 = match dispatch_outcome {
        aiaf_v1::execution::WorkerDispatchCheckpointOutcome::Dispatched(checkpoint) => checkpoint,
        _ => panic!("dispatch should proceed without extra approval"),
    };
    persist_checkpoint_lineage(
        &mut memory_store,
        &checkpoint_2,
        "cycle-2",
        "cycle 2 dispatch checkpoint remained reconstructable",
    );

    let mut task_graph = TaskGraph::new(
        "task-1",
        vec![AgendaItem::new(
            "agenda-1",
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
    task_graph.mark_dispatched("agenda-1", "worker-1").unwrap();
    task_graph
        .apply_synthesis_handoff(
            "agenda-1",
            &SynthesisHandoff {
                handoff_id: "handoff-1".to_string(),
                task_id: "task-1".to_string(),
                worker_output_refs: vec!["worker-result-1".to_string()],
                supervisor_summary: "cycle 2 output accepted".to_string(),
                next_action: "continue".to_string(),
                closure_decision: SynthesisClosureDecision::Continue,
            },
        )
        .unwrap();
    task_graph
        .agenda_items
        .iter_mut()
        .find(|agenda_item| agenda_item.agenda_item_id == "agenda-1")
        .expect("agenda item should exist")
        .status = AgendaStatus::AwaitingSynthesis;
    task_graph.recover_orphaned_dispatches(&[]);
    assert_eq!(
        task_graph.agenda_item("agenda-1").unwrap().status,
        AgendaStatus::AwaitingSynthesis
    );

    memory_store.propose_memory_update(MemoryUpdateProposal {
        proposal_id: "proposal-cycle-2".to_string(),
        pointer_index_ref: Some("pointer-index-1".to_string()),
        bundle_class: TopicBundleClass::CampaignOperatingNotes,
        scope: aiaf_v1::execution::MemoryScope::Task(task.task_id.clone()),
        proposed_summary: "cycle 2 evidence accepted".to_string(),
        evidence_refs: vec!["worker-result-1".to_string()],
        verification_refs: vec![checkpoint_2.checkpoint_id.clone()],
        status: MemoryUpdateStatus::Proposed,
    });
    memory_store
        .accept_memory_update("proposal-cycle-2", "bundle-cycle-2", "verified")
        .unwrap();

    append_audit(
        &mut memory_store,
        "memory-audit-rollback-cycle-1",
        "audit-rollback-cycle-1",
        AuditRecordClass::PromotionAuditRecord,
        &session,
        Some(&task.task_id),
        "rollback-1",
        "rollback remained reconstructable across cycles",
    );

    let rollback_handle = create_rollback_handle(
        "rollback-1",
        "task",
        "checkpoint-cycle-1",
        vec!["restore checkpoint-cycle-1".to_string()],
        Vec::new(),
    );

    let root = temp_store_root("integrated-multicycle-stability");
    let _ = fs::remove_dir_all(&root);
    let store = DurableArtifactStore::bootstrap(&root).unwrap();
    let mut restored_cycle_1 = approval_blocked_runtime_state(
        memory_store.clone(),
        &approval_request.approval_request_id,
        &checkpoint_1.checkpoint_id,
        &task.task_id,
    );
    restored_cycle_1.memory_store = memory_store.clone();
    store.persist_runtime_state(&restored_cycle_1).unwrap();
    let mut active_cycle_2 = ReplayableRuntimeState::new(
        session.clone(),
        task.clone(),
        task_graph.clone(),
        memory_store.clone(),
        Some(checkpoint_2.clone()),
        vec![aiaf_v1::execution::ExecutionEvent::new(
            "event-cycle-2",
            aiaf_v1::execution::EventFamily::WorkerDispatchEvent,
            "campaign-1",
            "epoch-1",
            "session-1",
            Some("worker-1".to_string()),
            Some("task-1".to_string()),
            "cycle 2 worker dispatch completed",
        )],
    );
    active_cycle_2.session.latest_checkpoint_ref = Some(checkpoint_2.checkpoint_id.clone());
    store.persist_runtime_state(&active_cycle_2).unwrap();

    let rolled_back = execute_rollback(&rollback_handle, &store).unwrap();
    assert_eq!(
        rolled_back
            .session
            .latest_checkpoint_ref
            .as_deref()
            .expect("rollback should restore checkpoint 1"),
        "checkpoint-cycle-1"
    );
    assert!(
        rolled_back
            .memory_store
            .artifacts_for_related_ref("rollback-1")
            .iter()
            .any(|artifact| artifact.class
                == aiaf_v1::execution::MemoryArtifactClass::AuditRecordArtifact)
    );
    assert!(
        rolled_back
            .memory_store
            .load_pointer_index("pointer-index-1")
            .expect("pointer index should survive")
            .critical_refs
            .iter()
            .any(|critical_ref| critical_ref == "worker-result-1")
    );
}
