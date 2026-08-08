use std::fs;

use aiaf_v1::execution::{
    ApprovalClass, DurableArtifactStore, FailureBudget, MemoryArtifactClass, MemoryStore,
    TaskGraph, WorkerDispatchCheckpointOutcome, checkpointed_dispatch_to_worker,
    persist_approval_decision_bundle, persist_approval_request_bundle, start_turn,
};

use crate::hardening_support::{
    granted_dispatch_decision, ready_session, root_task, runtime_state_with_checkpoint,
    temp_store_root, worker_card, worker_dispatch, worker_envelope,
};

#[test]
fn supervisor_native_capability_organelle_approval_transport_acceptance() {
    let root = temp_store_root("native-capability-organelle-approval-transport");
    let _ = fs::remove_dir_all(&root);
    let store = DurableArtifactStore::bootstrap(&root).unwrap();

    let mut session = ready_session(
        "session-capability-organelle",
        "campaign-capability-organelle",
        "epoch-1",
        "envelope-capability-organelle",
    );
    let mut task = root_task(
        "task-capability-organelle",
        "governed capability organelle dispatch",
    );
    task.owner_session_id = Some(session.header.session_id.clone());

    let worker = worker_card("worker-capability-organelle");
    let envelope = worker_envelope(
        "envelope-capability-organelle",
        &session.header.campaign_id,
        &session.header.epoch_id,
        ApprovalClass::HumanRequired,
    );
    let dispatch = worker_dispatch(
        "dispatch-1",
        &session,
        &task.task_id,
        &worker.worker_id,
        &envelope.envelope_id,
    );
    start_turn(&mut session, &mut task, "turn-capability-organelle-1").unwrap();

    let outcome = checkpointed_dispatch_to_worker(
        &mut session,
        &mut task,
        &worker,
        &envelope,
        &dispatch,
        "checkpoint-capability-organelle-1",
        Vec::new(),
        Vec::new(),
        FailureBudget::default().snapshot(),
        vec!["dispatch-once".to_string()],
    )
    .unwrap();
    let WorkerDispatchCheckpointOutcome::ApprovalBlocked {
        approval_request,
        checkpoint,
    } = outcome
    else {
        panic!("dispatch should require governed approval transport");
    };

    let mut memory_store = MemoryStore::default();
    persist_approval_request_bundle(&mut memory_store, &approval_request, &checkpoint);
    let approval_decision = granted_dispatch_decision(
        &approval_request.approval_request_id,
        &session,
        &task.task_id,
    );
    let write = persist_approval_decision_bundle(&mut memory_store, &approval_decision, &[]);

    let runtime_state = runtime_state_with_checkpoint(
        session,
        task,
        TaskGraph::new("task-capability-organelle", Vec::new()),
        memory_store,
        checkpoint,
        "event-capability-organelle-checkpoint",
        "capability organelle checkpoint captured",
    );
    store.persist_runtime_state(&runtime_state).unwrap();
    let reloaded = store.load_runtime_state().unwrap();

    assert!(write.audit_artifact_ids.len() >= 2);
    assert!(
        reloaded
            .memory_store
            .artifacts_for_related_ref("approval-transport:approval-dispatch-1")
            .iter()
            .all(|artifact| artifact.class == MemoryArtifactClass::AuditRecordArtifact)
    );
    assert!(
        reloaded
            .memory_store
            .artifacts_for_related_ref(
                "capability:dispatch-1:WorkspaceObserve:search:workspace-root"
            )
            .iter()
            .any(|artifact| artifact.class == MemoryArtifactClass::AuditRecordArtifact)
    );
    assert!(
        reloaded
            .memory_store
            .approval_lineage("approval-dispatch-1")
            .len()
            >= 2
    );
    assert!(
        reloaded
            .memory_store
            .approval_lineage("approval-dispatch-1")
            .iter()
            .any(|artifact| artifact.class == MemoryArtifactClass::ApprovalRequestArtifact)
    );
    assert!(
        reloaded
            .memory_store
            .approval_lineage("approval-dispatch-1")
            .iter()
            .any(|artifact| artifact.class == MemoryArtifactClass::ApprovalDecisionArtifact)
    );
}
