use std::fs;

use aiaf_v1::execution::{
    AgendaItem, DurableArtifactStore, OrchestrationError, OwnershipBoundary, OwnershipMode,
    TaskGraph, validate_ownership_boundary,
};

use crate::hardening_support::{
    append_named_related_audit, append_v14_program_evidence, checkpoint,
    persist_checkpoint_lineage, ready_session, root_pointer_index, root_task,
    runtime_state_with_checkpoint, temp_store_root,
};

#[test]
fn supervisor_bounded_multi_campaign_contention_control_acceptance() {
    let shared_scope = "shared-review-queue";
    let existing_boundary = OwnershipBoundary {
        boundary_id: "boundary-existing".to_string(),
        resource_scope: shared_scope.to_string(),
        mode: OwnershipMode::ExclusiveMutable,
        owner_actor_ref: "supervisor-alpha".to_string(),
    };
    let allowed_boundary = OwnershipBoundary {
        boundary_id: "boundary-allowed".to_string(),
        resource_scope: shared_scope.to_string(),
        mode: OwnershipMode::ExclusiveMutable,
        owner_actor_ref: "supervisor-alpha".to_string(),
    };
    validate_ownership_boundary(std::slice::from_ref(&existing_boundary), &allowed_boundary)
        .unwrap();

    let conflicting_boundary = OwnershipBoundary {
        boundary_id: "boundary-conflicting".to_string(),
        resource_scope: shared_scope.to_string(),
        mode: OwnershipMode::ExclusiveMutable,
        owner_actor_ref: "worker-beta".to_string(),
    };
    assert_eq!(
        validate_ownership_boundary(
            std::slice::from_ref(&existing_boundary),
            &conflicting_boundary,
        )
        .unwrap_err(),
        OrchestrationError::OwnershipConflict {
            resource_scope: shared_scope.to_string(),
            existing_owner: "supervisor-alpha".to_string(),
            requested_owner: "worker-beta".to_string(),
        }
    );

    let session = ready_session(
        "session-contention-control",
        "campaign-contention-control",
        "epoch-1",
        "envelope-contention-control",
    );
    let mut task = root_task(
        "task-contention-root",
        "bounded multi-campaign contention control",
    );
    task.owner_session_id = Some(session.header.session_id.clone());

    let mut memory_store = aiaf_v1::execution::MemoryStore::default();
    memory_store.insert_pointer_index(root_pointer_index(
        "pointer-index-contention-control",
        &session.header.campaign_id,
        &task.task_id,
    ));
    let review_artifact_ref = "review-artifact-contention-control-1".to_string();
    append_named_related_audit(
        &mut memory_store,
        &session,
        Some(&task.task_id),
        &review_artifact_ref,
        "audit-review-artifact-contention-control-1",
        aiaf_v1::execution::AuditRecordClass::GovernanceAuditRecord,
        "contention control review artifact remained reconstructable",
    );
    append_v14_program_evidence(
        &mut memory_store,
        &session,
        Some(&task.task_id),
        "contention-control-1",
        std::slice::from_ref(&review_artifact_ref),
    );

    let checkpoint = checkpoint(
        "checkpoint-contention-control-1",
        &session,
        Some(&task),
        vec!["pointer-index-contention-control".to_string()],
        Vec::new(),
    );
    persist_checkpoint_lineage(
        &mut memory_store,
        &checkpoint,
        "contention-control",
        "contention control checkpoint remained reconstructable",
    );

    let task_graph = TaskGraph::new(
        &task.task_id,
        vec![
            AgendaItem::new(
                "agenda-alpha",
                "task-contention-alpha",
                "bounded-analysis",
                Vec::new(),
                existing_boundary,
            ),
            AgendaItem::new(
                "agenda-beta",
                "task-contention-beta",
                "bounded-analysis",
                Vec::new(),
                allowed_boundary,
            ),
        ],
    );
    let runtime_state = runtime_state_with_checkpoint(
        session,
        task,
        task_graph,
        memory_store,
        checkpoint,
        "event-contention-control-1",
        "contention control checkpoint captured",
    );

    let root = temp_store_root("bounded-multi-campaign-contention-control");
    let _ = fs::remove_dir_all(&root);
    let store = DurableArtifactStore::bootstrap(&root).unwrap();
    store.persist_runtime_state(&runtime_state).unwrap();
    let reloaded = store.load_runtime_state().unwrap();

    assert_eq!(reloaded.task_graph.agenda_items.len(), 2);
    assert!(
        reloaded
            .memory_store
            .topic_bundles
            .iter()
            .any(|bundle| bundle.bundle_id == "contention:contention-control-1")
    );
    assert!(
        reloaded
            .memory_store
            .artifacts
            .iter()
            .any(|artifact| artifact.related_ref == "fairness:contention-control-1")
    );
}
