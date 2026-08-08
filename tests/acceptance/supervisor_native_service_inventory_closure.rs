use std::fs;

use aiaf_v1::execution::{
    DurableArtifactStore, carried_import_targets, closure_inventory_has_hidden_imports,
    closure_inventory_is_complete,
};

use crate::hardening_support::{
    append_inventory_audits, append_named_related_audit, completed_runtime_state,
    full_closure_inventory, temp_store_root,
};

#[test]
fn supervisor_native_service_inventory_closure_acceptance() {
    let root = temp_store_root("native-service-inventory-closure");
    let _ = fs::remove_dir_all(&root);
    let store = DurableArtifactStore::bootstrap(&root).unwrap();

    let inventory = full_closure_inventory("closure-v1-3-services");
    let mut runtime_state = completed_runtime_state(
        "session-service-inventory",
        "campaign-service-inventory",
        "epoch-1",
        "task-service-inventory",
        "checkpoint-service-inventory",
        vec!["service-inventory-output".to_string()],
        "native service inventory checkpoint captured",
    );
    append_inventory_audits(
        &mut runtime_state.memory_store,
        &runtime_state.session,
        Some(&runtime_state.root_task.task_id),
        &inventory,
    );
    append_named_related_audit(
        &mut runtime_state.memory_store,
        &runtime_state.session,
        Some(&runtime_state.root_task.task_id),
        &inventory.inventory_id,
        "audit-service-inventory-closure",
        aiaf_v1::execution::AuditRecordClass::GovernanceAuditRecord,
        "native service inventory closure remained reconstructable",
    );

    store.persist_runtime_state(&runtime_state).unwrap();
    let reloaded = store.load_runtime_state().unwrap();

    assert!(closure_inventory_is_complete(&inventory));
    assert!(!closure_inventory_has_hidden_imports(&inventory));

    let carried_targets = carried_import_targets(&inventory);
    assert_eq!(
        carried_targets,
        vec![
            "ModelHosting".to_string(),
            "WorktreeHostAdapter".to_string(),
            "EnvironmentBridge".to_string(),
        ]
    );
    assert!(
        reloaded
            .memory_store
            .artifacts_for_related_ref(&inventory.inventory_id)
            .iter()
            .any(|artifact| artifact.class
                == aiaf_v1::execution::MemoryArtifactClass::AuditRecordArtifact)
    );

    for entry in &inventory.entries {
        let audit_ref = entry.audit_ref.as_deref().unwrap();
        assert!(
            reloaded
                .memory_store
                .artifacts_for_related_ref(audit_ref)
                .iter()
                .any(|artifact| artifact.class
                    == aiaf_v1::execution::MemoryArtifactClass::AuditRecordArtifact)
        );
    }
}
