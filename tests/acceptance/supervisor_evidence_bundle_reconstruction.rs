use std::fs;

use aiaf_v1::execution::{
    AuditRecordClass, ConsolidationJob, ConsolidationJobStatus, DurableArtifactStore,
    MemoryArtifactPayload, MemoryStore, MemoryUpdateProposal, MemoryUpdateStatus, MemoryWriteError,
    TopicBundle, TopicBundleClass, TranscriptSlice, persist_approval_decision_bundle,
    persist_approval_request_bundle,
};

use crate::hardening_support::{
    append_audit, checkpoint, granted_dispatch_decision, persist_checkpoint_lineage, ready_session,
    request_for_dispatch, root_pointer_index, root_task, temp_store_root,
};

#[test]
fn supervisor_evidence_bundle_reconstruction_acceptance() {
    let session = ready_session("session-1", "campaign-1", "epoch-1", "envelope-1");
    let task = root_task("task-1", "reconstruct evidence bundle after consolidation");
    let checkpoint = checkpoint(
        "checkpoint-1",
        &session,
        Some(&task),
        vec!["pointer-index-1".to_string()],
        Vec::new(),
    );

    let mut memory_store = MemoryStore::default();
    memory_store.insert_pointer_index(root_pointer_index(
        "pointer-index-1",
        &session.header.campaign_id,
        &task.task_id,
    ));
    persist_checkpoint_lineage(
        &mut memory_store,
        &checkpoint,
        "evidence",
        "checkpoint lineage retained for later reconstruction",
    );

    let approval_request = request_for_dispatch("approval-1", &session, &task.task_id);
    let request_write =
        persist_approval_request_bundle(&mut memory_store, &approval_request, &checkpoint);
    let granted_decision = granted_dispatch_decision("approval-1", &session, &task.task_id);
    let decision_write =
        persist_approval_decision_bundle(&mut memory_store, &granted_decision, &[]);

    let contradiction = memory_store.register_contradiction(
        "contradiction-1",
        vec![
            checkpoint.checkpoint_id.clone(),
            approval_request.approval_request_id.clone(),
        ],
        "verify replay lineage against approval evidence",
        Some("pointer-index-1"),
    );
    assert_eq!(contradiction.contradiction_id, "contradiction-1");

    append_audit(
        &mut memory_store,
        "memory-audit-quarantine-1",
        "audit-quarantine-1",
        AuditRecordClass::GovernanceAuditRecord,
        &session,
        Some(&task.task_id),
        "quarantine-1",
        "quarantine review preserved the affected evidence set",
    );
    append_audit(
        &mut memory_store,
        "memory-audit-rollback-1",
        "audit-rollback-1",
        AuditRecordClass::PromotionAuditRecord,
        &session,
        Some(&task.task_id),
        "rollback-1",
        "rollback handle remained reconstructable after consolidation",
    );

    memory_store.add_transcript_slice(TranscriptSlice {
        slice_id: "slice-1".to_string(),
        campaign_id: session.header.campaign_id.clone(),
        epoch_id: session.header.epoch_id.clone(),
        session_id: Some(session.header.session_id.clone()),
        task_id: Some(task.task_id.clone()),
        referenced_artifacts: vec![
            request_write.approval_request_artifact_id.clone(),
            decision_write.approval_decision_artifact_id.clone(),
            "memory-audit-rollback-1".to_string(),
            "worker-result-1".to_string(),
        ],
        summary: "replay operator can explain the bounded result path".to_string(),
        excerpts: vec!["worker-result-1 stayed attached to rollback evidence".to_string()],
    });

    memory_store.add_topic_bundle(TopicBundle {
        bundle_id: "bundle-legacy".to_string(),
        bundle_class: TopicBundleClass::CampaignOperatingNotes,
        scope: aiaf_v1::execution::MemoryScope::Campaign(session.header.campaign_id.clone()),
        summary: "legacy bundle".to_string(),
        evidence_refs: vec![checkpoint.checkpoint_id.clone()],
        freshness_policy: "manual".to_string(),
    });

    memory_store.propose_memory_update(MemoryUpdateProposal {
        proposal_id: "proposal-1".to_string(),
        pointer_index_ref: Some("pointer-index-1".to_string()),
        bundle_class: TopicBundleClass::GovernanceNotes,
        scope: aiaf_v1::execution::MemoryScope::Task(task.task_id.clone()),
        proposed_summary: "bounded replay evidence accepted".to_string(),
        evidence_refs: vec!["worker-result-1".to_string(), "rollback-1".to_string()],
        verification_refs: vec![
            checkpoint.checkpoint_id.clone(),
            approval_request.approval_request_id.clone(),
        ],
        status: MemoryUpdateStatus::Proposed,
    });
    memory_store
        .accept_memory_update("proposal-1", "bundle-evidence", "verified-by-checkpoint")
        .unwrap();

    memory_store
        .run_consolidation_job(ConsolidationJob {
            job_id: "consolidation-1".to_string(),
            pointer_index_ref: "pointer-index-1".to_string(),
            input_bundle_refs: vec!["bundle-legacy".to_string(), "bundle-evidence".to_string()],
            output_bundle_id: "bundle-governed-summary".to_string(),
            output_bundle_class: TopicBundleClass::GovernanceNotes,
            output_scope: aiaf_v1::execution::MemoryScope::Campaign(
                session.header.campaign_id.clone(),
            ),
            output_summary: "governed summary".to_string(),
            freshness_policy: "consolidated".to_string(),
            status: ConsolidationJobStatus::Planned,
        })
        .unwrap();

    let pointer_index = memory_store
        .load_pointer_index("pointer-index-1")
        .expect("pointer index should still exist");
    for critical_ref in [
        "checkpoint-1",
        "approval-1",
        "contradiction-1",
        "rollback-1",
        "worker-result-1",
    ] {
        assert!(
            pointer_index
                .critical_refs
                .iter()
                .any(|candidate| candidate == critical_ref),
            "critical ref {critical_ref} should survive evidence-preserving compaction"
        );
    }

    let checkpoint_lineage = memory_store.checkpoint_lineage("checkpoint-1");
    assert!(
        checkpoint_lineage
            .iter()
            .any(|artifact| matches!(artifact.payload, MemoryArtifactPayload::Checkpoint(_)))
    );
    assert!(
        checkpoint_lineage
            .iter()
            .any(|artifact| matches!(artifact.payload, MemoryArtifactPayload::AuditRecord(_)))
    );

    let approval_lineage = memory_store.approval_lineage("approval-1");
    assert!(
        approval_lineage
            .iter()
            .any(|artifact| matches!(artifact.payload, MemoryArtifactPayload::ApprovalRequest(_)))
    );
    assert!(
        approval_lineage
            .iter()
            .any(|artifact| matches!(artifact.payload, MemoryArtifactPayload::ApprovalDecision(_)))
    );

    let root = temp_store_root("evidence-bundle-reconstruction");
    let _ = fs::remove_dir_all(&root);
    let store = DurableArtifactStore::bootstrap(&root).unwrap();
    let mut persisted_session = session.clone();
    persisted_session.latest_checkpoint_ref = Some(checkpoint.checkpoint_id.clone());
    let runtime_state = aiaf_v1::execution::ReplayableRuntimeState::new(
        persisted_session,
        task.clone(),
        aiaf_v1::execution::TaskGraph::new("task-1", Vec::new()),
        memory_store.clone(),
        Some(checkpoint.clone()),
        vec![aiaf_v1::execution::ExecutionEvent::new(
            "event-checkpoint-1",
            aiaf_v1::execution::EventFamily::CheckpointEvent,
            "campaign-1",
            "epoch-1",
            "session-1",
            None,
            Some("task-1".to_string()),
            "checkpoint persisted",
        )],
    );
    store.persist_runtime_state(&runtime_state).unwrap();
    let mut reloaded = store.load_runtime_state().unwrap();

    assert_eq!(
        reloaded
            .memory_store
            .artifacts_for_related_ref("rollback-1")
            .len(),
        1
    );
    assert_eq!(
        reloaded
            .memory_store
            .run_consolidation_job(ConsolidationJob {
                job_id: "missing-pointer".to_string(),
                pointer_index_ref: "missing".to_string(),
                input_bundle_refs: vec!["bundle-governed-summary".to_string()],
                output_bundle_id: "bundle-impossible".to_string(),
                output_bundle_class: TopicBundleClass::GovernanceNotes,
                output_scope: aiaf_v1::execution::MemoryScope::Campaign("campaign-1".to_string()),
                output_summary: "should fail".to_string(),
                freshness_policy: "never".to_string(),
                status: ConsolidationJobStatus::Planned,
            })
            .unwrap_err(),
        MemoryWriteError::PointerIndexNotFound {
            pointer_index_id: "missing".to_string(),
        }
    );
}
