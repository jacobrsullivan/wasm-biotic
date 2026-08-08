use aiaf_v1::execution::{
    ApprovalDecision, ApprovalDecisionStatus, AuditRecordClass, GovernanceError, MemoryArtifact,
    MemoryArtifactPayload, MemoryStore, QuarantineResolutionState, create_quarantine_record,
    persist_approval_decision_bundle, persist_approval_request_bundle,
    validate_background_resume_with_runtime_state,
};

use crate::hardening_support::{
    append_audit, approval_blocked_runtime_state, background_campaign, checkpoint,
    granted_dispatch_decision, ready_session, request_for_dispatch, root_task,
};

#[test]
fn supervisor_capability_audit_reconstruction_acceptance() {
    let session = ready_session("session-1", "campaign-1", "epoch-1", "envelope-1");
    let task = root_task("task-1", "reconstruct governed capability history");
    let checkpoint = checkpoint(
        "checkpoint-1",
        &session,
        Some(&task),
        vec!["pointer-index-1".to_string()],
        Vec::new(),
    );

    let mut memory_store = MemoryStore::default();
    let approval_request = request_for_dispatch("approval-1", &session, &task.task_id);
    persist_approval_request_bundle(&mut memory_store, &approval_request, &checkpoint);

    append_audit(
        &mut memory_store,
        "memory-audit-envelope-1",
        "audit-envelope-1",
        AuditRecordClass::CapabilityAuditRecord,
        &session,
        Some(&task.task_id),
        "capability-envelope:envelope-1",
        "capability envelope envelope-1 remained the active authority anchor",
    );

    let denied_decision = ApprovalDecision {
        approval_request_id: approval_request.approval_request_id.clone(),
        campaign_id: session.header.campaign_id.clone(),
        epoch_id: session.header.epoch_id.clone(),
        session_id: session.header.session_id.clone(),
        task_id: task.task_id.clone(),
        action_ref: approval_request.action_ref.clone(),
        decision: ApprovalDecisionStatus::Denied,
        decided_by: "operator-1".to_string(),
        scope_ref: approval_request.scope_ref.clone(),
        notes: Some("denied pending review".to_string()),
    };
    persist_approval_decision_bundle(&mut memory_store, &denied_decision, &[]);

    let runtime_state = approval_blocked_runtime_state(
        memory_store.clone(),
        &approval_request.approval_request_id,
        &checkpoint.checkpoint_id,
        &task.task_id,
    );
    let denied_error = validate_background_resume_with_runtime_state(
        &background_campaign("campaign-1"),
        &aiaf_v1::execution::TickSource::ApprovalResponse,
        &runtime_state,
        &[denied_decision.clone()],
        &[],
        &task.task_id,
    )
    .unwrap_err();
    assert_eq!(
        denied_error,
        GovernanceError::InvalidApprovalsForBackgroundResume {
            campaign_id: "campaign-1".to_string(),
        }
    );

    let granted_decision = granted_dispatch_decision("approval-1", &session, &task.task_id);
    persist_approval_decision_bundle(&mut memory_store, &granted_decision, &[]);

    let capability_related_ref = "capability:dispatch-1:WorkspaceObserve:search:workspace-root";
    append_audit(
        &mut memory_store,
        "memory-audit-capability-revoked-1",
        "audit-capability-revoked-1",
        AuditRecordClass::GovernanceAuditRecord,
        &session,
        Some(&task.task_id),
        capability_related_ref,
        "capability was revoked after quarantine review",
    );

    let mut quarantine_record = create_quarantine_record(
        "quarantine-1",
        aiaf_v1::execution::QuarantineReasonClass::PostApprovalAnomaly,
        vec![task.task_id.clone()],
        Some("rollback-1".to_string()),
    );
    let runtime_state = approval_blocked_runtime_state(
        memory_store.clone(),
        &approval_request.approval_request_id,
        &checkpoint.checkpoint_id,
        &task.task_id,
    );
    let quarantine_error = validate_background_resume_with_runtime_state(
        &background_campaign("campaign-1"),
        &aiaf_v1::execution::TickSource::ApprovalResponse,
        &runtime_state,
        std::slice::from_ref(&granted_decision),
        std::slice::from_ref(&quarantine_record),
        &task.task_id,
    )
    .unwrap_err();
    assert_eq!(
        quarantine_error,
        GovernanceError::QuarantineBlocksAction {
            quarantine_id: "quarantine-1".to_string(),
            affected_ref: "task-1".to_string(),
        }
    );

    quarantine_record.resolution_state = QuarantineResolutionState::Resolved;
    validate_background_resume_with_runtime_state(
        &background_campaign("campaign-1"),
        &aiaf_v1::execution::TickSource::ApprovalResponse,
        &runtime_state,
        std::slice::from_ref(&granted_decision),
        std::slice::from_ref(&quarantine_record),
        &task.task_id,
    )
    .unwrap();

    let capability_audits = memory_store
        .artifacts_for_related_ref(capability_related_ref)
        .into_iter()
        .filter_map(|artifact| match &artifact.payload {
            MemoryArtifactPayload::AuditRecord(audit_record) => Some(audit_record),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(
        capability_audits
            .iter()
            .filter(|audit| audit.class == AuditRecordClass::CapabilityAuditRecord)
            .count()
            >= 3
    );
    assert!(
        capability_audits
            .iter()
            .any(|audit| audit.summary.contains("Denied"))
    );
    assert!(
        capability_audits
            .iter()
            .any(|audit| audit.summary.contains("Granted"))
    );
    assert!(
        memory_store
            .artifacts_for_related_ref("capability-envelope:envelope-1")
            .iter()
            .any(|artifact| matches!(
                artifact,
                MemoryArtifact {
                    class: aiaf_v1::execution::MemoryArtifactClass::AuditRecordArtifact,
                    ..
                }
            ))
    );
}
