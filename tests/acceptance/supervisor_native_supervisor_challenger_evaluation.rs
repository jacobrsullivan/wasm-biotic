use std::fs;

use aiaf_v1::execution::{
    AuditRecord, AuditRecordClass, CapabilityImportTarget, DurableArtifactStore, MemoryArtifact,
    MemoryStore, NativeReplacementTier, NativeSufficiencyGate, PromotionReadinessStatus,
    ShadowCampaignStatus, ShadowEvaluationBundle, TaskGraph, build_native_sufficiency_evidence,
    compare_challenger_outputs, create_rollback_handle, decide_promotion_readiness,
    open_challenger_evaluation_session, open_shadow_campaign,
};

use crate::hardening_support::{
    append_named_related_audit, checkpoint, persist_checkpoint_lineage, ready_session,
    root_pointer_index, root_task, runtime_state_with_checkpoint, supervisor_dimension_scores,
    temp_store_root,
};

#[test]
fn supervisor_native_supervisor_challenger_evaluation_acceptance() {
    let root = temp_store_root("native-supervisor-challenger-evaluation");
    let _ = fs::remove_dir_all(&root);
    let store = DurableArtifactStore::bootstrap(&root).unwrap();

    let shared_input_refs = vec!["campaign-brief".to_string(), "pointer-index".to_string()];
    let mut incumbent_session = ready_session(
        "session-incumbent",
        "campaign-eval",
        "epoch-1",
        "envelope-root",
    );
    incumbent_session.state = aiaf_v1::execution::ExecutionSessionState::Completed;
    let mut incumbent_task = root_task("task-incumbent", "incumbent evaluation run");
    incumbent_task.state = aiaf_v1::execution::TaskState::Completed;
    incumbent_task.owner_session_id = Some(incumbent_session.header.session_id.clone());
    incumbent_task.record_output_ref("incumbent-output-1");
    let mut incumbent_memory = MemoryStore::default();
    incumbent_memory.insert_pointer_index(root_pointer_index(
        "pointer-index",
        &incumbent_session.header.campaign_id,
        &incumbent_task.task_id,
    ));
    let incumbent_checkpoint = checkpoint(
        "checkpoint-incumbent-eval",
        &incumbent_session,
        Some(&incumbent_task),
        vec!["pointer-index".to_string()],
        Vec::new(),
    );
    persist_checkpoint_lineage(
        &mut incumbent_memory,
        &incumbent_checkpoint,
        "incumbent-eval",
        "incumbent checkpoint remained reconstructable",
    );
    let incumbent_state = runtime_state_with_checkpoint(
        incumbent_session,
        incumbent_task,
        TaskGraph::new("task-incumbent", Vec::new()),
        incumbent_memory,
        incumbent_checkpoint,
        "event-incumbent",
        "incumbent evaluation checkpoint captured",
    );

    let mut challenger_session = ready_session(
        "session-challenger",
        "campaign-eval",
        "epoch-1",
        "envelope-root",
    );
    challenger_session.state = aiaf_v1::execution::ExecutionSessionState::Completed;
    let mut challenger_task = root_task("task-challenger", "challenger evaluation run");
    challenger_task.state = aiaf_v1::execution::TaskState::Completed;
    challenger_task.owner_session_id = Some(challenger_session.header.session_id.clone());
    challenger_task.record_output_ref("challenger-output-1");
    let mut challenger_memory = MemoryStore::default();
    challenger_memory.insert_pointer_index(root_pointer_index(
        "pointer-index",
        &challenger_session.header.campaign_id,
        &challenger_task.task_id,
    ));
    let challenger_checkpoint = checkpoint(
        "checkpoint-challenger-eval",
        &challenger_session,
        Some(&challenger_task),
        vec!["pointer-index".to_string()],
        Vec::new(),
    );
    persist_checkpoint_lineage(
        &mut challenger_memory,
        &challenger_checkpoint,
        "challenger-eval",
        "challenger checkpoint remained reconstructable",
    );

    let comparison = compare_challenger_outputs(
        "comparison-challenger-v1-2",
        "session-incumbent",
        "session-challenger",
        shared_input_refs.clone(),
        vec!["incumbent-output-1".to_string()],
        vec!["challenger-output-1".to_string()],
        supervisor_dimension_scores("incumbent", "challenger"),
        "native challenger remained promotable under fixed interfaces",
    )
    .unwrap();
    challenger_memory.append(MemoryArtifact::audit_record(
        "memory-audit-comparison-challenger-v1-2",
        AuditRecord::new(
            "audit-comparison-challenger-v1-2",
            AuditRecordClass::GovernanceAuditRecord,
            "campaign-eval",
            "epoch-1",
            "session-challenger",
            Some("task-challenger".to_string()),
            comparison.comparison_id.clone(),
            "challenger comparison remained reconstructable",
        ),
    ));

    let evidence = build_native_sufficiency_evidence(
        "evidence-challenger-v1-2",
        CapabilityImportTarget::NativeSupervisorChallenger,
        NativeReplacementTier::NativeSupervisorChallengers,
        vec![
            "review-artifact-1".to_string(),
            comparison.comparison_id.clone(),
        ],
        vec!["checkpoint-challenger-eval".to_string()],
        vec!["audit-comparison-challenger-v1-2".to_string()],
        "native challenger evidence remained explicit",
        true,
    );
    challenger_memory.append(MemoryArtifact::audit_record(
        "memory-audit-evidence-challenger-v1-2",
        AuditRecord::new(
            "audit-evidence-challenger-v1-2",
            AuditRecordClass::PromotionAuditRecord,
            "campaign-eval",
            "epoch-1",
            "session-challenger",
            Some("task-challenger".to_string()),
            evidence.evidence_id.clone(),
            "challenger evidence remained reconstructable",
        ),
    ));
    append_named_related_audit(
        &mut challenger_memory,
        &challenger_session,
        Some(&challenger_task.task_id),
        "review-artifact-1",
        "audit-review-artifact-1",
        AuditRecordClass::GovernanceAuditRecord,
        "review artifact remained reconstructable",
    );

    let challenger_state = runtime_state_with_checkpoint(
        challenger_session,
        challenger_task,
        TaskGraph::new("task-challenger", Vec::new()),
        challenger_memory,
        challenger_checkpoint,
        "event-challenger",
        "challenger evaluation checkpoint captured",
    );

    let mut shadow_campaign = open_shadow_campaign(
        "shadow-campaign-eval-v1-2",
        "campaign-eval",
        incumbent_state.session.header.session_id.clone(),
        challenger_state.session.header.session_id.clone(),
        shared_input_refs.clone(),
        vec![aiaf_v1::execution::TickSource::ApprovalResponse],
        vec![
            CapabilityImportTarget::CampaignControl,
            CapabilityImportTarget::ApprovalGateway,
            CapabilityImportTarget::ReviewPromotion,
        ],
        true,
        "rollback-eval-v1-2",
    )
    .unwrap();
    shadow_campaign.status = ShadowCampaignStatus::DecisionReady;
    let evaluation_session = open_challenger_evaluation_session(
        "evaluation-eval-v1-2",
        &shadow_campaign,
        &shared_input_refs,
        &shared_input_refs,
        vec!["envelope-review".to_string()],
    )
    .unwrap();

    let readiness = decide_promotion_readiness(
        "promotion-readiness-eval-v1-2",
        &comparison,
        &NativeSufficiencyGate {
            target: CapabilityImportTarget::NativeSupervisorChallenger,
            required_tier: NativeReplacementTier::NativeSupervisorChallengers,
            requires_exact_match: true,
        },
        &evidence,
        &[create_rollback_handle(
            "rollback-eval-v1-2",
            "shadow-campaign-eval-v1-2",
            "checkpoint-incumbent-eval",
            vec!["restore checkpoint-incumbent-eval".to_string()],
            Vec::new(),
        )],
        &["review-artifact-1".to_string()],
        &[],
    );
    assert_eq!(readiness.status, PromotionReadinessStatus::Promotable);

    let bundle = ShadowEvaluationBundle {
        shadow_campaign,
        challenger_evaluation_session: evaluation_session,
        incumbent_runtime_state: incumbent_state,
        challenger_runtime_state: challenger_state.clone(),
        comparison_record: comparison.clone(),
        sufficiency_evidence: evidence.clone(),
        promotion_readiness_decision: readiness,
    };
    store.persist_shadow_evaluation_bundle(&bundle).unwrap();
    let reloaded = store
        .load_shadow_evaluation_bundle("shadow-campaign-eval-v1-2")
        .unwrap();

    assert_eq!(reloaded.comparison_record.dimension_scores.len(), 6);
    assert_eq!(
        reloaded.promotion_readiness_decision.status,
        PromotionReadinessStatus::Promotable
    );
    assert_eq!(reloaded, bundle);
}
