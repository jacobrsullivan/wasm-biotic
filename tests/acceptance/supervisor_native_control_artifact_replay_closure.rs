use std::fs;

use aiaf_v1::execution::{
    AuditRecord, AuditRecordClass, CapabilityImportTarget, DurableArtifactStore,
    ExecutionSessionState, MemoryArtifact, MemoryStore, NativeReplacementTier,
    NativeSufficiencyGate, PromotionReadinessStatus, ShadowCampaignStatus, ShadowEvaluationBundle,
    TaskGraph, TaskState, build_native_sufficiency_evidence, compare_challenger_outputs,
    create_rollback_handle, decide_promotion_readiness, open_challenger_evaluation_session,
    open_shadow_campaign,
};

use crate::hardening_support::{
    append_named_related_audit, checkpoint, full_closure_inventory, persist_checkpoint_lineage,
    ready_session, root_pointer_index, root_task, runtime_state_with_checkpoint,
    supervisor_dimension_scores, temp_store_root,
};

fn completed_state(
    session_id: &str,
    actor_id: &str,
    task_id: &str,
    checkpoint_id: &str,
    output_ref: &str,
) -> aiaf_v1::execution::ReplayableRuntimeState {
    let mut session = ready_session(session_id, "campaign-shadow", "epoch-1", "envelope-root");
    session.header.actor_id = actor_id.to_string();
    session.state = ExecutionSessionState::Completed;

    let mut task = root_task(task_id, "bounded shadow control run");
    task.state = TaskState::Completed;
    task.owner_session_id = Some(session.header.session_id.clone());
    task.record_output_ref(output_ref);

    let mut memory_store = MemoryStore::default();
    memory_store.insert_pointer_index(root_pointer_index(
        "pointer-index-shadow",
        &session.header.campaign_id,
        &task.task_id,
    ));
    let checkpoint = checkpoint(
        checkpoint_id,
        &session,
        Some(&task),
        vec!["pointer-index-shadow".to_string()],
        Vec::new(),
    );
    persist_checkpoint_lineage(
        &mut memory_store,
        &checkpoint,
        checkpoint_id,
        "shadow checkpoint remained reconstructable",
    );

    runtime_state_with_checkpoint(
        session,
        task,
        TaskGraph::new(task_id, Vec::new()),
        memory_store,
        checkpoint,
        &format!("event-{session_id}"),
        "bounded shadow checkpoint captured",
    )
}

#[test]
fn supervisor_native_control_artifact_replay_closure_acceptance() {
    let root = temp_store_root("native-control-artifact-replay-closure");
    let _ = fs::remove_dir_all(&root);
    let store = DurableArtifactStore::bootstrap(&root).unwrap();

    let shared_input_refs = vec![
        "campaign-brief-shadow".to_string(),
        "pointer-index-shadow".to_string(),
    ];
    let incumbent_runtime_state = completed_state(
        "session-incumbent-shadow",
        "supervisor-incumbent",
        "task-incumbent-shadow",
        "checkpoint-incumbent-shadow",
        "incumbent-output-shadow",
    );
    let mut challenger_runtime_state = completed_state(
        "session-challenger-shadow",
        "supervisor-challenger",
        "task-challenger-shadow",
        "checkpoint-challenger-shadow",
        "challenger-output-shadow",
    );

    let mut shadow_campaign = open_shadow_campaign(
        "shadow-campaign-v1-2",
        "campaign-shadow",
        incumbent_runtime_state.session.header.session_id.clone(),
        challenger_runtime_state.session.header.session_id.clone(),
        shared_input_refs.clone(),
        vec![aiaf_v1::execution::TickSource::ApprovalResponse],
        vec![
            CapabilityImportTarget::CampaignControl,
            CapabilityImportTarget::ApprovalGateway,
            CapabilityImportTarget::ReviewPromotion,
        ],
        true,
        "rollback-shadow-v1-2",
    )
    .unwrap();
    shadow_campaign.status = ShadowCampaignStatus::DecisionReady;

    let mut evaluation_session = open_challenger_evaluation_session(
        "evaluation-shadow-v1-2",
        &shadow_campaign,
        &shared_input_refs,
        &shared_input_refs,
        vec![
            "envelope-campaign-control".to_string(),
            "envelope-review-promotion".to_string(),
        ],
    )
    .unwrap();
    evaluation_session.latest_challenger_checkpoint_ref =
        Some("checkpoint-challenger-shadow".to_string());

    let comparison = compare_challenger_outputs(
        "comparison-shadow-v1-2",
        incumbent_runtime_state.session.header.session_id.clone(),
        challenger_runtime_state.session.header.session_id.clone(),
        shared_input_refs.clone(),
        incumbent_runtime_state.root_task.output_refs.clone(),
        challenger_runtime_state.root_task.output_refs.clone(),
        supervisor_dimension_scores("incumbent", "challenger"),
        "native shadow comparison remained explicit and replayable",
    )
    .unwrap();
    challenger_runtime_state
        .memory_store
        .append(MemoryArtifact::audit_record(
            "memory-audit-comparison-shadow-v1-2",
            AuditRecord::new(
                "audit-comparison-shadow-v1-2",
                AuditRecordClass::GovernanceAuditRecord,
                challenger_runtime_state.session.header.campaign_id.clone(),
                challenger_runtime_state.session.header.epoch_id.clone(),
                challenger_runtime_state.session.header.session_id.clone(),
                Some(challenger_runtime_state.root_task.task_id.clone()),
                comparison.comparison_id.clone(),
                "native shadow comparison remained reconstructable",
            ),
        ));

    let sufficiency_evidence = build_native_sufficiency_evidence(
        "evidence-shadow-v1-2",
        CapabilityImportTarget::NativeSupervisorChallenger,
        NativeReplacementTier::NativeSupervisorChallengers,
        vec![
            "review-artifact-shadow-v1-2".to_string(),
            comparison.comparison_id.clone(),
        ],
        vec!["checkpoint-challenger-shadow".to_string()],
        vec!["audit-comparison-shadow-v1-2".to_string()],
        "native control evidence remained explicit and replayable",
        true,
    );
    challenger_runtime_state
        .memory_store
        .append(MemoryArtifact::audit_record(
            "memory-audit-evidence-shadow-v1-2",
            AuditRecord::new(
                "audit-evidence-shadow-v1-2",
                AuditRecordClass::PromotionAuditRecord,
                challenger_runtime_state.session.header.campaign_id.clone(),
                challenger_runtime_state.session.header.epoch_id.clone(),
                challenger_runtime_state.session.header.session_id.clone(),
                Some(challenger_runtime_state.root_task.task_id.clone()),
                sufficiency_evidence.evidence_id.clone(),
                "native sufficiency evidence remained reconstructable",
            ),
        ));
    append_named_related_audit(
        &mut challenger_runtime_state.memory_store,
        &challenger_runtime_state.session,
        Some(&challenger_runtime_state.root_task.task_id),
        "review-artifact-shadow-v1-2",
        "audit-review-artifact-shadow-v1-2",
        AuditRecordClass::GovernanceAuditRecord,
        "shadow review artifact remained reconstructable",
    );

    let readiness = decide_promotion_readiness(
        "promotion-readiness-shadow-v1-2",
        &comparison,
        &NativeSufficiencyGate {
            target: CapabilityImportTarget::NativeSupervisorChallenger,
            required_tier: NativeReplacementTier::NativeSupervisorChallengers,
            requires_exact_match: true,
        },
        &sufficiency_evidence,
        &[create_rollback_handle(
            "rollback-shadow-v1-2",
            "shadow-campaign-v1-2",
            "checkpoint-incumbent-shadow",
            vec!["restore checkpoint-incumbent-shadow".to_string()],
            Vec::new(),
        )],
        &["review-artifact-shadow-v1-2".to_string()],
        &[],
    );
    assert_eq!(readiness.status, PromotionReadinessStatus::Promotable);

    let bundle = ShadowEvaluationBundle {
        shadow_campaign,
        challenger_evaluation_session: evaluation_session,
        incumbent_runtime_state,
        challenger_runtime_state: challenger_runtime_state.clone(),
        comparison_record: comparison.clone(),
        sufficiency_evidence: sufficiency_evidence.clone(),
        promotion_readiness_decision: readiness,
    };
    store.persist_shadow_evaluation_bundle(&bundle).unwrap();
    let reloaded = store
        .load_shadow_evaluation_bundle("shadow-campaign-v1-2")
        .unwrap();

    assert_eq!(reloaded, bundle);
    assert!(
        reloaded
            .challenger_runtime_state
            .memory_store
            .checkpoint_lineage("checkpoint-challenger-shadow")
            .len()
            >= 2
    );
    assert!(
        reloaded
            .challenger_runtime_state
            .memory_store
            .artifacts_for_related_ref("comparison-shadow-v1-2")
            .iter()
            .any(|artifact| artifact.class
                == aiaf_v1::execution::MemoryArtifactClass::AuditRecordArtifact)
    );
    assert!(
        full_closure_inventory("closure-v1-2-shadow")
            .entries
            .iter()
            .any(|entry| entry.target == CapabilityImportTarget::NativeSupervisorChallenger)
    );
}
