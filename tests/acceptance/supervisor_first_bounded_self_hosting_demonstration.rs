use std::fs;

use aiaf_v1::execution::{
    AuditRecord, AuditRecordClass, CapabilityImportTarget, CycleClosureDecisionStatus,
    DurableArtifactStore, ExecutionSessionState, MemoryArtifact, MemoryStore,
    NativeReplacementTier, NativeSufficiencyGate, PromotionActStatus, PromotionActivationBundle,
    PromotionReadinessStatus, ReplayableRuntimeState, ReversalWindowStatus, ShadowCampaignStatus,
    ShadowEvaluationBundle, TaskGraph, TaskState, V1CompletionBundle, V1CompletionStatus,
    build_native_sufficiency_evidence, build_successor_genome, compare_challenger_outputs,
    compare_successor_loop_outputs, create_rollback_handle, decide_cycle_closure,
    decide_promotion_readiness, evaluate_v1_completion_gate, materialize_successor_phenotype,
    open_challenger_evaluation_session, open_promotion_act, open_reversal_window,
    open_shadow_campaign, plan_epoch_adoption, validate_semantic_phenotype,
};

use crate::hardening_support::{
    append_inventory_audits, append_named_related_audit, append_v14_program_evidence, checkpoint,
    full_closure_inventory, persist_checkpoint_lineage, ready_session, root_pointer_index,
    root_task, runtime_state_with_checkpoint, supervisor_dimension_scores, temp_store_root,
};

fn completed_state(
    session_id: &str,
    campaign_id: &str,
    epoch_id: &str,
    task_id: &str,
    checkpoint_id: &str,
    output_ref: &str,
) -> ReplayableRuntimeState {
    let mut session = ready_session(session_id, campaign_id, epoch_id, "envelope-root");
    session.state = ExecutionSessionState::Completed;

    let mut task = root_task(task_id, "bounded self-hosting control slice");
    task.state = TaskState::Completed;
    task.owner_session_id = Some(session.header.session_id.clone());
    task.record_output_ref(output_ref);

    let mut memory_store = MemoryStore::default();
    memory_store.insert_pointer_index(root_pointer_index(
        "pointer-index-self-hosting",
        &session.header.campaign_id,
        &task.task_id,
    ));
    let checkpoint = checkpoint(
        checkpoint_id,
        &session,
        Some(&task),
        vec!["pointer-index-self-hosting".to_string()],
        Vec::new(),
    );
    persist_checkpoint_lineage(
        &mut memory_store,
        &checkpoint,
        checkpoint_id,
        "self-hosting checkpoint remained reconstructable",
    );

    runtime_state_with_checkpoint(
        session,
        task,
        TaskGraph::new(task_id, Vec::new()),
        memory_store,
        checkpoint,
        &format!("event-{session_id}"),
        "self-hosting checkpoint captured",
    )
}

#[test]
fn supervisor_first_bounded_self_hosting_demonstration_acceptance() {
    let root = temp_store_root("first-bounded-self-hosting-demonstration");
    let _ = fs::remove_dir_all(&root);
    let store = DurableArtifactStore::bootstrap(&root).unwrap();

    let shared_input_refs = vec![
        "campaign-brief-self-hosting".to_string(),
        "pointer-index-self-hosting".to_string(),
    ];
    let incumbent_state = completed_state(
        "session-incumbent",
        "campaign-shadow",
        "epoch-1",
        "task-incumbent",
        "checkpoint-incumbent",
        "incumbent-output-1",
    );
    let mut challenger_state = completed_state(
        "session-challenger",
        "campaign-shadow",
        "epoch-1",
        "task-challenger",
        "checkpoint-challenger",
        "challenger-output-1",
    );

    let shadow_comparison = compare_challenger_outputs(
        "comparison-shadow-self-hosting",
        incumbent_state.session.header.session_id.clone(),
        challenger_state.session.header.session_id.clone(),
        shared_input_refs.clone(),
        incumbent_state.root_task.output_refs.clone(),
        challenger_state.root_task.output_refs.clone(),
        supervisor_dimension_scores("incumbent", "challenger"),
        "native supervisor challenger remained promotable under fixed interfaces",
    )
    .unwrap();
    challenger_state
        .memory_store
        .append(MemoryArtifact::audit_record(
            "memory-audit-shadow-self-hosting-comparison",
            AuditRecord::new(
                "audit-shadow-self-hosting-comparison",
                AuditRecordClass::GovernanceAuditRecord,
                challenger_state.session.header.campaign_id.clone(),
                challenger_state.session.header.epoch_id.clone(),
                challenger_state.session.header.session_id.clone(),
                Some(challenger_state.root_task.task_id.clone()),
                shadow_comparison.comparison_id.clone(),
                "shadow comparison remained reconstructable",
            ),
        ));
    let shadow_evidence = build_native_sufficiency_evidence(
        "evidence-shadow-self-hosting",
        CapabilityImportTarget::NativeSupervisorChallenger,
        NativeReplacementTier::NativeSupervisorChallengers,
        vec!["review-artifact-shadow".to_string()],
        vec!["checkpoint-challenger".to_string()],
        vec!["audit-shadow-self-hosting-comparison".to_string()],
        "shadow challenger evidence remained reconstructable",
        true,
    );
    challenger_state
        .memory_store
        .append(MemoryArtifact::audit_record(
            "memory-audit-shadow-self-hosting-evidence",
            AuditRecord::new(
                "audit-shadow-self-hosting-evidence",
                AuditRecordClass::PromotionAuditRecord,
                challenger_state.session.header.campaign_id.clone(),
                challenger_state.session.header.epoch_id.clone(),
                challenger_state.session.header.session_id.clone(),
                Some(challenger_state.root_task.task_id.clone()),
                shadow_evidence.evidence_id.clone(),
                "shadow evidence remained reconstructable",
            ),
        ));
    append_named_related_audit(
        &mut challenger_state.memory_store,
        &challenger_state.session,
        Some(&challenger_state.root_task.task_id),
        "review-artifact-shadow",
        "audit-review-artifact-shadow",
        AuditRecordClass::GovernanceAuditRecord,
        "shadow review artifact remained reconstructable",
    );

    let mut shadow_campaign = open_shadow_campaign(
        "shadow-campaign-self-hosting",
        "campaign-shadow",
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
        "rollback-self-hosting",
    )
    .unwrap();
    shadow_campaign.status = ShadowCampaignStatus::DecisionReady;
    let evaluation_session = open_challenger_evaluation_session(
        "evaluation-self-hosting",
        &shadow_campaign,
        &shared_input_refs,
        &shared_input_refs,
        vec!["envelope-review".to_string()],
    )
    .unwrap();
    let rollback_handle = create_rollback_handle(
        "rollback-self-hosting",
        "shadow-campaign-self-hosting",
        "checkpoint-incumbent",
        vec!["restore checkpoint-incumbent".to_string()],
        Vec::new(),
    );
    let shadow_readiness = decide_promotion_readiness(
        "promotion-readiness-self-hosting",
        &shadow_comparison,
        &NativeSufficiencyGate {
            target: CapabilityImportTarget::NativeSupervisorChallenger,
            required_tier: NativeReplacementTier::NativeSupervisorChallengers,
            requires_exact_match: true,
        },
        &shadow_evidence,
        std::slice::from_ref(&rollback_handle),
        &["review-artifact-shadow".to_string()],
        &[],
    );
    assert_eq!(
        shadow_readiness.status,
        PromotionReadinessStatus::Promotable
    );

    let shadow_bundle = ShadowEvaluationBundle {
        shadow_campaign,
        challenger_evaluation_session: evaluation_session,
        incumbent_runtime_state: incumbent_state.clone(),
        challenger_runtime_state: challenger_state.clone(),
        comparison_record: shadow_comparison.clone(),
        sufficiency_evidence: shadow_evidence.clone(),
        promotion_readiness_decision: shadow_readiness.clone(),
    };
    store
        .persist_shadow_evaluation_bundle(&shadow_bundle)
        .unwrap();

    let mut promotion_act = open_promotion_act(
        "promotion-act-self-hosting",
        &shadow_readiness,
        &shadow_comparison,
        "epoch-1",
        "epoch-2",
        "campaign-successor-1",
        vec![shadow_comparison.comparison_id.clone()],
    )
    .unwrap();
    let mut adoption = plan_epoch_adoption(
        "adoption-self-hosting",
        &promotion_act,
        incumbent_state.session.header.session_id.clone(),
        challenger_state.session.header.session_id.clone(),
        "session-promoted",
        vec!["review-artifact-shadow".to_string()],
        "bounded epoch adoption planned",
    );
    let reversal_window = open_reversal_window(
        "reversal-window-self-hosting",
        &promotion_act,
        std::slice::from_ref(&rollback_handle),
        &[],
        "bounded reversal window opened",
    )
    .unwrap();
    assert_eq!(reversal_window.status, ReversalWindowStatus::Open);

    let mut promoted_state = completed_state(
        "session-promoted",
        "campaign-successor-1",
        "epoch-2",
        "task-promoted",
        "checkpoint-promoted",
        "promoted-output-1",
    );
    for (related_ref, class, summary) in [
        (
            "promotion-act-self-hosting",
            AuditRecordClass::PromotionAuditRecord,
            "promotion act remained reconstructable",
        ),
        (
            "adoption-self-hosting",
            AuditRecordClass::PromotionAuditRecord,
            "epoch adoption remained reconstructable",
        ),
        (
            "reversal-window-self-hosting",
            AuditRecordClass::GovernanceAuditRecord,
            "reversal window remained reconstructable",
        ),
    ] {
        promoted_state
            .memory_store
            .append(MemoryArtifact::audit_record(
                format!("memory-audit-{related_ref}"),
                AuditRecord::new(
                    format!("audit-{related_ref}"),
                    class,
                    promoted_state.session.header.campaign_id.clone(),
                    promoted_state.session.header.epoch_id.clone(),
                    promoted_state.session.header.session_id.clone(),
                    Some(promoted_state.root_task.task_id.clone()),
                    related_ref.to_string(),
                    summary,
                ),
            ));
    }
    aiaf_v1::execution::mark_promotion_activated(&mut promotion_act);
    aiaf_v1::execution::mark_epoch_adoption_active(
        &mut adoption,
        "checkpoint-promoted".to_string(),
    );
    append_named_related_audit(
        &mut promoted_state.memory_store,
        &promoted_state.session,
        Some(&promoted_state.root_task.task_id),
        &promotion_act.promotion_act_id,
        "audit-promotion-act-self-hosting",
        AuditRecordClass::PromotionAuditRecord,
        "promotion act remained reconstructable",
    );
    append_named_related_audit(
        &mut promoted_state.memory_store,
        &promoted_state.session,
        Some(&promoted_state.root_task.task_id),
        &adoption.adoption_id,
        "audit-adoption-self-hosting",
        AuditRecordClass::PromotionAuditRecord,
        "epoch adoption remained reconstructable",
    );
    append_named_related_audit(
        &mut promoted_state.memory_store,
        &promoted_state.session,
        Some(&promoted_state.root_task.task_id),
        &reversal_window.reversal_window_id,
        "audit-reversal-window-self-hosting",
        AuditRecordClass::GovernanceAuditRecord,
        "reversal window remained reconstructable",
    );
    append_named_related_audit(
        &mut promoted_state.memory_store,
        &promoted_state.session,
        Some(&promoted_state.root_task.task_id),
        "review-artifact-shadow",
        "audit-review-artifact-shadow-promoted",
        AuditRecordClass::GovernanceAuditRecord,
        "shadow review artifact remained reconstructable through epoch handoff",
    );
    append_v14_program_evidence(
        &mut promoted_state.memory_store,
        &promoted_state.session,
        Some(&promoted_state.root_task.task_id),
        "first-self-hosting",
        &promotion_act.review_artifact_refs,
    );

    let successor_loop_comparison = compare_successor_loop_outputs(
        "comparison-loop-self-hosting",
        promoted_state.session.header.session_id.clone(),
        "successor-candidate-1",
        shared_input_refs.clone(),
        promoted_state.root_task.output_refs.clone(),
        vec!["successor-output-1".to_string()],
        supervisor_dimension_scores("promoted incumbent", "successor candidate"),
        "bounded self-hosting loop remained governed",
    )
    .unwrap();
    let successor_loop_evidence = build_native_sufficiency_evidence(
        "evidence-loop-self-hosting",
        CapabilityImportTarget::NativeSupervisorChallenger,
        NativeReplacementTier::BoundedSelfHostingLoop,
        vec!["successor-output-1".to_string()],
        vec!["checkpoint-promoted".to_string()],
        vec!["audit-loop-self-hosting".to_string()],
        "bounded self-hosting loop evidence remained reconstructable",
        true,
    );
    append_named_related_audit(
        &mut promoted_state.memory_store,
        &promoted_state.session,
        Some(&promoted_state.root_task.task_id),
        &successor_loop_evidence.evidence_id,
        "audit-loop-self-hosting",
        AuditRecordClass::PromotionAuditRecord,
        "bounded self-hosting loop audit remained reconstructable",
    );
    for (related_ref, class, summary) in [
        (
            successor_loop_comparison.comparison_id.clone(),
            AuditRecordClass::GovernanceAuditRecord,
            "successor loop comparison remained reconstructable",
        ),
        (
            successor_loop_evidence.evidence_id.clone(),
            AuditRecordClass::PromotionAuditRecord,
            "successor loop evidence remained reconstructable",
        ),
    ] {
        promoted_state
            .memory_store
            .append(MemoryArtifact::audit_record(
                format!("memory-audit-{related_ref}"),
                AuditRecord::new(
                    format!("audit-{related_ref}"),
                    class,
                    promoted_state.session.header.campaign_id.clone(),
                    promoted_state.session.header.epoch_id.clone(),
                    promoted_state.session.header.session_id.clone(),
                    Some(promoted_state.root_task.task_id.clone()),
                    related_ref,
                    summary,
                ),
            ));
    }

    let genome = build_successor_genome(
        "genome-self-hosting",
        promoted_state.session.header.session_id.clone(),
        "package:aiaf/supervisor@v1",
        "typed-dag:self-hosting",
        vec!["policy:bounded".to_string()],
        "first bounded self-hosting genome",
    )
    .unwrap();
    let phenotype = materialize_successor_phenotype(
        "phenotype-self-hosting",
        &genome,
        "package:aiaf/supervisor@v1",
        "component:phenotype-self-hosting",
        vec!["wit:supervisor".to_string()],
        vec!["successor-output-2".to_string()],
        "first bounded self-hosting phenotype",
    )
    .unwrap();
    let semantic_validation = validate_semantic_phenotype(
        "validation-self-hosting",
        &genome,
        &phenotype,
        vec!["validator:semantic-check".to_string()],
        vec!["evidence:semantic-check".to_string()],
        "first bounded self-hosting validation passed",
    )
    .unwrap();
    let second_cycle_comparison = compare_successor_loop_outputs(
        "comparison-cycle-2-self-hosting",
        promoted_state.session.header.session_id.clone(),
        phenotype.artifact_id.clone(),
        shared_input_refs.clone(),
        promoted_state.root_task.output_refs.clone(),
        phenotype.output_refs.clone(),
        supervisor_dimension_scores("promoted incumbent", "successor phenotype"),
        "second bounded cycle remained governed under fixed interfaces",
    )
    .unwrap();
    let second_cycle_evidence = build_native_sufficiency_evidence(
        "evidence-cycle-2-self-hosting",
        CapabilityImportTarget::NativeSupervisorChallenger,
        NativeReplacementTier::BoundedSelfHostingLoop,
        vec![
            genome.genome_id.clone(),
            phenotype.artifact_id.clone(),
            semantic_validation.validation_id.clone(),
        ],
        vec!["checkpoint-promoted".to_string()],
        vec!["audit-cycle-2-self-hosting".to_string()],
        "second-cycle evidence remained reconstructable",
        true,
    );
    append_named_related_audit(
        &mut promoted_state.memory_store,
        &promoted_state.session,
        Some(&promoted_state.root_task.task_id),
        "review-artifact-cycle-2",
        "audit-review-artifact-cycle-2",
        AuditRecordClass::GovernanceAuditRecord,
        "second-cycle review artifact remained reconstructable",
    );
    append_named_related_audit(
        &mut promoted_state.memory_store,
        &promoted_state.session,
        Some(&promoted_state.root_task.task_id),
        &second_cycle_evidence.evidence_id,
        "audit-cycle-2-self-hosting",
        AuditRecordClass::PromotionAuditRecord,
        "second-cycle audit evidence remained reconstructable",
    );
    let second_cycle_readiness = decide_promotion_readiness(
        "promotion-readiness-cycle-2-self-hosting",
        &second_cycle_comparison,
        &NativeSufficiencyGate {
            target: CapabilityImportTarget::NativeSupervisorChallenger,
            required_tier: NativeReplacementTier::BoundedSelfHostingLoop,
            requires_exact_match: true,
        },
        &second_cycle_evidence,
        std::slice::from_ref(&rollback_handle),
        &["review-artifact-cycle-2".to_string()],
        &[],
    );
    let second_cycle_decision = decide_cycle_closure(
        "cycle-closure-self-hosting",
        &second_cycle_readiness,
        &second_cycle_comparison,
        std::slice::from_ref(&rollback_handle),
        &[],
    );
    assert_eq!(
        second_cycle_decision.status,
        CycleClosureDecisionStatus::Promote
    );
    let closure_inventory = full_closure_inventory("closure-self-hosting");
    append_inventory_audits(
        &mut promoted_state.memory_store,
        &promoted_state.session,
        Some(&promoted_state.root_task.task_id),
        &closure_inventory,
    );

    let promotion_bundle = PromotionActivationBundle {
        shadow_evaluation_bundle: shadow_bundle,
        promotion_act: promotion_act.clone(),
        epoch_adoption_record: adoption.clone(),
        reversal_window,
        promoted_runtime_state: promoted_state.clone(),
        successor_loop_comparison: successor_loop_comparison.clone(),
        successor_loop_evidence: successor_loop_evidence.clone(),
    };
    store
        .persist_promotion_activation_bundle(&promotion_bundle)
        .unwrap();

    let v1_completion_gate = evaluate_v1_completion_gate(
        "v1-gate-self-hosting",
        &closure_inventory,
        &semantic_validation,
        &second_cycle_decision,
    );
    assert_eq!(v1_completion_gate.status, V1CompletionStatus::Satisfied);

    let completion_bundle = V1CompletionBundle {
        promotion_activation_bundle: promotion_bundle,
        closure_inventory,
        successor_genome: genome.clone(),
        successor_phenotype: phenotype.clone(),
        semantic_validation_record: semantic_validation,
        second_cycle_comparison,
        second_cycle_evidence,
        second_cycle_readiness,
        second_cycle_decision,
        second_cycle_promotion_act: None,
        v1_completion_gate: v1_completion_gate.clone(),
    };
    store
        .persist_v1_completion_bundle(&completion_bundle)
        .unwrap();
    let reloaded = store
        .load_v1_completion_bundle("v1-gate-self-hosting")
        .unwrap();

    assert_eq!(reloaded, completion_bundle);
    assert_eq!(
        reloaded.successor_genome.stable_interface_ref,
        "package:aiaf/supervisor@v1"
    );
    assert_eq!(
        reloaded.successor_phenotype.stable_interface_ref,
        "package:aiaf/supervisor@v1"
    );
    assert_eq!(promotion_act.status, PromotionActStatus::Activated);
}
