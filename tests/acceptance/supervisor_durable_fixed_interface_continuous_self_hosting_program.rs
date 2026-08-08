use std::fs;

use aiaf_v1::execution::{
    CycleClosureDecisionStatus, DurableArtifactStore, NativeReplacementTier, NativeSufficiencyGate,
    PromotionActivationBundle, PromotionReadinessStatus, ShadowCampaignStatus,
    ShadowEvaluationBundle, V1CompletionBundle, V1CompletionStatus,
    build_native_sufficiency_evidence, build_successor_genome, compare_challenger_outputs,
    compare_successor_loop_outputs, create_rollback_handle, decide_cycle_closure,
    decide_promotion_readiness, evaluate_v1_completion_gate, mark_epoch_adoption_active,
    mark_promotion_activated, materialize_successor_phenotype, open_challenger_evaluation_session,
    open_promotion_act, open_reversal_window, open_shadow_campaign, plan_epoch_adoption,
    validate_semantic_phenotype,
};

use crate::hardening_support::{
    append_inventory_audits, append_named_related_audit, append_v14_program_evidence,
    completed_runtime_state, full_closure_inventory, supervisor_dimension_scores, temp_store_root,
};

#[test]
fn supervisor_durable_fixed_interface_continuous_self_hosting_program_acceptance() {
    let root = temp_store_root("durable-fixed-interface-continuous-self-hosting-program");
    let _ = fs::remove_dir_all(&root);
    let store = DurableArtifactStore::bootstrap(&root).unwrap();

    let shared_input_refs = vec![
        "service:memory".to_string(),
        "service:governance".to_string(),
        "service:capability-broker".to_string(),
    ];
    let incumbent_state = completed_runtime_state(
        "session-continuous-incumbent",
        "campaign-continuous",
        "epoch-1",
        "task-continuous-incumbent",
        "checkpoint-continuous-incumbent",
        vec!["incumbent-output-continuous".to_string()],
        "continuous incumbent checkpoint captured",
    );
    let mut challenger_state = completed_runtime_state(
        "session-continuous-challenger",
        "campaign-continuous",
        "epoch-1",
        "task-continuous-challenger",
        "checkpoint-continuous-challenger",
        vec!["challenger-output-continuous".to_string()],
        "continuous challenger checkpoint captured",
    );
    let closure_inventory = full_closure_inventory("closure-continuous-program");
    append_inventory_audits(
        &mut challenger_state.memory_store,
        &challenger_state.session,
        Some(&challenger_state.root_task.task_id),
        &closure_inventory,
    );
    append_named_related_audit(
        &mut challenger_state.memory_store,
        &challenger_state.session,
        Some(&challenger_state.root_task.task_id),
        "review-artifact-shadow-continuous-1",
        "audit-review-artifact-shadow-continuous-1",
        aiaf_v1::execution::AuditRecordClass::GovernanceAuditRecord,
        "continuous program shadow review artifact remained reconstructable",
    );

    let shadow_comparison = compare_challenger_outputs(
        "comparison-shadow-continuous-1",
        incumbent_state.session.header.session_id.clone(),
        challenger_state.session.header.session_id.clone(),
        shared_input_refs.clone(),
        incumbent_state.root_task.output_refs.clone(),
        challenger_state.root_task.output_refs.clone(),
        supervisor_dimension_scores("continuous incumbent", "continuous challenger"),
        "continuous challenger remained promotable under fixed interfaces",
    )
    .unwrap();
    append_named_related_audit(
        &mut challenger_state.memory_store,
        &challenger_state.session,
        Some(&challenger_state.root_task.task_id),
        &shadow_comparison.comparison_id,
        "audit-shadow-continuous-comparison-1",
        aiaf_v1::execution::AuditRecordClass::GovernanceAuditRecord,
        "continuous shadow comparison remained reconstructable",
    );
    let shadow_evidence = build_native_sufficiency_evidence(
        "evidence-shadow-continuous-1",
        aiaf_v1::execution::CapabilityImportTarget::NativeSupervisorChallenger,
        NativeReplacementTier::NativeSupervisorChallengers,
        vec!["review-artifact-shadow-continuous-1".to_string()],
        vec!["checkpoint-continuous-challenger".to_string()],
        vec!["audit-shadow-continuous-comparison-1".to_string()],
        "continuous shadow evidence remained reconstructable",
        true,
    );
    append_named_related_audit(
        &mut challenger_state.memory_store,
        &challenger_state.session,
        Some(&challenger_state.root_task.task_id),
        &shadow_evidence.evidence_id,
        "audit-shadow-continuous-evidence-1",
        aiaf_v1::execution::AuditRecordClass::PromotionAuditRecord,
        "continuous shadow evidence remained reconstructable",
    );
    let rollback_handle = create_rollback_handle(
        "rollback-continuous-1",
        "campaign-continuous",
        "checkpoint-continuous-incumbent",
        vec!["restore checkpoint-continuous-incumbent".to_string()],
        Vec::new(),
    );
    let mut shadow_campaign = open_shadow_campaign(
        "shadow-campaign-continuous-1",
        "campaign-continuous",
        incumbent_state.session.header.session_id.clone(),
        challenger_state.session.header.session_id.clone(),
        shared_input_refs.clone(),
        vec![aiaf_v1::execution::TickSource::ApprovalResponse],
        vec![
            aiaf_v1::execution::CapabilityImportTarget::CampaignControl,
            aiaf_v1::execution::CapabilityImportTarget::ApprovalGateway,
            aiaf_v1::execution::CapabilityImportTarget::ReviewPromotion,
        ],
        true,
        "rollback-continuous-1",
    )
    .unwrap();
    shadow_campaign.status = ShadowCampaignStatus::DecisionReady;
    let evaluation_session = open_challenger_evaluation_session(
        "evaluation-continuous-1",
        &shadow_campaign,
        &shared_input_refs,
        &shared_input_refs,
        vec!["envelope-continuous-review".to_string()],
    )
    .unwrap();
    let shadow_readiness = decide_promotion_readiness(
        "promotion-readiness-continuous-1",
        &shadow_comparison,
        &NativeSufficiencyGate {
            target: aiaf_v1::execution::CapabilityImportTarget::NativeSupervisorChallenger,
            required_tier: NativeReplacementTier::NativeSupervisorChallengers,
            requires_exact_match: true,
        },
        &shadow_evidence,
        std::slice::from_ref(&rollback_handle),
        &["review-artifact-shadow-continuous-1".to_string()],
        &[],
    );
    assert_eq!(
        shadow_readiness.status,
        PromotionReadinessStatus::Promotable
    );

    let shadow_bundle = ShadowEvaluationBundle {
        shadow_campaign,
        challenger_evaluation_session: evaluation_session,
        incumbent_runtime_state: incumbent_state,
        challenger_runtime_state: challenger_state,
        comparison_record: shadow_comparison.clone(),
        sufficiency_evidence: shadow_evidence,
        promotion_readiness_decision: shadow_readiness.clone(),
    };
    store
        .persist_shadow_evaluation_bundle(&shadow_bundle)
        .unwrap();

    let mut promotion_act = open_promotion_act(
        "promotion-act-continuous-1",
        &shadow_readiness,
        &shadow_comparison,
        "epoch-1",
        "epoch-2",
        "campaign-continuous-successor",
        vec![shadow_comparison.comparison_id.clone()],
    )
    .unwrap();
    let mut adoption = plan_epoch_adoption(
        "adoption-continuous-1",
        &promotion_act,
        "session-continuous-incumbent",
        "session-continuous-challenger",
        "session-continuous-promoted",
        vec!["review-artifact-shadow-continuous-1".to_string()],
        "continuous epoch adoption planned",
    );
    let reversal_window = open_reversal_window(
        "reversal-window-continuous-1",
        &promotion_act,
        std::slice::from_ref(&rollback_handle),
        &[],
        "continuous reversal window opened",
    )
    .unwrap();
    let mut promoted_state = completed_runtime_state(
        "session-continuous-promoted",
        "campaign-continuous-successor",
        "epoch-2",
        "task-continuous-promoted",
        "checkpoint-continuous-promoted",
        vec!["successor-output-continuous-1".to_string()],
        "continuous promoted checkpoint captured",
    );
    append_inventory_audits(
        &mut promoted_state.memory_store,
        &promoted_state.session,
        Some(&promoted_state.root_task.task_id),
        &closure_inventory,
    );
    append_named_related_audit(
        &mut promoted_state.memory_store,
        &promoted_state.session,
        Some(&promoted_state.root_task.task_id),
        "review-artifact-shadow-continuous-1",
        "audit-review-artifact-shadow-continuous-promoted-1",
        aiaf_v1::execution::AuditRecordClass::GovernanceAuditRecord,
        "continuous shadow review artifact remained reconstructable through promotion",
    );
    append_named_related_audit(
        &mut promoted_state.memory_store,
        &promoted_state.session,
        Some(&promoted_state.root_task.task_id),
        &promotion_act.promotion_act_id,
        "audit-promotion-act-continuous-1",
        aiaf_v1::execution::AuditRecordClass::PromotionAuditRecord,
        "continuous promotion act remained reconstructable",
    );
    append_named_related_audit(
        &mut promoted_state.memory_store,
        &promoted_state.session,
        Some(&promoted_state.root_task.task_id),
        &adoption.adoption_id,
        "audit-adoption-continuous-1",
        aiaf_v1::execution::AuditRecordClass::PromotionAuditRecord,
        "continuous adoption remained reconstructable",
    );
    append_named_related_audit(
        &mut promoted_state.memory_store,
        &promoted_state.session,
        Some(&promoted_state.root_task.task_id),
        &reversal_window.reversal_window_id,
        "audit-reversal-window-continuous-1",
        aiaf_v1::execution::AuditRecordClass::GovernanceAuditRecord,
        "continuous reversal window remained reconstructable",
    );
    append_v14_program_evidence(
        &mut promoted_state.memory_store,
        &promoted_state.session,
        Some(&promoted_state.root_task.task_id),
        "continuous-program-1",
        &promotion_act.review_artifact_refs,
    );
    mark_promotion_activated(&mut promotion_act);
    mark_epoch_adoption_active(&mut adoption, "checkpoint-continuous-promoted".to_string());

    let successor_loop_comparison = compare_successor_loop_outputs(
        "comparison-successor-loop-continuous-1",
        promoted_state.session.header.session_id.clone(),
        "continuous-successor-candidate",
        shared_input_refs.clone(),
        promoted_state.root_task.output_refs.clone(),
        vec!["successor-output-continuous-2".to_string()],
        supervisor_dimension_scores("continuous promoted", "continuous successor candidate"),
        "continuous successor loop remained governed",
    )
    .unwrap();
    let successor_loop_evidence = build_native_sufficiency_evidence(
        "evidence-successor-loop-continuous-1",
        aiaf_v1::execution::CapabilityImportTarget::NativeSupervisorChallenger,
        NativeReplacementTier::BoundedSelfHostingLoop,
        vec!["successor-output-continuous-2".to_string()],
        vec!["checkpoint-continuous-promoted".to_string()],
        vec!["audit-successor-loop-continuous-1".to_string()],
        "continuous successor loop evidence remained reconstructable",
        true,
    );
    append_named_related_audit(
        &mut promoted_state.memory_store,
        &promoted_state.session,
        Some(&promoted_state.root_task.task_id),
        &successor_loop_comparison.comparison_id,
        "audit-successor-loop-comparison-continuous-1",
        aiaf_v1::execution::AuditRecordClass::GovernanceAuditRecord,
        "continuous successor loop comparison remained reconstructable",
    );
    append_named_related_audit(
        &mut promoted_state.memory_store,
        &promoted_state.session,
        Some(&promoted_state.root_task.task_id),
        &successor_loop_evidence.evidence_id,
        "audit-successor-loop-continuous-1",
        aiaf_v1::execution::AuditRecordClass::PromotionAuditRecord,
        "continuous successor loop evidence remained reconstructable",
    );

    let genome = build_successor_genome(
        "genome-continuous-1",
        promoted_state.session.header.session_id.clone(),
        "package:aiaf/supervisor@v1",
        "typed-dag:continuous",
        vec!["policy:continuous".to_string()],
        "continuous successor genome",
    )
    .unwrap();
    let phenotype = materialize_successor_phenotype(
        "phenotype-continuous-1",
        &genome,
        "package:aiaf/supervisor@v1",
        "component:continuous",
        vec!["wit:supervisor".to_string()],
        vec!["successor-output-continuous-3".to_string()],
        "continuous successor phenotype",
    )
    .unwrap();
    let semantic_validation = validate_semantic_phenotype(
        "validation-continuous-1",
        &genome,
        &phenotype,
        vec!["validator:semantic-check".to_string()],
        vec!["evidence:continuous".to_string()],
        "continuous semantic validation passed",
    )
    .unwrap();
    let second_cycle_comparison = compare_successor_loop_outputs(
        "comparison-second-cycle-continuous-1",
        promoted_state.session.header.session_id.clone(),
        phenotype.artifact_id.clone(),
        shared_input_refs.clone(),
        promoted_state.root_task.output_refs.clone(),
        phenotype.output_refs.clone(),
        supervisor_dimension_scores("continuous promoted", "continuous phenotype"),
        "continuous second cycle remained governed",
    )
    .unwrap();
    let second_cycle_evidence = build_native_sufficiency_evidence(
        "evidence-second-cycle-continuous-1",
        aiaf_v1::execution::CapabilityImportTarget::NativeSupervisorChallenger,
        NativeReplacementTier::BoundedSelfHostingLoop,
        vec![
            genome.genome_id.clone(),
            phenotype.artifact_id.clone(),
            semantic_validation.validation_id.clone(),
        ],
        vec!["checkpoint-continuous-promoted".to_string()],
        vec!["audit-second-cycle-continuous-1".to_string()],
        "continuous second-cycle evidence remained reconstructable",
        true,
    );
    append_named_related_audit(
        &mut promoted_state.memory_store,
        &promoted_state.session,
        Some(&promoted_state.root_task.task_id),
        "review-artifact-cycle-continuous-1",
        "audit-review-artifact-cycle-continuous-1",
        aiaf_v1::execution::AuditRecordClass::GovernanceAuditRecord,
        "continuous second-cycle review artifact remained reconstructable",
    );
    append_named_related_audit(
        &mut promoted_state.memory_store,
        &promoted_state.session,
        Some(&promoted_state.root_task.task_id),
        &second_cycle_evidence.evidence_id,
        "audit-second-cycle-continuous-1",
        aiaf_v1::execution::AuditRecordClass::PromotionAuditRecord,
        "continuous second-cycle evidence remained reconstructable",
    );
    let second_cycle_readiness = decide_promotion_readiness(
        "promotion-readiness-second-cycle-continuous-1",
        &second_cycle_comparison,
        &NativeSufficiencyGate {
            target: aiaf_v1::execution::CapabilityImportTarget::NativeSupervisorChallenger,
            required_tier: NativeReplacementTier::BoundedSelfHostingLoop,
            requires_exact_match: true,
        },
        &second_cycle_evidence,
        std::slice::from_ref(&rollback_handle),
        &["review-artifact-cycle-continuous-1".to_string()],
        &[],
    );
    let second_cycle_decision = decide_cycle_closure(
        "cycle-closure-continuous-1",
        &second_cycle_readiness,
        &second_cycle_comparison,
        std::slice::from_ref(&rollback_handle),
        &[],
    );
    assert_eq!(
        second_cycle_decision.status,
        CycleClosureDecisionStatus::Promote
    );
    let v1_completion_gate = evaluate_v1_completion_gate(
        "v1-gate-continuous-1",
        &closure_inventory,
        &semantic_validation,
        &second_cycle_decision,
    );
    assert_eq!(v1_completion_gate.status, V1CompletionStatus::Satisfied);

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

    let completion_bundle = V1CompletionBundle {
        promotion_activation_bundle: promotion_bundle,
        closure_inventory: closure_inventory.clone(),
        successor_genome: genome.clone(),
        successor_phenotype: phenotype.clone(),
        semantic_validation_record: semantic_validation,
        second_cycle_comparison,
        second_cycle_evidence,
        second_cycle_readiness,
        second_cycle_decision,
        second_cycle_promotion_act: None,
        v1_completion_gate,
    };
    store
        .persist_v1_completion_bundle(&completion_bundle)
        .unwrap();
    let reloaded = store
        .load_v1_completion_bundle("v1-gate-continuous-1")
        .unwrap();

    assert_eq!(reloaded, completion_bundle);
    assert_eq!(
        reloaded.successor_phenotype.stable_interface_ref,
        "package:aiaf/supervisor@v1"
    );
    assert!(
        reloaded
            .promotion_activation_bundle
            .promoted_runtime_state
            .memory_store
            .topic_bundles
            .iter()
            .any(|bundle| bundle.bundle_id == "portfolio:continuous-program-1")
    );
    assert!(
        reloaded
            .promotion_activation_bundle
            .promoted_runtime_state
            .memory_store
            .topic_bundles
            .iter()
            .any(|bundle| bundle.bundle_id == "review:continuous-program-1")
    );
    assert!(
        reloaded
            .promotion_activation_bundle
            .promoted_runtime_state
            .memory_store
            .topic_bundles
            .iter()
            .any(|bundle| bundle.bundle_id == "program-memory:continuous-program-1")
    );
}
