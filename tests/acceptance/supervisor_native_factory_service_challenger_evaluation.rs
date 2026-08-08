use std::fs;

use aiaf_v1::execution::{
    DurableArtifactStore, NativeReplacementTier, NativeSufficiencyGate, PromotionReadinessStatus,
    ShadowCampaignStatus, ShadowEvaluationBundle, build_native_sufficiency_evidence,
    closure_inventory_is_complete, compare_challenger_outputs, create_rollback_handle,
    decide_promotion_readiness, open_challenger_evaluation_session, open_shadow_campaign,
};

use crate::hardening_support::{
    append_inventory_audits, append_named_related_audit, completed_runtime_state,
    full_closure_inventory, supervisor_dimension_scores, temp_store_root,
};

#[test]
fn supervisor_native_factory_service_challenger_evaluation_acceptance() {
    let root = temp_store_root("native-factory-service-challenger-evaluation");
    let _ = fs::remove_dir_all(&root);
    let store = DurableArtifactStore::bootstrap(&root).unwrap();

    let shared_input_refs = vec![
        "service:memory".to_string(),
        "service:governance".to_string(),
        "service:capability-broker".to_string(),
    ];
    let incumbent_state = completed_runtime_state(
        "session-factory-incumbent",
        "campaign-factory",
        "epoch-1",
        "task-factory-incumbent",
        "checkpoint-factory-incumbent",
        vec!["incumbent-factory-output".to_string()],
        "incumbent factory-service checkpoint captured",
    );
    let mut challenger_state = completed_runtime_state(
        "session-factory-challenger",
        "campaign-factory",
        "epoch-1",
        "task-factory-challenger",
        "checkpoint-factory-challenger",
        vec!["challenger-factory-output".to_string()],
        "challenger factory-service checkpoint captured",
    );
    let inventory = full_closure_inventory("closure-factory-service");
    append_inventory_audits(
        &mut challenger_state.memory_store,
        &challenger_state.session,
        Some(&challenger_state.root_task.task_id),
        &inventory,
    );
    append_named_related_audit(
        &mut challenger_state.memory_store,
        &challenger_state.session,
        Some(&challenger_state.root_task.task_id),
        "review-artifact-factory-1",
        "audit-review-artifact-factory-1",
        aiaf_v1::execution::AuditRecordClass::GovernanceAuditRecord,
        "factory review artifact remained reconstructable",
    );

    let comparison = compare_challenger_outputs(
        "comparison-factory-service-1",
        incumbent_state.session.header.session_id.clone(),
        challenger_state.session.header.session_id.clone(),
        shared_input_refs.clone(),
        incumbent_state.root_task.output_refs.clone(),
        challenger_state.root_task.output_refs.clone(),
        supervisor_dimension_scores("incumbent factory", "challenger factory"),
        "native factory-service challenger remained promotable under fixed interfaces",
    )
    .unwrap();
    append_named_related_audit(
        &mut challenger_state.memory_store,
        &challenger_state.session,
        Some(&challenger_state.root_task.task_id),
        &comparison.comparison_id,
        "audit-factory-comparison-1",
        aiaf_v1::execution::AuditRecordClass::GovernanceAuditRecord,
        "factory comparison remained reconstructable",
    );
    let evidence = build_native_sufficiency_evidence(
        "evidence-factory-service-1",
        aiaf_v1::execution::CapabilityImportTarget::NativeSupervisorChallenger,
        NativeReplacementTier::NativeSupervisorChallengers,
        vec![
            inventory.inventory_id.clone(),
            "review-artifact-factory-1".to_string(),
            comparison.comparison_id.clone(),
        ],
        vec!["checkpoint-factory-challenger".to_string()],
        vec!["audit-factory-comparison-1".to_string()],
        "factory-service challenger evidence remained explicit",
        true,
    );
    append_named_related_audit(
        &mut challenger_state.memory_store,
        &challenger_state.session,
        Some(&challenger_state.root_task.task_id),
        &evidence.evidence_id,
        "audit-factory-evidence-1",
        aiaf_v1::execution::AuditRecordClass::PromotionAuditRecord,
        "factory-service evidence remained reconstructable",
    );
    let mut shadow_campaign = open_shadow_campaign(
        "shadow-campaign-factory-1",
        "campaign-factory",
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
        "rollback-factory-1",
    )
    .unwrap();
    shadow_campaign.status = ShadowCampaignStatus::DecisionReady;
    let evaluation_session = open_challenger_evaluation_session(
        "evaluation-factory-1",
        &shadow_campaign,
        &shared_input_refs,
        &shared_input_refs,
        vec!["envelope-factory-review".to_string()],
    )
    .unwrap();
    let readiness = decide_promotion_readiness(
        "promotion-readiness-factory-1",
        &comparison,
        &NativeSufficiencyGate {
            target: aiaf_v1::execution::CapabilityImportTarget::NativeSupervisorChallenger,
            required_tier: NativeReplacementTier::NativeSupervisorChallengers,
            requires_exact_match: true,
        },
        &evidence,
        &[create_rollback_handle(
            "rollback-factory-1",
            "shadow-campaign-factory-1",
            "checkpoint-factory-incumbent",
            vec!["restore checkpoint-factory-incumbent".to_string()],
            Vec::new(),
        )],
        &["review-artifact-factory-1".to_string()],
        &[],
    );
    assert_eq!(readiness.status, PromotionReadinessStatus::Promotable);

    let bundle = ShadowEvaluationBundle {
        shadow_campaign,
        challenger_evaluation_session: evaluation_session,
        incumbent_runtime_state: incumbent_state,
        challenger_runtime_state: challenger_state.clone(),
        comparison_record: comparison.clone(),
        sufficiency_evidence: evidence,
        promotion_readiness_decision: readiness,
    };
    store.persist_shadow_evaluation_bundle(&bundle).unwrap();
    let reloaded = store
        .load_shadow_evaluation_bundle("shadow-campaign-factory-1")
        .unwrap();

    assert!(closure_inventory_is_complete(&inventory));
    assert_eq!(reloaded, bundle);
    assert!(
        reloaded
            .challenger_runtime_state
            .memory_store
            .artifacts_for_related_ref("audit-model-hosting")
            .iter()
            .any(|artifact| artifact.class
                == aiaf_v1::execution::MemoryArtifactClass::AuditRecordArtifact)
    );
}
