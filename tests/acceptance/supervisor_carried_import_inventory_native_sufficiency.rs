use aiaf_v1::execution::{
    CapabilityImportTarget, NativeReplacementTier, NativeSufficiencyGate, carried_import_targets,
    closure_inventory_is_complete, compare_challenger_outputs,
    evaluate_native_sufficiency_with_evidence,
};

use crate::hardening_support::{full_closure_inventory, supervisor_dimension_scores};

#[test]
fn supervisor_carried_import_inventory_native_sufficiency_acceptance() {
    let closure_inventory = full_closure_inventory("closure-v1-2-inventory");
    assert!(closure_inventory_is_complete(&closure_inventory));

    let carried_imports = carried_import_targets(&closure_inventory);
    assert_eq!(
        carried_imports,
        vec![
            "ModelHosting".to_string(),
            "WorktreeHostAdapter".to_string(),
            "EnvironmentBridge".to_string(),
        ]
    );

    let comparison = compare_challenger_outputs(
        "comparison-native-sufficiency-v1-2",
        "session-incumbent",
        "session-challenger",
        vec!["campaign-brief".to_string(), "pointer-index".to_string()],
        vec!["incumbent-output".to_string()],
        vec!["challenger-output".to_string()],
        supervisor_dimension_scores("incumbent", "challenger"),
        "native supervisor challenger remained sufficient under explicit carried imports",
    )
    .unwrap();

    let evidence = aiaf_v1::execution::build_native_sufficiency_evidence(
        "evidence-native-sufficiency-v1-2",
        CapabilityImportTarget::NativeSupervisorChallenger,
        NativeReplacementTier::NativeSupervisorChallengers,
        vec![
            comparison.comparison_id.clone(),
            "review-artifact-native-sufficiency".to_string(),
        ],
        vec![
            "checkpoint-incumbent".to_string(),
            "checkpoint-challenger".to_string(),
        ],
        vec!["audit-native-sufficiency".to_string()],
        "native sufficiency remained explicit under carried-import discipline",
        true,
    );

    assert!(evaluate_native_sufficiency_with_evidence(
        &NativeSufficiencyGate {
            target: CapabilityImportTarget::NativeSupervisorChallenger,
            required_tier: NativeReplacementTier::NativeSupervisorChallengers,
            requires_exact_match: true,
        },
        &comparison,
        &evidence
    ));
}
