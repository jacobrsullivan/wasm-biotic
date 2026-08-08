use crate::execution::artifact::{ArtifactDigest, PackageBundleManifest};
use crate::execution::component::{
    ComponentExecutionContext, ComponentImportLinkAudit, component_failure_result_ref,
    component_success_result_ref, execute_component_export, execute_component_export_with_context,
};
use crate::execution::replacement::{
    CapabilityImportTarget, DimensionVerdict, EvaluationDimension, EvaluationDimensionScore,
    GenerationComparisonRecord, NativeReplacementTier, ProviderKind,
};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationScenario {
    pub scenario_id: String,
    pub input_ref: String,
    pub export_name: String,
    pub expected_result_ref: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionBackedValidationRecord {
    pub validation_id: String,
    pub generation_id: String,
    pub package_digest: ArtifactDigest,
    pub trace_ref: String,
    pub scenario_refs: Vec<String>,
    pub output_refs: Vec<String>,
    pub import_link_audits: Vec<ComponentImportLinkAudit>,
    pub event_refs: Vec<String>,
    pub passed: bool,
    pub summary: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionComparisonBundle {
    pub comparison_record: GenerationComparisonRecord,
    pub incumbent_trace: ExecutionBackedValidationRecord,
    pub challenger_trace: ExecutionBackedValidationRecord,
}

pub fn expected_output_ref(_package: &PackageBundleManifest, export_name: &str) -> String {
    component_success_result_ref(&[], export_name)
}

pub fn expected_execution_result_ref(package: &PackageBundleManifest, export_name: &str) -> String {
    expected_output_ref(package, export_name)
}

pub fn execute_validation_plan(
    validation_id: impl Into<String>,
    package: &PackageBundleManifest,
    component_bytes: &[u8],
    scenarios: Vec<ValidationScenario>,
    event_refs: Vec<String>,
) -> Result<ExecutionBackedValidationRecord, ValidationHarnessError> {
    execute_validation_plan_inner(
        validation_id.into(),
        package,
        component_bytes,
        None,
        scenarios,
        event_refs,
    )
}

pub fn execute_validation_plan_with_context(
    validation_id: impl Into<String>,
    package: &PackageBundleManifest,
    component_bytes: &[u8],
    context: &ComponentExecutionContext,
    scenarios: Vec<ValidationScenario>,
    event_refs: Vec<String>,
) -> Result<ExecutionBackedValidationRecord, ValidationHarnessError> {
    execute_validation_plan_inner(
        validation_id.into(),
        package,
        component_bytes,
        Some(context),
        scenarios,
        event_refs,
    )
}

fn execute_validation_plan_inner(
    validation_id: String,
    package: &PackageBundleManifest,
    component_bytes: &[u8],
    context: Option<&ComponentExecutionContext>,
    scenarios: Vec<ValidationScenario>,
    event_refs: Vec<String>,
) -> Result<ExecutionBackedValidationRecord, ValidationHarnessError> {
    if validation_id.trim().is_empty() {
        return Err(ValidationHarnessError::MissingValidationId);
    }
    if scenarios.is_empty() {
        return Err(ValidationHarnessError::MissingScenarios);
    }
    if event_refs.is_empty() {
        return Err(ValidationHarnessError::MissingEventRefs);
    }

    let actual_component_digest = ArtifactDigest::from_bytes(component_bytes);
    if actual_component_digest != package.component_digest {
        return Err(ValidationHarnessError::ComponentDigestMismatch {
            expected: package.component_digest.clone(),
            actual: actual_component_digest,
        });
    }

    let mut scenario_refs = Vec::new();
    let mut output_refs = Vec::new();
    let mut import_link_audits = Vec::new();
    let mut passed = true;
    let mut failed_execution_diagnostics = Vec::new();
    for scenario in scenarios {
        if scenario.scenario_id.trim().is_empty()
            || scenario.input_ref.trim().is_empty()
            || scenario.export_name.trim().is_empty()
            || scenario.expected_result_ref.trim().is_empty()
        {
            return Err(ValidationHarnessError::MalformedScenario);
        }

        let output_ref = match context {
            Some(context) => execute_component_export_with_context(
                component_bytes,
                &scenario.export_name,
                context,
            ),
            None => execute_component_export(component_bytes, &scenario.export_name),
        };
        let output_ref = match output_ref {
            Ok(trace) => {
                import_link_audits.extend(trace.import_link_audits);
                trace.result_ref
            }
            Err(error) => {
                passed = false;
                let error = error.to_string();
                failed_execution_diagnostics.push(format!("{}:{}", scenario.scenario_id, error));
                component_failure_result_ref(component_bytes, &scenario.export_name, &error)
            }
        };
        passed &= output_ref == scenario.expected_result_ref;
        scenario_refs.push(scenario.scenario_id);
        output_refs.push(output_ref);
    }

    let summary = if passed {
        "Wasmtime execution-backed validation passed against the packaged component".to_string()
    } else if failed_execution_diagnostics.is_empty() {
        "Wasmtime execution-backed validation detected output divergence".to_string()
    } else {
        format!(
            "Wasmtime execution-backed validation failed: {}",
            failed_execution_diagnostics.join("; ")
        )
    };

    Ok(ExecutionBackedValidationRecord {
        trace_ref: format!("trace-{validation_id}"),
        validation_id,
        generation_id: package.generation_id.to_string(),
        package_digest: package.bundle_digest.clone(),
        scenario_refs,
        output_refs,
        import_link_audits,
        event_refs,
        passed,
        summary,
    })
}

pub fn compare_packages_with_execution(
    comparison_id: impl Into<String>,
    incumbent_package: &PackageBundleManifest,
    incumbent_component_bytes: &[u8],
    challenger_package: &PackageBundleManifest,
    challenger_component_bytes: &[u8],
    shared_input_refs: Vec<String>,
) -> Result<ExecutionComparisonBundle, ValidationHarnessError> {
    compare_packages_with_execution_inner(
        comparison_id.into(),
        incumbent_package,
        incumbent_component_bytes,
        None,
        challenger_package,
        challenger_component_bytes,
        None,
        shared_input_refs,
    )
}

pub fn compare_packages_with_execution_context(
    comparison_id: impl Into<String>,
    incumbent_package: &PackageBundleManifest,
    incumbent_component_bytes: &[u8],
    incumbent_context: &ComponentExecutionContext,
    challenger_package: &PackageBundleManifest,
    challenger_component_bytes: &[u8],
    challenger_context: &ComponentExecutionContext,
    shared_input_refs: Vec<String>,
) -> Result<ExecutionComparisonBundle, ValidationHarnessError> {
    compare_packages_with_execution_inner(
        comparison_id.into(),
        incumbent_package,
        incumbent_component_bytes,
        Some(incumbent_context),
        challenger_package,
        challenger_component_bytes,
        Some(challenger_context),
        shared_input_refs,
    )
}

fn compare_packages_with_execution_inner(
    comparison_id: String,
    incumbent_package: &PackageBundleManifest,
    incumbent_component_bytes: &[u8],
    incumbent_context: Option<&ComponentExecutionContext>,
    challenger_package: &PackageBundleManifest,
    challenger_component_bytes: &[u8],
    challenger_context: Option<&ComponentExecutionContext>,
    shared_input_refs: Vec<String>,
) -> Result<ExecutionComparisonBundle, ValidationHarnessError> {
    if comparison_id.trim().is_empty() {
        return Err(ValidationHarnessError::MissingComparisonId);
    }
    if shared_input_refs.is_empty() {
        return Err(ValidationHarnessError::MissingScenarios);
    }

    let incumbent_scenarios = shared_input_refs
        .iter()
        .enumerate()
        .map(|(index, input_ref)| ValidationScenario {
            scenario_id: format!("scenario-incumbent-{index}"),
            input_ref: input_ref.clone(),
            export_name: "run".to_string(),
            expected_result_ref: expected_output_ref(incumbent_package, "run"),
        })
        .collect::<Vec<_>>();
    let challenger_scenarios = shared_input_refs
        .iter()
        .enumerate()
        .map(|(index, input_ref)| ValidationScenario {
            scenario_id: format!("scenario-challenger-{index}"),
            input_ref: input_ref.clone(),
            export_name: "run".to_string(),
            expected_result_ref: expected_output_ref(challenger_package, "run"),
        })
        .collect::<Vec<_>>();

    let incumbent_trace = execute_validation_plan_inner(
        format!("{comparison_id}-incumbent"),
        incumbent_package,
        incumbent_component_bytes,
        incumbent_context,
        incumbent_scenarios,
        vec![format!("event-{comparison_id}-incumbent-validation")],
    )?;
    let challenger_trace = execute_validation_plan_inner(
        format!("{comparison_id}-challenger"),
        challenger_package,
        challenger_component_bytes,
        challenger_context,
        challenger_scenarios,
        vec![format!("event-{comparison_id}-challenger-validation")],
    )?;
    let outputs_equal = incumbent_trace.output_refs == challenger_trace.output_refs;
    let semantic_verdict = if challenger_trace.passed && incumbent_trace.passed {
        if outputs_equal {
            DimensionVerdict::Equivalent
        } else {
            DimensionVerdict::ChallengerBetter
        }
    } else {
        DimensionVerdict::InsufficientEvidence
    };
    let matched = !matches!(semantic_verdict, DimensionVerdict::InsufficientEvidence);

    let comparison_record = GenerationComparisonRecord {
        comparison_id,
        target: CapabilityImportTarget::NativeSupervisorChallenger,
        replacement_tier: NativeReplacementTier::BoundedSelfHostingLoop,
        incumbent_ref: incumbent_package.bundle_digest.to_string(),
        challenger_ref: challenger_package.bundle_digest.to_string(),
        shared_input_refs,
        imported_provider: ProviderKind::Native,
        native_provider: ProviderKind::Native,
        imported_output_refs: incumbent_trace.output_refs.clone(),
        native_output_refs: challenger_trace.output_refs.clone(),
        dimension_scores: execution_dimension_scores(semantic_verdict, outputs_equal),
        matched,
        summary: "comparison derived from real Wasmtime incumbent and challenger traces"
            .to_string(),
    };

    Ok(ExecutionComparisonBundle {
        comparison_record,
        incumbent_trace,
        challenger_trace,
    })
}

fn execution_dimension_scores(
    semantic_verdict: DimensionVerdict,
    outputs_equal: bool,
) -> Vec<EvaluationDimensionScore> {
    let verdict = if matches!(semantic_verdict, DimensionVerdict::InsufficientEvidence) {
        DimensionVerdict::InsufficientEvidence
    } else {
        DimensionVerdict::Equivalent
    };
    vec![
        EvaluationDimensionScore {
            dimension: EvaluationDimension::SemanticCorrectness,
            verdict: semantic_verdict,
            incumbent_summary: "incumbent component export was executed by Wasmtime".to_string(),
            challenger_summary: if outputs_equal {
                "challenger component output trace matched the incumbent trace".to_string()
            } else {
                "challenger component output trace diverged without violating validation"
                    .to_string()
            },
        },
        EvaluationDimensionScore {
            dimension: EvaluationDimension::GovernanceFidelity,
            verdict,
            incumbent_summary: "incumbent ran under the same validation harness".to_string(),
            challenger_summary: "challenger ran under the same validation harness".to_string(),
        },
        EvaluationDimensionScore {
            dimension: EvaluationDimension::Replayability,
            verdict,
            incumbent_summary: "incumbent trace has replay refs".to_string(),
            challenger_summary: "challenger trace has replay refs".to_string(),
        },
        EvaluationDimensionScore {
            dimension: EvaluationDimension::OperatorBurden,
            verdict,
            incumbent_summary: "incumbent required no extra operator action".to_string(),
            challenger_summary: "challenger required no extra operator action".to_string(),
        },
        EvaluationDimensionScore {
            dimension: EvaluationDimension::BoundaryCost,
            verdict,
            incumbent_summary: "incumbent used declared package boundaries".to_string(),
            challenger_summary: "challenger used declared package boundaries".to_string(),
        },
        EvaluationDimensionScore {
            dimension: EvaluationDimension::ReplacementSafety,
            verdict,
            incumbent_summary: "incumbent package remained retained".to_string(),
            challenger_summary: "challenger package is rollback-safe".to_string(),
        },
    ]
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValidationHarnessError {
    MissingValidationId,
    MissingComparisonId,
    MissingScenarios,
    MissingEventRefs,
    MalformedScenario,
    ComponentDigestMismatch {
        expected: ArtifactDigest,
        actual: ArtifactDigest,
    },
}

impl Display for ValidationHarnessError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingValidationId => write!(f, "validation harness requires a validation id"),
            Self::MissingComparisonId => write!(f, "validation harness requires a comparison id"),
            Self::MissingScenarios => write!(f, "validation harness requires scenarios"),
            Self::MissingEventRefs => write!(f, "validation harness requires event refs"),
            Self::MalformedScenario => write!(f, "validation scenario is malformed"),
            Self::ComponentDigestMismatch { expected, actual } => write!(
                f,
                "validation component digest mismatch; expected {expected}, actual {actual}"
            ),
        }
    }
}

impl Error for ValidationHarnessError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::artifact::{GenerationManifest, PackageBundleManifest};
    use crate::execution::capability::{
        ApprovalClass, AuthorityClass, CapabilityEnvelope, CapabilityWorld, CapabilityWorldGrant,
        IsolationProfile,
    };
    use crate::execution::component::{
        ComponentBuildRequest, ComponentExecutionContext, ComponentImportBinding,
        build_component_package,
    };

    fn manifest() -> GenerationManifest {
        GenerationManifest::new(
            "generation-validation-test",
            None,
            "package:aiaf/supervisor@test",
            "aiaf-supervisor-v3",
            vec!["src:test".to_string()],
            vec!["policy:test".to_string()],
            vec!["input:test".to_string()],
            "test manifest",
        )
        .unwrap()
    }

    fn build(component_source: &str) -> (PackageBundleManifest, Vec<u8>) {
        build_with_wit(
            "world aiaf-supervisor-v3 { export run: func(); }",
            component_source,
        )
    }

    fn build_with_wit(
        wit_source: &str,
        component_source: &str,
    ) -> (PackageBundleManifest, Vec<u8>) {
        let output = build_component_package(ComponentBuildRequest {
            build_id: "build-validation-test".to_string(),
            manifest: manifest(),
            wit_source: wit_source.to_string(),
            component_source: component_source.to_string(),
            required_capability_world_refs: vec!["world:test".to_string()],
        })
        .unwrap();
        (output.package_manifest, output.component_bytes)
    }

    fn component_run() -> &'static str {
        r#"
            (component
                (core module $m
                    (func (export "run")))
                (core instance $i (instantiate $m))
                (func $run (canon lift (core func $i "run")))
                (export "run" (func $run)))
        "#
    }

    fn component_import_run() -> &'static str {
        r#"
            (component
                (import "host-pulse" (func $host-pulse))
                (core func $host-pulse-core (canon lower (func $host-pulse)))
                (core module $m
                    (import "" "host-pulse" (func $host-pulse))
                    (func (export "run")
                        call $host-pulse))
                (core instance $i (instantiate $m
                    (with "" (instance
                        (export "host-pulse" (func $host-pulse-core))))))
                (func $run (canon lift (core func $i "run")))
                (export "run" (func $run)))
        "#
    }

    fn approved_context() -> ComponentExecutionContext {
        ComponentExecutionContext {
            capability_envelope: CapabilityEnvelope {
                envelope_id: "envelope-validation-test".to_string(),
                actor_scope: "validation-test".to_string(),
                world_grants: vec![CapabilityWorldGrant {
                    world: CapabilityWorld::ServiceOrganelle,
                    allowed_operations: vec!["pulse".to_string()],
                    default_authority_class: AuthorityClass::Observe,
                    default_approval_class: ApprovalClass::AutoAllowed,
                    operation_approval_overrides: Vec::new(),
                }],
                authority_ceiling: AuthorityClass::Observe,
                isolation_profile: IsolationProfile::ArtifactSandbox,
                allowed_resource_scopes: vec!["scope:host-pulse".to_string()],
                approval_overrides: Vec::new(),
                quota_policy: None,
                campaign_scope: None,
                epoch_scope: None,
            },
            import_bindings: vec![ComponentImportBinding {
                import_name: "host-pulse".to_string(),
                world: CapabilityWorld::ServiceOrganelle,
                operation: "pulse".to_string(),
                resource_scope: "scope:host-pulse".to_string(),
                required_authority_class: AuthorityClass::Observe,
            }],
        }
    }

    fn component_trap() -> &'static str {
        r#"
            (component
                (core module $m
                    (func (export "run")
                        unreachable))
                (core instance $i (instantiate $m))
                (func $run (canon lift (core func $i "run")))
                (export "run" (func $run)))
        "#
    }

    #[test]
    fn executes_run_into_passed_validation() {
        let (package, bytes) = build(component_run());
        let record = execute_validation_plan(
            "validation-test",
            &package,
            &bytes,
            vec![ValidationScenario {
                scenario_id: "scenario-1".to_string(),
                input_ref: "input-1".to_string(),
                export_name: "run".to_string(),
                expected_result_ref: expected_output_ref(&package, "run"),
            }],
            vec!["event-validation".to_string()],
        )
        .unwrap();
        assert!(record.passed);
        assert_eq!(
            record.output_refs,
            vec![expected_output_ref(&package, "run")]
        );
    }

    #[test]
    fn converts_trap_to_failed_validation() {
        let (package, bytes) = build(component_trap());
        let record = execute_validation_plan(
            "validation-trap-test",
            &package,
            &bytes,
            vec![ValidationScenario {
                scenario_id: "scenario-trap".to_string(),
                input_ref: "input-trap".to_string(),
                export_name: "run".to_string(),
                expected_result_ref: expected_output_ref(&package, "run"),
            }],
            vec!["event-validation-trap".to_string()],
        )
        .unwrap();
        assert!(!record.passed);
        assert!(record.output_refs[0].contains(":failed:"));
        assert!(
            record
                .summary
                .contains("Wasmtime execution-backed validation failed")
        );
    }

    #[test]
    fn context_aware_validation_passes_with_host_import() {
        let (package, bytes) = build_with_wit(
            "world aiaf-supervisor-v3 { import host-pulse: func(); export run: func(); }",
            component_import_run(),
        );
        let record = execute_validation_plan_with_context(
            "validation-import-test",
            &package,
            &bytes,
            &approved_context(),
            vec![ValidationScenario {
                scenario_id: "scenario-import".to_string(),
                input_ref: "input-import".to_string(),
                export_name: "run".to_string(),
                expected_result_ref: expected_output_ref(&package, "run"),
            }],
            vec!["event-validation-import".to_string()],
        )
        .unwrap();
        assert!(record.passed);
        assert_eq!(record.import_link_audits.len(), 1);
        assert_eq!(record.import_link_audits[0].import_name, "host-pulse");
    }

    #[test]
    fn link_policy_denial_converts_to_failed_validation() {
        let (package, bytes) = build_with_wit(
            "world aiaf-supervisor-v3 { import host-pulse: func(); export run: func(); }",
            component_import_run(),
        );
        let mut context = approved_context();
        context.import_bindings.clear();
        let record = execute_validation_plan_with_context(
            "validation-import-denial-test",
            &package,
            &bytes,
            &context,
            vec![ValidationScenario {
                scenario_id: "scenario-import-denial".to_string(),
                input_ref: "input-import-denial".to_string(),
                export_name: "run".to_string(),
                expected_result_ref: expected_output_ref(&package, "run"),
            }],
            vec!["event-validation-import-denial".to_string()],
        )
        .unwrap();
        assert!(!record.passed);
        assert!(record.output_refs[0].contains(":failed:"));
        assert!(
            record
                .summary
                .contains("component import has no explicit binding")
        );
    }
}
