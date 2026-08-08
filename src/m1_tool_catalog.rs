//! Separate model-facing tool catalog for the effectful M1 reference workflow.
//!
//! The existing canonical v1 catalog describes a broad rehearsal surface and
//! remains unchanged. This v2 catalog exposes only the eight operations needed
//! by the bounded, synchronous M1 lifecycle. Its argument schemas accept exact
//! effect inputs and persisted evidence identities; they never accept a desired
//! outcome, verdict, score, or promotion decision.

use crate::execution::ToolContextField;
use crate::execution::capability::{ApprovalClass, AuthorityClass, CapabilityWorld};
use crate::execution::tool_membrane::{
    CanonicalToolCatalogBundle, ModelToolDefinition, ModelToolFamily, ToolArgumentSchemaRecord,
    ToolCatalogRecord, ToolExposureDecisionRecord, ToolMembraneError, ToolResultSchemaRecord,
    validate_json_against_schema,
};
use crate::execution::turn_package::TurnPackageRole;
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

pub const M1_REFERENCE_TOOL_CATALOG_ID: &str = "tool-catalog:m1-reference:v2";
pub const M1_REFERENCE_TEMPLATE_REF: &str = "m1-reference-component:template:v1";

pub const M1_REFERENCE_TOOL_IDS: [&str; 8] = [
    "candidate.open_workspace.v2",
    "candidate.materialize_patchset.v2",
    "candidate.package.v2",
    "validation.run_proving.v2",
    "validation.compare_candidate.v2",
    "program.submit_cycle_decision.v2",
    "validation.record_observation.v2",
    "deployment.rollback.v2",
];

const SHA256_PATTERN: &str = "^sha256:[0-9a-f]{64}$";
const WORKSPACE_ID_PATTERN: &str = "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$";
const MAX_REPLACEMENT_WAT_CHARS: u64 = 65_536;

/// Builds the isolated M1 v2 catalog without adding to or changing the v1
/// canonical catalog.
pub fn build_m1_reference_tool_catalog_v2() -> Result<CanonicalToolCatalogBundle, ToolMembraneError>
{
    let created_at = current_timestamp();
    let definitions = m1_definitions();
    let argument_schemas = definitions
        .iter()
        .map(|definition| ToolArgumentSchemaRecord {
            tool_argument_schema_id: argument_schema_id(&definition.tool_id),
            tool_definition_ref: definition.tool_id.clone(),
            argument_schema_json: m1_argument_schema(&definition.tool_id).to_string(),
            created_at: created_at.clone(),
        })
        .collect::<Vec<_>>();
    let result_schemas = definitions
        .iter()
        .map(|definition| ToolResultSchemaRecord {
            tool_result_schema_id: result_schema_id(&definition.tool_id),
            tool_definition_ref: definition.tool_id.clone(),
            result_schema_json: m1_result_schema(&definition.tool_id).to_string(),
            created_at: created_at.clone(),
        })
        .collect::<Vec<_>>();
    let catalog_json = render_definitions(&definitions, &argument_schemas)?;
    let catalog = ToolCatalogRecord {
        tool_catalog_id: M1_REFERENCE_TOOL_CATALOG_ID.to_string(),
        tool_definition_refs: definitions
            .iter()
            .map(|definition| definition.tool_id.clone())
            .collect(),
        tool_catalog_json: catalog_json,
        summary: "Effectful, local-only M1 reference lifecycle; all conclusions are derived by services from exact bytes and persisted evidence.".to_string(),
        created_at: created_at.clone(),
    };
    let exposure_decisions = definitions
        .iter()
        .map(|definition| ToolExposureDecisionRecord {
            tool_exposure_decision_id: format!("tool-exposure:{}", definition.tool_id),
            tool_catalog_ref: M1_REFERENCE_TOOL_CATALOG_ID.to_string(),
            tool_definition_ref: definition.tool_id.clone(),
            exposed: true,
            rationale: "Exposed only in the bounded M1 reference catalog under its declared capability, context, scope, and approval constraints.".to_string(),
            created_at: created_at.clone(),
        })
        .collect();
    let bundle = CanonicalToolCatalogBundle {
        catalog,
        definitions,
        argument_schemas,
        result_schemas,
        exposure_decisions,
        operator_only_surfaces: Vec::new(),
    };
    validate_m1_catalog_invariants(&bundle)?;
    Ok(bundle)
}

/// Renders this catalog for a role using the schemas stored in the bundle.
///
/// The general v1 renderer is intentionally not reused because its private
/// schema switch describes the v1 ids.
pub fn render_m1_reference_tool_catalog_for_role_v2(
    bundle: &CanonicalToolCatalogBundle,
    role: TurnPackageRole,
) -> Result<String, ToolMembraneError> {
    validate_m1_catalog_invariants(bundle)?;
    let definitions = bundle
        .definitions
        .iter()
        .filter(|definition| definition.role_compatibility.contains(&role))
        .cloned()
        .collect::<Vec<_>>();
    render_definitions(&definitions, &bundle.argument_schemas)
}

/// Validates concrete arguments against the closed v2 schema before a handler
/// performs any effect.
pub fn validate_m1_reference_tool_arguments_v2(
    bundle: &CanonicalToolCatalogBundle,
    tool_id: &str,
    payload_json: &str,
) -> Result<(), ToolMembraneError> {
    validate_m1_catalog_invariants(bundle)?;
    let schema =
        bundle
            .argument_schema_for(tool_id)
            .ok_or_else(|| ToolMembraneError::ToolNotFound {
                tool_id: tool_id.to_string(),
            })?;
    validate_json_against_schema("arguments", payload_json, &schema.argument_schema_json)
}

/// Validates a handler result against the corresponding closed v2 result
/// schema before it crosses the model-facing membrane.
pub fn validate_m1_reference_tool_result_v2(
    bundle: &CanonicalToolCatalogBundle,
    tool_id: &str,
    payload_json: &str,
) -> Result<(), ToolMembraneError> {
    validate_m1_catalog_invariants(bundle)?;
    let schema =
        bundle
            .result_schema_for(tool_id)
            .ok_or_else(|| ToolMembraneError::ToolNotFound {
                tool_id: tool_id.to_string(),
            })?;
    validate_json_against_schema("result", payload_json, &schema.result_schema_json)
}

fn m1_definitions() -> Vec<ModelToolDefinition> {
    vec![
        definition(
            "candidate.open_workspace.v2",
            ModelToolFamily::CandidateConstruction,
            "service:m1:candidate:open-workspace:v2",
            CapabilityWorld::WorkspaceMutate,
            AuthorityClass::LocalMutate,
            ApprovalClass::SupervisorAllowed,
            "workspace-scope-ref",
            vec![ToolContextField::WorkspaceScopeRef],
            "Create a fresh service-owned two-file reference workspace from the frozen template.",
        ),
        definition(
            "candidate.materialize_patchset.v2",
            ModelToolFamily::CandidateConstruction,
            "service:m1:candidate:materialize-patchset:v2",
            CapabilityWorld::WorkspaceMutate,
            AuthorityClass::LocalMutate,
            ApprovalClass::SupervisorAllowed,
            "workspace-scope-ref",
            vec![ToolContextField::WorkspaceScopeRef],
            "Atomically replace component.wat after containment, size, and expected-base-digest checks.",
        ),
        definition(
            "candidate.package.v2",
            ModelToolFamily::CandidateConstruction,
            "service:m1:candidate:package:v2",
            CapabilityWorld::ServiceOrganelle,
            AuthorityClass::LocalMutate,
            ApprovalClass::SupervisorAllowed,
            "workspace-scope-ref",
            vec![ToolContextField::WorkspaceScopeRef],
            "Build and package the exact workspace bytes through the bounded component toolchain.",
        ),
        definition(
            "validation.run_proving.v2",
            ModelToolFamily::ValidationObservation,
            "service:m1:validation:run-proving:v2",
            CapabilityWorld::ServiceOrganelle,
            AuthorityClass::CampaignControl,
            ApprovalClass::SupervisorAllowed,
            "workspace-scope-ref",
            vec![ToolContextField::WorkspaceScopeRef],
            "Execute the fixed reference workload under bounded Wasmtime and persist derived traces.",
        ),
        definition(
            "validation.compare_candidate.v2",
            ModelToolFamily::ValidationObservation,
            "service:m1:validation:compare-candidate:v2",
            CapabilityWorld::ReviewPromotion,
            AuthorityClass::PromotionControl,
            ApprovalClass::SupervisorAllowed,
            "factory-program-instance-ref",
            vec![ToolContextField::FactoryProgramInstanceRef],
            "Derive the incumbent-versus-challenger decision from two persisted proving reports.",
        ),
        definition(
            "program.submit_cycle_decision.v2",
            ModelToolFamily::Program,
            "service:m1:program:submit-cycle-decision:v2",
            CapabilityWorld::ReviewPromotion,
            AuthorityClass::PromotionControl,
            ApprovalClass::HumanRequired,
            "factory-program-instance-ref",
            vec![
                ToolContextField::FactoryProgramInstanceRef,
                ToolContextField::CampaignRef,
                ToolContextField::EpochRef,
            ],
            "Submit exact comparison, package, incumbent, and approval evidence for an independently derived activation decision.",
        ),
        definition(
            "validation.record_observation.v2",
            ModelToolFamily::ValidationObservation,
            "service:m1:validation:record-observation:v2",
            CapabilityWorld::ServiceOrganelle,
            AuthorityClass::LocalMutate,
            ApprovalClass::SupervisorAllowed,
            "workspace-scope-ref",
            vec![ToolContextField::WorkspaceScopeRef],
            "Execute and persist one fixed post-activation observation without accepting a caller-authored health outcome.",
        ),
        definition(
            "deployment.rollback.v2",
            ModelToolFamily::Governance,
            "service:m1:deployment:rollback:v2",
            CapabilityWorld::ServiceOrganelle,
            AuthorityClass::LocalMutate,
            ApprovalClass::HumanRequired,
            "workspace-scope-ref",
            vec![ToolContextField::WorkspaceScopeRef],
            "Restore the exact incumbent bytes bound to a named post-activation observation and activation.",
        ),
    ]
}

#[allow(clippy::too_many_arguments)]
fn definition(
    tool_id: &str,
    family: ModelToolFamily,
    internal_service_ref: &str,
    capability_world: CapabilityWorld,
    required_authority_class: AuthorityClass,
    default_approval_class: ApprovalClass,
    scope_ref: &str,
    required_context_fields: Vec<ToolContextField>,
    summary: &str,
) -> ModelToolDefinition {
    ModelToolDefinition {
        tool_id: tool_id.to_string(),
        family,
        internal_service_ref: internal_service_ref.to_string(),
        capability_world,
        required_authority_class,
        default_approval_class,
        allowed_scope_refs: vec![scope_ref.to_string()],
        required_context_fields,
        argument_schema_ref: argument_schema_id(tool_id),
        result_schema_ref: result_schema_id(tool_id),
        role_compatibility: vec![TurnPackageRole::Supervisor],
        summary: summary.to_string(),
    }
}

fn argument_schema_id(tool_id: &str) -> String {
    format!("tool-argument-schema:{tool_id}")
}

fn result_schema_id(tool_id: &str) -> String {
    format!("tool-result-schema:{tool_id}")
}

fn m1_argument_schema(tool_id: &str) -> Value {
    match tool_id {
        "candidate.open_workspace.v2" => closed_object(
            [
                ("workspace_id", workspace_id_schema()),
                (
                    "template_ref",
                    json!({
                        "type": "string",
                        "enum": [M1_REFERENCE_TEMPLATE_REF]
                    }),
                ),
            ],
            &["workspace_id", "template_ref"],
        ),
        "candidate.materialize_patchset.v2" => closed_object(
            [
                ("workspace_id", workspace_id_schema()),
                (
                    "relative_path",
                    json!({
                        "type": "string",
                        "enum": ["component.wat"]
                    }),
                ),
                ("expected_before_digest", digest_schema()),
                (
                    "replacement_wat",
                    json!({
                        "type": "string",
                        "minLength": 1,
                        "maxLength": MAX_REPLACEMENT_WAT_CHARS
                    }),
                ),
            ],
            &[
                "workspace_id",
                "relative_path",
                "expected_before_digest",
                "replacement_wat",
            ],
        ),
        "candidate.package.v2" => closed_object(
            [
                ("workspace_id", workspace_id_schema()),
                ("expected_source_tree_digest", digest_schema()),
            ],
            &["workspace_id", "expected_source_tree_digest"],
        ),
        "validation.run_proving.v2" => closed_object(
            [
                ("package_digest", digest_schema()),
                ("expected_source_tree_digest", digest_schema()),
            ],
            &["package_digest", "expected_source_tree_digest"],
        ),
        "validation.compare_candidate.v2" => closed_object(
            [
                ("incumbent_proving_report_digest", digest_schema()),
                ("challenger_proving_report_digest", digest_schema()),
            ],
            &[
                "incumbent_proving_report_digest",
                "challenger_proving_report_digest",
            ],
        ),
        "program.submit_cycle_decision.v2" => closed_object(
            [
                ("comparison_digest", digest_schema()),
                ("challenger_package_digest", digest_schema()),
                ("expected_incumbent_package_digest", digest_schema()),
            ],
            &[
                "comparison_digest",
                "challenger_package_digest",
                "expected_incumbent_package_digest",
            ],
        ),
        "validation.record_observation.v2" => closed_object(
            [
                ("activation_id", nonempty_string_schema()),
                ("expected_active_package_digest", digest_schema()),
                ("proving_report_digest", digest_schema()),
                (
                    "input",
                    json!({
                        "type": "integer",
                        "enum": [41]
                    }),
                ),
            ],
            &[
                "activation_id",
                "expected_active_package_digest",
                "proving_report_digest",
                "input",
            ],
        ),
        "deployment.rollback.v2" => closed_object(
            [
                ("activation_id", nonempty_string_schema()),
                ("observation_record_digest", digest_schema()),
                ("expected_active_package_digest", digest_schema()),
            ],
            &[
                "activation_id",
                "observation_record_digest",
                "expected_active_package_digest",
            ],
        ),
        _ => closed_object([], &[]),
    }
}

fn m1_result_schema(tool_id: &str) -> Value {
    match tool_id {
        "candidate.open_workspace.v2" => closed_object(
            [
                ("workspace_snapshot_id", nonempty_string_schema()),
                ("workspace_id", workspace_id_schema()),
                ("workspace_ref", nonempty_string_schema()),
                ("workspace_snapshot_digest", digest_schema()),
                ("source_tree_digest", digest_schema()),
                ("component_wit_digest", digest_schema()),
                ("component_wat_digest", digest_schema()),
                ("incumbent_package_digest", digest_schema()),
                ("incumbent_proving_report_digest", digest_schema()),
            ],
            &[
                "workspace_snapshot_id",
                "workspace_id",
                "workspace_ref",
                "workspace_snapshot_digest",
                "source_tree_digest",
                "component_wit_digest",
                "component_wat_digest",
                "incumbent_package_digest",
                "incumbent_proving_report_digest",
            ],
        ),
        "candidate.materialize_patchset.v2" => closed_object(
            [
                ("patchset_id", nonempty_string_schema()),
                ("patchset_digest", digest_schema()),
                ("workspace_id", workspace_id_schema()),
                ("before_tree_digest", digest_schema()),
                ("after_tree_digest", digest_schema()),
                ("before_content_digest", digest_schema()),
                ("after_content_digest", digest_schema()),
            ],
            &[
                "patchset_id",
                "patchset_digest",
                "workspace_id",
                "before_tree_digest",
                "after_tree_digest",
                "before_content_digest",
                "after_content_digest",
            ],
        ),
        "candidate.package.v2" => closed_object(
            [
                ("build_id", nonempty_string_schema()),
                ("generation_id", nonempty_string_schema()),
                ("package_id", nonempty_string_schema()),
                ("source_tree_digest", digest_schema()),
                ("component_digest", digest_schema()),
                ("package_digest", digest_schema()),
            ],
            &[
                "build_id",
                "generation_id",
                "package_id",
                "source_tree_digest",
                "component_digest",
                "package_digest",
            ],
        ),
        "validation.run_proving.v2" => closed_object(
            [
                ("proving_run_id", nonempty_string_schema()),
                ("proving_report_digest", digest_schema()),
                ("suite_digest", digest_schema()),
                ("component_digest", digest_schema()),
                ("case_count", json!({ "type": "integer", "minimum": 1 })),
                ("passed_count", json!({ "type": "integer", "minimum": 0 })),
                ("overall_pass", json!({ "type": "boolean" })),
            ],
            &[
                "proving_run_id",
                "proving_report_digest",
                "suite_digest",
                "component_digest",
                "case_count",
                "passed_count",
                "overall_pass",
            ],
        ),
        "validation.compare_candidate.v2" => closed_object(
            [
                ("comparison_id", nonempty_string_schema()),
                ("comparison_digest", digest_schema()),
                ("incumbent_component_digest", digest_schema()),
                ("challenger_component_digest", digest_schema()),
                (
                    "incumbent_passed_count",
                    json!({ "type": "integer", "minimum": 0 }),
                ),
                (
                    "challenger_passed_count",
                    json!({ "type": "integer", "minimum": 0 }),
                ),
                (
                    "decision",
                    json!({
                        "type": "string",
                        "enum": [
                            "challenger_preferred",
                            "equivalent",
                            "incumbent_retained"
                        ]
                    }),
                ),
                ("eligible_for_activation", json!({ "type": "boolean" })),
            ],
            &[
                "comparison_id",
                "comparison_digest",
                "incumbent_component_digest",
                "challenger_component_digest",
                "incumbent_passed_count",
                "challenger_passed_count",
                "decision",
                "eligible_for_activation",
            ],
        ),
        "program.submit_cycle_decision.v2" => closed_object(
            [
                ("cycle_decision_id", nonempty_string_schema()),
                ("decision_record_digest", digest_schema()),
                ("activation_id", nonempty_string_schema()),
                ("previous_package_digest", digest_schema()),
                ("active_package_digest", digest_schema()),
                (
                    "decision",
                    json!({
                        "type": "string",
                        "enum": ["activated", "refused"]
                    }),
                ),
            ],
            &[
                "cycle_decision_id",
                "decision_record_digest",
                "activation_id",
                "previous_package_digest",
                "active_package_digest",
                "decision",
            ],
        ),
        "validation.record_observation.v2" => closed_object(
            [
                ("observation_id", nonempty_string_schema()),
                ("observation_record_digest", digest_schema()),
                ("evidence_digest", digest_schema()),
                ("active_package_digest", digest_schema()),
                ("input", json!({ "type": "integer" })),
                ("actual_output", json!({ "type": "integer" })),
                ("expected_output", json!({ "type": "integer" })),
                (
                    "outcome",
                    json!({
                        "type": "string",
                        "enum": ["healthy", "regressed"]
                    }),
                ),
            ],
            &[
                "observation_id",
                "observation_record_digest",
                "evidence_digest",
                "active_package_digest",
                "input",
                "actual_output",
                "expected_output",
                "outcome",
            ],
        ),
        "deployment.rollback.v2" => closed_object(
            [
                ("rollback_id", nonempty_string_schema()),
                ("rollback_record_digest", digest_schema()),
                ("from_package_digest", digest_schema()),
                ("restored_package_digest", digest_schema()),
            ],
            &[
                "rollback_id",
                "rollback_record_digest",
                "from_package_digest",
                "restored_package_digest",
            ],
        ),
        _ => closed_object([], &[]),
    }
}

fn closed_object<const N: usize>(properties: [(&str, Value); N], required: &[&str]) -> Value {
    let properties = properties
        .into_iter()
        .map(|(name, schema)| (name.to_string(), schema))
        .collect::<Map<String, Value>>();
    json!({
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": false
    })
}

fn digest_schema() -> Value {
    json!({
        "type": "string",
        "pattern": SHA256_PATTERN
    })
}

fn workspace_id_schema() -> Value {
    json!({
        "type": "string",
        "pattern": WORKSPACE_ID_PATTERN,
        "minLength": 1,
        "maxLength": 128
    })
}

fn nonempty_string_schema() -> Value {
    json!({
        "type": "string",
        "minLength": 1
    })
}

fn render_definitions(
    definitions: &[ModelToolDefinition],
    schemas: &[ToolArgumentSchemaRecord],
) -> Result<String, ToolMembraneError> {
    let rendered =
        definitions
            .iter()
            .map(|definition| {
                let schema = schemas
                    .iter()
                    .find(|schema| schema.tool_definition_ref == definition.tool_id)
                    .ok_or(ToolMembraneError::MissingArgumentSchemaRef)?;
                let parameters = serde_json::from_str::<Value>(&schema.argument_schema_json)
                    .map_err(|error| ToolMembraneError::ServiceFailure {
                        tool_id: definition.tool_id.clone(),
                        reason: format!("invalid M1 argument schema: {error}"),
                    })?;
                Ok(json!({
                    "type": "function",
                    "name": definition.tool_id,
                    "description": definition.summary,
                    "parameters": parameters
                }))
            })
            .collect::<Result<Vec<_>, ToolMembraneError>>()?;
    serde_json::to_string(&rendered).map_err(|error| ToolMembraneError::ServiceFailure {
        tool_id: M1_REFERENCE_TOOL_CATALOG_ID.to_string(),
        reason: error.to_string(),
    })
}

fn validate_m1_catalog_invariants(
    bundle: &CanonicalToolCatalogBundle,
) -> Result<(), ToolMembraneError> {
    bundle.validate()?;
    if bundle.catalog.tool_catalog_id != M1_REFERENCE_TOOL_CATALOG_ID {
        return invariant_error("unexpected M1 tool catalog id");
    }
    if bundle.definitions.len() != M1_REFERENCE_TOOL_IDS.len()
        || bundle.argument_schemas.len() != M1_REFERENCE_TOOL_IDS.len()
        || bundle.result_schemas.len() != M1_REFERENCE_TOOL_IDS.len()
        || bundle.exposure_decisions.len() != M1_REFERENCE_TOOL_IDS.len()
        || !bundle.operator_only_surfaces.is_empty()
    {
        return invariant_error("M1 catalog does not have exactly eight complete tool records");
    }
    let expected = M1_REFERENCE_TOOL_IDS
        .into_iter()
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    let actual = bundle
        .definitions
        .iter()
        .map(|definition| definition.tool_id.clone())
        .collect::<BTreeSet<_>>();
    if actual != expected || bundle.catalog.tool_definition_refs != M1_REFERENCE_TOOL_IDS {
        return invariant_error("M1 tool ids or catalog order differ from the frozen v2 set");
    }
    for definition in &bundle.definitions {
        if definition.role_compatibility != [TurnPackageRole::Supervisor]
            || definition.allowed_scope_refs.len() != 1
            || bundle.argument_schema_for(&definition.tool_id).is_none()
            || bundle.result_schema_for(&definition.tool_id).is_none()
            || bundle
                .exposure_for(&definition.tool_id)
                .is_none_or(|decision| {
                    !decision.exposed || decision.tool_catalog_ref != M1_REFERENCE_TOOL_CATALOG_ID
                })
        {
            return invariant_error(&format!(
                "incomplete or over-broad M1 definition: {}",
                definition.tool_id
            ));
        }
    }
    Ok(())
}

fn invariant_error(reason: &str) -> Result<(), ToolMembraneError> {
    Err(ToolMembraneError::ServiceFailure {
        tool_id: M1_REFERENCE_TOOL_CATALOG_ID.to_string(),
        reason: reason.to_string(),
    })
}

fn current_timestamp() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        M1_REFERENCE_TEMPLATE_REF, M1_REFERENCE_TOOL_CATALOG_ID, M1_REFERENCE_TOOL_IDS,
        build_m1_reference_tool_catalog_v2, render_m1_reference_tool_catalog_for_role_v2,
        validate_m1_reference_tool_arguments_v2, validate_m1_reference_tool_result_v2,
    };
    use crate::execution::capability::{ApprovalClass, AuthorityClass, CapabilityWorld};
    use crate::execution::tool_membrane::{
        ModelToolDefinition, ToolMembraneError, build_canonical_tool_catalog,
    };
    use crate::execution::turn_package::TurnPackageRole;
    use serde_json::Value;
    use std::collections::{BTreeMap, BTreeSet};

    fn parsed_schema(json: &str) -> Value {
        serde_json::from_str(json).expect("valid schema JSON")
    }

    fn property_names(schema: &Value) -> BTreeSet<String> {
        schema["properties"]
            .as_object()
            .expect("closed object properties")
            .keys()
            .cloned()
            .collect()
    }

    fn policy_tuple(
        definition: &ModelToolDefinition,
    ) -> (CapabilityWorld, AuthorityClass, ApprovalClass, Vec<String>) {
        (
            definition.capability_world.clone(),
            definition.required_authority_class.clone(),
            definition.default_approval_class.clone(),
            definition.allowed_scope_refs.clone(),
        )
    }

    #[test]
    fn v2_catalog_is_separate_and_does_not_change_v1() {
        let v1 = build_canonical_tool_catalog().expect("build v1 catalog");
        let v2 = build_m1_reference_tool_catalog_v2().expect("build M1 v2 catalog");

        assert_eq!(v1.catalog.tool_catalog_id, "tool-catalog:canonical:v1");
        assert_eq!(v2.catalog.tool_catalog_id, M1_REFERENCE_TOOL_CATALOG_ID);
        assert_eq!(
            v2.catalog.tool_definition_refs,
            M1_REFERENCE_TOOL_IDS.map(str::to_string)
        );
        assert!(
            M1_REFERENCE_TOOL_IDS
                .iter()
                .all(|tool_id| v1.definition(tool_id).is_none())
        );
        assert!(
            v1.definitions
                .iter()
                .all(|definition| v2.definition(&definition.tool_id).is_none())
        );
    }

    #[test]
    fn every_definition_is_complete_unique_exposed_and_supervisor_only() {
        let bundle = build_m1_reference_tool_catalog_v2().expect("build catalog");
        let ids = bundle
            .definitions
            .iter()
            .map(|definition| definition.tool_id.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(ids.len(), M1_REFERENCE_TOOL_IDS.len());
        for tool_id in M1_REFERENCE_TOOL_IDS {
            let definition = bundle.definition(tool_id).expect("definition");
            assert_eq!(
                definition.role_compatibility,
                vec![TurnPackageRole::Supervisor]
            );
            assert_eq!(definition.allowed_scope_refs.len(), 1);
            assert!(bundle.argument_schema_for(tool_id).is_some());
            assert!(bundle.result_schema_for(tool_id).is_some());
            let exposure = bundle.exposure_for(tool_id).expect("exposure");
            assert!(exposure.exposed);
            assert_eq!(exposure.tool_catalog_ref, M1_REFERENCE_TOOL_CATALOG_ID);
        }
    }

    #[test]
    fn capability_authority_approval_and_scope_are_bounded_per_effect() {
        let bundle = build_m1_reference_tool_catalog_v2().expect("build catalog");
        let expected = BTreeMap::from([
            (
                "candidate.open_workspace.v2",
                (
                    CapabilityWorld::WorkspaceMutate,
                    AuthorityClass::LocalMutate,
                    ApprovalClass::SupervisorAllowed,
                    vec!["workspace-scope-ref".to_string()],
                ),
            ),
            (
                "candidate.materialize_patchset.v2",
                (
                    CapabilityWorld::WorkspaceMutate,
                    AuthorityClass::LocalMutate,
                    ApprovalClass::SupervisorAllowed,
                    vec!["workspace-scope-ref".to_string()],
                ),
            ),
            (
                "candidate.package.v2",
                (
                    CapabilityWorld::ServiceOrganelle,
                    AuthorityClass::LocalMutate,
                    ApprovalClass::SupervisorAllowed,
                    vec!["workspace-scope-ref".to_string()],
                ),
            ),
            (
                "validation.run_proving.v2",
                (
                    CapabilityWorld::ServiceOrganelle,
                    AuthorityClass::CampaignControl,
                    ApprovalClass::SupervisorAllowed,
                    vec!["workspace-scope-ref".to_string()],
                ),
            ),
            (
                "validation.compare_candidate.v2",
                (
                    CapabilityWorld::ReviewPromotion,
                    AuthorityClass::PromotionControl,
                    ApprovalClass::SupervisorAllowed,
                    vec!["factory-program-instance-ref".to_string()],
                ),
            ),
            (
                "program.submit_cycle_decision.v2",
                (
                    CapabilityWorld::ReviewPromotion,
                    AuthorityClass::PromotionControl,
                    ApprovalClass::HumanRequired,
                    vec!["factory-program-instance-ref".to_string()],
                ),
            ),
            (
                "validation.record_observation.v2",
                (
                    CapabilityWorld::ServiceOrganelle,
                    AuthorityClass::LocalMutate,
                    ApprovalClass::SupervisorAllowed,
                    vec!["workspace-scope-ref".to_string()],
                ),
            ),
            (
                "deployment.rollback.v2",
                (
                    CapabilityWorld::ServiceOrganelle,
                    AuthorityClass::LocalMutate,
                    ApprovalClass::HumanRequired,
                    vec!["workspace-scope-ref".to_string()],
                ),
            ),
        ]);
        for definition in &bundle.definitions {
            assert_eq!(
                policy_tuple(definition),
                expected[definition.tool_id.as_str()]
            );
        }
    }

    #[test]
    fn argument_schemas_are_closed_and_never_accept_conclusions() {
        let bundle = build_m1_reference_tool_catalog_v2().expect("build catalog");
        let forbidden = [
            "decision",
            "outcome",
            "verdict",
            "eligible_for_activation",
            "passed",
            "matched",
            "risk_posture",
            "summary",
            "approval_ref",
        ];
        for schema in &bundle.argument_schemas {
            let value = parsed_schema(&schema.argument_schema_json);
            assert_eq!(value["type"], "object");
            assert_eq!(value["additionalProperties"], false);
            let properties = property_names(&value);
            for name in forbidden {
                assert!(
                    !properties.contains(name),
                    "{} must derive {name}, not accept it",
                    schema.tool_definition_ref
                );
            }
        }

        let materialize = parsed_schema(
            &bundle
                .argument_schema_for("candidate.materialize_patchset.v2")
                .expect("materialize schema")
                .argument_schema_json,
        );
        assert_eq!(
            materialize["properties"]["relative_path"]["enum"],
            serde_json::json!(["component.wat"])
        );
        assert!(property_names(&materialize).contains("replacement_wat"));

        let open = parsed_schema(
            &bundle
                .argument_schema_for("candidate.open_workspace.v2")
                .expect("open schema")
                .argument_schema_json,
        );
        assert_eq!(
            open["properties"]["template_ref"]["enum"],
            serde_json::json!([M1_REFERENCE_TEMPLATE_REF])
        );
    }

    #[test]
    fn every_result_exposes_derived_identity_and_content_digest() {
        let bundle = build_m1_reference_tool_catalog_v2().expect("build catalog");
        for schema in &bundle.result_schemas {
            let value = parsed_schema(&schema.result_schema_json);
            assert_eq!(value["additionalProperties"], false);
            let required = value["required"]
                .as_array()
                .expect("required results")
                .iter()
                .map(|item| item.as_str().expect("required name"))
                .collect::<Vec<_>>();
            assert!(
                required.iter().any(|name| name.ends_with("_id")),
                "{} lacks a derived id",
                schema.tool_definition_ref
            );
            assert!(
                required.iter().any(|name| name.ends_with("_digest")),
                "{} lacks a derived digest",
                schema.tool_definition_ref
            );
        }
        let comparison = parsed_schema(
            &bundle
                .result_schema_for("validation.compare_candidate.v2")
                .expect("comparison result schema")
                .result_schema_json,
        );
        assert!(property_names(&comparison).contains("decision"));
        assert!(property_names(&comparison).contains("eligible_for_activation"));
    }

    #[test]
    fn concrete_arguments_pass_and_caller_supplied_verdict_is_rejected() {
        let bundle = build_m1_reference_tool_catalog_v2().expect("build catalog");
        let digest = format!("sha256:{}", "a".repeat(64));
        let valid = serde_json::json!({
            "workspace_id": "candidate-1",
            "relative_path": "component.wat",
            "expected_before_digest": digest,
            "replacement_wat": "(component)"
        });
        validate_m1_reference_tool_arguments_v2(
            &bundle,
            "candidate.materialize_patchset.v2",
            &valid.to_string(),
        )
        .expect("valid concrete mutation input");

        let invalid = serde_json::json!({
            "incumbent_proving_report_digest": format!("sha256:{}", "b".repeat(64)),
            "challenger_proving_report_digest": format!("sha256:{}", "c".repeat(64)),
            "decision": "challenger_preferred"
        });
        assert!(matches!(
            validate_m1_reference_tool_arguments_v2(
                &bundle,
                "validation.compare_candidate.v2",
                &invalid.to_string()
            ),
            Err(ToolMembraneError::JsonSchemaViolation { .. })
        ));
    }

    #[test]
    fn catalog_json_and_role_renderer_use_the_stored_v2_schemas() {
        let bundle = build_m1_reference_tool_catalog_v2().expect("build catalog");
        let catalog: Value =
            serde_json::from_str(&bundle.catalog.tool_catalog_json).expect("catalog JSON");
        let functions = catalog.as_array().expect("function array");
        assert_eq!(functions.len(), M1_REFERENCE_TOOL_IDS.len());
        for function in functions {
            let tool_id = function["name"].as_str().expect("tool name");
            let stored = parsed_schema(
                &bundle
                    .argument_schema_for(tool_id)
                    .expect("stored schema")
                    .argument_schema_json,
            );
            assert_eq!(function["parameters"], stored);
        }

        let supervisor =
            render_m1_reference_tool_catalog_for_role_v2(&bundle, TurnPackageRole::Supervisor)
                .expect("supervisor catalog");
        assert_eq!(
            serde_json::from_str::<Value>(&supervisor)
                .expect("supervisor JSON")
                .as_array()
                .expect("supervisor tools")
                .len(),
            8
        );
        let worker = render_m1_reference_tool_catalog_for_role_v2(&bundle, TurnPackageRole::Worker)
            .expect("worker catalog");
        assert_eq!(worker, "[]");
    }

    #[test]
    fn derived_result_schema_accepts_service_output_but_rejects_missing_digest() {
        let bundle = build_m1_reference_tool_catalog_v2().expect("build catalog");
        let valid = serde_json::json!({
            "rollback_id": "rollback:1",
            "rollback_record_digest": format!("sha256:{}", "d".repeat(64)),
            "from_package_digest": format!("sha256:{}", "e".repeat(64)),
            "restored_package_digest": format!("sha256:{}", "f".repeat(64))
        });
        validate_m1_reference_tool_result_v2(&bundle, "deployment.rollback.v2", &valid.to_string())
            .expect("valid derived rollback result");

        let missing = serde_json::json!({
            "rollback_id": "rollback:1",
            "from_package_digest": format!("sha256:{}", "e".repeat(64)),
            "restored_package_digest": format!("sha256:{}", "f".repeat(64))
        });
        assert!(matches!(
            validate_m1_reference_tool_result_v2(
                &bundle,
                "deployment.rollback.v2",
                &missing.to_string()
            ),
            Err(ToolMembraneError::JsonSchemaViolation { .. })
        ));
    }
}
