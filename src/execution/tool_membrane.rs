use crate::execution::capability::{
    ApprovalClass, AuthorityClass, CapabilityEnvelope, CapabilityWorld,
};
use crate::execution::turn_package::{
    ParsedToolCallIntentRecord, ParsedTurnResult, TurnContractError, TurnPackage, TurnPackageRole,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::future::Future;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelToolFamily {
    Continuity,
    Program,
    CandidateConstruction,
    WorkerEcology,
    ValidationObservation,
    Governance,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolExecutionDecision {
    Allowed,
    Denied,
    ApprovalBlocked,
    Quarantined,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolContextField {
    CampaignRef,
    EpochRef,
    TaskRef,
    PointerIndexRef,
    FactoryProgramInstanceRef,
    WorkspaceScopeRef,
    EcologySnapshotRef,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelToolDefinition {
    pub tool_id: String,
    pub family: ModelToolFamily,
    pub internal_service_ref: String,
    pub capability_world: CapabilityWorld,
    pub required_authority_class: AuthorityClass,
    pub default_approval_class: ApprovalClass,
    pub allowed_scope_refs: Vec<String>,
    pub required_context_fields: Vec<ToolContextField>,
    pub argument_schema_ref: String,
    pub result_schema_ref: String,
    pub role_compatibility: Vec<TurnPackageRole>,
    pub summary: String,
}

impl ModelToolDefinition {
    pub fn validate(&self) -> Result<(), ToolMembraneError> {
        require_nonempty(&self.tool_id, ToolMembraneError::MissingToolDefinitionId)?;
        require_nonempty(
            &self.internal_service_ref,
            ToolMembraneError::MissingInternalServiceRef,
        )?;
        validate_string_list(
            &self.allowed_scope_refs,
            ToolMembraneError::MissingAllowedScopeRefs,
        )?;
        if self.required_context_fields.is_empty() {
            return Err(ToolMembraneError::MissingRequiredContextFields);
        }
        require_nonempty(
            &self.argument_schema_ref,
            ToolMembraneError::MissingArgumentSchemaRef,
        )?;
        require_nonempty(
            &self.result_schema_ref,
            ToolMembraneError::MissingResultSchemaRef,
        )?;
        if self.role_compatibility.is_empty() {
            return Err(ToolMembraneError::MissingRoleCompatibility);
        }
        require_nonempty(&self.summary, ToolMembraneError::MissingSummary)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolCatalogRecord {
    pub tool_catalog_id: String,
    pub tool_definition_refs: Vec<String>,
    pub tool_catalog_json: String,
    pub summary: String,
    pub created_at: String,
}

impl ToolCatalogRecord {
    pub fn validate(&self) -> Result<(), ToolMembraneError> {
        require_nonempty(
            &self.tool_catalog_id,
            ToolMembraneError::MissingToolCatalogId,
        )?;
        validate_string_list(
            &self.tool_definition_refs,
            ToolMembraneError::MissingToolDefinitionRefs,
        )?;
        require_nonempty(
            &self.tool_catalog_json,
            ToolMembraneError::MissingToolCatalogJson,
        )?;
        let value = parse_json_payload(
            &self.tool_catalog_json,
            ToolMembraneError::InvalidToolCatalogJson,
        )?;
        if !value.is_array() {
            return Err(ToolMembraneError::InvalidToolCatalogJson);
        }
        require_nonempty(&self.summary, ToolMembraneError::MissingSummary)?;
        require_nonempty(&self.created_at, ToolMembraneError::MissingCreatedAt)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolArgumentSchemaRecord {
    pub tool_argument_schema_id: String,
    pub tool_definition_ref: String,
    pub argument_schema_json: String,
    pub created_at: String,
}

impl ToolArgumentSchemaRecord {
    pub fn validate(&self) -> Result<(), ToolMembraneError> {
        require_nonempty(
            &self.tool_argument_schema_id,
            ToolMembraneError::MissingToolArgumentSchemaId,
        )?;
        require_nonempty(
            &self.tool_definition_ref,
            ToolMembraneError::MissingToolDefinitionRef,
        )?;
        require_nonempty(
            &self.argument_schema_json,
            ToolMembraneError::MissingArgumentSchemaJson,
        )?;
        parse_json_payload(
            &self.argument_schema_json,
            ToolMembraneError::InvalidArgumentSchemaJson,
        )?;
        require_nonempty(&self.created_at, ToolMembraneError::MissingCreatedAt)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolResultSchemaRecord {
    pub tool_result_schema_id: String,
    pub tool_definition_ref: String,
    pub result_schema_json: String,
    pub created_at: String,
}

impl ToolResultSchemaRecord {
    pub fn validate(&self) -> Result<(), ToolMembraneError> {
        require_nonempty(
            &self.tool_result_schema_id,
            ToolMembraneError::MissingToolResultSchemaId,
        )?;
        require_nonempty(
            &self.tool_definition_ref,
            ToolMembraneError::MissingToolDefinitionRef,
        )?;
        require_nonempty(
            &self.result_schema_json,
            ToolMembraneError::MissingResultSchemaJson,
        )?;
        parse_json_payload(
            &self.result_schema_json,
            ToolMembraneError::InvalidResultSchemaJson,
        )?;
        require_nonempty(&self.created_at, ToolMembraneError::MissingCreatedAt)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolExecutionContextRecord {
    pub tool_execution_context_id: String,
    pub turn_package_ref: String,
    pub capability_envelope: CapabilityEnvelope,
    pub campaign_ref: Option<String>,
    pub epoch_ref: Option<String>,
    pub task_ref: Option<String>,
    pub pointer_index_ref: Option<String>,
    pub factory_program_instance_ref: Option<String>,
    pub workspace_scope_ref: Option<String>,
    pub ecology_snapshot_ref: Option<String>,
    pub created_at: String,
}

impl ToolExecutionContextRecord {
    pub fn validate(&self) -> Result<(), ToolMembraneError> {
        require_nonempty(
            &self.tool_execution_context_id,
            ToolMembraneError::MissingToolExecutionContextId,
        )?;
        require_nonempty(
            &self.turn_package_ref,
            ToolMembraneError::MissingTurnPackageRef,
        )?;
        for value in [
            self.campaign_ref.as_ref(),
            self.epoch_ref.as_ref(),
            self.task_ref.as_ref(),
            self.pointer_index_ref.as_ref(),
            self.factory_program_instance_ref.as_ref(),
            self.workspace_scope_ref.as_ref(),
            self.ecology_snapshot_ref.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            require_nonempty(value, ToolMembraneError::MissingContextValue)?;
        }
        require_nonempty(&self.created_at, ToolMembraneError::MissingCreatedAt)
    }

    pub fn context_value(&self, field: ToolContextField) -> Option<&str> {
        match field {
            ToolContextField::CampaignRef => self.campaign_ref.as_deref(),
            ToolContextField::EpochRef => self.epoch_ref.as_deref(),
            ToolContextField::TaskRef => self.task_ref.as_deref(),
            ToolContextField::PointerIndexRef => self.pointer_index_ref.as_deref(),
            ToolContextField::FactoryProgramInstanceRef => {
                self.factory_program_instance_ref.as_deref()
            }
            ToolContextField::WorkspaceScopeRef => self.workspace_scope_ref.as_deref(),
            ToolContextField::EcologySnapshotRef => self.ecology_snapshot_ref.as_deref(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolExposureDecisionRecord {
    pub tool_exposure_decision_id: String,
    pub tool_catalog_ref: String,
    pub tool_definition_ref: String,
    pub exposed: bool,
    pub rationale: String,
    pub created_at: String,
}

impl ToolExposureDecisionRecord {
    pub fn validate(&self) -> Result<(), ToolMembraneError> {
        require_nonempty(
            &self.tool_exposure_decision_id,
            ToolMembraneError::MissingToolExposureDecisionId,
        )?;
        require_nonempty(
            &self.tool_catalog_ref,
            ToolMembraneError::MissingToolCatalogRef,
        )?;
        require_nonempty(
            &self.tool_definition_ref,
            ToolMembraneError::MissingToolDefinitionRef,
        )?;
        require_nonempty(&self.rationale, ToolMembraneError::MissingRationale)?;
        require_nonempty(&self.created_at, ToolMembraneError::MissingCreatedAt)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolCallLegalityRecord {
    pub tool_legality_id: String,
    pub parsed_tool_call_intent_ref: String,
    pub parsed_turn_result_ref: String,
    pub turn_package_ref: String,
    pub tool_definition_ref: String,
    pub decision: ToolExecutionDecision,
    pub rationale: String,
    pub diagnostics: Vec<String>,
    pub created_at: String,
}

impl ToolCallLegalityRecord {
    pub fn validate(&self) -> Result<(), ToolMembraneError> {
        require_nonempty(
            &self.tool_legality_id,
            ToolMembraneError::MissingToolLegalityId,
        )?;
        require_nonempty(
            &self.parsed_tool_call_intent_ref,
            ToolMembraneError::MissingParsedToolIntentRef,
        )?;
        require_nonempty(
            &self.parsed_turn_result_ref,
            ToolMembraneError::MissingParsedTurnResultRef,
        )?;
        require_nonempty(
            &self.turn_package_ref,
            ToolMembraneError::MissingTurnPackageRef,
        )?;
        require_nonempty(
            &self.tool_definition_ref,
            ToolMembraneError::MissingToolDefinitionRef,
        )?;
        require_nonempty(&self.rationale, ToolMembraneError::MissingRationale)?;
        if self.diagnostics.iter().any(|item| item.trim().is_empty()) {
            return Err(ToolMembraneError::MissingDiagnostic);
        }
        require_nonempty(&self.created_at, ToolMembraneError::MissingCreatedAt)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolExecutionRecord {
    pub tool_execution_id: String,
    pub parsed_tool_call_intent_ref: String,
    pub parsed_turn_result_ref: String,
    pub tool_id: String,
    pub decision: ToolExecutionDecision,
    pub legality_ref: String,
    pub result_refs: Vec<String>,
    pub governance_refs: Vec<String>,
    pub diagnostics: Vec<String>,
    pub result_payload_json: Option<String>,
    pub governance_payload_json: Option<String>,
    pub created_at: String,
}

impl ToolExecutionRecord {
    pub fn validate(&self) -> Result<(), ToolMembraneError> {
        require_nonempty(
            &self.tool_execution_id,
            ToolMembraneError::MissingToolExecutionId,
        )?;
        require_nonempty(
            &self.parsed_tool_call_intent_ref,
            ToolMembraneError::MissingParsedToolIntentRef,
        )?;
        require_nonempty(
            &self.parsed_turn_result_ref,
            ToolMembraneError::MissingParsedTurnResultRef,
        )?;
        require_nonempty(&self.tool_id, ToolMembraneError::MissingToolId)?;
        require_nonempty(
            &self.legality_ref,
            ToolMembraneError::MissingToolLegalityRef,
        )?;
        if self.result_refs.iter().any(|item| item.trim().is_empty()) {
            return Err(ToolMembraneError::MissingResultRef);
        }
        if self
            .governance_refs
            .iter()
            .any(|item| item.trim().is_empty())
        {
            return Err(ToolMembraneError::MissingGovernanceRef);
        }
        if self.diagnostics.iter().any(|item| item.trim().is_empty()) {
            return Err(ToolMembraneError::MissingDiagnostic);
        }
        if let Some(payload) = &self.result_payload_json {
            parse_json_payload(payload, ToolMembraneError::InvalidResultPayloadJson)?;
        }
        if let Some(payload) = &self.governance_payload_json {
            parse_json_payload(payload, ToolMembraneError::InvalidGovernancePayloadJson)?;
        }
        require_nonempty(&self.created_at, ToolMembraneError::MissingCreatedAt)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorOnlySurfaceRecord {
    pub operator_only_surface_id: String,
    pub internal_service_ref: String,
    pub summary: String,
    pub reason: String,
    pub created_at: String,
}

impl OperatorOnlySurfaceRecord {
    pub fn validate(&self) -> Result<(), ToolMembraneError> {
        require_nonempty(
            &self.operator_only_surface_id,
            ToolMembraneError::MissingOperatorOnlySurfaceId,
        )?;
        require_nonempty(
            &self.internal_service_ref,
            ToolMembraneError::MissingInternalServiceRef,
        )?;
        require_nonempty(&self.summary, ToolMembraneError::MissingSummary)?;
        require_nonempty(&self.reason, ToolMembraneError::MissingRationale)?;
        require_nonempty(&self.created_at, ToolMembraneError::MissingCreatedAt)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedTurnToolExecutionReceipt {
    pub parsed_turn_tool_execution_receipt_id: String,
    pub parsed_turn_result_ref: String,
    pub attempted_tool_intent_refs: Vec<String>,
    pub tool_execution_refs: Vec<String>,
    pub terminal_decision: ToolExecutionDecision,
    pub stopped_after_tool_intent_ref: Option<String>,
    pub created_at: String,
}

impl ParsedTurnToolExecutionReceipt {
    pub fn validate(&self) -> Result<(), ToolMembraneError> {
        require_nonempty(
            &self.parsed_turn_tool_execution_receipt_id,
            ToolMembraneError::MissingParsedTurnToolExecutionReceiptId,
        )?;
        require_nonempty(
            &self.parsed_turn_result_ref,
            ToolMembraneError::MissingParsedTurnResultRef,
        )?;
        validate_string_list(
            &self.attempted_tool_intent_refs,
            ToolMembraneError::MissingAttemptedToolIntentRefs,
        )?;
        validate_string_list(
            &self.tool_execution_refs,
            ToolMembraneError::MissingToolExecutionRefs,
        )?;
        if let Some(reference) = &self.stopped_after_tool_intent_ref {
            require_nonempty(
                reference,
                ToolMembraneError::MissingStoppedAfterToolIntentRef,
            )?;
        }
        require_nonempty(&self.created_at, ToolMembraneError::MissingCreatedAt)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalToolCatalogBundle {
    pub catalog: ToolCatalogRecord,
    pub definitions: Vec<ModelToolDefinition>,
    pub argument_schemas: Vec<ToolArgumentSchemaRecord>,
    pub result_schemas: Vec<ToolResultSchemaRecord>,
    pub exposure_decisions: Vec<ToolExposureDecisionRecord>,
    pub operator_only_surfaces: Vec<OperatorOnlySurfaceRecord>,
}

impl CanonicalToolCatalogBundle {
    pub fn validate(&self) -> Result<(), ToolMembraneError> {
        self.catalog.validate()?;
        if self.definitions.is_empty() {
            return Err(ToolMembraneError::MissingToolDefinitions);
        }
        for definition in &self.definitions {
            definition.validate()?;
        }
        for schema in &self.argument_schemas {
            schema.validate()?;
        }
        for schema in &self.result_schemas {
            schema.validate()?;
        }
        for decision in &self.exposure_decisions {
            decision.validate()?;
        }
        for record in &self.operator_only_surfaces {
            record.validate()?;
        }
        Ok(())
    }

    pub fn definition(&self, tool_id: &str) -> Option<&ModelToolDefinition> {
        self.definitions
            .iter()
            .find(|definition| definition.tool_id == tool_id)
    }

    pub fn argument_schema_for(&self, tool_id: &str) -> Option<&ToolArgumentSchemaRecord> {
        let definition = self.definition(tool_id)?;
        self.argument_schemas
            .iter()
            .find(|schema| schema.tool_argument_schema_id == definition.argument_schema_ref)
    }

    pub fn result_schema_for(&self, tool_id: &str) -> Option<&ToolResultSchemaRecord> {
        let definition = self.definition(tool_id)?;
        self.result_schemas
            .iter()
            .find(|schema| schema.tool_result_schema_id == definition.result_schema_ref)
    }

    pub fn exposure_for(&self, tool_id: &str) -> Option<&ToolExposureDecisionRecord> {
        let definition = self.definition(tool_id)?;
        self.exposure_decisions
            .iter()
            .find(|decision| decision.tool_definition_ref == definition.tool_id)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolServiceExecutionOutcome {
    pub decision: ToolExecutionDecision,
    pub result_refs: Vec<String>,
    pub governance_refs: Vec<String>,
    pub diagnostics: Vec<String>,
    pub result_payload_json: Option<String>,
    pub governance_payload_json: Option<String>,
}

impl ToolServiceExecutionOutcome {
    pub fn validate(&self) -> Result<(), ToolMembraneError> {
        if self.result_refs.iter().any(|item| item.trim().is_empty()) {
            return Err(ToolMembraneError::MissingResultRef);
        }
        if self
            .governance_refs
            .iter()
            .any(|item| item.trim().is_empty())
        {
            return Err(ToolMembraneError::MissingGovernanceRef);
        }
        if self.diagnostics.iter().any(|item| item.trim().is_empty()) {
            return Err(ToolMembraneError::MissingDiagnostic);
        }
        if let Some(payload) = &self.result_payload_json {
            parse_json_payload(payload, ToolMembraneError::InvalidResultPayloadJson)?;
        }
        if let Some(payload) = &self.governance_payload_json {
            parse_json_payload(payload, ToolMembraneError::InvalidGovernancePayloadJson)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolExecutionBundle {
    pub definition: ModelToolDefinition,
    pub argument_schema: ToolArgumentSchemaRecord,
    pub result_schema: ToolResultSchemaRecord,
    pub exposure_decision: ToolExposureDecisionRecord,
    pub legality: ToolCallLegalityRecord,
    pub execution: ToolExecutionRecord,
}

impl ToolExecutionBundle {
    pub fn validate(&self) -> Result<(), ToolMembraneError> {
        self.definition.validate()?;
        self.argument_schema.validate()?;
        self.result_schema.validate()?;
        self.exposure_decision.validate()?;
        self.legality.validate()?;
        self.execution.validate()?;
        if self.argument_schema.tool_definition_ref != self.definition.tool_id {
            return Err(ToolMembraneError::SchemaToolMismatch);
        }
        if self.result_schema.tool_definition_ref != self.definition.tool_id {
            return Err(ToolMembraneError::SchemaToolMismatch);
        }
        if self.exposure_decision.tool_definition_ref != self.definition.tool_id {
            return Err(ToolMembraneError::ExposureToolMismatch);
        }
        if self.legality.tool_definition_ref != self.definition.tool_id {
            return Err(ToolMembraneError::LegalityToolMismatch);
        }
        if self.execution.tool_id != self.definition.tool_id {
            return Err(ToolMembraneError::ExecutionToolMismatch);
        }
        if self.execution.legality_ref != self.legality.tool_legality_id {
            return Err(ToolMembraneError::ExecutionLegalityMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedTurnToolExecutionBatch {
    pub receipt: ParsedTurnToolExecutionReceipt,
    pub executions: Vec<ToolExecutionBundle>,
}

impl ParsedTurnToolExecutionBatch {
    pub fn validate(&self) -> Result<(), ToolMembraneError> {
        self.receipt.validate()?;
        if self.executions.is_empty() {
            return Err(ToolMembraneError::MissingToolExecutionRefs);
        }
        for execution in &self.executions {
            execution.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ToolMembraneError {
    MissingToolCatalogId,
    MissingToolCatalogRef,
    MissingToolCatalogJson,
    InvalidToolCatalogJson,
    MissingToolDefinitions,
    MissingToolDefinitionId,
    MissingToolDefinitionRef,
    MissingToolDefinitionRefs,
    MissingToolArgumentSchemaId,
    MissingToolResultSchemaId,
    MissingToolExposureDecisionId,
    MissingToolLegalityId,
    MissingToolExecutionId,
    MissingOperatorOnlySurfaceId,
    MissingParsedTurnToolExecutionReceiptId,
    MissingAttemptedToolIntentRefs,
    MissingToolExecutionRefs,
    MissingStoppedAfterToolIntentRef,
    MissingInternalServiceRef,
    MissingAllowedScopeRefs,
    MissingRequiredContextFields,
    MissingArgumentSchemaRef,
    MissingResultSchemaRef,
    MissingRoleCompatibility,
    MissingArgumentSchemaJson,
    InvalidArgumentSchemaJson,
    MissingResultSchemaJson,
    InvalidResultSchemaJson,
    MissingToolExecutionContextId,
    MissingTurnPackageRef,
    MissingContextValue,
    MissingParsedToolIntentRef,
    MissingParsedTurnResultRef,
    MissingToolId,
    MissingToolLegalityRef,
    MissingResultRef,
    MissingGovernanceRef,
    MissingDiagnostic,
    MissingSummary,
    MissingRationale,
    MissingCreatedAt,
    InvalidResultPayloadJson,
    InvalidGovernancePayloadJson,
    ToolNotFound {
        tool_id: String,
    },
    ToolNotExposed {
        tool_id: String,
    },
    ToolNotRoleCompatible {
        tool_id: String,
        role: TurnPackageRole,
    },
    MissingExecutionContextField {
        field: ToolContextField,
    },
    ScopeKindNotAllowed {
        tool_id: String,
        scope_kind: String,
    },
    ScopeValueNotAllowed {
        tool_id: String,
        scope_ref: String,
    },
    WorldNotGranted {
        tool_id: String,
        world: CapabilityWorld,
    },
    OperationNotAllowed {
        tool_id: String,
        operation: String,
    },
    AuthorityExceeded {
        tool_id: String,
        required: AuthorityClass,
        ceiling: AuthorityClass,
    },
    SchemaToolMismatch,
    ExposureToolMismatch,
    LegalityToolMismatch,
    ExecutionToolMismatch,
    ExecutionLegalityMismatch,
    OutcomeDecisionMismatch {
        expected: ToolExecutionDecision,
        actual: ToolExecutionDecision,
    },
    JsonSchemaViolation {
        field: String,
        reason: String,
    },
    TurnContract(String),
    ServiceFailure {
        tool_id: String,
        reason: String,
    },
}

impl Display for ToolMembraneError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ToolNotFound { tool_id } => write!(f, "tool '{tool_id}' is not defined"),
            Self::ToolNotExposed { tool_id } => write!(f, "tool '{tool_id}' is not model-facing"),
            Self::ToolNotRoleCompatible { tool_id, role } => {
                write!(f, "tool '{tool_id}' is not compatible with role {role:?}")
            }
            Self::MissingExecutionContextField { field } => {
                write!(
                    f,
                    "tool execution context is missing required field {field:?}"
                )
            }
            Self::ScopeKindNotAllowed {
                tool_id,
                scope_kind,
            } => write!(
                f,
                "tool '{tool_id}' is not allowed to use scope kind '{scope_kind}'"
            ),
            Self::ScopeValueNotAllowed { tool_id, scope_ref } => write!(
                f,
                "tool '{tool_id}' cannot use scope '{scope_ref}' under the active envelope"
            ),
            Self::WorldNotGranted { tool_id, world } => write!(
                f,
                "tool '{tool_id}' requires capability world {world:?} which is absent from the envelope"
            ),
            Self::OperationNotAllowed { tool_id, operation } => write!(
                f,
                "tool '{tool_id}' requires operation '{operation}' which is not allowed by the envelope"
            ),
            Self::AuthorityExceeded {
                tool_id,
                required,
                ceiling,
            } => write!(
                f,
                "tool '{tool_id}' requires authority {required:?} which exceeds envelope ceiling {ceiling:?}"
            ),
            Self::OutcomeDecisionMismatch { expected, actual } => write!(
                f,
                "tool service outcome decision {actual:?} does not match expected membrane decision {expected:?}"
            ),
            Self::JsonSchemaViolation { field, reason } => {
                write!(f, "JSON schema violation for '{field}': {reason}")
            }
            Self::TurnContract(reason) => write!(f, "turn package contract error: {reason}"),
            Self::ServiceFailure { tool_id, reason } => {
                write!(f, "tool '{tool_id}' service execution failed: {reason}")
            }
            other => write!(f, "{other:?}"),
        }
    }
}

impl Error for ToolMembraneError {}

impl From<TurnContractError> for ToolMembraneError {
    fn from(value: TurnContractError) -> Self {
        Self::TurnContract(value.to_string())
    }
}

pub fn build_canonical_tool_catalog() -> Result<CanonicalToolCatalogBundle, ToolMembraneError> {
    let timestamp = current_timestamp();
    let definitions = vec![
        model_tool_definition(
            "continuity.retrieve",
            ModelToolFamily::Continuity,
            "service:continuity:retrieve",
            CapabilityWorld::MemoryAccess,
            AuthorityClass::Observe,
            ApprovalClass::SupervisorAllowed,
            vec!["pointer-index-ref"],
            vec![ToolContextField::PointerIndexRef],
            vec![TurnPackageRole::Supervisor, TurnPackageRole::Worker],
            "Retrieve bounded continuity bundles, transcript slices, and evidence.",
        ),
        model_tool_definition(
            "continuity.inspect_open_questions",
            ModelToolFamily::Continuity,
            "service:continuity:inspect-open-questions",
            CapabilityWorld::MemoryAccess,
            AuthorityClass::Observe,
            ApprovalClass::SupervisorAllowed,
            vec!["pointer-index-ref"],
            vec![ToolContextField::PointerIndexRef],
            vec![TurnPackageRole::Supervisor, TurnPackageRole::Worker],
            "Inspect unresolved contradictions and open questions for the current continuity scope.",
        ),
        model_tool_definition(
            "continuity.propose_update",
            ModelToolFamily::Continuity,
            "service:continuity:propose-update",
            CapabilityWorld::MemoryAccess,
            AuthorityClass::LocalMutate,
            ApprovalClass::SupervisorAllowed,
            vec!["pointer-index-ref"],
            vec![ToolContextField::PointerIndexRef],
            vec![TurnPackageRole::Supervisor, TurnPackageRole::Worker],
            "Propose a verified memory update backed by evidence and verification refs.",
        ),
        model_tool_definition(
            "program.inspect",
            ModelToolFamily::Program,
            "service:program:inspect",
            CapabilityWorld::CampaignControl,
            AuthorityClass::Observe,
            ApprovalClass::SupervisorAllowed,
            vec!["factory-program-instance-ref"],
            vec![ToolContextField::FactoryProgramInstanceRef],
            vec![TurnPackageRole::Supervisor],
            "Inspect the active factory-program state, receipts, and lineage posture.",
        ),
        model_tool_definition(
            "program.inspect_lineage_health",
            ModelToolFamily::Program,
            "service:program:inspect-lineage-health",
            CapabilityWorld::ReviewPromotion,
            AuthorityClass::Observe,
            ApprovalClass::SupervisorAllowed,
            vec!["factory-program-instance-ref"],
            vec![ToolContextField::FactoryProgramInstanceRef],
            vec![TurnPackageRole::Supervisor],
            "Inspect longitudinal lineage-health and regression posture for the active program.",
        ),
        model_tool_definition(
            "program.submit_cycle_decision",
            ModelToolFamily::Program,
            "service:program:submit-cycle-decision",
            CapabilityWorld::ReviewPromotion,
            AuthorityClass::PromotionControl,
            ApprovalClass::HumanRequired,
            vec!["factory-program-instance-ref"],
            vec![
                ToolContextField::FactoryProgramInstanceRef,
                ToolContextField::CampaignRef,
                ToolContextField::EpochRef,
            ],
            vec![TurnPackageRole::Supervisor],
            "Submit a governed cycle decision for the active bounded factory program.",
        ),
        model_tool_definition(
            "program.raise_stop_condition",
            ModelToolFamily::Program,
            "service:program:raise-stop-condition",
            CapabilityWorld::CampaignControl,
            AuthorityClass::CampaignControl,
            ApprovalClass::SupervisorAllowed,
            vec!["factory-program-instance-ref"],
            vec![ToolContextField::FactoryProgramInstanceRef],
            vec![TurnPackageRole::Supervisor],
            "Raise a bounded stop-condition recommendation for the active factory program.",
        ),
        model_tool_definition(
            "candidate.open_workspace",
            ModelToolFamily::CandidateConstruction,
            "service:candidate:open-workspace",
            CapabilityWorld::WorkspaceMutate,
            AuthorityClass::LocalMutate,
            ApprovalClass::SupervisorAllowed,
            vec!["workspace-scope-ref"],
            vec![ToolContextField::WorkspaceScopeRef],
            vec![TurnPackageRole::Supervisor, TurnPackageRole::Worker],
            "Open a disposable candidate workspace inside the bounded scope.",
        ),
        model_tool_definition(
            "candidate.materialize_patchset",
            ModelToolFamily::CandidateConstruction,
            "service:candidate:materialize-patchset",
            CapabilityWorld::WorkspaceMutate,
            AuthorityClass::LocalMutate,
            ApprovalClass::SupervisorAllowed,
            vec!["workspace-scope-ref"],
            vec![ToolContextField::WorkspaceScopeRef],
            vec![TurnPackageRole::Supervisor, TurnPackageRole::Worker],
            "Materialize a bounded patchset inside the candidate workspace.",
        ),
        model_tool_definition(
            "candidate.package",
            ModelToolFamily::CandidateConstruction,
            "service:candidate:package",
            CapabilityWorld::ServiceOrganelle,
            AuthorityClass::LocalMutate,
            ApprovalClass::SupervisorAllowed,
            vec!["workspace-scope-ref"],
            vec![ToolContextField::WorkspaceScopeRef],
            vec![TurnPackageRole::Supervisor, TurnPackageRole::Worker],
            "Package the bounded candidate artifact behind the stable interface boundary.",
        ),
        model_tool_definition(
            "ecology.inspect",
            ModelToolFamily::WorkerEcology,
            "service:ecology:inspect",
            CapabilityWorld::WorkerMessaging,
            AuthorityClass::Observe,
            ApprovalClass::SupervisorAllowed,
            vec!["ecology-snapshot-ref"],
            vec![ToolContextField::EcologySnapshotRef],
            vec![TurnPackageRole::Supervisor, TurnPackageRole::Worker],
            "Inspect worker cards, leases, routing posture, and ecology health.",
        ),
        model_tool_definition(
            "ecology.dispatch_worker",
            ModelToolFamily::WorkerEcology,
            "service:ecology:dispatch-worker",
            CapabilityWorld::WorkerMessaging,
            AuthorityClass::CampaignControl,
            ApprovalClass::SupervisorAllowed,
            vec!["task-ref"],
            vec![ToolContextField::TaskRef],
            vec![TurnPackageRole::Supervisor, TurnPackageRole::Worker],
            "Dispatch a bounded worker under the active envelope and task scope.",
        ),
        model_tool_definition(
            "ecology.collect_results",
            ModelToolFamily::WorkerEcology,
            "service:ecology:collect-results",
            CapabilityWorld::WorkerMessaging,
            AuthorityClass::Observe,
            ApprovalClass::SupervisorAllowed,
            vec!["task-ref"],
            vec![ToolContextField::TaskRef],
            vec![TurnPackageRole::Supervisor, TurnPackageRole::Worker],
            "Collect bounded worker results and synthesis-ready refs.",
        ),
        model_tool_definition(
            "validation.run_proving",
            ModelToolFamily::ValidationObservation,
            "service:validation:run-proving",
            CapabilityWorld::ServiceOrganelle,
            AuthorityClass::CampaignControl,
            ApprovalClass::SupervisorAllowed,
            vec!["workspace-scope-ref"],
            vec![ToolContextField::WorkspaceScopeRef],
            vec![TurnPackageRole::Supervisor],
            "Run bounded proving workloads against the active candidate scope.",
        ),
        model_tool_definition(
            "validation.record_observation",
            ModelToolFamily::ValidationObservation,
            "service:validation:record-observation",
            CapabilityWorld::ReviewPromotion,
            AuthorityClass::Observe,
            ApprovalClass::SupervisorAllowed,
            vec!["factory-program-instance-ref"],
            vec![ToolContextField::FactoryProgramInstanceRef],
            vec![TurnPackageRole::Supervisor],
            "Record a bounded observation window and resulting risk posture.",
        ),
        model_tool_definition(
            "validation.compare_candidate",
            ModelToolFamily::ValidationObservation,
            "service:validation:compare-candidate",
            CapabilityWorld::ReviewPromotion,
            AuthorityClass::PromotionControl,
            ApprovalClass::SupervisorAllowed,
            vec!["factory-program-instance-ref"],
            vec![ToolContextField::FactoryProgramInstanceRef],
            vec![TurnPackageRole::Supervisor],
            "Compare candidate versus incumbent and emit a bounded comparison artifact.",
        ),
        model_tool_definition(
            "governance.request_approval",
            ModelToolFamily::Governance,
            "service:governance:request-approval",
            CapabilityWorld::ApprovalGateway,
            AuthorityClass::SensitiveAccess,
            ApprovalClass::HumanRequired,
            vec!["task-ref"],
            vec![ToolContextField::TaskRef],
            vec![TurnPackageRole::Supervisor, TurnPackageRole::Worker],
            "Request approval for a blocked action under bounded governance law.",
        ),
        model_tool_definition(
            "governance.inspect_constraints",
            ModelToolFamily::Governance,
            "service:governance:inspect-constraints",
            CapabilityWorld::ApprovalGateway,
            AuthorityClass::Observe,
            ApprovalClass::SupervisorAllowed,
            vec!["task-ref"],
            vec![ToolContextField::TaskRef],
            vec![TurnPackageRole::Supervisor, TurnPackageRole::Worker],
            "Inspect approval, rollback, and quarantine constraints in scope.",
        ),
        model_tool_definition(
            "governance.recommend_quarantine",
            ModelToolFamily::Governance,
            "service:governance:recommend-quarantine",
            CapabilityWorld::ReviewPromotion,
            AuthorityClass::PromotionControl,
            ApprovalClass::HumanRequired,
            vec!["task-ref"],
            vec![ToolContextField::TaskRef],
            vec![TurnPackageRole::Supervisor],
            "Recommend quarantine with explicit evidence without mutating operator-only state.",
        ),
    ];

    let argument_schemas = definitions
        .iter()
        .map(|definition| ToolArgumentSchemaRecord {
            tool_argument_schema_id: format!("tool-argument-schema:{}", definition.tool_id),
            tool_definition_ref: definition.tool_id.clone(),
            argument_schema_json: canonical_argument_schema_json(&definition.tool_id).to_string(),
            created_at: timestamp.clone(),
        })
        .collect::<Vec<_>>();
    let result_schemas = definitions
        .iter()
        .map(|definition| ToolResultSchemaRecord {
            tool_result_schema_id: format!("tool-result-schema:{}", definition.tool_id),
            tool_definition_ref: definition.tool_id.clone(),
            result_schema_json: canonical_result_schema_json(&definition.tool_id).to_string(),
            created_at: timestamp.clone(),
        })
        .collect::<Vec<_>>();
    let catalog_json = serde_json::to_string(
        &definitions
            .iter()
            .map(|definition| {
                json!({
                    "type": "function",
                    "name": definition.tool_id,
                    "description": definition.summary,
                    "parameters": canonical_argument_schema_json(&definition.tool_id),
                })
            })
            .collect::<Vec<_>>(),
    )
    .map_err(|error| ToolMembraneError::ServiceFailure {
        tool_id: "tool-catalog".to_string(),
        reason: error.to_string(),
    })?;
    let catalog = ToolCatalogRecord {
        tool_catalog_id: "tool-catalog:canonical:v1".to_string(),
        tool_definition_refs: definitions
            .iter()
            .map(|definition| definition.tool_id.clone())
            .collect(),
        tool_catalog_json: catalog_json,
        summary:
            "Canonical Wasm-Biotic model-facing tool catalog for the current-line LLM membrane."
                .to_string(),
        created_at: timestamp.clone(),
    };
    let exposure_decisions = definitions
        .iter()
        .map(|definition| ToolExposureDecisionRecord {
            tool_exposure_decision_id: format!("tool-exposure:{}", definition.tool_id),
            tool_catalog_ref: catalog.tool_catalog_id.clone(),
            tool_definition_ref: definition.tool_id.clone(),
            exposed: true,
            rationale:
                "Tool is intentionally model-facing inside the bounded Wasm-Biotic membrane."
                    .to_string(),
            created_at: timestamp.clone(),
        })
        .collect::<Vec<_>>();
    let operator_only_surfaces = vec![
        operator_only_surface(
            "operator-surface:approval-grant",
            "service:operator:approval-grant",
            "Grant approval",
            "Operator-only approval release remains outside the model-facing membrane.",
            &timestamp,
        ),
        operator_only_surface(
            "operator-surface:approval-deny",
            "service:operator:approval-deny",
            "Deny approval",
            "Operator-only denial remains outside the model-facing membrane.",
            &timestamp,
        ),
        operator_only_surface(
            "operator-surface:approval-expire",
            "service:operator:approval-expire",
            "Expire approval",
            "Approval expiration remains operator-owned.",
            &timestamp,
        ),
        operator_only_surface(
            "operator-surface:approval-escalate",
            "service:operator:approval-escalate",
            "Escalate approval",
            "Escalation remains operator-owned.",
            &timestamp,
        ),
        operator_only_surface(
            "operator-surface:execute-rollback",
            "service:operator:execute-rollback",
            "Execute rollback",
            "Rollback execution remains operator-only in the current line.",
            &timestamp,
        ),
        operator_only_surface(
            "operator-surface:forced-program-tick",
            "service:operator:forced-program-tick",
            "Forced program tick",
            "Direct forced adoption/tick mutation remains operator-only.",
            &timestamp,
        ),
        operator_only_surface(
            "operator-surface:emergency-stop",
            "service:operator:emergency-stop",
            "Emergency stop or archive",
            "Emergency controls remain operator-only.",
            &timestamp,
        ),
        operator_only_surface(
            "operator-surface:raw-shell",
            "service:operator:raw-shell",
            "Raw shell access",
            "Ambient shell access is never model-facing.",
            &timestamp,
        ),
    ];

    let bundle = CanonicalToolCatalogBundle {
        catalog,
        definitions,
        argument_schemas,
        result_schemas,
        exposure_decisions,
        operator_only_surfaces,
    };
    bundle.validate()?;
    Ok(bundle)
}

pub fn render_tool_catalog_json_for_role(
    bundle: &CanonicalToolCatalogBundle,
    role: TurnPackageRole,
) -> Result<String, ToolMembraneError> {
    bundle.validate()?;
    let tools = bundle
        .definitions
        .iter()
        .filter(|definition| definition.role_compatibility.contains(&role))
        .map(|definition| {
            let argument_schema = bundle
                .argument_schema_for(&definition.tool_id)
                .ok_or(ToolMembraneError::MissingArgumentSchemaRef)
                .and_then(|record| {
                    parse_json_payload(
                        &record.argument_schema_json,
                        ToolMembraneError::InvalidArgumentSchemaJson,
                    )
                })?;
            Ok(json!({
                "type": "function",
                "name": definition.tool_id,
                "description": definition.summary,
                "parameters": argument_schema,
            }))
        })
        .collect::<Result<Vec<_>, ToolMembraneError>>()?;
    serde_json::to_string(&tools).map_err(|error| ToolMembraneError::ServiceFailure {
        tool_id: "tool-catalog".to_string(),
        reason: error.to_string(),
    })
}

pub fn evaluate_tool_call_legality(
    definition: &ModelToolDefinition,
    argument_schema: &ToolArgumentSchemaRecord,
    exposure_decision: &ToolExposureDecisionRecord,
    turn_package: &TurnPackage,
    parsed_result: &ParsedTurnResult,
    intent: &ParsedToolCallIntentRecord,
    context: &ToolExecutionContextRecord,
) -> Result<ToolCallLegalityRecord, ToolMembraneError> {
    definition.validate()?;
    argument_schema.validate()?;
    exposure_decision.validate()?;
    turn_package.validate()?;
    parsed_result.validate()?;
    intent.validate().map_err(ToolMembraneError::from)?;
    context.validate()?;
    if context.turn_package_ref != turn_package.turn_package_id {
        return Err(ToolMembraneError::TurnContract(
            "tool execution context does not match turn package".to_string(),
        ));
    }
    if argument_schema.tool_definition_ref != definition.tool_id {
        return Err(ToolMembraneError::SchemaToolMismatch);
    }
    if exposure_decision.tool_definition_ref != definition.tool_id {
        return Err(ToolMembraneError::ExposureToolMismatch);
    }
    if !exposure_decision.exposed {
        return Err(ToolMembraneError::ToolNotExposed {
            tool_id: definition.tool_id.clone(),
        });
    }
    if !definition.role_compatibility.contains(&turn_package.role) {
        return Err(ToolMembraneError::ToolNotRoleCompatible {
            tool_id: definition.tool_id.clone(),
            role: turn_package.role,
        });
    }
    validate_json_against_schema(
        "arguments",
        &intent.arguments_json,
        &argument_schema.argument_schema_json,
    )?;

    let (scope_kind, scope_value) = resolve_effective_scope(definition, context)?;
    if !definition
        .allowed_scope_refs
        .iter()
        .any(|allowed| allowed == scope_kind)
    {
        return Err(ToolMembraneError::ScopeKindNotAllowed {
            tool_id: definition.tool_id.clone(),
            scope_kind: scope_kind.to_string(),
        });
    }
    let envelope = &context.capability_envelope;
    if !envelope.grants_world(&definition.capability_world) {
        return Ok(ToolCallLegalityRecord {
            tool_legality_id: legality_id(intent),
            parsed_tool_call_intent_ref: intent.parsed_tool_call_intent_id.clone(),
            parsed_turn_result_ref: parsed_result.parsed_turn_result_id.clone(),
            turn_package_ref: turn_package.turn_package_id.clone(),
            tool_definition_ref: definition.tool_id.clone(),
            decision: ToolExecutionDecision::Denied,
            rationale: format!(
                "capability world {:?} is missing from envelope {}",
                definition.capability_world, envelope.envelope_id
            ),
            diagnostics: Vec::new(),
            created_at: current_timestamp(),
        });
    }
    if !envelope.allows_operation(&definition.capability_world, &definition.tool_id) {
        return Ok(ToolCallLegalityRecord {
            tool_legality_id: legality_id(intent),
            parsed_tool_call_intent_ref: intent.parsed_tool_call_intent_id.clone(),
            parsed_turn_result_ref: parsed_result.parsed_turn_result_id.clone(),
            turn_package_ref: turn_package.turn_package_id.clone(),
            tool_definition_ref: definition.tool_id.clone(),
            decision: ToolExecutionDecision::Denied,
            rationale: format!(
                "operation '{}' is not allowed for {:?} in envelope {}",
                definition.tool_id, definition.capability_world, envelope.envelope_id
            ),
            diagnostics: Vec::new(),
            created_at: current_timestamp(),
        });
    }
    if !envelope.authority_allows(&definition.required_authority_class) {
        return Ok(ToolCallLegalityRecord {
            tool_legality_id: legality_id(intent),
            parsed_tool_call_intent_ref: intent.parsed_tool_call_intent_id.clone(),
            parsed_turn_result_ref: parsed_result.parsed_turn_result_id.clone(),
            turn_package_ref: turn_package.turn_package_id.clone(),
            tool_definition_ref: definition.tool_id.clone(),
            decision: ToolExecutionDecision::Denied,
            rationale: format!(
                "required authority {:?} exceeds envelope ceiling {:?}",
                definition.required_authority_class, envelope.authority_ceiling
            ),
            diagnostics: Vec::new(),
            created_at: current_timestamp(),
        });
    }
    if !envelope.scope_allows(scope_value) {
        return Ok(ToolCallLegalityRecord {
            tool_legality_id: legality_id(intent),
            parsed_tool_call_intent_ref: intent.parsed_tool_call_intent_id.clone(),
            parsed_turn_result_ref: parsed_result.parsed_turn_result_id.clone(),
            turn_package_ref: turn_package.turn_package_id.clone(),
            tool_definition_ref: definition.tool_id.clone(),
            decision: ToolExecutionDecision::Denied,
            rationale: format!(
                "scope '{}' is not allowed by envelope {}",
                scope_value, envelope.envelope_id
            ),
            diagnostics: Vec::new(),
            created_at: current_timestamp(),
        });
    }

    let approval_class = envelope
        .approval_for(&definition.capability_world, &definition.tool_id)
        .unwrap_or(definition.default_approval_class.clone());
    let (decision, rationale) = match approval_class {
        ApprovalClass::AutoAllowed | ApprovalClass::SupervisorAllowed => (
            ToolExecutionDecision::Allowed,
            "tool call is allowed through the bounded Wasm-Biotic membrane".to_string(),
        ),
        ApprovalClass::HumanRequired => (
            ToolExecutionDecision::ApprovalBlocked,
            "tool call requires explicit approval before execution".to_string(),
        ),
        ApprovalClass::QuarantineOnExpand => (
            ToolExecutionDecision::Quarantined,
            "tool call is quarantined by the active approval posture".to_string(),
        ),
        ApprovalClass::Forbidden => (
            ToolExecutionDecision::Denied,
            "tool call is forbidden by the active approval posture".to_string(),
        ),
    };

    Ok(ToolCallLegalityRecord {
        tool_legality_id: legality_id(intent),
        parsed_tool_call_intent_ref: intent.parsed_tool_call_intent_id.clone(),
        parsed_turn_result_ref: parsed_result.parsed_turn_result_id.clone(),
        turn_package_ref: turn_package.turn_package_id.clone(),
        tool_definition_ref: definition.tool_id.clone(),
        decision,
        rationale,
        diagnostics: Vec::new(),
        created_at: current_timestamp(),
    })
}

pub async fn execute_parsed_tool_intent<F, Fut>(
    bundle: &CanonicalToolCatalogBundle,
    turn_package: &TurnPackage,
    parsed_result: &ParsedTurnResult,
    intent: &ParsedToolCallIntentRecord,
    context: &ToolExecutionContextRecord,
    mut execute_service: F,
) -> Result<ToolExecutionBundle, ToolMembraneError>
where
    F: FnMut(
        &ModelToolDefinition,
        &ToolCallLegalityRecord,
        &ParsedToolCallIntentRecord,
        &ToolExecutionContextRecord,
    ) -> Fut,
    Fut: Future<Output = Result<ToolServiceExecutionOutcome, ToolMembraneError>>,
{
    bundle.validate()?;
    turn_package.validate()?;
    parsed_result.validate()?;
    intent.validate().map_err(ToolMembraneError::from)?;
    context.validate()?;

    let definition = bundle.definition(&intent.tool_id).cloned().ok_or_else(|| {
        ToolMembraneError::ToolNotFound {
            tool_id: intent.tool_id.clone(),
        }
    })?;
    let argument_schema = bundle
        .argument_schema_for(&intent.tool_id)
        .cloned()
        .ok_or(ToolMembraneError::MissingArgumentSchemaRef)?;
    let result_schema = bundle
        .result_schema_for(&intent.tool_id)
        .cloned()
        .ok_or(ToolMembraneError::MissingResultSchemaRef)?;
    let exposure_decision = bundle
        .exposure_for(&intent.tool_id)
        .cloned()
        .ok_or_else(|| ToolMembraneError::ToolNotExposed {
            tool_id: intent.tool_id.clone(),
        })?;
    let legality = evaluate_tool_call_legality(
        &definition,
        &argument_schema,
        &exposure_decision,
        turn_package,
        parsed_result,
        intent,
        context,
    )?;
    let service_outcome = execute_service(&definition, &legality, intent, context).await?;
    service_outcome.validate()?;
    if service_outcome.decision != legality.decision
        && !(legality.decision == ToolExecutionDecision::Allowed
            && service_outcome.decision == ToolExecutionDecision::Failed)
    {
        return Err(ToolMembraneError::OutcomeDecisionMismatch {
            expected: legality.decision,
            actual: service_outcome.decision,
        });
    }
    if legality.decision == ToolExecutionDecision::Allowed {
        let payload = service_outcome
            .result_payload_json
            .as_ref()
            .ok_or_else(|| ToolMembraneError::ServiceFailure {
                tool_id: definition.tool_id.clone(),
                reason: "allowed tool execution did not return a result payload".to_string(),
            })?;
        validate_json_against_schema("result", payload, &result_schema.result_schema_json)?;
    }
    let execution = ToolExecutionRecord {
        tool_execution_id: format!(
            "tool-execution:{}:{}",
            sanitize_id(&intent.parsed_tool_call_intent_id),
            current_timestamp()
        ),
        parsed_tool_call_intent_ref: intent.parsed_tool_call_intent_id.clone(),
        parsed_turn_result_ref: parsed_result.parsed_turn_result_id.clone(),
        tool_id: definition.tool_id.clone(),
        decision: service_outcome.decision,
        legality_ref: legality.tool_legality_id.clone(),
        result_refs: service_outcome.result_refs.clone(),
        governance_refs: service_outcome.governance_refs.clone(),
        diagnostics: service_outcome.diagnostics.clone(),
        result_payload_json: service_outcome.result_payload_json.clone(),
        governance_payload_json: service_outcome.governance_payload_json.clone(),
        created_at: current_timestamp(),
    };
    let bundle = ToolExecutionBundle {
        definition,
        argument_schema,
        result_schema,
        exposure_decision,
        legality,
        execution,
    };
    bundle.validate()?;
    Ok(bundle)
}

pub async fn execute_parsed_turn_tool_intents<F, Fut>(
    bundle: &CanonicalToolCatalogBundle,
    turn_package: &TurnPackage,
    parsed_result: &ParsedTurnResult,
    intents: &[ParsedToolCallIntentRecord],
    context: &ToolExecutionContextRecord,
    mut execute_service: F,
) -> Result<ParsedTurnToolExecutionBatch, ToolMembraneError>
where
    F: FnMut(
        &ModelToolDefinition,
        &ToolCallLegalityRecord,
        &ParsedToolCallIntentRecord,
        &ToolExecutionContextRecord,
    ) -> Fut,
    Fut: Future<Output = Result<ToolServiceExecutionOutcome, ToolMembraneError>>,
{
    if intents.is_empty() {
        return Err(ToolMembraneError::MissingAttemptedToolIntentRefs);
    }

    let mut executions = Vec::new();
    let mut attempted = Vec::new();
    let mut terminal_decision = ToolExecutionDecision::Allowed;
    let mut stopped_after = None;
    for intent in intents {
        attempted.push(intent.parsed_tool_call_intent_id.clone());
        let execution = execute_parsed_tool_intent(
            bundle,
            turn_package,
            parsed_result,
            intent,
            context,
            &mut execute_service,
        )
        .await?;
        terminal_decision = execution.execution.decision;
        let is_terminal = execution.execution.decision != ToolExecutionDecision::Allowed;
        if is_terminal {
            stopped_after = Some(intent.parsed_tool_call_intent_id.clone());
        }
        executions.push(execution);
        if is_terminal {
            break;
        }
    }

    let receipt = ParsedTurnToolExecutionReceipt {
        parsed_turn_tool_execution_receipt_id: format!(
            "parsed-turn-tool-execution-receipt:{}:{}",
            sanitize_id(&parsed_result.parsed_turn_result_id),
            current_timestamp()
        ),
        parsed_turn_result_ref: parsed_result.parsed_turn_result_id.clone(),
        attempted_tool_intent_refs: attempted,
        tool_execution_refs: executions
            .iter()
            .map(|execution| execution.execution.tool_execution_id.clone())
            .collect(),
        terminal_decision,
        stopped_after_tool_intent_ref: stopped_after,
        created_at: current_timestamp(),
    };
    let batch = ParsedTurnToolExecutionBatch {
        receipt,
        executions,
    };
    batch.validate()?;
    Ok(batch)
}

fn model_tool_definition(
    tool_id: &str,
    family: ModelToolFamily,
    internal_service_ref: &str,
    capability_world: CapabilityWorld,
    required_authority_class: AuthorityClass,
    default_approval_class: ApprovalClass,
    allowed_scope_refs: Vec<&str>,
    required_context_fields: Vec<ToolContextField>,
    role_compatibility: Vec<TurnPackageRole>,
    summary: &str,
) -> ModelToolDefinition {
    ModelToolDefinition {
        tool_id: tool_id.to_string(),
        family,
        internal_service_ref: internal_service_ref.to_string(),
        capability_world,
        required_authority_class,
        default_approval_class,
        allowed_scope_refs: allowed_scope_refs.into_iter().map(str::to_string).collect(),
        required_context_fields,
        argument_schema_ref: format!("tool-argument-schema:{tool_id}"),
        result_schema_ref: format!("tool-result-schema:{tool_id}"),
        role_compatibility,
        summary: summary.to_string(),
    }
}

fn operator_only_surface(
    operator_only_surface_id: &str,
    internal_service_ref: &str,
    summary: &str,
    reason: &str,
    created_at: &str,
) -> OperatorOnlySurfaceRecord {
    OperatorOnlySurfaceRecord {
        operator_only_surface_id: operator_only_surface_id.to_string(),
        internal_service_ref: internal_service_ref.to_string(),
        summary: summary.to_string(),
        reason: reason.to_string(),
        created_at: created_at.to_string(),
    }
}

fn canonical_argument_schema_json(tool_id: &str) -> Value {
    match tool_id {
        "continuity.retrieve" => json!({
            "type": "object",
            "properties": {
                "bundle_class": { "type": "string" },
                "search_term": { "type": "string" },
                "max_bundle_refs": { "type": "integer" }
            },
            "additionalProperties": false
        }),
        "continuity.inspect_open_questions" => empty_object_schema(),
        "continuity.propose_update" => json!({
            "type": "object",
            "properties": {
                "summary": { "type": "string" },
                "evidence_refs": string_array_schema(),
                "verification_refs": string_array_schema()
            },
            "required": ["summary", "evidence_refs", "verification_refs"],
            "additionalProperties": false
        }),
        "program.inspect" | "program.inspect_lineage_health" | "ecology.inspect" => {
            empty_object_schema()
        }
        "program.submit_cycle_decision" => json!({
            "type": "object",
            "properties": {
                "candidate_factory_ref": { "type": "string" },
                "proving_refs": string_array_schema(),
                "observation_refs": string_array_schema(),
                "comparison_refs": string_array_schema(),
                "risk_refs": string_array_schema(),
                "trend_refs": string_array_schema(),
                "rollback_refs": string_array_schema(),
                "decision": {
                    "type": "string",
                    "enum": ["adopted", "refused", "rolled_back", "paused"]
                },
                "operator_note": { "type": "string" }
            },
            "required": [
                "candidate_factory_ref",
                "proving_refs",
                "observation_refs",
                "comparison_refs",
                "risk_refs",
                "trend_refs",
                "rollback_refs",
                "decision",
                "operator_note"
            ],
            "additionalProperties": false
        }),
        "program.raise_stop_condition" => json!({
            "type": "object",
            "properties": {
                "decision": {
                    "type": "string",
                    "enum": ["continue", "constrain", "pause", "stop"]
                },
                "trigger_refs": string_array_schema(),
                "operator_guidance": { "type": "string" }
            },
            "required": ["decision", "trigger_refs", "operator_guidance"],
            "additionalProperties": false
        }),
        "candidate.open_workspace" => json!({
            "type": "object",
            "properties": {
                "workspace_label": { "type": "string" },
                "candidate_factory_ref": { "type": "string" }
            },
            "required": ["workspace_label", "candidate_factory_ref"],
            "additionalProperties": false
        }),
        "candidate.materialize_patchset" => json!({
            "type": "object",
            "properties": {
                "patch_summary": { "type": "string" },
                "changed_paths": string_array_schema()
            },
            "required": ["patch_summary", "changed_paths"],
            "additionalProperties": false
        }),
        "candidate.package" => json!({
            "type": "object",
            "properties": {
                "package_ref": { "type": "string" },
                "boundary_refs": string_array_schema()
            },
            "required": ["package_ref", "boundary_refs"],
            "additionalProperties": false
        }),
        "ecology.dispatch_worker" => json!({
            "type": "object",
            "properties": {
                "worker_id": { "type": "string" },
                "worker_task_ref": { "type": "string" },
                "task_kind": { "type": "string" },
                "requested_capabilities": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "world": { "type": "string" },
                            "operation": { "type": "string" },
                            "resource_scope": { "type": "string" }
                        },
                        "required": ["world", "operation", "resource_scope"],
                        "additionalProperties": false
                    }
                }
            },
            "required": ["worker_id", "worker_task_ref", "task_kind", "requested_capabilities"],
            "additionalProperties": false
        }),
        "ecology.collect_results" => json!({
            "type": "object",
            "properties": {
                "dispatch_id": { "type": "string" },
                "worker_id": { "type": "string" },
                "worker_task_ref": { "type": "string" },
                "result_ref": { "type": "string" },
                "summary": { "type": "string" }
            },
            "required": ["dispatch_id", "worker_id", "worker_task_ref", "result_ref", "summary"],
            "additionalProperties": false
        }),
        "validation.run_proving" => json!({
            "type": "object",
            "properties": {
                "candidate_factory_ref": { "type": "string" },
                "proving_run_ref": { "type": "string" },
                "summary": { "type": "string" }
            },
            "required": ["candidate_factory_ref", "proving_run_ref", "summary"],
            "additionalProperties": false
        }),
        "validation.record_observation" => json!({
            "type": "object",
            "properties": {
                "candidate_factory_ref": { "type": "string" },
                "observation_window_ref": { "type": "string" },
                "summary": { "type": "string" }
            },
            "required": ["candidate_factory_ref", "observation_window_ref", "summary"],
            "additionalProperties": false
        }),
        "validation.compare_candidate" => json!({
            "type": "object",
            "properties": {
                "comparison_id": { "type": "string" },
                "candidate_factory_ref": { "type": "string" },
                "incumbent_factory_ref": { "type": "string" },
                "summary": { "type": "string" }
            },
            "required": ["comparison_id", "candidate_factory_ref", "incumbent_factory_ref", "summary"],
            "additionalProperties": false
        }),
        "governance.request_approval" => json!({
            "type": "object",
            "properties": {
                "summary": { "type": "string" },
                "action_ref": { "type": "string" },
                "scope_ref": { "type": "string" },
                "requested_authority_class": {
                    "type": "string",
                    "enum": [
                        "observe",
                        "local_mutate",
                        "campaign_control",
                        "external_interact",
                        "sensitive_access",
                        "promotion_control",
                        "automation_control"
                    ]
                }
            },
            "required": ["summary", "action_ref", "scope_ref", "requested_authority_class"],
            "additionalProperties": false
        }),
        "governance.inspect_constraints" => empty_object_schema(),
        "governance.recommend_quarantine" => json!({
            "type": "object",
            "properties": {
                "reason_class": {
                    "type": "string",
                    "enum": [
                        "authority_expansion",
                        "policy_violation",
                        "post_approval_anomaly",
                        "evaluation_mismatch"
                    ]
                },
                "affected_refs": string_array_schema(),
                "summary": { "type": "string" }
            },
            "required": ["reason_class", "affected_refs", "summary"],
            "additionalProperties": false
        }),
        _ => empty_object_schema(),
    }
}

fn canonical_result_schema_json(tool_id: &str) -> Value {
    match tool_id {
        "continuity.retrieve" => json!({
            "type": "object",
            "properties": {
                "trace_id": { "type": "string" },
                "bundle_refs": string_array_schema(),
                "transcript_slice_refs": string_array_schema(),
                "evidence_refs": string_array_schema()
            },
            "required": ["trace_id", "bundle_refs", "transcript_slice_refs", "evidence_refs"],
            "additionalProperties": false
        }),
        "continuity.inspect_open_questions" => json!({
            "type": "object",
            "properties": {
                "pointer_index_ref": { "type": "string" },
                "open_question_refs": string_array_schema(),
                "contradiction_refs": string_array_schema()
            },
            "required": ["pointer_index_ref", "open_question_refs", "contradiction_refs"],
            "additionalProperties": false
        }),
        "continuity.propose_update" => json!({
            "type": "object",
            "properties": {
                "record_id": { "type": "string" },
                "output_bundle_id": { "type": "string" },
                "pointer_index_ref": { "type": "string" }
            },
            "required": ["record_id", "output_bundle_id", "pointer_index_ref"],
            "additionalProperties": false
        }),
        "program.inspect" | "program.inspect_lineage_health" => json!({
            "type": "object",
            "properties": {
                "program_ref": { "type": "string" },
                "summary": { "type": "string" },
                "result_ref": { "type": "string" }
            },
            "required": ["program_ref", "summary", "result_ref"],
            "additionalProperties": false
        }),
        "program.submit_cycle_decision" => json!({
            "type": "object",
            "properties": {
                "tick_id": { "type": "string" },
                "instance_id": { "type": "string" },
                "resulting_factory_ref": { "type": "string" }
            },
            "required": ["tick_id", "instance_id", "resulting_factory_ref"],
            "additionalProperties": false
        }),
        "program.raise_stop_condition" => json!({
            "type": "object",
            "properties": {
                "stop_condition_id": { "type": "string" },
                "program_ref": { "type": "string" },
                "decision": { "type": "string" }
            },
            "required": ["stop_condition_id", "program_ref", "decision"],
            "additionalProperties": false
        }),
        "candidate.open_workspace" => json!({
            "type": "object",
            "properties": {
                "workspace_id": { "type": "string" },
                "workspace_scope_ref": { "type": "string" },
                "candidate_factory_ref": { "type": "string" }
            },
            "required": ["workspace_id", "workspace_scope_ref", "candidate_factory_ref"],
            "additionalProperties": false
        }),
        "candidate.materialize_patchset" => json!({
            "type": "object",
            "properties": {
                "patchset_id": { "type": "string" },
                "workspace_scope_ref": { "type": "string" },
                "changed_paths": string_array_schema()
            },
            "required": ["patchset_id", "workspace_scope_ref", "changed_paths"],
            "additionalProperties": false
        }),
        "candidate.package" => json!({
            "type": "object",
            "properties": {
                "package_record_id": { "type": "string" },
                "package_ref": { "type": "string" },
                "boundary_refs": string_array_schema()
            },
            "required": ["package_record_id", "package_ref", "boundary_refs"],
            "additionalProperties": false
        }),
        "ecology.inspect" => json!({
            "type": "object",
            "properties": {
                "ecology_snapshot_ref": { "type": "string" },
                "worker_card_refs": string_array_schema(),
                "lease_refs": string_array_schema()
            },
            "required": ["ecology_snapshot_ref", "worker_card_refs", "lease_refs"],
            "additionalProperties": false
        }),
        "ecology.dispatch_worker" => json!({
            "type": "object",
            "properties": {
                "dispatch_id": { "type": "string" },
                "worker_id": { "type": "string" },
                "worker_task_ref": { "type": "string" }
            },
            "required": ["dispatch_id", "worker_id", "worker_task_ref"],
            "additionalProperties": false
        }),
        "ecology.collect_results" => json!({
            "type": "object",
            "properties": {
                "dispatch_id": { "type": "string" },
                "result_ref": { "type": "string" },
                "worker_id": { "type": "string" }
            },
            "required": ["dispatch_id", "result_ref", "worker_id"],
            "additionalProperties": false
        }),
        "validation.run_proving" => json!({
            "type": "object",
            "properties": {
                "proving_run_id": { "type": "string" },
                "candidate_factory_ref": { "type": "string" },
                "summary": { "type": "string" }
            },
            "required": ["proving_run_id", "candidate_factory_ref", "summary"],
            "additionalProperties": false
        }),
        "validation.record_observation" => json!({
            "type": "object",
            "properties": {
                "observation_id": { "type": "string" },
                "candidate_factory_ref": { "type": "string" },
                "summary": { "type": "string" }
            },
            "required": ["observation_id", "candidate_factory_ref", "summary"],
            "additionalProperties": false
        }),
        "validation.compare_candidate" => json!({
            "type": "object",
            "properties": {
                "comparison_id": { "type": "string" },
                "summary": { "type": "string" },
                "matched": { "type": "boolean" }
            },
            "required": ["comparison_id", "summary", "matched"],
            "additionalProperties": false
        }),
        "governance.request_approval" => json!({
            "type": "object",
            "properties": {
                "approval_request_id": { "type": "string" },
                "action_ref": { "type": "string" },
                "scope_ref": { "type": "string" }
            },
            "required": ["approval_request_id", "action_ref", "scope_ref"],
            "additionalProperties": false
        }),
        "governance.inspect_constraints" => json!({
            "type": "object",
            "properties": {
                "task_ref": { "type": "string" },
                "constraint_refs": string_array_schema(),
                "quarantine_refs": string_array_schema(),
                "rollback_refs": string_array_schema()
            },
            "required": ["task_ref", "constraint_refs", "quarantine_refs", "rollback_refs"],
            "additionalProperties": false
        }),
        "governance.recommend_quarantine" => json!({
            "type": "object",
            "properties": {
                "quarantine_id": { "type": "string" },
                "affected_refs": string_array_schema(),
                "reason_class": { "type": "string" }
            },
            "required": ["quarantine_id", "affected_refs", "reason_class"],
            "additionalProperties": false
        }),
        _ => empty_object_schema(),
    }
}

pub(crate) fn resolve_effective_scope<'a>(
    definition: &ModelToolDefinition,
    context: &'a ToolExecutionContextRecord,
) -> Result<(&'static str, &'a str), ToolMembraneError> {
    for field in &definition.required_context_fields {
        let label = scope_label_for_context_field(*field);
        if !label.is_empty() {
            let value = context
                .context_value(*field)
                .ok_or(ToolMembraneError::MissingExecutionContextField { field: *field })?;
            return Ok((label, value));
        }
    }
    Err(ToolMembraneError::MissingRequiredContextFields)
}

fn scope_label_for_context_field(field: ToolContextField) -> &'static str {
    match field {
        ToolContextField::PointerIndexRef => "pointer-index-ref",
        ToolContextField::FactoryProgramInstanceRef => "factory-program-instance-ref",
        ToolContextField::WorkspaceScopeRef => "workspace-scope-ref",
        ToolContextField::EcologySnapshotRef => "ecology-snapshot-ref",
        ToolContextField::TaskRef => "task-ref",
        ToolContextField::CampaignRef => "campaign-ref",
        ToolContextField::EpochRef => "epoch-ref",
    }
}

pub(crate) fn validate_json_against_schema(
    field: &str,
    payload_json: &str,
    schema_json: &str,
) -> Result<(), ToolMembraneError> {
    let value = parse_json_payload(
        payload_json,
        ToolMembraneError::JsonSchemaViolation {
            field: field.to_string(),
            reason: "payload is not valid JSON".to_string(),
        },
    )?;
    let schema = parse_json_payload(
        schema_json,
        ToolMembraneError::JsonSchemaViolation {
            field: field.to_string(),
            reason: "schema is not valid JSON".to_string(),
        },
    )?;
    validate_value_against_schema(field, &value, &schema)
}

fn validate_value_against_schema(
    field: &str,
    value: &Value,
    schema: &Value,
) -> Result<(), ToolMembraneError> {
    let object = schema
        .as_object()
        .ok_or_else(|| ToolMembraneError::JsonSchemaViolation {
            field: field.to_string(),
            reason: "schema must be a JSON object".to_string(),
        })?;
    if let Some(expected_type) = object.get("type").and_then(Value::as_str) {
        match expected_type {
            "object" => {
                let value_object =
                    value
                        .as_object()
                        .ok_or_else(|| ToolMembraneError::JsonSchemaViolation {
                            field: field.to_string(),
                            reason: "expected object".to_string(),
                        })?;
                let required = object
                    .get("required")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                for item in required {
                    let key =
                        item.as_str()
                            .ok_or_else(|| ToolMembraneError::JsonSchemaViolation {
                                field: field.to_string(),
                                reason: "required entries must be strings".to_string(),
                            })?;
                    if !value_object.contains_key(key) {
                        return Err(ToolMembraneError::JsonSchemaViolation {
                            field: format!("{field}.{key}"),
                            reason: "missing required property".to_string(),
                        });
                    }
                }
                let properties = object
                    .get("properties")
                    .and_then(Value::as_object)
                    .cloned()
                    .unwrap_or_default();
                let additional_allowed = object
                    .get("additionalProperties")
                    .and_then(Value::as_bool)
                    .unwrap_or(true);
                if !additional_allowed {
                    for key in value_object.keys() {
                        if !properties.contains_key(key) {
                            return Err(ToolMembraneError::JsonSchemaViolation {
                                field: format!("{field}.{key}"),
                                reason: "unexpected property".to_string(),
                            });
                        }
                    }
                }
                for (key, property_schema) in properties {
                    if let Some(property_value) = value_object.get(&key) {
                        validate_value_against_schema(
                            &format!("{field}.{key}"),
                            property_value,
                            &property_schema,
                        )?;
                    }
                }
            }
            "array" => {
                let array =
                    value
                        .as_array()
                        .ok_or_else(|| ToolMembraneError::JsonSchemaViolation {
                            field: field.to_string(),
                            reason: "expected array".to_string(),
                        })?;
                if let Some(items) = object.get("items") {
                    for (index, item) in array.iter().enumerate() {
                        validate_value_against_schema(&format!("{field}[{index}]"), item, items)?;
                    }
                }
            }
            "string" => {
                if !value.is_string() {
                    return Err(ToolMembraneError::JsonSchemaViolation {
                        field: field.to_string(),
                        reason: "expected string".to_string(),
                    });
                }
            }
            "integer" => {
                if value.as_i64().is_none() && value.as_u64().is_none() {
                    return Err(ToolMembraneError::JsonSchemaViolation {
                        field: field.to_string(),
                        reason: "expected integer".to_string(),
                    });
                }
            }
            "boolean" => {
                if !value.is_boolean() {
                    return Err(ToolMembraneError::JsonSchemaViolation {
                        field: field.to_string(),
                        reason: "expected boolean".to_string(),
                    });
                }
            }
            unsupported => {
                return Err(ToolMembraneError::JsonSchemaViolation {
                    field: field.to_string(),
                    reason: format!("unsupported schema type '{unsupported}'"),
                });
            }
        }
    }
    if let Some(values) = object.get("enum").and_then(Value::as_array) {
        if !values.iter().any(|candidate| candidate == value) {
            return Err(ToolMembraneError::JsonSchemaViolation {
                field: field.to_string(),
                reason: "value is not in the allowed enum set".to_string(),
            });
        }
    }
    Ok(())
}

fn empty_object_schema() -> Value {
    json!({
        "type": "object",
        "properties": {},
        "additionalProperties": false
    })
}

fn string_array_schema() -> Value {
    json!({
        "type": "array",
        "items": { "type": "string" }
    })
}

fn legality_id(intent: &ParsedToolCallIntentRecord) -> String {
    format!(
        "tool-legality:{}",
        sanitize_id(&intent.parsed_tool_call_intent_id)
    )
}

fn parse_json_payload<T>(json_payload: &str, error: T) -> Result<Value, T> {
    serde_json::from_str(json_payload).map_err(|_| error)
}

fn require_nonempty(value: &str, error: ToolMembraneError) -> Result<(), ToolMembraneError> {
    if value.trim().is_empty() {
        return Err(error);
    }
    Ok(())
}

fn validate_string_list(
    values: &[String],
    error: ToolMembraneError,
) -> Result<(), ToolMembraneError> {
    if values.is_empty() || values.iter().any(|value| value.trim().is_empty()) {
        return Err(error);
    }
    Ok(())
}

fn current_timestamp() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

fn sanitize_id(value: &str) -> String {
    value
        .chars()
        .map(|character| match character {
            'a'..='z' | 'A'..='Z' | '0'..='9' => character,
            _ => '-',
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        ApprovalClass, AuthorityClass, CapabilityEnvelope, CapabilityWorld, ModelToolFamily,
        ToolContextField, ToolExecutionContextRecord, ToolExecutionDecision,
        build_canonical_tool_catalog, evaluate_tool_call_legality,
        render_tool_catalog_json_for_role,
    };
    use crate::execution::capability::{
        CapabilityOperationApproval, CapabilityWorldGrant, IsolationProfile,
    };
    use crate::execution::turn_package::{
        ContextBudgetRecord, ContinuityEntryPriority, ParsedToolCallIntentRecord, ParsedTurnResult,
        ParsedTurnResultStatus, TurnContinuityEntry, TurnPackage, TurnPackageRole,
        TurnResponseSchemaFamily,
    };

    fn context() -> ToolExecutionContextRecord {
        ToolExecutionContextRecord {
            tool_execution_context_id: "tool-context:1".to_string(),
            turn_package_ref: "turn-package:1".to_string(),
            capability_envelope: CapabilityEnvelope {
                envelope_id: "envelope-1".to_string(),
                actor_scope: "llm-turn".to_string(),
                world_grants: vec![
                    CapabilityWorldGrant {
                        world: CapabilityWorld::MemoryAccess,
                        allowed_operations: vec![
                            "continuity.retrieve".to_string(),
                            "continuity.inspect_open_questions".to_string(),
                            "continuity.propose_update".to_string(),
                        ],
                        default_authority_class: AuthorityClass::LocalMutate,
                        default_approval_class: ApprovalClass::SupervisorAllowed,
                        operation_approval_overrides: vec![CapabilityOperationApproval {
                            operation: "continuity.propose_update".to_string(),
                            approval_class: ApprovalClass::HumanRequired,
                        }],
                    },
                    CapabilityWorldGrant {
                        world: CapabilityWorld::ReviewPromotion,
                        allowed_operations: vec![
                            "program.submit_cycle_decision".to_string(),
                            "validation.compare_candidate".to_string(),
                        ],
                        default_authority_class: AuthorityClass::PromotionControl,
                        default_approval_class: ApprovalClass::SupervisorAllowed,
                        operation_approval_overrides: vec![CapabilityOperationApproval {
                            operation: "program.submit_cycle_decision".to_string(),
                            approval_class: ApprovalClass::HumanRequired,
                        }],
                    },
                ],
                authority_ceiling: AuthorityClass::PromotionControl,
                isolation_profile: IsolationProfile::SupervisorExclusive,
                allowed_resource_scopes: vec![
                    "pointer-index:1".to_string(),
                    "factory-program-instance:1".to_string(),
                ],
                approval_overrides: Vec::new(),
                quota_policy: None,
                campaign_scope: Some("campaign:1".to_string()),
                epoch_scope: Some("epoch:1".to_string()),
            },
            campaign_ref: Some("campaign:1".to_string()),
            epoch_ref: Some("epoch:1".to_string()),
            task_ref: Some("task:1".to_string()),
            pointer_index_ref: Some("pointer-index:1".to_string()),
            factory_program_instance_ref: Some("factory-program-instance:1".to_string()),
            workspace_scope_ref: Some("workspace-scope:1".to_string()),
            ecology_snapshot_ref: Some("ecology-snapshot:1".to_string()),
            created_at: "1".to_string(),
        }
    }

    fn turn_package() -> TurnPackage {
        TurnPackage {
            turn_package_id: "turn-package:1".to_string(),
            program_ref: "program:1".to_string(),
            session_ref: "session:1".to_string(),
            turn_ref: "turn:1".to_string(),
            envelope_ref: "envelope-1".to_string(),
            role: TurnPackageRole::Supervisor,
            system_frame_ref: "system:1".to_string(),
            system_frame_text: "system".to_string(),
            program_frame_ref: "program-frame:1".to_string(),
            program_frame_text: "program".to_string(),
            capability_frame_ref: "capability-frame:1".to_string(),
            capability_frame_text: "capability".to_string(),
            agenda_ref: "agenda:1".to_string(),
            agenda_text: "agenda".to_string(),
            continuity_entries: vec![TurnContinuityEntry {
                entry_ref: "continuity:1".to_string(),
                text: "continuity".to_string(),
                priority: ContinuityEntryPriority::Critical,
            }],
            tool_catalog_ref: "tool-catalog:canonical:v1".to_string(),
            tool_execution_context_ref: "tool-context:1".to_string(),
            response_schema_family: TurnResponseSchemaFamily::SupervisorTurnV1,
            context_budget: ContextBudgetRecord {
                context_budget_id: "context-budget:1".to_string(),
                turn_package_ref: "turn-package:1".to_string(),
                max_rendered_prompt_chars: 2048,
                max_continuity_entries: 4,
                created_at: "1".to_string(),
            },
            created_at: "1".to_string(),
        }
    }

    fn parsed_result() -> ParsedTurnResult {
        ParsedTurnResult {
            parsed_turn_result_id: "parsed-turn:1".to_string(),
            turn_package_ref: "turn-package:1".to_string(),
            inference_turn_result_ref: "turn-result:1".to_string(),
            inference_parsed_output_ref: Some("parsed-output:1".to_string()),
            status: ParsedTurnResultStatus::Parsed,
            parsed_tool_call_intent_refs: vec!["intent:1".to_string()],
            parsed_proposal_refs: Vec::new(),
            parsed_approval_request_ref: None,
            stop_recommendation: None,
            repair_refs: Vec::new(),
            tool_execution_refs: Vec::new(),
            tool_execution_receipt_refs: Vec::new(),
            summary: "summary".to_string(),
            notes: Vec::new(),
            created_at: "1".to_string(),
        }
    }

    fn intent(tool_id: &str, arguments_json: &str) -> ParsedToolCallIntentRecord {
        ParsedToolCallIntentRecord {
            parsed_tool_call_intent_id: format!("intent:{tool_id}"),
            parsed_result_ref: "parsed-turn:1".to_string(),
            tool_id: tool_id.to_string(),
            arguments_json: arguments_json.to_string(),
            summary: "tool call".to_string(),
            created_at: "1".to_string(),
        }
    }

    #[test]
    fn canonical_catalog_contains_expected_tool_ids_and_operator_surfaces_are_separate() {
        let bundle = build_canonical_tool_catalog().unwrap();
        assert_eq!(bundle.catalog.tool_catalog_id, "tool-catalog:canonical:v1");
        assert!(bundle.definition("continuity.retrieve").is_some());
        assert!(bundle.definition("program.inspect").is_some());
        assert!(bundle.definition("candidate.open_workspace").is_some());
        assert!(bundle.definition("ecology.dispatch_worker").is_some());
        assert!(bundle.definition("validation.compare_candidate").is_some());
        assert!(bundle.definition("governance.request_approval").is_some());
        assert!(
            bundle
                .operator_only_surfaces
                .iter()
                .any(|record| record.internal_service_ref == "service:operator:execute-rollback")
        );
    }

    #[test]
    fn role_filtered_catalog_excludes_supervisor_only_tools_for_workers() {
        let bundle = build_canonical_tool_catalog().unwrap();
        let json = render_tool_catalog_json_for_role(&bundle, TurnPackageRole::Worker).unwrap();
        assert!(json.contains("continuity.retrieve"));
        assert!(json.contains("ecology.collect_results"));
        assert!(!json.contains("program.submit_cycle_decision"));
    }

    #[test]
    fn legality_distinguishes_allowed_and_approval_blocked() {
        let bundle = build_canonical_tool_catalog().unwrap();
        let allowed = evaluate_tool_call_legality(
            bundle.definition("continuity.retrieve").unwrap(),
            bundle.argument_schema_for("continuity.retrieve").unwrap(),
            bundle.exposure_for("continuity.retrieve").unwrap(),
            &turn_package(),
            &parsed_result(),
            &intent("continuity.retrieve", r#"{"max_bundle_refs":1}"#),
            &context(),
        )
        .unwrap();
        assert_eq!(allowed.decision, ToolExecutionDecision::Allowed);

        let blocked = evaluate_tool_call_legality(
            bundle.definition("continuity.propose_update").unwrap(),
            bundle
                .argument_schema_for("continuity.propose_update")
                .unwrap(),
            bundle.exposure_for("continuity.propose_update").unwrap(),
            &turn_package(),
            &parsed_result(),
            &intent(
                "continuity.propose_update",
                r#"{"summary":"update","evidence_refs":["e1"],"verification_refs":["v1"]}"#,
            ),
            &context(),
        )
        .unwrap();
        assert_eq!(blocked.decision, ToolExecutionDecision::ApprovalBlocked);
    }

    #[test]
    fn invalid_argument_shape_is_rejected_before_execution() {
        let bundle = build_canonical_tool_catalog().unwrap();
        let error = evaluate_tool_call_legality(
            bundle.definition("program.submit_cycle_decision").unwrap(),
            bundle
                .argument_schema_for("program.submit_cycle_decision")
                .unwrap(),
            bundle
                .exposure_for("program.submit_cycle_decision")
                .unwrap(),
            &turn_package(),
            &parsed_result(),
            &intent(
                "program.submit_cycle_decision",
                r#"{"candidate_factory_ref":"factory:g1"}"#,
            ),
            &context(),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            super::ToolMembraneError::JsonSchemaViolation { .. }
        ));
    }

    #[test]
    fn definitions_carry_expected_family_and_context_rules() {
        let bundle = build_canonical_tool_catalog().unwrap();
        let definition = bundle.definition("validation.compare_candidate").unwrap();
        assert_eq!(definition.family, ModelToolFamily::ValidationObservation);
        assert_eq!(
            definition.required_context_fields,
            vec![ToolContextField::FactoryProgramInstanceRef]
        );
    }
}
