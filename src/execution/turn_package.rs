use crate::execution::{
    AuthorityClass, InferenceFinishReason, InferenceParsedOutputRecord, InferenceTurnResult,
    NormalizedProposal, ProposalFamily, StopConditionDecision,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TurnPackageRole {
    Supervisor,
    Worker,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TurnResponseSchemaFamily {
    SupervisorTurnV1,
    WorkerTurnV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromptLayerKind {
    SystemFrame,
    ProgramFrame,
    CapabilityFrame,
    ContinuityFrame,
    AgendaFrame,
    ResponseContractFrame,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContinuityEntryPriority {
    Critical,
    Supporting,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParsedTurnResultStatus {
    Parsed,
    RejectedContract,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParseRepairClass {
    CodeFenceUnwrap,
    SingleJsonObjectExtract,
    WhitespaceNormalization,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TurnContinuityEntry {
    pub entry_ref: String,
    pub text: String,
    pub priority: ContinuityEntryPriority,
}

impl TurnContinuityEntry {
    pub fn validate(&self) -> Result<(), TurnContractError> {
        require_nonempty(
            &self.entry_ref,
            TurnContractError::MissingContinuityEntryRef,
        )?;
        require_nonempty(&self.text, TurnContractError::MissingContinuityEntryText)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextBudgetRecord {
    pub context_budget_id: String,
    pub turn_package_ref: String,
    pub max_rendered_prompt_chars: usize,
    pub max_continuity_entries: usize,
    pub created_at: String,
}

impl ContextBudgetRecord {
    pub fn validate(&self) -> Result<(), TurnContractError> {
        require_nonempty(
            &self.context_budget_id,
            TurnContractError::MissingContextBudgetId,
        )?;
        require_nonempty(
            &self.turn_package_ref,
            TurnContractError::MissingTurnPackageRef,
        )?;
        if self.max_rendered_prompt_chars == 0 {
            return Err(TurnContractError::InvalidMaxRenderedPromptChars);
        }
        if self.max_continuity_entries == 0 {
            return Err(TurnContractError::InvalidMaxContinuityEntries);
        }
        require_nonempty(&self.created_at, TurnContractError::MissingCreatedAt)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TurnPackage {
    pub turn_package_id: String,
    pub program_ref: String,
    pub session_ref: String,
    pub turn_ref: String,
    pub envelope_ref: String,
    pub role: TurnPackageRole,
    pub system_frame_ref: String,
    pub system_frame_text: String,
    pub program_frame_ref: String,
    pub program_frame_text: String,
    pub capability_frame_ref: String,
    pub capability_frame_text: String,
    pub agenda_ref: String,
    pub agenda_text: String,
    pub continuity_entries: Vec<TurnContinuityEntry>,
    pub tool_catalog_ref: String,
    pub tool_execution_context_ref: String,
    pub response_schema_family: TurnResponseSchemaFamily,
    pub context_budget: ContextBudgetRecord,
    pub created_at: String,
}

impl TurnPackage {
    pub fn validate(&self) -> Result<(), TurnContractError> {
        require_nonempty(
            &self.turn_package_id,
            TurnContractError::MissingTurnPackageId,
        )?;
        require_nonempty(&self.program_ref, TurnContractError::MissingProgramRef)?;
        require_nonempty(&self.session_ref, TurnContractError::MissingSessionRef)?;
        require_nonempty(&self.turn_ref, TurnContractError::MissingTurnRef)?;
        require_nonempty(&self.envelope_ref, TurnContractError::MissingEnvelopeRef)?;
        require_nonempty(
            &self.system_frame_ref,
            TurnContractError::MissingSystemFrameRef,
        )?;
        require_nonempty(
            &self.system_frame_text,
            TurnContractError::MissingSystemFrameText,
        )?;
        require_nonempty(
            &self.program_frame_ref,
            TurnContractError::MissingProgramFrameRef,
        )?;
        require_nonempty(
            &self.program_frame_text,
            TurnContractError::MissingProgramFrameText,
        )?;
        require_nonempty(
            &self.capability_frame_ref,
            TurnContractError::MissingCapabilityFrameRef,
        )?;
        require_nonempty(
            &self.capability_frame_text,
            TurnContractError::MissingCapabilityFrameText,
        )?;
        require_nonempty(&self.agenda_ref, TurnContractError::MissingAgendaRef)?;
        require_nonempty(&self.agenda_text, TurnContractError::MissingAgendaText)?;
        if self.continuity_entries.is_empty() {
            return Err(TurnContractError::MissingContinuityEntries);
        }
        for entry in &self.continuity_entries {
            entry.validate()?;
        }
        require_nonempty(
            &self.tool_catalog_ref,
            TurnContractError::MissingToolCatalogRef,
        )?;
        require_nonempty(
            &self.tool_execution_context_ref,
            TurnContractError::MissingToolExecutionContextRef,
        )?;
        self.context_budget.validate()?;
        if self.context_budget.turn_package_ref != self.turn_package_id {
            return Err(TurnContractError::ContextBudgetPackageMismatch {
                budget_turn_package_ref: self.context_budget.turn_package_ref.clone(),
                turn_package_id: self.turn_package_id.clone(),
            });
        }
        if !schema_family_matches_role(self.role, self.response_schema_family) {
            return Err(TurnContractError::RoleSchemaMismatch {
                role: self.role,
                schema_family: self.response_schema_family,
            });
        }
        require_nonempty(&self.created_at, TurnContractError::MissingCreatedAt)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextTruncationRecord {
    pub context_truncation_id: String,
    pub turn_package_ref: String,
    pub included_entry_refs: Vec<String>,
    pub omitted_entry_refs: Vec<String>,
    pub summary: String,
    pub created_at: String,
}

impl ContextTruncationRecord {
    pub fn validate(&self) -> Result<(), TurnContractError> {
        require_nonempty(
            &self.context_truncation_id,
            TurnContractError::MissingContextTruncationId,
        )?;
        require_nonempty(
            &self.turn_package_ref,
            TurnContractError::MissingTurnPackageRef,
        )?;
        if self
            .included_entry_refs
            .iter()
            .any(|entry_ref| entry_ref.trim().is_empty())
        {
            return Err(TurnContractError::MissingIncludedEntryRef);
        }
        if self
            .omitted_entry_refs
            .iter()
            .any(|entry_ref| entry_ref.trim().is_empty())
        {
            return Err(TurnContractError::MissingOmittedEntryRef);
        }
        require_nonempty(&self.summary, TurnContractError::MissingSummary)?;
        require_nonempty(&self.created_at, TurnContractError::MissingCreatedAt)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromptLayerRecord {
    pub prompt_layer_id: String,
    pub turn_package_ref: String,
    pub kind: PromptLayerKind,
    pub source_ref: String,
    pub rendered_text: String,
    pub rendered_char_count: usize,
    pub created_at: String,
}

impl PromptLayerRecord {
    pub fn validate(&self) -> Result<(), TurnContractError> {
        require_nonempty(
            &self.prompt_layer_id,
            TurnContractError::MissingPromptLayerId,
        )?;
        require_nonempty(
            &self.turn_package_ref,
            TurnContractError::MissingTurnPackageRef,
        )?;
        require_nonempty(
            &self.source_ref,
            TurnContractError::MissingPromptLayerSourceRef,
        )?;
        require_nonempty(
            &self.rendered_text,
            TurnContractError::MissingPromptLayerText,
        )?;
        if self.rendered_char_count != self.rendered_text.chars().count() {
            return Err(TurnContractError::InvalidPromptLayerCharCount);
        }
        require_nonempty(&self.created_at, TurnContractError::MissingCreatedAt)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromptRenderingRecord {
    pub prompt_rendering_id: String,
    pub turn_package_ref: String,
    pub layer_refs: Vec<String>,
    pub context_budget_ref: String,
    pub truncation_ref: String,
    pub response_schema_ref: String,
    pub rendered_prompt_text: String,
    pub rendered_prompt_char_count: usize,
    pub created_at: String,
}

impl PromptRenderingRecord {
    pub fn validate(&self) -> Result<(), TurnContractError> {
        require_nonempty(
            &self.prompt_rendering_id,
            TurnContractError::MissingPromptRenderingId,
        )?;
        require_nonempty(
            &self.turn_package_ref,
            TurnContractError::MissingTurnPackageRef,
        )?;
        validate_ref_entries(&self.layer_refs, TurnContractError::MissingPromptLayerRef)?;
        require_nonempty(
            &self.context_budget_ref,
            TurnContractError::MissingContextBudgetRef,
        )?;
        require_nonempty(
            &self.truncation_ref,
            TurnContractError::MissingContextTruncationRef,
        )?;
        require_nonempty(
            &self.response_schema_ref,
            TurnContractError::MissingResponseSchemaRef,
        )?;
        require_nonempty(
            &self.rendered_prompt_text,
            TurnContractError::MissingRenderedPromptText,
        )?;
        if self.rendered_prompt_char_count != self.rendered_prompt_text.chars().count() {
            return Err(TurnContractError::InvalidRenderedPromptCharCount);
        }
        require_nonempty(&self.created_at, TurnContractError::MissingCreatedAt)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TurnResponseSchemaRecord {
    pub turn_response_schema_id: String,
    pub turn_package_ref: String,
    pub schema_family: TurnResponseSchemaFamily,
    pub response_schema_json: String,
    pub created_at: String,
}

impl TurnResponseSchemaRecord {
    pub fn validate(&self) -> Result<(), TurnContractError> {
        require_nonempty(
            &self.turn_response_schema_id,
            TurnContractError::MissingTurnResponseSchemaId,
        )?;
        require_nonempty(
            &self.turn_package_ref,
            TurnContractError::MissingTurnPackageRef,
        )?;
        require_nonempty(
            &self.response_schema_json,
            TurnContractError::MissingResponseSchemaJson,
        )?;
        parse_json_payload(
            &self.response_schema_json,
            TurnContractError::InvalidResponseSchemaJson,
        )?;
        require_nonempty(&self.created_at, TurnContractError::MissingCreatedAt)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedToolCallIntentRecord {
    pub parsed_tool_call_intent_id: String,
    pub parsed_result_ref: String,
    pub tool_id: String,
    pub arguments_json: String,
    pub summary: String,
    pub created_at: String,
}

impl ParsedToolCallIntentRecord {
    pub fn validate(&self) -> Result<(), TurnContractError> {
        require_nonempty(
            &self.parsed_tool_call_intent_id,
            TurnContractError::MissingParsedToolCallIntentId,
        )?;
        require_nonempty(
            &self.parsed_result_ref,
            TurnContractError::MissingParsedTurnResultRef,
        )?;
        require_nonempty(&self.tool_id, TurnContractError::MissingToolId)?;
        require_nonempty(
            &self.arguments_json,
            TurnContractError::MissingToolArgumentsJson,
        )?;
        parse_json_payload(
            &self.arguments_json,
            TurnContractError::InvalidToolArgumentsJson,
        )?;
        require_nonempty(&self.summary, TurnContractError::MissingSummary)?;
        require_nonempty(&self.created_at, TurnContractError::MissingCreatedAt)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedProposalRecord {
    pub parsed_proposal_id: String,
    pub parsed_result_ref: String,
    pub proposal: NormalizedProposal,
    pub created_at: String,
}

impl ParsedProposalRecord {
    pub fn validate(&self) -> Result<(), TurnContractError> {
        require_nonempty(
            &self.parsed_proposal_id,
            TurnContractError::MissingParsedProposalId,
        )?;
        require_nonempty(
            &self.parsed_result_ref,
            TurnContractError::MissingParsedTurnResultRef,
        )?;
        self.proposal
            .validate()
            .map_err(TurnContractError::InvalidProposal)?;
        require_nonempty(&self.created_at, TurnContractError::MissingCreatedAt)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedApprovalRequestRecord {
    pub parsed_approval_request_id: String,
    pub parsed_result_ref: String,
    pub summary: String,
    pub action_ref: String,
    pub scope_ref: String,
    pub requested_authority_class: AuthorityClass,
    pub created_at: String,
}

impl ParsedApprovalRequestRecord {
    pub fn validate(&self) -> Result<(), TurnContractError> {
        require_nonempty(
            &self.parsed_approval_request_id,
            TurnContractError::MissingParsedApprovalRequestId,
        )?;
        require_nonempty(
            &self.parsed_result_ref,
            TurnContractError::MissingParsedTurnResultRef,
        )?;
        require_nonempty(&self.summary, TurnContractError::MissingSummary)?;
        require_nonempty(
            &self.action_ref,
            TurnContractError::MissingApprovalActionRef,
        )?;
        require_nonempty(&self.scope_ref, TurnContractError::MissingApprovalScopeRef)?;
        require_nonempty(&self.created_at, TurnContractError::MissingCreatedAt)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseRepairRecord {
    pub parse_repair_id: String,
    pub parsed_result_ref: String,
    pub repair_class: ParseRepairClass,
    pub summary: String,
    pub created_at: String,
}

impl ParseRepairRecord {
    pub fn validate(&self) -> Result<(), TurnContractError> {
        require_nonempty(
            &self.parse_repair_id,
            TurnContractError::MissingParseRepairId,
        )?;
        require_nonempty(
            &self.parsed_result_ref,
            TurnContractError::MissingParsedTurnResultRef,
        )?;
        require_nonempty(&self.summary, TurnContractError::MissingSummary)?;
        require_nonempty(&self.created_at, TurnContractError::MissingCreatedAt)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedTurnResult {
    pub parsed_turn_result_id: String,
    pub turn_package_ref: String,
    pub inference_turn_result_ref: String,
    pub inference_parsed_output_ref: Option<String>,
    pub status: ParsedTurnResultStatus,
    pub parsed_tool_call_intent_refs: Vec<String>,
    pub parsed_proposal_refs: Vec<String>,
    pub parsed_approval_request_ref: Option<String>,
    pub stop_recommendation: Option<StopConditionDecision>,
    pub repair_refs: Vec<String>,
    pub tool_execution_refs: Vec<String>,
    pub tool_execution_receipt_refs: Vec<String>,
    pub summary: String,
    pub notes: Vec<String>,
    pub created_at: String,
}

impl ParsedTurnResult {
    pub fn validate(&self) -> Result<(), TurnContractError> {
        require_nonempty(
            &self.parsed_turn_result_id,
            TurnContractError::MissingParsedTurnResultId,
        )?;
        require_nonempty(
            &self.turn_package_ref,
            TurnContractError::MissingTurnPackageRef,
        )?;
        require_nonempty(
            &self.inference_turn_result_ref,
            TurnContractError::MissingInferenceTurnResultRef,
        )?;
        if self
            .inference_parsed_output_ref
            .as_ref()
            .is_some_and(|reference| reference.trim().is_empty())
        {
            return Err(TurnContractError::MissingInferenceParsedOutputRef);
        }
        if self
            .parsed_tool_call_intent_refs
            .iter()
            .any(|reference| reference.trim().is_empty())
        {
            return Err(TurnContractError::MissingParsedToolCallIntentRef);
        }
        if self
            .parsed_proposal_refs
            .iter()
            .any(|reference| reference.trim().is_empty())
        {
            return Err(TurnContractError::MissingParsedProposalRef);
        }
        if self
            .parsed_approval_request_ref
            .as_ref()
            .is_some_and(|reference| reference.trim().is_empty())
        {
            return Err(TurnContractError::MissingParsedApprovalRequestRef);
        }
        if self
            .repair_refs
            .iter()
            .any(|reference| reference.trim().is_empty())
        {
            return Err(TurnContractError::MissingParseRepairRef);
        }
        if self
            .tool_execution_refs
            .iter()
            .any(|reference| reference.trim().is_empty())
        {
            return Err(TurnContractError::MissingToolExecutionRef);
        }
        if self
            .tool_execution_receipt_refs
            .iter()
            .any(|reference| reference.trim().is_empty())
        {
            return Err(TurnContractError::MissingToolExecutionReceiptRef);
        }
        require_nonempty(&self.summary, TurnContractError::MissingSummary)?;
        if self.notes.iter().any(|note| note.trim().is_empty()) {
            return Err(TurnContractError::MissingParsedNote);
        }
        match self.status {
            ParsedTurnResultStatus::Parsed => {
                if self.inference_parsed_output_ref.is_none() {
                    return Err(TurnContractError::MissingInferenceParsedOutputRef);
                }
            }
            ParsedTurnResultStatus::RejectedContract => {}
        }
        require_nonempty(&self.created_at, TurnContractError::MissingCreatedAt)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TurnRenderBundle {
    pub turn_package: TurnPackage,
    pub context_budget: ContextBudgetRecord,
    pub truncation: ContextTruncationRecord,
    pub prompt_layers: Vec<PromptLayerRecord>,
    pub response_schema: TurnResponseSchemaRecord,
    pub rendering: PromptRenderingRecord,
}

impl TurnRenderBundle {
    pub fn validate(&self) -> Result<(), TurnContractError> {
        self.turn_package.validate()?;
        self.context_budget.validate()?;
        self.truncation.validate()?;
        self.response_schema.validate()?;
        self.rendering.validate()?;
        if self.prompt_layers.len() != 6 {
            return Err(TurnContractError::MissingPromptLayers);
        }
        for layer in &self.prompt_layers {
            layer.validate()?;
            if layer.turn_package_ref != self.turn_package.turn_package_id {
                return Err(TurnContractError::PromptLayerPackageMismatch);
            }
        }
        if self.context_budget.context_budget_id
            != self.turn_package.context_budget.context_budget_id
        {
            return Err(TurnContractError::ContextBudgetPackageMismatch {
                budget_turn_package_ref: self.context_budget.turn_package_ref.clone(),
                turn_package_id: self.turn_package.turn_package_id.clone(),
            });
        }
        if self.truncation.turn_package_ref != self.turn_package.turn_package_id {
            return Err(TurnContractError::TruncationPackageMismatch);
        }
        if self.response_schema.turn_package_ref != self.turn_package.turn_package_id {
            return Err(TurnContractError::ResponseSchemaPackageMismatch);
        }
        if self.rendering.turn_package_ref != self.turn_package.turn_package_id {
            return Err(TurnContractError::RenderingPackageMismatch);
        }
        if self.rendering.context_budget_ref != self.context_budget.context_budget_id {
            return Err(TurnContractError::ContextBudgetRenderingMismatch);
        }
        if self.rendering.truncation_ref != self.truncation.context_truncation_id {
            return Err(TurnContractError::TruncationRenderingMismatch);
        }
        if self.rendering.response_schema_ref != self.response_schema.turn_response_schema_id {
            return Err(TurnContractError::ResponseSchemaRenderingMismatch);
        }
        if self.rendering.layer_refs.len() != self.prompt_layers.len() {
            return Err(TurnContractError::MissingPromptLayers);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedTurnBundle {
    pub turn_package: TurnPackage,
    pub inference_turn_result: InferenceTurnResult,
    pub parsed_output: Option<InferenceParsedOutputRecord>,
    pub parsed_result: ParsedTurnResult,
    pub parsed_tool_call_intents: Vec<ParsedToolCallIntentRecord>,
    pub parsed_proposals: Vec<ParsedProposalRecord>,
    pub parsed_approval_request: Option<ParsedApprovalRequestRecord>,
    pub repair_records: Vec<ParseRepairRecord>,
}

impl ParsedTurnBundle {
    pub fn validate(&self) -> Result<(), TurnContractError> {
        self.turn_package.validate()?;
        self.parsed_result.validate()?;
        if self.parsed_result.turn_package_ref != self.turn_package.turn_package_id {
            return Err(TurnContractError::ParsedResultPackageMismatch);
        }
        if self.parsed_result.inference_turn_result_ref != self.inference_turn_result.turn_result_id
        {
            return Err(TurnContractError::ParsedResultInferenceMismatch);
        }
        match (
            &self.parsed_output,
            &self.parsed_result.inference_parsed_output_ref,
        ) {
            (Some(parsed_output), Some(reference)) => {
                parsed_output
                    .validate()
                    .map_err(TurnContractError::InvalidInferenceParsedOutput)?;
                if &parsed_output.parsed_output_id != reference {
                    return Err(TurnContractError::ParsedResultInferenceMismatch);
                }
            }
            (None, None) => {}
            _ => return Err(TurnContractError::ParsedResultInferenceMismatch),
        }
        for record in &self.parsed_tool_call_intents {
            record.validate()?;
            if record.parsed_result_ref != self.parsed_result.parsed_turn_result_id {
                return Err(TurnContractError::ParsedIntentResultMismatch);
            }
        }
        for record in &self.parsed_proposals {
            record.validate()?;
            if record.parsed_result_ref != self.parsed_result.parsed_turn_result_id {
                return Err(TurnContractError::ParsedProposalResultMismatch);
            }
        }
        if let Some(record) = &self.parsed_approval_request {
            record.validate()?;
            if record.parsed_result_ref != self.parsed_result.parsed_turn_result_id {
                return Err(TurnContractError::ParsedApprovalResultMismatch);
            }
        }
        for record in &self.repair_records {
            record.validate()?;
            if record.parsed_result_ref != self.parsed_result.parsed_turn_result_id {
                return Err(TurnContractError::ParseRepairResultMismatch);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TurnContractError {
    MissingTurnPackageId,
    MissingProgramRef,
    MissingSessionRef,
    MissingTurnRef,
    MissingEnvelopeRef,
    MissingSystemFrameRef,
    MissingSystemFrameText,
    MissingProgramFrameRef,
    MissingProgramFrameText,
    MissingCapabilityFrameRef,
    MissingCapabilityFrameText,
    MissingAgendaRef,
    MissingAgendaText,
    MissingContinuityEntries,
    MissingContinuityEntryRef,
    MissingContinuityEntryText,
    MissingToolCatalogRef,
    MissingToolExecutionContextRef,
    MissingContextBudgetId,
    InvalidMaxRenderedPromptChars,
    InvalidMaxContinuityEntries,
    MissingContextTruncationId,
    MissingPromptLayerId,
    MissingPromptLayerSourceRef,
    MissingPromptLayerText,
    InvalidPromptLayerCharCount,
    MissingPromptRenderingId,
    MissingPromptLayerRef,
    MissingContextBudgetRef,
    MissingContextTruncationRef,
    MissingRenderedPromptText,
    InvalidRenderedPromptCharCount,
    MissingTurnResponseSchemaId,
    MissingResponseSchemaJson,
    InvalidResponseSchemaJson,
    MissingParsedToolCallIntentId,
    MissingParsedProposalId,
    MissingParsedApprovalRequestId,
    MissingParseRepairId,
    MissingParsedTurnResultId,
    MissingParsedTurnResultRef,
    MissingInferenceTurnResultRef,
    MissingInferenceParsedOutputRef,
    MissingToolId,
    MissingToolArgumentsJson,
    InvalidToolArgumentsJson,
    MissingApprovalActionRef,
    MissingApprovalScopeRef,
    MissingSummary,
    MissingParsedNote,
    MissingCreatedAt,
    MissingTurnPackageRef,
    MissingIncludedEntryRef,
    MissingOmittedEntryRef,
    MissingResponseSchemaRef,
    MissingParsedToolCallIntentRef,
    MissingParsedProposalRef,
    MissingParsedApprovalRequestRef,
    MissingParseRepairRef,
    MissingToolExecutionRef,
    MissingToolExecutionReceiptRef,
    MissingPromptLayers,
    MissingExecutionProviderRef,
    MissingExecutionModelRef,
    InvalidGenerationPolicy(String),
    RoleSchemaMismatch {
        role: TurnPackageRole,
        schema_family: TurnResponseSchemaFamily,
    },
    ContextBudgetPackageMismatch {
        budget_turn_package_ref: String,
        turn_package_id: String,
    },
    PromptLayerPackageMismatch,
    TruncationPackageMismatch,
    ResponseSchemaPackageMismatch,
    RenderingPackageMismatch,
    ContextBudgetRenderingMismatch,
    TruncationRenderingMismatch,
    ResponseSchemaRenderingMismatch,
    ParsedResultPackageMismatch,
    ParsedResultInferenceMismatch,
    ParsedIntentResultMismatch,
    ParsedProposalResultMismatch,
    ParsedApprovalResultMismatch,
    ParseRepairResultMismatch,
    InvalidProposal(crate::execution::ProposalValidationError),
    InvalidInferenceParsedOutput(crate::execution::InferenceAdapterError),
    UnsupportedOutputShape,
    JsonRepairFailed,
    MissingRequiredField {
        field: &'static str,
    },
    InvalidFieldType {
        field: &'static str,
    },
    UnknownField {
        field: String,
    },
    InvalidEnumValue {
        field: &'static str,
        value: String,
    },
    MissingWorkerActionOrProposal,
}

impl Display for TurnContractError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RoleSchemaMismatch {
                role,
                schema_family,
            } => write!(
                f,
                "turn package role {:?} is incompatible with response schema family {:?}",
                role, schema_family
            ),
            Self::ContextBudgetPackageMismatch {
                budget_turn_package_ref,
                turn_package_id,
            } => write!(
                f,
                "context budget references turn package '{}', expected '{}'",
                budget_turn_package_ref, turn_package_id
            ),
            Self::MissingRequiredField { field } => {
                write!(f, "parsed turn output is missing required field '{field}'")
            }
            Self::InvalidFieldType { field } => {
                write!(f, "parsed turn output field '{field}' has the wrong type")
            }
            Self::UnknownField { field } => {
                write!(f, "parsed turn output contains unsupported field '{field}'")
            }
            Self::InvalidEnumValue { field, value } => write!(
                f,
                "parsed turn output field '{field}' contains unsupported value '{}'",
                value
            ),
            Self::InvalidProposal(error) => write!(f, "proposal validation failed: {error}"),
            Self::InvalidInferenceParsedOutput(error) => {
                write!(f, "inference parsed output validation failed: {error}")
            }
            other => write!(f, "{other:?}"),
        }
    }
}

impl Error for TurnContractError {}

pub fn render_turn_package(
    turn_package: &TurnPackage,
) -> Result<TurnRenderBundle, TurnContractError> {
    turn_package.validate()?;

    let timestamp = current_timestamp();
    let response_schema = build_turn_response_schema_record(turn_package, &timestamp)?;
    let budget = turn_package.context_budget.clone();
    let truncation_id = format!(
        "context-truncation:{}:{}",
        sanitize_id(&turn_package.turn_package_id),
        timestamp
    );
    let response_contract_text =
        build_response_contract_text(turn_package.response_schema_family, &response_schema)?;
    let system_text = build_prompt_frame(
        "System Frame",
        &turn_package.system_frame_ref,
        &turn_package.system_frame_text,
    );
    let program_text = build_prompt_frame(
        "Program Frame",
        &turn_package.program_frame_ref,
        &turn_package.program_frame_text,
    );
    let capability_text = build_prompt_frame(
        "Capability Frame",
        &turn_package.capability_frame_ref,
        &turn_package.capability_frame_text,
    );
    let agenda_text = build_prompt_frame(
        "Agenda Frame",
        &turn_package.agenda_ref,
        &turn_package.agenda_text,
    );

    let base_prompt_chars = system_text.chars().count()
        + program_text.chars().count()
        + capability_text.chars().count()
        + agenda_text.chars().count()
        + response_contract_text.chars().count();
    let remaining_chars = budget
        .max_rendered_prompt_chars
        .saturating_sub(base_prompt_chars);
    let selected_entries = select_continuity_entries(turn_package, remaining_chars);
    let omitted_entry_refs = turn_package
        .continuity_entries
        .iter()
        .filter(|entry| {
            !selected_entries
                .iter()
                .any(|selected| selected.entry_ref == entry.entry_ref)
        })
        .map(|entry| entry.entry_ref.clone())
        .collect::<Vec<_>>();
    let included_entry_refs = selected_entries
        .iter()
        .map(|entry| entry.entry_ref.clone())
        .collect::<Vec<_>>();
    let continuity_text =
        build_continuity_frame(&selected_entries, &omitted_entry_refs, &truncation_id);
    let truncation = ContextTruncationRecord {
        context_truncation_id: truncation_id.clone(),
        turn_package_ref: turn_package.turn_package_id.clone(),
        included_entry_refs,
        omitted_entry_refs: omitted_entry_refs.clone(),
        summary: if omitted_entry_refs.is_empty() {
            "continuity entries fit within the explicit context budget".to_string()
        } else {
            format!(
                "{} continuity entr{} were omitted under bounded context budgeting",
                omitted_entry_refs.len(),
                if omitted_entry_refs.len() == 1 {
                    "y"
                } else {
                    "ies"
                }
            )
        },
        created_at: timestamp.clone(),
    };

    let prompt_layers = vec![
        build_prompt_layer_record(
            turn_package,
            PromptLayerKind::SystemFrame,
            &turn_package.system_frame_ref,
            system_text,
            &timestamp,
        ),
        build_prompt_layer_record(
            turn_package,
            PromptLayerKind::ProgramFrame,
            &turn_package.program_frame_ref,
            program_text,
            &timestamp,
        ),
        build_prompt_layer_record(
            turn_package,
            PromptLayerKind::CapabilityFrame,
            &turn_package.capability_frame_ref,
            capability_text,
            &timestamp,
        ),
        build_prompt_layer_record(
            turn_package,
            PromptLayerKind::ContinuityFrame,
            &truncation.context_truncation_id,
            continuity_text,
            &timestamp,
        ),
        build_prompt_layer_record(
            turn_package,
            PromptLayerKind::AgendaFrame,
            &turn_package.agenda_ref,
            agenda_text,
            &timestamp,
        ),
        build_prompt_layer_record(
            turn_package,
            PromptLayerKind::ResponseContractFrame,
            &response_schema.turn_response_schema_id,
            response_contract_text,
            &timestamp,
        ),
    ];
    let rendered_prompt_text = prompt_layers
        .iter()
        .map(|layer| layer.rendered_text.clone())
        .collect::<Vec<_>>()
        .join("\n\n");
    let rendering = PromptRenderingRecord {
        prompt_rendering_id: format!(
            "prompt-rendering:{}:{}",
            sanitize_id(&turn_package.turn_package_id),
            timestamp
        ),
        turn_package_ref: turn_package.turn_package_id.clone(),
        layer_refs: prompt_layers
            .iter()
            .map(|layer| layer.prompt_layer_id.clone())
            .collect(),
        context_budget_ref: budget.context_budget_id.clone(),
        truncation_ref: truncation.context_truncation_id.clone(),
        response_schema_ref: response_schema.turn_response_schema_id.clone(),
        rendered_prompt_text: rendered_prompt_text.clone(),
        rendered_prompt_char_count: rendered_prompt_text.chars().count(),
        created_at: current_timestamp(),
    };

    let bundle = TurnRenderBundle {
        turn_package: turn_package.clone(),
        context_budget: budget,
        truncation,
        prompt_layers,
        response_schema,
        rendering,
    };
    bundle.validate()?;
    Ok(bundle)
}

pub fn parse_turn_package_output(
    turn_package: &TurnPackage,
    inference_turn_result: &InferenceTurnResult,
    parsed_output: Option<&InferenceParsedOutputRecord>,
) -> Result<ParsedTurnBundle, TurnContractError> {
    turn_package.validate()?;
    let parsed_result_id = format!(
        "parsed-turn-result:{}:{}",
        sanitize_id(&turn_package.turn_package_id),
        sanitize_id(&inference_turn_result.turn_result_id)
    );
    let timestamp = current_timestamp();

    if inference_turn_result.finish_reason != InferenceFinishReason::Completed
        || parsed_output.is_none()
    {
        let bundle = ParsedTurnBundle {
            turn_package: turn_package.clone(),
            inference_turn_result: inference_turn_result.clone(),
            parsed_output: parsed_output.cloned(),
            parsed_result: ParsedTurnResult {
                parsed_turn_result_id: parsed_result_id,
                turn_package_ref: turn_package.turn_package_id.clone(),
                inference_turn_result_ref: inference_turn_result.turn_result_id.clone(),
                inference_parsed_output_ref: parsed_output
                    .map(|record| record.parsed_output_id.clone()),
                status: ParsedTurnResultStatus::RejectedContract,
                parsed_tool_call_intent_refs: Vec::new(),
                parsed_proposal_refs: Vec::new(),
                parsed_approval_request_ref: None,
                stop_recommendation: None,
                repair_refs: Vec::new(),
                tool_execution_refs: Vec::new(),
                tool_execution_receipt_refs: Vec::new(),
                summary: format!(
                    "inference turn `{}` finished as `{:?}` and did not yield a parseable contract result",
                    inference_turn_result.turn_result_id, inference_turn_result.finish_reason
                ),
                notes: Vec::new(),
                created_at: timestamp,
            },
            parsed_tool_call_intents: Vec::new(),
            parsed_proposals: Vec::new(),
            parsed_approval_request: None,
            repair_records: Vec::new(),
        };
        bundle.validate()?;
        return Ok(bundle);
    }

    let parsed_output = parsed_output.expect("checked above").clone();
    parsed_output
        .validate()
        .map_err(TurnContractError::InvalidInferenceParsedOutput)?;
    let parse_outcome =
        parse_contract_output(turn_package, &parsed_output, &parsed_result_id, &timestamp)?;
    let parsed_result = ParsedTurnResult {
        parsed_turn_result_id: parsed_result_id.clone(),
        turn_package_ref: turn_package.turn_package_id.clone(),
        inference_turn_result_ref: inference_turn_result.turn_result_id.clone(),
        inference_parsed_output_ref: Some(parsed_output.parsed_output_id.clone()),
        status: parse_outcome.status,
        parsed_tool_call_intent_refs: parse_outcome
            .tool_call_intents
            .iter()
            .map(|record| record.parsed_tool_call_intent_id.clone())
            .collect(),
        parsed_proposal_refs: parse_outcome
            .proposals
            .iter()
            .map(|record| record.parsed_proposal_id.clone())
            .collect(),
        parsed_approval_request_ref: parse_outcome
            .approval_request
            .as_ref()
            .map(|record| record.parsed_approval_request_id.clone()),
        stop_recommendation: parse_outcome.stop_recommendation,
        repair_refs: parse_outcome
            .repair_records
            .iter()
            .map(|record| record.parse_repair_id.clone())
            .collect(),
        tool_execution_refs: Vec::new(),
        tool_execution_receipt_refs: Vec::new(),
        summary: parse_outcome.summary,
        notes: parse_outcome.notes,
        created_at: timestamp.clone(),
    };
    let bundle = ParsedTurnBundle {
        turn_package: turn_package.clone(),
        inference_turn_result: inference_turn_result.clone(),
        parsed_output: Some(parsed_output),
        parsed_result,
        parsed_tool_call_intents: parse_outcome.tool_call_intents,
        parsed_proposals: parse_outcome.proposals,
        parsed_approval_request: parse_outcome.approval_request,
        repair_records: parse_outcome.repair_records,
    };
    bundle.validate()?;
    Ok(bundle)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ParseOutcome {
    status: ParsedTurnResultStatus,
    tool_call_intents: Vec<ParsedToolCallIntentRecord>,
    proposals: Vec<ParsedProposalRecord>,
    approval_request: Option<ParsedApprovalRequestRecord>,
    stop_recommendation: Option<StopConditionDecision>,
    repair_records: Vec<ParseRepairRecord>,
    summary: String,
    notes: Vec<String>,
}

fn parse_contract_output(
    turn_package: &TurnPackage,
    parsed_output: &InferenceParsedOutputRecord,
    parsed_result_id: &str,
    timestamp: &str,
) -> Result<ParseOutcome, TurnContractError> {
    let (value, repair_steps) = normalize_output_value(&parsed_output.normalized_output_json)?;
    let repair_records = repair_steps
        .iter()
        .enumerate()
        .map(|(index, (repair_class, summary))| ParseRepairRecord {
            parse_repair_id: format!(
                "parse-repair:{}:{}",
                sanitize_id(parsed_result_id),
                index + 1
            ),
            parsed_result_ref: parsed_result_id.to_string(),
            repair_class: *repair_class,
            summary: summary.clone(),
            created_at: timestamp.to_string(),
        })
        .collect::<Vec<_>>();

    let Some(object) = value.as_object() else {
        return Ok(rejected_parse_outcome(
            repair_records,
            format!(
                "turn package `{}` received a parsed output that is not a JSON object",
                turn_package.turn_package_id
            ),
        ));
    };

    let allowed_fields = BTreeSet::from([
        "summary",
        "proposals",
        "tool_call_intents",
        "approval_request",
        "stop_recommendation",
        "notes",
    ]);
    for key in object.keys() {
        if !allowed_fields.contains(key.as_str()) {
            return Ok(rejected_parse_outcome(
                repair_records,
                TurnContractError::UnknownField { field: key.clone() }.to_string(),
            ));
        }
    }

    let summary = match required_string_field(object, "summary") {
        Ok(summary) => summary,
        Err(error) => return Ok(rejected_parse_outcome(repair_records, error.to_string())),
    };
    let proposals_value = object.get("proposals");
    let tool_calls_value = object.get("tool_call_intents");
    let approval_value = object.get("approval_request");
    let stop_value = object.get("stop_recommendation");
    let notes = match optional_string_array_field(object, "notes") {
        Ok(notes) => notes,
        Err(error) => return Ok(rejected_parse_outcome(repair_records, error.to_string())),
    };

    let proposals = match proposals_value {
        Some(value) => match parse_proposals(parsed_result_id, value, timestamp) {
            Ok(records) => records,
            Err(error) => return Ok(rejected_parse_outcome(repair_records, error.to_string())),
        },
        None => Vec::new(),
    };
    let tool_call_intents = match tool_calls_value {
        Some(value) => match parse_tool_call_intents(parsed_result_id, value, timestamp) {
            Ok(records) => records,
            Err(error) => return Ok(rejected_parse_outcome(repair_records, error.to_string())),
        },
        None => Vec::new(),
    };
    let approval_request = match approval_value {
        Some(value) => match parse_approval_request(parsed_result_id, value, timestamp) {
            Ok(record) => Some(record),
            Err(error) => return Ok(rejected_parse_outcome(repair_records, error.to_string())),
        },
        None => None,
    };
    let stop_recommendation = match stop_value {
        Some(value) => match parse_stop_recommendation(value) {
            Ok(decision) => Some(decision),
            Err(error) => return Ok(rejected_parse_outcome(repair_records, error.to_string())),
        },
        None => None,
    };

    match turn_package.response_schema_family {
        TurnResponseSchemaFamily::SupervisorTurnV1 => {
            if proposals.is_empty() {
                return Ok(rejected_parse_outcome(
                    repair_records,
                    TurnContractError::MissingRequiredField { field: "proposals" }.to_string(),
                ));
            }
            if stop_recommendation.is_none() {
                return Ok(rejected_parse_outcome(
                    repair_records,
                    TurnContractError::MissingRequiredField {
                        field: "stop_recommendation",
                    }
                    .to_string(),
                ));
            }
        }
        TurnResponseSchemaFamily::WorkerTurnV1 => {
            if proposals.is_empty() && tool_call_intents.is_empty() {
                return Ok(rejected_parse_outcome(
                    repair_records,
                    TurnContractError::MissingWorkerActionOrProposal.to_string(),
                ));
            }
        }
    }

    Ok(ParseOutcome {
        status: ParsedTurnResultStatus::Parsed,
        tool_call_intents,
        proposals,
        approval_request,
        stop_recommendation,
        repair_records,
        summary,
        notes,
    })
}

fn rejected_parse_outcome(repair_records: Vec<ParseRepairRecord>, summary: String) -> ParseOutcome {
    ParseOutcome {
        status: ParsedTurnResultStatus::RejectedContract,
        tool_call_intents: Vec::new(),
        proposals: Vec::new(),
        approval_request: None,
        stop_recommendation: None,
        repair_records,
        summary: format!("did not yield a parseable contract result: {summary}"),
        notes: Vec::new(),
    }
}

fn parse_proposals(
    parsed_result_id: &str,
    value: &Value,
    timestamp: &str,
) -> Result<Vec<ParsedProposalRecord>, TurnContractError> {
    let array = value
        .as_array()
        .ok_or(TurnContractError::InvalidFieldType { field: "proposals" })?;
    if array.is_empty() {
        return Ok(Vec::new());
    }
    array
        .iter()
        .enumerate()
        .map(|(index, item)| {
            let object = item
                .as_object()
                .ok_or(TurnContractError::InvalidFieldType { field: "proposals" })?;
            let proposal_family =
                proposal_family_from_wire(required_string_field(object, "proposal_family")?)?;
            let summary = required_string_field(object, "summary")?;
            let target_ref = match object.get("target_ref") {
                Some(Value::String(value)) if !value.trim().is_empty() => Some(value.clone()),
                Some(Value::Null) | None => None,
                Some(_) => {
                    return Err(TurnContractError::InvalidFieldType {
                        field: "target_ref",
                    });
                }
            };
            let proposal = NormalizedProposal::new(proposal_family, summary, target_ref)
                .map_err(TurnContractError::InvalidProposal)?;
            Ok(ParsedProposalRecord {
                parsed_proposal_id: format!(
                    "parsed-proposal:{}:{}",
                    sanitize_id(parsed_result_id),
                    index + 1
                ),
                parsed_result_ref: parsed_result_id.to_string(),
                proposal,
                created_at: timestamp.to_string(),
            })
        })
        .collect()
}

fn parse_tool_call_intents(
    parsed_result_id: &str,
    value: &Value,
    timestamp: &str,
) -> Result<Vec<ParsedToolCallIntentRecord>, TurnContractError> {
    let array = value
        .as_array()
        .ok_or(TurnContractError::InvalidFieldType {
            field: "tool_call_intents",
        })?;
    if array.is_empty() {
        return Ok(Vec::new());
    }
    array
        .iter()
        .enumerate()
        .map(|(index, item)| {
            let object = item
                .as_object()
                .ok_or(TurnContractError::InvalidFieldType {
                    field: "tool_call_intents",
                })?;
            let tool_id = required_string_field(object, "tool_id")?;
            let arguments = object
                .get("arguments")
                .ok_or(TurnContractError::MissingRequiredField { field: "arguments" })?;
            let summary = object
                .get("summary")
                .and_then(Value::as_str)
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| format!("model requested tool `{tool_id}`"));
            Ok(ParsedToolCallIntentRecord {
                parsed_tool_call_intent_id: format!(
                    "parsed-tool-call-intent:{}:{}",
                    sanitize_id(parsed_result_id),
                    index + 1
                ),
                parsed_result_ref: parsed_result_id.to_string(),
                tool_id,
                arguments_json: serde_json::to_string(arguments)
                    .map_err(|_| TurnContractError::InvalidToolArgumentsJson)?,
                summary,
                created_at: timestamp.to_string(),
            })
        })
        .collect()
}

fn parse_approval_request(
    parsed_result_id: &str,
    value: &Value,
    timestamp: &str,
) -> Result<ParsedApprovalRequestRecord, TurnContractError> {
    let object = value
        .as_object()
        .ok_or(TurnContractError::InvalidFieldType {
            field: "approval_request",
        })?;
    Ok(ParsedApprovalRequestRecord {
        parsed_approval_request_id: format!(
            "parsed-approval-request:{}",
            sanitize_id(parsed_result_id)
        ),
        parsed_result_ref: parsed_result_id.to_string(),
        summary: required_string_field(object, "summary")?,
        action_ref: required_string_field(object, "action_ref")?,
        scope_ref: required_string_field(object, "scope_ref")?,
        requested_authority_class: authority_class_from_wire(required_string_field(
            object,
            "requested_authority_class",
        )?)?,
        created_at: timestamp.to_string(),
    })
}

fn parse_stop_recommendation(value: &Value) -> Result<StopConditionDecision, TurnContractError> {
    let value = value.as_str().ok_or(TurnContractError::InvalidFieldType {
        field: "stop_recommendation",
    })?;
    match value {
        "continue" => Ok(StopConditionDecision::Continue),
        "constrain" => Ok(StopConditionDecision::Constrain),
        "pause" => Ok(StopConditionDecision::Pause),
        "stop" => Ok(StopConditionDecision::Stop),
        other => Err(TurnContractError::InvalidEnumValue {
            field: "stop_recommendation",
            value: other.to_string(),
        }),
    }
}

fn normalize_output_value(
    normalized_output_json: &str,
) -> Result<(Value, Vec<(ParseRepairClass, String)>), TurnContractError> {
    let base_value = serde_json::from_str::<Value>(normalized_output_json)
        .map_err(|_| TurnContractError::JsonRepairFailed)?;
    if base_value.is_object() {
        return Ok((base_value, Vec::new()));
    }
    let Some(mut working) = base_value.as_str().map(str::to_string) else {
        return Ok((base_value, Vec::new()));
    };
    let mut repairs = Vec::new();
    let trimmed = working.trim().to_string();
    if trimmed != working {
        working = trimmed;
        repairs.push((
            ParseRepairClass::WhitespaceNormalization,
            "trimmed surrounding whitespace around the parsed output payload".to_string(),
        ));
    }
    if let Some(unwrapped) = unwrap_code_fence(&working) {
        working = unwrapped;
        repairs.push((
            ParseRepairClass::CodeFenceUnwrap,
            "removed a markdown code fence around the parsed output payload".to_string(),
        ));
    }
    let trimmed = working.trim().to_string();
    if trimmed != working {
        working = trimmed;
        repairs.push((
            ParseRepairClass::WhitespaceNormalization,
            "trimmed whitespace after removing formatting wrappers".to_string(),
        ));
    }
    if let Ok(value) = serde_json::from_str::<Value>(&working) {
        return Ok((value, repairs));
    }
    if let Some(extracted) = extract_single_json_object(&working) {
        working = extracted;
        repairs.push((
            ParseRepairClass::SingleJsonObjectExtract,
            "extracted one unambiguous JSON object from surrounding prose".to_string(),
        ));
        let value = serde_json::from_str::<Value>(&working)
            .map_err(|_| TurnContractError::JsonRepairFailed)?;
        return Ok((value, repairs));
    }
    Err(TurnContractError::JsonRepairFailed)
}

fn unwrap_code_fence(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if !trimmed.starts_with("```") || !trimmed.ends_with("```") {
        return None;
    }
    let inner = trimmed
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim_start_matches("json")
        .trim_start_matches('\n')
        .trim();
    Some(inner.to_string())
}

fn extract_single_json_object(value: &str) -> Option<String> {
    let mut start_index = None;
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escape = false;
    let mut end_index = None;
    for (index, ch) in value.char_indices() {
        if in_string {
            if escape {
                escape = false;
                continue;
            }
            match ch {
                '\\' => escape = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match ch {
            '"' => in_string = true,
            '{' => {
                if start_index.is_none() {
                    start_index = Some(index);
                }
                depth += 1;
            }
            '}' => {
                if depth == 0 {
                    return None;
                }
                depth -= 1;
                if depth == 0 {
                    end_index = Some(index + ch.len_utf8());
                    break;
                }
            }
            _ => {}
        }
    }
    let (start, end) = (start_index?, end_index?);
    if value[end..].chars().any(|ch| !ch.is_whitespace())
        && value[..start].chars().all(|ch| ch.is_whitespace())
    {
        // leading-only whitespace with trailing prose is still allowed below
    }
    if value[..start]
        .chars()
        .chain(value[end..].chars())
        .any(|ch| !ch.is_whitespace() && ch != ':' && ch != '-')
    {
        let prefix = value[..start].trim();
        let suffix = value[end..].trim();
        if !prefix.is_empty() && !suffix.is_empty() {
            return Some(value[start..end].to_string());
        }
    }
    Some(value[start..end].to_string())
}

fn required_string_field(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<String, TurnContractError> {
    let value = object
        .get(field)
        .ok_or(TurnContractError::MissingRequiredField { field })?;
    let value = value
        .as_str()
        .ok_or(TurnContractError::InvalidFieldType { field })?;
    require_nonempty(value, TurnContractError::MissingRequiredField { field })?;
    Ok(value.to_string())
}

fn optional_string_array_field(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<Vec<String>, TurnContractError> {
    let Some(value) = object.get(field) else {
        return Ok(Vec::new());
    };
    let array = value
        .as_array()
        .ok_or(TurnContractError::InvalidFieldType { field })?;
    array
        .iter()
        .map(|item| {
            let value = item
                .as_str()
                .ok_or(TurnContractError::InvalidFieldType { field })?;
            require_nonempty(value, TurnContractError::MissingParsedNote)?;
            Ok(value.to_string())
        })
        .collect()
}

fn proposal_family_from_wire(value: String) -> Result<ProposalFamily, TurnContractError> {
    match value.as_str() {
        "task_complete" => Ok(ProposalFamily::TaskComplete),
        "task_update" => Ok(ProposalFamily::TaskUpdate),
        "capability_call_request" => Ok(ProposalFamily::CapabilityCallRequest),
        "worker_spawn_request" => Ok(ProposalFamily::WorkerSpawnRequest),
        "memory_fetch_request" => Ok(ProposalFamily::MemoryFetchRequest),
        "memory_write_request" => Ok(ProposalFamily::MemoryWriteRequest),
        "approval_request" => Ok(ProposalFamily::ApprovalRequest),
        "synthesis_summary" => Ok(ProposalFamily::SynthesisSummary),
        "halt_or_escalate" => Ok(ProposalFamily::HaltOrEscalate),
        other => Err(TurnContractError::InvalidEnumValue {
            field: "proposal_family",
            value: other.to_string(),
        }),
    }
}

fn authority_class_from_wire(value: String) -> Result<AuthorityClass, TurnContractError> {
    match value.as_str() {
        "observe" => Ok(AuthorityClass::Observe),
        "local_mutate" => Ok(AuthorityClass::LocalMutate),
        "campaign_control" => Ok(AuthorityClass::CampaignControl),
        "external_interact" => Ok(AuthorityClass::ExternalInteract),
        "sensitive_access" => Ok(AuthorityClass::SensitiveAccess),
        "promotion_control" => Ok(AuthorityClass::PromotionControl),
        "automation_control" => Ok(AuthorityClass::AutomationControl),
        other => Err(TurnContractError::InvalidEnumValue {
            field: "requested_authority_class",
            value: other.to_string(),
        }),
    }
}

fn select_continuity_entries(
    turn_package: &TurnPackage,
    mut remaining_chars: usize,
) -> Vec<TurnContinuityEntry> {
    let mut selected = Vec::new();
    let mut ordered = turn_package
        .continuity_entries
        .iter()
        .filter(|entry| entry.priority == ContinuityEntryPriority::Critical)
        .chain(
            turn_package
                .continuity_entries
                .iter()
                .filter(|entry| entry.priority == ContinuityEntryPriority::Supporting),
        );

    for entry in ordered.by_ref() {
        if selected.len() >= turn_package.context_budget.max_continuity_entries {
            break;
        }
        let candidate_text = build_continuity_entry_text(entry);
        let candidate_chars = candidate_text.chars().count();
        if candidate_chars > remaining_chars {
            continue;
        }
        selected.push(entry.clone());
        remaining_chars = remaining_chars.saturating_sub(candidate_chars);
    }
    selected
}

fn build_turn_response_schema_record(
    turn_package: &TurnPackage,
    timestamp: &str,
) -> Result<TurnResponseSchemaRecord, TurnContractError> {
    let schema_json = match turn_package.response_schema_family {
        TurnResponseSchemaFamily::SupervisorTurnV1 => supervisor_turn_schema_json(),
        TurnResponseSchemaFamily::WorkerTurnV1 => worker_turn_schema_json(),
    };
    Ok(TurnResponseSchemaRecord {
        turn_response_schema_id: format!(
            "turn-response-schema:{}:{}",
            sanitize_id(&turn_package.turn_package_id),
            timestamp
        ),
        turn_package_ref: turn_package.turn_package_id.clone(),
        schema_family: turn_package.response_schema_family,
        response_schema_json: serde_json::to_string(&schema_json)
            .map_err(|_| TurnContractError::InvalidResponseSchemaJson)?,
        created_at: timestamp.to_string(),
    })
}

fn build_prompt_layer_record(
    turn_package: &TurnPackage,
    kind: PromptLayerKind,
    source_ref: &str,
    rendered_text: String,
    timestamp: &str,
) -> PromptLayerRecord {
    PromptLayerRecord {
        prompt_layer_id: format!(
            "prompt-layer:{}:{}:{}",
            sanitize_id(&turn_package.turn_package_id),
            prompt_layer_kind_label(kind),
            timestamp
        ),
        turn_package_ref: turn_package.turn_package_id.clone(),
        kind,
        source_ref: source_ref.to_string(),
        rendered_text: rendered_text.clone(),
        rendered_char_count: rendered_text.chars().count(),
        created_at: timestamp.to_string(),
    }
}

fn prompt_layer_kind_label(kind: PromptLayerKind) -> &'static str {
    match kind {
        PromptLayerKind::SystemFrame => "system",
        PromptLayerKind::ProgramFrame => "program",
        PromptLayerKind::CapabilityFrame => "capability",
        PromptLayerKind::ContinuityFrame => "continuity",
        PromptLayerKind::AgendaFrame => "agenda",
        PromptLayerKind::ResponseContractFrame => "response-contract",
    }
}

fn build_prompt_frame(title: &str, source_ref: &str, body: &str) -> String {
    format!("### {title}\nsource_ref: {source_ref}\n{body}")
}

fn build_continuity_frame(
    included_entries: &[TurnContinuityEntry],
    omitted_entry_refs: &[String],
    truncation_ref: &str,
) -> String {
    let mut sections = vec!["### Continuity Frame".to_string()];
    if included_entries.is_empty() {
        sections.push("No continuity entries were carried into this bounded turn.".to_string());
    } else {
        for entry in included_entries {
            sections.push(build_continuity_entry_text(entry));
        }
    }
    if !omitted_entry_refs.is_empty() {
        sections.push(format!(
            "Missing context note: {} continuity entr{} were omitted under truncation record `{}`.",
            omitted_entry_refs.len(),
            if omitted_entry_refs.len() == 1 {
                "y"
            } else {
                "ies"
            },
            truncation_ref
        ));
    }
    sections.join("\n")
}

fn build_continuity_entry_text(entry: &TurnContinuityEntry) -> String {
    format!(
        "- entry_ref: {}\n  priority: {:?}\n  text: {}",
        entry.entry_ref, entry.priority, entry.text
    )
}

fn build_response_contract_text(
    family: TurnResponseSchemaFamily,
    response_schema: &TurnResponseSchemaRecord,
) -> Result<String, TurnContractError> {
    Ok(format!(
        "### Response Contract\nschema_family: {:?}\nresponse_schema_ref: {}\nReturn JSON that conforms exactly to this schema:\n{}",
        family, response_schema.turn_response_schema_id, response_schema.response_schema_json
    ))
}

fn supervisor_turn_schema_json() -> Value {
    json!({
        "type": "json_schema",
        "name": "supervisor_turn_v1",
        "strict": true,
        "schema": {
            "type": "object",
            "additionalProperties": false,
            "properties": common_turn_properties(),
            "required": ["summary", "proposals", "stop_recommendation"]
        }
    })
}

fn worker_turn_schema_json() -> Value {
    json!({
        "type": "json_schema",
        "name": "worker_turn_v1",
        "strict": true,
        "schema": {
            "type": "object",
            "additionalProperties": false,
            "properties": common_turn_properties(),
            "required": ["summary"],
            "anyOf": [
                { "required": ["proposals"] },
                { "required": ["tool_call_intents"] }
            ]
        }
    })
}

fn common_turn_properties() -> Value {
    json!({
        "summary": { "type": "string" },
        "notes": {
            "type": "array",
            "items": { "type": "string" }
        },
        "stop_recommendation": {
            "type": "string",
            "enum": ["continue", "constrain", "pause", "stop"]
        },
        "proposals": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "proposal_family": {
                        "type": "string",
                        "enum": [
                            "task_complete",
                            "task_update",
                            "capability_call_request",
                            "worker_spawn_request",
                            "memory_fetch_request",
                            "memory_write_request",
                            "approval_request",
                            "synthesis_summary",
                            "halt_or_escalate"
                        ]
                    },
                    "summary": { "type": "string" },
                    "target_ref": { "type": ["string", "null"] }
                },
                "required": ["proposal_family", "summary"]
            }
        },
        "tool_call_intents": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "tool_id": { "type": "string" },
                    "summary": { "type": "string" },
                    "arguments": { "type": ["object", "array", "string", "number", "boolean", "null"] }
                },
                "required": ["tool_id", "arguments"]
            }
        },
        "approval_request": {
            "type": "object",
            "additionalProperties": false,
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
            "required": ["summary", "action_ref", "scope_ref", "requested_authority_class"]
        }
    })
}

fn schema_family_matches_role(
    role: TurnPackageRole,
    schema_family: TurnResponseSchemaFamily,
) -> bool {
    matches!(
        (role, schema_family),
        (
            TurnPackageRole::Supervisor,
            TurnResponseSchemaFamily::SupervisorTurnV1
        ) | (
            TurnPackageRole::Worker,
            TurnResponseSchemaFamily::WorkerTurnV1
        )
    )
}

fn require_nonempty(value: &str, error: TurnContractError) -> Result<(), TurnContractError> {
    if value.trim().is_empty() {
        return Err(error);
    }
    Ok(())
}

fn validate_ref_entries(
    refs: &[String],
    error: TurnContractError,
) -> Result<(), TurnContractError> {
    if refs.is_empty() || refs.iter().any(|reference| reference.trim().is_empty()) {
        return Err(error);
    }
    Ok(())
}

fn parse_json_payload(payload: &str, error: TurnContractError) -> Result<(), TurnContractError> {
    serde_json::from_str::<Value>(payload)
        .map(|_| ())
        .map_err(|_| error)
}

fn sanitize_id(id: &str) -> String {
    id.chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect()
}

fn current_timestamp() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::{
        ContextBudgetRecord, ContinuityEntryPriority, ParseRepairClass, ParsedTurnResultStatus,
        TurnPackage, TurnPackageRole, TurnResponseSchemaFamily, parse_turn_package_output,
        render_turn_package,
    };
    use crate::execution::{
        InferenceFinishReason, InferenceParsedOutputRecord, InferenceTurnResult,
    };

    fn supervisor_package() -> TurnPackage {
        TurnPackage {
            turn_package_id: "turn-package:supervisor".to_string(),
            program_ref: "program:1".to_string(),
            session_ref: "session:1".to_string(),
            turn_ref: "turn:1".to_string(),
            envelope_ref: "envelope:1".to_string(),
            role: TurnPackageRole::Supervisor,
            system_frame_ref: "system:1".to_string(),
            system_frame_text: "You are the Wasm-Biotic supervisor.".to_string(),
            program_frame_ref: "program-frame:1".to_string(),
            program_frame_text: "Advance the bounded factory program.".to_string(),
            capability_frame_ref: "capability-frame:1".to_string(),
            capability_frame_text: "Stay inside the active capability envelope.".to_string(),
            agenda_ref: "agenda:1".to_string(),
            agenda_text: "Evaluate the next bounded lineage step.".to_string(),
            continuity_entries: vec![
                super::TurnContinuityEntry {
                    entry_ref: "continuity:critical".to_string(),
                    text: "Critical contradiction evidence.".to_string(),
                    priority: ContinuityEntryPriority::Critical,
                },
                super::TurnContinuityEntry {
                    entry_ref: "continuity:supporting".to_string(),
                    text: "Supporting context that may be omitted.".to_string(),
                    priority: ContinuityEntryPriority::Supporting,
                },
            ],
            tool_catalog_ref: "tool-catalog:canonical:v1".to_string(),
            tool_execution_context_ref: "tool-context:supervisor".to_string(),
            response_schema_family: TurnResponseSchemaFamily::SupervisorTurnV1,
            context_budget: ContextBudgetRecord {
                context_budget_id: "context-budget:1".to_string(),
                turn_package_ref: "turn-package:supervisor".to_string(),
                max_rendered_prompt_chars: 5_000,
                max_continuity_entries: 1,
                created_at: "1".to_string(),
            },
            created_at: "1".to_string(),
        }
    }

    fn worker_package() -> TurnPackage {
        let mut package = supervisor_package();
        package.turn_package_id = "turn-package:worker".to_string();
        package.role = TurnPackageRole::Worker;
        package.response_schema_family = TurnResponseSchemaFamily::WorkerTurnV1;
        package.context_budget.turn_package_ref = package.turn_package_id.clone();
        package
    }

    fn inference_turn_result() -> InferenceTurnResult {
        InferenceTurnResult {
            turn_result_id: "inference-turn-result:1".to_string(),
            turn_request_ref: "inference-turn-request:1".to_string(),
            raw_output_ref: "inference-raw-output:1".to_string(),
            parsed_output_ref: Some("inference-parsed-output:1".to_string()),
            finish_reason: InferenceFinishReason::Completed,
            usage_record_ref: "usage:1".to_string(),
            provider_outcome_ref: "outcome:1".to_string(),
            attempt_refs: vec!["attempt:1".to_string()],
            provider_metadata_refs: vec!["provider-meta:1".to_string()],
            degradation_ref: None,
            created_at: "2".to_string(),
        }
    }

    #[test]
    fn turn_package_validation_rejects_role_schema_mismatch() {
        let mut package = supervisor_package();
        package.response_schema_family = TurnResponseSchemaFamily::WorkerTurnV1;
        let error = package.validate().unwrap_err();
        assert!(matches!(
            error,
            super::TurnContractError::RoleSchemaMismatch { .. }
        ));
    }

    #[test]
    fn render_is_deterministic_and_emits_visible_truncation() {
        let bundle = render_turn_package(&supervisor_package()).unwrap();
        assert_eq!(bundle.prompt_layers.len(), 6);
        assert!(
            bundle
                .prompt_layers
                .iter()
                .any(|layer| layer.kind == super::PromptLayerKind::ContinuityFrame)
        );
        assert_eq!(
            bundle.truncation.omitted_entry_refs,
            vec!["continuity:supporting"]
        );
        assert!(
            bundle
                .rendering
                .rendered_prompt_text
                .contains("Missing context note:")
        );
    }

    #[test]
    fn supervisor_parse_yields_proposals_tool_intents_approval_and_stop() {
        let output = InferenceParsedOutputRecord {
            parsed_output_id: "inference-parsed-output:1".to_string(),
            turn_request_ref: "inference-turn-request:1".to_string(),
            provider_ref: "provider:1".to_string(),
            model_ref: "model:1".to_string(),
            normalized_output_json: serde_json::json!({
                "summary": "bounded supervisor result",
                "proposals": [
                    {
                        "proposal_family": "task_update",
                        "summary": "update the active task"
                    }
                ],
                "tool_call_intents": [
                    {
                        "tool_id": "continuity.retrieve",
                        "arguments": {"pointer_index_ref": "pointer:1"}
                    }
                ],
                "approval_request": {
                    "summary": "need approval",
                    "action_ref": "action:1",
                    "scope_ref": "scope:1",
                    "requested_authority_class": "observe"
                },
                "stop_recommendation": "continue",
                "notes": ["grounded in continuity"]
            })
            .to_string(),
            created_at: "2".to_string(),
        };

        let bundle = parse_turn_package_output(
            &supervisor_package(),
            &inference_turn_result(),
            Some(&output),
        )
        .unwrap();
        assert_eq!(bundle.parsed_result.status, ParsedTurnResultStatus::Parsed);
        assert_eq!(bundle.parsed_proposals.len(), 1);
        assert_eq!(bundle.parsed_tool_call_intents.len(), 1);
        assert!(bundle.parsed_approval_request.is_some());
        assert_eq!(
            bundle.parsed_result.stop_recommendation,
            Some(crate::execution::StopConditionDecision::Continue)
        );
    }

    #[test]
    fn worker_role_accepts_tool_intent_without_supervisor_stop_requirement() {
        let output = InferenceParsedOutputRecord {
            parsed_output_id: "inference-parsed-output:1".to_string(),
            turn_request_ref: "inference-turn-request:1".to_string(),
            provider_ref: "provider:1".to_string(),
            model_ref: "model:1".to_string(),
            normalized_output_json: serde_json::json!({
                "summary": "worker result",
                "tool_call_intents": [
                    {
                        "tool_id": "ecology.collect_results",
                        "arguments": {"lease_ref": "lease:1"}
                    }
                ]
            })
            .to_string(),
            created_at: "2".to_string(),
        };

        let bundle =
            parse_turn_package_output(&worker_package(), &inference_turn_result(), Some(&output))
                .unwrap();
        assert_eq!(bundle.parsed_result.status, ParsedTurnResultStatus::Parsed);
        assert_eq!(bundle.parsed_proposals.len(), 0);
        assert_eq!(bundle.parsed_tool_call_intents.len(), 1);
        assert_eq!(bundle.parsed_result.stop_recommendation, None);
    }

    #[test]
    fn parse_repair_unwraps_fenced_json_and_records_repair() {
        let output = InferenceParsedOutputRecord {
            parsed_output_id: "inference-parsed-output:1".to_string(),
            turn_request_ref: "inference-turn-request:1".to_string(),
            provider_ref: "provider:1".to_string(),
            model_ref: "model:1".to_string(),
            normalized_output_json: serde_json::json!(
                "```json\n{\"summary\":\"ok\",\"proposals\":[{\"proposal_family\":\"task_update\",\"summary\":\"step\"}],\"stop_recommendation\":\"continue\"}\n```"
            )
            .to_string(),
            created_at: "2".to_string(),
        };

        let bundle = parse_turn_package_output(
            &supervisor_package(),
            &inference_turn_result(),
            Some(&output),
        )
        .unwrap();
        assert_eq!(bundle.parsed_result.status, ParsedTurnResultStatus::Parsed);
        assert_eq!(bundle.repair_records.len(), 1);
        assert_eq!(
            bundle.repair_records[0].repair_class,
            ParseRepairClass::CodeFenceUnwrap
        );
    }

    #[test]
    fn invalid_contract_is_persisted_as_rejected_contract() {
        let output = InferenceParsedOutputRecord {
            parsed_output_id: "inference-parsed-output:1".to_string(),
            turn_request_ref: "inference-turn-request:1".to_string(),
            provider_ref: "provider:1".to_string(),
            model_ref: "model:1".to_string(),
            normalized_output_json: serde_json::json!({
                "summary": "missing supervisor fields"
            })
            .to_string(),
            created_at: "2".to_string(),
        };

        let bundle = parse_turn_package_output(
            &supervisor_package(),
            &inference_turn_result(),
            Some(&output),
        )
        .unwrap();
        assert_eq!(
            bundle.parsed_result.status,
            ParsedTurnResultStatus::RejectedContract
        );
        assert!(bundle.parsed_proposals.is_empty());
        assert!(bundle.parsed_tool_call_intents.is_empty());
        assert!(
            bundle
                .parsed_result
                .summary
                .contains("did not yield a parseable contract result")
        );
        assert!(
            bundle
                .parsed_result
                .summary
                .contains("missing required field")
        );
    }
}
