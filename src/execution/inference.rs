use reqwest::{Client, StatusCode, Url};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_PROVIDER_RESPONSE_BODY_BYTES: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InferenceProviderMode {
    DeterministicFixture,
    OpenAiResponses,
    OpenRouterChatCompletions,
    Disabled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InferenceFinishReason {
    Completed,
    Refused,
    TimedOut,
    MalformedOutput,
    ProviderError,
    Interrupted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderDegradationReasonClass {
    Timeout,
    TransportFailure,
    MalformedOutput,
    Refusal,
    ProviderDisabled,
    UnsupportedModel,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InferenceRetryClassification {
    NoRetryNeeded,
    RetriedTimeout,
    RetriedTransportFailure,
    RetriedRateLimited,
    RetriedServerError,
    NonRetryableClientError,
    ExhaustedTimeout,
    ExhaustedTransportFailure,
    ExhaustedRateLimited,
    ExhaustedServerError,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceProviderModelEntry {
    pub model_ref: String,
    pub input_cost_per_million_microunits: u64,
    pub output_cost_per_million_microunits: u64,
    pub supports_json_schema: bool,
    pub supports_function_tools: bool,
}

impl InferenceProviderModelEntry {
    pub fn validate(&self) -> Result<(), InferenceAdapterError> {
        require_nonempty(&self.model_ref, InferenceAdapterError::MissingModelRef)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceProviderRegistryEntry {
    pub provider_id: String,
    pub provider_mode: InferenceProviderMode,
    pub models: Vec<InferenceProviderModelEntry>,
    pub capability_summary: String,
    pub policy_summary: String,
    pub active: bool,
    pub api_base_url: String,
    pub api_key_env_var: String,
    pub organization_env_var: Option<String>,
    pub project_env_var: Option<String>,
    pub request_timeout_ms: u64,
}

impl InferenceProviderRegistryEntry {
    pub fn validate(&self) -> Result<(), InferenceAdapterError> {
        require_nonempty(&self.provider_id, InferenceAdapterError::MissingProviderId)?;
        if self.models.is_empty() {
            return Err(InferenceAdapterError::MissingProviderModels);
        }
        for model in &self.models {
            model.validate()?;
        }
        for (index, model) in self.models.iter().enumerate() {
            if self.models[index + 1..]
                .iter()
                .any(|other| other.model_ref == model.model_ref)
            {
                return Err(InferenceAdapterError::DuplicateModelRef {
                    model_ref: model.model_ref.clone(),
                });
            }
        }
        require_nonempty(
            &self.capability_summary,
            InferenceAdapterError::MissingCapabilitySummary,
        )?;
        require_nonempty(
            &self.policy_summary,
            InferenceAdapterError::MissingPolicySummary,
        )?;
        validate_optional_ref(
            &self.organization_env_var,
            InferenceAdapterError::MissingEnvVarName,
        )?;
        validate_optional_ref(
            &self.project_env_var,
            InferenceAdapterError::MissingEnvVarName,
        )?;

        match self.provider_mode {
            InferenceProviderMode::OpenAiResponses
            | InferenceProviderMode::OpenRouterChatCompletions => {
                require_nonempty(&self.api_base_url, InferenceAdapterError::MissingApiBaseUrl)?;
                require_nonempty(
                    &self.api_key_env_var,
                    InferenceAdapterError::MissingApiKeyEnvVar,
                )?;
                if self.request_timeout_ms == 0 {
                    return Err(InferenceAdapterError::InvalidRequestTimeoutMs);
                }
                parse_base_url(&self.api_base_url)?;
            }
            InferenceProviderMode::DeterministicFixture | InferenceProviderMode::Disabled => {
                if self.request_timeout_ms == 0 {
                    return Err(InferenceAdapterError::InvalidRequestTimeoutMs);
                }
            }
        }

        Ok(())
    }

    pub fn allows_model(&self, model_ref: &str) -> bool {
        self.models.iter().any(|model| model.model_ref == model_ref)
    }

    pub fn model_entry(
        &self,
        model_ref: &str,
    ) -> Result<&InferenceProviderModelEntry, InferenceAdapterError> {
        self.models
            .iter()
            .find(|model| model.model_ref == model_ref)
            .ok_or_else(|| InferenceAdapterError::UnsupportedModel {
                provider_id: self.provider_id.clone(),
                model_ref: model_ref.to_string(),
            })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceGenerationPolicy {
    pub generation_policy_id: String,
    pub max_output_tokens: usize,
    pub max_retries: usize,
    pub summary: String,
}

impl InferenceGenerationPolicy {
    pub fn validate(&self) -> Result<(), InferenceAdapterError> {
        require_nonempty(
            &self.generation_policy_id,
            InferenceAdapterError::MissingGenerationPolicyId,
        )?;
        if self.max_output_tokens == 0 {
            return Err(InferenceAdapterError::InvalidMaxOutputTokens);
        }
        require_nonempty(
            &self.summary,
            InferenceAdapterError::MissingGenerationPolicySummary,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceTurnRequest {
    pub turn_request_id: String,
    pub provider_ref: String,
    pub model_ref: String,
    pub rendered_prompt_ref: String,
    pub tool_catalog_ref: String,
    pub response_schema_ref: String,
    pub generation_policy_ref: String,
}

impl InferenceTurnRequest {
    pub fn validate(&self) -> Result<(), InferenceAdapterError> {
        require_nonempty(
            &self.turn_request_id,
            InferenceAdapterError::MissingTurnRequestId,
        )?;
        require_nonempty(
            &self.provider_ref,
            InferenceAdapterError::MissingProviderRef,
        )?;
        require_nonempty(&self.model_ref, InferenceAdapterError::MissingModelRef)?;
        require_nonempty(
            &self.rendered_prompt_ref,
            InferenceAdapterError::MissingRenderedPromptRef,
        )?;
        require_nonempty(
            &self.tool_catalog_ref,
            InferenceAdapterError::MissingToolCatalogRef,
        )?;
        require_nonempty(
            &self.response_schema_ref,
            InferenceAdapterError::MissingResponseSchemaRef,
        )?;
        require_nonempty(
            &self.generation_policy_ref,
            InferenceAdapterError::MissingGenerationPolicyRef,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceRenderedPromptRecord {
    pub rendered_prompt_id: String,
    pub turn_request_ref: String,
    pub prompt_text: String,
    pub created_at: String,
}

impl InferenceRenderedPromptRecord {
    pub fn validate(&self) -> Result<(), InferenceAdapterError> {
        require_nonempty(
            &self.rendered_prompt_id,
            InferenceAdapterError::MissingRenderedPromptId,
        )?;
        require_nonempty(
            &self.turn_request_ref,
            InferenceAdapterError::MissingTurnRequestRef,
        )?;
        require_nonempty(&self.prompt_text, InferenceAdapterError::MissingPromptText)?;
        require_nonempty(&self.created_at, InferenceAdapterError::MissingCreatedAt)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceToolCatalogPayloadRecord {
    pub tool_catalog_id: String,
    pub turn_request_ref: String,
    pub tool_catalog_json: String,
    pub created_at: String,
}

impl InferenceToolCatalogPayloadRecord {
    pub fn validate(&self) -> Result<(), InferenceAdapterError> {
        require_nonempty(
            &self.tool_catalog_id,
            InferenceAdapterError::MissingToolCatalogId,
        )?;
        require_nonempty(
            &self.turn_request_ref,
            InferenceAdapterError::MissingTurnRequestRef,
        )?;
        require_nonempty(
            &self.tool_catalog_json,
            InferenceAdapterError::MissingToolCatalogJson,
        )?;
        parse_json_payload(
            &self.tool_catalog_json,
            InferenceAdapterError::InvalidToolCatalogJson,
        )?;
        require_nonempty(&self.created_at, InferenceAdapterError::MissingCreatedAt)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceResponseSchemaPayloadRecord {
    pub response_schema_id: String,
    pub turn_request_ref: String,
    pub response_schema_json: String,
    pub created_at: String,
}

impl InferenceResponseSchemaPayloadRecord {
    pub fn validate(&self) -> Result<(), InferenceAdapterError> {
        require_nonempty(
            &self.response_schema_id,
            InferenceAdapterError::MissingResponseSchemaId,
        )?;
        require_nonempty(
            &self.turn_request_ref,
            InferenceAdapterError::MissingTurnRequestRef,
        )?;
        require_nonempty(
            &self.response_schema_json,
            InferenceAdapterError::MissingResponseSchemaJson,
        )?;
        parse_json_payload(
            &self.response_schema_json,
            InferenceAdapterError::InvalidResponseSchemaJson,
        )?;
        require_nonempty(&self.created_at, InferenceAdapterError::MissingCreatedAt)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceRequestBodyRecord {
    pub request_body_id: String,
    pub turn_request_ref: String,
    pub attempt_number: usize,
    pub request_body_json: String,
    pub created_at: String,
}

impl InferenceRequestBodyRecord {
    pub fn validate(&self) -> Result<(), InferenceAdapterError> {
        require_nonempty(
            &self.request_body_id,
            InferenceAdapterError::MissingRequestBodyId,
        )?;
        require_nonempty(
            &self.turn_request_ref,
            InferenceAdapterError::MissingTurnRequestRef,
        )?;
        if self.attempt_number == 0 {
            return Err(InferenceAdapterError::InvalidAttemptNumber);
        }
        require_nonempty(
            &self.request_body_json,
            InferenceAdapterError::MissingRequestBodyJson,
        )?;
        parse_json_payload(
            &self.request_body_json,
            InferenceAdapterError::InvalidRequestBodyJson,
        )?;
        require_nonempty(&self.created_at, InferenceAdapterError::MissingCreatedAt)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceRawOutputRecord {
    pub raw_output_id: String,
    pub turn_request_ref: String,
    pub provider_ref: String,
    pub model_ref: String,
    pub attempt_number: usize,
    pub raw_output_payload: String,
    pub created_at: String,
}

impl InferenceRawOutputRecord {
    pub fn validate(&self) -> Result<(), InferenceAdapterError> {
        require_nonempty(
            &self.raw_output_id,
            InferenceAdapterError::MissingRawOutputId,
        )?;
        require_nonempty(
            &self.turn_request_ref,
            InferenceAdapterError::MissingTurnRequestRef,
        )?;
        require_nonempty(
            &self.provider_ref,
            InferenceAdapterError::MissingProviderRef,
        )?;
        require_nonempty(&self.model_ref, InferenceAdapterError::MissingModelRef)?;
        if self.attempt_number == 0 {
            return Err(InferenceAdapterError::InvalidAttemptNumber);
        }
        require_nonempty(
            &self.raw_output_payload,
            InferenceAdapterError::MissingRawOutputPayload,
        )?;
        require_nonempty(&self.created_at, InferenceAdapterError::MissingCreatedAt)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceUsageRecord {
    pub usage_record_id: String,
    pub turn_request_ref: String,
    pub input_tokens: usize,
    pub output_tokens: usize,
    pub total_tokens: usize,
    pub latency_ms: u64,
    pub estimated_cost_microunits: u64,
    pub currency: String,
    pub created_at: String,
}

impl InferenceUsageRecord {
    pub fn validate(&self) -> Result<(), InferenceAdapterError> {
        require_nonempty(
            &self.usage_record_id,
            InferenceAdapterError::MissingUsageRecordId,
        )?;
        require_nonempty(
            &self.turn_request_ref,
            InferenceAdapterError::MissingTurnRequestRef,
        )?;
        if self.total_tokens != self.input_tokens + self.output_tokens {
            return Err(InferenceAdapterError::InvalidUsageTotals);
        }
        require_nonempty(&self.currency, InferenceAdapterError::MissingCurrency)?;
        require_nonempty(&self.created_at, InferenceAdapterError::MissingCreatedAt)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceAttemptRecord {
    pub attempt_id: String,
    pub turn_request_ref: String,
    pub attempt_number: usize,
    pub request_body_ref: String,
    pub raw_response_body_ref: String,
    pub http_status: Option<u16>,
    pub latency_ms: u64,
    pub retry_classification: InferenceRetryClassification,
    pub provider_response_id: Option<String>,
    pub provider_request_id: Option<String>,
    pub transport_error_summary: Option<String>,
    pub created_at: String,
}

impl InferenceAttemptRecord {
    pub fn validate(&self) -> Result<(), InferenceAdapterError> {
        require_nonempty(&self.attempt_id, InferenceAdapterError::MissingAttemptId)?;
        require_nonempty(
            &self.turn_request_ref,
            InferenceAdapterError::MissingTurnRequestRef,
        )?;
        if self.attempt_number == 0 {
            return Err(InferenceAdapterError::InvalidAttemptNumber);
        }
        require_nonempty(
            &self.request_body_ref,
            InferenceAdapterError::MissingRequestBodyRef,
        )?;
        require_nonempty(
            &self.raw_response_body_ref,
            InferenceAdapterError::MissingRawResponseBodyRef,
        )?;
        validate_optional_ref(
            &self.provider_response_id,
            InferenceAdapterError::MissingProviderResponseId,
        )?;
        validate_optional_ref(
            &self.provider_request_id,
            InferenceAdapterError::MissingProviderRequestId,
        )?;
        validate_optional_ref(
            &self.transport_error_summary,
            InferenceAdapterError::MissingTransportErrorSummary,
        )?;
        require_nonempty(&self.created_at, InferenceAdapterError::MissingCreatedAt)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceProviderOutcomeRecord {
    pub provider_outcome_id: String,
    pub turn_request_ref: String,
    pub provider_ref: String,
    pub model_ref: String,
    pub finish_reason: InferenceFinishReason,
    pub final_http_status: Option<u16>,
    pub attempt_refs: Vec<String>,
    pub refusal_summary: Option<String>,
    pub provider_response_id: Option<String>,
    pub provider_request_id: Option<String>,
    pub input_tokens: usize,
    pub output_tokens: usize,
    pub total_tokens: usize,
    pub latency_ms: u64,
    pub estimated_cost_microunits: u64,
    pub currency: String,
    pub created_at: String,
}

impl InferenceProviderOutcomeRecord {
    pub fn validate(&self) -> Result<(), InferenceAdapterError> {
        require_nonempty(
            &self.provider_outcome_id,
            InferenceAdapterError::MissingProviderOutcomeId,
        )?;
        require_nonempty(
            &self.turn_request_ref,
            InferenceAdapterError::MissingTurnRequestRef,
        )?;
        require_nonempty(
            &self.provider_ref,
            InferenceAdapterError::MissingProviderRef,
        )?;
        require_nonempty(&self.model_ref, InferenceAdapterError::MissingModelRef)?;
        if self.attempt_refs.is_empty()
            || self
                .attempt_refs
                .iter()
                .any(|reference| reference.trim().is_empty())
        {
            return Err(InferenceAdapterError::MissingOutcomeAttemptRefs);
        }
        validate_optional_ref(
            &self.refusal_summary,
            InferenceAdapterError::MissingRefusalSummary,
        )?;
        validate_optional_ref(
            &self.provider_response_id,
            InferenceAdapterError::MissingProviderResponseId,
        )?;
        validate_optional_ref(
            &self.provider_request_id,
            InferenceAdapterError::MissingProviderRequestId,
        )?;
        if self.total_tokens != self.input_tokens + self.output_tokens {
            return Err(InferenceAdapterError::InvalidUsageTotals);
        }
        require_nonempty(&self.currency, InferenceAdapterError::MissingCurrency)?;
        require_nonempty(&self.created_at, InferenceAdapterError::MissingCreatedAt)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceParsedOutputRecord {
    pub parsed_output_id: String,
    pub turn_request_ref: String,
    pub provider_ref: String,
    pub model_ref: String,
    pub normalized_output_json: String,
    pub created_at: String,
}

impl InferenceParsedOutputRecord {
    pub fn validate(&self) -> Result<(), InferenceAdapterError> {
        require_nonempty(
            &self.parsed_output_id,
            InferenceAdapterError::MissingParsedOutputId,
        )?;
        require_nonempty(
            &self.turn_request_ref,
            InferenceAdapterError::MissingTurnRequestRef,
        )?;
        require_nonempty(
            &self.provider_ref,
            InferenceAdapterError::MissingProviderRef,
        )?;
        require_nonempty(&self.model_ref, InferenceAdapterError::MissingModelRef)?;
        require_nonempty(
            &self.normalized_output_json,
            InferenceAdapterError::MissingParsedOutputPayload,
        )?;
        parse_json_payload(
            &self.normalized_output_json,
            InferenceAdapterError::InvalidParsedOutputJson,
        )?;
        require_nonempty(&self.created_at, InferenceAdapterError::MissingCreatedAt)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceTurnResult {
    pub turn_result_id: String,
    pub turn_request_ref: String,
    pub raw_output_ref: String,
    pub parsed_output_ref: Option<String>,
    pub finish_reason: InferenceFinishReason,
    pub usage_record_ref: String,
    pub provider_outcome_ref: String,
    pub attempt_refs: Vec<String>,
    pub provider_metadata_refs: Vec<String>,
    pub degradation_ref: Option<String>,
    pub created_at: String,
}

impl InferenceTurnResult {
    pub fn validate(&self) -> Result<(), InferenceAdapterError> {
        require_nonempty(
            &self.turn_result_id,
            InferenceAdapterError::MissingTurnResultId,
        )?;
        require_nonempty(
            &self.turn_request_ref,
            InferenceAdapterError::MissingTurnRequestRef,
        )?;
        require_nonempty(
            &self.raw_output_ref,
            InferenceAdapterError::MissingRawOutputRef,
        )?;
        require_nonempty(
            &self.usage_record_ref,
            InferenceAdapterError::MissingUsageRecordRef,
        )?;
        require_nonempty(
            &self.provider_outcome_ref,
            InferenceAdapterError::MissingProviderOutcomeRef,
        )?;
        if self.attempt_refs.is_empty()
            || self
                .attempt_refs
                .iter()
                .any(|reference| reference.trim().is_empty())
        {
            return Err(InferenceAdapterError::MissingOutcomeAttemptRefs);
        }
        if self.provider_metadata_refs.is_empty()
            || self
                .provider_metadata_refs
                .iter()
                .any(|reference| reference.trim().is_empty())
        {
            return Err(InferenceAdapterError::MissingProviderMetadataRefs);
        }
        validate_optional_ref(
            &self.parsed_output_ref,
            InferenceAdapterError::MissingParsedOutputRef,
        )?;
        validate_optional_ref(
            &self.degradation_ref,
            InferenceAdapterError::MissingDegradationRef,
        )?;
        require_nonempty(&self.created_at, InferenceAdapterError::MissingCreatedAt)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderDegradationRecord {
    pub degradation_id: String,
    pub turn_result_ref: String,
    pub reason_class: ProviderDegradationReasonClass,
    pub summary: String,
    pub recovery_attempt_refs: Vec<String>,
    pub created_at: String,
}

impl ProviderDegradationRecord {
    pub fn validate(&self) -> Result<(), InferenceAdapterError> {
        require_nonempty(
            &self.degradation_id,
            InferenceAdapterError::MissingDegradationId,
        )?;
        require_nonempty(
            &self.turn_result_ref,
            InferenceAdapterError::MissingTurnResultRef,
        )?;
        require_nonempty(
            &self.summary,
            InferenceAdapterError::MissingDegradationSummary,
        )?;
        validate_ref_entries(
            &self.recovery_attempt_refs,
            InferenceAdapterError::MissingRecoveryAttemptRef,
        )?;
        require_nonempty(&self.created_at, InferenceAdapterError::MissingCreatedAt)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixtureInferenceResponse {
    pub fixture_response_id: String,
    pub finish_reason: InferenceFinishReason,
    pub http_status: Option<u16>,
    pub raw_output_payload: String,
    pub parsed_output_json: Option<String>,
    pub refusal_summary: Option<String>,
    pub provider_response_id: Option<String>,
    pub provider_request_id: Option<String>,
    pub provider_metadata_refs: Vec<String>,
    pub input_tokens: usize,
    pub output_tokens: usize,
    pub degraded: bool,
    pub degradation_reason: Option<ProviderDegradationReasonClass>,
    pub degradation_summary: Option<String>,
    pub recovery_attempt_refs: Vec<String>,
    pub transport_error_summary: Option<String>,
    pub latency_ms: u64,
}

impl FixtureInferenceResponse {
    pub fn validate(&self) -> Result<(), InferenceAdapterError> {
        require_nonempty(
            &self.fixture_response_id,
            InferenceAdapterError::MissingFixtureResponseId,
        )?;
        require_nonempty(
            &self.raw_output_payload,
            InferenceAdapterError::MissingRawOutputPayload,
        )?;
        if self.provider_metadata_refs.is_empty()
            || self
                .provider_metadata_refs
                .iter()
                .any(|reference| reference.trim().is_empty())
        {
            return Err(InferenceAdapterError::MissingProviderMetadataRefs);
        }
        validate_optional_ref(
            &self.provider_response_id,
            InferenceAdapterError::MissingProviderResponseId,
        )?;
        validate_optional_ref(
            &self.provider_request_id,
            InferenceAdapterError::MissingProviderRequestId,
        )?;
        validate_optional_ref(
            &self.refusal_summary,
            InferenceAdapterError::MissingRefusalSummary,
        )?;
        validate_optional_ref(
            &self.transport_error_summary,
            InferenceAdapterError::MissingTransportErrorSummary,
        )?;
        validate_ref_entries(
            &self.recovery_attempt_refs,
            InferenceAdapterError::MissingRecoveryAttemptRef,
        )?;
        if let Some(parsed_output_json) = &self.parsed_output_json {
            require_nonempty(
                parsed_output_json,
                InferenceAdapterError::MissingParsedOutputPayload,
            )?;
            parse_json_payload(
                parsed_output_json,
                InferenceAdapterError::InvalidParsedOutputJson,
            )?;
        }

        match self.finish_reason {
            InferenceFinishReason::Completed => {
                if self.degraded
                    || self.degradation_reason.is_some()
                    || self.degradation_summary.is_some()
                {
                    return Err(InferenceAdapterError::UnexpectedDegradation);
                }
                if self.parsed_output_json.is_none() {
                    return Err(InferenceAdapterError::MissingParsedOutputPayload);
                }
            }
            InferenceFinishReason::Refused => {
                if self.parsed_output_json.is_some() {
                    return Err(InferenceAdapterError::UnexpectedParsedOutput);
                }
            }
            InferenceFinishReason::TimedOut => {
                validate_required_degradation(
                    self.degraded,
                    self.degradation_reason,
                    self.degradation_summary.as_deref(),
                    ProviderDegradationReasonClass::Timeout,
                )?;
            }
            InferenceFinishReason::MalformedOutput => {
                validate_required_degradation(
                    self.degraded,
                    self.degradation_reason,
                    self.degradation_summary.as_deref(),
                    ProviderDegradationReasonClass::MalformedOutput,
                )?;
                if self.parsed_output_json.is_some() {
                    return Err(InferenceAdapterError::UnexpectedParsedOutput);
                }
            }
            InferenceFinishReason::ProviderError => {
                validate_required_degradation(
                    self.degraded,
                    self.degradation_reason,
                    self.degradation_summary.as_deref(),
                    ProviderDegradationReasonClass::TransportFailure,
                )?;
                if self.parsed_output_json.is_some() {
                    return Err(InferenceAdapterError::UnexpectedParsedOutput);
                }
            }
            InferenceFinishReason::Interrupted => {
                if self.degraded
                    && self
                        .degradation_summary
                        .as_ref()
                        .is_none_or(|summary| summary.trim().is_empty())
                {
                    return Err(InferenceAdapterError::MissingDegradationSummary);
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceTurnBundle {
    pub turn_request: InferenceTurnRequest,
    pub generation_policy: InferenceGenerationPolicy,
    pub rendered_prompt: InferenceRenderedPromptRecord,
    pub tool_catalog: InferenceToolCatalogPayloadRecord,
    pub response_schema: InferenceResponseSchemaPayloadRecord,
    pub request_body_records: Vec<InferenceRequestBodyRecord>,
    pub raw_output_records: Vec<InferenceRawOutputRecord>,
    pub usage_record: InferenceUsageRecord,
    pub attempts: Vec<InferenceAttemptRecord>,
    pub provider_outcome: InferenceProviderOutcomeRecord,
    pub parsed_output: Option<InferenceParsedOutputRecord>,
    pub turn_result: InferenceTurnResult,
    pub degradation_record: Option<ProviderDegradationRecord>,
}

impl InferenceTurnBundle {
    pub fn validate(&self) -> Result<(), InferenceAdapterError> {
        self.turn_request.validate()?;
        self.generation_policy.validate()?;
        self.rendered_prompt.validate()?;
        self.tool_catalog.validate()?;
        self.response_schema.validate()?;
        self.usage_record.validate()?;
        self.provider_outcome.validate()?;
        self.turn_result.validate()?;

        if self.request_body_records.is_empty()
            || self.raw_output_records.is_empty()
            || self.attempts.is_empty()
        {
            return Err(InferenceAdapterError::BundleAttemptMismatch);
        }
        for request_body in &self.request_body_records {
            request_body.validate()?;
            if request_body.turn_request_ref != self.turn_request.turn_request_id {
                return Err(InferenceAdapterError::BundleTurnRequestMismatch);
            }
        }
        for raw_output in &self.raw_output_records {
            raw_output.validate()?;
            if raw_output.turn_request_ref != self.turn_request.turn_request_id {
                return Err(InferenceAdapterError::BundleTurnRequestMismatch);
            }
        }
        for attempt in &self.attempts {
            attempt.validate()?;
            if attempt.turn_request_ref != self.turn_request.turn_request_id {
                return Err(InferenceAdapterError::BundleTurnRequestMismatch);
            }
            let Some(request_body) = self
                .request_body_records
                .iter()
                .find(|record| record.request_body_id == attempt.request_body_ref)
            else {
                return Err(InferenceAdapterError::BundleAttemptMismatch);
            };
            if request_body.attempt_number != attempt.attempt_number {
                return Err(InferenceAdapterError::BundleAttemptMismatch);
            }
            let Some(raw_output) = self
                .raw_output_records
                .iter()
                .find(|record| record.raw_output_id == attempt.raw_response_body_ref)
            else {
                return Err(InferenceAdapterError::BundleRawOutputMismatch);
            };
            if raw_output.attempt_number != attempt.attempt_number {
                return Err(InferenceAdapterError::BundleRawOutputMismatch);
            }
        }
        if self.rendered_prompt.turn_request_ref != self.turn_request.turn_request_id {
            return Err(InferenceAdapterError::BundlePromptMismatch);
        }
        if self.tool_catalog.turn_request_ref != self.turn_request.turn_request_id {
            return Err(InferenceAdapterError::BundleToolCatalogMismatch);
        }
        if self.response_schema.turn_request_ref != self.turn_request.turn_request_id {
            return Err(InferenceAdapterError::BundleResponseSchemaMismatch);
        }
        if self.turn_request.rendered_prompt_ref != self.rendered_prompt.rendered_prompt_id {
            return Err(InferenceAdapterError::BundlePromptMismatch);
        }
        if self.turn_request.tool_catalog_ref != self.tool_catalog.tool_catalog_id {
            return Err(InferenceAdapterError::BundleToolCatalogMismatch);
        }
        if self.turn_request.response_schema_ref != self.response_schema.response_schema_id {
            return Err(InferenceAdapterError::BundleResponseSchemaMismatch);
        }
        if self.turn_request.generation_policy_ref != self.generation_policy.generation_policy_id {
            return Err(InferenceAdapterError::GenerationPolicyRefMismatch {
                request_generation_policy_ref: self.turn_request.generation_policy_ref.clone(),
                generation_policy_id: self.generation_policy.generation_policy_id.clone(),
            });
        }
        if self.usage_record.turn_request_ref != self.turn_request.turn_request_id {
            return Err(InferenceAdapterError::BundleUsageMismatch);
        }
        if self.turn_result.turn_request_ref != self.turn_request.turn_request_id {
            return Err(InferenceAdapterError::BundleTurnRequestMismatch);
        }
        if self.turn_result.usage_record_ref != self.usage_record.usage_record_id {
            return Err(InferenceAdapterError::BundleUsageMismatch);
        }
        if self.turn_result.provider_outcome_ref != self.provider_outcome.provider_outcome_id {
            return Err(InferenceAdapterError::BundleOutcomeMismatch);
        }
        if self.turn_result.attempt_refs != self.provider_outcome.attempt_refs {
            return Err(InferenceAdapterError::BundleOutcomeMismatch);
        }
        if self.provider_outcome.turn_request_ref != self.turn_request.turn_request_id {
            return Err(InferenceAdapterError::BundleTurnRequestMismatch);
        }
        if self.provider_outcome.attempt_refs.len() != self.attempts.len() {
            return Err(InferenceAdapterError::BundleOutcomeMismatch);
        }
        for attempt in &self.attempts {
            if !self
                .provider_outcome
                .attempt_refs
                .contains(&attempt.attempt_id)
            {
                return Err(InferenceAdapterError::BundleOutcomeMismatch);
            }
        }
        if !self
            .raw_output_records
            .iter()
            .any(|record| record.raw_output_id == self.turn_result.raw_output_ref)
        {
            return Err(InferenceAdapterError::BundleRawOutputMismatch);
        }
        match (&self.parsed_output, &self.turn_result.parsed_output_ref) {
            (Some(parsed_output), Some(reference)) => {
                parsed_output.validate()?;
                if &parsed_output.parsed_output_id != reference
                    || parsed_output.turn_request_ref != self.turn_request.turn_request_id
                    || parsed_output.provider_ref != self.provider_outcome.provider_ref
                    || parsed_output.model_ref != self.provider_outcome.model_ref
                {
                    return Err(InferenceAdapterError::BundleParsedOutputMismatch);
                }
            }
            (None, None) => {}
            _ => return Err(InferenceAdapterError::BundleParsedOutputMismatch),
        }
        match (&self.degradation_record, &self.turn_result.degradation_ref) {
            (Some(record), Some(reference)) => {
                record.validate()?;
                if &record.degradation_id != reference
                    || record.turn_result_ref != self.turn_result.turn_result_id
                {
                    return Err(InferenceAdapterError::BundleDegradationMismatch);
                }
            }
            (None, None) => {
                if matches!(
                    self.turn_result.finish_reason,
                    InferenceFinishReason::TimedOut
                        | InferenceFinishReason::MalformedOutput
                        | InferenceFinishReason::ProviderError
                ) {
                    return Err(InferenceAdapterError::MissingDegradationRecord);
                }
            }
            _ => return Err(InferenceAdapterError::BundleDegradationMismatch),
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InferenceAdapterError {
    MissingProviderId,
    MissingProviderModels,
    DuplicateModelRef {
        model_ref: String,
    },
    MissingCapabilitySummary,
    MissingPolicySummary,
    MissingApiBaseUrl,
    MissingApiKeyEnvVar,
    MissingEnvVarName,
    InvalidRequestTimeoutMs,
    MissingGenerationPolicyId,
    InvalidMaxOutputTokens,
    MissingGenerationPolicySummary,
    MissingTurnRequestId,
    MissingProviderRef,
    MissingModelRef,
    MissingRenderedPromptRef,
    MissingToolCatalogRef,
    MissingResponseSchemaRef,
    MissingGenerationPolicyRef,
    MissingCreatedAt,
    MissingRenderedPromptId,
    MissingPromptText,
    MissingToolCatalogId,
    MissingToolCatalogJson,
    InvalidToolCatalogJson,
    RequiredFunctionToolUnavailable {
        required_function_name: String,
    },
    MissingResponseSchemaId,
    MissingResponseSchemaJson,
    InvalidResponseSchemaJson,
    MissingRequestBodyId,
    MissingRequestBodyJson,
    InvalidRequestBodyJson,
    MissingRawOutputId,
    MissingTurnRequestRef,
    MissingRawOutputPayload,
    MissingUsageRecordId,
    MissingProviderUsage,
    InvalidProviderUsage {
        reason: String,
    },
    InvalidUsageTotals,
    MissingCurrency,
    MissingAttemptId,
    InvalidAttemptNumber,
    MissingRequestBodyRef,
    MissingRawResponseBodyRef,
    MissingProviderResponseId,
    MissingProviderRequestId,
    MissingTransportErrorSummary,
    MissingProviderOutcomeId,
    MissingOutcomeAttemptRefs,
    MissingParsedOutputId,
    MissingParsedOutputPayload,
    InvalidParsedOutputJson,
    MissingTurnResultId,
    MissingRawOutputRef,
    MissingParsedOutputRef,
    MissingUsageRecordRef,
    MissingProviderOutcomeRef,
    MissingProviderMetadataRefs,
    MissingDegradationRef,
    MissingDegradationId,
    MissingTurnResultRef,
    MissingDegradationSummary,
    MissingRecoveryAttemptRef,
    MissingFixtureResponseId,
    MissingDegradationReason,
    InvalidDegradationReason,
    MissingRefusalSummary,
    UnexpectedDegradation,
    UnexpectedParsedOutput,
    ProviderInactive {
        provider_id: String,
    },
    ProviderDisabled {
        provider_id: String,
    },
    UnsupportedModel {
        provider_id: String,
        model_ref: String,
    },
    ProviderRefMismatch {
        request_provider_ref: String,
        provider_id: String,
    },
    GenerationPolicyRefMismatch {
        request_generation_policy_ref: String,
        generation_policy_id: String,
    },
    MissingProviderSecretEnv {
        env_var: String,
    },
    InvalidApiBaseUrl {
        reason: String,
    },
    HttpClientBuildError {
        reason: String,
    },
    TransportError {
        reason: String,
    },
    DeterministicFixtureRequiresFixtureResponse,
    BundleTurnRequestMismatch,
    BundlePromptMismatch,
    BundleToolCatalogMismatch,
    BundleResponseSchemaMismatch,
    BundleUsageMismatch,
    BundleOutcomeMismatch,
    BundleAttemptMismatch,
    BundleRawOutputMismatch,
    BundleParsedOutputMismatch,
    BundleDegradationMismatch,
    MissingDegradationRecord,
}

impl Display for InferenceAdapterError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for InferenceAdapterError {}

pub async fn execute_inference_turn(
    provider: &InferenceProviderRegistryEntry,
    generation_policy: &InferenceGenerationPolicy,
    request: &InferenceTurnRequest,
    rendered_prompt: &InferenceRenderedPromptRecord,
    tool_catalog: &InferenceToolCatalogPayloadRecord,
    response_schema: &InferenceResponseSchemaPayloadRecord,
) -> Result<InferenceTurnBundle, InferenceAdapterError> {
    execute_inference_turn_with_required_function(
        provider,
        generation_policy,
        request,
        rendered_prompt,
        tool_catalog,
        response_schema,
        None,
    )
    .await
}

/// Execute a live turn whose terminal response must be exactly one call to the
/// named function. Structured-output and assistant-content fallbacks remain
/// available through [`execute_inference_turn`], but are forbidden here.
pub async fn execute_inference_turn_requiring_function_tool(
    provider: &InferenceProviderRegistryEntry,
    generation_policy: &InferenceGenerationPolicy,
    request: &InferenceTurnRequest,
    rendered_prompt: &InferenceRenderedPromptRecord,
    tool_catalog: &InferenceToolCatalogPayloadRecord,
    response_schema: &InferenceResponseSchemaPayloadRecord,
    required_function_name: &str,
) -> Result<InferenceTurnBundle, InferenceAdapterError> {
    if required_function_name.is_empty() {
        return Err(InferenceAdapterError::RequiredFunctionToolUnavailable {
            required_function_name: required_function_name.to_string(),
        });
    }
    execute_inference_turn_with_required_function(
        provider,
        generation_policy,
        request,
        rendered_prompt,
        tool_catalog,
        response_schema,
        Some(required_function_name),
    )
    .await
}

async fn execute_inference_turn_with_required_function(
    provider: &InferenceProviderRegistryEntry,
    generation_policy: &InferenceGenerationPolicy,
    request: &InferenceTurnRequest,
    rendered_prompt: &InferenceRenderedPromptRecord,
    tool_catalog: &InferenceToolCatalogPayloadRecord,
    response_schema: &InferenceResponseSchemaPayloadRecord,
    required_function_name: Option<&str>,
) -> Result<InferenceTurnBundle, InferenceAdapterError> {
    match provider.provider_mode {
        InferenceProviderMode::DeterministicFixture => {
            Err(InferenceAdapterError::DeterministicFixtureRequiresFixtureResponse)
        }
        InferenceProviderMode::OpenAiResponses => {
            let transport = OpenAiResponsesTransport::new(provider)?;
            execute_openai_responses_turn_with_required_function(
                provider,
                generation_policy,
                request,
                rendered_prompt,
                tool_catalog,
                response_schema,
                &transport,
                required_function_name,
            )
            .await
        }
        InferenceProviderMode::OpenRouterChatCompletions => {
            let transport = OpenRouterChatCompletionsTransport::new(provider)?;
            execute_openrouter_chat_completions_turn_with_required_function(
                provider,
                generation_policy,
                request,
                rendered_prompt,
                tool_catalog,
                response_schema,
                &transport,
                required_function_name,
            )
            .await
        }
        InferenceProviderMode::Disabled => Err(InferenceAdapterError::ProviderDisabled {
            provider_id: provider.provider_id.clone(),
        }),
    }
}

pub async fn execute_inference_turn_with_fixture(
    provider: &InferenceProviderRegistryEntry,
    generation_policy: &InferenceGenerationPolicy,
    request: &InferenceTurnRequest,
    rendered_prompt: &InferenceRenderedPromptRecord,
    tool_catalog: &InferenceToolCatalogPayloadRecord,
    response_schema: &InferenceResponseSchemaPayloadRecord,
    fixture: &FixtureInferenceResponse,
) -> Result<InferenceTurnBundle, InferenceAdapterError> {
    validate_shared_request_state(
        provider,
        generation_policy,
        request,
        rendered_prompt,
        tool_catalog,
        response_schema,
    )?;
    fixture.validate()?;

    let timestamp = current_timestamp();
    let model = provider.model_entry(&request.model_ref)?;
    let request_body_json = build_request_body_json(
        provider,
        request,
        generation_policy,
        rendered_prompt,
        tool_catalog,
        response_schema,
    )?;
    let request_body = InferenceRequestBodyRecord {
        request_body_id: format!(
            "inference-request-body:{}:1",
            sanitize_id(&request.turn_request_id)
        ),
        turn_request_ref: request.turn_request_id.clone(),
        attempt_number: 1,
        request_body_json,
        created_at: timestamp.clone(),
    };
    let raw_output = InferenceRawOutputRecord {
        raw_output_id: format!(
            "inference-raw-output:{}:1",
            sanitize_id(&request.turn_request_id)
        ),
        turn_request_ref: request.turn_request_id.clone(),
        provider_ref: provider.provider_id.clone(),
        model_ref: request.model_ref.clone(),
        attempt_number: 1,
        raw_output_payload: fixture.raw_output_payload.clone(),
        created_at: timestamp.clone(),
    };
    let attempt = InferenceAttemptRecord {
        attempt_id: format!(
            "inference-attempt:{}:1",
            sanitize_id(&request.turn_request_id)
        ),
        turn_request_ref: request.turn_request_id.clone(),
        attempt_number: 1,
        request_body_ref: request_body.request_body_id.clone(),
        raw_response_body_ref: raw_output.raw_output_id.clone(),
        http_status: fixture.http_status,
        latency_ms: fixture.latency_ms,
        retry_classification: InferenceRetryClassification::NoRetryNeeded,
        provider_response_id: fixture.provider_response_id.clone(),
        provider_request_id: fixture.provider_request_id.clone(),
        transport_error_summary: fixture.transport_error_summary.clone(),
        created_at: timestamp.clone(),
    };
    let parsed_output = fixture
        .parsed_output_json
        .as_ref()
        .map(|normalized_output_json| InferenceParsedOutputRecord {
            parsed_output_id: format!(
                "inference-parsed-output:{}",
                sanitize_id(&request.turn_request_id)
            ),
            turn_request_ref: request.turn_request_id.clone(),
            provider_ref: provider.provider_id.clone(),
            model_ref: request.model_ref.clone(),
            normalized_output_json: normalized_output_json.clone(),
            created_at: timestamp.clone(),
        });
    let usage_record = InferenceUsageRecord {
        usage_record_id: format!("inference-usage:{}", sanitize_id(&request.turn_request_id)),
        turn_request_ref: request.turn_request_id.clone(),
        input_tokens: fixture.input_tokens,
        output_tokens: fixture.output_tokens,
        total_tokens: fixture.input_tokens + fixture.output_tokens,
        latency_ms: fixture.latency_ms,
        estimated_cost_microunits: estimate_cost_microunits(
            model,
            fixture.input_tokens,
            fixture.output_tokens,
        ),
        currency: "usd".to_string(),
        created_at: timestamp.clone(),
    };
    let provider_outcome = InferenceProviderOutcomeRecord {
        provider_outcome_id: format!(
            "inference-provider-outcome:{}",
            sanitize_id(&request.turn_request_id)
        ),
        turn_request_ref: request.turn_request_id.clone(),
        provider_ref: provider.provider_id.clone(),
        model_ref: request.model_ref.clone(),
        finish_reason: fixture.finish_reason,
        final_http_status: fixture.http_status,
        attempt_refs: vec![attempt.attempt_id.clone()],
        refusal_summary: fixture.refusal_summary.clone(),
        provider_response_id: fixture.provider_response_id.clone(),
        provider_request_id: fixture.provider_request_id.clone(),
        input_tokens: fixture.input_tokens,
        output_tokens: fixture.output_tokens,
        total_tokens: fixture.input_tokens + fixture.output_tokens,
        latency_ms: fixture.latency_ms,
        estimated_cost_microunits: usage_record.estimated_cost_microunits,
        currency: usage_record.currency.clone(),
        created_at: timestamp.clone(),
    };
    let turn_result_id = format!(
        "inference-turn-result:{}",
        sanitize_id(&request.turn_request_id)
    );
    let degradation_record = fixture.degraded.then(|| ProviderDegradationRecord {
        degradation_id: format!(
            "inference-degradation:{}",
            sanitize_id(&request.turn_request_id)
        ),
        turn_result_ref: turn_result_id.clone(),
        reason_class: fixture
            .degradation_reason
            .expect("validated fixture includes degradation reason"),
        summary: fixture
            .degradation_summary
            .clone()
            .expect("validated fixture includes degradation summary"),
        recovery_attempt_refs: fixture.recovery_attempt_refs.clone(),
        created_at: timestamp.clone(),
    });
    let turn_result = InferenceTurnResult {
        turn_result_id,
        turn_request_ref: request.turn_request_id.clone(),
        raw_output_ref: raw_output.raw_output_id.clone(),
        parsed_output_ref: parsed_output
            .as_ref()
            .map(|record| record.parsed_output_id.clone()),
        finish_reason: fixture.finish_reason,
        usage_record_ref: usage_record.usage_record_id.clone(),
        provider_outcome_ref: provider_outcome.provider_outcome_id.clone(),
        attempt_refs: vec![attempt.attempt_id.clone()],
        provider_metadata_refs: fixture.provider_metadata_refs.clone(),
        degradation_ref: degradation_record
            .as_ref()
            .map(|record| record.degradation_id.clone()),
        created_at: timestamp,
    };

    let bundle = InferenceTurnBundle {
        turn_request: request.clone(),
        generation_policy: generation_policy.clone(),
        rendered_prompt: rendered_prompt.clone(),
        tool_catalog: tool_catalog.clone(),
        response_schema: response_schema.clone(),
        request_body_records: vec![request_body],
        raw_output_records: vec![raw_output],
        usage_record,
        attempts: vec![attempt],
        provider_outcome,
        parsed_output,
        turn_result,
        degradation_record,
    };
    bundle.validate()?;
    Ok(bundle)
}

fn validate_shared_request_state(
    provider: &InferenceProviderRegistryEntry,
    generation_policy: &InferenceGenerationPolicy,
    request: &InferenceTurnRequest,
    rendered_prompt: &InferenceRenderedPromptRecord,
    tool_catalog: &InferenceToolCatalogPayloadRecord,
    response_schema: &InferenceResponseSchemaPayloadRecord,
) -> Result<(), InferenceAdapterError> {
    provider.validate()?;
    generation_policy.validate()?;
    request.validate()?;
    rendered_prompt.validate()?;
    tool_catalog.validate()?;
    response_schema.validate()?;

    if !provider.active {
        return Err(InferenceAdapterError::ProviderInactive {
            provider_id: provider.provider_id.clone(),
        });
    }
    if provider.provider_mode == InferenceProviderMode::Disabled {
        return Err(InferenceAdapterError::ProviderDisabled {
            provider_id: provider.provider_id.clone(),
        });
    }
    if request.provider_ref != provider.provider_id {
        return Err(InferenceAdapterError::ProviderRefMismatch {
            request_provider_ref: request.provider_ref.clone(),
            provider_id: provider.provider_id.clone(),
        });
    }
    if request.generation_policy_ref != generation_policy.generation_policy_id {
        return Err(InferenceAdapterError::GenerationPolicyRefMismatch {
            request_generation_policy_ref: request.generation_policy_ref.clone(),
            generation_policy_id: generation_policy.generation_policy_id.clone(),
        });
    }
    provider.model_entry(&request.model_ref)?;
    if rendered_prompt.turn_request_ref != request.turn_request_id
        || rendered_prompt.rendered_prompt_id != request.rendered_prompt_ref
    {
        return Err(InferenceAdapterError::BundlePromptMismatch);
    }
    if tool_catalog.turn_request_ref != request.turn_request_id
        || tool_catalog.tool_catalog_id != request.tool_catalog_ref
    {
        return Err(InferenceAdapterError::BundleToolCatalogMismatch);
    }
    if response_schema.turn_request_ref != request.turn_request_id
        || response_schema.response_schema_id != request.response_schema_ref
    {
        return Err(InferenceAdapterError::BundleResponseSchemaMismatch);
    }
    Ok(())
}

#[cfg(test)]
async fn execute_openai_responses_turn(
    provider: &InferenceProviderRegistryEntry,
    generation_policy: &InferenceGenerationPolicy,
    request: &InferenceTurnRequest,
    rendered_prompt: &InferenceRenderedPromptRecord,
    tool_catalog: &InferenceToolCatalogPayloadRecord,
    response_schema: &InferenceResponseSchemaPayloadRecord,
    transport: &dyn InferenceTransport,
) -> Result<InferenceTurnBundle, InferenceAdapterError> {
    execute_openai_responses_turn_with_required_function(
        provider,
        generation_policy,
        request,
        rendered_prompt,
        tool_catalog,
        response_schema,
        transport,
        None,
    )
    .await
}

async fn execute_openai_responses_turn_with_required_function(
    provider: &InferenceProviderRegistryEntry,
    generation_policy: &InferenceGenerationPolicy,
    request: &InferenceTurnRequest,
    rendered_prompt: &InferenceRenderedPromptRecord,
    tool_catalog: &InferenceToolCatalogPayloadRecord,
    response_schema: &InferenceResponseSchemaPayloadRecord,
    transport: &dyn InferenceTransport,
    required_function_name: Option<&str>,
) -> Result<InferenceTurnBundle, InferenceAdapterError> {
    validate_shared_request_state(
        provider,
        generation_policy,
        request,
        rendered_prompt,
        tool_catalog,
        response_schema,
    )?;
    let request_body_json = build_request_body_json_with_required_function(
        provider,
        request,
        generation_policy,
        rendered_prompt,
        tool_catalog,
        response_schema,
        required_function_name,
    )?;
    execute_transport_turn(
        provider,
        generation_policy,
        request,
        rendered_prompt,
        tool_catalog,
        response_schema,
        transport,
        required_function_name,
        request_body_json,
        parse_openai_responses_envelope,
    )
    .await
}

#[cfg(test)]
async fn execute_openrouter_chat_completions_turn(
    provider: &InferenceProviderRegistryEntry,
    generation_policy: &InferenceGenerationPolicy,
    request: &InferenceTurnRequest,
    rendered_prompt: &InferenceRenderedPromptRecord,
    tool_catalog: &InferenceToolCatalogPayloadRecord,
    response_schema: &InferenceResponseSchemaPayloadRecord,
    transport: &dyn InferenceTransport,
) -> Result<InferenceTurnBundle, InferenceAdapterError> {
    execute_openrouter_chat_completions_turn_with_required_function(
        provider,
        generation_policy,
        request,
        rendered_prompt,
        tool_catalog,
        response_schema,
        transport,
        None,
    )
    .await
}

async fn execute_openrouter_chat_completions_turn_with_required_function(
    provider: &InferenceProviderRegistryEntry,
    generation_policy: &InferenceGenerationPolicy,
    request: &InferenceTurnRequest,
    rendered_prompt: &InferenceRenderedPromptRecord,
    tool_catalog: &InferenceToolCatalogPayloadRecord,
    response_schema: &InferenceResponseSchemaPayloadRecord,
    transport: &dyn InferenceTransport,
    required_function_name: Option<&str>,
) -> Result<InferenceTurnBundle, InferenceAdapterError> {
    validate_shared_request_state(
        provider,
        generation_policy,
        request,
        rendered_prompt,
        tool_catalog,
        response_schema,
    )?;
    let request_body_json = build_request_body_json_with_required_function(
        provider,
        request,
        generation_policy,
        rendered_prompt,
        tool_catalog,
        response_schema,
        required_function_name,
    )?;
    execute_transport_turn(
        provider,
        generation_policy,
        request,
        rendered_prompt,
        tool_catalog,
        response_schema,
        transport,
        required_function_name,
        request_body_json,
        parse_openrouter_chat_completions_envelope,
    )
    .await
}

type ResponseEnvelopeParser = fn(
    raw_output_payload: &str,
    provider: &InferenceProviderRegistryEntry,
    request: &InferenceTurnRequest,
    model: &InferenceProviderModelEntry,
    exposed_function_tool_names: &BTreeSet<String>,
    required_function_name: Option<&str>,
    http_status: Option<u16>,
    provider_response_id: Option<String>,
    provider_request_id: Option<String>,
    latency_ms: u64,
    attempts: &[InferenceAttemptRecord],
    created_at: &str,
) -> Result<FinalizedProviderOutcome, InferenceAdapterError>;

fn exposed_function_tool_names(request_body_json: &str) -> BTreeSet<String> {
    let Ok(request_body) = serde_json::from_str::<Value>(request_body_json) else {
        return BTreeSet::new();
    };
    let Some(tools) = request_body.get("tools").and_then(Value::as_array) else {
        return BTreeSet::new();
    };
    tools
        .iter()
        .filter_map(function_tool_name)
        .map(ToOwned::to_owned)
        .collect()
}

fn function_tool_name(tool: &Value) -> Option<&str> {
    if tool.get("type").and_then(Value::as_str) != Some("function") {
        return None;
    }
    tool.get("function")
        .unwrap_or(tool)
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
}

async fn execute_transport_turn(
    provider: &InferenceProviderRegistryEntry,
    generation_policy: &InferenceGenerationPolicy,
    request: &InferenceTurnRequest,
    rendered_prompt: &InferenceRenderedPromptRecord,
    tool_catalog: &InferenceToolCatalogPayloadRecord,
    response_schema: &InferenceResponseSchemaPayloadRecord,
    transport: &dyn InferenceTransport,
    required_function_name: Option<&str>,
    request_body_json: String,
    parse_response_envelope: ResponseEnvelopeParser,
) -> Result<InferenceTurnBundle, InferenceAdapterError> {
    let model = provider.model_entry(&request.model_ref)?;
    let exposed_function_tool_names = exposed_function_tool_names(&request_body_json);
    let mut request_body_records = Vec::new();
    let mut raw_output_records = Vec::new();
    let mut attempts = Vec::new();

    for attempt_number in 1..=generation_policy.max_retries + 1 {
        let attempt_timestamp = current_timestamp();
        let request_body = InferenceRequestBodyRecord {
            request_body_id: format!(
                "inference-request-body:{}:{}",
                sanitize_id(&request.turn_request_id),
                attempt_number
            ),
            turn_request_ref: request.turn_request_id.clone(),
            attempt_number,
            request_body_json: request_body_json.clone(),
            created_at: attempt_timestamp.clone(),
        };
        let transport_request = InferenceTransportRequest {
            provider,
            request_body_json: &request_body.request_body_json,
        };
        let result = transport.send(transport_request).await;

        match result {
            Ok(response) => {
                let retry_disposition = classify_http_status_retry(
                    response.http_status,
                    attempt_number <= generation_policy.max_retries,
                );
                let raw_output = build_raw_output_record(
                    request,
                    provider,
                    attempt_number,
                    response.raw_response_body,
                    &attempt_timestamp,
                );
                let attempt = InferenceAttemptRecord {
                    attempt_id: format!(
                        "inference-attempt:{}:{}",
                        sanitize_id(&request.turn_request_id),
                        attempt_number
                    ),
                    turn_request_ref: request.turn_request_id.clone(),
                    attempt_number,
                    request_body_ref: request_body.request_body_id.clone(),
                    raw_response_body_ref: raw_output.raw_output_id.clone(),
                    http_status: response.http_status,
                    latency_ms: response.latency_ms,
                    retry_classification: retry_disposition.classification,
                    provider_response_id: response.provider_response_id.clone(),
                    provider_request_id: response.provider_request_id.clone(),
                    transport_error_summary: None,
                    created_at: attempt_timestamp.clone(),
                };

                request_body_records.push(request_body);
                raw_output_records.push(raw_output.clone());
                attempts.push(attempt.clone());

                if retry_disposition.should_retry {
                    continue;
                }

                let final_timestamp = current_timestamp();
                let parsed_envelope = parse_response_envelope(
                    &raw_output.raw_output_payload,
                    provider,
                    request,
                    model,
                    &exposed_function_tool_names,
                    required_function_name,
                    response.http_status,
                    response.provider_response_id,
                    response.provider_request_id,
                    total_latency_ms(&attempts),
                    &attempts,
                    &final_timestamp,
                )?;

                return build_bundle_from_finalized_outcome(
                    request,
                    generation_policy,
                    rendered_prompt,
                    tool_catalog,
                    response_schema,
                    request_body_records,
                    raw_output_records,
                    attempts,
                    parsed_envelope,
                );
            }
            Err(failure) => {
                let classification = classify_transport_failure_retry(
                    failure.kind,
                    attempt_number <= generation_policy.max_retries,
                );
                let attempt_timestamp = current_timestamp();
                let safe_failure_message =
                    safe_transport_failure_summary(failure.kind, &failure.message);
                let raw_output = build_raw_output_record(
                    request,
                    provider,
                    attempt_number,
                    synthetic_transport_payload(failure.kind, &safe_failure_message),
                    &attempt_timestamp,
                );
                let attempt = InferenceAttemptRecord {
                    attempt_id: format!(
                        "inference-attempt:{}:{}",
                        sanitize_id(&request.turn_request_id),
                        attempt_number
                    ),
                    turn_request_ref: request.turn_request_id.clone(),
                    attempt_number,
                    request_body_ref: request_body.request_body_id.clone(),
                    raw_response_body_ref: raw_output.raw_output_id.clone(),
                    http_status: None,
                    latency_ms: failure.latency_ms,
                    retry_classification: classification.classification,
                    provider_response_id: None,
                    provider_request_id: None,
                    transport_error_summary: Some(safe_failure_message.clone()),
                    created_at: attempt_timestamp.clone(),
                };
                request_body_records.push(request_body);
                raw_output_records.push(raw_output);
                attempts.push(attempt);

                if classification.should_retry {
                    continue;
                }

                let final_timestamp = current_timestamp();
                let usage_record = build_usage_record(
                    request,
                    0,
                    0,
                    total_latency_ms(&attempts),
                    estimate_cost_microunits(model, 0, 0),
                    &final_timestamp,
                );
                let provider_outcome = InferenceProviderOutcomeRecord {
                    provider_outcome_id: format!(
                        "inference-provider-outcome:{}",
                        sanitize_id(&request.turn_request_id)
                    ),
                    turn_request_ref: request.turn_request_id.clone(),
                    provider_ref: provider.provider_id.clone(),
                    model_ref: request.model_ref.clone(),
                    finish_reason: match failure.kind {
                        InferenceTransportFailureKind::Timeout => InferenceFinishReason::TimedOut,
                        InferenceTransportFailureKind::Transport => {
                            InferenceFinishReason::ProviderError
                        }
                    },
                    final_http_status: None,
                    attempt_refs: attempts
                        .iter()
                        .map(|item| item.attempt_id.clone())
                        .collect(),
                    refusal_summary: None,
                    provider_response_id: None,
                    provider_request_id: None,
                    input_tokens: 0,
                    output_tokens: 0,
                    total_tokens: 0,
                    latency_ms: usage_record.latency_ms,
                    estimated_cost_microunits: usage_record.estimated_cost_microunits,
                    currency: usage_record.currency.clone(),
                    created_at: final_timestamp.clone(),
                };
                let turn_result_id = format!(
                    "inference-turn-result:{}",
                    sanitize_id(&request.turn_request_id)
                );
                let degradation_record = ProviderDegradationRecord {
                    degradation_id: format!(
                        "inference-degradation:{}",
                        sanitize_id(&request.turn_request_id)
                    ),
                    turn_result_ref: turn_result_id.clone(),
                    reason_class: match failure.kind {
                        InferenceTransportFailureKind::Timeout => {
                            ProviderDegradationReasonClass::Timeout
                        }
                        InferenceTransportFailureKind::Transport => {
                            ProviderDegradationReasonClass::TransportFailure
                        }
                    },
                    summary: safe_failure_message,
                    recovery_attempt_refs: attempts
                        .iter()
                        .map(|item| item.attempt_id.clone())
                        .collect(),
                    created_at: final_timestamp.clone(),
                };
                let turn_result = InferenceTurnResult {
                    turn_result_id,
                    turn_request_ref: request.turn_request_id.clone(),
                    raw_output_ref: raw_output_records
                        .last()
                        .expect("at least one raw output exists")
                        .raw_output_id
                        .clone(),
                    parsed_output_ref: None,
                    finish_reason: provider_outcome.finish_reason,
                    usage_record_ref: usage_record.usage_record_id.clone(),
                    provider_outcome_ref: provider_outcome.provider_outcome_id.clone(),
                    attempt_refs: provider_outcome.attempt_refs.clone(),
                    provider_metadata_refs: vec![provider_outcome.provider_outcome_id.clone()],
                    degradation_ref: Some(degradation_record.degradation_id.clone()),
                    created_at: final_timestamp,
                };
                let bundle = InferenceTurnBundle {
                    turn_request: request.clone(),
                    generation_policy: generation_policy.clone(),
                    rendered_prompt: rendered_prompt.clone(),
                    tool_catalog: tool_catalog.clone(),
                    response_schema: response_schema.clone(),
                    request_body_records,
                    raw_output_records,
                    usage_record,
                    attempts,
                    provider_outcome,
                    parsed_output: None,
                    turn_result,
                    degradation_record: Some(degradation_record),
                };
                bundle.validate()?;
                return Ok(bundle);
            }
        }
    }

    Err(InferenceAdapterError::TransportError {
        reason: "retry loop exited without a final inference result".to_string(),
    })
}

fn build_bundle_from_finalized_outcome(
    request: &InferenceTurnRequest,
    generation_policy: &InferenceGenerationPolicy,
    rendered_prompt: &InferenceRenderedPromptRecord,
    tool_catalog: &InferenceToolCatalogPayloadRecord,
    response_schema: &InferenceResponseSchemaPayloadRecord,
    request_body_records: Vec<InferenceRequestBodyRecord>,
    raw_output_records: Vec<InferenceRawOutputRecord>,
    attempts: Vec<InferenceAttemptRecord>,
    finalized: FinalizedProviderOutcome,
) -> Result<InferenceTurnBundle, InferenceAdapterError> {
    let turn_result_id = format!(
        "inference-turn-result:{}",
        sanitize_id(&request.turn_request_id)
    );
    let parsed_output =
        finalized
            .parsed_output
            .map(|normalized_output_json| InferenceParsedOutputRecord {
                parsed_output_id: format!(
                    "inference-parsed-output:{}",
                    sanitize_id(&request.turn_request_id)
                ),
                turn_request_ref: request.turn_request_id.clone(),
                provider_ref: finalized.provider_ref.clone(),
                model_ref: finalized.model_ref.clone(),
                normalized_output_json,
                created_at: finalized.created_at.clone(),
            });
    let usage_record = build_usage_record(
        request,
        finalized.input_tokens,
        finalized.output_tokens,
        finalized.latency_ms,
        finalized.estimated_cost_microunits,
        &finalized.created_at,
    );
    let provider_outcome = InferenceProviderOutcomeRecord {
        provider_outcome_id: format!(
            "inference-provider-outcome:{}",
            sanitize_id(&request.turn_request_id)
        ),
        turn_request_ref: request.turn_request_id.clone(),
        provider_ref: finalized.provider_ref.clone(),
        model_ref: finalized.model_ref.clone(),
        finish_reason: finalized.finish_reason,
        final_http_status: finalized.final_http_status,
        attempt_refs: attempts
            .iter()
            .map(|item| item.attempt_id.clone())
            .collect(),
        refusal_summary: finalized.refusal_summary.clone(),
        provider_response_id: finalized.provider_response_id.clone(),
        provider_request_id: finalized.provider_request_id.clone(),
        input_tokens: finalized.input_tokens,
        output_tokens: finalized.output_tokens,
        total_tokens: finalized.input_tokens + finalized.output_tokens,
        latency_ms: finalized.latency_ms,
        estimated_cost_microunits: finalized.estimated_cost_microunits,
        currency: "usd".to_string(),
        created_at: finalized.created_at.clone(),
    };
    let degradation_record =
        finalized
            .degradation
            .map(|(reason_class, summary)| ProviderDegradationRecord {
                degradation_id: format!(
                    "inference-degradation:{}",
                    sanitize_id(&request.turn_request_id)
                ),
                turn_result_ref: turn_result_id.clone(),
                reason_class,
                summary,
                recovery_attempt_refs: attempts
                    .iter()
                    .map(|item| item.attempt_id.clone())
                    .collect(),
                created_at: finalized.created_at.clone(),
            });
    let turn_result = InferenceTurnResult {
        turn_result_id,
        turn_request_ref: request.turn_request_id.clone(),
        raw_output_ref: finalized.raw_output_ref,
        parsed_output_ref: parsed_output
            .as_ref()
            .map(|item| item.parsed_output_id.clone()),
        finish_reason: finalized.finish_reason,
        usage_record_ref: usage_record.usage_record_id.clone(),
        provider_outcome_ref: provider_outcome.provider_outcome_id.clone(),
        attempt_refs: provider_outcome.attempt_refs.clone(),
        provider_metadata_refs: finalized.provider_metadata_refs,
        degradation_ref: degradation_record
            .as_ref()
            .map(|record| record.degradation_id.clone()),
        created_at: finalized.created_at,
    };
    let bundle = InferenceTurnBundle {
        turn_request: request.clone(),
        generation_policy: generation_policy.clone(),
        rendered_prompt: rendered_prompt.clone(),
        tool_catalog: tool_catalog.clone(),
        response_schema: response_schema.clone(),
        request_body_records,
        raw_output_records,
        usage_record,
        attempts,
        provider_outcome,
        parsed_output,
        turn_result,
        degradation_record,
    };
    bundle.validate()?;
    Ok(bundle)
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FinalizedProviderOutcome {
    provider_ref: String,
    model_ref: String,
    finish_reason: InferenceFinishReason,
    final_http_status: Option<u16>,
    raw_output_ref: String,
    parsed_output: Option<String>,
    refusal_summary: Option<String>,
    provider_response_id: Option<String>,
    provider_request_id: Option<String>,
    provider_metadata_refs: Vec<String>,
    input_tokens: usize,
    output_tokens: usize,
    latency_ms: u64,
    estimated_cost_microunits: u64,
    degradation: Option<(ProviderDegradationReasonClass, String)>,
    created_at: String,
}

fn parse_openai_responses_envelope(
    raw_output_payload: &str,
    provider: &InferenceProviderRegistryEntry,
    request: &InferenceTurnRequest,
    model: &InferenceProviderModelEntry,
    exposed_function_tool_names: &BTreeSet<String>,
    required_function_name: Option<&str>,
    http_status: Option<u16>,
    provider_response_id: Option<String>,
    provider_request_id: Option<String>,
    latency_ms: u64,
    attempts: &[InferenceAttemptRecord],
    created_at: &str,
) -> Result<FinalizedProviderOutcome, InferenceAdapterError> {
    let value = serde_json::from_str::<Value>(raw_output_payload).map_err(|_| {
        InferenceAdapterError::TransportError {
            reason: "received non-JSON OpenAI response body".to_string(),
        }
    })?;

    let successful_http = http_status.is_none_or(|status| (200..300).contains(&status));
    let refusal_summary = extract_refusal_summary(&value);
    let required_envelope_terminal = required_function_name.is_none()
        || value.get("status").and_then(Value::as_str) == Some("completed")
            && value.get("error").is_none_or(Value::is_null)
            && value.get("incomplete_details").is_none_or(Value::is_null);
    let parsed_output =
        if !successful_http || refusal_summary.is_some() || !required_envelope_terminal {
            None
        } else {
            extract_normalized_openai_output(
                &value,
                exposed_function_tool_names,
                required_function_name,
            )
        };
    let finish_reason = if !successful_http {
        InferenceFinishReason::ProviderError
    } else if refusal_summary.is_some() {
        InferenceFinishReason::Refused
    } else if parsed_output.is_some() {
        InferenceFinishReason::Completed
    } else {
        InferenceFinishReason::MalformedOutput
    };
    let (input_tokens, output_tokens) =
        provider_usage_for_outcome(finish_reason, extract_usage(&value))?;
    let estimated_cost_microunits = estimate_cost_microunits(model, input_tokens, output_tokens);

    let response_id = provider_response_id.or_else(|| {
        value
            .get("id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    });
    let provider_metadata_refs = build_provider_metadata_refs(
        attempts,
        response_id.as_deref(),
        provider_request_id.as_deref(),
    );

    Ok(FinalizedProviderOutcome {
        provider_ref: provider.provider_id.clone(),
        model_ref: request.model_ref.clone(),
        finish_reason,
        final_http_status: http_status,
        raw_output_ref: attempts
            .last()
            .expect("attempts exist")
            .raw_response_body_ref
            .clone(),
        parsed_output,
        refusal_summary,
        provider_response_id: response_id,
        provider_request_id,
        provider_metadata_refs,
        input_tokens,
        output_tokens,
        latency_ms,
        estimated_cost_microunits,
        degradation: match finish_reason {
            InferenceFinishReason::MalformedOutput => Some((
                ProviderDegradationReasonClass::MalformedOutput,
                "OpenAI response envelope was valid JSON but did not contain usable output."
                    .to_string(),
            )),
            InferenceFinishReason::ProviderError => Some((
                ProviderDegradationReasonClass::TransportFailure,
                match http_status {
                    Some(status) => {
                        format!("OpenAI provider returned non-success HTTP status {status}.")
                    }
                    None => "OpenAI provider returned a non-success outcome.".to_string(),
                },
            )),
            _ => None,
        },
        created_at: created_at.to_string(),
    })
}

fn parse_openrouter_chat_completions_envelope(
    raw_output_payload: &str,
    provider: &InferenceProviderRegistryEntry,
    request: &InferenceTurnRequest,
    model: &InferenceProviderModelEntry,
    exposed_function_tool_names: &BTreeSet<String>,
    required_function_name: Option<&str>,
    http_status: Option<u16>,
    provider_response_id: Option<String>,
    provider_request_id: Option<String>,
    latency_ms: u64,
    attempts: &[InferenceAttemptRecord],
    created_at: &str,
) -> Result<FinalizedProviderOutcome, InferenceAdapterError> {
    let value = serde_json::from_str::<Value>(raw_output_payload).map_err(|_| {
        InferenceAdapterError::TransportError {
            reason: "received non-JSON OpenRouter chat completion body".to_string(),
        }
    })?;

    let successful_http = http_status.is_none_or(|status| (200..300).contains(&status));
    let has_exact_message = exact_openrouter_chat_completion_message(&value).is_some();
    let required_envelope_terminal = required_function_name.is_none()
        || value.get("error").is_none_or(Value::is_null)
            && exact_openrouter_chat_completion_message(&value)
                .and_then(|message| message.get("role"))
                .and_then(Value::as_str)
                == Some("assistant")
            && exact_openrouter_chat_completion_message(&value)
                .and_then(|message| message.get("refusal"))
                .is_none_or(Value::is_null);
    let refusal_summary = has_exact_message
        .then(|| {
            extract_openrouter_chat_completion_refusal_summary(&value)
                .or_else(|| extract_refusal_summary(&value))
        })
        .flatten();
    let parsed_output = if !successful_http
        || !has_exact_message
        || !required_envelope_terminal
        || refusal_summary.is_some()
    {
        None
    } else {
        extract_normalized_openrouter_output(
            &value,
            exposed_function_tool_names,
            required_function_name,
        )
    };
    let finish_reason = if !successful_http {
        InferenceFinishReason::ProviderError
    } else if !has_exact_message || !required_envelope_terminal {
        InferenceFinishReason::MalformedOutput
    } else if refusal_summary.is_some() {
        InferenceFinishReason::Refused
    } else if parsed_output.is_some() {
        InferenceFinishReason::Completed
    } else {
        InferenceFinishReason::MalformedOutput
    };
    let (input_tokens, output_tokens) =
        provider_usage_for_outcome(finish_reason, extract_chat_completion_usage(&value))?;
    let estimated_cost_microunits = estimate_cost_microunits(model, input_tokens, output_tokens);
    let response_id = provider_response_id.or_else(|| {
        value
            .get("id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    });
    let provider_metadata_refs = build_provider_metadata_refs(
        attempts,
        response_id.as_deref(),
        provider_request_id.as_deref(),
    );

    Ok(FinalizedProviderOutcome {
        provider_ref: provider.provider_id.clone(),
        model_ref: request.model_ref.clone(),
        finish_reason,
        final_http_status: http_status,
        raw_output_ref: attempts
            .last()
            .expect("attempts exist")
            .raw_response_body_ref
            .clone(),
        parsed_output,
        refusal_summary,
        provider_response_id: response_id,
        provider_request_id,
        provider_metadata_refs,
        input_tokens,
        output_tokens,
        latency_ms,
        estimated_cost_microunits,
        degradation: match finish_reason {
            InferenceFinishReason::MalformedOutput => Some((
                ProviderDegradationReasonClass::MalformedOutput,
                "OpenRouter chat completion did not contain usable assistant JSON or function-call arguments."
                    .to_string(),
            )),
            InferenceFinishReason::ProviderError => Some((
                ProviderDegradationReasonClass::TransportFailure,
                match http_status {
                    Some(status) => {
                        format!("OpenRouter provider returned non-success HTTP status {status}.")
                    }
                    None => "OpenRouter provider returned a non-success outcome.".to_string(),
                },
            )),
            _ => None,
        },
        created_at: created_at.to_string(),
    })
}

fn build_provider_metadata_refs(
    attempts: &[InferenceAttemptRecord],
    provider_response_id: Option<&str>,
    provider_request_id: Option<&str>,
) -> Vec<String> {
    let mut refs = attempts
        .iter()
        .map(|attempt| attempt.attempt_id.clone())
        .collect::<Vec<_>>();
    if let Some(provider_response_id) = provider_response_id {
        refs.push(format!("provider-response:{provider_response_id}"));
    }
    if let Some(provider_request_id) = provider_request_id {
        refs.push(format!("provider-request:{provider_request_id}"));
    }
    refs
}

fn extract_refusal_summary(value: &Value) -> Option<String> {
    if let Some(refusal) = value.get("refusal").and_then(Value::as_str) {
        return Some(refusal.to_string());
    }

    let output = value.get("output")?.as_array()?;
    for item in output {
        let Some(content) = item.get("content").and_then(Value::as_array) else {
            continue;
        };
        for content_item in content {
            if content_item.get("type").and_then(Value::as_str) == Some("refusal") {
                if let Some(refusal) = content_item.get("refusal").and_then(Value::as_str) {
                    return Some(refusal.to_string());
                }
                if let Some(text) = content_item.get("text").and_then(Value::as_str) {
                    return Some(text.to_string());
                }
            }
        }
    }
    None
}

fn extract_normalized_openai_output(
    value: &Value,
    exposed_function_tool_names: &BTreeSet<String>,
    required_function_name: Option<&str>,
) -> Option<String> {
    if let Some(output) = value.get("output").and_then(Value::as_array) {
        let function_calls = output
            .iter()
            .filter(|item| item.get("type").and_then(Value::as_str) == Some("function_call"))
            .collect::<Vec<_>>();
        if !function_calls.is_empty() {
            let executable_items = output
                .iter()
                .filter(|item| {
                    item.get("type")
                        .and_then(Value::as_str)
                        .is_some_and(|item_type| item_type.ends_with("_call"))
                })
                .count();
            if function_calls.len() != 1
                || required_function_name.is_some() && executable_items != 1
            {
                return None;
            }
            let function_call = function_calls[0];
            if required_function_name.is_some()
                && function_call.get("status").and_then(Value::as_str) != Some("completed")
            {
                return None;
            }
            let function_name = function_call.get("name").and_then(Value::as_str)?;
            if !exposed_function_tool_names.contains(function_name)
                || required_function_name.is_some_and(|required| required != function_name)
            {
                return None;
            }
            return function_call
                .get("arguments")
                .and_then(Value::as_str)
                .and_then(parse_embedded_json_object);
        }
    }

    if required_function_name.is_some() {
        return None;
    }

    if let Some(parsed) = value.get("output_parsed") {
        return Some(parsed.to_string());
    }
    if let Some(output_text) = value.get("output_text").and_then(Value::as_str) {
        return Some(
            parse_embedded_json(output_text)
                .unwrap_or_else(|| json!({ "output_text": output_text }).to_string()),
        );
    }

    if let Some(output) = value.get("output").and_then(Value::as_array) {
        for item in output {
            let Some(content) = item.get("content").and_then(Value::as_array) else {
                continue;
            };
            for content_item in content {
                if let Some(parsed) = content_item.get("parsed") {
                    return Some(parsed.to_string());
                }
                if content_item.get("type").and_then(Value::as_str) == Some("output_text") {
                    if let Some(text) = content_item.get("text").and_then(Value::as_str) {
                        return Some(
                            parse_embedded_json(text)
                                .unwrap_or_else(|| json!({ "output_text": text }).to_string()),
                        );
                    }
                }
            }
        }
    }

    // Keep the original generic fallback for response variants which do not
    // expose structured output in one of the provider's documented fields.
    value.get("output").map(Value::to_string)
}

fn parse_embedded_json(payload: &str) -> Option<String> {
    serde_json::from_str::<Value>(payload)
        .ok()
        .map(|value| value.to_string())
}

fn parse_embedded_json_object(payload: &str) -> Option<String> {
    serde_json::from_str::<Value>(payload)
        .ok()
        .filter(Value::is_object)
        .map(|value| value.to_string())
}

fn extract_usage(value: &Value) -> Result<(usize, usize), InferenceAdapterError> {
    let usage = provider_usage_object(value)?;
    let input_tokens = required_provider_usage_count(usage, "input_tokens")?;
    let output_tokens = required_provider_usage_count(usage, "output_tokens")?;
    validate_provider_usage_total(usage, input_tokens, output_tokens)?;
    Ok((input_tokens, output_tokens))
}

fn provider_usage_for_outcome(
    finish_reason: InferenceFinishReason,
    reported_usage: Result<(usize, usize), InferenceAdapterError>,
) -> Result<(usize, usize), InferenceAdapterError> {
    match reported_usage {
        Ok(usage) => Ok(usage),
        Err(error) if finish_reason == InferenceFinishReason::Completed => Err(error),
        // Non-completed outcomes are never usable M5 qualification evidence.
        // Preserve their governed refusal/degradation record with zero billing
        // rather than erasing the outcome because the provider omitted usage.
        Err(_) => Ok((0, 0)),
    }
}

fn provider_usage_object(value: &Value) -> Result<&Value, InferenceAdapterError> {
    match value.get("usage") {
        None => Err(InferenceAdapterError::MissingProviderUsage),
        Some(usage) if usage.is_object() => Ok(usage),
        Some(_) => Err(InferenceAdapterError::InvalidProviderUsage {
            reason: "provider usage must be a JSON object".to_string(),
        }),
    }
}

fn required_provider_usage_count(
    usage: &Value,
    field: &str,
) -> Result<usize, InferenceAdapterError> {
    let Some(value) = usage.get(field) else {
        return Err(InferenceAdapterError::InvalidProviderUsage {
            reason: format!("provider usage is missing required field {field}"),
        });
    };
    provider_usage_count(value, field)
}

fn aliased_provider_usage_count(
    usage: &Value,
    fields: &[&str],
) -> Result<usize, InferenceAdapterError> {
    let mut reported = None;
    for field in fields {
        let Some(value) = usage.get(*field) else {
            continue;
        };
        let count = provider_usage_count(value, field)?;
        if reported.is_some_and(|previous| previous != count) {
            return Err(InferenceAdapterError::InvalidProviderUsage {
                reason: format!(
                    "provider usage contains conflicting aliases {}",
                    fields.join("/")
                ),
            });
        }
        reported = Some(count);
    }
    reported.ok_or_else(|| InferenceAdapterError::InvalidProviderUsage {
        reason: format!(
            "provider usage is missing required field {}",
            fields.join(" or ")
        ),
    })
}

fn provider_usage_count(value: &Value, field: &str) -> Result<usize, InferenceAdapterError> {
    let Some(count) = value.as_u64() else {
        return Err(InferenceAdapterError::InvalidProviderUsage {
            reason: format!("provider usage field {field} must be an unsigned integer"),
        });
    };
    usize::try_from(count).map_err(|_| InferenceAdapterError::InvalidProviderUsage {
        reason: format!("provider usage field {field} exceeds the platform token-count range"),
    })
}

fn validate_provider_usage_total(
    usage: &Value,
    input_tokens: usize,
    output_tokens: usize,
) -> Result<(), InferenceAdapterError> {
    let total_tokens = required_provider_usage_count(usage, "total_tokens")?;
    let Some(derived_total) = input_tokens.checked_add(output_tokens) else {
        return Err(InferenceAdapterError::InvalidProviderUsage {
            reason:
                "provider usage input and output token sum exceeds the platform token-count range"
                    .to_string(),
        });
    };
    if total_tokens != derived_total {
        return Err(InferenceAdapterError::InvalidProviderUsage {
            reason: "provider usage total_tokens does not equal input plus output tokens"
                .to_string(),
        });
    }
    Ok(())
}

fn build_usage_record(
    request: &InferenceTurnRequest,
    input_tokens: usize,
    output_tokens: usize,
    latency_ms: u64,
    estimated_cost_microunits: u64,
    created_at: &str,
) -> InferenceUsageRecord {
    InferenceUsageRecord {
        usage_record_id: format!("inference-usage:{}", sanitize_id(&request.turn_request_id)),
        turn_request_ref: request.turn_request_id.clone(),
        input_tokens,
        output_tokens,
        total_tokens: input_tokens + output_tokens,
        latency_ms,
        estimated_cost_microunits,
        currency: "usd".to_string(),
        created_at: created_at.to_string(),
    }
}

/// Purely rebuild the exact live-provider request body for one required
/// function call. The caller supplies only frozen, non-secret inputs; no
/// registry lookup, environment access, clock, or network operation occurs.
pub fn build_required_function_request_body_json_from_frozen_inputs(
    provider_mode: InferenceProviderMode,
    model_ref: &str,
    prompt_text: &str,
    tool_catalog_json: &str,
    response_schema_json: &str,
    response_schema_id: &str,
    max_output_tokens: u32,
    required_function_name: &str,
) -> Result<String, InferenceAdapterError> {
    require_nonempty(model_ref, InferenceAdapterError::MissingModelRef)?;
    require_nonempty(prompt_text, InferenceAdapterError::MissingPromptText)?;
    require_nonempty(
        tool_catalog_json,
        InferenceAdapterError::MissingToolCatalogJson,
    )?;
    require_nonempty(
        response_schema_json,
        InferenceAdapterError::MissingResponseSchemaJson,
    )?;
    require_nonempty(
        response_schema_id,
        InferenceAdapterError::MissingResponseSchemaId,
    )?;
    if max_output_tokens == 0 {
        return Err(InferenceAdapterError::InvalidMaxOutputTokens);
    }
    if required_function_name.is_empty() {
        return Err(InferenceAdapterError::RequiredFunctionToolUnavailable {
            required_function_name: String::new(),
        });
    }

    let tool_catalog_value = serde_json::from_str::<Value>(tool_catalog_json)
        .map_err(|_| InferenceAdapterError::InvalidToolCatalogJson)?;
    let response_schema_value = serde_json::from_str::<Value>(response_schema_json)
        .map_err(|_| InferenceAdapterError::InvalidResponseSchemaJson)?;
    let Some(tools) = tool_catalog_value.as_array() else {
        return Err(InferenceAdapterError::InvalidToolCatalogJson);
    };

    match provider_mode {
        InferenceProviderMode::OpenAiResponses => {
            if !tools
                .iter()
                .filter_map(function_tool_name)
                .any(|name| name == required_function_name)
            {
                return Err(InferenceAdapterError::RequiredFunctionToolUnavailable {
                    required_function_name: required_function_name.to_string(),
                });
            }
            let response_format =
                normalize_openai_responses_format(response_schema_value, response_schema_id)?;
            Ok(json!({
                "model": model_ref,
                "input": prompt_text,
                "tools": tools,
                "tool_choice": {
                    "type": "function",
                    "name": required_function_name
                },
                "text": {"format": response_format},
                "max_output_tokens": max_output_tokens
            })
            .to_string())
        }
        InferenceProviderMode::OpenRouterChatCompletions => {
            let tools = normalize_openrouter_tools(tools)?;
            if !tools
                .iter()
                .filter_map(function_tool_name)
                .any(|name| name == required_function_name)
            {
                return Err(InferenceAdapterError::RequiredFunctionToolUnavailable {
                    required_function_name: required_function_name.to_string(),
                });
            }
            let response_format =
                normalize_openrouter_response_format(response_schema_value, response_schema_id)?;
            Ok(json!({
                "model": model_ref,
                "messages": [{"role": "user", "content": prompt_text}],
                "tools": tools,
                "tool_choice": {
                    "type": "function",
                    "function": {"name": required_function_name}
                },
                "parallel_tool_calls": false,
                "response_format": response_format,
                "max_tokens": max_output_tokens
            })
            .to_string())
        }
        InferenceProviderMode::DeterministicFixture | InferenceProviderMode::Disabled => {
            Err(InferenceAdapterError::RequiredFunctionToolUnavailable {
                required_function_name: required_function_name.to_string(),
            })
        }
    }
}

fn build_request_body_json(
    provider: &InferenceProviderRegistryEntry,
    request: &InferenceTurnRequest,
    generation_policy: &InferenceGenerationPolicy,
    rendered_prompt: &InferenceRenderedPromptRecord,
    tool_catalog: &InferenceToolCatalogPayloadRecord,
    response_schema: &InferenceResponseSchemaPayloadRecord,
) -> Result<String, InferenceAdapterError> {
    build_request_body_json_with_required_function(
        provider,
        request,
        generation_policy,
        rendered_prompt,
        tool_catalog,
        response_schema,
        None,
    )
}

fn build_request_body_json_with_required_function(
    provider: &InferenceProviderRegistryEntry,
    request: &InferenceTurnRequest,
    generation_policy: &InferenceGenerationPolicy,
    rendered_prompt: &InferenceRenderedPromptRecord,
    tool_catalog: &InferenceToolCatalogPayloadRecord,
    response_schema: &InferenceResponseSchemaPayloadRecord,
    required_function_name: Option<&str>,
) -> Result<String, InferenceAdapterError> {
    if let Some(required_function_name) = required_function_name {
        let max_output_tokens = u32::try_from(generation_policy.max_output_tokens)
            .map_err(|_| InferenceAdapterError::InvalidMaxOutputTokens)?;
        return build_required_function_request_body_json_from_frozen_inputs(
            provider.provider_mode,
            &request.model_ref,
            &rendered_prompt.prompt_text,
            &tool_catalog.tool_catalog_json,
            &response_schema.response_schema_json,
            &response_schema.response_schema_id,
            max_output_tokens,
            required_function_name,
        );
    }
    let tool_catalog_value = serde_json::from_str::<Value>(&tool_catalog.tool_catalog_json)
        .map_err(|_| InferenceAdapterError::InvalidToolCatalogJson)?;
    let response_schema_value =
        serde_json::from_str::<Value>(&response_schema.response_schema_json)
            .map_err(|_| InferenceAdapterError::InvalidResponseSchemaJson)?;

    match provider.provider_mode {
        InferenceProviderMode::OpenAiResponses => {
            let Some(tools) = tool_catalog_value.as_array() else {
                return Err(InferenceAdapterError::InvalidToolCatalogJson);
            };
            let response_format = normalize_openai_responses_format(
                response_schema_value,
                &response_schema.response_schema_id,
            )?;
            let tool_choice = if tools.is_empty() {
                Value::String("none".to_string())
            } else {
                Value::String("auto".to_string())
            };
            Ok(json!({
                "model": request.model_ref,
                "input": rendered_prompt.prompt_text,
                "tools": tools,
                "tool_choice": tool_choice,
                "text": {
                    "format": response_format
                },
                "max_output_tokens": generation_policy.max_output_tokens
            })
            .to_string())
        }
        InferenceProviderMode::OpenRouterChatCompletions => {
            let Some(tools) = tool_catalog_value.as_array() else {
                return Err(InferenceAdapterError::InvalidToolCatalogJson);
            };
            let tools = normalize_openrouter_tools(tools)?;
            let response_format = normalize_openrouter_response_format(
                response_schema_value,
                &response_schema.response_schema_id,
            )?;
            let tool_choice = if tools.is_empty() {
                Value::String("none".to_string())
            } else {
                Value::String("auto".to_string())
            };
            Ok(json!({
                "model": request.model_ref,
                "messages": [
                    {
                        "role": "user",
                        "content": rendered_prompt.prompt_text,
                    }
                ],
                "tools": tools,
                "tool_choice": tool_choice,
                "response_format": response_format,
                "max_tokens": generation_policy.max_output_tokens
            })
            .to_string())
        }
        InferenceProviderMode::DeterministicFixture | InferenceProviderMode::Disabled => {
            Ok(json!({
                "provider_mode": provider.provider_mode,
                "provider_ref": provider.provider_id,
                "model": request.model_ref,
                "input": rendered_prompt.prompt_text,
                "tools": tool_catalog_value,
                "response_schema": response_schema_value,
                "max_output_tokens": generation_policy.max_output_tokens
            })
            .to_string())
        }
    }
}

fn normalize_openai_responses_format(
    response_schema: Value,
    response_schema_id: &str,
) -> Result<Value, InferenceAdapterError> {
    if response_schema.get("type").and_then(Value::as_str) == Some("json_schema") {
        if response_schema.get("schema").is_some() {
            return Ok(response_schema);
        }
        if let Some(chat_format) = response_schema.get("json_schema") {
            return responses_format_from_definition(chat_format, response_schema_id);
        }
        return Err(InferenceAdapterError::InvalidResponseSchemaJson);
    }

    Ok(json!({
        "type": "json_schema",
        "name": response_schema_name(response_schema_id),
        "strict": true,
        "schema": response_schema,
    }))
}

fn normalize_openrouter_response_format(
    response_schema: Value,
    response_schema_id: &str,
) -> Result<Value, InferenceAdapterError> {
    let response_schema_type = response_schema
        .get("type")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    match response_schema_type.as_deref() {
        Some("json_schema") => {
            if response_schema.get("json_schema").is_some() {
                return Ok(response_schema);
            }
            let definition = responses_definition(&response_schema, response_schema_id)?;
            Ok(json!({
                "type": "json_schema",
                "json_schema": definition,
            }))
        }
        // Preserve the older JSON-object response mode for generic callers.
        Some("json_object") => Ok(response_schema),
        _ => Ok(json!({
            "type": "json_schema",
            "json_schema": {
                "name": response_schema_name(response_schema_id),
                "strict": true,
                "schema": response_schema,
            },
        })),
    }
}

fn responses_format_from_definition(
    definition: &Value,
    response_schema_id: &str,
) -> Result<Value, InferenceAdapterError> {
    let definition = responses_definition(definition, response_schema_id)?;
    let Some(definition) = definition.as_object() else {
        return Err(InferenceAdapterError::InvalidResponseSchemaJson);
    };
    let mut format = definition.clone();
    format.insert("type".to_string(), Value::String("json_schema".to_string()));
    Ok(Value::Object(format))
}

fn responses_definition(
    value: &Value,
    response_schema_id: &str,
) -> Result<Value, InferenceAdapterError> {
    let Some(schema) = value.get("schema") else {
        return Err(InferenceAdapterError::InvalidResponseSchemaJson);
    };
    let name = value
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.trim().is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| response_schema_name(response_schema_id));
    let strict = value.get("strict").and_then(Value::as_bool).unwrap_or(true);
    let mut definition = serde_json::Map::new();
    definition.insert("name".to_string(), Value::String(name));
    if let Some(description) = value.get("description") {
        definition.insert("description".to_string(), description.clone());
    }
    definition.insert("strict".to_string(), Value::Bool(strict));
    definition.insert("schema".to_string(), schema.clone());
    Ok(Value::Object(definition))
}

fn response_schema_name(response_schema_id: &str) -> String {
    let mut name = response_schema_id
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '_' | '-') {
                character
            } else {
                '_'
            }
        })
        .take(64)
        .collect::<String>();
    if name.is_empty() {
        name.push_str("response_schema");
    }
    name
}

fn normalize_openrouter_tools(tools: &[Value]) -> Result<Vec<Value>, InferenceAdapterError> {
    tools
        .iter()
        .map(|tool| {
            if tool.get("type").and_then(Value::as_str) != Some("function") {
                return Ok(tool.clone());
            }
            if let Some(function) = tool.get("function") {
                if !function.is_object() {
                    return Err(InferenceAdapterError::InvalidToolCatalogJson);
                }
                return Ok(tool.clone());
            }

            let Some(tool) = tool.as_object() else {
                return Err(InferenceAdapterError::InvalidToolCatalogJson);
            };
            let mut function = tool.clone();
            function.remove("type");
            if function.get("name").and_then(Value::as_str).is_none() {
                return Err(InferenceAdapterError::InvalidToolCatalogJson);
            }
            Ok(json!({
                "type": "function",
                "function": Value::Object(function),
            }))
        })
        .collect()
}

fn build_raw_output_record(
    request: &InferenceTurnRequest,
    provider: &InferenceProviderRegistryEntry,
    attempt_number: usize,
    raw_output_payload: String,
    created_at: &str,
) -> InferenceRawOutputRecord {
    InferenceRawOutputRecord {
        raw_output_id: format!(
            "inference-raw-output:{}:{}",
            sanitize_id(&request.turn_request_id),
            attempt_number
        ),
        turn_request_ref: request.turn_request_id.clone(),
        provider_ref: provider.provider_id.clone(),
        model_ref: request.model_ref.clone(),
        attempt_number,
        raw_output_payload,
        created_at: created_at.to_string(),
    }
}

fn estimate_cost_microunits(
    model: &InferenceProviderModelEntry,
    input_tokens: usize,
    output_tokens: usize,
) -> u64 {
    let input_cost =
        (input_tokens as u128 * model.input_cost_per_million_microunits as u128) / 1_000_000u128;
    let output_cost =
        (output_tokens as u128 * model.output_cost_per_million_microunits as u128) / 1_000_000u128;
    (input_cost + output_cost).min(u128::from(u64::MAX)) as u64
}

fn total_latency_ms(attempts: &[InferenceAttemptRecord]) -> u64 {
    attempts.iter().map(|attempt| attempt.latency_ms).sum()
}

fn safe_transport_failure_summary(
    kind: InferenceTransportFailureKind,
    _untrusted_message: &str,
) -> String {
    // Transport libraries can include full request URLs in error strings. The
    // provider base URL is operator-controlled and may itself contain query or
    // user-info data, so never persist the library text in durable artifacts.
    match kind {
        InferenceTransportFailureKind::Timeout => {
            "provider request timed out before a response was available".to_string()
        }
        InferenceTransportFailureKind::Transport => {
            "provider transport failed before a complete response was available".to_string()
        }
    }
}

fn synthetic_transport_payload(kind: InferenceTransportFailureKind, message: &str) -> String {
    json!({
        "transport_failure_kind": match kind {
            InferenceTransportFailureKind::Timeout => "timeout",
            InferenceTransportFailureKind::Transport => "transport",
        },
        "message": message
    })
    .to_string()
}

fn classify_http_status_retry(status: Option<u16>, retries_remaining: bool) -> RetryDisposition {
    match status.map(StatusCode::from_u16) {
        Some(Ok(StatusCode::TOO_MANY_REQUESTS)) if retries_remaining => RetryDisposition {
            classification: InferenceRetryClassification::RetriedRateLimited,
            should_retry: true,
        },
        Some(Ok(status)) if status.is_server_error() && retries_remaining => RetryDisposition {
            classification: InferenceRetryClassification::RetriedServerError,
            should_retry: true,
        },
        Some(Ok(StatusCode::TOO_MANY_REQUESTS)) => RetryDisposition {
            classification: InferenceRetryClassification::ExhaustedRateLimited,
            should_retry: false,
        },
        Some(Ok(status)) if status.is_server_error() => RetryDisposition {
            classification: InferenceRetryClassification::ExhaustedServerError,
            should_retry: false,
        },
        Some(Ok(status)) if status.is_client_error() => RetryDisposition {
            classification: InferenceRetryClassification::NonRetryableClientError,
            should_retry: false,
        },
        _ => RetryDisposition {
            classification: InferenceRetryClassification::NoRetryNeeded,
            should_retry: false,
        },
    }
}

fn classify_transport_failure_retry(
    kind: InferenceTransportFailureKind,
    retries_remaining: bool,
) -> RetryDisposition {
    match (kind, retries_remaining) {
        (InferenceTransportFailureKind::Timeout, true) => RetryDisposition {
            classification: InferenceRetryClassification::RetriedTimeout,
            should_retry: true,
        },
        (InferenceTransportFailureKind::Timeout, false) => RetryDisposition {
            classification: InferenceRetryClassification::ExhaustedTimeout,
            should_retry: false,
        },
        (InferenceTransportFailureKind::Transport, true) => RetryDisposition {
            classification: InferenceRetryClassification::RetriedTransportFailure,
            should_retry: true,
        },
        (InferenceTransportFailureKind::Transport, false) => RetryDisposition {
            classification: InferenceRetryClassification::ExhaustedTransportFailure,
            should_retry: false,
        },
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RetryDisposition {
    classification: InferenceRetryClassification,
    should_retry: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InferenceTransportFailureKind {
    Timeout,
    Transport,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct InferenceTransportFailure {
    kind: InferenceTransportFailureKind,
    message: String,
    latency_ms: u64,
}

struct InferenceTransportRequest<'a> {
    provider: &'a InferenceProviderRegistryEntry,
    request_body_json: &'a str,
}

struct InferenceTransportResponse {
    http_status: Option<u16>,
    raw_response_body: String,
    latency_ms: u64,
    provider_response_id: Option<String>,
    provider_request_id: Option<String>,
}

async fn read_bounded_provider_response_body(
    mut response: reqwest::Response,
    started: Instant,
) -> Result<(String, u64), InferenceTransportFailure> {
    let failure = |kind, message| InferenceTransportFailure {
        kind,
        message,
        latency_ms: started.elapsed().as_millis() as u64,
    };

    if response
        .content_length()
        .is_some_and(|length| length > MAX_PROVIDER_RESPONSE_BODY_BYTES as u64)
    {
        return Err(failure(
            InferenceTransportFailureKind::Transport,
            format!("provider response body exceeds {MAX_PROVIDER_RESPONSE_BODY_BYTES} bytes"),
        ));
    }

    let initial_capacity = response
        .content_length()
        .and_then(|length| usize::try_from(length).ok())
        .unwrap_or(0)
        .min(MAX_PROVIDER_RESPONSE_BODY_BYTES);
    let mut body = Vec::with_capacity(initial_capacity);
    loop {
        let chunk = response.chunk().await.map_err(|error| {
            failure(
                if error.is_timeout() {
                    InferenceTransportFailureKind::Timeout
                } else {
                    InferenceTransportFailureKind::Transport
                },
                "provider response body could not be read completely".to_string(),
            )
        })?;
        let Some(chunk) = chunk else {
            break;
        };
        let next_length = body.len().checked_add(chunk.len()).ok_or_else(|| {
            failure(
                InferenceTransportFailureKind::Transport,
                "provider response body length overflowed".to_string(),
            )
        })?;
        if next_length > MAX_PROVIDER_RESPONSE_BODY_BYTES {
            return Err(failure(
                InferenceTransportFailureKind::Transport,
                format!("provider response body exceeds {MAX_PROVIDER_RESPONSE_BODY_BYTES} bytes"),
            ));
        }
        body.extend_from_slice(&chunk);
    }

    let body = String::from_utf8(body).map_err(|_| {
        failure(
            InferenceTransportFailureKind::Transport,
            "provider response body is not valid UTF-8".to_string(),
        )
    })?;
    Ok((body, started.elapsed().as_millis() as u64))
}

trait InferenceTransport: Send + Sync {
    fn send<'a>(
        &'a self,
        request: InferenceTransportRequest<'a>,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<InferenceTransportResponse, InferenceTransportFailure>>
                + Send
                + 'a,
        >,
    >;
}

struct OpenAiResponsesTransport {
    client: Client,
    api_key: String,
    organization: Option<String>,
    project: Option<String>,
}

impl OpenAiResponsesTransport {
    fn new(provider: &InferenceProviderRegistryEntry) -> Result<Self, InferenceAdapterError> {
        let client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| InferenceAdapterError::HttpClientBuildError {
                reason: error.to_string(),
            })?;
        let api_key = std::env::var(&provider.api_key_env_var).map_err(|_| {
            InferenceAdapterError::MissingProviderSecretEnv {
                env_var: provider.api_key_env_var.clone(),
            }
        })?;
        let organization = provider
            .organization_env_var
            .as_ref()
            .and_then(|env_var| std::env::var(env_var).ok());
        let project = provider
            .project_env_var
            .as_ref()
            .and_then(|env_var| std::env::var(env_var).ok());

        Ok(Self {
            client,
            api_key,
            organization,
            project,
        })
    }

    #[cfg(test)]
    fn with_credentials(
        api_key: impl Into<String>,
        organization: Option<impl Into<String>>,
        project: Option<impl Into<String>>,
    ) -> Result<Self, InferenceAdapterError> {
        let client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| InferenceAdapterError::HttpClientBuildError {
                reason: error.to_string(),
            })?;
        Ok(Self {
            client,
            api_key: api_key.into(),
            organization: organization.map(Into::into),
            project: project.map(Into::into),
        })
    }
}

impl InferenceTransport for OpenAiResponsesTransport {
    fn send<'a>(
        &'a self,
        request: InferenceTransportRequest<'a>,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<InferenceTransportResponse, InferenceTransportFailure>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let endpoint = parse_base_url(&request.provider.api_base_url)
                .map_err(|error| InferenceTransportFailure {
                    kind: InferenceTransportFailureKind::Transport,
                    message: error.to_string(),
                    latency_ms: 0,
                })?
                .join("v1/responses")
                .map_err(|error| InferenceTransportFailure {
                    kind: InferenceTransportFailureKind::Transport,
                    message: format!("invalid responses endpoint: {error}"),
                    latency_ms: 0,
                })?;

            let mut builder = self
                .client
                .post(endpoint)
                .header("authorization", format!("Bearer {}", self.api_key))
                .header("content-type", "application/json")
                .timeout(Duration::from_millis(request.provider.request_timeout_ms))
                .body(request.request_body_json.to_string());

            if let Some(value) = &self.organization {
                builder = builder.header("OpenAI-Organization", value);
            }
            if let Some(value) = &self.project {
                builder = builder.header("OpenAI-Project", value);
            }

            let started = Instant::now();
            let response = builder
                .send()
                .await
                .map_err(|error| InferenceTransportFailure {
                    kind: if error.is_timeout() {
                        InferenceTransportFailureKind::Timeout
                    } else {
                        InferenceTransportFailureKind::Transport
                    },
                    message: error.to_string(),
                    latency_ms: started.elapsed().as_millis() as u64,
                })?;

            let status = response.status();
            let provider_request_id = response
                .headers()
                .get("x-request-id")
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned);
            let (raw_response_body, latency_ms) =
                read_bounded_provider_response_body(response, started).await?;
            let provider_response_id = serde_json::from_str::<Value>(&raw_response_body)
                .ok()
                .and_then(|value| {
                    value
                        .get("id")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned)
                });

            Ok(InferenceTransportResponse {
                http_status: Some(status.as_u16()),
                raw_response_body,
                latency_ms,
                provider_response_id,
                provider_request_id,
            })
        })
    }
}

struct OpenRouterChatCompletionsTransport {
    client: Client,
    api_key: String,
    organization: Option<String>,
    project: Option<String>,
}

impl OpenRouterChatCompletionsTransport {
    fn new(provider: &InferenceProviderRegistryEntry) -> Result<Self, InferenceAdapterError> {
        let client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| InferenceAdapterError::HttpClientBuildError {
                reason: error.to_string(),
            })?;
        let api_key = std::env::var(&provider.api_key_env_var).map_err(|_| {
            InferenceAdapterError::MissingProviderSecretEnv {
                env_var: provider.api_key_env_var.clone(),
            }
        })?;
        let organization = provider
            .organization_env_var
            .as_ref()
            .and_then(|env_var| std::env::var(env_var).ok());
        let project = provider
            .project_env_var
            .as_ref()
            .and_then(|env_var| std::env::var(env_var).ok());

        Ok(Self {
            client,
            api_key,
            organization,
            project,
        })
    }

    #[cfg(test)]
    fn with_credentials(
        api_key: impl Into<String>,
        organization: Option<impl Into<String>>,
        project: Option<impl Into<String>>,
    ) -> Result<Self, InferenceAdapterError> {
        let client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| InferenceAdapterError::HttpClientBuildError {
                reason: error.to_string(),
            })?;
        Ok(Self {
            client,
            api_key: api_key.into(),
            organization: organization.map(Into::into),
            project: project.map(Into::into),
        })
    }
}

impl InferenceTransport for OpenRouterChatCompletionsTransport {
    fn send<'a>(
        &'a self,
        request: InferenceTransportRequest<'a>,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<InferenceTransportResponse, InferenceTransportFailure>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let endpoint = parse_base_url(&request.provider.api_base_url)
                .map_err(|error| InferenceTransportFailure {
                    kind: InferenceTransportFailureKind::Transport,
                    message: error.to_string(),
                    latency_ms: 0,
                })?
                .join("chat/completions")
                .map_err(|error| InferenceTransportFailure {
                    kind: InferenceTransportFailureKind::Transport,
                    message: format!("invalid chat completions endpoint: {error}"),
                    latency_ms: 0,
                })?;

            let mut builder = self
                .client
                .post(endpoint)
                .header("authorization", format!("Bearer {}", self.api_key))
                .header("content-type", "application/json")
                .timeout(Duration::from_millis(request.provider.request_timeout_ms))
                .body(request.request_body_json.to_string());

            if let Some(value) = &self.organization {
                builder = builder.header("OpenAI-Organization", value);
            }
            if let Some(value) = &self.project {
                builder = builder.header("OpenAI-Project", value);
            }

            let started = Instant::now();
            let response = builder
                .send()
                .await
                .map_err(|error| InferenceTransportFailure {
                    kind: if error.is_timeout() {
                        InferenceTransportFailureKind::Timeout
                    } else {
                        InferenceTransportFailureKind::Transport
                    },
                    message: error.to_string(),
                    latency_ms: started.elapsed().as_millis() as u64,
                })?;

            let status = response.status();
            let provider_request_id = response
                .headers()
                .get("x-request-id")
                .and_then(|value| value.to_str().ok())
                .map(ToOwned::to_owned);
            let (raw_response_body, latency_ms) =
                read_bounded_provider_response_body(response, started).await?;
            let provider_response_id = serde_json::from_str::<Value>(&raw_response_body)
                .ok()
                .and_then(|value| {
                    value
                        .get("id")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned)
                });

            Ok(InferenceTransportResponse {
                http_status: Some(status.as_u16()),
                raw_response_body,
                latency_ms,
                provider_response_id,
                provider_request_id,
            })
        })
    }
}

fn exact_openrouter_chat_completion_message(value: &Value) -> Option<&Value> {
    exact_openrouter_chat_completion_choice(value)?.get("message")
}

fn exact_openrouter_chat_completion_choice(value: &Value) -> Option<&Value> {
    let choices = value.get("choices")?.as_array()?;
    (choices.len() == 1).then(|| choices.first()).flatten()
}

fn extract_openrouter_chat_completion_refusal_summary(value: &Value) -> Option<String> {
    exact_openrouter_chat_completion_message(value)?
        .get("refusal")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn extract_openrouter_chat_completion_message_content(value: &Value) -> Option<String> {
    exact_openrouter_chat_completion_message(value)?
        .get("content")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn extract_normalized_openrouter_output(
    value: &Value,
    exposed_function_tool_names: &BTreeSet<String>,
    required_function_name: Option<&str>,
) -> Option<String> {
    let choice = exact_openrouter_chat_completion_choice(value)?;
    if required_function_name.is_some()
        && choice.get("finish_reason").and_then(Value::as_str) != Some("tool_calls")
    {
        return None;
    }
    let message = exact_openrouter_chat_completion_message(value)?;
    if required_function_name.is_some()
        && (value.get("error").is_some_and(|error| !error.is_null())
            || message.get("role").and_then(Value::as_str) != Some("assistant")
            || message
                .get("refusal")
                .is_some_and(|refusal| !refusal.is_null()))
    {
        return None;
    }

    if let Some(tool_calls_value) = message.get("tool_calls").filter(|value| !value.is_null()) {
        let tool_calls = tool_calls_value.as_array()?;
        if !tool_calls.is_empty() {
            if tool_calls.len() != 1 || message.get("function_call").is_some_and(|v| !v.is_null()) {
                return None;
            }
            let tool_call = tool_calls.first()?;
            if tool_call.get("type").and_then(Value::as_str) != Some("function") {
                return None;
            }
            let function = tool_call.get("function")?;
            let function_name = function.get("name").and_then(Value::as_str)?;
            if !exposed_function_tool_names.contains(function_name)
                || required_function_name.is_some_and(|required| required != function_name)
            {
                return None;
            }
            return function
                .get("arguments")
                .and_then(Value::as_str)
                .and_then(parse_embedded_json_object);
        }
    }

    // Older compatible Chat Completions implementations can expose a single
    // function_call instead of the current tool_calls array.
    if let Some(function) = message
        .get("function_call")
        .filter(|value| !value.is_null())
    {
        if required_function_name.is_some() {
            return None;
        }
        let function_name = function.get("name").and_then(Value::as_str)?;
        if !exposed_function_tool_names.contains(function_name)
            || required_function_name.is_some_and(|required| required != function_name)
        {
            return None;
        }
        return function
            .get("arguments")
            .and_then(Value::as_str)
            .and_then(parse_embedded_json_object);
    }

    if required_function_name.is_some() {
        return None;
    }

    extract_openrouter_chat_completion_message_content(value).map(|content| {
        parse_embedded_json(&content).unwrap_or_else(|| Value::String(content).to_string())
    })
}

fn extract_chat_completion_usage(value: &Value) -> Result<(usize, usize), InferenceAdapterError> {
    let usage = provider_usage_object(value)?;
    let input_tokens = aliased_provider_usage_count(usage, &["prompt_tokens", "input_tokens"])?;
    let output_tokens =
        aliased_provider_usage_count(usage, &["completion_tokens", "output_tokens"])?;
    validate_provider_usage_total(usage, input_tokens, output_tokens)?;
    Ok((input_tokens, output_tokens))
}

/// Normalize a provider base URL exactly as the transports do and report
/// whether its host is one of the narrowly permitted loopback test hosts.
pub fn normalize_safe_provider_api_base_url(
    raw: &str,
) -> Result<(String, bool), InferenceAdapterError> {
    let base = parse_base_url(raw)?;
    let loopback = base.host_str().is_some_and(is_loopback_provider_host);
    Ok((base.to_string(), loopback))
}

fn parse_base_url(raw: &str) -> Result<Url, InferenceAdapterError> {
    let mut base =
        Url::parse(raw.trim()).map_err(|_| InferenceAdapterError::InvalidApiBaseUrl {
            reason: "provider base URL must be a valid absolute URL".to_string(),
        })?;
    if !matches!(base.scheme(), "http" | "https") {
        return Err(InferenceAdapterError::InvalidApiBaseUrl {
            reason: "provider base URL scheme must be https, or http for an exact loopback host"
                .to_string(),
        });
    }
    if !base.username().is_empty() || base.password().is_some() {
        return Err(InferenceAdapterError::InvalidApiBaseUrl {
            reason: "provider base URL must not contain user-info credentials".to_string(),
        });
    }
    if base.query().is_some() || base.fragment().is_some() {
        return Err(InferenceAdapterError::InvalidApiBaseUrl {
            reason: "provider base URL must not contain a query or fragment".to_string(),
        });
    }
    let host = base
        .host_str()
        .ok_or_else(|| InferenceAdapterError::InvalidApiBaseUrl {
            reason: "provider base URL must contain a host".to_string(),
        })?;
    if is_unspecified_provider_host(host) {
        return Err(InferenceAdapterError::InvalidApiBaseUrl {
            reason: "provider base URL must not use an unspecified IP literal".to_string(),
        });
    }
    let exact_loopback_host = is_loopback_provider_host(host);
    if base.scheme() == "http" && !exact_loopback_host {
        return Err(InferenceAdapterError::InvalidApiBaseUrl {
            reason: "plaintext http is allowed only for 127.0.0.1, ::1, or localhost".to_string(),
        });
    }
    if !base.path().ends_with('/') {
        let mut path = base.path().to_string();
        path.push('/');
        base.set_path(&path);
    }
    Ok(base)
}

fn is_loopback_provider_host(host: &str) -> bool {
    let normalized = host
        .trim_end_matches('.')
        .trim_start_matches('[')
        .trim_end_matches(']');
    normalized.eq_ignore_ascii_case("localhost")
        || normalized
            .parse::<IpAddr>()
            .is_ok_and(|address| match address {
                IpAddr::V4(address) => address.is_loopback(),
                IpAddr::V6(address) => {
                    address.is_loopback()
                        || address.to_ipv4().is_some_and(|mapped| mapped.is_loopback())
                }
            })
}

fn is_unspecified_provider_host(host: &str) -> bool {
    let normalized = host
        .trim_end_matches('.')
        .trim_start_matches('[')
        .trim_end_matches(']');
    normalized
        .parse::<IpAddr>()
        .is_ok_and(|address| match address {
            IpAddr::V4(address) => address.is_unspecified(),
            IpAddr::V6(address) => {
                address.is_unspecified()
                    || address
                        .to_ipv4()
                        .is_some_and(|mapped| mapped.is_unspecified())
            }
        })
}

fn require_nonempty(
    value: &str,
    error: InferenceAdapterError,
) -> Result<(), InferenceAdapterError> {
    if value.trim().is_empty() {
        return Err(error);
    }
    Ok(())
}

fn validate_optional_ref(
    value: &Option<String>,
    error: InferenceAdapterError,
) -> Result<(), InferenceAdapterError> {
    if value.as_ref().is_some_and(|value| value.trim().is_empty()) {
        return Err(error);
    }
    Ok(())
}

fn validate_ref_entries(
    refs: &[String],
    error: InferenceAdapterError,
) -> Result<(), InferenceAdapterError> {
    if refs.iter().any(|reference| reference.trim().is_empty()) {
        return Err(error);
    }
    Ok(())
}

fn parse_json_payload(
    payload: &str,
    error: InferenceAdapterError,
) -> Result<Value, InferenceAdapterError> {
    serde_json::from_str(payload).map_err(|_| error)
}

fn validate_required_degradation(
    degraded: bool,
    degradation_reason: Option<ProviderDegradationReasonClass>,
    degradation_summary: Option<&str>,
    expected_reason: ProviderDegradationReasonClass,
) -> Result<(), InferenceAdapterError> {
    if !degraded {
        return Err(InferenceAdapterError::MissingDegradationRecord);
    }
    if degradation_reason != Some(expected_reason) {
        return Err(InferenceAdapterError::InvalidDegradationReason);
    }
    if degradation_summary.is_none_or(|summary| summary.trim().is_empty()) {
        return Err(InferenceAdapterError::MissingDegradationSummary);
    }
    Ok(())
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
    use super::*;
    use axum::body::{Body, Bytes};
    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::Response;
    use axum::routing::post;
    use axum::{Json, Router};
    use std::convert::Infallible;
    use std::fs;
    use std::net::{SocketAddr, TcpListener};
    use std::path::Path;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::{Mutex, mpsc};
    use tokio_stream::wrappers::ReceiverStream;

    #[derive(Clone)]
    struct MockServerState {
        behavior: MockBehavior,
        bodies: Arc<Mutex<Vec<Value>>>,
        attempts: Arc<AtomicUsize>,
    }

    #[derive(Clone)]
    struct StreamingResponseState {
        chunks: Arc<Vec<Vec<u8>>>,
        delay_before_later_chunks_ms: u64,
    }

    #[derive(Clone, Copy)]
    enum MockBehavior {
        Success,
        Timeout,
        ServerError,
        RateLimited,
        ClientError,
        Malformed,
        Refusal,
        MissingContent,
        NonStringContent,
        ToolCall,
        PlainContent,
    }

    struct SecretBearingFailureTransport {
        secret: String,
    }

    impl InferenceTransport for SecretBearingFailureTransport {
        fn send<'a>(
            &'a self,
            _request: InferenceTransportRequest<'a>,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<InferenceTransportResponse, InferenceTransportFailure>>
                    + Send
                    + 'a,
            >,
        > {
            Box::pin(async move {
                Err(InferenceTransportFailure {
                    kind: InferenceTransportFailureKind::Transport,
                    message: format!(
                        "request failed for https://operator:{}@provider.invalid/v1?api_key={}",
                        self.secret, self.secret
                    ),
                    latency_ms: 1,
                })
            })
        }
    }

    fn provider(
        mode: InferenceProviderMode,
        base_url: &str,
        api_key_env_var: &str,
    ) -> InferenceProviderRegistryEntry {
        InferenceProviderRegistryEntry {
            provider_id: format!("provider:{}", sanitize_id(base_url)),
            provider_mode: mode,
            models: vec![InferenceProviderModelEntry {
                model_ref: "gpt-5.4-mini".to_string(),
                input_cost_per_million_microunits: 750_000,
                output_cost_per_million_microunits: 4_500_000,
                supports_json_schema: true,
                supports_function_tools: true,
            }],
            capability_summary: "OpenAI Responses transport".to_string(),
            policy_summary: "bounded runtime inference".to_string(),
            active: true,
            api_base_url: base_url.to_string(),
            api_key_env_var: api_key_env_var.to_string(),
            organization_env_var: None,
            project_env_var: None,
            request_timeout_ms: 25,
        }
    }

    fn fixture_provider() -> InferenceProviderRegistryEntry {
        InferenceProviderRegistryEntry {
            provider_id: "provider:fixture".to_string(),
            provider_mode: InferenceProviderMode::DeterministicFixture,
            models: vec![InferenceProviderModelEntry {
                model_ref: "model:test".to_string(),
                input_cost_per_million_microunits: 0,
                output_cost_per_million_microunits: 0,
                supports_json_schema: true,
                supports_function_tools: true,
            }],
            capability_summary: "deterministic fixture-backed inference".to_string(),
            policy_summary: "bounded fixture provider only".to_string(),
            active: true,
            api_base_url: "".to_string(),
            api_key_env_var: "".to_string(),
            organization_env_var: None,
            project_env_var: None,
            request_timeout_ms: 50,
        }
    }

    fn generation_policy(max_retries: usize) -> InferenceGenerationPolicy {
        InferenceGenerationPolicy {
            generation_policy_id: "policy:bounded-generation".to_string(),
            max_output_tokens: 512,
            max_retries,
            summary: "bounded deterministic generation policy".to_string(),
        }
    }

    fn request(provider_ref: &str, model_ref: &str) -> InferenceTurnRequest {
        InferenceTurnRequest {
            turn_request_id: "turn:1".to_string(),
            provider_ref: provider_ref.to_string(),
            model_ref: model_ref.to_string(),
            rendered_prompt_ref: "prompt:turn:1".to_string(),
            tool_catalog_ref: "tools:turn:1".to_string(),
            response_schema_ref: "schema:turn:1".to_string(),
            generation_policy_ref: "policy:bounded-generation".to_string(),
        }
    }

    fn rendered_prompt() -> InferenceRenderedPromptRecord {
        InferenceRenderedPromptRecord {
            rendered_prompt_id: "prompt:turn:1".to_string(),
            turn_request_ref: "turn:1".to_string(),
            prompt_text: "You are a bounded Wasm-Biotic runtime.".to_string(),
            created_at: "1".to_string(),
        }
    }

    fn tool_catalog() -> InferenceToolCatalogPayloadRecord {
        InferenceToolCatalogPayloadRecord {
            tool_catalog_id: "tools:turn:1".to_string(),
            turn_request_ref: "turn:1".to_string(),
            tool_catalog_json: r#"[{"type":"function","name":"continuity.retrieve","description":"retrieve continuity","parameters":{"type":"object","properties":{},"additionalProperties":false}}]"#.to_string(),
            created_at: "1".to_string(),
        }
    }

    fn response_schema() -> InferenceResponseSchemaPayloadRecord {
        InferenceResponseSchemaPayloadRecord {
            response_schema_id: "schema:turn:1".to_string(),
            turn_request_ref: "turn:1".to_string(),
            response_schema_json: r#"{"type":"json_schema","name":"turn_result","strict":true,"schema":{"type":"object","properties":{"turn_outcome":{"type":"string"}},"required":["turn_outcome"],"additionalProperties":false}}"#.to_string(),
            created_at: "1".to_string(),
        }
    }

    fn bare_response_schema() -> InferenceResponseSchemaPayloadRecord {
        InferenceResponseSchemaPayloadRecord {
            response_schema_id: "schema:turn:1".to_string(),
            turn_request_ref: "turn:1".to_string(),
            response_schema_json: r#"{"type":"object","properties":{"turn_outcome":{"type":"string"}},"required":["turn_outcome"],"additionalProperties":false}"#.to_string(),
            created_at: "1".to_string(),
        }
    }

    fn completed_fixture() -> FixtureInferenceResponse {
        FixtureInferenceResponse {
            fixture_response_id: "fixture:completed".to_string(),
            finish_reason: InferenceFinishReason::Completed,
            http_status: Some(200),
            raw_output_payload: r#"{"id":"resp_fixture","output_parsed":{"turn_outcome":"proposals"},"usage":{"input_tokens":17,"output_tokens":11,"total_tokens":28}}"#.to_string(),
            parsed_output_json: Some(r#"{"turn_outcome":"proposals"}"#.to_string()),
            refusal_summary: None,
            provider_response_id: Some("resp_fixture".to_string()),
            provider_request_id: Some("req_fixture".to_string()),
            provider_metadata_refs: vec![
                "provider-response:resp_fixture".to_string(),
                "provider-request:req_fixture".to_string(),
            ],
            input_tokens: 17,
            output_tokens: 11,
            degraded: false,
            degradation_reason: None,
            degradation_summary: None,
            recovery_attempt_refs: Vec::new(),
            transport_error_summary: None,
            latency_ms: 13,
        }
    }

    async fn mock_responses_handler(
        State(state): State<MockServerState>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> (StatusCode, HeaderMap, String) {
        let _auth = headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        state.attempts.fetch_add(1, Ordering::SeqCst);
        state.bodies.lock().await.push(body);
        let mut response_headers = HeaderMap::new();
        response_headers.insert("x-request-id", "req_live".parse().unwrap());

        match state.behavior {
            MockBehavior::Success => (
                StatusCode::OK,
                response_headers,
                json!({
                    "id": "resp_live",
                    "object": "response",
                    "status": "completed",
                    "output": [{
                        "id": "msg_live",
                        "type": "message",
                        "status": "completed",
                        "role": "assistant",
                        "content": [{
                            "type": "output_text",
                            "annotations": [],
                            "text": "{\"turn_outcome\":\"proposals\",\"summary\":\"live ok\"}"
                        }]
                    }],
                    "usage": {"input_tokens": 120, "output_tokens": 60, "total_tokens": 180}
                })
                .to_string(),
            ),
            MockBehavior::Timeout => {
                tokio::time::sleep(Duration::from_millis(80)).await;
                (
                    StatusCode::OK,
                    response_headers,
                    json!({
                        "id": "resp_too_late",
                        "output_parsed": {"turn_outcome": "late"},
                        "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}
                    })
                    .to_string(),
                )
            }
            MockBehavior::ServerError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                response_headers,
                json!({"error": {"message": "server exploded"}}).to_string(),
            ),
            MockBehavior::RateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                response_headers,
                json!({"error": {"message": "slow down"}}).to_string(),
            ),
            MockBehavior::ClientError => (
                StatusCode::BAD_REQUEST,
                response_headers,
                json!({"error": {"message": "bad request"}}).to_string(),
            ),
            MockBehavior::Malformed => (
                StatusCode::OK,
                response_headers,
                json!({
                    "id": "resp_malformed",
                    "usage": {"input_tokens": 12, "output_tokens": 5, "total_tokens": 17}
                })
                .to_string(),
            ),
            MockBehavior::Refusal => (
                StatusCode::OK,
                response_headers,
                json!({
                    "id": "resp_refused",
                    "output": [{
                        "type": "message",
                        "content": [{
                            "type": "refusal",
                            "refusal": "policy refusal"
                        }]
                    }]
                })
                .to_string(),
            ),
            MockBehavior::ToolCall => (
                StatusCode::OK,
                response_headers,
                json!({
                    "id": "resp_function_call",
                    "object": "response",
                    "status": "completed",
                    "output": [{
                        "id": "call_live",
                        "type": "function_call",
                        "status": "completed",
                        "call_id": "call_1",
                        "name": "continuity.retrieve",
                        "arguments": "{\"continuity_key\":\"bounded\"}"
                    }],
                    "usage": {"input_tokens": 21, "output_tokens": 8, "total_tokens": 29}
                })
                .to_string(),
            ),
            MockBehavior::MissingContent
            | MockBehavior::NonStringContent
            | MockBehavior::PlainContent => (
                StatusCode::INTERNAL_SERVER_ERROR,
                response_headers,
                json!({"error": {"message": "responses endpoint behavior mismatch"}}).to_string(),
            ),
        }
    }

    async fn mock_chat_completions_handler(
        State(state): State<MockServerState>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> (StatusCode, HeaderMap, String) {
        let _auth = headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        state.attempts.fetch_add(1, Ordering::SeqCst);
        state.bodies.lock().await.push(body);
        let mut response_headers = HeaderMap::new();
        response_headers.insert("x-request-id", "req_live".parse().unwrap());

        match state.behavior {
            MockBehavior::Success => (
                StatusCode::OK,
                response_headers,
                json!({
                    "id": "chatcmpl_live",
                    "choices": [{
                        "message": {
                            "role": "assistant",
                            "content": "{\"turn_outcome\":\"proposals\",\"summary\":\"live ok\"}"
                        }
                    }],
                    "usage": {"prompt_tokens": 120, "completion_tokens": 60, "total_tokens": 180}
                })
                .to_string(),
            ),
            MockBehavior::Timeout => {
                tokio::time::sleep(Duration::from_millis(80)).await;
                (
                    StatusCode::OK,
                    response_headers,
                    json!({
                        "id": "chatcmpl_too_late",
                        "choices": [{
                            "message": {
                                "role": "assistant",
                                "content": "{\"turn_outcome\":\"late\"}"
                            }
                        }],
                        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
                    })
                    .to_string(),
                )
            }
            MockBehavior::ServerError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                response_headers,
                json!({"error": {"message": "server exploded"}}).to_string(),
            ),
            MockBehavior::RateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                response_headers,
                json!({"error": {"message": "slow down"}}).to_string(),
            ),
            MockBehavior::ClientError => (
                StatusCode::BAD_REQUEST,
                response_headers,
                json!({"error": {"message": "bad request"}}).to_string(),
            ),
            MockBehavior::Malformed | MockBehavior::MissingContent => (
                StatusCode::OK,
                response_headers,
                json!({
                    "id": "chatcmpl_missing_content",
                    "choices": [{
                        "message": {
                            "role": "assistant"
                        }
                    }],
                    "usage": {"prompt_tokens": 12, "completion_tokens": 5, "total_tokens": 17}
                })
                .to_string(),
            ),
            MockBehavior::NonStringContent => (
                StatusCode::OK,
                response_headers,
                json!({
                    "id": "chatcmpl_non_string",
                    "choices": [{
                        "message": {
                            "role": "assistant",
                            "content": {"summary": "not a string"}
                        }
                    }],
                    "usage": {"prompt_tokens": 12, "completion_tokens": 5, "total_tokens": 17}
                })
                .to_string(),
            ),
            MockBehavior::ToolCall => (
                StatusCode::OK,
                response_headers,
                json!({
                    "id": "chatcmpl_tool_call",
                    "choices": [{
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": null,
                            "tool_calls": [{
                                "id": "call_live",
                                "type": "function",
                                "function": {
                                    "name": "continuity.retrieve",
                                    "arguments": "{\"continuity_key\":\"bounded\"}"
                                }
                            }]
                        },
                        "finish_reason": "tool_calls"
                    }],
                    "usage": {"prompt_tokens": 21, "completion_tokens": 8, "total_tokens": 29}
                })
                .to_string(),
            ),
            MockBehavior::PlainContent => (
                StatusCode::OK,
                response_headers,
                json!({
                    "id": "chatcmpl_plain",
                    "choices": [{
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": "plain assistant response"
                        },
                        "finish_reason": "stop"
                    }],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 4, "total_tokens": 14}
                })
                .to_string(),
            ),
            MockBehavior::Refusal => (
                StatusCode::OK,
                response_headers,
                json!({
                    "id": "chatcmpl_refused",
                    "choices": [{
                        "message": {
                            "role": "assistant",
                            "refusal": "policy refusal"
                        }
                    }]
                })
                .to_string(),
            ),
        }
    }

    async fn spawn_mock_server(
        behavior: MockBehavior,
    ) -> (
        SocketAddr,
        Arc<Mutex<Vec<Value>>>,
        Arc<AtomicUsize>,
        tokio::task::JoinHandle<()>,
    ) {
        let bodies = Arc::new(Mutex::new(Vec::new()));
        let attempts = Arc::new(AtomicUsize::new(0));
        let state = MockServerState {
            behavior,
            bodies: bodies.clone(),
            attempts: attempts.clone(),
        };
        let app = Router::new()
            .route("/v1/responses", post(mock_responses_handler))
            .route("/v1/chat/completions", post(mock_chat_completions_handler))
            .with_state(state);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let listener = tokio::net::TcpListener::bind(address).await.unwrap();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (address, bodies, attempts, handle)
    }

    async fn streaming_response_handler(
        State(state): State<StreamingResponseState>,
        Json(_body): Json<Value>,
    ) -> Response {
        let (sender, receiver) = mpsc::channel(1);
        tokio::spawn(async move {
            for (index, chunk) in state.chunks.iter().enumerate() {
                if index > 0 && state.delay_before_later_chunks_ms > 0 {
                    tokio::time::sleep(Duration::from_millis(state.delay_before_later_chunks_ms))
                        .await;
                }
                if sender
                    .send(Ok::<Bytes, Infallible>(Bytes::copy_from_slice(chunk)))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        Response::builder()
            .status(StatusCode::OK)
            .header("x-request-id", "req_streamed")
            .body(Body::from_stream(ReceiverStream::new(receiver)))
            .expect("construct streamed provider response")
    }

    async fn spawn_streaming_mock_server(
        chunks: Vec<Vec<u8>>,
        delay_before_later_chunks_ms: u64,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let state = StreamingResponseState {
            chunks: Arc::new(chunks),
            delay_before_later_chunks_ms,
        };
        let app = Router::new()
            .route("/v1/responses", post(streaming_response_handler))
            .route("/v1/chat/completions", post(streaming_response_handler))
            .with_state(state);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let listener = tokio::net::TcpListener::bind(address).await.unwrap();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (address, handle)
    }

    async fn redirect_response_handler(State(location): State<String>) -> Response {
        Response::builder()
            .status(StatusCode::FOUND)
            .header("location", location)
            .body(Body::empty())
            .expect("construct provider redirect response")
    }

    async fn redirect_target_handler(
        State(attempts): State<Arc<AtomicUsize>>,
        _body: Bytes,
    ) -> Response {
        attempts.fetch_add(1, Ordering::SeqCst);
        Response::builder()
            .status(StatusCode::OK)
            .body(Body::from("{}"))
            .expect("construct redirect target response")
    }

    async fn spawn_redirect_target_server()
    -> (SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        let attempts = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route("/v1/responses", post(redirect_target_handler))
            .route("/v1/chat/completions", post(redirect_target_handler))
            .with_state(attempts.clone());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let listener = tokio::net::TcpListener::bind(address).await.unwrap();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (address, attempts, handle)
    }

    async fn spawn_redirect_server(location: String) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let app = Router::new()
            .route("/v1/responses", post(redirect_response_handler))
            .route("/v1/chat/completions", post(redirect_response_handler))
            .with_state(location);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let listener = tokio::net::TcpListener::bind(address).await.unwrap();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (address, handle)
    }

    #[tokio::test]
    async fn provider_transports_never_follow_redirects() {
        let (target_address, target_attempts, target_handle) = spawn_redirect_target_server().await;
        let request_body_json = "{}";

        let (openai_redirect_address, openai_redirect_handle) =
            spawn_redirect_server(format!("http://{target_address}/v1/responses")).await;
        let openai_provider = provider(
            InferenceProviderMode::OpenAiResponses,
            &format!("http://{openai_redirect_address}"),
            "OPENAI_API_KEY_REDIRECT_TEST",
        );
        let openai = OpenAiResponsesTransport::with_credentials(
            "secret-openai-redirect",
            None::<String>,
            None::<String>,
        )
        .unwrap();
        let openai_response = openai
            .send(InferenceTransportRequest {
                provider: &openai_provider,
                request_body_json,
            })
            .await
            .expect("redirect response itself is observable");
        assert_eq!(
            openai_response.http_status,
            Some(StatusCode::FOUND.as_u16())
        );
        assert_eq!(target_attempts.load(Ordering::SeqCst), 0);
        openai_redirect_handle.abort();

        let (openrouter_redirect_address, openrouter_redirect_handle) =
            spawn_redirect_server(format!("http://{target_address}/v1/chat/completions")).await;
        let openrouter_provider = provider(
            InferenceProviderMode::OpenRouterChatCompletions,
            &format!("http://{openrouter_redirect_address}/v1"),
            "OPENROUTER_API_KEY_REDIRECT_TEST",
        );
        let openrouter = OpenRouterChatCompletionsTransport::with_credentials(
            "secret-openrouter-redirect",
            None::<String>,
            None::<String>,
        )
        .unwrap();
        let openrouter_response = openrouter
            .send(InferenceTransportRequest {
                provider: &openrouter_provider,
                request_body_json,
            })
            .await
            .expect("redirect response itself is observable");
        assert_eq!(
            openrouter_response.http_status,
            Some(StatusCode::FOUND.as_u16())
        );
        assert_eq!(target_attempts.load(Ordering::SeqCst), 0);

        openrouter_redirect_handle.abort();
        target_handle.abort();
    }

    #[test]
    fn provider_policy_and_request_validate() {
        fixture_provider().validate().unwrap();
        generation_policy(0).validate().unwrap();
        request("provider:fixture", "model:test")
            .validate()
            .unwrap();
        rendered_prompt().validate().unwrap();
        tool_catalog().validate().unwrap();
        response_schema().validate().unwrap();
    }

    #[tokio::test]
    async fn provider_transports_reject_chunked_response_bodies_over_the_hard_limit() {
        let (address, handle) = spawn_streaming_mock_server(
            vec![
                vec![b'x'; MAX_PROVIDER_RESPONSE_BODY_BYTES / 2],
                vec![b'x'; MAX_PROVIDER_RESPONSE_BODY_BYTES / 2 + 1],
            ],
            0,
        )
        .await;
        let request_body_json = "{}";

        let mut openai_provider = provider(
            InferenceProviderMode::OpenAiResponses,
            &format!("http://{address}"),
            "OPENAI_API_KEY_BOUNDED_BODY_TEST",
        );
        openai_provider.request_timeout_ms = 1_000;
        let openai = OpenAiResponsesTransport::with_credentials(
            "secret-openai-bounded-body",
            None::<String>,
            None::<String>,
        )
        .unwrap();
        let openai_error = match openai
            .send(InferenceTransportRequest {
                provider: &openai_provider,
                request_body_json,
            })
            .await
        {
            Ok(_) => panic!("oversized OpenAI response must fail closed"),
            Err(error) => error,
        };
        assert_eq!(openai_error.kind, InferenceTransportFailureKind::Transport);
        assert_eq!(
            openai_error.message,
            format!("provider response body exceeds {MAX_PROVIDER_RESPONSE_BODY_BYTES} bytes")
        );

        let mut openrouter_provider = provider(
            InferenceProviderMode::OpenRouterChatCompletions,
            &format!("http://{address}/v1"),
            "OPENROUTER_API_KEY_BOUNDED_BODY_TEST",
        );
        openrouter_provider.request_timeout_ms = 1_000;
        let openrouter = OpenRouterChatCompletionsTransport::with_credentials(
            "secret-openrouter-bounded-body",
            None::<String>,
            None::<String>,
        )
        .unwrap();
        let openrouter_error = match openrouter
            .send(InferenceTransportRequest {
                provider: &openrouter_provider,
                request_body_json,
            })
            .await
        {
            Ok(_) => panic!("oversized OpenRouter response must fail closed"),
            Err(error) => error,
        };
        assert_eq!(
            openrouter_error.kind,
            InferenceTransportFailureKind::Transport
        );
        assert_eq!(
            openrouter_error.message,
            format!("provider response body exceeds {MAX_PROVIDER_RESPONSE_BODY_BYTES} bytes")
        );

        handle.abort();
    }

    #[tokio::test]
    async fn provider_latency_includes_reading_the_complete_streamed_body() {
        let first = br#"{"id":"resp_streamed","output":[]"#.to_vec();
        let second =
            br#", "usage":{"input_tokens":0,"output_tokens":0,"total_tokens":0}}"#.to_vec();
        let expected_body = [first.clone(), second.clone()].concat();
        let (address, handle) = spawn_streaming_mock_server(vec![first, second], 75).await;
        let mut provider = provider(
            InferenceProviderMode::OpenAiResponses,
            &format!("http://{address}"),
            "OPENAI_API_KEY_STREAM_LATENCY_TEST",
        );
        provider.request_timeout_ms = 1_000;
        let transport = OpenAiResponsesTransport::with_credentials(
            "secret-stream-latency",
            None::<String>,
            None::<String>,
        )
        .unwrap();

        let response = transport
            .send(InferenceTransportRequest {
                provider: &provider,
                request_body_json: "{}",
            })
            .await
            .expect("bounded streamed response must complete");

        assert_eq!(response.raw_response_body.as_bytes(), expected_body);
        assert!(
            response.latency_ms >= 50,
            "latency {} ms did not include the delayed body chunk",
            response.latency_ms
        );
        handle.abort();
    }

    #[test]
    fn provider_base_url_accepts_https_and_exact_loopback_http_hosts() {
        let https = parse_base_url("https://api.openai.com/v1").unwrap();
        assert_eq!(https.as_str(), "https://api.openai.com/v1/");

        for url in [
            "http://127.0.0.1:8080/v1",
            "http://127.0.0.2:8080/v1",
            "http://localhost:8080/v1",
            "http://LOCALHOST.:8080/v1",
            "http://[::1]:8080/v1",
        ] {
            let parsed = parse_base_url(url).unwrap();
            assert_eq!(parsed.scheme(), "http");
            assert!(parsed.path().ends_with('/'));
        }
    }

    #[test]
    fn provider_base_url_rejects_credentials_query_fragment_scheme_and_remote_http() {
        let invalid = [
            "https://operator:secret@example.com/v1",
            "https://example.com/v1?api_key=secret",
            "https://example.com/v1#secret",
            "ftp://example.com/v1",
            "http://example.com/v1",
        ];

        for raw in invalid {
            let error = parse_base_url(raw).unwrap_err();
            assert!(matches!(
                &error,
                InferenceAdapterError::InvalidApiBaseUrl { .. }
            ));
            let rendered = error.to_string();
            assert!(!rendered.contains("secret"));
            assert!(!rendered.contains("api_key"));
            assert!(!rendered.contains("operator"));
        }
    }

    #[test]
    fn provider_base_url_classifier_covers_the_complete_loopback_space() {
        for raw in [
            "https://127.0.0.1/v1",
            "https://127.0.0.2/v1",
            "https://127.255.255.254/v1",
            "https://localhost/v1",
            "https://LOCALHOST./v1",
            "https://[::1]/v1",
            "https://[::ffff:127.0.0.1]/v1",
            "https://[::ffff:127.0.0.2]/v1",
            "https://[::127.0.0.1]/v1",
        ] {
            let (_, loopback) = normalize_safe_provider_api_base_url(raw).unwrap();
            assert!(loopback, "{raw} must classify as LoopbackTest");
        }

        for raw in [
            "https://128.0.0.1/v1",
            "https://192.168.0.1/v1",
            "https://example.com/v1",
        ] {
            let (_, loopback) = normalize_safe_provider_api_base_url(raw).unwrap();
            assert!(!loopback, "{raw} must classify as ExternalHttps");
        }
    }

    #[test]
    fn provider_base_url_rejects_unspecified_ip_literals() {
        for raw in [
            "https://0.0.0.0/v1",
            "https://[::]/v1",
            "https://[::ffff:0.0.0.0]/v1",
        ] {
            let error = normalize_safe_provider_api_base_url(raw).unwrap_err();
            assert!(matches!(
                error,
                InferenceAdapterError::InvalidApiBaseUrl { .. }
            ));
        }
    }

    #[test]
    fn openai_usage_is_required_and_explicit_zero_is_not_missing() {
        assert_eq!(
            extract_usage(&json!({
                "usage": {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}
            })),
            Ok((0, 0))
        );
        assert_eq!(
            extract_usage(&json!({"output": []})),
            Err(InferenceAdapterError::MissingProviderUsage)
        );

        for invalid in [
            json!({"usage": null}),
            json!({"usage": {"input_tokens": 0, "total_tokens": 0}}),
            json!({"usage": {"input_tokens": "0", "output_tokens": 0, "total_tokens": 0}}),
            json!({"usage": {"input_tokens": 0, "output_tokens": 0}}),
            json!({"usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 1}}),
            json!({"usage": {"input_tokens": u64::MAX, "output_tokens": 1, "total_tokens": u64::MAX}}),
        ] {
            assert!(matches!(
                extract_usage(&invalid),
                Err(InferenceAdapterError::InvalidProviderUsage { .. })
            ));
        }
    }

    #[test]
    fn openrouter_usage_is_required_and_explicit_zero_is_not_missing() {
        for explicit_zero in [
            json!({
                "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
            }),
            json!({
                "usage": {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}
            }),
        ] {
            assert_eq!(extract_chat_completion_usage(&explicit_zero), Ok((0, 0)));
        }
        assert_eq!(
            extract_chat_completion_usage(&json!({"choices": []})),
            Err(InferenceAdapterError::MissingProviderUsage)
        );

        for invalid in [
            json!({"usage": []}),
            json!({"usage": {"prompt_tokens": 0, "total_tokens": 0}}),
            json!({"usage": {"prompt_tokens": -1, "completion_tokens": 0, "total_tokens": 0}}),
            json!({"usage": {"prompt_tokens": 0, "completion_tokens": 0}}),
            json!({"usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 3}}),
            json!({"usage": {"prompt_tokens": 1, "input_tokens": 2, "completion_tokens": 0, "total_tokens": 1}}),
            json!({"usage": {"prompt_tokens": u64::MAX, "completion_tokens": 1, "total_tokens": u64::MAX}}),
        ] {
            assert!(matches!(
                extract_chat_completion_usage(&invalid),
                Err(InferenceAdapterError::InvalidProviderUsage { .. })
            ));
        }
    }

    #[test]
    fn completed_outcomes_require_usage_while_noncompleted_outcomes_remain_governed() {
        for missing_usage in [
            extract_usage(&json!({"output": []})),
            extract_chat_completion_usage(&json!({"choices": []})),
        ] {
            assert_eq!(
                provider_usage_for_outcome(InferenceFinishReason::Completed, missing_usage),
                Err(InferenceAdapterError::MissingProviderUsage)
            );
        }
        for invalid_usage in [
            extract_usage(&json!({
                "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 3}
            })),
            extract_chat_completion_usage(&json!({
                "usage": {"prompt_tokens": "1", "completion_tokens": 1, "total_tokens": 2}
            })),
        ] {
            assert!(matches!(
                provider_usage_for_outcome(InferenceFinishReason::Completed, invalid_usage),
                Err(InferenceAdapterError::InvalidProviderUsage { .. })
            ));
        }

        for finish_reason in [
            InferenceFinishReason::ProviderError,
            InferenceFinishReason::Refused,
            InferenceFinishReason::MalformedOutput,
        ] {
            assert_eq!(
                provider_usage_for_outcome(
                    finish_reason,
                    Err(InferenceAdapterError::MissingProviderUsage),
                ),
                Ok((0, 0))
            );
        }
    }

    #[test]
    fn invalid_empty_ids_and_refs_fail_validation() {
        let mut invalid_provider = fixture_provider();
        invalid_provider.provider_id = " ".to_string();
        assert_eq!(
            invalid_provider.validate().unwrap_err(),
            InferenceAdapterError::MissingProviderId
        );

        let mut invalid_policy = generation_policy(0);
        invalid_policy.max_output_tokens = 0;
        assert_eq!(
            invalid_policy.validate().unwrap_err(),
            InferenceAdapterError::InvalidMaxOutputTokens
        );

        let mut invalid_prompt = rendered_prompt();
        invalid_prompt.prompt_text = "".to_string();
        assert_eq!(
            invalid_prompt.validate().unwrap_err(),
            InferenceAdapterError::MissingPromptText
        );
    }

    #[tokio::test]
    async fn completed_fixture_yields_result_without_degradation() {
        let bundle = execute_inference_turn_with_fixture(
            &fixture_provider(),
            &generation_policy(0),
            &request("provider:fixture", "model:test"),
            &rendered_prompt(),
            &tool_catalog(),
            &response_schema(),
            &completed_fixture(),
        )
        .await
        .unwrap();

        assert_eq!(
            bundle.turn_result.finish_reason,
            InferenceFinishReason::Completed
        );
        assert!(bundle.degradation_record.is_none());
        assert!(bundle.parsed_output.is_some());
        assert_eq!(bundle.request_body_records.len(), 1);
        assert_eq!(bundle.attempts.len(), 1);
    }

    #[tokio::test]
    async fn unsupported_model_fails_before_execution() {
        let error = execute_inference_turn_with_fixture(
            &fixture_provider(),
            &generation_policy(0),
            &request("provider:fixture", "model:other"),
            &rendered_prompt(),
            &tool_catalog(),
            &response_schema(),
            &completed_fixture(),
        )
        .await
        .unwrap_err();

        assert_eq!(
            error,
            InferenceAdapterError::UnsupportedModel {
                provider_id: "provider:fixture".to_string(),
                model_ref: "model:other".to_string(),
            }
        );
    }

    #[tokio::test]
    async fn disabled_provider_fails_before_execution() {
        let mut provider = fixture_provider();
        provider.provider_mode = InferenceProviderMode::Disabled;
        let error = execute_inference_turn_with_fixture(
            &provider,
            &generation_policy(0),
            &request("provider:fixture", "model:test"),
            &rendered_prompt(),
            &tool_catalog(),
            &response_schema(),
            &completed_fixture(),
        )
        .await
        .unwrap_err();

        assert_eq!(
            error,
            InferenceAdapterError::ProviderDisabled {
                provider_id: "provider:fixture".to_string(),
            }
        );
    }

    #[tokio::test]
    async fn successful_openai_turn_yields_parsed_output_and_accounting() {
        let (address, bodies, attempts, handle) = spawn_mock_server(MockBehavior::Success).await;

        let provider = provider(
            InferenceProviderMode::OpenAiResponses,
            &format!("http://{address}"),
            "OPENAI_API_KEY_SUCCESS_TEST",
        );
        let transport = OpenAiResponsesTransport::with_credentials(
            "secret-success",
            None::<String>,
            None::<String>,
        )
        .unwrap();
        let bundle = execute_openai_responses_turn(
            &provider,
            &generation_policy(0),
            &request(&provider.provider_id, "gpt-5.4-mini"),
            &rendered_prompt(),
            &tool_catalog(),
            &bare_response_schema(),
            &transport,
        )
        .await
        .unwrap();

        assert_eq!(
            bundle.turn_result.finish_reason,
            InferenceFinishReason::Completed
        );
        assert!(bundle.parsed_output.is_some());
        assert_eq!(
            serde_json::from_str::<Value>(
                &bundle
                    .parsed_output
                    .as_ref()
                    .unwrap()
                    .normalized_output_json
            )
            .unwrap(),
            json!({"turn_outcome": "proposals", "summary": "live ok"})
        );
        assert_eq!(
            bundle.provider_outcome.finish_reason,
            InferenceFinishReason::Completed
        );
        assert!(!bundle.turn_result.attempt_refs.is_empty());
        assert_eq!(bundle.usage_record.input_tokens, 120);
        assert_eq!(bundle.usage_record.output_tokens, 60);
        assert_eq!(
            bundle.usage_record.latency_ms,
            bundle.provider_outcome.latency_ms
        );
        assert!(bundle.usage_record.estimated_cost_microunits > 0);
        assert_eq!(attempts.load(Ordering::SeqCst), 1);

        let recorded_bodies = bodies.lock().await;
        assert_eq!(recorded_bodies.len(), 1);
        assert_eq!(
            recorded_bodies[0]["model"],
            Value::String("gpt-5.4-mini".to_string())
        );
        assert_eq!(
            recorded_bodies[0]["input"],
            Value::String("You are a bounded Wasm-Biotic runtime.".to_string())
        );
        assert_eq!(
            recorded_bodies[0]["tool_choice"],
            Value::String("auto".to_string())
        );
        assert_eq!(
            recorded_bodies[0]["tools"][0]["name"],
            Value::String("continuity.retrieve".to_string())
        );
        assert_eq!(
            recorded_bodies[0]["text"]["format"]["type"],
            Value::String("json_schema".to_string())
        );
        assert_eq!(
            recorded_bodies[0]["text"]["format"]["name"],
            Value::String("schema_turn_1".to_string())
        );
        assert_eq!(
            recorded_bodies[0]["text"]["format"]["strict"],
            Value::Bool(true)
        );
        assert_eq!(
            recorded_bodies[0]["text"]["format"]["schema"]["type"],
            Value::String("object".to_string())
        );
        assert!(
            recorded_bodies[0]["text"]["format"]
                .get("json_schema")
                .is_none()
        );

        handle.abort();
    }

    #[tokio::test]
    async fn openai_function_call_arguments_are_normalized_from_realistic_envelope() {
        let (address, _, attempts, handle) = spawn_mock_server(MockBehavior::ToolCall).await;
        let provider = provider(
            InferenceProviderMode::OpenAiResponses,
            &format!("http://{address}"),
            "OPENAI_API_KEY_TOOL_CALL_TEST",
        );
        let transport = OpenAiResponsesTransport::with_credentials(
            "secret-tool-call",
            None::<String>,
            None::<String>,
        )
        .unwrap();

        let bundle = execute_openai_responses_turn(
            &provider,
            &generation_policy(0),
            &request(&provider.provider_id, "gpt-5.4-mini"),
            &rendered_prompt(),
            &tool_catalog(),
            &response_schema(),
            &transport,
        )
        .await
        .unwrap();

        assert_eq!(
            bundle.turn_result.finish_reason,
            InferenceFinishReason::Completed
        );
        assert_eq!(
            serde_json::from_str::<Value>(
                &bundle
                    .parsed_output
                    .as_ref()
                    .unwrap()
                    .normalized_output_json
            )
            .unwrap(),
            json!({"continuity_key": "bounded"})
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 1);

        handle.abort();
    }

    #[test]
    fn openai_legacy_output_parsed_and_wrapped_schema_remain_compatible() {
        let provider = provider(
            InferenceProviderMode::OpenAiResponses,
            "http://127.0.0.1:1",
            "OPENAI_API_KEY_COMPATIBILITY_TEST",
        );
        let body = build_request_body_json(
            &provider,
            &request(&provider.provider_id, "gpt-5.4-mini"),
            &generation_policy(0),
            &rendered_prompt(),
            &tool_catalog(),
            &response_schema(),
        )
        .unwrap();
        let body: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            body["text"]["format"],
            json!({
                "type": "json_schema",
                "name": "turn_result",
                "strict": true,
                "schema": {
                    "type": "object",
                    "properties": {"turn_outcome": {"type": "string"}},
                    "required": ["turn_outcome"],
                    "additionalProperties": false
                }
            })
        );
        assert_eq!(
            extract_normalized_openai_output(
                &json!({
                    "output_parsed": {"turn_outcome": "legacy"}
                }),
                &BTreeSet::from(["continuity.retrieve".to_string()]),
                None,
            ),
            Some(json!({"turn_outcome": "legacy"}).to_string())
        );
    }

    #[test]
    fn required_function_builders_force_the_exact_provider_choice() {
        let required_function_name = "candidate.materialize_patchset";
        let required_tool_catalog = InferenceToolCatalogPayloadRecord {
            tool_catalog_json: json!([{
                "type": "function",
                "name": required_function_name,
                "parameters": {
                    "type": "object",
                    "additionalProperties": false
                }
            }])
            .to_string(),
            ..tool_catalog()
        };
        let openai = provider(
            InferenceProviderMode::OpenAiResponses,
            "http://127.0.0.1:1",
            "OPENAI_API_KEY_REQUIRED_TOOL_TEST",
        );
        let openai_body = build_request_body_json_with_required_function(
            &openai,
            &request(&openai.provider_id, "gpt-5.4-mini"),
            &generation_policy(0),
            &rendered_prompt(),
            &required_tool_catalog,
            &response_schema(),
            Some(required_function_name),
        )
        .expect("required OpenAI function request");
        let openai_body: Value = serde_json::from_str(&openai_body).expect("OpenAI request JSON");
        assert_eq!(
            openai_body["tool_choice"],
            json!({"type": "function", "name": required_function_name})
        );

        let openrouter = provider(
            InferenceProviderMode::OpenRouterChatCompletions,
            "http://127.0.0.1:1",
            "OPENROUTER_API_KEY_REQUIRED_TOOL_TEST",
        );
        let openrouter_body = build_request_body_json_with_required_function(
            &openrouter,
            &request(&openrouter.provider_id, "gpt-5.4-mini"),
            &generation_policy(0),
            &rendered_prompt(),
            &required_tool_catalog,
            &response_schema(),
            Some(required_function_name),
        )
        .expect("required OpenRouter function request");
        let openrouter_body: Value =
            serde_json::from_str(&openrouter_body).expect("OpenRouter request JSON");
        assert_eq!(
            openrouter_body["tool_choice"],
            json!({
                "type": "function",
                "function": {"name": required_function_name}
            })
        );
        assert_eq!(openrouter_body["parallel_tool_calls"], Value::Bool(false));

        assert!(matches!(
            build_request_body_json_with_required_function(
                &openai,
                &request(&openai.provider_id, "gpt-5.4-mini"),
                &generation_policy(0),
                &rendered_prompt(),
                &required_tool_catalog,
                &response_schema(),
                Some("continuity.unexposed"),
            ),
            Err(InferenceAdapterError::RequiredFunctionToolUnavailable {
                required_function_name
            }) if required_function_name == "continuity.unexposed"
        ));
    }

    #[tokio::test]
    async fn required_openai_function_rejects_no_call_structured_output() {
        let (address, _, _, handle) = spawn_mock_server(MockBehavior::Success).await;
        let provider = provider(
            InferenceProviderMode::OpenAiResponses,
            &format!("http://{address}"),
            "OPENAI_API_KEY_REQUIRED_NO_CALL_TEST",
        );
        let transport = OpenAiResponsesTransport::with_credentials(
            "secret-required-no-call",
            None::<String>,
            None::<String>,
        )
        .expect("required OpenAI transport");
        let bundle = execute_openai_responses_turn_with_required_function(
            &provider,
            &generation_policy(0),
            &request(&provider.provider_id, "gpt-5.4-mini"),
            &rendered_prompt(),
            &tool_catalog(),
            &response_schema(),
            &transport,
            Some("continuity.retrieve"),
        )
        .await
        .expect("governed malformed OpenAI outcome");

        assert_eq!(
            bundle.turn_result.finish_reason,
            InferenceFinishReason::MalformedOutput
        );
        assert!(bundle.parsed_output.is_none());
        handle.abort();
    }

    #[tokio::test]
    async fn required_openrouter_function_rejects_no_call_structured_output() {
        let (address, _, _, handle) = spawn_mock_server(MockBehavior::Success).await;
        let provider = provider(
            InferenceProviderMode::OpenRouterChatCompletions,
            &format!("http://{address}/v1"),
            "OPENROUTER_API_KEY_REQUIRED_NO_CALL_TEST",
        );
        let transport = OpenRouterChatCompletionsTransport::with_credentials(
            "secret-required-no-call",
            None::<String>,
            None::<String>,
        )
        .expect("required OpenRouter transport");
        let bundle = execute_openrouter_chat_completions_turn_with_required_function(
            &provider,
            &generation_policy(0),
            &request(&provider.provider_id, "gpt-5.4-mini"),
            &rendered_prompt(),
            &tool_catalog(),
            &response_schema(),
            &transport,
            Some("continuity.retrieve"),
        )
        .await
        .expect("governed malformed OpenRouter outcome");

        assert_eq!(
            bundle.turn_result.finish_reason,
            InferenceFinishReason::MalformedOutput
        );
        assert!(bundle.parsed_output.is_none());
        handle.abort();
    }

    #[test]
    fn provider_tool_call_envelopes_require_one_exposed_function_name() {
        let exposed_names = BTreeSet::from([
            "continuity.replace".to_string(),
            "continuity.retrieve".to_string(),
        ]);
        assert_eq!(
            exposed_function_tool_names(
                &json!({
                    "tools": [
                        {"type": "function", "name": "continuity.retrieve"},
                        {
                            "type": "function",
                            "function": {"name": "continuity.replace"}
                        }
                    ]
                })
                .to_string(),
            ),
            exposed_names
        );

        let expected_arguments = Some(json!({"continuity_key": "bounded"}).to_string());
        let openai_call = json!({
            "output": [{
                "type": "function_call",
                "status": "completed",
                "name": "continuity.retrieve",
                "arguments": "{\"continuity_key\":\"bounded\"}"
            }]
        });
        assert_eq!(
            extract_normalized_openai_output(
                &openai_call,
                &exposed_names,
                Some("continuity.retrieve"),
            ),
            expected_arguments
        );
        assert_eq!(
            extract_normalized_openai_output(
                &openai_call,
                &BTreeSet::from(["continuity.replace".to_string()]),
                Some("continuity.retrieve"),
            ),
            None
        );
        assert_eq!(
            extract_normalized_openai_output(
                &json!({
                    "output": [
                        {
                            "type": "function_call",
                            "status": "completed",
                            "name": "continuity.retrieve",
                            "arguments": "{}"
                        },
                        {
                            "type": "computer_call",
                            "id": "computer_1"
                        }
                    ]
                }),
                &exposed_names,
                Some("continuity.retrieve"),
            ),
            None
        );
        assert_eq!(
            extract_normalized_openai_output(
                &json!({
                    "output": [
                        {
                            "type": "function_call",
                            "status": "completed",
                            "name": "continuity.retrieve",
                            "arguments": "{}"
                        },
                        {
                            "type": "function_call",
                            "status": "completed",
                            "name": "continuity.retrieve",
                            "arguments": "{}"
                        }
                    ]
                }),
                &exposed_names,
                Some("continuity.retrieve"),
            ),
            None
        );
        assert_eq!(
            extract_normalized_openai_output(
                &json!({
                    "output_parsed": {"continuity_key": "structured-fallback"}
                }),
                &exposed_names,
                Some("continuity.retrieve"),
            ),
            None
        );

        let openrouter_call = json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "tool_calls": [{
                        "type": "function",
                        "function": {
                            "name": "continuity.retrieve",
                            "arguments": "{\"continuity_key\":\"bounded\"}"
                        }
                    }]
                },
                "finish_reason": "tool_calls"
            }]
        });
        assert_eq!(
            extract_normalized_openrouter_output(
                &openrouter_call,
                &exposed_names,
                Some("continuity.retrieve"),
            ),
            Some(json!({"continuity_key": "bounded"}).to_string())
        );
        for role in [Value::Null, json!("user"), json!("system"), json!("tool")] {
            let mut invalid = openrouter_call.clone();
            if role.is_null() {
                invalid["choices"][0]["message"]
                    .as_object_mut()
                    .expect("message object")
                    .remove("role");
            } else {
                invalid["choices"][0]["message"]["role"] = role;
            }
            assert_eq!(
                extract_normalized_openrouter_output(
                    &invalid,
                    &exposed_names,
                    Some("continuity.retrieve"),
                ),
                None
            );
        }
        let mut error_with_call = openrouter_call.clone();
        error_with_call["error"] = json!({"message": "contradictory success"});
        assert_eq!(
            extract_normalized_openrouter_output(
                &error_with_call,
                &exposed_names,
                Some("continuity.retrieve"),
            ),
            None
        );
        let mut refusal_with_call = openrouter_call.clone();
        refusal_with_call["choices"][0]["message"]["refusal"] =
            Value::String("refused".to_string());
        assert_eq!(
            extract_normalized_openrouter_output(
                &refusal_with_call,
                &exposed_names,
                Some("continuity.retrieve"),
            ),
            None
        );
        assert_eq!(
            extract_normalized_openrouter_output(
                &openrouter_call,
                &BTreeSet::from(["continuity.replace".to_string()]),
                Some("continuity.retrieve"),
            ),
            None
        );
        assert_eq!(
            extract_normalized_openrouter_output(
                &json!({
                    "choices": [{
                        "message": {
                            "tool_calls": [{
                                "type": "function",
                                "function": {
                                    "name": "continuity.retrieve",
                                    "arguments": "{}"
                                }
                            }]
                        },
                        "finish_reason": "stop"
                    }]
                }),
                &exposed_names,
                Some("continuity.retrieve"),
            ),
            None
        );
        assert_eq!(
            extract_normalized_openrouter_output(
                &json!({
                    "choices": [{
                        "message": {
                            "function_call": {
                                "name": "continuity.retrieve",
                                "arguments": "{}"
                            }
                        },
                        "finish_reason": "tool_calls"
                    }]
                }),
                &exposed_names,
                Some("continuity.retrieve"),
            ),
            None
        );
        assert_eq!(
            extract_normalized_openrouter_output(
                &json!({
                    "choices": [{
                        "message": {
                            "tool_calls": [
                                {
                                    "type": "function",
                                    "function": {
                                        "name": "continuity.retrieve",
                                        "arguments": "{}"
                                    }
                                },
                                {
                                    "type": "function",
                                    "function": {
                                        "name": "continuity.retrieve",
                                        "arguments": "{}"
                                    }
                                }
                            ]
                        }
                    }]
                }),
                &exposed_names,
                Some("continuity.retrieve"),
            ),
            None
        );
        assert_eq!(
            extract_normalized_openrouter_output(
                &json!({
                    "choices": [
                        {
                            "message": {
                                "tool_calls": [{
                                    "type": "function",
                                    "function": {
                                        "name": "continuity.retrieve",
                                        "arguments": "{}"
                                    }
                                }]
                            }
                        },
                        {
                            "message": {
                                "tool_calls": [{
                                    "type": "function",
                                    "function": {
                                        "name": "continuity.replace",
                                        "arguments": "{}"
                                    }
                                }]
                            }
                        }
                    ]
                }),
                &exposed_names,
                Some("continuity.retrieve"),
            ),
            None
        );
        assert_eq!(
            extract_normalized_openrouter_output(
                &json!({
                    "choices": [{
                        "message": {
                            "function_call": {
                                "name": "continuity.replace",
                                "arguments": "{}"
                            }
                        }
                    }]
                }),
                &BTreeSet::from(["continuity.retrieve".to_string()]),
                Some("continuity.retrieve"),
            ),
            None
        );
        assert_eq!(
            extract_normalized_openrouter_output(
                &json!({
                    "choices": [{
                        "message": {
                            "content": "{\"continuity_key\":\"structured-fallback\"}"
                        }
                    }]
                }),
                &exposed_names,
                Some("continuity.retrieve"),
            ),
            None
        );
    }

    #[test]
    fn required_openai_function_requires_completed_envelope_and_call_status() {
        let provider = provider(
            InferenceProviderMode::OpenAiResponses,
            "http://127.0.0.1:1",
            "OPENAI_API_KEY_REQUIRED_STATUS_TEST",
        );
        let request = request(&provider.provider_id, "gpt-5.4-mini");
        let exposed = BTreeSet::from(["continuity.retrieve".to_string()]);
        let attempts = vec![InferenceAttemptRecord {
            attempt_id: "attempt:required-status".to_string(),
            turn_request_ref: request.turn_request_id.clone(),
            attempt_number: 1,
            request_body_ref: "request-body:required-status".to_string(),
            raw_response_body_ref: "raw-output:required-status".to_string(),
            http_status: Some(200),
            latency_ms: 1,
            retry_classification: InferenceRetryClassification::NoRetryNeeded,
            provider_response_id: None,
            provider_request_id: None,
            transport_error_summary: None,
            created_at: "test-time".to_string(),
        }];
        let valid = json!({
            "id": "resp_required_status",
            "status": "completed",
            "error": null,
            "incomplete_details": null,
            "output": [{
                "type": "function_call",
                "status": "completed",
                "name": "continuity.retrieve",
                "arguments": "{\"continuity_key\":\"bounded\"}"
            }],
            "usage": {"input_tokens": 2, "output_tokens": 1, "total_tokens": 3}
        });
        let parse = |envelope: &Value| {
            parse_openai_responses_envelope(
                &envelope.to_string(),
                &provider,
                &request,
                &provider.models[0],
                &exposed,
                Some("continuity.retrieve"),
                Some(200),
                None,
                None,
                1,
                &attempts,
                "test-time",
            )
            .expect("parse bounded OpenAI envelope")
        };
        assert_eq!(
            parse(&valid).finish_reason,
            InferenceFinishReason::Completed
        );

        let mut missing_status = valid.clone();
        missing_status
            .as_object_mut()
            .expect("response object")
            .remove("status");
        let mut incomplete = valid.clone();
        incomplete["status"] = Value::String("incomplete".to_string());
        incomplete["incomplete_details"] = json!({"reason": "max_output_tokens"});
        let mut in_progress = valid.clone();
        in_progress["status"] = Value::String("in_progress".to_string());
        let mut provider_error = valid.clone();
        provider_error["error"] = json!({"code": "provider_error"});
        let mut item_in_progress = valid.clone();
        item_in_progress["output"][0]["status"] = Value::String("in_progress".to_string());
        let mut missing_item_status = valid;
        missing_item_status["output"][0]
            .as_object_mut()
            .expect("function call object")
            .remove("status");

        for invalid in [
            missing_status,
            incomplete,
            in_progress,
            provider_error,
            item_in_progress,
            missing_item_status,
        ] {
            let outcome = parse(&invalid);
            assert_ne!(outcome.finish_reason, InferenceFinishReason::Completed);
            assert!(outcome.parsed_output.is_none());
        }
    }

    #[test]
    fn required_openrouter_function_rejects_contradictory_envelopes() {
        let provider = provider(
            InferenceProviderMode::OpenRouterChatCompletions,
            "http://127.0.0.1:1/v1",
            "OPENROUTER_API_KEY_REQUIRED_ENVELOPE_TEST",
        );
        let request = request(&provider.provider_id, "gpt-5.4-mini");
        let exposed = BTreeSet::from(["continuity.retrieve".to_string()]);
        let attempts = vec![InferenceAttemptRecord {
            attempt_id: "attempt:required-openrouter-envelope".to_string(),
            turn_request_ref: request.turn_request_id.clone(),
            attempt_number: 1,
            request_body_ref: "request-body:required-openrouter-envelope".to_string(),
            raw_response_body_ref: "raw-output:required-openrouter-envelope".to_string(),
            http_status: Some(200),
            latency_ms: 1,
            retry_classification: InferenceRetryClassification::NoRetryNeeded,
            provider_response_id: None,
            provider_request_id: None,
            transport_error_summary: None,
            created_at: "test-time".to_string(),
        }];
        let valid = json!({
            "id": "chatcmpl_required_envelope",
            "error": null,
            "choices": [{
                "finish_reason": "tool_calls",
                "message": {
                    "role": "assistant",
                    "refusal": null,
                    "tool_calls": [{
                        "type": "function",
                        "function": {
                            "name": "continuity.retrieve",
                            "arguments": "{\"continuity_key\":\"bounded\"}"
                        }
                    }]
                }
            }],
            "usage": {"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3}
        });
        let parse = |envelope: &Value| {
            parse_openrouter_chat_completions_envelope(
                &envelope.to_string(),
                &provider,
                &request,
                &provider.models[0],
                &exposed,
                Some("continuity.retrieve"),
                Some(200),
                None,
                None,
                1,
                &attempts,
                "test-time",
            )
            .expect("parse bounded OpenRouter envelope")
        };
        assert_eq!(
            parse(&valid).finish_reason,
            InferenceFinishReason::Completed
        );

        let mut provider_error = valid.clone();
        provider_error["error"] = json!({"code": "provider_error"});
        let mut missing_role = valid.clone();
        missing_role["choices"][0]["message"]
            .as_object_mut()
            .expect("message object")
            .remove("role");
        let mut user_role = valid.clone();
        user_role["choices"][0]["message"]["role"] = Value::String("user".to_string());
        let mut system_role = valid.clone();
        system_role["choices"][0]["message"]["role"] = Value::String("system".to_string());
        let mut tool_role = valid.clone();
        tool_role["choices"][0]["message"]["role"] = Value::String("tool".to_string());
        let mut refusal = valid;
        refusal["choices"][0]["message"]["refusal"] = Value::String("cannot comply".to_string());

        for invalid in [
            provider_error,
            missing_role,
            user_role,
            system_role,
            tool_role,
            refusal,
        ] {
            let outcome = parse(&invalid);
            assert_ne!(outcome.finish_reason, InferenceFinishReason::Completed);
            assert!(outcome.parsed_output.is_none());
        }
    }

    #[tokio::test]
    async fn timeout_path_retries_and_exhausts() {
        let (address, _, attempts, handle) = spawn_mock_server(MockBehavior::Timeout).await;

        let mut provider = provider(
            InferenceProviderMode::OpenAiResponses,
            &format!("http://{address}"),
            "OPENAI_API_KEY_TIMEOUT_TEST",
        );
        provider.request_timeout_ms = 10;
        let transport = OpenAiResponsesTransport::with_credentials(
            "secret-timeout",
            None::<String>,
            None::<String>,
        )
        .unwrap();
        let bundle = execute_openai_responses_turn(
            &provider,
            &generation_policy(2),
            &request(&provider.provider_id, "gpt-5.4-mini"),
            &rendered_prompt(),
            &tool_catalog(),
            &response_schema(),
            &transport,
        )
        .await
        .unwrap();

        assert_eq!(
            bundle.turn_result.finish_reason,
            InferenceFinishReason::TimedOut
        );
        assert_eq!(bundle.attempts.len(), 3);
        assert_eq!(
            bundle.attempts[0].retry_classification,
            InferenceRetryClassification::RetriedTimeout
        );
        assert_eq!(
            bundle.attempts[2].retry_classification,
            InferenceRetryClassification::ExhaustedTimeout
        );
        assert!(bundle.degradation_record.is_some());
        assert_eq!(attempts.load(Ordering::SeqCst), 3);

        handle.abort();
    }

    #[tokio::test]
    async fn server_error_path_retries_and_exhausts() {
        let (address, _, attempts, handle) = spawn_mock_server(MockBehavior::ServerError).await;

        let provider = provider(
            InferenceProviderMode::OpenAiResponses,
            &format!("http://{address}"),
            "OPENAI_API_KEY_SERVER_TEST",
        );
        let transport = OpenAiResponsesTransport::with_credentials(
            "secret-server",
            None::<String>,
            None::<String>,
        )
        .unwrap();
        let bundle = execute_openai_responses_turn(
            &provider,
            &generation_policy(1),
            &request(&provider.provider_id, "gpt-5.4-mini"),
            &rendered_prompt(),
            &tool_catalog(),
            &response_schema(),
            &transport,
        )
        .await
        .unwrap();

        assert_eq!(
            bundle.turn_result.finish_reason,
            InferenceFinishReason::ProviderError
        );
        assert_eq!(bundle.attempts.len(), 2);
        assert_eq!(bundle.usage_record.total_tokens, 0);
        assert_eq!(
            bundle.attempts[0].retry_classification,
            InferenceRetryClassification::RetriedServerError
        );
        assert_eq!(
            bundle.attempts[1].retry_classification,
            InferenceRetryClassification::ExhaustedServerError
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 2);

        handle.abort();
    }

    #[tokio::test]
    async fn rate_limited_path_retries_and_exhausts() {
        let (address, _, attempts, handle) = spawn_mock_server(MockBehavior::RateLimited).await;

        let provider = provider(
            InferenceProviderMode::OpenAiResponses,
            &format!("http://{address}"),
            "OPENAI_API_KEY_429_TEST",
        );
        let transport = OpenAiResponsesTransport::with_credentials(
            "secret-429",
            None::<String>,
            None::<String>,
        )
        .unwrap();
        let bundle = execute_openai_responses_turn(
            &provider,
            &generation_policy(1),
            &request(&provider.provider_id, "gpt-5.4-mini"),
            &rendered_prompt(),
            &tool_catalog(),
            &response_schema(),
            &transport,
        )
        .await
        .unwrap();

        assert_eq!(
            bundle.turn_result.finish_reason,
            InferenceFinishReason::ProviderError
        );
        assert_eq!(
            bundle.attempts[0].retry_classification,
            InferenceRetryClassification::RetriedRateLimited
        );
        assert_eq!(
            bundle.attempts[1].retry_classification,
            InferenceRetryClassification::ExhaustedRateLimited
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 2);

        handle.abort();
    }

    #[tokio::test]
    async fn client_error_does_not_retry() {
        let (address, _, attempts, handle) = spawn_mock_server(MockBehavior::ClientError).await;

        let provider = provider(
            InferenceProviderMode::OpenAiResponses,
            &format!("http://{address}"),
            "OPENAI_API_KEY_CLIENT_TEST",
        );
        let transport = OpenAiResponsesTransport::with_credentials(
            "secret-client",
            None::<String>,
            None::<String>,
        )
        .unwrap();
        let bundle = execute_openai_responses_turn(
            &provider,
            &generation_policy(3),
            &request(&provider.provider_id, "gpt-5.4-mini"),
            &rendered_prompt(),
            &tool_catalog(),
            &response_schema(),
            &transport,
        )
        .await
        .unwrap();

        assert_eq!(
            bundle.turn_result.finish_reason,
            InferenceFinishReason::ProviderError
        );
        assert_eq!(bundle.attempts.len(), 1);
        assert_eq!(
            bundle.attempts[0].retry_classification,
            InferenceRetryClassification::NonRetryableClientError
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 1);

        handle.abort();
    }

    #[tokio::test]
    async fn malformed_response_yields_malformed_output() {
        let (address, _, attempts, handle) = spawn_mock_server(MockBehavior::Malformed).await;

        let provider = provider(
            InferenceProviderMode::OpenAiResponses,
            &format!("http://{address}"),
            "OPENAI_API_KEY_MALFORMED_TEST",
        );
        let transport = OpenAiResponsesTransport::with_credentials(
            "secret-malformed",
            None::<String>,
            None::<String>,
        )
        .unwrap();
        let bundle = execute_openai_responses_turn(
            &provider,
            &generation_policy(0),
            &request(&provider.provider_id, "gpt-5.4-mini"),
            &rendered_prompt(),
            &tool_catalog(),
            &response_schema(),
            &transport,
        )
        .await
        .unwrap();

        assert_eq!(
            bundle.turn_result.finish_reason,
            InferenceFinishReason::MalformedOutput
        );
        assert!(bundle.degradation_record.is_some());
        assert_eq!(attempts.load(Ordering::SeqCst), 1);

        handle.abort();
    }

    #[tokio::test]
    async fn refusal_response_yields_refused() {
        let (address, _, attempts, handle) = spawn_mock_server(MockBehavior::Refusal).await;

        let provider = provider(
            InferenceProviderMode::OpenAiResponses,
            &format!("http://{address}"),
            "OPENAI_API_KEY_REFUSAL_TEST",
        );
        let transport = OpenAiResponsesTransport::with_credentials(
            "secret-refusal",
            None::<String>,
            None::<String>,
        )
        .unwrap();
        let bundle = execute_openai_responses_turn(
            &provider,
            &generation_policy(0),
            &request(&provider.provider_id, "gpt-5.4-mini"),
            &rendered_prompt(),
            &tool_catalog(),
            &response_schema(),
            &transport,
        )
        .await
        .unwrap();

        assert_eq!(
            bundle.turn_result.finish_reason,
            InferenceFinishReason::Refused
        );
        assert!(bundle.parsed_output.is_none());
        assert!(bundle.degradation_record.is_none());
        assert_eq!(bundle.usage_record.total_tokens, 0);
        assert_eq!(attempts.load(Ordering::SeqCst), 1);

        handle.abort();
    }

    #[tokio::test]
    async fn persisted_artifacts_never_store_resolved_authorization_value() {
        let (address, _, _, handle) = spawn_mock_server(MockBehavior::Success).await;
        let secret = "super-secret-runtime-token";

        let provider = provider(
            InferenceProviderMode::OpenAiResponses,
            &format!("http://{address}"),
            "OPENAI_API_KEY_PERSISTENCE_TEST",
        );
        let transport =
            OpenAiResponsesTransport::with_credentials(secret, None::<String>, None::<String>)
                .unwrap();
        let bundle = execute_openai_responses_turn(
            &provider,
            &generation_policy(0),
            &request(&provider.provider_id, "gpt-5.4-mini"),
            &rendered_prompt(),
            &tool_catalog(),
            &response_schema(),
            &transport,
        )
        .await
        .unwrap();

        let temp_root =
            std::env::temp_dir().join(format!("aiaf-inference-secret-{}", current_timestamp()));
        let raw = serde_json::to_string(&bundle).unwrap();
        fs::write(&temp_root, &raw).unwrap();
        let persisted = fs::read_to_string(&temp_root).unwrap();
        assert!(!persisted.contains(secret));
        assert!(!persisted.to_ascii_lowercase().contains("authorization"));

        let _ = fs::remove_file(Path::new(&temp_root));
        handle.abort();
    }

    #[tokio::test]
    async fn persisted_transport_failure_redacts_untrusted_error_details() {
        let secret = "operator-secret-in-untrusted-transport-error";
        let provider = provider(
            InferenceProviderMode::OpenAiResponses,
            "https://provider.invalid",
            "OPENAI_API_KEY_REDACTED_ERROR_TEST",
        );
        let transport = SecretBearingFailureTransport {
            secret: secret.to_string(),
        };

        let bundle = execute_openai_responses_turn(
            &provider,
            &generation_policy(0),
            &request(&provider.provider_id, "gpt-5.4-mini"),
            &rendered_prompt(),
            &tool_catalog(),
            &response_schema(),
            &transport,
        )
        .await
        .unwrap();

        let persisted = serde_json::to_string(&bundle).unwrap();
        assert!(!persisted.contains(secret));
        assert!(!persisted.contains("api_key="));
        assert!(!persisted.contains("operator:"));
        assert_eq!(
            bundle.attempts[0].transport_error_summary.as_deref(),
            Some("provider transport failed before a complete response was available")
        );
        assert_eq!(
            bundle
                .degradation_record
                .as_ref()
                .map(|record| record.summary.as_str()),
            Some("provider transport failed before a complete response was available")
        );
    }

    #[tokio::test]
    async fn successful_openrouter_turn_normalizes_json_content_and_chat_envelopes() {
        let (address, bodies, attempts, handle) = spawn_mock_server(MockBehavior::Success).await;

        let provider = provider(
            InferenceProviderMode::OpenRouterChatCompletions,
            &format!("http://{address}/v1"),
            "OPENROUTER_API_KEY_SUCCESS_TEST",
        );
        let transport = OpenRouterChatCompletionsTransport::with_credentials(
            "secret-openrouter-success",
            None::<String>,
            None::<String>,
        )
        .unwrap();
        let bundle = execute_openrouter_chat_completions_turn(
            &provider,
            &generation_policy(0),
            &request(&provider.provider_id, "gpt-5.4-mini"),
            &rendered_prompt(),
            &tool_catalog(),
            &response_schema(),
            &transport,
        )
        .await
        .unwrap();

        assert_eq!(
            bundle.turn_result.finish_reason,
            InferenceFinishReason::Completed
        );
        assert!(bundle.parsed_output.is_some());
        assert_eq!(bundle.usage_record.input_tokens, 120);
        assert_eq!(bundle.usage_record.output_tokens, 60);
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert_eq!(
            serde_json::from_str::<Value>(
                &bundle
                    .parsed_output
                    .as_ref()
                    .unwrap()
                    .normalized_output_json
            )
            .unwrap(),
            json!({"turn_outcome": "proposals", "summary": "live ok"})
        );

        let recorded_bodies = bodies.lock().await;
        assert_eq!(recorded_bodies.len(), 1);
        assert_eq!(
            recorded_bodies[0]["model"],
            Value::String("gpt-5.4-mini".to_string())
        );
        assert_eq!(
            recorded_bodies[0]["messages"][0]["role"],
            Value::String("user".to_string())
        );
        assert_eq!(
            recorded_bodies[0]["messages"][0]["content"],
            Value::String("You are a bounded Wasm-Biotic runtime.".to_string())
        );
        assert_eq!(
            recorded_bodies[0]["tool_choice"],
            Value::String("auto".to_string())
        );
        assert_eq!(
            recorded_bodies[0]["max_tokens"].as_u64(),
            Some(generation_policy(0).max_output_tokens as u64)
        );
        assert_eq!(
            recorded_bodies[0]["tools"][0]["type"],
            Value::String("function".to_string())
        );
        assert_eq!(
            recorded_bodies[0]["tools"][0]["function"]["name"],
            Value::String("continuity.retrieve".to_string())
        );
        assert!(recorded_bodies[0]["tools"][0].get("name").is_none());
        assert_eq!(
            recorded_bodies[0]["response_format"]["type"],
            Value::String("json_schema".to_string())
        );
        assert_eq!(
            recorded_bodies[0]["response_format"]["json_schema"]["name"],
            Value::String("turn_result".to_string())
        );
        assert_eq!(
            recorded_bodies[0]["response_format"]["json_schema"]["schema"]["type"],
            Value::String("object".to_string())
        );
        assert!(recorded_bodies[0].get("text").is_none());

        handle.abort();
    }

    #[tokio::test]
    async fn openrouter_tool_call_arguments_are_normalized() {
        let (address, bodies, attempts, handle) = spawn_mock_server(MockBehavior::ToolCall).await;
        let provider = provider(
            InferenceProviderMode::OpenRouterChatCompletions,
            &format!("http://{address}/v1"),
            "OPENROUTER_API_KEY_TOOL_CALL_TEST",
        );
        let transport = OpenRouterChatCompletionsTransport::with_credentials(
            "secret-openrouter-tool-call",
            None::<String>,
            None::<String>,
        )
        .unwrap();

        let bundle = execute_openrouter_chat_completions_turn(
            &provider,
            &generation_policy(0),
            &request(&provider.provider_id, "gpt-5.4-mini"),
            &rendered_prompt(),
            &tool_catalog(),
            &bare_response_schema(),
            &transport,
        )
        .await
        .unwrap();

        assert_eq!(
            bundle.turn_result.finish_reason,
            InferenceFinishReason::Completed
        );
        assert_eq!(
            serde_json::from_str::<Value>(
                &bundle
                    .parsed_output
                    .as_ref()
                    .unwrap()
                    .normalized_output_json
            )
            .unwrap(),
            json!({"continuity_key": "bounded"})
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        let recorded_bodies = bodies.lock().await;
        assert_eq!(
            recorded_bodies[0]["response_format"]["json_schema"]["name"],
            Value::String("schema_turn_1".to_string())
        );

        handle.abort();
    }

    #[tokio::test]
    async fn openrouter_plain_content_preserves_generic_string_output() {
        let (address, _, attempts, handle) = spawn_mock_server(MockBehavior::PlainContent).await;
        let provider = provider(
            InferenceProviderMode::OpenRouterChatCompletions,
            &format!("http://{address}/v1"),
            "OPENROUTER_API_KEY_PLAIN_TEST",
        );
        let transport = OpenRouterChatCompletionsTransport::with_credentials(
            "secret-openrouter-plain",
            None::<String>,
            None::<String>,
        )
        .unwrap();

        let bundle = execute_openrouter_chat_completions_turn(
            &provider,
            &generation_policy(0),
            &request(&provider.provider_id, "gpt-5.4-mini"),
            &rendered_prompt(),
            &tool_catalog(),
            &response_schema(),
            &transport,
        )
        .await
        .unwrap();

        assert_eq!(
            bundle
                .parsed_output
                .as_ref()
                .unwrap()
                .normalized_output_json,
            Value::String("plain assistant response".to_string()).to_string()
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 1);

        handle.abort();
    }

    #[test]
    fn openrouter_nested_function_tool_and_chat_schema_remain_compatible() {
        let provider = provider(
            InferenceProviderMode::OpenRouterChatCompletions,
            "http://127.0.0.1:1/v1",
            "OPENROUTER_API_KEY_COMPATIBILITY_TEST",
        );
        let nested_tools = InferenceToolCatalogPayloadRecord {
            tool_catalog_json: json!([{
                "type": "function",
                "function": {
                    "name": "continuity.retrieve",
                    "description": "retrieve continuity",
                    "parameters": {
                        "type": "object",
                        "properties": {},
                        "additionalProperties": false
                    }
                }
            }])
            .to_string(),
            ..tool_catalog()
        };
        let chat_schema = InferenceResponseSchemaPayloadRecord {
            response_schema_json: json!({
                "type": "json_schema",
                "json_schema": {
                    "name": "turn_result",
                    "strict": true,
                    "schema": {
                        "type": "object",
                        "properties": {"turn_outcome": {"type": "string"}},
                        "required": ["turn_outcome"],
                        "additionalProperties": false
                    }
                }
            })
            .to_string(),
            ..response_schema()
        };
        let body = build_request_body_json(
            &provider,
            &request(&provider.provider_id, "gpt-5.4-mini"),
            &generation_policy(0),
            &rendered_prompt(),
            &nested_tools,
            &chat_schema,
        )
        .unwrap();
        let body: Value = serde_json::from_str(&body).unwrap();

        assert_eq!(
            body["tools"][0],
            json!({
                "type": "function",
                "function": {
                    "name": "continuity.retrieve",
                    "description": "retrieve continuity",
                    "parameters": {
                        "type": "object",
                        "properties": {},
                        "additionalProperties": false
                    }
                }
            })
        );
        assert_eq!(
            body["response_format"],
            chat_schema.response_schema_json.parse::<Value>().unwrap()
        );
    }

    #[tokio::test]
    async fn openrouter_timeout_path_retries_and_exhausts() {
        let (address, _, attempts, handle) = spawn_mock_server(MockBehavior::Timeout).await;

        let mut provider = provider(
            InferenceProviderMode::OpenRouterChatCompletions,
            &format!("http://{address}/v1"),
            "OPENROUTER_API_KEY_TIMEOUT_TEST",
        );
        provider.request_timeout_ms = 10;
        let transport = OpenRouterChatCompletionsTransport::with_credentials(
            "secret-openrouter-timeout",
            None::<String>,
            None::<String>,
        )
        .unwrap();
        let bundle = execute_openrouter_chat_completions_turn(
            &provider,
            &generation_policy(2),
            &request(&provider.provider_id, "gpt-5.4-mini"),
            &rendered_prompt(),
            &tool_catalog(),
            &response_schema(),
            &transport,
        )
        .await
        .unwrap();

        assert_eq!(
            bundle.turn_result.finish_reason,
            InferenceFinishReason::TimedOut
        );
        assert_eq!(bundle.attempts.len(), 3);
        assert_eq!(
            bundle.attempts[0].retry_classification,
            InferenceRetryClassification::RetriedTimeout
        );
        assert_eq!(
            bundle.attempts[2].retry_classification,
            InferenceRetryClassification::ExhaustedTimeout
        );
        assert!(bundle.degradation_record.is_some());
        assert_eq!(attempts.load(Ordering::SeqCst), 3);

        handle.abort();
    }

    #[tokio::test]
    async fn openrouter_server_error_path_retries_and_exhausts() {
        let (address, _, attempts, handle) = spawn_mock_server(MockBehavior::ServerError).await;

        let provider = provider(
            InferenceProviderMode::OpenRouterChatCompletions,
            &format!("http://{address}/v1"),
            "OPENROUTER_API_KEY_SERVER_TEST",
        );
        let transport = OpenRouterChatCompletionsTransport::with_credentials(
            "secret-openrouter-server",
            None::<String>,
            None::<String>,
        )
        .unwrap();
        let bundle = execute_openrouter_chat_completions_turn(
            &provider,
            &generation_policy(1),
            &request(&provider.provider_id, "gpt-5.4-mini"),
            &rendered_prompt(),
            &tool_catalog(),
            &response_schema(),
            &transport,
        )
        .await
        .unwrap();

        assert_eq!(
            bundle.turn_result.finish_reason,
            InferenceFinishReason::ProviderError
        );
        assert_eq!(bundle.attempts.len(), 2);
        assert_eq!(bundle.usage_record.total_tokens, 0);
        assert_eq!(
            bundle.attempts[0].retry_classification,
            InferenceRetryClassification::RetriedServerError
        );
        assert_eq!(
            bundle.attempts[1].retry_classification,
            InferenceRetryClassification::ExhaustedServerError
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 2);

        handle.abort();
    }

    #[tokio::test]
    async fn openrouter_rate_limited_path_retries_and_exhausts() {
        let (address, _, attempts, handle) = spawn_mock_server(MockBehavior::RateLimited).await;

        let provider = provider(
            InferenceProviderMode::OpenRouterChatCompletions,
            &format!("http://{address}/v1"),
            "OPENROUTER_API_KEY_429_TEST",
        );
        let transport = OpenRouterChatCompletionsTransport::with_credentials(
            "secret-openrouter-429",
            None::<String>,
            None::<String>,
        )
        .unwrap();
        let bundle = execute_openrouter_chat_completions_turn(
            &provider,
            &generation_policy(1),
            &request(&provider.provider_id, "gpt-5.4-mini"),
            &rendered_prompt(),
            &tool_catalog(),
            &response_schema(),
            &transport,
        )
        .await
        .unwrap();

        assert_eq!(
            bundle.turn_result.finish_reason,
            InferenceFinishReason::ProviderError
        );
        assert_eq!(
            bundle.attempts[0].retry_classification,
            InferenceRetryClassification::RetriedRateLimited
        );
        assert_eq!(
            bundle.attempts[1].retry_classification,
            InferenceRetryClassification::ExhaustedRateLimited
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 2);

        handle.abort();
    }

    #[tokio::test]
    async fn openrouter_transport_failure_retries_and_exhausts() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);

        let provider = provider(
            InferenceProviderMode::OpenRouterChatCompletions,
            &format!("http://{address}/v1"),
            "OPENROUTER_API_KEY_TRANSPORT_TEST",
        );
        let transport = OpenRouterChatCompletionsTransport::with_credentials(
            "secret-openrouter-transport",
            None::<String>,
            None::<String>,
        )
        .unwrap();
        let bundle = execute_openrouter_chat_completions_turn(
            &provider,
            &generation_policy(1),
            &request(&provider.provider_id, "gpt-5.4-mini"),
            &rendered_prompt(),
            &tool_catalog(),
            &response_schema(),
            &transport,
        )
        .await
        .unwrap();

        assert_eq!(
            bundle.turn_result.finish_reason,
            InferenceFinishReason::ProviderError
        );
        assert_eq!(bundle.attempts.len(), 2);
        assert_eq!(
            bundle.attempts[0].retry_classification,
            InferenceRetryClassification::RetriedTransportFailure
        );
        assert_eq!(
            bundle.attempts[1].retry_classification,
            InferenceRetryClassification::ExhaustedTransportFailure
        );
        assert!(bundle.degradation_record.is_some());
    }

    #[tokio::test]
    async fn openrouter_missing_string_content_yields_malformed_output() {
        let (address, _, attempts, handle) = spawn_mock_server(MockBehavior::MissingContent).await;

        let provider = provider(
            InferenceProviderMode::OpenRouterChatCompletions,
            &format!("http://{address}/v1"),
            "OPENROUTER_API_KEY_MALFORMED_TEST",
        );
        let transport = OpenRouterChatCompletionsTransport::with_credentials(
            "secret-openrouter-malformed",
            None::<String>,
            None::<String>,
        )
        .unwrap();
        let bundle = execute_openrouter_chat_completions_turn(
            &provider,
            &generation_policy(0),
            &request(&provider.provider_id, "gpt-5.4-mini"),
            &rendered_prompt(),
            &tool_catalog(),
            &response_schema(),
            &transport,
        )
        .await
        .unwrap();

        assert_eq!(
            bundle.turn_result.finish_reason,
            InferenceFinishReason::MalformedOutput
        );
        assert!(bundle.degradation_record.is_some());
        assert_eq!(attempts.load(Ordering::SeqCst), 1);

        handle.abort();
    }

    #[tokio::test]
    async fn openrouter_non_string_content_yields_malformed_output() {
        let (address, _, attempts, handle) =
            spawn_mock_server(MockBehavior::NonStringContent).await;

        let provider = provider(
            InferenceProviderMode::OpenRouterChatCompletions,
            &format!("http://{address}/v1"),
            "OPENROUTER_API_KEY_NON_STRING_TEST",
        );
        let transport = OpenRouterChatCompletionsTransport::with_credentials(
            "secret-openrouter-non-string",
            None::<String>,
            None::<String>,
        )
        .unwrap();
        let bundle = execute_openrouter_chat_completions_turn(
            &provider,
            &generation_policy(0),
            &request(&provider.provider_id, "gpt-5.4-mini"),
            &rendered_prompt(),
            &tool_catalog(),
            &response_schema(),
            &transport,
        )
        .await
        .unwrap();

        assert_eq!(
            bundle.turn_result.finish_reason,
            InferenceFinishReason::MalformedOutput
        );
        assert!(bundle.degradation_record.is_some());
        assert_eq!(attempts.load(Ordering::SeqCst), 1);

        handle.abort();
    }
}
