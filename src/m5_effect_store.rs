//! M3-owned effect backend for the bounded M5 factory lifecycle.
//!
//! The reproduction engine owns intent and evidence projection. This module
//! owns physical factory effects: the active component route, immutable package
//! and state blobs, staged migrations, observations, and rollback. It is only
//! reached through [`FactoryEvolutionPort`]; callers do not invoke its mutation
//! methods directly.

use crate::capability_services::{
    CapabilityOperation, FactoryEffectRequest, FactoryEffectResult, FactoryEvolutionPort,
    InvocationControl, ServiceFailure,
};
use crate::deployment::{
    ActivationRequest as DeploymentActivationRequest,
    ArtifactSnapshot as DeploymentArtifactSnapshot, InitializationRecord, LocalDeploymentService,
    ObservationOutcome as DeploymentObservationOutcome,
    ObservationRequest as DeploymentObservationRequest, RollbackRequest,
};
use crate::execution::artifact::{ContentDigest, digest_json_content};
use crate::execution::component::{
    ComponentExecutionLimits, ComponentI32ExecutionTrace, execute_component_i32_export,
};
use crate::factory_reproduction::{
    ActivationReceipt, ActivationRequest, BenchmarkSpec, ExecutionTerminal, FactoryPackage,
    HealthObservation, HealthStatus, InvariantKind, InvariantObservation, MigrationReceipt,
    MigrationRequest, ParsedProviderIntent, PendingStage, PostActivationEvidence,
    PostActivationRequest, ProviderQualificationRequest, RecoveryReceipt, RecoveryRequest,
    ResourceUsage, ShadowExecutionEvidence, ShadowExecutionRequest, TaskExecutionObservation,
};
use crate::m5_provider_binding::{PROVIDER_CANDIDATE_INTENT_SCHEMA, PROVIDER_CANDIDATE_OPERATION};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::Instant;

const EFFECT_STORE_STATE_SCHEMA_VERSION: u32 = 2;
const FACTORY_SNAPSHOT_SCHEMA: &str = "wasm-biotic.m5-factory-snapshot.v1";
const INITIALIZE_REQUEST_SCHEMA: &str = "wasm-biotic.m5-factory-initialize-request.v1";
const INITIALIZE_EVIDENCE_SCHEMA: &str = "wasm-biotic.m5-factory-initialize-evidence.v1";
const EXECUTE_REQUEST_SCHEMA: &str = "wasm-biotic.m5-factory-execute-request.v1";
pub const CAUSALLY_BOUND_EXECUTE_REQUEST_SCHEMA: &str = "wasm-biotic.m5-factory-execute-request.v2";
const EXECUTE_RESULT_SCHEMA: &str = "wasm-biotic.m5-factory-execute-result.v1";
const PROVIDER_PROPOSAL_REQUEST_SCHEMA: &str =
    "wasm-biotic.m5-factory-provider-proposal-request.v4";
const PROVIDER_PROPOSAL_RESULT_SCHEMA: &str = "wasm-biotic.m5-factory-provider-proposal-result.v2";
const INSPECT_REQUEST_SCHEMA: &str = "wasm-biotic.m5-factory-inspect-request.v1";
const INSPECTION_SCHEMA: &str = "wasm-biotic.m5-factory-inspection.v1";
const MIGRATION_ARTIFACT_SCHEMA: &str = "wasm-biotic.m5-state-transform-artifact.v1";
const MIGRATION_BUNDLE_SCHEMA: &str = "wasm-biotic.m5-state-transform-bundle.v1";
const MIGRATION_EFFECT_REQUEST_SCHEMA: &str = "wasm-biotic.m5-migration-effect-request.v1";
const EFFECT_RECORD_SCHEMA: &str = "wasm-biotic.m5-factory-effect-record.v1";
const STATE_FILE: &str = "factory-effect-state.json";
const PACKAGE_DIRECTORY: &str = "factory-packages";
const STATE_BLOB_DIRECTORY: &str = "state-blobs";
const CANDIDATE_DIRECTORY: &str = "deployment-candidates";
const DEPLOYMENT_DIRECTORY: &str = "deployment";
const EFFECT_INTENT_DIRECTORY: &str = "effect-intents";
const EFFECT_RESULT_DIRECTORY: &str = "effect-results";
const FAULT_DIRECTORY: &str = "faults";
const FAIL_AFTER_BACKEND_COMMIT: &str = "fail-after-backend-commit";
const FAIL_AFTER_DEPLOYMENT_COMMIT: &str = "fail-after-deployment-commit";
const FAIL_NEXT_OBSERVATION_HEALTH: &str = "fail-next-observation-health";
const MAX_DOMAIN_BYTES: usize = 16 * 1_048_576;
const MAX_STATE_BYTES: usize = 4 * 1_048_576;
const MAX_TRANSFORM_PREFIX_BYTES: usize = 16 * 1_024;
const MAX_PROVIDER_PROPOSAL_BYTES: usize = 256 * 1_024;
const MAX_RECORDS: usize = 10_000;

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactoryRuntimeSnapshot {
    pub schema: String,
    pub factory_id: String,
    pub package_digest: ContentDigest,
    pub package_bytes_digest: ContentDigest,
    pub component_digest: ContentDigest,
    pub generation: u32,
    pub state_schema: u32,
    pub state_blob_digest: ContentDigest,
    pub activation_id: Option<String>,
    pub snapshot_digest: ContentDigest,
}

impl FactoryRuntimeSnapshot {
    fn new(
        factory_id: String,
        package: &FactoryPackage,
        package_bytes: &[u8],
        state_schema: u32,
        state_bytes: &[u8],
        activation_id: Option<String>,
    ) -> Result<Self, FactoryEffectStoreError> {
        let mut snapshot = Self {
            schema: FACTORY_SNAPSHOT_SCHEMA.to_string(),
            factory_id,
            package_digest: package.package_digest.clone(),
            package_bytes_digest: ContentDigest::from_bytes(package_bytes),
            component_digest: package.payload.genome.component_digest.clone(),
            generation: package.payload.generation,
            state_schema,
            state_blob_digest: ContentDigest::from_bytes(state_bytes),
            activation_id,
            snapshot_digest: ContentDigest::from_bytes(&[]),
        };
        snapshot.snapshot_digest = snapshot.expected_digest()?;
        Ok(snapshot)
    }

    fn validate(&self) -> Result<(), FactoryEffectStoreError> {
        if self.schema != FACTORY_SNAPSHOT_SCHEMA || self.factory_id.trim().is_empty() {
            return Err(FactoryEffectStoreError::Integrity(
                "invalid factory runtime snapshot identity".to_string(),
            ));
        }
        require_digest(
            "factory runtime snapshot",
            &self.snapshot_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, FactoryEffectStoreError> {
        Ok(digest_json_content(&(
            FACTORY_SNAPSHOT_SCHEMA,
            &self.factory_id,
            &self.package_digest,
            &self.package_bytes_digest,
            &self.component_digest,
            self.generation,
            self.state_schema,
            &self.state_blob_digest,
            &self.activation_id,
        ))?)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactoryInitializeRequest {
    pub schema: String,
    pub operation_id: String,
    pub factory_id: String,
    pub package_bytes: Vec<u8>,
    pub initial_state_schema: u32,
    pub initial_state_bytes: Vec<u8>,
    pub request_digest: ContentDigest,
}

impl FactoryInitializeRequest {
    pub fn new(
        operation_id: impl Into<String>,
        factory_id: impl Into<String>,
        package_bytes: Vec<u8>,
        initial_state_schema: u32,
        initial_state_bytes: Vec<u8>,
    ) -> Result<Self, FactoryEffectStoreError> {
        let mut request = Self {
            schema: INITIALIZE_REQUEST_SCHEMA.to_string(),
            operation_id: operation_id.into(),
            factory_id: factory_id.into(),
            package_bytes,
            initial_state_schema,
            initial_state_bytes,
            request_digest: ContentDigest::from_bytes(&[]),
        };
        request.validate_fields()?;
        request.request_digest = request.expected_digest()?;
        Ok(request)
    }

    fn validate(&self) -> Result<(), FactoryEffectStoreError> {
        self.validate_fields()?;
        require_digest(
            "factory initialize request",
            &self.request_digest,
            &self.expected_digest()?,
        )
    }

    fn validate_fields(&self) -> Result<(), FactoryEffectStoreError> {
        if self.schema != INITIALIZE_REQUEST_SCHEMA
            || self.operation_id.trim().is_empty()
            || self.factory_id.trim().is_empty()
            || self.package_bytes.is_empty()
            || self.package_bytes.len() > MAX_DOMAIN_BYTES
            || self.initial_state_schema == 0
            || self.initial_state_bytes.is_empty()
            || self.initial_state_bytes.len() > MAX_STATE_BYTES
        {
            return Err(FactoryEffectStoreError::InvalidRequest(
                "factory initialization is outside its bounded schema".to_string(),
            ));
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, FactoryEffectStoreError> {
        Ok(digest_json_content(&(
            INITIALIZE_REQUEST_SCHEMA,
            &self.operation_id,
            &self.factory_id,
            &self.package_bytes,
            self.initial_state_schema,
            &self.initial_state_bytes,
        ))?)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactoryInitializationEvidence {
    pub schema: String,
    pub request_digest: ContentDigest,
    pub snapshot: FactoryRuntimeSnapshot,
    pub deployment_record_digest: ContentDigest,
    pub evidence_digest: ContentDigest,
}

impl FactoryInitializationEvidence {
    fn seal(mut self) -> Result<Self, FactoryEffectStoreError> {
        self.evidence_digest = digest_json_content(&(
            INITIALIZE_EVIDENCE_SCHEMA,
            &self.request_digest,
            &self.snapshot,
            &self.deployment_record_digest,
        ))?;
        Ok(self)
    }

    fn validate(&self) -> Result<(), FactoryEffectStoreError> {
        if self.schema != INITIALIZE_EVIDENCE_SCHEMA {
            return Err(FactoryEffectStoreError::Integrity(
                "unsupported factory initialization evidence".to_string(),
            ));
        }
        self.snapshot.validate()?;
        require_digest(
            "factory initialization evidence",
            &self.evidence_digest,
            &self.clone().seal()?.evidence_digest,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactoryExecuteRequest {
    pub schema: String,
    pub expected_package_digest: ContentDigest,
    pub input: i32,
    /// Optional caller-owned causal context sealed into the exact M3 request.
    ///
    /// Ordinary execution leaves this absent and retains the original V1 wire
    /// representation and request digest. Proof-run chronology uses the
    /// challenged constructor so an execution cannot be detached from the
    /// evidence that had to exist before it was invoked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub causal_context_digest: Option<ContentDigest>,
    pub request_digest: ContentDigest,
}

impl FactoryExecuteRequest {
    pub fn new(
        expected_package_digest: ContentDigest,
        input: i32,
    ) -> Result<Self, FactoryEffectStoreError> {
        let mut request = Self {
            schema: EXECUTE_REQUEST_SCHEMA.to_string(),
            expected_package_digest,
            input,
            causal_context_digest: None,
            request_digest: ContentDigest::from_bytes(&[]),
        };
        request.request_digest = request.expected_digest()?;
        Ok(request)
    }

    pub(crate) fn new_with_causal_context(
        expected_package_digest: ContentDigest,
        input: i32,
        causal_context_digest: ContentDigest,
    ) -> Result<Self, FactoryEffectStoreError> {
        let mut request = Self {
            schema: CAUSALLY_BOUND_EXECUTE_REQUEST_SCHEMA.to_string(),
            expected_package_digest,
            input,
            causal_context_digest: Some(causal_context_digest),
            request_digest: ContentDigest::from_bytes(&[]),
        };
        request.request_digest = request.expected_digest()?;
        Ok(request)
    }

    fn validate(&self) -> Result<(), FactoryEffectStoreError> {
        if (self.causal_context_digest.is_none() && self.schema != EXECUTE_REQUEST_SCHEMA)
            || (self.causal_context_digest.is_some()
                && self.schema != CAUSALLY_BOUND_EXECUTE_REQUEST_SCHEMA)
        {
            return Err(FactoryEffectStoreError::InvalidRequest(
                "unsupported factory execute request".to_string(),
            ));
        }
        require_digest(
            "factory execute request",
            &self.request_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, FactoryEffectStoreError> {
        match &self.causal_context_digest {
            None => Ok(digest_json_content(&(
                EXECUTE_REQUEST_SCHEMA,
                &self.expected_package_digest,
                self.input,
            ))?),
            Some(causal_context_digest) => Ok(digest_json_content(&(
                CAUSALLY_BOUND_EXECUTE_REQUEST_SCHEMA,
                &self.expected_package_digest,
                self.input,
                causal_context_digest,
            ))?),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactoryExecutionResult {
    pub schema: String,
    pub request_digest: ContentDigest,
    pub snapshot: FactoryRuntimeSnapshot,
    pub input: i32,
    pub output: i32,
    pub trace: ComponentI32ExecutionTrace,
    pub result_digest: ContentDigest,
}

impl FactoryExecutionResult {
    fn seal(mut self) -> Result<Self, FactoryEffectStoreError> {
        self.result_digest = digest_json_content(&(
            EXECUTE_RESULT_SCHEMA,
            &self.request_digest,
            &self.snapshot,
            self.input,
            self.output,
            &self.trace,
        ))?;
        Ok(self)
    }
}

/// Exact, frozen provider proposal material submitted to M3 for durable,
/// read-only admission.
///
/// This is deliberately not a qualification or candidate binding. The full
/// qualification request retains the replay capsule bytes; the duplicated
/// capsule and target digests make the two security-relevant anchors explicit
/// in the M3 request and fail closed if a caller constructs inconsistent wire
/// data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactoryProviderProposalRequest {
    pub schema: String,
    pub qualification_request: ProviderQualificationRequest,
    pub replay_capsule_digest: ContentDigest,
    pub normalized_parser_input_bytes: Vec<u8>,
    pub target_digest: ContentDigest,
    pub request_digest: ContentDigest,
}

impl FactoryProviderProposalRequest {
    pub fn new(
        qualification_request: ProviderQualificationRequest,
        normalized_parser_input_bytes: Vec<u8>,
    ) -> Result<Self, FactoryEffectStoreError> {
        let mut request = Self {
            schema: PROVIDER_PROPOSAL_REQUEST_SCHEMA.to_string(),
            replay_capsule_digest: qualification_request.replay_capsule.capsule_digest.clone(),
            target_digest: qualification_request.target_digest.clone(),
            qualification_request,
            normalized_parser_input_bytes,
            request_digest: ContentDigest::from_bytes(&[]),
        };
        request.validate_fields()?;
        request.request_digest = request.expected_digest()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), FactoryEffectStoreError> {
        self.validate_fields()?;
        require_digest(
            "factory provider proposal request",
            &self.request_digest,
            &self.expected_digest()?,
        )
    }

    fn validate_fields(&self) -> Result<(), FactoryEffectStoreError> {
        if self.schema != PROVIDER_PROPOSAL_REQUEST_SCHEMA
            || self.normalized_parser_input_bytes.is_empty()
            || self.normalized_parser_input_bytes.len() > MAX_PROVIDER_PROPOSAL_BYTES
            || self.replay_capsule_digest
                != self.qualification_request.replay_capsule.capsule_digest
            || self.target_digest != self.qualification_request.target_digest
        {
            return Err(FactoryEffectStoreError::InvalidRequest(
                "provider proposal is outside its bounded frozen schema".to_string(),
            ));
        }
        self.qualification_request.validate().map_err(|error| {
            FactoryEffectStoreError::InvalidRequest(format!(
                "provider proposal qualification request is invalid: {error}"
            ))
        })?;
        let arguments = decode_provider_proposal_arguments(&self.normalized_parser_input_bytes)?;
        let expected = expected_provider_proposal_wire(&self.qualification_request)?;
        if arguments != expected.arguments {
            return Err(FactoryEffectStoreError::InvalidRequest(
                "provider proposal arguments differ from the exact frozen prompt contract"
                    .to_string(),
            ));
        }
        expected.intent()?.intent_digest().map_err(|error| {
            FactoryEffectStoreError::InvalidRequest(format!(
                "provider proposal intent is invalid: {error}"
            ))
        })?;
        if serde_json::to_vec(&arguments)? != self.normalized_parser_input_bytes {
            return Err(FactoryEffectStoreError::InvalidRequest(
                "provider proposal parser input is not exact canonical normalized JSON".to_string(),
            ));
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, FactoryEffectStoreError> {
        Ok(digest_json_content(&(
            PROVIDER_PROPOSAL_REQUEST_SCHEMA,
            &self.qualification_request,
            &self.replay_capsule_digest,
            &self.normalized_parser_input_bytes,
            &self.target_digest,
        ))?)
    }

    fn parsed_intent(&self) -> Result<ParsedProviderIntent, FactoryEffectStoreError> {
        let arguments = decode_provider_proposal_arguments(&self.normalized_parser_input_bytes)?;
        let expected = expected_provider_proposal_wire(&self.qualification_request)?;
        if arguments != expected.arguments {
            return Err(FactoryEffectStoreError::InvalidRequest(
                "provider proposal arguments differ from the exact frozen prompt contract"
                    .to_string(),
            ));
        }
        expected.intent()
    }
}

/// Digest-sealed M3/backend acknowledgement of one exact proposal payload.
///
/// The result says only what the backend admitted and content-addressed. It
/// does not claim that the provider was qualified or that a candidate target
/// was published by the separate binding store.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactoryProviderProposalResult {
    pub schema: String,
    pub request_digest: ContentDigest,
    pub qualification_request_digest: ContentDigest,
    pub replay_capsule_digest: ContentDigest,
    pub normalized_parser_input_digest: ContentDigest,
    pub target_digest: ContentDigest,
    pub proposed_target_genome_digest: ContentDigest,
    pub intent_digest: ContentDigest,
    pub result_digest: ContentDigest,
}

impl FactoryProviderProposalResult {
    pub fn from_request(
        request: &FactoryProviderProposalRequest,
    ) -> Result<Self, FactoryEffectStoreError> {
        request.validate()?;
        let intent = request.parsed_intent()?;
        let mut result = Self {
            schema: PROVIDER_PROPOSAL_RESULT_SCHEMA.to_string(),
            request_digest: request.request_digest.clone(),
            qualification_request_digest: request.qualification_request.request_digest.clone(),
            replay_capsule_digest: request.replay_capsule_digest.clone(),
            normalized_parser_input_digest: ContentDigest::from_bytes(
                &request.normalized_parser_input_bytes,
            ),
            target_digest: request.target_digest.clone(),
            proposed_target_genome_digest: intent.target_genome_digest.clone(),
            intent_digest: intent.intent_digest().map_err(|error| {
                FactoryEffectStoreError::InvalidRequest(format!(
                    "provider proposal intent cannot be digested: {error}"
                ))
            })?,
            result_digest: ContentDigest::from_bytes(&[]),
        };
        result.result_digest = result.expected_digest()?;
        Ok(result)
    }

    pub fn validate_for(
        &self,
        request: &FactoryProviderProposalRequest,
    ) -> Result<(), FactoryEffectStoreError> {
        let expected = Self::from_request(request)?;
        if self != &expected {
            return Err(FactoryEffectStoreError::Integrity(
                "provider proposal result differs from its exact frozen request".to_string(),
            ));
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, FactoryEffectStoreError> {
        Ok(digest_json_content(&(
            PROVIDER_PROPOSAL_RESULT_SCHEMA,
            &self.request_digest,
            &self.qualification_request_digest,
            &self.replay_capsule_digest,
            &self.normalized_parser_input_digest,
            &self.target_digest,
            &self.proposed_target_genome_digest,
            &self.intent_digest,
        ))?)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderProposalWire {
    operation: String,
    target_genome_digest: ContentDigest,
    arguments: BTreeMap<String, String>,
}

impl ProviderProposalWire {
    fn intent(&self) -> Result<ParsedProviderIntent, FactoryEffectStoreError> {
        if self.operation != PROVIDER_CANDIDATE_OPERATION {
            return Err(FactoryEffectStoreError::InvalidRequest(format!(
                "provider proposal operation must be exactly '{PROVIDER_CANDIDATE_OPERATION}'"
            )));
        }
        let expected_keys = [
            "challenger_wat_digest",
            "cycle_id",
            "invocation_challenge_digest",
            "policy_digest",
        ];
        if self.arguments.len() != expected_keys.len()
            || !expected_keys
                .iter()
                .all(|key| self.arguments.contains_key(*key))
            || self.arguments.get("cycle_id").is_none_or(|value| {
                value.trim().is_empty() || value.len() > 512 || value.chars().any(char::is_control)
            })
            || [
                "challenger_wat_digest",
                "invocation_challenge_digest",
                "policy_digest",
            ]
            .iter()
            .any(|key| {
                self.arguments
                    .get(*key)
                    .and_then(|value| ContentDigest::new(value.clone()).ok())
                    .is_none()
            })
        {
            return Err(FactoryEffectStoreError::InvalidRequest(
                "provider proposal arguments are not the bounded candidate materialization shape"
                    .to_string(),
            ));
        }
        Ok(ParsedProviderIntent {
            intent_schema: PROVIDER_CANDIDATE_INTENT_SCHEMA.to_string(),
            operation: self.operation.clone(),
            target_genome_digest: self.target_genome_digest.clone(),
            arguments: self.arguments.clone(),
        })
    }
}

fn decode_provider_proposal_arguments(
    bytes: &[u8],
) -> Result<BTreeMap<String, String>, FactoryEffectStoreError> {
    serde_json::from_slice(bytes).map_err(|error| {
        FactoryEffectStoreError::InvalidRequest(format!(
            "normalized provider proposal arguments are not valid bounded JSON: {error}"
        ))
    })
}

fn expected_provider_proposal_wire(
    qualification: &ProviderQualificationRequest,
) -> Result<ProviderProposalWire, FactoryEffectStoreError> {
    let prompt: serde_json::Value =
        serde_json::from_slice(&qualification.prompt_bytes).map_err(|error| {
            FactoryEffectStoreError::InvalidRequest(format!(
                "frozen provider prompt is not valid JSON: {error}"
            ))
        })?;
    serde_json::from_value(prompt.get("required_response").cloned().ok_or_else(|| {
        FactoryEffectStoreError::InvalidRequest(
            "frozen provider prompt has no exact required_response contract".to_string(),
        )
    })?)
    .map_err(|error| {
        FactoryEffectStoreError::InvalidRequest(format!(
            "frozen provider required_response is invalid: {error}"
        ))
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateTransformDirection {
    Forward,
    Rollback,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "operation")]
pub enum StateTransformProgram {
    Prepend { prefix: Vec<u8> },
    RemovePrefix { prefix: Vec<u8> },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateTransformArtifact {
    pub schema: String,
    pub direction: StateTransformDirection,
    pub from_schema: u32,
    pub to_schema: u32,
    pub program: StateTransformProgram,
    pub program_digest: ContentDigest,
    pub proving_record_digest: ContentDigest,
    pub artifact_digest: ContentDigest,
}

impl StateTransformArtifact {
    pub fn new(
        direction: StateTransformDirection,
        from_schema: u32,
        to_schema: u32,
        program: StateTransformProgram,
        proving_record_digest: ContentDigest,
    ) -> Result<Self, FactoryEffectStoreError> {
        let program_digest =
            digest_json_content(&("wasm-biotic:m5-state-transform-program:v1", &program))?;
        let mut artifact = Self {
            schema: MIGRATION_ARTIFACT_SCHEMA.to_string(),
            direction,
            from_schema,
            to_schema,
            program,
            program_digest,
            proving_record_digest,
            artifact_digest: ContentDigest::from_bytes(&[]),
        };
        artifact.validate_fields()?;
        artifact.artifact_digest = artifact.expected_digest()?;
        Ok(artifact)
    }

    fn validate(&self) -> Result<(), FactoryEffectStoreError> {
        self.validate_fields()?;
        require_digest(
            "state transform program",
            &self.program_digest,
            &digest_json_content(&("wasm-biotic:m5-state-transform-program:v1", &self.program))?,
        )?;
        require_digest(
            "state transform artifact",
            &self.artifact_digest,
            &self.expected_digest()?,
        )
    }

    fn validate_fields(&self) -> Result<(), FactoryEffectStoreError> {
        let prefix = match &self.program {
            StateTransformProgram::Prepend { prefix }
            | StateTransformProgram::RemovePrefix { prefix } => prefix,
        };
        if self.schema != MIGRATION_ARTIFACT_SCHEMA
            || self.from_schema == 0
            || self.to_schema == 0
            || prefix.is_empty()
            || prefix.len() > MAX_TRANSFORM_PREFIX_BYTES
        {
            return Err(FactoryEffectStoreError::InvalidRequest(
                "state transform artifact is outside its bounded schema".to_string(),
            ));
        }
        match (&self.direction, &self.program) {
            (StateTransformDirection::Forward, StateTransformProgram::Prepend { .. })
            | (StateTransformDirection::Rollback, StateTransformProgram::RemovePrefix { .. }) => {
                Ok(())
            }
            _ => Err(FactoryEffectStoreError::InvalidRequest(
                "state transform direction does not match its executable program".to_string(),
            )),
        }
    }

    fn expected_digest(&self) -> Result<ContentDigest, FactoryEffectStoreError> {
        Ok(digest_json_content(&(
            MIGRATION_ARTIFACT_SCHEMA,
            &self.direction,
            self.from_schema,
            self.to_schema,
            &self.program_digest,
            &self.proving_record_digest,
        ))?)
    }

    fn execute(
        &self,
        input: &[u8],
        max_output_bytes: usize,
    ) -> Result<Vec<u8>, FactoryEffectStoreError> {
        self.validate()?;
        let output = match &self.program {
            StateTransformProgram::Prepend { prefix } => {
                let mut output = Vec::with_capacity(prefix.len().saturating_add(input.len()));
                output.extend_from_slice(prefix);
                output.extend_from_slice(input);
                output
            }
            StateTransformProgram::RemovePrefix { prefix } => input
                .strip_prefix(prefix.as_slice())
                .ok_or_else(|| {
                    FactoryEffectStoreError::Migration(
                        "rollback transform input does not contain its approved prefix".to_string(),
                    )
                })?
                .to_vec(),
        };
        if output.is_empty() || output.len() > max_output_bytes {
            return Err(FactoryEffectStoreError::Migration(
                "state transform output is outside its byte budget".to_string(),
            ));
        }
        Ok(output)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateMigrationArtifactBundle {
    pub schema: String,
    pub forward: StateTransformArtifact,
    pub rollback: StateTransformArtifact,
    pub bundle_digest: ContentDigest,
}

impl StateMigrationArtifactBundle {
    pub fn new(
        forward: StateTransformArtifact,
        rollback: StateTransformArtifact,
    ) -> Result<Self, FactoryEffectStoreError> {
        let mut bundle = Self {
            schema: MIGRATION_BUNDLE_SCHEMA.to_string(),
            forward,
            rollback,
            bundle_digest: ContentDigest::from_bytes(&[]),
        };
        bundle.validate_fields()?;
        bundle.bundle_digest = bundle.expected_digest()?;
        Ok(bundle)
    }

    pub fn validate(&self) -> Result<(), FactoryEffectStoreError> {
        self.validate_fields()?;
        require_digest(
            "state migration artifact bundle",
            &self.bundle_digest,
            &self.expected_digest()?,
        )
    }

    fn validate_fields(&self) -> Result<(), FactoryEffectStoreError> {
        if self.schema != MIGRATION_BUNDLE_SCHEMA {
            return Err(FactoryEffectStoreError::InvalidRequest(
                "unsupported state migration artifact bundle".to_string(),
            ));
        }
        self.forward.validate()?;
        self.rollback.validate()?;
        if self.forward.direction != StateTransformDirection::Forward
            || self.rollback.direction != StateTransformDirection::Rollback
            || self.forward.from_schema != self.rollback.to_schema
            || self.forward.to_schema != self.rollback.from_schema
        {
            return Err(FactoryEffectStoreError::InvalidRequest(
                "forward and rollback artifacts are not exact inverse schema edges".to_string(),
            ));
        }
        let forward_prefix = match &self.forward.program {
            StateTransformProgram::Prepend { prefix } => prefix,
            _ => unreachable!("validated forward program"),
        };
        let rollback_prefix = match &self.rollback.program {
            StateTransformProgram::RemovePrefix { prefix } => prefix,
            _ => unreachable!("validated rollback program"),
        };
        if forward_prefix != rollback_prefix {
            return Err(FactoryEffectStoreError::InvalidRequest(
                "forward and rollback artifacts do not share the exact transform parameter"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, FactoryEffectStoreError> {
        Ok(digest_json_content(&(
            MIGRATION_BUNDLE_SCHEMA,
            &self.forward.artifact_digest,
            &self.rollback.artifact_digest,
        ))?)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactoryMigrationEffectRequest {
    pub schema: String,
    pub request: MigrationRequest,
    pub artifacts: StateMigrationArtifactBundle,
    pub effect_request_digest: ContentDigest,
}

impl FactoryMigrationEffectRequest {
    pub fn new(
        request: MigrationRequest,
        artifacts: StateMigrationArtifactBundle,
    ) -> Result<Self, FactoryEffectStoreError> {
        let mut effect = Self {
            schema: MIGRATION_EFFECT_REQUEST_SCHEMA.to_string(),
            request,
            artifacts,
            effect_request_digest: ContentDigest::from_bytes(&[]),
        };
        effect.validate_fields()?;
        effect.effect_request_digest = effect.expected_digest()?;
        Ok(effect)
    }

    fn validate(&self) -> Result<(), FactoryEffectStoreError> {
        self.validate_fields()?;
        require_digest(
            "factory migration effect request",
            &self.effect_request_digest,
            &self.expected_digest()?,
        )
    }

    fn validate_fields(&self) -> Result<(), FactoryEffectStoreError> {
        if self.schema != MIGRATION_EFFECT_REQUEST_SCHEMA {
            return Err(FactoryEffectStoreError::InvalidRequest(
                "unsupported factory migration effect request".to_string(),
            ));
        }
        self.request.plan.validate()?;
        self.artifacts.validate()?;
        if self.request.plan.from_schema != self.artifacts.forward.from_schema
            || self.request.plan.to_schema != self.artifacts.forward.to_schema
            || self.request.plan.rollback_schema != self.artifacts.rollback.to_schema
            || self.request.plan.migration_program_digest != self.artifacts.bundle_digest
        {
            return Err(FactoryEffectStoreError::InvalidRequest(
                "migration plan does not bind the exact executable forward and rollback artifacts"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, FactoryEffectStoreError> {
        Ok(digest_json_content(&(
            MIGRATION_EFFECT_REQUEST_SCHEMA,
            &self.request,
            &self.artifacts.bundle_digest,
        ))?)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactoryInspectRequest {
    pub schema: String,
    pub factory_id: String,
    pub request_digest: ContentDigest,
}

impl FactoryInspectRequest {
    pub fn new(factory_id: impl Into<String>) -> Result<Self, FactoryEffectStoreError> {
        let mut request = Self {
            schema: INSPECT_REQUEST_SCHEMA.to_string(),
            factory_id: factory_id.into(),
            request_digest: ContentDigest::from_bytes(&[]),
        };
        if request.factory_id.trim().is_empty() {
            return Err(FactoryEffectStoreError::InvalidRequest(
                "factory inspection requires a factory id".to_string(),
            ));
        }
        request.request_digest =
            digest_json_content(&(INSPECT_REQUEST_SCHEMA, &request.factory_id))?;
        Ok(request)
    }

    fn validate(&self) -> Result<(), FactoryEffectStoreError> {
        if self.schema != INSPECT_REQUEST_SCHEMA {
            return Err(FactoryEffectStoreError::InvalidRequest(
                "unsupported factory inspection request".to_string(),
            ));
        }
        require_digest(
            "factory inspection request",
            &self.request_digest,
            &digest_json_content(&(INSPECT_REQUEST_SCHEMA, &self.factory_id))?,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactoryRuntimeInspection {
    pub schema: String,
    pub factory_id: String,
    pub active: Option<FactoryRuntimeSnapshot>,
    pub mutation_count: usize,
    pub migration_count: usize,
    pub observation_count: usize,
    pub deployment_active_component_digest: Option<ContentDigest>,
    pub in_flight: bool,
    pub inspection_digest: ContentDigest,
}

impl FactoryRuntimeInspection {
    fn seal(mut self) -> Result<Self, FactoryEffectStoreError> {
        self.inspection_digest = digest_json_content(&(
            INSPECTION_SCHEMA,
            &self.factory_id,
            &self.active,
            self.mutation_count,
            self.migration_count,
            self.observation_count,
            &self.deployment_active_component_digest,
            self.in_flight,
        ))?;
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MutationKind {
    Initialize,
    Activate,
    Rollback,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MutationPhase {
    IntentRecorded,
    DeploymentCommitted,
    StatePointerCommitted,
    Complete,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "receipt")]
enum MutationReceipt {
    Initialization(FactoryInitializationEvidence),
    Activation(ActivationReceipt),
    Rollback(RecoveryReceipt),
}

/// Exact, reloadable fields required to re-derive the domain request and
/// idempotently resume its physical deployment effect.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "intent")]
enum MutationIntent {
    Initialize,
    Activate {
        cycle_id: String,
        candidate_path: PathBuf,
        approval_digest: ContentDigest,
        gate_decision_digest: ContentDigest,
    },
    Rollback {
        cycle_id: String,
        activation_id: String,
        interrupted_stage: PendingStage,
        migration_receipt: Option<MigrationReceipt>,
        activation_receipt: Option<ActivationReceipt>,
        reason: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeMutation {
    operation_id: String,
    request_digest: ContentDigest,
    kind: MutationKind,
    before: Option<FactoryRuntimeSnapshot>,
    after: FactoryRuntimeSnapshot,
    intent: MutationIntent,
    phase: MutationPhase,
    receipt: MutationReceipt,
}

impl RuntimeMutation {
    fn validate(&self) -> Result<(), FactoryEffectStoreError> {
        if self.operation_id.trim().is_empty() {
            return Err(FactoryEffectStoreError::Integrity(
                "runtime mutation has an empty operation identity".to_string(),
            ));
        }
        self.after.validate()?;
        if let Some(before) = &self.before {
            before.validate()?;
            if before.factory_id != self.after.factory_id {
                return Err(FactoryEffectStoreError::Integrity(
                    "runtime mutation crosses factory identities".to_string(),
                ));
            }
        }

        match (&self.kind, &self.intent, &self.receipt, &self.before) {
            (
                MutationKind::Initialize,
                MutationIntent::Initialize,
                MutationReceipt::Initialization(evidence),
                None,
            ) => {
                evidence.validate()?;
                if evidence.request_digest != self.request_digest
                    || evidence.snapshot != self.after
                    || self.after.activation_id.is_some()
                {
                    return Err(FactoryEffectStoreError::Integrity(
                        "initialization mutation does not bind its exact request and snapshot"
                            .to_string(),
                    ));
                }
            }
            (
                MutationKind::Activate,
                MutationIntent::Activate {
                    cycle_id,
                    candidate_path,
                    approval_digest: _,
                    gate_decision_digest: _,
                },
                MutationReceipt::Activation(receipt),
                Some(before),
            ) => {
                let expected_path = PathBuf::from(format!(
                    "{}.component",
                    self.after.component_digest.file_stem()
                ));
                if cycle_id.trim().is_empty()
                    || self.operation_id != format!("m5-activation:{cycle_id}")
                    || candidate_path != &expected_path
                    || before.component_digest == self.after.component_digest
                    || self.after.activation_id.as_ref() != Some(&self.operation_id)
                    || receipt.clone().seal()? != *receipt
                    || receipt.activation_id != self.operation_id
                    || receipt.request_digest != self.request_digest
                    || receipt.previous_package_digest != before.package_digest
                    || receipt.active_package_digest != self.after.package_digest
                    || receipt.active_package_bytes_digest != self.after.package_bytes_digest
                    || receipt.active_state_schema != self.after.state_schema
                {
                    return Err(FactoryEffectStoreError::Integrity(
                        "activation mutation does not bind its exact route and receipt".to_string(),
                    ));
                }
            }
            (
                MutationKind::Rollback,
                MutationIntent::Rollback {
                    cycle_id,
                    activation_id,
                    interrupted_stage: _,
                    migration_receipt,
                    activation_receipt,
                    reason,
                },
                MutationReceipt::Rollback(receipt),
                Some(before),
            ) => {
                if let Some(migration) = migration_receipt
                    && migration.clone().seal()? != *migration
                {
                    return Err(FactoryEffectStoreError::Integrity(
                        "rollback mutation contains altered migration evidence".to_string(),
                    ));
                }
                if let Some(activation) = activation_receipt
                    && (activation.clone().seal()? != *activation
                        || activation.activation_id != *activation_id
                        || activation.active_package_digest != before.package_digest)
                {
                    return Err(FactoryEffectStoreError::Integrity(
                        "rollback mutation contains altered activation evidence".to_string(),
                    ));
                }
                if cycle_id.trim().is_empty()
                    || reason.trim().is_empty()
                    || before.component_digest == self.after.component_digest
                    || before.activation_id.as_ref() != Some(activation_id)
                    || receipt.clone().seal()? != *receipt
                    || receipt.recovery_id != self.operation_id
                    || receipt.request_digest != self.request_digest
                    || receipt.restored_package_digest != self.after.package_digest
                    || receipt.restored_package_bytes_digest != self.after.package_bytes_digest
                    || receipt.restored_state_schema != self.after.state_schema
                    || !receipt.state_readable
                {
                    return Err(FactoryEffectStoreError::Integrity(
                        "rollback mutation does not bind its exact route and receipt".to_string(),
                    ));
                }
            }
            _ => {
                return Err(FactoryEffectStoreError::Integrity(
                    "runtime mutation kind, intent, receipt, and snapshots disagree".to_string(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredMigration {
    migration_id: String,
    request_digest: ContentDigest,
    request: MigrationRequest,
    incumbent_snapshot_digest: ContentDigest,
    challenger_package_digest: ContentDigest,
    prepared_state_blob_digest: ContentDigest,
    artifacts: StateMigrationArtifactBundle,
    receipt: MigrationReceipt,
}

impl StoredMigration {
    fn validate(&self) -> Result<(), FactoryEffectStoreError> {
        self.artifacts.validate()?;
        self.request.plan.validate()?;
        if self.migration_id.trim().is_empty()
            || self.receipt.clone().seal()? != self.receipt
            || migration_request_digest(&self.request)? != self.request.request_digest
            || self.request.request_digest != self.request_digest
            || self.request.plan.migration_id != self.migration_id
            || self.request.incumbent_package_digest == self.request.challenger_package_digest
            || self.request.challenger_package_digest != self.challenger_package_digest
            || self.request.plan.from_schema != self.artifacts.forward.from_schema
            || self.request.plan.to_schema != self.artifacts.forward.to_schema
            || self.request.plan.rollback_schema != self.artifacts.rollback.to_schema
            || self.request.plan.migration_program_digest != self.artifacts.bundle_digest
            || self.receipt.migration_id != self.migration_id
            || self.receipt.request_digest != self.request_digest
            || self.receipt.from_schema != self.artifacts.forward.from_schema
            || self.receipt.to_schema != self.artifacts.forward.to_schema
            || self.receipt.pre_migration_state_digest != self.receipt.rollback_backup_digest
            || self.receipt.post_migration_state_digest != self.prepared_state_blob_digest
            || !self.receipt.rollback_verified
        {
            return Err(FactoryEffectStoreError::Integrity(
                "stored migration does not bind its exact artifacts, state edge, and receipt"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredObservation {
    observation_id: String,
    request_digest: ContentDigest,
    evidence: PostActivationEvidence,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FactoryEffectStoreState {
    schema_version: u32,
    factory_id: Option<String>,
    active: Option<FactoryRuntimeSnapshot>,
    mutations: BTreeMap<String, RuntimeMutation>,
    migrations: BTreeMap<String, StoredMigration>,
    observations: BTreeMap<String, StoredObservation>,
    state_digest: ContentDigest,
}

impl FactoryEffectStoreState {
    fn empty() -> Result<Self, FactoryEffectStoreError> {
        let mut state = Self {
            schema_version: EFFECT_STORE_STATE_SCHEMA_VERSION,
            factory_id: None,
            active: None,
            mutations: BTreeMap::new(),
            migrations: BTreeMap::new(),
            observations: BTreeMap::new(),
            state_digest: ContentDigest::from_bytes(&[]),
        };
        state.seal()?;
        Ok(state)
    }

    fn seal(&mut self) -> Result<(), FactoryEffectStoreError> {
        let mut material = self.clone();
        material.state_digest = ContentDigest::from_bytes(&[]);
        self.state_digest =
            digest_json_content(&("wasm-biotic:m5-factory-effect-store-state:v2", material))?;
        Ok(())
    }

    fn validate(&self) -> Result<(), FactoryEffectStoreError> {
        if self.schema_version != EFFECT_STORE_STATE_SCHEMA_VERSION
            || self.mutations.len() > MAX_RECORDS
            || self.migrations.len() > MAX_RECORDS
            || self.observations.len() > MAX_RECORDS
        {
            return Err(FactoryEffectStoreError::Integrity(
                "factory effect store schema or record bound is invalid".to_string(),
            ));
        }
        if let Some(active) = &self.active {
            active.validate()?;
            if self.factory_id.as_ref() != Some(&active.factory_id) {
                return Err(FactoryEffectStoreError::Integrity(
                    "active snapshot differs from the store factory identity".to_string(),
                ));
            }
        }
        let mut pending_count = 0_usize;
        for (operation_id, mutation) in &self.mutations {
            mutation.validate()?;
            if operation_id != &mutation.operation_id
                || self.factory_id.as_ref() != Some(&mutation.after.factory_id)
            {
                return Err(FactoryEffectStoreError::Integrity(
                    "runtime mutation map identity or factory binding is invalid".to_string(),
                ));
            }
            if mutation.phase != MutationPhase::Complete {
                pending_count = pending_count.saturating_add(1);
                let expected_active = match mutation.phase {
                    MutationPhase::IntentRecorded | MutationPhase::DeploymentCommitted => {
                        mutation.before.as_ref()
                    }
                    MutationPhase::StatePointerCommitted => Some(&mutation.after),
                    MutationPhase::Complete => unreachable!(),
                };
                if self.active.as_ref() != expected_active {
                    return Err(FactoryEffectStoreError::Integrity(
                        "pending runtime mutation phase disagrees with its active snapshot pointer"
                            .to_string(),
                    ));
                }
            }
        }
        if pending_count > 1 {
            return Err(FactoryEffectStoreError::Integrity(
                "factory effect store contains more than one pending runtime mutation".to_string(),
            ));
        }
        for (migration_id, migration) in &self.migrations {
            migration.validate()?;
            if migration_id != &migration.migration_id {
                return Err(FactoryEffectStoreError::Integrity(
                    "stored migration map key differs from its exact identity".to_string(),
                ));
            }
        }
        let mut material = self.clone();
        material.state_digest = ContentDigest::from_bytes(&[]);
        require_digest(
            "factory effect store",
            &self.state_digest,
            &digest_json_content(&("wasm-biotic:m5-factory-effect-store-state:v2", material))?,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredEffectIntent {
    schema: String,
    operation: CapabilityOperation,
    logical_effect_id: String,
    request_digest: ContentDigest,
    request_bytes_digest: ContentDigest,
    intent_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredEffectResult {
    schema: String,
    operation: CapabilityOperation,
    logical_effect_id: String,
    request_digest: ContentDigest,
    response_digest: ContentDigest,
    response_bytes: Vec<u8>,
    record_digest: ContentDigest,
}

/// Read-only, digest-sealed projection of one accepted backend effect result.
///
/// This exposes no replay or mutation method. It exists so a higher-level
/// reopen audit can independently compare M3's receipt against the exact
/// intent/result fact retained by the physical effect owner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactoryEffectBackendFact {
    pub operation: CapabilityOperation,
    pub logical_effect_id: String,
    pub request_digest: ContentDigest,
    pub request_bytes_digest: ContentDigest,
    pub intent_digest: ContentDigest,
    pub response_digest: ContentDigest,
    pub response_bytes: Vec<u8>,
    pub result_record_digest: ContentDigest,
    pub fact_digest: ContentDigest,
}

pub struct FactoryEffectStore {
    root: PathBuf,
    packages_root: PathBuf,
    state_blobs_root: PathBuf,
    candidates_root: PathBuf,
    intents_root: PathBuf,
    results_root: PathBuf,
    faults_root: PathBuf,
    deployment: LocalDeploymentService,
    limits: ComponentExecutionLimits,
    state: Mutex<FactoryEffectStoreState>,
}

impl FactoryEffectStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, FactoryEffectStoreError> {
        let root = secure_root(root.as_ref())?;
        let packages_root = secure_child(&root, PACKAGE_DIRECTORY)?;
        let state_blobs_root = secure_child(&root, STATE_BLOB_DIRECTORY)?;
        let candidates_root = secure_child(&root, CANDIDATE_DIRECTORY)?;
        let deployment_root = secure_child(&root, DEPLOYMENT_DIRECTORY)?;
        let intents_root = secure_child(&root, EFFECT_INTENT_DIRECTORY)?;
        let results_root = secure_child(&root, EFFECT_RESULT_DIRECTORY)?;
        let faults_root = secure_child(&root, FAULT_DIRECTORY)?;
        let deployment = LocalDeploymentService::open(&deployment_root, &candidates_root)?;
        let state_path = root.join(STATE_FILE);
        let state = if state_path.exists() {
            let state: FactoryEffectStoreState = read_json(&state_path, MAX_DOMAIN_BYTES)?;
            state.validate()?;
            state
        } else {
            let state = FactoryEffectStoreState::empty()?;
            write_json_atomic(&root, &state_path, &state)?;
            state
        };
        let store = Self {
            root,
            packages_root,
            state_blobs_root,
            candidates_root,
            intents_root,
            results_root,
            faults_root,
            deployment,
            limits: ComponentExecutionLimits::default(),
            state: Mutex::new(state),
        };
        store.validate_persisted_mutations()?;
        store.reconcile_mutations()?;
        store.validate_authoritative_state()?;
        Ok(store)
    }

    pub fn arm_fail_after_backend_commit(&self) -> Result<(), FactoryEffectStoreError> {
        persist_immutable(
            &self.faults_root,
            &self.faults_root.join(FAIL_AFTER_BACKEND_COMMIT),
            b"armed",
        )
    }

    pub fn arm_fail_after_deployment_commit(&self) -> Result<(), FactoryEffectStoreError> {
        persist_immutable(
            &self.faults_root,
            &self.faults_root.join(FAIL_AFTER_DEPLOYMENT_COMMIT),
            b"armed",
        )
    }

    pub fn arm_next_observation_regression(&self) -> Result<(), FactoryEffectStoreError> {
        persist_immutable(
            &self.faults_root,
            &self.faults_root.join(FAIL_NEXT_OBSERVATION_HEALTH),
            b"armed",
        )
    }

    pub fn snapshot(&self) -> Result<Option<FactoryRuntimeSnapshot>, FactoryEffectStoreError> {
        self.reconcile_mutations()?;
        self.validate_authoritative_state()?;
        Ok(self.lock_state()?.active.clone())
    }

    /// Return the independently retained fact for one logical effect without
    /// invoking or replaying the effect.
    pub fn effect_fact(
        &self,
        logical_effect_id: &str,
    ) -> Result<Option<FactoryEffectBackendFact>, FactoryEffectStoreError> {
        if logical_effect_id.trim().is_empty() {
            return Err(FactoryEffectStoreError::InvalidRequest(
                "logical effect id must not be blank".to_string(),
            ));
        }
        let key = ContentDigest::from_bytes(logical_effect_id.as_bytes()).file_stem();
        let result_path = self.results_root.join(format!("{key}.json"));
        if !result_path.exists() {
            return Ok(None);
        }
        let intent_path = self.intents_root.join(format!("{key}.json"));
        if !intent_path.exists() {
            return Err(FactoryEffectStoreError::Integrity(format!(
                "accepted backend result '{logical_effect_id}' has no durable intent"
            )));
        }
        let intent: StoredEffectIntent = read_json(&intent_path, MAX_DOMAIN_BYTES)?;
        let result: StoredEffectResult = read_json(&result_path, MAX_DOMAIN_BYTES)?;
        let fact = backend_fact(&intent, &result)?;
        if fact.logical_effect_id != logical_effect_id {
            return Err(FactoryEffectStoreError::Integrity(format!(
                "backend fact key for '{logical_effect_id}' resolves to a different logical effect"
            )));
        }
        Ok(Some(fact))
    }

    /// Scan and validate every accepted backend result in deterministic order.
    pub fn all_effect_facts(
        &self,
    ) -> Result<Vec<FactoryEffectBackendFact>, FactoryEffectStoreError> {
        let mut facts = Vec::new();
        for entry in fs::read_dir(&self.results_root)
            .map_err(|source| FactoryEffectStoreError::io(&self.results_root, source))?
        {
            let entry =
                entry.map_err(|source| FactoryEffectStoreError::io(&self.results_root, source))?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)
                .map_err(|source| FactoryEffectStoreError::io(&path, source))?;
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || path.extension().and_then(|value| value.to_str()) != Some("json")
            {
                return Err(FactoryEffectStoreError::Integrity(format!(
                    "unexpected backend effect-result entry '{}'",
                    path.display()
                )));
            }
            if facts.len() >= MAX_RECORDS {
                return Err(FactoryEffectStoreError::ResourceBound(
                    "backend effect-result journal exceeds its record bound".to_string(),
                ));
            }
            let result: StoredEffectResult = read_json(&path, MAX_DOMAIN_BYTES)?;
            let expected_key =
                ContentDigest::from_bytes(result.logical_effect_id.as_bytes()).file_stem();
            if path != self.results_root.join(format!("{expected_key}.json")) {
                return Err(FactoryEffectStoreError::Integrity(format!(
                    "backend effect result '{}' is not named by its logical identity",
                    path.display()
                )));
            }
            let intent_path = self.intents_root.join(format!("{expected_key}.json"));
            let intent: StoredEffectIntent = read_json(&intent_path, MAX_DOMAIN_BYTES)?;
            facts.push(backend_fact(&intent, &result)?);
        }
        facts.sort_by(|left, right| left.logical_effect_id.cmp(&right.logical_effect_id));
        if facts
            .windows(2)
            .any(|pair| pair[0].logical_effect_id == pair[1].logical_effect_id)
        {
            return Err(FactoryEffectStoreError::Integrity(
                "backend effect-result journal contains duplicate logical identities".to_string(),
            ));
        }
        Ok(facts)
    }

    fn apply(
        &self,
        operation: CapabilityOperation,
        request: &FactoryEffectRequest,
    ) -> Result<FactoryEffectResult, FactoryEffectStoreError> {
        self.validate_wire(operation, request)?;
        self.reconcile_mutations()?;
        let key = ContentDigest::from_bytes(request.logical_effect_id.as_bytes()).file_stem();
        let intent_path = self.intents_root.join(format!("{key}.json"));
        let result_path = self.results_root.join(format!("{key}.json"));
        let intent = self.make_intent(operation, request)?;
        persist_immutable(
            &self.intents_root,
            &intent_path,
            &serde_json::to_vec_pretty(&intent)?,
        )?;
        if result_path.exists() {
            let stored: StoredEffectResult = read_json(&result_path, MAX_DOMAIN_BYTES)?;
            self.validate_stored_result(operation, request, &stored)?;
            return Ok(FactoryEffectResult::new(request, stored.response_bytes));
        }

        let response_bytes = match operation {
            CapabilityOperation::FactoryInitialize => {
                let domain: FactoryInitializeRequest = decode_exact(&request.exact_request_bytes)?;
                serde_json::to_vec(&self.initialize(domain)?)?
            }
            CapabilityOperation::FactoryExecute => {
                let domain: FactoryExecuteRequest = decode_exact(&request.exact_request_bytes)?;
                serde_json::to_vec(&self.execute_active(domain)?)?
            }
            CapabilityOperation::FactoryProviderProposal => {
                let domain: FactoryProviderProposalRequest =
                    decode_exact(&request.exact_request_bytes)?;
                serde_json::to_vec(&self.admit_provider_proposal(domain)?)?
            }
            CapabilityOperation::FactoryShadow => {
                let domain: ShadowExecutionRequest = decode_exact(&request.exact_request_bytes)?;
                serde_json::to_vec(&self.shadow(domain)?)?
            }
            CapabilityOperation::FactoryStateMigrate => {
                let domain: FactoryMigrationEffectRequest =
                    decode_exact(&request.exact_request_bytes)?;
                serde_json::to_vec(&self.prepare_migration(domain)?)?
            }
            CapabilityOperation::FactoryActivate => {
                let domain: ActivationRequest = decode_exact(&request.exact_request_bytes)?;
                serde_json::to_vec(&self.activate(domain)?)?
            }
            CapabilityOperation::FactoryObserve => {
                let domain: PostActivationRequest = decode_exact(&request.exact_request_bytes)?;
                serde_json::to_vec(&self.observe(domain)?)?
            }
            CapabilityOperation::FactoryRollback => {
                let domain: RecoveryRequest = decode_exact(&request.exact_request_bytes)?;
                serde_json::to_vec(&self.rollback(domain)?)?
            }
            CapabilityOperation::FactoryInspect => {
                let domain: FactoryInspectRequest = decode_exact(&request.exact_request_bytes)?;
                serde_json::to_vec(&self.inspect(domain)?)?
            }
            _ => {
                return Err(FactoryEffectStoreError::InvalidRequest(format!(
                    "operation {operation:?} is not a factory effect"
                )));
            }
        };
        if response_bytes.is_empty() || response_bytes.len() > MAX_DOMAIN_BYTES {
            return Err(FactoryEffectStoreError::ResourceBound(
                "factory effect response is outside its byte bound".to_string(),
            ));
        }
        let mut stored = StoredEffectResult {
            schema: EFFECT_RECORD_SCHEMA.to_string(),
            operation,
            logical_effect_id: request.logical_effect_id.clone(),
            request_digest: request.exact_request_digest.clone(),
            response_digest: ContentDigest::from_bytes(&response_bytes),
            response_bytes: response_bytes.clone(),
            record_digest: ContentDigest::from_bytes(&[]),
        };
        stored.record_digest = stored_effect_result_digest(&stored)?;
        persist_immutable(
            &self.results_root,
            &result_path,
            &serde_json::to_vec_pretty(&stored)?,
        )?;
        if self.consume_fault(FAIL_AFTER_BACKEND_COMMIT)? {
            return Err(FactoryEffectStoreError::Interrupted(
                "backend committed exact result before outer M3 receipt".to_string(),
            ));
        }
        Ok(FactoryEffectResult::new(request, response_bytes))
    }

    fn validate_wire(
        &self,
        operation: CapabilityOperation,
        request: &FactoryEffectRequest,
    ) -> Result<(), FactoryEffectStoreError> {
        if request.factory_id.trim().is_empty()
            || request.logical_effect_id.trim().is_empty()
            || request.exact_request_bytes.is_empty()
            || request.exact_request_bytes.len() > MAX_DOMAIN_BYTES
            || request.exact_request_digest
                != ContentDigest::from_bytes(&request.exact_request_bytes)
            || !matches!(
                operation,
                CapabilityOperation::FactoryInitialize
                    | CapabilityOperation::FactoryExecute
                    | CapabilityOperation::FactoryProviderProposal
                    | CapabilityOperation::FactoryShadow
                    | CapabilityOperation::FactoryStateMigrate
                    | CapabilityOperation::FactoryActivate
                    | CapabilityOperation::FactoryObserve
                    | CapabilityOperation::FactoryRollback
                    | CapabilityOperation::FactoryInspect
            )
        {
            return Err(FactoryEffectStoreError::InvalidRequest(
                "invalid factory effect wire request".to_string(),
            ));
        }
        let state = self.lock_state()?;
        if let Some(factory_id) = &state.factory_id
            && factory_id != &request.factory_id
        {
            return Err(FactoryEffectStoreError::Conflict(
                "factory effect request targets a different initialized factory".to_string(),
            ));
        }
        Ok(())
    }

    fn make_intent(
        &self,
        operation: CapabilityOperation,
        request: &FactoryEffectRequest,
    ) -> Result<StoredEffectIntent, FactoryEffectStoreError> {
        let mut intent = StoredEffectIntent {
            schema: EFFECT_RECORD_SCHEMA.to_string(),
            operation,
            logical_effect_id: request.logical_effect_id.clone(),
            request_digest: request.exact_request_digest.clone(),
            request_bytes_digest: ContentDigest::from_bytes(&request.exact_request_bytes),
            intent_digest: ContentDigest::from_bytes(&[]),
        };
        intent.intent_digest = digest_json_content(&(
            EFFECT_RECORD_SCHEMA,
            intent.operation,
            &intent.logical_effect_id,
            &intent.request_digest,
            &intent.request_bytes_digest,
        ))?;
        Ok(intent)
    }

    fn validate_stored_result(
        &self,
        operation: CapabilityOperation,
        request: &FactoryEffectRequest,
        stored: &StoredEffectResult,
    ) -> Result<(), FactoryEffectStoreError> {
        if stored.schema != EFFECT_RECORD_SCHEMA
            || stored.operation != operation
            || stored.logical_effect_id != request.logical_effect_id
            || stored.request_digest != request.exact_request_digest
            || stored.response_digest != ContentDigest::from_bytes(&stored.response_bytes)
        {
            return Err(FactoryEffectStoreError::Integrity(
                "stored factory effect result differs from its exact request".to_string(),
            ));
        }
        require_digest(
            "stored factory effect result",
            &stored.record_digest,
            &stored_effect_result_digest(stored)?,
        )
    }

    fn initialize(
        &self,
        request: FactoryInitializeRequest,
    ) -> Result<FactoryInitializationEvidence, FactoryEffectStoreError> {
        request.validate()?;
        let package = FactoryPackage::from_canonical_bytes(&request.package_bytes)?;
        if package.payload.factory_id != request.factory_id
            || package.payload.generation != 0
            || package.payload.parent_package_digest.is_some()
            || package
                .payload
                .boot_manifest
                .state_compatibility
                .written_schema
                != request.initial_state_schema
        {
            return Err(FactoryEffectStoreError::InvalidRequest(
                "initial package does not describe the exact generation-zero state".to_string(),
            ));
        }
        if let Some(existing) = self
            .lock_state()?
            .mutations
            .get(&request.operation_id)
            .cloned()
        {
            return match existing.receipt {
                MutationReceipt::Initialization(evidence)
                    if existing.kind == MutationKind::Initialize
                        && existing.request_digest == request.request_digest =>
                {
                    Ok(evidence)
                }
                _ => Err(FactoryEffectStoreError::Conflict(
                    "initialization operation id already names different exact work".to_string(),
                )),
            };
        }
        {
            let state = self.lock_state()?;
            if state.factory_id.is_some() || state.active.is_some() {
                return Err(FactoryEffectStoreError::Conflict(
                    "factory effect store is already initialized differently".to_string(),
                ));
            }
        }
        self.persist_package(&package, &request.package_bytes)?;
        self.persist_state_blob(&request.initial_state_bytes)?;
        let snapshot = FactoryRuntimeSnapshot::new(
            request.factory_id.clone(),
            &package,
            &request.package_bytes,
            request.initial_state_schema,
            &request.initial_state_bytes,
            None,
        )?;
        let expected_deployment_record = InitializationRecord {
            operation_id: request.operation_id.clone(),
            installed_artifact: DeploymentArtifactSnapshot {
                digest: snapshot.component_digest.clone(),
                byte_len: package.payload.genome.component_bytes.len() as u64,
            },
        };
        let deployment_record_digest = digest_json_content(&expected_deployment_record)?;
        let evidence = FactoryInitializationEvidence {
            schema: INITIALIZE_EVIDENCE_SCHEMA.to_string(),
            request_digest: request.request_digest.clone(),
            snapshot: snapshot.clone(),
            deployment_record_digest,
            evidence_digest: ContentDigest::from_bytes(&[]),
        }
        .seal()?;
        let mutation = RuntimeMutation {
            operation_id: request.operation_id.clone(),
            request_digest: request.request_digest,
            kind: MutationKind::Initialize,
            before: None,
            after: snapshot.clone(),
            intent: MutationIntent::Initialize,
            phase: MutationPhase::IntentRecorded,
            receipt: MutationReceipt::Initialization(evidence.clone()),
        };
        mutation.validate()?;
        {
            let mut state = self.lock_state()?;
            state.factory_id = Some(request.factory_id);
            state
                .mutations
                .insert(request.operation_id.clone(), mutation.clone());
            self.persist_locked_state(&mut state)?;
        }
        self.commit_deployment_mutation(&mutation)?;
        if self.consume_fault(FAIL_AFTER_DEPLOYMENT_COMMIT)? {
            return Err(FactoryEffectStoreError::Interrupted(
                "initial deployment committed before active snapshot pointer".to_string(),
            ));
        }
        self.advance_mutation(
            &request.operation_id,
            MutationPhase::DeploymentCommitted,
            None,
        )?;
        self.advance_mutation(
            &request.operation_id,
            MutationPhase::StatePointerCommitted,
            Some(snapshot),
        )?;
        self.advance_mutation(&request.operation_id, MutationPhase::Complete, None)?;
        Ok(evidence)
    }

    fn execute_active(
        &self,
        request: FactoryExecuteRequest,
    ) -> Result<FactoryExecutionResult, FactoryEffectStoreError> {
        request.validate()?;
        self.validate_authoritative_state()?;
        let snapshot = self
            .lock_state()?
            .active
            .clone()
            .ok_or(FactoryEffectStoreError::NotInitialized)?;
        if snapshot.package_digest != request.expected_package_digest {
            return Err(FactoryEffectStoreError::Conflict(
                "active package differs from the exact execution request".to_string(),
            ));
        }
        let active_bytes = self.deployment.read_active_bytes()?;
        require_digest(
            "active deployed component",
            &snapshot.component_digest,
            &ContentDigest::from_bytes(&active_bytes),
        )?;
        let trace = execute_component_i32_export(
            &active_bytes,
            crate::factory_reproduction::REFERENCE_EXPORT,
            request.input,
            &self.limits,
        )?;
        let output = trace.output.ok_or_else(|| {
            FactoryEffectStoreError::Execution(
                "active factory component returned no i32 output".to_string(),
            )
        })?;
        FactoryExecutionResult {
            schema: EXECUTE_RESULT_SCHEMA.to_string(),
            request_digest: request.request_digest,
            snapshot,
            input: request.input,
            output,
            trace,
            result_digest: ContentDigest::from_bytes(&[]),
        }
        .seal()
    }

    fn admit_provider_proposal(
        &self,
        request: FactoryProviderProposalRequest,
    ) -> Result<FactoryProviderProposalResult, FactoryEffectStoreError> {
        request.validate()?;
        self.validate_authoritative_state()?;
        let active = self
            .lock_state()?
            .active
            .clone()
            .ok_or(FactoryEffectStoreError::NotInitialized)?;
        if active.package_digest != request.qualification_request.package_digest {
            return Err(FactoryEffectStoreError::Conflict(
                "provider proposal qualification does not name the active incumbent package"
                    .to_string(),
            ));
        }
        FactoryProviderProposalResult::from_request(&request)
    }

    fn shadow(
        &self,
        request: ShadowExecutionRequest,
    ) -> Result<ShadowExecutionEvidence, FactoryEffectStoreError> {
        self.validate_authoritative_state()?;
        let incumbent = FactoryPackage::from_canonical_bytes(&request.incumbent_package_bytes)?;
        let challenger = FactoryPackage::from_canonical_bytes(&request.challenger_package_bytes)?;
        if incumbent.package_digest != request.incumbent_package_digest
            || challenger.package_digest != request.challenger_package_digest
        {
            return Err(FactoryEffectStoreError::Integrity(
                "shadow package bytes differ from their declared identities".to_string(),
            ));
        }
        let active = self
            .lock_state()?
            .active
            .clone()
            .ok_or(FactoryEffectStoreError::NotInitialized)?;
        if active.package_digest != request.incumbent_package_digest {
            return Err(FactoryEffectStoreError::Conflict(
                "shadow incumbent is not the active factory package".to_string(),
            ));
        }
        let incumbent_observations = request
            .gate
            .benchmarks
            .iter()
            .map(|benchmark| self.execute_benchmark(&incumbent, benchmark, "incumbent"))
            .collect::<Vec<_>>();
        let challenger_observations = request
            .gate
            .benchmarks
            .iter()
            .map(|benchmark| self.execute_benchmark(&challenger, benchmark, "challenger"))
            .collect::<Vec<_>>();
        let runnable = challenger_observations
            .iter()
            .all(|observation| observation.terminal == ExecutionTerminal::Succeeded);
        let exact_identity = challenger.payload.genome.component_digest
            == ContentDigest::from_bytes(&challenger.payload.genome.component_bytes)
            && challenger.package_digest
                == ContentDigest::from_bytes(&request.challenger_package_bytes);
        let deployment = self.deployment.state()?;
        let durable_rollback = deployment
            .active_artifact
            .as_ref()
            .is_some_and(|route| route.digest == active.component_digest)
            && !deployment.initializations.is_empty();
        let invariant_observations = request
            .gate
            .invariants
            .iter()
            .map(|invariant| {
                let satisfied = match invariant.kind {
                    InvariantKind::StableInterface => {
                        challenger.payload.stable_interface.validate().is_ok()
                    }
                    InvariantKind::RunnableComponent => runnable,
                    InvariantKind::ExactPackageIdentity => exact_identity,
                    InvariantKind::BoundedCapabilities => {
                        challenger.payload.genome.component_bytes.len() as u64
                            <= request.gate.budgets.max_component_bytes
                    }
                    InvariantKind::DurableRollback => durable_rollback,
                };
                let evidence_digest = digest_json_content(&(
                    "wasm-biotic:m5-shadow-invariant:v2",
                    &invariant.invariant_id,
                    &challenger.package_digest,
                    satisfied,
                    &incumbent_observations,
                    &challenger_observations,
                ))?;
                Ok(InvariantObservation {
                    invariant_id: invariant.invariant_id.clone(),
                    package_digest: challenger.package_digest.clone(),
                    satisfied,
                    evidence_digest,
                })
            })
            .collect::<Result<Vec<_>, FactoryEffectStoreError>>()?;
        ShadowExecutionEvidence {
            request_digest: request.request_digest.clone(),
            resource_usage: ResourceUsage {
                shadow_tasks: (incumbent_observations.len() + challenger_observations.len()) as u32,
                component_bytes: challenger.payload.genome.component_bytes.len() as u64,
                state_bytes: self.read_state_blob(&active.state_blob_digest)?.len() as u64,
            },
            incumbent_observations,
            challenger_observations,
            invariant_observations,
            evidence_digest: ContentDigest::from_bytes(&[]),
        }
        .seal()
        .map_err(Into::into)
    }

    fn prepare_migration(
        &self,
        effect: FactoryMigrationEffectRequest,
    ) -> Result<MigrationReceipt, FactoryEffectStoreError> {
        effect.validate()?;
        let request = &effect.request;
        require_digest(
            "factory migration request",
            &request.request_digest,
            &migration_request_digest(request)?,
        )?;
        let active = self
            .lock_state()?
            .active
            .clone()
            .ok_or(FactoryEffectStoreError::NotInitialized)?;
        if active.package_digest != request.incumbent_package_digest
            || active.state_schema != request.plan.from_schema
            || request.plan.rollback_schema != active.state_schema
        {
            return Err(FactoryEffectStoreError::Conflict(
                "migration does not target the exact active package and state schema".to_string(),
            ));
        }
        let before = self.read_state_blob(&active.state_blob_digest)?;
        if before.len() as u64 > request.plan.maximum_state_bytes {
            return Err(FactoryEffectStoreError::ResourceBound(
                "active state exceeds the migration input budget".to_string(),
            ));
        }
        let maximum = usize::try_from(request.plan.maximum_state_bytes)
            .unwrap_or(usize::MAX)
            .min(MAX_STATE_BYTES);
        let migrated = effect.artifacts.forward.execute(&before, maximum)?;
        let restored = effect.artifacts.rollback.execute(&migrated, maximum)?;
        if restored != before {
            return Err(FactoryEffectStoreError::Migration(
                "approved rollback artifact did not reproduce the exact original state".to_string(),
            ));
        }
        self.persist_state_blob(&migrated)?;
        let receipt = MigrationReceipt {
            request_digest: request.request_digest.clone(),
            migration_id: request.plan.migration_id.clone(),
            from_schema: request.plan.from_schema,
            to_schema: request.plan.to_schema,
            pre_migration_state_digest: ContentDigest::from_bytes(&before),
            post_migration_state_digest: ContentDigest::from_bytes(&migrated),
            rollback_backup_digest: ContentDigest::from_bytes(&before),
            rollback_verified: true,
            receipt_digest: ContentDigest::from_bytes(&[]),
        }
        .seal()?;
        let stored = StoredMigration {
            migration_id: request.plan.migration_id.clone(),
            request_digest: request.request_digest.clone(),
            request: request.clone(),
            incumbent_snapshot_digest: active.snapshot_digest,
            challenger_package_digest: request.challenger_package_digest.clone(),
            prepared_state_blob_digest: ContentDigest::from_bytes(&migrated),
            artifacts: effect.artifacts,
            receipt: receipt.clone(),
        };
        let mut state = self.lock_state()?;
        if let Some(existing) = state.migrations.get(&stored.migration_id) {
            if existing != &stored {
                return Err(FactoryEffectStoreError::Conflict(
                    "migration id already names different exact artifacts or state".to_string(),
                ));
            }
        } else {
            state.migrations.insert(stored.migration_id.clone(), stored);
            self.persist_locked_state(&mut state)?;
        }
        Ok(receipt)
    }

    fn activate(
        &self,
        request: ActivationRequest,
    ) -> Result<ActivationReceipt, FactoryEffectStoreError> {
        require_digest(
            "factory activation request",
            &request.request_digest,
            &activation_request_digest(&request)?,
        )?;
        let challenger = FactoryPackage::from_canonical_bytes(&request.challenger_package_bytes)?;
        if challenger.package_digest != request.challenger_package_digest {
            return Err(FactoryEffectStoreError::Integrity(
                "activation package bytes differ from the approved identity".to_string(),
            ));
        }
        let before = self
            .lock_state()?
            .active
            .clone()
            .ok_or(FactoryEffectStoreError::NotInitialized)?;
        let operation_id = format!("m5-activation:{}", request.cycle_id);
        if let Some(existing) = self.lock_state()?.mutations.get(&operation_id).cloned() {
            return match existing.receipt {
                MutationReceipt::Activation(receipt)
                    if existing.kind == MutationKind::Activate
                        && existing.request_digest == request.request_digest =>
                {
                    Ok(receipt)
                }
                _ => Err(FactoryEffectStoreError::Conflict(
                    "activation operation id already names different exact work".to_string(),
                )),
            };
        }
        let challenger_state_schema = challenger
            .payload
            .boot_manifest
            .state_compatibility
            .written_schema;
        if before.package_digest != request.incumbent_package_digest
            || request.target_state_schema == 0
            || request.target_state_schema != challenger_state_schema
        {
            return Err(FactoryEffectStoreError::Conflict(
                "activation precondition or target schema differs from the exact packages"
                    .to_string(),
            ));
        }
        let state_blob_digest = if request.target_state_schema == before.state_schema {
            before.state_blob_digest.clone()
        } else {
            let state = self.lock_state()?;
            let exact = state
                .migrations
                .values()
                .filter(|migration| {
                    migration.request.cycle_id == request.cycle_id
                        && migration.request.incumbent_package_digest == before.package_digest
                        && migration.incumbent_snapshot_digest == before.snapshot_digest
                        && migration.receipt.from_schema == before.state_schema
                        && migration.challenger_package_digest == challenger.package_digest
                        && migration.receipt.to_schema == request.target_state_schema
                        && migration.receipt.pre_migration_state_digest == before.state_blob_digest
                        && migration.receipt.rollback_backup_digest == before.state_blob_digest
                        && migration.receipt.post_migration_state_digest
                            == migration.prepared_state_blob_digest
                        && migration.receipt.rollback_verified
                })
                .collect::<Vec<_>>();
            if exact.len() != 1 {
                return Err(FactoryEffectStoreError::Conflict(
                    "activation requires one exact prepared migration from the active snapshot to the challenger schema".to_string(),
                ));
            }
            exact[0].prepared_state_blob_digest.clone()
        };
        let state_bytes = self.read_state_blob(&state_blob_digest)?;
        self.persist_package(&challenger, &request.challenger_package_bytes)?;
        let candidate_name = format!(
            "{}.component",
            challenger.payload.genome.component_digest.file_stem()
        );
        persist_immutable(
            &self.candidates_root,
            &self.candidates_root.join(&candidate_name),
            &challenger.payload.genome.component_bytes,
        )?;
        let after = FactoryRuntimeSnapshot::new(
            before.factory_id.clone(),
            &challenger,
            &request.challenger_package_bytes,
            request.target_state_schema,
            &state_bytes,
            Some(operation_id.clone()),
        )?;
        let receipt = ActivationReceipt {
            activation_id: operation_id.clone(),
            request_digest: request.request_digest.clone(),
            previous_package_digest: before.package_digest.clone(),
            active_package_digest: after.package_digest.clone(),
            active_package_bytes_digest: after.package_bytes_digest.clone(),
            active_state_schema: after.state_schema,
            receipt_digest: ContentDigest::from_bytes(&[]),
        }
        .seal()?;
        let intent = MutationIntent::Activate {
            cycle_id: request.cycle_id.clone(),
            candidate_path: PathBuf::from(candidate_name),
            approval_digest: request.approval_digest.clone(),
            gate_decision_digest: request.gate_decision_digest.clone(),
        };
        let mutation = RuntimeMutation {
            operation_id: operation_id.clone(),
            request_digest: request.request_digest.clone(),
            kind: MutationKind::Activate,
            before: Some(before.clone()),
            after: after.clone(),
            intent,
            phase: MutationPhase::IntentRecorded,
            receipt: MutationReceipt::Activation(receipt.clone()),
        };
        mutation.validate()?;
        {
            let mut state = self.lock_state()?;
            state
                .mutations
                .insert(operation_id.clone(), mutation.clone());
            self.persist_locked_state(&mut state)?;
        }
        self.commit_deployment_mutation(&mutation)?;
        if self.consume_fault(FAIL_AFTER_DEPLOYMENT_COMMIT)? {
            return Err(FactoryEffectStoreError::Interrupted(
                "deployment committed before active snapshot pointer".to_string(),
            ));
        }
        self.advance_mutation(&operation_id, MutationPhase::DeploymentCommitted, None)?;
        self.advance_mutation(
            &operation_id,
            MutationPhase::StatePointerCommitted,
            Some(after),
        )?;
        self.advance_mutation(&operation_id, MutationPhase::Complete, None)?;
        Ok(receipt)
    }

    fn observe(
        &self,
        request: PostActivationRequest,
    ) -> Result<PostActivationEvidence, FactoryEffectStoreError> {
        self.validate_authoritative_state()?;
        let snapshot = self
            .lock_state()?
            .active
            .clone()
            .ok_or(FactoryEffectStoreError::NotInitialized)?;
        if snapshot.package_digest != request.active_package_digest
            || snapshot.package_bytes_digest != request.active_package_bytes_digest
            || snapshot.activation_id.as_ref() != Some(&request.activation_id)
        {
            return Err(FactoryEffectStoreError::Conflict(
                "observation does not target the exact active snapshot".to_string(),
            ));
        }
        let active_bytes = self.deployment.read_active_bytes()?;
        let mut task_observations = Vec::new();
        for index in 0..request.minimum_successes {
            let input = i32::try_from(index).unwrap_or(i32::MAX);
            let start = Instant::now();
            let trace = execute_component_i32_export(
                &active_bytes,
                crate::factory_reproduction::REFERENCE_EXPORT,
                input,
                &self.limits,
            );
            let (terminal, output_digest, health) = match trace {
                Ok(trace) if trace.output.is_some() => (
                    ExecutionTerminal::Succeeded,
                    trace
                        .output
                        .map(|output| ContentDigest::from_bytes(&output.to_le_bytes())),
                    HealthStatus::Healthy,
                ),
                _ => (ExecutionTerminal::Failed, None, HealthStatus::Unhealthy),
            };
            task_observations.push(TaskExecutionObservation {
                execution_id: format!("m5-live:{}:{index}", request.activation_id),
                benchmark_id: format!("m5-live-reference:{index}"),
                package_digest: snapshot.package_digest.clone(),
                request_digest: ContentDigest::from_bytes(&input.to_le_bytes()),
                output_digest,
                terminal,
                health,
                duration_ms: u64::try_from(start.elapsed().as_millis())
                    .unwrap_or(u64::MAX)
                    .max(1),
            });
        }
        let forced_regression = self.consume_fault(FAIL_NEXT_OBSERVATION_HEALTH)?;
        let healthy = !forced_regression
            && task_observations.iter().all(|observation| {
                observation.terminal == ExecutionTerminal::Succeeded
                    && observation.health == HealthStatus::Healthy
            });
        let health_observations = vec![HealthObservation {
            check_id: "m5-active-route-health".to_string(),
            active_package_digest: snapshot.package_digest.clone(),
            status: if healthy {
                HealthStatus::Healthy
            } else {
                HealthStatus::Unhealthy
            },
            measurement_digest: digest_json_content(&(
                "wasm-biotic:m5-active-health:v2",
                &snapshot,
                &task_observations,
            ))?,
        }];
        let evidence = PostActivationEvidence {
            request_digest: request.request_digest.clone(),
            active_package_digest: snapshot.package_digest.clone(),
            task_observations,
            health_observations,
            evidence_digest: ContentDigest::from_bytes(&[]),
        }
        .seal()?;
        let evidence_bytes = serde_json::to_vec(&evidence)?;
        self.deployment.record_observation(
            &DeploymentObservationRequest {
                observation_id: format!("m5-observation:{}", request.cycle_id),
                activation_id: request.activation_id.clone(),
                expected_active_digest: snapshot.component_digest.clone(),
                outcome: if healthy {
                    DeploymentObservationOutcome::Healthy
                } else {
                    DeploymentObservationOutcome::Regressed
                },
                summary: if healthy {
                    "exact routed reference tasks are healthy".to_string()
                } else {
                    "exact routed reference task regressed".to_string()
                },
            },
            &evidence_bytes,
        )?;
        let stored = StoredObservation {
            observation_id: format!("m5-observation:{}", request.cycle_id),
            request_digest: request.request_digest,
            evidence: evidence.clone(),
        };
        let mut state = self.lock_state()?;
        if let Some(existing) = state.observations.get(&stored.observation_id) {
            if existing != &stored {
                return Err(FactoryEffectStoreError::Conflict(
                    "observation id already contains different exact measurements".to_string(),
                ));
            }
        } else {
            state
                .observations
                .insert(stored.observation_id.clone(), stored);
            self.persist_locked_state(&mut state)?;
        }
        Ok(evidence)
    }

    fn rollback(
        &self,
        request: RecoveryRequest,
    ) -> Result<RecoveryReceipt, FactoryEffectStoreError> {
        require_digest(
            "factory recovery request",
            &request.request_digest,
            &recovery_request_digest(&request)?,
        )?;
        let restore = FactoryPackage::from_canonical_bytes(&request.restore_package_bytes)?;
        if restore.package_digest != request.restore_package_digest {
            return Err(FactoryEffectStoreError::Integrity(
                "rollback package bytes differ from the retained identity".to_string(),
            ));
        }
        let operation_id = request.recovery_id.clone();
        if let Some(existing) = self.lock_state()?.mutations.get(&operation_id).cloned() {
            return match existing.receipt {
                MutationReceipt::Rollback(receipt)
                    if existing.kind == MutationKind::Rollback
                        && existing.request_digest == request.request_digest =>
                {
                    Ok(receipt)
                }
                _ => Err(FactoryEffectStoreError::Conflict(
                    "rollback operation id already names different exact work".to_string(),
                )),
            };
        }
        let current = self
            .lock_state()?
            .active
            .clone()
            .ok_or(FactoryEffectStoreError::NotInitialized)?;
        if current.package_digest == request.restore_package_digest {
            if current.package_bytes_digest
                != ContentDigest::from_bytes(&request.restore_package_bytes)
                || current.state_schema != request.restore_state_schema
            {
                return Err(FactoryEffectStoreError::Integrity(
                    "already-restored active snapshot differs from the recovery request"
                        .to_string(),
                ));
            }
            return RecoveryReceipt {
                recovery_id: request.recovery_id,
                request_digest: request.request_digest,
                restored_package_digest: current.package_digest,
                restored_package_bytes_digest: current.package_bytes_digest,
                restored_state_schema: current.state_schema,
                state_readable: !self.read_state_blob(&current.state_blob_digest)?.is_empty(),
                receipt_digest: ContentDigest::from_bytes(&[]),
            }
            .seal()
            .map_err(Into::into);
        }
        let retained = {
            let state = self.lock_state()?;
            state
                .mutations
                .values()
                .rev()
                .find_map(|mutation| {
                    (mutation.kind == MutationKind::Activate
                        && mutation.after.package_digest == current.package_digest
                        && mutation.before.as_ref().is_some_and(|before| {
                            before.package_digest == request.restore_package_digest
                        }))
                    .then(|| mutation.before.clone())
                    .flatten()
                })
                .ok_or_else(|| {
                    FactoryEffectStoreError::Conflict(
                        "active snapshot has no exact retained rollback edge".to_string(),
                    )
                })?
        };
        if retained.state_schema != request.restore_state_schema
            || retained.package_bytes_digest
                != ContentDigest::from_bytes(&request.restore_package_bytes)
        {
            return Err(FactoryEffectStoreError::Integrity(
                "retained rollback snapshot differs from the recovery request".to_string(),
            ));
        }
        let activation_id = current.activation_id.clone().ok_or_else(|| {
            FactoryEffectStoreError::Integrity(
                "active challenger snapshot has no activation identity".to_string(),
            )
        })?;
        let receipt = RecoveryReceipt {
            recovery_id: request.recovery_id.clone(),
            request_digest: request.request_digest.clone(),
            restored_package_digest: retained.package_digest.clone(),
            restored_package_bytes_digest: retained.package_bytes_digest.clone(),
            restored_state_schema: retained.state_schema,
            state_readable: !self
                .read_state_blob(&retained.state_blob_digest)?
                .is_empty(),
            receipt_digest: ContentDigest::from_bytes(&[]),
        }
        .seal()?;
        let mutation = RuntimeMutation {
            operation_id: operation_id.clone(),
            request_digest: request.request_digest.clone(),
            kind: MutationKind::Rollback,
            before: Some(current.clone()),
            after: retained.clone(),
            intent: MutationIntent::Rollback {
                cycle_id: request.cycle_id.clone(),
                activation_id,
                interrupted_stage: request.interrupted_stage,
                migration_receipt: request.migration_receipt.clone(),
                activation_receipt: request.activation_receipt.clone(),
                reason: request.reason.clone(),
            },
            phase: MutationPhase::IntentRecorded,
            receipt: MutationReceipt::Rollback(receipt.clone()),
        };
        mutation.validate()?;
        {
            let mut state = self.lock_state()?;
            state
                .mutations
                .insert(operation_id.clone(), mutation.clone());
            self.persist_locked_state(&mut state)?;
        }
        self.commit_deployment_mutation(&mutation)?;
        if self.consume_fault(FAIL_AFTER_DEPLOYMENT_COMMIT)? {
            return Err(FactoryEffectStoreError::Interrupted(
                "rollback route committed before active snapshot pointer".to_string(),
            ));
        }
        self.advance_mutation(&operation_id, MutationPhase::DeploymentCommitted, None)?;
        self.advance_mutation(
            &operation_id,
            MutationPhase::StatePointerCommitted,
            Some(retained),
        )?;
        self.advance_mutation(&operation_id, MutationPhase::Complete, None)?;
        Ok(receipt)
    }

    fn inspect(
        &self,
        request: FactoryInspectRequest,
    ) -> Result<FactoryRuntimeInspection, FactoryEffectStoreError> {
        request.validate()?;
        self.reconcile_mutations()?;
        self.validate_authoritative_state()?;
        let state = self.lock_state()?;
        if state.factory_id.as_deref() != Some(request.factory_id.as_str()) {
            return Err(FactoryEffectStoreError::Conflict(
                "inspection targets a different factory".to_string(),
            ));
        }
        let deployment = self.deployment.state()?;
        FactoryRuntimeInspection {
            schema: INSPECTION_SCHEMA.to_string(),
            factory_id: request.factory_id,
            active: state.active.clone(),
            mutation_count: state.mutations.len(),
            migration_count: state.migrations.len(),
            observation_count: state.observations.len(),
            deployment_active_component_digest: deployment
                .active_artifact
                .map(|artifact| artifact.digest),
            in_flight: state
                .mutations
                .values()
                .any(|mutation| mutation.phase != MutationPhase::Complete)
                || deployment.in_flight.is_some(),
            inspection_digest: ContentDigest::from_bytes(&[]),
        }
        .seal()
    }

    fn execute_benchmark(
        &self,
        package: &FactoryPackage,
        benchmark: &BenchmarkSpec,
        side: &str,
    ) -> TaskExecutionObservation {
        let request_digest = ContentDigest::from_bytes(&benchmark.request_bytes);
        let start = Instant::now();
        let execution = <[u8; 4]>::try_from(benchmark.request_bytes.as_slice())
            .ok()
            .and_then(|bytes| {
                execute_component_i32_export(
                    &package.payload.genome.component_bytes,
                    package.payload.stable_interface.exported_function.clone(),
                    i32::from_le_bytes(bytes),
                    &self.limits,
                )
                .ok()
            });
        match execution {
            Some(trace) if trace.output.is_some() => TaskExecutionObservation {
                execution_id: format!("{side}:{}", benchmark.benchmark_id),
                benchmark_id: benchmark.benchmark_id.clone(),
                package_digest: package.package_digest.clone(),
                request_digest,
                output_digest: trace
                    .output
                    .map(|output| ContentDigest::from_bytes(&output.to_le_bytes())),
                terminal: ExecutionTerminal::Succeeded,
                health: HealthStatus::Healthy,
                duration_ms: u64::try_from(start.elapsed().as_millis())
                    .unwrap_or(u64::MAX)
                    .max(1),
            },
            _ => TaskExecutionObservation {
                execution_id: format!("{side}:{}", benchmark.benchmark_id),
                benchmark_id: benchmark.benchmark_id.clone(),
                package_digest: package.package_digest.clone(),
                request_digest,
                output_digest: None,
                terminal: ExecutionTerminal::Failed,
                health: HealthStatus::Unhealthy,
                duration_ms: u64::try_from(start.elapsed().as_millis())
                    .unwrap_or(u64::MAX)
                    .max(1),
            },
        }
    }

    fn validate_persisted_mutations(&self) -> Result<(), FactoryEffectStoreError> {
        let state = self.lock_state()?.clone();
        for mutation in state.mutations.values() {
            self.validate_runtime_mutation_artifacts(mutation)?;
        }
        for migration in state.migrations.values() {
            migration.validate()?;
            let prepared = self.read_state_blob(&migration.prepared_state_blob_digest)?;
            require_digest(
                "prepared migration state",
                &migration.receipt.post_migration_state_digest,
                &ContentDigest::from_bytes(&prepared),
            )?;
            let incumbent = state
                .active
                .iter()
                .chain(
                    state
                        .mutations
                        .values()
                        .flat_map(|mutation| mutation.before.iter().chain([&mutation.after])),
                )
                .find(|snapshot| snapshot.snapshot_digest == migration.incumbent_snapshot_digest)
                .ok_or_else(|| {
                    FactoryEffectStoreError::Integrity(format!(
                        "migration '{}' cites an unknown incumbent snapshot",
                        migration.migration_id
                    ))
                })?;
            if incumbent.package_digest != migration.request.incumbent_package_digest
                || incumbent.state_schema != migration.receipt.from_schema
                || incumbent.state_blob_digest != migration.receipt.pre_migration_state_digest
            {
                return Err(FactoryEffectStoreError::Integrity(format!(
                    "migration '{}' changed its exact incumbent state",
                    migration.migration_id
                )));
            }
            let challenger_path = self.packages_root.join(format!(
                "{}.json",
                migration.challenger_package_digest.file_stem()
            ));
            if challenger_path.exists() {
                let challenger_bytes = self.read_package(&migration.challenger_package_digest)?;
                let challenger = FactoryPackage::from_canonical_bytes(&challenger_bytes)?;
                if challenger
                    .payload
                    .boot_manifest
                    .state_compatibility
                    .written_schema
                    != migration.receipt.to_schema
                {
                    return Err(FactoryEffectStoreError::Integrity(format!(
                        "migration '{}' target schema differs from its challenger package",
                        migration.migration_id
                    )));
                }
            }
        }
        Ok(())
    }

    fn validate_runtime_mutation_artifacts(
        &self,
        mutation: &RuntimeMutation,
    ) -> Result<(), FactoryEffectStoreError> {
        mutation.validate()?;
        let (after_package, after_package_bytes, after_state_bytes) =
            self.load_snapshot_artifacts(&mutation.after)?;
        let before_artifacts = mutation
            .before
            .as_ref()
            .map(|before| self.load_snapshot_artifacts(before))
            .transpose()?;

        match (&mutation.intent, &mutation.receipt) {
            (MutationIntent::Initialize, MutationReceipt::Initialization(evidence)) => {
                let rederived = FactoryInitializeRequest::new(
                    mutation.operation_id.clone(),
                    mutation.after.factory_id.clone(),
                    after_package_bytes,
                    mutation.after.state_schema,
                    after_state_bytes,
                )?;
                let deployment_record = InitializationRecord {
                    operation_id: mutation.operation_id.clone(),
                    installed_artifact: DeploymentArtifactSnapshot {
                        digest: mutation.after.component_digest.clone(),
                        byte_len: after_package.payload.genome.component_bytes.len() as u64,
                    },
                };
                if rederived.request_digest != mutation.request_digest
                    || evidence.deployment_record_digest != digest_json_content(&deployment_record)?
                {
                    return Err(FactoryEffectStoreError::Integrity(
                        "initialization mutation cannot rederive its exact request or deployment record"
                            .to_string(),
                    ));
                }
            }
            (
                MutationIntent::Activate {
                    cycle_id,
                    candidate_path,
                    approval_digest,
                    gate_decision_digest,
                },
                MutationReceipt::Activation(_),
            ) => {
                let (before, _, _) = before_artifacts.as_ref().ok_or_else(|| {
                    FactoryEffectStoreError::Integrity(
                        "activation mutation lost its incumbent artifacts".to_string(),
                    )
                })?;
                let rederived = ActivationRequest {
                    cycle_id: cycle_id.clone(),
                    incumbent_package_digest: before.package_digest.clone(),
                    challenger_package_digest: after_package.package_digest.clone(),
                    challenger_package_bytes: after_package_bytes,
                    approval_digest: approval_digest.clone(),
                    gate_decision_digest: gate_decision_digest.clone(),
                    target_state_schema: mutation.after.state_schema,
                    request_digest: mutation.request_digest.clone(),
                };
                let candidate_bytes =
                    read_bounded(&self.candidates_root.join(candidate_path), MAX_DOMAIN_BYTES)?;
                if activation_request_digest(&rederived)? != mutation.request_digest
                    || candidate_bytes != after_package.payload.genome.component_bytes
                    || ContentDigest::from_bytes(&candidate_bytes)
                        != mutation.after.component_digest
                {
                    return Err(FactoryEffectStoreError::Integrity(
                        "activation mutation cannot rederive its exact request and candidate bytes"
                            .to_string(),
                    ));
                }
                if mutation.after.state_schema != mutation.before.as_ref().unwrap().state_schema {
                    let state = self.lock_state()?;
                    let exact = state
                        .migrations
                        .values()
                        .filter(|migration| {
                            migration.request.cycle_id == *cycle_id
                                && migration.request.incumbent_package_digest
                                    == mutation.before.as_ref().unwrap().package_digest
                                && migration.incumbent_snapshot_digest
                                    == mutation.before.as_ref().unwrap().snapshot_digest
                                && migration.challenger_package_digest
                                    == mutation.after.package_digest
                                && migration.receipt.from_schema
                                    == mutation.before.as_ref().unwrap().state_schema
                                && migration.receipt.to_schema == mutation.after.state_schema
                                && migration.receipt.pre_migration_state_digest
                                    == mutation.before.as_ref().unwrap().state_blob_digest
                                && migration.receipt.rollback_backup_digest
                                    == mutation.before.as_ref().unwrap().state_blob_digest
                                && migration.prepared_state_blob_digest
                                    == mutation.after.state_blob_digest
                                && migration.receipt.post_migration_state_digest
                                    == mutation.after.state_blob_digest
                                && migration.receipt.rollback_verified
                        })
                        .count();
                    if exact != 1 {
                        return Err(FactoryEffectStoreError::Integrity(
                            "activation mutation no longer has one exact prepared migration"
                                .to_string(),
                        ));
                    }
                }
            }
            (
                MutationIntent::Rollback {
                    cycle_id,
                    activation_id: _,
                    interrupted_stage,
                    migration_receipt,
                    activation_receipt,
                    reason,
                },
                MutationReceipt::Rollback(_),
            ) => {
                let rederived = RecoveryRequest {
                    recovery_id: mutation.operation_id.clone(),
                    cycle_id: cycle_id.clone(),
                    restore_package_digest: after_package.package_digest.clone(),
                    restore_package_bytes: after_package_bytes,
                    restore_state_schema: mutation.after.state_schema,
                    interrupted_stage: *interrupted_stage,
                    migration_receipt: migration_receipt.clone(),
                    activation_receipt: activation_receipt.clone(),
                    reason: reason.clone(),
                    request_digest: mutation.request_digest.clone(),
                };
                if recovery_request_digest(&rederived)? != mutation.request_digest {
                    return Err(FactoryEffectStoreError::Integrity(
                        "rollback mutation cannot rederive its exact recovery request".to_string(),
                    ));
                }
            }
            _ => {
                return Err(FactoryEffectStoreError::Integrity(
                    "runtime mutation intent and receipt changed kind".to_string(),
                ));
            }
        }
        Ok(())
    }

    fn load_snapshot_artifacts(
        &self,
        snapshot: &FactoryRuntimeSnapshot,
    ) -> Result<(FactoryPackage, Vec<u8>, Vec<u8>), FactoryEffectStoreError> {
        snapshot.validate()?;
        let package_bytes = self.read_package(&snapshot.package_digest)?;
        require_digest(
            "snapshot package bytes",
            &snapshot.package_bytes_digest,
            &ContentDigest::from_bytes(&package_bytes),
        )?;
        let package = FactoryPackage::from_canonical_bytes(&package_bytes)?;
        if package.payload.factory_id != snapshot.factory_id
            || package.payload.generation != snapshot.generation
            || package.payload.genome.component_digest != snapshot.component_digest
            || package
                .payload
                .boot_manifest
                .state_compatibility
                .written_schema
                != snapshot.state_schema
        {
            return Err(FactoryEffectStoreError::Integrity(
                "runtime snapshot no longer rederives from its immutable package".to_string(),
            ));
        }
        let state_bytes = self.read_state_blob(&snapshot.state_blob_digest)?;
        Ok((package, package_bytes, state_bytes))
    }

    fn commit_deployment_mutation(
        &self,
        mutation: &RuntimeMutation,
    ) -> Result<(), FactoryEffectStoreError> {
        self.validate_runtime_mutation_artifacts(mutation)?;
        let (after_package, _, _) = self.load_snapshot_artifacts(&mutation.after)?;
        let after_artifact = DeploymentArtifactSnapshot {
            digest: mutation.after.component_digest.clone(),
            byte_len: after_package.payload.genome.component_bytes.len() as u64,
        };
        match (&mutation.intent, &mutation.receipt) {
            (MutationIntent::Initialize, MutationReceipt::Initialization(evidence)) => {
                let record = self.deployment.initialize_active(
                    &mutation.operation_id,
                    &after_package.payload.genome.component_bytes,
                )?;
                if record.operation_id != mutation.operation_id
                    || record.installed_artifact != after_artifact
                    || digest_json_content(&record)? != evidence.deployment_record_digest
                {
                    return Err(FactoryEffectStoreError::Integrity(
                        "initial deployment result differs from its durable mutation intent"
                            .to_string(),
                    ));
                }
            }
            (
                MutationIntent::Activate {
                    cycle_id,
                    candidate_path,
                    approval_digest,
                    gate_decision_digest,
                },
                MutationReceipt::Activation(_),
            ) => {
                let before = mutation.before.as_ref().ok_or_else(|| {
                    FactoryEffectStoreError::Integrity(
                        "activation mutation has no incumbent snapshot".to_string(),
                    )
                })?;
                let (before_package, _, _) = self.load_snapshot_artifacts(before)?;
                let before_artifact = DeploymentArtifactSnapshot {
                    digest: before.component_digest.clone(),
                    byte_len: before_package.payload.genome.component_bytes.len() as u64,
                };
                let record = self.deployment.activate(&DeploymentActivationRequest {
                    operation_id: mutation.operation_id.clone(),
                    candidate_path: candidate_path.clone(),
                    expected_candidate_digest: mutation.after.component_digest.clone(),
                    expected_active_digest: before.component_digest.clone(),
                    approval_ref: approval_digest.to_string(),
                    comparison_ref: gate_decision_digest.to_string(),
                    observation_window_ref: format!("m5-observation:{cycle_id}"),
                })?;
                if record.operation_id != mutation.operation_id
                    || record.candidate_source != *candidate_path
                    || record.previous_artifact != before_artifact
                    || record.activated_artifact != after_artifact
                    || record.approval_ref != approval_digest.to_string()
                    || record.comparison_ref != gate_decision_digest.to_string()
                    || record.observation_window_ref != format!("m5-observation:{cycle_id}")
                    || record.rolled_back_by.is_some()
                {
                    return Err(FactoryEffectStoreError::Integrity(
                        "activation deployment result differs from its exact durable request"
                            .to_string(),
                    ));
                }
            }
            (
                MutationIntent::Rollback {
                    activation_id,
                    reason,
                    ..
                },
                MutationReceipt::Rollback(_),
            ) => {
                let before = mutation.before.as_ref().ok_or_else(|| {
                    FactoryEffectStoreError::Integrity(
                        "rollback mutation has no pre-recovery snapshot".to_string(),
                    )
                })?;
                let (before_package, _, _) = self.load_snapshot_artifacts(before)?;
                let before_artifact = DeploymentArtifactSnapshot {
                    digest: before.component_digest.clone(),
                    byte_len: before_package.payload.genome.component_bytes.len() as u64,
                };
                let record = self.deployment.rollback(&RollbackRequest {
                    operation_id: mutation.operation_id.clone(),
                    activation_id: activation_id.clone(),
                    reason_ref: reason.clone(),
                })?;
                if record.operation_id != mutation.operation_id
                    || record.activation_id != *activation_id
                    || record.from_artifact != before_artifact
                    || record.restored_artifact != after_artifact
                    || record.reason_ref != *reason
                {
                    return Err(FactoryEffectStoreError::Integrity(
                        "rollback deployment result differs from its exact durable request"
                            .to_string(),
                    ));
                }
            }
            _ => {
                return Err(FactoryEffectStoreError::Integrity(
                    "cannot commit deployment for a mismatched mutation intent".to_string(),
                ));
            }
        }
        Ok(())
    }

    fn reconcile_mutations(&self) -> Result<(), FactoryEffectStoreError> {
        loop {
            let pending = self
                .lock_state()?
                .mutations
                .values()
                .find(|mutation| mutation.phase != MutationPhase::Complete)
                .cloned();
            let Some(mutation) = pending else {
                break;
            };
            self.validate_runtime_mutation_artifacts(&mutation)?;
            let after_component = &mutation.after.component_digest;
            match mutation.phase {
                MutationPhase::IntentRecorded => {
                    self.commit_deployment_mutation(&mutation)?;
                    let route = self.deployment.active_artifact()?;
                    if route.as_ref().map(|artifact| &artifact.digest) != Some(after_component) {
                        return Err(FactoryEffectStoreError::Integrity(
                            "resumed deployment did not install the mutation's exact route"
                                .to_string(),
                        ));
                    }
                    self.advance_mutation(
                        &mutation.operation_id,
                        MutationPhase::DeploymentCommitted,
                        None,
                    )?;
                }
                MutationPhase::DeploymentCommitted => {
                    let route = self.deployment.active_artifact()?;
                    let route_digest = route.as_ref().map(|artifact| &artifact.digest);
                    if route_digest != Some(after_component) {
                        return Err(FactoryEffectStoreError::Integrity(
                            "deployment-committed mutation does not own the active route"
                                .to_string(),
                        ));
                    }
                    self.advance_mutation(
                        &mutation.operation_id,
                        MutationPhase::StatePointerCommitted,
                        Some(mutation.after.clone()),
                    )?;
                }
                MutationPhase::StatePointerCommitted => {
                    let route = self.deployment.active_artifact()?;
                    let route_digest = route.as_ref().map(|artifact| &artifact.digest);
                    let state_active = self.lock_state()?.active.clone();
                    if route_digest != Some(after_component)
                        || state_active.as_ref() != Some(&mutation.after)
                    {
                        return Err(FactoryEffectStoreError::Integrity(
                            "route and active snapshot pointer split is unexplained".to_string(),
                        ));
                    }
                    self.advance_mutation(&mutation.operation_id, MutationPhase::Complete, None)?;
                }
                MutationPhase::Complete => unreachable!(),
            }
        }
        Ok(())
    }

    fn advance_mutation(
        &self,
        operation_id: &str,
        phase: MutationPhase,
        active: Option<FactoryRuntimeSnapshot>,
    ) -> Result<(), FactoryEffectStoreError> {
        let mut state = self.lock_state()?;
        let mutation = state.mutations.get_mut(operation_id).ok_or_else(|| {
            FactoryEffectStoreError::Integrity(format!(
                "mutation '{operation_id}' disappeared during commit"
            ))
        })?;
        mutation.phase = phase;
        if let Some(active) = active {
            state.active = Some(active);
        }
        self.persist_locked_state(&mut state)
    }

    fn validate_authoritative_state(&self) -> Result<(), FactoryEffectStoreError> {
        self.validate_persisted_mutations()?;
        let state = self.lock_state()?;
        state.validate()?;
        let deployment = self.deployment.state()?;
        match (&state.active, &deployment.active_artifact) {
            (None, None) => Ok(()),
            (Some(active), Some(route)) if active.component_digest == route.digest => {
                let package_bytes = self.read_package(&active.package_digest)?;
                require_digest(
                    "active package bytes",
                    &active.package_bytes_digest,
                    &ContentDigest::from_bytes(&package_bytes),
                )?;
                let package = FactoryPackage::from_canonical_bytes(&package_bytes)?;
                if package.package_digest != active.package_digest
                    || package.payload.genome.component_digest != active.component_digest
                    || package.payload.generation != active.generation
                {
                    return Err(FactoryEffectStoreError::Integrity(
                        "active package does not rederive the runtime snapshot".to_string(),
                    ));
                }
                let state_bytes = self.read_state_blob(&active.state_blob_digest)?;
                require_digest(
                    "active state blob",
                    &active.state_blob_digest,
                    &ContentDigest::from_bytes(&state_bytes),
                )
            }
            _ => Err(FactoryEffectStoreError::Integrity(
                "deployment route and active runtime snapshot disagree".to_string(),
            )),
        }
    }

    fn persist_package(
        &self,
        package: &FactoryPackage,
        bytes: &[u8],
    ) -> Result<(), FactoryEffectStoreError> {
        if package.package_digest != ContentDigest::from_bytes(bytes) {
            return Err(FactoryEffectStoreError::Integrity(
                "factory package bytes do not match their content identity".to_string(),
            ));
        }
        persist_immutable(
            &self.packages_root,
            &self
                .packages_root
                .join(format!("{}.json", package.package_digest.file_stem())),
            bytes,
        )
    }

    fn read_package(&self, digest: &ContentDigest) -> Result<Vec<u8>, FactoryEffectStoreError> {
        let bytes = read_bounded(
            &self
                .packages_root
                .join(format!("{}.json", digest.file_stem())),
            MAX_DOMAIN_BYTES,
        )?;
        require_digest(
            "factory package CAS",
            digest,
            &ContentDigest::from_bytes(&bytes),
        )?;
        Ok(bytes)
    }

    fn persist_state_blob(&self, bytes: &[u8]) -> Result<(), FactoryEffectStoreError> {
        if bytes.is_empty() || bytes.len() > MAX_STATE_BYTES {
            return Err(FactoryEffectStoreError::ResourceBound(
                "state blob is outside its byte bound".to_string(),
            ));
        }
        let digest = ContentDigest::from_bytes(bytes);
        persist_immutable(
            &self.state_blobs_root,
            &self
                .state_blobs_root
                .join(format!("{}.bin", digest.file_stem())),
            bytes,
        )
    }

    fn read_state_blob(&self, digest: &ContentDigest) -> Result<Vec<u8>, FactoryEffectStoreError> {
        let bytes = read_bounded(
            &self
                .state_blobs_root
                .join(format!("{}.bin", digest.file_stem())),
            MAX_STATE_BYTES,
        )?;
        require_digest("state blob CAS", digest, &ContentDigest::from_bytes(&bytes))?;
        Ok(bytes)
    }

    fn persist_locked_state(
        &self,
        state: &mut FactoryEffectStoreState,
    ) -> Result<(), FactoryEffectStoreError> {
        state.seal()?;
        state.validate()?;
        write_json_atomic(&self.root, &self.root.join(STATE_FILE), state)
    }

    fn lock_state(
        &self,
    ) -> Result<MutexGuard<'_, FactoryEffectStoreState>, FactoryEffectStoreError> {
        self.state
            .lock()
            .map_err(|_| FactoryEffectStoreError::LockPoisoned)
    }

    fn consume_fault(&self, name: &str) -> Result<bool, FactoryEffectStoreError> {
        let path = self.faults_root.join(name);
        if !path.exists() {
            return Ok(false);
        }
        let consumed = self.faults_root.join(format!(
            "{name}.consumed.{}",
            TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::rename(&path, &consumed)
            .map_err(|source| FactoryEffectStoreError::io(&path, source))?;
        Ok(true)
    }
}

impl FactoryEvolutionPort for FactoryEffectStore {
    fn apply_factory_effect(
        &self,
        operation: CapabilityOperation,
        request: &FactoryEffectRequest,
        control: &InvocationControl,
    ) -> Result<FactoryEffectResult, ServiceFailure> {
        control.check()?;
        self.apply(operation, request)
            .map_err(|error| ServiceFailure::failed("m5_factory_effect_failed", error.to_string()))
    }
}

fn activation_request_digest(
    request: &ActivationRequest,
) -> Result<ContentDigest, FactoryEffectStoreError> {
    Ok(digest_json_content(&(
        "wasm-biotic:activation-request:v1",
        &request.cycle_id,
        &request.incumbent_package_digest,
        &request.challenger_package_digest,
        &request.challenger_package_bytes,
        &request.approval_digest,
        &request.gate_decision_digest,
        request.target_state_schema,
    ))?)
}

fn migration_request_digest(
    request: &MigrationRequest,
) -> Result<ContentDigest, FactoryEffectStoreError> {
    Ok(digest_json_content(&(
        "wasm-biotic:migration-request:v1",
        &request.cycle_id,
        &request.incumbent_package_digest,
        &request.challenger_package_digest,
        &request.plan.plan_digest,
    ))?)
}

fn recovery_request_digest(
    request: &RecoveryRequest,
) -> Result<ContentDigest, FactoryEffectStoreError> {
    Ok(digest_json_content(&(
        "wasm-biotic:recovery-request:v1",
        &request.recovery_id,
        &request.cycle_id,
        &request.restore_package_digest,
        &request.restore_package_bytes,
        request.restore_state_schema,
        request.interrupted_stage,
        &request.migration_receipt,
        &request.activation_receipt,
        &request.reason,
    ))?)
}

fn stored_effect_result_digest(
    result: &StoredEffectResult,
) -> Result<ContentDigest, FactoryEffectStoreError> {
    Ok(digest_json_content(&(
        EFFECT_RECORD_SCHEMA,
        result.operation,
        &result.logical_effect_id,
        &result.request_digest,
        &result.response_digest,
    ))?)
}

fn backend_fact(
    intent: &StoredEffectIntent,
    result: &StoredEffectResult,
) -> Result<FactoryEffectBackendFact, FactoryEffectStoreError> {
    let expected_intent_digest = digest_json_content(&(
        EFFECT_RECORD_SCHEMA,
        intent.operation,
        &intent.logical_effect_id,
        &intent.request_digest,
        &intent.request_bytes_digest,
    ))?;
    let expected_result_digest = stored_effect_result_digest(result)?;
    if intent.schema != EFFECT_RECORD_SCHEMA
        || result.schema != EFFECT_RECORD_SCHEMA
        || intent.operation != result.operation
        || intent.logical_effect_id != result.logical_effect_id
        || intent.request_digest != result.request_digest
        || intent.request_digest != intent.request_bytes_digest
        || intent.intent_digest != expected_intent_digest
        || result.response_digest != ContentDigest::from_bytes(&result.response_bytes)
        || result.record_digest != expected_result_digest
    {
        return Err(FactoryEffectStoreError::Integrity(format!(
            "backend fact '{}' does not bind one exact intent and result",
            result.logical_effect_id
        )));
    }
    let mut fact = FactoryEffectBackendFact {
        operation: result.operation,
        logical_effect_id: result.logical_effect_id.clone(),
        request_digest: result.request_digest.clone(),
        request_bytes_digest: intent.request_bytes_digest.clone(),
        intent_digest: intent.intent_digest.clone(),
        response_digest: result.response_digest.clone(),
        response_bytes: result.response_bytes.clone(),
        result_record_digest: result.record_digest.clone(),
        fact_digest: ContentDigest::from_bytes(&[]),
    };
    fact.fact_digest = digest_json_content(&(
        "wasm-biotic:m5-factory-effect-backend-fact:v1",
        fact.operation,
        &fact.logical_effect_id,
        &fact.request_digest,
        &fact.request_bytes_digest,
        &fact.intent_digest,
        &fact.response_digest,
        &fact.result_record_digest,
    ))?;
    Ok(fact)
}

fn decode_exact<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
) -> Result<T, FactoryEffectStoreError> {
    if bytes.is_empty() || bytes.len() > MAX_DOMAIN_BYTES {
        return Err(FactoryEffectStoreError::ResourceBound(
            "domain request is outside its byte bound".to_string(),
        ));
    }
    let value: T = serde_json::from_slice(bytes)?;
    let canonical = serde_json::to_vec(&value)?;
    if canonical != bytes {
        return Err(FactoryEffectStoreError::Integrity(
            "domain request bytes are not the exact canonical JSON encoding".to_string(),
        ));
    }
    Ok(value)
}

fn secure_root(path: &Path) -> Result<PathBuf, FactoryEffectStoreError> {
    reject_symlink(path)?;
    fs::create_dir_all(path).map_err(|source| FactoryEffectStoreError::io(path, source))?;
    let canonical =
        fs::canonicalize(path).map_err(|source| FactoryEffectStoreError::io(path, source))?;
    let metadata = fs::symlink_metadata(&canonical)
        .map_err(|source| FactoryEffectStoreError::io(&canonical, source))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(FactoryEffectStoreError::UnsafePath(canonical));
    }
    Ok(canonical)
}

fn secure_child(root: &Path, name: &str) -> Result<PathBuf, FactoryEffectStoreError> {
    let path = root.join(name);
    reject_symlink(&path)?;
    fs::create_dir_all(&path).map_err(|source| FactoryEffectStoreError::io(&path, source))?;
    let canonical =
        fs::canonicalize(&path).map_err(|source| FactoryEffectStoreError::io(&path, source))?;
    if canonical.parent() != Some(root) {
        return Err(FactoryEffectStoreError::UnsafePath(path));
    }
    Ok(canonical)
}

fn reject_symlink(path: &Path) -> Result<(), FactoryEffectStoreError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(FactoryEffectStoreError::UnsafePath(path.to_path_buf()))
        }
        Ok(_) => Ok(()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(FactoryEffectStoreError::io(path, source)),
    }
}

fn persist_immutable(
    root: &Path,
    path: &Path,
    bytes: &[u8],
) -> Result<(), FactoryEffectStoreError> {
    if path.parent() != Some(root) || bytes.is_empty() {
        return Err(FactoryEffectStoreError::UnsafePath(path.to_path_buf()));
    }
    reject_symlink(path)?;
    if path.exists() {
        let existing = read_bounded(path, bytes.len().max(1))?;
        if existing == bytes {
            return Ok(());
        }
        return Err(FactoryEffectStoreError::Conflict(format!(
            "immutable path '{}' already contains different bytes",
            path.display()
        )));
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| FactoryEffectStoreError::io(path, source))?;
    file.write_all(bytes)
        .map_err(|source| FactoryEffectStoreError::io(path, source))?;
    file.sync_all()
        .map_err(|source| FactoryEffectStoreError::io(path, source))
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, FactoryEffectStoreError> {
    reject_symlink(path)?;
    let metadata =
        fs::metadata(path).map_err(|source| FactoryEffectStoreError::io(path, source))?;
    if !metadata.is_file() || metadata.len() > maximum as u64 {
        return Err(FactoryEffectStoreError::ResourceBound(format!(
            "file '{}' is not regular or exceeds {maximum} bytes",
            path.display()
        )));
    }
    let file = File::open(path).map_err(|source| FactoryEffectStoreError::io(path, source))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum.saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| FactoryEffectStoreError::io(path, source))?;
    if bytes.len() > maximum {
        return Err(FactoryEffectStoreError::ResourceBound(format!(
            "file '{}' exceeds {maximum} bytes",
            path.display()
        )));
    }
    Ok(bytes)
}

fn read_json<T: DeserializeOwned>(
    path: &Path,
    maximum: usize,
) -> Result<T, FactoryEffectStoreError> {
    Ok(serde_json::from_slice(&read_bounded(path, maximum)?)?)
}

fn write_json_atomic<T: Serialize>(
    root: &Path,
    path: &Path,
    value: &T,
) -> Result<(), FactoryEffectStoreError> {
    let bytes = serde_json::to_vec_pretty(value)?;
    if path.parent() != Some(root) || bytes.is_empty() {
        return Err(FactoryEffectStoreError::UnsafePath(path.to_path_buf()));
    }
    let temporary = root.join(format!(
        ".{}.tmp-{}-{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("m5-effect-state"),
        std::process::id(),
        TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|source| FactoryEffectStoreError::io(&temporary, source))?;
    file.write_all(&bytes)
        .map_err(|source| FactoryEffectStoreError::io(&temporary, source))?;
    file.sync_all()
        .map_err(|source| FactoryEffectStoreError::io(&temporary, source))?;
    fs::rename(&temporary, path).map_err(|source| FactoryEffectStoreError::io(path, source))
}

fn require_digest(
    subject: &str,
    expected: &ContentDigest,
    actual: &ContentDigest,
) -> Result<(), FactoryEffectStoreError> {
    if expected == actual {
        Ok(())
    } else {
        Err(FactoryEffectStoreError::Integrity(format!(
            "{subject} digest mismatch: expected {expected}, got {actual}"
        )))
    }
}

#[derive(Debug)]
pub enum FactoryEffectStoreError {
    InvalidRequest(String),
    Integrity(String),
    Conflict(String),
    ResourceBound(String),
    Migration(String),
    Execution(String),
    Interrupted(String),
    RecoveryRequired(String),
    NotInitialized,
    LockPoisoned,
    UnsafePath(PathBuf),
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Serialization(String),
    Dependency(String),
}

impl FactoryEffectStoreError {
    fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}

impl Display for FactoryEffectStoreError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRequest(message) => {
                write!(formatter, "invalid M5 effect request: {message}")
            }
            Self::Integrity(message) => write!(formatter, "M5 effect integrity failure: {message}"),
            Self::Conflict(message) => write!(formatter, "M5 effect conflict: {message}"),
            Self::ResourceBound(message) => {
                write!(formatter, "M5 effect resource bound: {message}")
            }
            Self::Migration(message) => write!(formatter, "M5 migration failed: {message}"),
            Self::Execution(message) => write!(formatter, "M5 execution failed: {message}"),
            Self::Interrupted(message) => write!(formatter, "M5 effect interrupted: {message}"),
            Self::RecoveryRequired(message) => write!(formatter, "M5 recovery required: {message}"),
            Self::NotInitialized => write!(formatter, "M5 factory effect store is not initialized"),
            Self::LockPoisoned => write!(formatter, "M5 effect store lock is poisoned"),
            Self::UnsafePath(path) => {
                write!(formatter, "unsafe M5 effect path '{}'", path.display())
            }
            Self::Io { path, source } => {
                write!(
                    formatter,
                    "M5 effect I/O failure at '{}': {source}",
                    path.display()
                )
            }
            Self::Serialization(message) => {
                write!(formatter, "M5 effect serialization failure: {message}")
            }
            Self::Dependency(message) => {
                write!(formatter, "M5 effect dependency failed: {message}")
            }
        }
    }
}

impl Error for FactoryEffectStoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<serde_json::Error> for FactoryEffectStoreError {
    fn from(error: serde_json::Error) -> Self {
        Self::Serialization(error.to_string())
    }
}

macro_rules! dependency_error {
    ($($type:path),+ $(,)?) => {
        $(
            impl From<$type> for FactoryEffectStoreError {
                fn from(error: $type) -> Self {
                    Self::Dependency(error.to_string())
                }
            }
        )+
    };
}

dependency_error!(
    crate::deployment::DeploymentError,
    crate::execution::artifact::ArtifactError,
    crate::execution::component::ComponentBuildError,
    crate::factory_reproduction::ReproductionError,
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::factory_reproduction::{
        M5ProviderProfileV1, MutableFactoryPolicy, MutableGenome, ProviderConfiguration,
        ProviderReplayCapsule, ServiceDependencyCatalog, StableInterfaceContract,
        StateCompatibility, StateMigrationPlan, WorkerCatalog,
    };

    const FACTORY_ID: &str = "factory:m5-effect-test";

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "wasm-biotic-m5-effect-{label}-{}-{}",
                std::process::id(),
                TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).expect("create isolated M5 effect-store root");
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            if self.0.exists() {
                fs::remove_dir_all(&self.0).expect("remove isolated M5 effect-store root");
            }
        }
    }

    fn component(delta: i32) -> Vec<u8> {
        wat::parse_str(format!(
            r#"(component
                (core module $implementation
                    (func (export "transform") (param i32) (result i32)
                        local.get 0
                        i32.const {delta}
                        i32.add))
                (core instance $instance (instantiate $implementation))
                (func (export "transform") (param "input" s32) (result s32)
                    (canon lift (core func $instance "transform"))))"#
        ))
        .expect("compile reference component")
    }

    fn compatibility(written_schema: u32) -> StateCompatibility {
        StateCompatibility {
            readable_schema_min: 1,
            readable_schema_max: 2,
            written_schema,
            incumbent_rollback_readable_through: 2,
        }
    }

    fn package(
        generation: u32,
        parent: Option<&FactoryPackage>,
        delta: i32,
        state_schema: u32,
    ) -> FactoryPackage {
        let parent_digest = parent.map(|package| package.package_digest.clone());
        let genome = MutableGenome::new(
            parent_digest,
            component(delta),
            MutableFactoryPolicy::terminal(generation.saturating_add(1), 2),
        )
        .expect("build mutable genome");
        FactoryPackage::build(
            FACTORY_ID,
            generation,
            genome,
            StableInterfaceContract::reference(),
            WorkerCatalog::reference().expect("reference worker catalog"),
            ServiceDependencyCatalog::reference().expect("reference service catalog"),
            compatibility(state_schema),
        )
        .expect("build factory package")
    }

    fn initialize_request(
        package: &FactoryPackage,
        operation_id: &str,
        state_schema: u32,
        state_bytes: &[u8],
    ) -> FactoryInitializeRequest {
        FactoryInitializeRequest::new(
            operation_id,
            FACTORY_ID,
            package.canonical_bytes().expect("canonical package bytes"),
            state_schema,
            state_bytes.to_vec(),
        )
        .expect("valid initialization request")
    }

    fn activation_request(
        cycle_id: &str,
        incumbent: &FactoryPackage,
        challenger: &FactoryPackage,
        target_state_schema: u32,
    ) -> ActivationRequest {
        let mut request = ActivationRequest {
            cycle_id: cycle_id.to_string(),
            incumbent_package_digest: incumbent.package_digest.clone(),
            challenger_package_digest: challenger.package_digest.clone(),
            challenger_package_bytes: challenger
                .canonical_bytes()
                .expect("canonical challenger bytes"),
            approval_digest: ContentDigest::from_bytes(format!("approval:{cycle_id}").as_bytes()),
            gate_decision_digest: ContentDigest::from_bytes(format!("gate:{cycle_id}").as_bytes()),
            target_state_schema,
            request_digest: ContentDigest::from_bytes(&[]),
        };
        request.request_digest =
            activation_request_digest(&request).expect("activation request digest");
        request
    }

    fn migration_effect(
        cycle_id: &str,
        incumbent: &FactoryPackage,
        challenger: &FactoryPackage,
        migration_id: &str,
    ) -> FactoryMigrationEffectRequest {
        let prefix = b"schema-2:".to_vec();
        let forward = StateTransformArtifact::new(
            StateTransformDirection::Forward,
            1,
            2,
            StateTransformProgram::Prepend {
                prefix: prefix.clone(),
            },
            ContentDigest::from_bytes(b"forward-proof"),
        )
        .expect("forward migration artifact");
        let rollback = StateTransformArtifact::new(
            StateTransformDirection::Rollback,
            2,
            1,
            StateTransformProgram::RemovePrefix { prefix },
            ContentDigest::from_bytes(b"rollback-proof"),
        )
        .expect("rollback migration artifact");
        let artifacts =
            StateMigrationArtifactBundle::new(forward, rollback).expect("migration bundle");
        let plan = StateMigrationPlan::new(
            migration_id,
            1,
            2,
            1,
            artifacts.bundle_digest.clone(),
            4_096,
        )
        .expect("migration plan");
        let mut request = MigrationRequest {
            cycle_id: cycle_id.to_string(),
            incumbent_package_digest: incumbent.package_digest.clone(),
            challenger_package_digest: challenger.package_digest.clone(),
            plan,
            request_digest: ContentDigest::from_bytes(&[]),
        };
        request.request_digest =
            migration_request_digest(&request).expect("migration request digest");
        FactoryMigrationEffectRequest::new(request, artifacts).expect("migration effect")
    }

    fn wire_request<T: Serialize>(logical_effect_id: &str, request: &T) -> FactoryEffectRequest {
        FactoryEffectRequest::new(
            "scope:m5-effect-test",
            FACTORY_ID,
            logical_effect_id,
            serde_json::to_vec(request).expect("canonical request bytes"),
        )
    }

    fn provider_proposal_request(
        incumbent_package_digest: ContentDigest,
    ) -> FactoryProviderProposalRequest {
        let argument_schema = serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "required": [
                "cycle_id",
                "challenger_wat_digest",
                "policy_digest",
                "invocation_challenge_digest"
            ],
            "properties": {
                "cycle_id": {"type": "string"},
                "challenger_wat_digest": {"type": "string"},
                "policy_digest": {"type": "string"},
                "invocation_challenge_digest": {"type": "string"}
            }
        });
        let selected_tool = serde_json::json!({
            "type": "function",
            "name": PROVIDER_CANDIDATE_OPERATION,
            "parameters": argument_schema
        });
        let tool_catalog_bytes =
            serde_json::to_vec(&vec![selected_tool.clone()]).expect("tool catalog JSON");
        let selected_tool_bytes = serde_json::to_vec(&selected_tool).expect("selected tool JSON");
        let argument_schema_bytes =
            serde_json::to_vec(&argument_schema).expect("argument schema JSON");
        let response_schema_bytes = serde_json::to_vec(&serde_json::json!({
            "type": "object"
        }))
        .expect("response schema JSON");
        let configuration = ProviderConfiguration {
            provider_id: "provider:test".to_string(),
            model_id: "model:test".to_string(),
            provider_profile: M5ProviderProfileV1::OpenAiResponses,
            api_base_url: "https://provider.example.test/v1/".to_string(),
            endpoint_class: crate::factory_reproduction::M5ProviderEndpointClassV1::ExternalHttps,
            driver_profile_digest: ContentDigest::from_bytes(b"driver-profile"),
            generation_policy_id: "policy:effect-store-test".to_string(),
            generation_policy_digest: ContentDigest::from_bytes(b"generation-policy"),
            maximum_retries: 0,
            maximum_output_tokens: 512,
            input_cost_per_million_microunits: 100_000,
            output_cost_per_million_microunits: 0,
            cost_currency: "usd".to_string(),
            parser_digest: ContentDigest::from_bytes(b"bounded-parser"),
            response_schema_digest: ContentDigest::from_bytes(&response_schema_bytes),
            prompt_renderer_digest: ContentDigest::from_bytes(b"prompt-renderer"),
            tool_catalog_digest: ContentDigest::from_bytes(&tool_catalog_bytes),
        };
        let proposal_arguments = BTreeMap::from([
            (
                "challenger_wat_digest".to_string(),
                ContentDigest::from_bytes(b"challenger-wat").to_string(),
            ),
            ("cycle_id".to_string(), "cycle:provider-test".to_string()),
            (
                "invocation_challenge_digest".to_string(),
                crate::factory_reproduction::unbound_provider_invocation_challenge_digest()
                    .to_string(),
            ),
            (
                "policy_digest".to_string(),
                ContentDigest::from_bytes(b"challenger-policy").to_string(),
            ),
        ]);
        let prompt_bytes = serde_json::to_vec(&serde_json::json!({
            "required_response": {
                "operation": PROVIDER_CANDIDATE_OPERATION,
                "target_genome_digest": ContentDigest::from_bytes(b"target-genome"),
                "arguments": &proposal_arguments,
            }
        }))
        .expect("frozen provider prompt JSON");
        let capsule = ProviderReplayCapsule::new(
            &configuration,
            prompt_bytes.clone(),
            tool_catalog_bytes,
            selected_tool_bytes,
            argument_schema_bytes,
            response_schema_bytes,
        )
        .expect("provider replay capsule");
        let qualification = ProviderQualificationRequest::new(
            "qualification:test",
            incumbent_package_digest,
            ContentDigest::from_bytes(b"candidate-target"),
            configuration,
            prompt_bytes,
            capsule,
        )
        .expect("provider qualification request");
        FactoryProviderProposalRequest::new(
            qualification,
            serde_json::to_vec(&proposal_arguments).expect("normalized provider arguments"),
        )
        .expect("provider proposal request")
    }

    #[test]
    fn ordinary_v1_and_causally_bound_v2_execute_requests_are_exactly_separated() {
        let package_digest = ContentDigest::from_bytes(b"execute-schema-package");
        let ordinary = FactoryExecuteRequest::new(package_digest.clone(), 7)
            .expect("ordinary V1 execute request");
        let ordinary_bytes = serde_json::to_vec(&ordinary).expect("canonical ordinary request");
        assert_eq!(ordinary.schema, EXECUTE_REQUEST_SCHEMA);
        assert!(ordinary.causal_context_digest.is_none());
        assert!(
            !ordinary_bytes
                .windows(b"causal_context_digest".len())
                .any(|window| window == b"causal_context_digest")
        );
        let ordinary_roundtrip: FactoryExecuteRequest =
            serde_json::from_slice(&ordinary_bytes).expect("round-trip ordinary request");
        ordinary_roundtrip.validate().expect("validate ordinary V1");

        let context = ContentDigest::from_bytes(b"execute-causal-context");
        let challenged =
            FactoryExecuteRequest::new_with_causal_context(package_digest, 7, context.clone())
                .expect("challenged V2 execute request");
        assert_eq!(challenged.schema, CAUSALLY_BOUND_EXECUTE_REQUEST_SCHEMA);
        assert_eq!(challenged.causal_context_digest.as_ref(), Some(&context));
        assert_ne!(challenged.request_digest, ordinary.request_digest);
        let challenged_bytes =
            serde_json::to_vec(&challenged).expect("canonical challenged request");
        let challenged_roundtrip: FactoryExecuteRequest =
            serde_json::from_slice(&challenged_bytes).expect("round-trip challenged request");
        challenged_roundtrip
            .validate()
            .expect("validate challenged V2");

        let mut v1_with_context = challenged.clone();
        v1_with_context.schema = EXECUTE_REQUEST_SCHEMA.to_string();
        assert!(v1_with_context.validate().is_err());
        let mut v2_without_context = ordinary;
        v2_without_context.schema = CAUSALLY_BOUND_EXECUTE_REQUEST_SCHEMA.to_string();
        assert!(v2_without_context.validate().is_err());
    }

    #[test]
    fn provider_proposal_is_read_only_content_addressed_and_reopen_replayable() {
        let directory = TestDirectory::new("provider-proposal");
        let incumbent = package(0, None, 0, 1);
        let initialize =
            initialize_request(&incumbent, "initialize-provider-proposal", 1, b"state-v1");
        let store = FactoryEffectStore::open(&directory.0).expect("open effect store");
        store.initialize(initialize).expect("initialize incumbent");
        let snapshot_before = store.snapshot().expect("snapshot before proposal");
        let mutation_count_before = store.lock_state().unwrap().mutations.len();
        let proposal = provider_proposal_request(incumbent.package_digest.clone());
        let wire = wire_request(
            &format!(
                "m5-provider-proposal:{}",
                proposal.request_digest.file_stem()
            ),
            &proposal,
        );

        let first = store
            .apply(CapabilityOperation::FactoryProviderProposal, &wire)
            .expect("admit provider proposal");
        let first_result: FactoryProviderProposalResult =
            serde_json::from_slice(&first.exact_response_bytes)
                .expect("decode provider proposal result");
        first_result
            .validate_for(&proposal)
            .expect("validate provider proposal result");
        assert_eq!(store.snapshot().unwrap(), snapshot_before);
        assert_eq!(
            store.lock_state().unwrap().mutations.len(),
            mutation_count_before
        );
        let fact = store
            .effect_fact(&wire.logical_effect_id)
            .expect("provider proposal backend fact")
            .expect("accepted provider proposal fact");
        assert_eq!(fact.operation, CapabilityOperation::FactoryProviderProposal);
        assert_eq!(fact.request_digest, wire.exact_request_digest);
        assert_eq!(first_result.request_digest, proposal.request_digest);
        drop(store);

        let reopened = FactoryEffectStore::open(&directory.0).expect("reopen effect store");
        let replayed = reopened
            .apply(CapabilityOperation::FactoryProviderProposal, &wire)
            .expect("replay exact provider proposal");
        assert!(
            replayed == first,
            "reopened provider-proposal replay differed from the first exact result"
        );
        assert_eq!(reopened.snapshot().unwrap(), snapshot_before);
        let reopened_fact = reopened
            .effect_fact(&wire.logical_effect_id)
            .unwrap()
            .unwrap();
        assert!(
            reopened_fact == fact,
            "reopened provider-proposal backend fact differed from the committed fact"
        );

        let mut inconsistent = proposal.clone();
        inconsistent.target_digest = ContentDigest::from_bytes(b"different-target");
        inconsistent.request_digest = inconsistent.expected_digest().unwrap();
        assert!(matches!(
            inconsistent.validate(),
            Err(FactoryEffectStoreError::InvalidRequest(_))
        ));
    }

    #[test]
    fn backend_commit_crash_replays_one_exact_result_after_reopen() {
        let directory = TestDirectory::new("backend-commit");
        let incumbent = package(0, None, 0, 1);
        let initialize = initialize_request(&incumbent, "initialize-backend", 1, b"state-v1");
        let wire = wire_request("effect:initialize-backend", &initialize);
        let store = FactoryEffectStore::open(&directory.0).expect("open effect store");
        store
            .arm_fail_after_backend_commit()
            .expect("arm backend crash");

        assert!(matches!(
            store.apply(CapabilityOperation::FactoryInitialize, &wire),
            Err(FactoryEffectStoreError::Interrupted(_))
        ));
        drop(store);

        let reopened = FactoryEffectStore::open(&directory.0).expect("reopen effect store");
        let recovered = reopened
            .apply(CapabilityOperation::FactoryInitialize, &wire)
            .expect("recover committed backend result");
        let replayed = reopened
            .apply(CapabilityOperation::FactoryInitialize, &wire)
            .expect("replay exact backend result");
        assert!(
            recovered == replayed,
            "recovered initialization result differed from its exact replay"
        );
        let evidence: FactoryInitializationEvidence =
            serde_json::from_slice(&recovered.exact_response_bytes)
                .expect("decode initialization evidence");
        assert_eq!(evidence.snapshot.package_digest, incumbent.package_digest);
        let fact = reopened
            .effect_fact(&wire.logical_effect_id)
            .expect("read exact backend fact")
            .expect("accepted backend fact");
        assert_eq!(fact.operation, CapabilityOperation::FactoryInitialize);
        assert_eq!(fact.request_digest, wire.exact_request_digest);
        assert!(
            fact.response_bytes == recovered.exact_response_bytes,
            "backend fact response bytes differed from the recovered result (fact_bytes={}, result_bytes={})",
            fact.response_bytes.len(),
            recovered.exact_response_bytes.len()
        );
        let reopened_facts = reopened.all_effect_facts().expect("scan backend facts");
        assert!(
            reopened_facts == vec![fact],
            "reopened backend fact inventory differed from the exact singleton (actual_count={})",
            reopened_facts.len()
        );
        assert_eq!(reopened.lock_state().unwrap().mutations.len(), 1);
        assert_eq!(
            reopened.deployment.state().unwrap().initializations.len(),
            1
        );
    }

    #[test]
    fn initialization_intent_precedes_deployment_and_recovers_from_intent_recorded() {
        let directory = TestDirectory::new("initialize-intent");
        let incumbent = package(0, None, 0, 1);
        let request = initialize_request(&incumbent, "initialize-intent", 1, b"state-v1");
        let store = FactoryEffectStore::open(&directory.0).expect("open effect store");
        store
            .arm_fail_after_deployment_commit()
            .expect("arm deployment crash");

        assert!(matches!(
            store.initialize(request.clone()),
            Err(FactoryEffectStoreError::Interrupted(_))
        ));
        {
            let state = store.lock_state().expect("state");
            let mutation = state
                .mutations
                .get(&request.operation_id)
                .expect("durable initialization intent");
            assert_eq!(mutation.phase, MutationPhase::IntentRecorded);
            assert!(state.active.is_none());
        }
        assert_eq!(
            store
                .deployment
                .active_artifact()
                .expect("deployment route")
                .expect("installed route")
                .digest,
            incumbent.payload.genome.component_digest
        );
        drop(store);

        let reopened = FactoryEffectStore::open(&directory.0).expect("recover initialization");
        let snapshot = reopened.snapshot().expect("snapshot").expect("active");
        assert_eq!(snapshot.package_digest, incumbent.package_digest);
        assert_eq!(
            reopened
                .lock_state()
                .unwrap()
                .mutations
                .get(&request.operation_id)
                .unwrap()
                .phase,
            MutationPhase::Complete
        );
        assert_eq!(
            reopened.deployment.state().unwrap().initializations.len(),
            1
        );
    }

    #[test]
    fn schema_changing_activation_requires_one_exact_prepared_migration() {
        let directory = TestDirectory::new("schema-migration");
        let incumbent = package(0, None, 0, 1);
        let challenger = package(1, Some(&incumbent), 1, 2);
        let store = FactoryEffectStore::open(&directory.0).expect("open effect store");
        store
            .initialize(initialize_request(
                &incumbent,
                "initialize-schema",
                1,
                b"state-v1",
            ))
            .expect("initialize incumbent");

        let mismatched = activation_request("cycle-schema", &incumbent, &challenger, 1);
        assert!(matches!(
            store.activate(mismatched),
            Err(FactoryEffectStoreError::Conflict(_))
        ));
        let exact_activation = activation_request("cycle-schema", &incumbent, &challenger, 2);
        assert!(matches!(
            store.activate(exact_activation.clone()),
            Err(FactoryEffectStoreError::Conflict(_))
        ));

        store
            .prepare_migration(migration_effect(
                "another-cycle",
                &incumbent,
                &challenger,
                "migration:another-cycle",
            ))
            .expect("prepare migration for another cycle");
        assert!(matches!(
            store.activate(exact_activation.clone()),
            Err(FactoryEffectStoreError::Conflict(_))
        ));

        store
            .prepare_migration(migration_effect(
                "cycle-schema",
                &incumbent,
                &challenger,
                "migration:cycle-schema",
            ))
            .expect("prepare exact migration");
        let receipt = store
            .activate(exact_activation)
            .expect("activate with exact migration");
        assert_eq!(receipt.active_state_schema, 2);
        let snapshot = store.snapshot().expect("snapshot").expect("active");
        assert_eq!(snapshot.package_digest, challenger.package_digest);
        assert_eq!(snapshot.state_schema, 2);
        assert_eq!(
            store
                .read_state_blob(&snapshot.state_blob_digest)
                .expect("migrated state"),
            b"schema-2:state-v1"
        );
    }

    #[test]
    fn deployment_commit_crash_resumes_exact_schema_activation_once() {
        let directory = TestDirectory::new("activation-deployment-commit");
        let incumbent = package(0, None, 0, 1);
        let challenger = package(1, Some(&incumbent), 1, 2);
        let store = FactoryEffectStore::open(&directory.0).expect("open effect store");
        store
            .initialize(initialize_request(
                &incumbent,
                "initialize-activation-crash",
                1,
                b"state-v1",
            ))
            .expect("initialize incumbent");
        store
            .prepare_migration(migration_effect(
                "cycle-activation-crash",
                &incumbent,
                &challenger,
                "migration:activation-crash",
            ))
            .expect("prepare exact migration");
        let request = activation_request("cycle-activation-crash", &incumbent, &challenger, 2);
        store
            .arm_fail_after_deployment_commit()
            .expect("arm deployment crash");

        assert!(matches!(
            store.activate(request.clone()),
            Err(FactoryEffectStoreError::Interrupted(_))
        ));
        {
            let state = store.lock_state().expect("state");
            assert_eq!(
                state
                    .mutations
                    .get("m5-activation:cycle-activation-crash")
                    .expect("activation intent")
                    .phase,
                MutationPhase::IntentRecorded
            );
            assert_eq!(
                state.active.as_ref().unwrap().package_digest,
                incumbent.package_digest
            );
        }
        assert_eq!(
            store.deployment.active_artifact().unwrap().unwrap().digest,
            challenger.payload.genome.component_digest
        );
        drop(store);

        let reopened = FactoryEffectStore::open(&directory.0).expect("recover activation");
        let recovered = reopened
            .activate(request)
            .expect("idempotently replay activation");
        let snapshot = reopened.snapshot().expect("snapshot").expect("active");
        assert_eq!(recovered.active_package_digest, challenger.package_digest);
        assert_eq!(snapshot.package_digest, challenger.package_digest);
        assert_eq!(snapshot.state_schema, 2);
        assert_eq!(reopened.deployment.state().unwrap().activations.len(), 1);
    }

    #[test]
    fn reconciliation_completes_every_later_durable_mutation_phase() {
        for phase in [
            MutationPhase::DeploymentCommitted,
            MutationPhase::StatePointerCommitted,
        ] {
            let label = match phase {
                MutationPhase::DeploymentCommitted => "phase-deployment",
                MutationPhase::StatePointerCommitted => "phase-pointer",
                _ => unreachable!(),
            };
            let directory = TestDirectory::new(label);
            let incumbent = package(0, None, 0, 1);
            let challenger = package(1, Some(&incumbent), 1, 1);
            let cycle_id = format!("cycle-{label}");
            let operation_id = format!("m5-activation:{cycle_id}");
            let store = FactoryEffectStore::open(&directory.0).expect("open effect store");
            store
                .initialize(initialize_request(
                    &incumbent,
                    &format!("initialize-{label}"),
                    1,
                    b"state-v1",
                ))
                .expect("initialize incumbent");
            store
                .activate(activation_request(&cycle_id, &incumbent, &challenger, 1))
                .expect("complete activation fixture");
            drop(store);

            let state_path = directory.0.join(STATE_FILE);
            let mut state: FactoryEffectStoreState =
                read_json(&state_path, MAX_DOMAIN_BYTES).expect("read effect-store state");
            let expected_active = {
                let mutation = state
                    .mutations
                    .get_mut(&operation_id)
                    .expect("activation mutation");
                mutation.phase = phase;
                match phase {
                    MutationPhase::DeploymentCommitted => mutation.before.clone(),
                    MutationPhase::StatePointerCommitted => Some(mutation.after.clone()),
                    _ => unreachable!(),
                }
            };
            state.active = expected_active;
            state.seal().expect("seal simulated crash phase");
            state.validate().expect("valid simulated crash phase");
            write_json_atomic(&directory.0, &state_path, &state)
                .expect("persist simulated crash phase");

            let reopened = FactoryEffectStore::open(&directory.0).expect("reconcile crash phase");
            assert_eq!(
                reopened
                    .lock_state()
                    .unwrap()
                    .mutations
                    .get(&operation_id)
                    .unwrap()
                    .phase,
                MutationPhase::Complete
            );
            assert_eq!(
                reopened.snapshot().unwrap().unwrap().package_digest,
                challenger.package_digest
            );
            assert_eq!(reopened.deployment.state().unwrap().activations.len(), 1);
        }
    }

    #[test]
    fn effect_idempotency_accepts_only_the_exact_same_request() {
        let directory = TestDirectory::new("exact-idempotency");
        let incumbent = package(0, None, 0, 1);
        let exact = initialize_request(&incumbent, "initialize-idempotent", 1, b"state-v1");
        let exact_wire = wire_request("effect:initialize-idempotent", &exact);
        let store = FactoryEffectStore::open(&directory.0).expect("open effect store");

        let first = store
            .apply(CapabilityOperation::FactoryInitialize, &exact_wire)
            .expect("first exact effect");
        let second = store
            .apply(CapabilityOperation::FactoryInitialize, &exact_wire)
            .expect("idempotent exact effect");
        assert!(
            first == second,
            "idempotent initialization returned a different exact effect result"
        );

        let changed =
            initialize_request(&incumbent, "initialize-idempotent", 1, b"different-state");
        let changed_wire = wire_request("effect:initialize-idempotent", &changed);
        assert!(matches!(
            store.apply(CapabilityOperation::FactoryInitialize, &changed_wire),
            Err(FactoryEffectStoreError::Conflict(_))
        ));
        assert_eq!(store.lock_state().unwrap().mutations.len(), 1);
        assert_eq!(store.deployment.state().unwrap().initializations.len(), 1);
    }

    #[test]
    fn resealed_mutation_request_tamper_is_rejected_before_recovery() {
        let directory = TestDirectory::new("mutation-tamper");
        let incumbent = package(0, None, 0, 1);
        let store = FactoryEffectStore::open(&directory.0).expect("open effect store");
        let request = initialize_request(&incumbent, "initialize-tamper", 1, b"state-v1");
        store
            .initialize(request.clone())
            .expect("initialize incumbent");
        drop(store);

        let state_path = directory.0.join(STATE_FILE);
        let mut state: FactoryEffectStoreState =
            read_json(&state_path, MAX_DOMAIN_BYTES).expect("read effect-store state");
        let mutation = state
            .mutations
            .get_mut(&request.operation_id)
            .expect("initialization mutation");
        let forged = ContentDigest::from_bytes(b"forged-initialization-request");
        mutation.request_digest = forged.clone();
        let MutationReceipt::Initialization(evidence) = &mut mutation.receipt else {
            panic!("expected initialization evidence");
        };
        evidence.request_digest = forged;
        *evidence = evidence.clone().seal().expect("reseal forged evidence");
        state.seal().expect("reseal forged store");
        state
            .validate()
            .expect("forgery is internally sealed before CAS re-derivation");
        write_json_atomic(&directory.0, &state_path, &state).expect("persist forged state");

        assert!(matches!(
            FactoryEffectStore::open(&directory.0),
            Err(FactoryEffectStoreError::Integrity(_))
        ));
    }
}
