//! Durable, proof-run-specific precommit for one M5 live-provider seed cycle.
//!
//! This module is deliberately pure: it performs no provider call and accepts
//! no credential material.  A precommit binds one M7 proof-run identifier, one
//! provider qualification identifier, one preparation time, the exact provider
//! configuration, and every material field of an [`M5SeedCyclePlan`] except its
//! `operator_context_digest`.  The returned plan has that excluded field
//! replaced with the precommit digest, making the ordinary M5 cycle law carry
//! the precommit identity without creating a circular digest.

use crate::execution::ContentDigest;
use crate::factory_reproduction::{
    ApprovalDecision, MutableFactoryPolicy, ProviderConfiguration, StateCompatibility,
    StateMigrationPlan,
};
use crate::m5_effect_store::StateMigrationArtifactBundle;
use crate::m5_runtime::M5SeedCyclePlan;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::path::{Component, Path};

pub const M5_PROVIDER_PRECOMMIT_SCHEMA: &str = "wasm-biotic.m5-provider-precommit.v2";

const PRECOMMIT_DIGEST_DOMAIN: &str = "wasm-biotic:m5-provider-precommit:v2";
const PLAN_MATERIAL_DIGEST_DOMAIN: &str = "wasm-biotic:m5-provider-precommit-plan-material:v1";
const MAX_IDENTIFIER_BYTES: usize = 512;
const MAX_APPROVAL_RATIONALE_BYTES: usize = 4_096;
const MAX_CHALLENGER_WAT_BYTES: usize = 256 * 1_024;
const MAX_PLAN_MATERIAL_BYTES: usize = 4 * 1_048_576;
const MAX_PRECOMMIT_BYTES: usize = 64 * 1_024;

/// Canonical wire record that must be constructed before its live provider
/// call.  It contains public configuration and content identities only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M5ProviderPrecommitV1 {
    pub schema: String,
    pub proof_run_id: String,
    pub qualification_id: String,
    pub prepared_at_ms: u64,
    pub provider_configuration: ProviderConfiguration,
    pub configuration_fingerprint: ContentDigest,
    pub seed_plan_material_digest: ContentDigest,
    pub precommit_digest: ContentDigest,
}

#[derive(Serialize)]
struct SeedPlanMaterialV1<'a> {
    cycle_id: &'a str,
    challenger_wat_bytes: &'a [u8],
    challenger_policy: &'a MutableFactoryPolicy,
    state_compatibility: &'a StateCompatibility,
    migration_plan: &'a Option<StateMigrationPlan>,
    migration_artifacts: &'a Option<StateMigrationArtifactBundle>,
    approval_decision: ApprovalDecision,
    approver_ref: &'a str,
    approval_rationale: &'a str,
}

#[derive(Serialize)]
struct PrecommitDigestMaterialV1<'a> {
    domain: &'static str,
    schema: &'a str,
    proof_run_id: &'a str,
    qualification_id: &'a str,
    prepared_at_ms: u64,
    provider_configuration: &'a ProviderConfiguration,
    configuration_fingerprint: &'a ContentDigest,
    seed_plan_material_digest: &'a ContentDigest,
}

impl M5ProviderPrecommitV1 {
    /// Freeze one exact provider configuration and seed plan, then replace the
    /// plan's caller context with this precommit's content identity.
    ///
    /// The original context is intentionally excluded.  This is the only
    /// excluded `M5SeedCyclePlan` field; including it would make the returned
    /// plan and precommit recursively depend on each other.
    pub fn prepare(
        proof_run_id: impl Into<String>,
        qualification_id: impl Into<String>,
        prepared_at_ms: u64,
        provider_configuration: ProviderConfiguration,
        mut plan: M5SeedCyclePlan,
    ) -> Result<(Self, M5SeedCyclePlan), M5ProviderPrecommitError> {
        let proof_run_id = proof_run_id.into();
        let qualification_id = qualification_id.into();
        validate_identifier("proof_run_id", &proof_run_id)?;
        validate_identifier("qualification_id", &qualification_id)?;
        if prepared_at_ms == 0 {
            return Err(M5ProviderPrecommitError::InvalidInput(
                "prepared_at_ms must be nonzero".to_string(),
            ));
        }
        validate_seed_plan(&plan)?;
        let configuration_fingerprint = provider_configuration
            .fingerprint()
            .map_err(|error| M5ProviderPrecommitError::InvalidInput(error.to_string()))?;
        let seed_plan_material_digest = seed_plan_material_digest(&plan)?;
        let mut precommit = Self {
            schema: M5_PROVIDER_PRECOMMIT_SCHEMA.to_string(),
            proof_run_id,
            qualification_id,
            prepared_at_ms,
            provider_configuration,
            configuration_fingerprint,
            seed_plan_material_digest,
            precommit_digest: ContentDigest::from_bytes(&[]),
        };
        precommit.precommit_digest = precommit.expected_digest()?;
        precommit.validate_record()?;

        plan.operator_context_digest = precommit.precommit_digest.clone();
        precommit.validate_for(
            &precommit.proof_run_id,
            &precommit.qualification_id,
            precommit.prepared_at_ms,
            &precommit.provider_configuration,
            &plan,
        )?;
        Ok((precommit, plan))
    }

    /// Validate the record and its exact expected proof-run inputs.
    ///
    /// The supplied plan must be the returned, context-bound plan: changing
    /// either a material plan field or `operator_context_digest` is rejected.
    #[allow(clippy::too_many_arguments)]
    pub fn validate_for(
        &self,
        expected_proof_run_id: &str,
        expected_qualification_id: &str,
        expected_prepared_at_ms: u64,
        expected_provider_configuration: &ProviderConfiguration,
        bound_plan: &M5SeedCyclePlan,
    ) -> Result<(), M5ProviderPrecommitError> {
        self.validate_record()?;
        validate_seed_plan(bound_plan)?;
        if self.proof_run_id != expected_proof_run_id {
            return Err(M5ProviderPrecommitError::BindingMismatch(
                "proof_run_id differs from the expected proof run".to_string(),
            ));
        }
        if self.qualification_id != expected_qualification_id {
            return Err(M5ProviderPrecommitError::BindingMismatch(
                "qualification_id differs from the expected qualification".to_string(),
            ));
        }
        if self.prepared_at_ms != expected_prepared_at_ms {
            return Err(M5ProviderPrecommitError::BindingMismatch(
                "prepared_at_ms differs from the expected preparation time".to_string(),
            ));
        }
        let expected_fingerprint = expected_provider_configuration
            .fingerprint()
            .map_err(|error| M5ProviderPrecommitError::InvalidInput(error.to_string()))?;
        if self.provider_configuration != *expected_provider_configuration
            || self.configuration_fingerprint != expected_fingerprint
        {
            return Err(M5ProviderPrecommitError::BindingMismatch(
                "provider configuration differs from the exact precommit".to_string(),
            ));
        }
        let observed_plan_digest = seed_plan_material_digest(bound_plan)?;
        if self.seed_plan_material_digest != observed_plan_digest {
            return Err(M5ProviderPrecommitError::BindingMismatch(
                "M5 seed-plan material differs from the exact precommit".to_string(),
            ));
        }
        if bound_plan.operator_context_digest != self.precommit_digest {
            return Err(M5ProviderPrecommitError::BindingMismatch(
                "M5 seed-plan operator context is not the precommit digest".to_string(),
            ));
        }
        Ok(())
    }

    /// Exact compact JSON encoding for durable storage and detached transfer.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, M5ProviderPrecommitError> {
        self.validate_record()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|error| M5ProviderPrecommitError::Serialization(error.to_string()))?;
        enforce_wire_bound(bytes.len())?;
        Ok(bytes)
    }

    /// Decode one exact canonical wire record and revalidate all internal
    /// fingerprints and digests.  Use [`Self::validate_for`] as the subsequent
    /// external plan/configuration check.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, M5ProviderPrecommitError> {
        enforce_wire_bound(bytes.len())?;
        if bytes.is_empty() {
            return Err(M5ProviderPrecommitError::InvalidInput(
                "provider precommit bytes are empty".to_string(),
            ));
        }
        let record: Self = serde_json::from_slice(bytes)
            .map_err(|error| M5ProviderPrecommitError::Serialization(error.to_string()))?;
        record.validate_record()?;
        let canonical = serde_json::to_vec(&record)
            .map_err(|error| M5ProviderPrecommitError::Serialization(error.to_string()))?;
        if canonical != bytes {
            return Err(M5ProviderPrecommitError::NonCanonicalEncoding);
        }
        Ok(record)
    }

    fn validate_record(&self) -> Result<(), M5ProviderPrecommitError> {
        if self.schema != M5_PROVIDER_PRECOMMIT_SCHEMA {
            return Err(M5ProviderPrecommitError::InvalidInput(
                "unsupported provider-precommit schema".to_string(),
            ));
        }
        validate_identifier("proof_run_id", &self.proof_run_id)?;
        validate_identifier("qualification_id", &self.qualification_id)?;
        if self.prepared_at_ms == 0 {
            return Err(M5ProviderPrecommitError::InvalidInput(
                "prepared_at_ms must be nonzero".to_string(),
            ));
        }
        let expected_fingerprint = self
            .provider_configuration
            .fingerprint()
            .map_err(|error| M5ProviderPrecommitError::InvalidInput(error.to_string()))?;
        if self.configuration_fingerprint != expected_fingerprint {
            return Err(M5ProviderPrecommitError::BindingMismatch(
                "provider configuration fingerprint is stale".to_string(),
            ));
        }
        let expected_digest = self.expected_digest()?;
        if self.precommit_digest != expected_digest {
            return Err(M5ProviderPrecommitError::BindingMismatch(
                "provider precommit digest is stale".to_string(),
            ));
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, M5ProviderPrecommitError> {
        digest_serializable(
            &PrecommitDigestMaterialV1 {
                domain: PRECOMMIT_DIGEST_DOMAIN,
                schema: &self.schema,
                proof_run_id: &self.proof_run_id,
                qualification_id: &self.qualification_id,
                prepared_at_ms: self.prepared_at_ms,
                provider_configuration: &self.provider_configuration,
                configuration_fingerprint: &self.configuration_fingerprint,
                seed_plan_material_digest: &self.seed_plan_material_digest,
            },
            MAX_PRECOMMIT_BYTES,
            "provider precommit digest material",
        )
    }
}

fn seed_plan_material_digest(
    plan: &M5SeedCyclePlan,
) -> Result<ContentDigest, M5ProviderPrecommitError> {
    validate_seed_plan(plan)?;
    digest_serializable(
        &(
            PLAN_MATERIAL_DIGEST_DOMAIN,
            SeedPlanMaterialV1 {
                cycle_id: &plan.cycle_id,
                challenger_wat_bytes: &plan.challenger_wat_bytes,
                challenger_policy: &plan.challenger_policy,
                state_compatibility: &plan.state_compatibility,
                migration_plan: &plan.migration_plan,
                migration_artifacts: &plan.migration_artifacts,
                approval_decision: plan.approval_decision,
                approver_ref: &plan.approver_ref,
                approval_rationale: &plan.approval_rationale,
            },
        ),
        MAX_PLAN_MATERIAL_BYTES,
        "M5 seed-plan material",
    )
}

fn validate_seed_plan(plan: &M5SeedCyclePlan) -> Result<(), M5ProviderPrecommitError> {
    validate_identifier("cycle_id", &plan.cycle_id)?;
    validate_identifier("approver_ref", &plan.approver_ref)?;
    if plan.challenger_wat_bytes.is_empty()
        || plan.challenger_wat_bytes.len() > MAX_CHALLENGER_WAT_BYTES
    {
        return Err(M5ProviderPrecommitError::InvalidInput(format!(
            "challenger WAT must contain 1..={MAX_CHALLENGER_WAT_BYTES} bytes"
        )));
    }
    if plan.approval_rationale.trim().is_empty()
        || plan.approval_rationale.len() > MAX_APPROVAL_RATIONALE_BYTES
        || plan.approval_rationale.contains('\0')
    {
        return Err(M5ProviderPrecommitError::InvalidInput(format!(
            "approval rationale must contain 1..={MAX_APPROVAL_RATIONALE_BYTES} non-NUL bytes"
        )));
    }
    plan.challenger_policy
        .validate()
        .map_err(|error| M5ProviderPrecommitError::InvalidInput(error.to_string()))?;
    plan.state_compatibility
        .validate()
        .map_err(|error| M5ProviderPrecommitError::InvalidInput(error.to_string()))?;
    match (&plan.migration_plan, &plan.migration_artifacts) {
        (None, None) => {}
        (Some(migration_plan), Some(migration_artifacts)) => {
            migration_plan
                .validate()
                .map_err(|error| M5ProviderPrecommitError::InvalidInput(error.to_string()))?;
            migration_artifacts
                .validate()
                .map_err(|error| M5ProviderPrecommitError::InvalidInput(error.to_string()))?;
            if migration_plan.migration_program_digest != migration_artifacts.bundle_digest {
                return Err(M5ProviderPrecommitError::InvalidInput(
                    "migration plan does not bind the exact artifact bundle".to_string(),
                ));
            }
        }
        (Some(_), None) => {
            return Err(M5ProviderPrecommitError::InvalidInput(
                "migration plan requires exact migration artifacts".to_string(),
            ));
        }
        (None, Some(_)) => {
            return Err(M5ProviderPrecommitError::InvalidInput(
                "migration artifacts require an exact migration plan".to_string(),
            ));
        }
    }
    Ok(())
}

fn digest_serializable<T: Serialize + ?Sized>(
    value: &T,
    maximum_bytes: usize,
    label: &str,
) -> Result<ContentDigest, M5ProviderPrecommitError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| M5ProviderPrecommitError::Serialization(error.to_string()))?;
    if bytes.is_empty() || bytes.len() > maximum_bytes {
        return Err(M5ProviderPrecommitError::ResourceExhausted(format!(
            "{label} must contain 1..={maximum_bytes} canonical bytes"
        )));
    }
    Ok(ContentDigest::from_bytes(&bytes))
}

fn validate_identifier(field: &str, value: &str) -> Result<(), M5ProviderPrecommitError> {
    if value.trim().is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.chars().any(char::is_control)
        || value.contains('/')
        || value.contains('\\')
        || matches!(value, "." | "..")
        || Path::new(value)
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(M5ProviderPrecommitError::InvalidInput(format!(
            "{field} is blank, unsafe, contains controls, or exceeds {MAX_IDENTIFIER_BYTES} bytes"
        )));
    }
    Ok(())
}

fn enforce_wire_bound(length: usize) -> Result<(), M5ProviderPrecommitError> {
    if length > MAX_PRECOMMIT_BYTES {
        return Err(M5ProviderPrecommitError::ResourceExhausted(format!(
            "provider precommit exceeds {MAX_PRECOMMIT_BYTES} bytes"
        )));
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub enum M5ProviderPrecommitError {
    InvalidInput(String),
    BindingMismatch(String),
    ResourceExhausted(String),
    NonCanonicalEncoding,
    Serialization(String),
}

impl Display for M5ProviderPrecommitError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidInput(message) => {
                write!(formatter, "invalid provider precommit: {message}")
            }
            Self::BindingMismatch(message) => {
                write!(formatter, "provider precommit binding mismatch: {message}")
            }
            Self::ResourceExhausted(message) => {
                write!(formatter, "provider precommit bound exceeded: {message}")
            }
            Self::NonCanonicalEncoding => {
                formatter.write_str("provider precommit is not exact canonical JSON")
            }
            Self::Serialization(message) => {
                write!(
                    formatter,
                    "provider precommit serialization failed: {message}"
                )
            }
        }
    }
}

impl Error for M5ProviderPrecommitError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::factory_reproduction::M5ProviderProfileV1;
    use crate::m5_effect_store::{
        StateTransformArtifact, StateTransformDirection, StateTransformProgram,
    };
    use serde_json::Value;

    fn content(label: &str) -> ContentDigest {
        ContentDigest::from_bytes(label.as_bytes())
    }

    fn configuration() -> ProviderConfiguration {
        ProviderConfiguration {
            provider_id: "provider:precommit-test".to_string(),
            model_id: "model:precommit-test".to_string(),
            provider_profile: M5ProviderProfileV1::OpenAiResponses,
            api_base_url: "https://provider.example.test/v1/".to_string(),
            endpoint_class: crate::factory_reproduction::M5ProviderEndpointClassV1::ExternalHttps,
            driver_profile_digest: content("driver-profile"),
            generation_policy_id: "policy:precommit-test".to_string(),
            generation_policy_digest: content("generation-policy"),
            maximum_retries: 0,
            maximum_output_tokens: 512,
            input_cost_per_million_microunits: 0,
            output_cost_per_million_microunits: 0,
            cost_currency: "usd".to_string(),
            parser_digest: content("parser"),
            response_schema_digest: content("response-schema"),
            prompt_renderer_digest: content("prompt-renderer"),
            tool_catalog_digest: content("tool-catalog"),
        }
    }

    fn seed_plan() -> M5SeedCyclePlan {
        M5SeedCyclePlan {
            cycle_id: "cycle:precommit-test".to_string(),
            challenger_wat_bytes: b"(component)".to_vec(),
            challenger_policy: MutableFactoryPolicy::terminal(2, 2),
            state_compatibility: StateCompatibility {
                readable_schema_min: 1,
                readable_schema_max: 2,
                written_schema: 1,
                incumbent_rollback_readable_through: 2,
            },
            migration_plan: None,
            migration_artifacts: None,
            operator_context_digest: content("unbound-operator-context"),
            approval_decision: ApprovalDecision::Approved,
            approver_ref: "operator:precommit-test".to_string(),
            approval_rationale: "approve the exact precommitted test plan".to_string(),
        }
    }

    fn migration_pair() -> (StateMigrationPlan, StateMigrationArtifactBundle) {
        let prefix = b"schema-v2:".to_vec();
        let forward = StateTransformArtifact::new(
            StateTransformDirection::Forward,
            1,
            2,
            StateTransformProgram::Prepend {
                prefix: prefix.clone(),
            },
            content("forward-proof"),
        )
        .expect("forward artifact");
        let rollback = StateTransformArtifact::new(
            StateTransformDirection::Rollback,
            2,
            1,
            StateTransformProgram::RemovePrefix { prefix },
            content("rollback-proof"),
        )
        .expect("rollback artifact");
        let artifacts =
            StateMigrationArtifactBundle::new(forward, rollback).expect("migration artifacts");
        let plan = StateMigrationPlan::new(
            "migration:precommit-test",
            1,
            2,
            1,
            artifacts.bundle_digest.clone(),
            4_096,
        )
        .expect("migration plan");
        (plan, artifacts)
    }

    fn prepare(
        proof_run_id: &str,
        prepared_at_ms: u64,
        configuration: ProviderConfiguration,
        plan: M5SeedCyclePlan,
    ) -> (M5ProviderPrecommitV1, M5SeedCyclePlan) {
        M5ProviderPrecommitV1::prepare(
            proof_run_id,
            "qualification:precommit-test",
            prepared_at_ms,
            configuration,
            plan,
        )
        .expect("prepare provider precommit")
    }

    #[test]
    fn prepares_context_bound_plan_and_round_trips_exact_canonical_wire() {
        let config = configuration();
        let original = seed_plan();
        let original_context = original.operator_context_digest.clone();
        let (record, bound_plan) = prepare("proof-run:one", 100, config.clone(), original);

        assert_ne!(record.precommit_digest, original_context);
        assert_eq!(bound_plan.operator_context_digest, record.precommit_digest);
        record
            .validate_for(
                "proof-run:one",
                "qualification:precommit-test",
                100,
                &config,
                &bound_plan,
            )
            .expect("exact bound inputs");

        let bytes = record.canonical_bytes().expect("canonical bytes");
        assert_eq!(
            M5ProviderPrecommitV1::from_canonical_bytes(&bytes).expect("canonical reopen"),
            record
        );
        let mut noncanonical = bytes;
        noncanonical.push(b'\n');
        assert!(matches!(
            M5ProviderPrecommitV1::from_canonical_bytes(&noncanonical),
            Err(M5ProviderPrecommitError::NonCanonicalEncoding)
        ));
    }

    #[test]
    fn proof_run_and_preparation_time_change_the_precommit() {
        let (first, _) = prepare("proof-run:one", 100, configuration(), seed_plan());
        let (other_run, _) = prepare("proof-run:two", 100, configuration(), seed_plan());
        let (other_time, _) = prepare("proof-run:one", 101, configuration(), seed_plan());

        assert_ne!(first.precommit_digest, other_run.precommit_digest);
        assert_ne!(first.precommit_digest, other_time.precommit_digest);
        assert!(matches!(
            M5ProviderPrecommitV1::prepare(
                "proof-run:one",
                "qualification:precommit-test",
                0,
                configuration(),
                seed_plan(),
            ),
            Err(M5ProviderPrecommitError::InvalidInput(_))
        ));
    }

    #[test]
    fn exact_configuration_and_plan_are_required() {
        let config = configuration();
        let (record, bound_plan) = prepare("proof-run:one", 100, config.clone(), seed_plan());

        let mut changed_config = config.clone();
        changed_config.model_id = "model:other".to_string();
        assert!(matches!(
            record.validate_for(
                "proof-run:one",
                "qualification:precommit-test",
                100,
                &changed_config,
                &bound_plan,
            ),
            Err(M5ProviderPrecommitError::BindingMismatch(_))
        ));

        let mut changed_plan = bound_plan.clone();
        changed_plan.approval_rationale.push_str(" changed");
        assert!(matches!(
            record.validate_for(
                "proof-run:one",
                "qualification:precommit-test",
                100,
                &config,
                &changed_plan,
            ),
            Err(M5ProviderPrecommitError::BindingMismatch(_))
        ));

        let mut changed_context = bound_plan;
        changed_context.operator_context_digest = content("other-context");
        assert!(matches!(
            record.validate_for(
                "proof-run:one",
                "qualification:precommit-test",
                100,
                &config,
                &changed_context,
            ),
            Err(M5ProviderPrecommitError::BindingMismatch(_))
        ));
    }

    #[test]
    fn plan_material_hashes_every_field_except_the_replaced_context() {
        let base = seed_plan();
        let base_digest = seed_plan_material_digest(&base).expect("base material");

        let mut context_only = base.clone();
        context_only.operator_context_digest = content("ignored-context-change");
        assert_eq!(
            seed_plan_material_digest(&context_only).expect("context-independent material"),
            base_digest
        );

        let mut variants = Vec::new();
        let mut cycle = base.clone();
        cycle.cycle_id = "cycle:changed".to_string();
        variants.push(cycle);
        let mut wat = base.clone();
        wat.challenger_wat_bytes.push(b' ');
        variants.push(wat);
        let mut policy = base.clone();
        policy.challenger_policy.policy_revision += 1;
        variants.push(policy);
        let mut compatibility = base.clone();
        compatibility.state_compatibility.written_schema = 2;
        variants.push(compatibility);
        let mut migration = base.clone();
        let (migration_plan, migration_artifacts) = migration_pair();
        migration.migration_plan = Some(migration_plan);
        migration.migration_artifacts = Some(migration_artifacts);
        variants.push(migration);
        let mut decision = base.clone();
        decision.approval_decision = ApprovalDecision::Rejected;
        variants.push(decision);
        let mut approver = base.clone();
        approver.approver_ref = "operator:changed".to_string();
        variants.push(approver);
        let mut rationale = base;
        rationale.approval_rationale = "changed rationale".to_string();
        variants.push(rationale);

        for variant in variants {
            assert_ne!(
                seed_plan_material_digest(&variant).expect("changed material"),
                base_digest
            );
        }
    }

    #[test]
    fn canonical_parser_rejects_digest_tamper_and_unknown_fields() {
        let (record, _) = prepare("proof-run:one", 100, configuration(), seed_plan());
        let mut value: Value =
            serde_json::from_slice(&record.canonical_bytes().expect("canonical bytes"))
                .expect("wire JSON");
        value["precommit_digest"] =
            serde_json::to_value(content("forged-precommit")).expect("digest JSON");
        let tampered = serde_json::to_vec(&value).expect("tampered canonical JSON");
        assert!(matches!(
            M5ProviderPrecommitV1::from_canonical_bytes(&tampered),
            Err(M5ProviderPrecommitError::BindingMismatch(_))
        ));

        value["unexpected"] = Value::Bool(true);
        let unknown = serde_json::to_vec(&value).expect("unknown-field JSON");
        assert!(matches!(
            M5ProviderPrecommitV1::from_canonical_bytes(&unknown),
            Err(M5ProviderPrecommitError::Serialization(_))
        ));
    }
}
