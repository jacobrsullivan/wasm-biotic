//! Factory-reproduction capability port backed exclusively by receipted M3
//! factory effects.
//!
//! The reproduction engine never calls the physical effect store through this
//! type. Every domain request is serialized exactly, submitted through the
//! durable M5→M3 proof ledger, decoded from the receipted response bytes, and
//! independently checked before it is returned to the engine.

use crate::capability_services::{InvocationOutcome, ServiceFailure, ServiceFailureKind};
use crate::execution::artifact::{ContentDigest, digest_json_content};
use crate::factory_reproduction::{
    ActivationReceipt, ActivationRequest, CycleRecord, FactoryPackage, GenerationDriverEvidence,
    GenerationDriverRequest, GenerationInitiationRecord, LineageDisposition, M3CapabilityPort,
    MigrationReceipt, MigrationRequest, PendingEffect, PendingStage, PortFailure, PortFailureKind,
    PostActivationEvidence, PostActivationRequest, REPRODUCTION_STATE_SCHEMA_VERSION,
    RecoveryReceipt, RecoveryRequest, ReproductionState, ShadowExecutionEvidence,
    ShadowExecutionRequest,
};
use crate::m5_effect_store::{
    FactoryEffectBackendFact, FactoryEffectStore, FactoryExecuteRequest, FactoryExecutionResult,
    FactoryInitializationEvidence, FactoryInitializeRequest, FactoryInspectRequest,
    FactoryMigrationEffectRequest, FactoryProviderProposalRequest, FactoryProviderProposalResult,
    FactoryRuntimeInspection, FactoryRuntimeSnapshot, StateMigrationArtifactBundle,
};
use crate::m5_m3_adapter::{
    FactoryEffectAttemptProof, FactoryEffectInvocationProof, FactoryEffectInvokeRequest,
    FactoryEffectOperation, FactoryEffectProofStatus, M5M3AdapterError, M5M3InvocationProofLedger,
};
use crate::m5_supervisor_adapter::{
    M5OperatorRollbackAuthorizationRecord, M5PromotionApprovalReference, M5SupervisorAdapter,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

const MIGRATION_ARTIFACT_DIRECTORY: &str = "migration-artifacts";
const FAULT_DIRECTORY: &str = "faults";
const INTERRUPT_BEFORE_ACTIVATION: &str = "interrupt-before-activation";
const MAX_ARTIFACT_BYTES: usize = 1_048_576;
static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Compact link from domain evidence to the full immutable M3 proof ledger.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M5M3EffectReference {
    pub logical_effect_id: String,
    pub invocation_id: String,
    pub receipt_digest: ContentDigest,
    pub attestation_digest: ContentDigest,
    pub proof_digest: ContentDigest,
    pub backend_fact_digest: ContentDigest,
}

/// Exact externally retained evidence for an ad-hoc active execution.
///
/// Generation-driver executions are already durable in [`ReproductionState`].
/// Ordinary calls to `M5Runtime::execute_active`, however, return their proof
/// reference to the caller and are not journaled by the reproduction engine.
/// Supplying those records upgrades the audit from a backend-served execution
/// classification to an exact caller-returned evidence cross-check. Unlisted
/// `FactoryExecute` proofs remain legitimate served work, but can never satisfy
/// a coordinator-owned generation-driver claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M5ActiveExecutionAuditRecord {
    pub package_digest: ContentDigest,
    pub package_bytes_digest: ContentDigest,
    pub component_digest: ContentDigest,
    pub input: i32,
    pub output: i32,
    pub m3_invocation_id: String,
    pub m3_receipt_digest: ContentDigest,
    pub m3_attestation_digest: ContentDigest,
    pub m3_proof_digest: ContentDigest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub causal_context_digest: Option<ContentDigest>,
    pub execution_digest: ContentDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum M5EffectAuditKind {
    Initialization,
    ProviderProposal,
    GenerationDriver,
    ActiveExecution,
    ServedExecution,
    Shadow,
    Migration,
    Activation,
    Observation,
    Recovery,
    InFlightMigration,
    InFlightActivation,
    InFlightObservation,
    InFlightRecovery,
    InspectionDiagnostic,
}

/// One exact state → ledger → M3 receipt/attestation → backend-result crosswalk.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M5EffectAuditEntry {
    pub kind: M5EffectAuditKind,
    pub evidence_id: String,
    pub logical_effect_id: String,
    pub domain_request_digest: ContentDigest,
    pub backend_response_digest: ContentDigest,
    pub backend_fact_digest: ContentDigest,
    pub invocation_id: String,
    pub receipt_digest: ContentDigest,
    pub attestation_digest: ContentDigest,
    pub proof_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M5EffectAuditReport {
    pub reproduction_state_digest: ContentDigest,
    pub backend_snapshot_digest: ContentDigest,
    pub entries: Vec<M5EffectAuditEntry>,
    pub report_digest: ContentDigest,
}

impl M5EffectAuditReport {
    /// Validate a detached audit report's canonical ordering and content seal.
    pub fn validate(&self) -> Result<(), M5EffectPortError> {
        if self.entries.is_empty() || self.entries.len() > 10_000 {
            return Err(M5EffectPortError::ResourceBound(
                "M5 effect audit must contain 1..=10000 entries".to_string(),
            ));
        }
        let mut previous: Option<(&str, &ContentDigest)> = None;
        let mut invocations = BTreeSet::new();
        let mut proofs = BTreeSet::new();
        for entry in &self.entries {
            if entry.evidence_id.trim().is_empty()
                || entry.logical_effect_id.trim().is_empty()
                || entry.invocation_id.trim().is_empty()
            {
                return Err(M5EffectPortError::Integrity(
                    "M5 effect audit entry has an empty identity".to_string(),
                ));
            }
            if let Some((logical_effect_id, proof_digest)) = previous {
                if (entry.logical_effect_id.as_str(), &entry.proof_digest)
                    < (logical_effect_id, proof_digest)
                {
                    return Err(M5EffectPortError::Integrity(
                        "M5 effect audit entries are not canonically ordered".to_string(),
                    ));
                }
            }
            if !invocations.insert(entry.invocation_id.as_str())
                || !proofs.insert(entry.proof_digest.as_str())
            {
                return Err(M5EffectPortError::Integrity(
                    "M5 effect audit contains duplicate invocation or proof identities".to_string(),
                ));
            }
            previous = Some((entry.logical_effect_id.as_str(), &entry.proof_digest));
        }
        let expected = digest_json_content(&(
            "wasm-biotic:m5-effect-audit-report:v1",
            &self.reproduction_state_digest,
            &self.backend_snapshot_digest,
            &self.entries,
        ))?;
        if self.report_digest != expected {
            return Err(M5EffectPortError::Integrity(
                "M5 effect audit report failed its content digest".to_string(),
            ));
        }
        Ok(())
    }
}

/// The only M3 capability port used by the production M5 runtime.
pub struct M5EffectCapabilityPort {
    root: PathBuf,
    migration_artifacts_root: PathBuf,
    faults_root: PathBuf,
    ledger: Arc<M5M3InvocationProofLedger>,
    supervisor: Arc<M5SupervisorAdapter>,
    backend: Arc<FactoryEffectStore>,
    mutation_gate: Mutex<()>,
}

impl M5EffectCapabilityPort {
    pub fn open(
        root: impl AsRef<Path>,
        ledger: Arc<M5M3InvocationProofLedger>,
        supervisor: Arc<M5SupervisorAdapter>,
        backend: Arc<FactoryEffectStore>,
    ) -> Result<Self, M5EffectPortError> {
        let root = secure_root(root.as_ref())?;
        let migration_artifacts_root = secure_child(&root, MIGRATION_ARTIFACT_DIRECTORY)?;
        let faults_root = secure_child(&root, FAULT_DIRECTORY)?;
        let port = Self {
            root,
            migration_artifacts_root,
            faults_root,
            ledger,
            supervisor,
            backend,
            mutation_gate: Mutex::new(()),
        };
        port.validate_registered_migrations()?;
        port.ledger.validate_all()?;
        Ok(port)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn register_migration_artifacts(
        &self,
        artifacts: &StateMigrationArtifactBundle,
    ) -> Result<(), M5EffectPortError> {
        let _guard = self.lock_gate()?;
        artifacts.validate()?;
        let path = self.migration_artifact_path(&artifacts.bundle_digest);
        let bytes = serde_json::to_vec_pretty(artifacts)?;
        if bytes.len() > MAX_ARTIFACT_BYTES {
            return Err(M5EffectPortError::ResourceBound(format!(
                "migration artifact bundle contains {} bytes; limit is {MAX_ARTIFACT_BYTES}",
                bytes.len()
            )));
        }
        persist_immutable(&self.migration_artifacts_root, &path, &bytes)?;
        let loaded = self.load_migration_artifacts(&artifacts.bundle_digest)?;
        if &loaded != artifacts {
            return Err(M5EffectPortError::Integrity(
                "persisted migration artifacts differ from their exact registration".to_string(),
            ));
        }
        Ok(())
    }

    pub fn initialize_factory(
        &self,
        request: &FactoryInitializeRequest,
        approval_ref: &str,
    ) -> Result<(FactoryInitializationEvidence, M5M3EffectReference), M5EffectPortError> {
        let (evidence, reference) = self.invoke_domain(
            FactoryEffectOperation::Initialize,
            format!("m5-initialize:{}", request.request_digest.file_stem()),
            request,
            Some(approval_ref.to_string()),
        )?;
        validate_initialization_evidence(request, &evidence)?;
        Ok((evidence, reference))
    }

    pub fn execute_active(
        &self,
        expected_package_digest: ContentDigest,
        input: i32,
    ) -> Result<(FactoryExecutionResult, M5M3EffectReference), M5EffectPortError> {
        let request =
            crate::m5_effect_store::FactoryExecuteRequest::new(expected_package_digest, input)?;
        let (result, reference) = self.invoke_domain(
            FactoryEffectOperation::Execute,
            format!("m5-execute:{}", request.request_digest.file_stem()),
            &request,
            None,
        )?;
        validate_execution_result(&request, &result)?;
        Ok((result, reference))
    }

    /// Execute the active package through an exact M3 request that is sealed
    /// to caller-owned causal evidence created before the invocation.
    pub(crate) fn execute_active_with_causal_context(
        &self,
        expected_package_digest: ContentDigest,
        input: i32,
        causal_context_digest: ContentDigest,
    ) -> Result<(FactoryExecutionResult, M5M3EffectReference), M5EffectPortError> {
        let request = crate::m5_effect_store::FactoryExecuteRequest::new_with_causal_context(
            expected_package_digest,
            input,
            causal_context_digest,
        )?;
        let (result, reference) = self.invoke_domain(
            FactoryEffectOperation::Execute,
            format!("m5-execute:{}", request.request_digest.file_stem()),
            &request,
            None,
        )?;
        validate_execution_result(&request, &result)?;
        Ok((result, reference))
    }

    /// Admit one frozen provider proposal through the durable M3 effect path.
    ///
    /// This read-only operation records exact proposal material and returns its
    /// M3 receipt/attestation reference. Provider qualification and publication
    /// into the separate candidate-binding store remain outside this method.
    pub fn record_provider_proposal(
        &self,
        request: &FactoryProviderProposalRequest,
    ) -> Result<(FactoryProviderProposalResult, M5M3EffectReference), M5EffectPortError> {
        request.validate()?;
        let (result, reference): (FactoryProviderProposalResult, M5M3EffectReference) = self
            .invoke_domain(
                FactoryEffectOperation::ProviderProposal,
                format!(
                    "m5-provider-proposal:{}",
                    request.request_digest.file_stem()
                ),
                request,
                None,
            )?;
        result.validate_for(request)?;
        Ok((result, reference))
    }

    /// Re-resolve one retained provider-proposal reference against the
    /// independently owned M3 ledger and backend CAS journal.
    ///
    /// A provider binding may retain these exact values, but it is never their
    /// authority. This method rejects missing, tampered, or cross-linked proof
    /// material after reopen.
    pub fn validate_provider_proposal_reference(
        &self,
        request: &FactoryProviderProposalRequest,
        result: &FactoryProviderProposalResult,
        reference: &M5M3EffectReference,
    ) -> Result<(), M5EffectPortError> {
        request.validate()?;
        result.validate_for(request)?;
        let expected_logical_effect_id = format!(
            "m5-provider-proposal:{}",
            request.request_digest.file_stem()
        );
        if reference.logical_effect_id != expected_logical_effect_id {
            return Err(M5EffectPortError::Integrity(
                "provider proposal reference uses a noncanonical logical effect id".to_string(),
            ));
        }
        let proofs = self.ledger.validate_all()?;
        let proof = proofs
            .iter()
            .find(|proof| proof.request.logical_effect_id == reference.logical_effect_id)
            .ok_or_else(|| {
                M5EffectPortError::Integrity(format!(
                    "provider proposal proof '{}' is absent from the M3 ledger",
                    reference.logical_effect_id
                ))
            })?;
        let fact = validate_succeeded_proof(proof)?;
        let (
            ValidatedDomainRequest::ProviderProposal(proven_request),
            ValidatedDomainResponse::ProviderProposal(proven_result),
        ) = (&fact.request, &fact.response)
        else {
            return Err(M5EffectPortError::Integrity(
                "provider proposal reference resolves to a different M3 operation".to_string(),
            ));
        };
        if proven_request != request
            || proven_result != result
            || proof.proof_digest != reference.proof_digest
            || fact.attempt.receipt.invocation_id() != reference.invocation_id
            || fact.attempt.receipt.receipt_digest() != &reference.receipt_digest
            || fact.attempt.attestation.attestation_digest != reference.attestation_digest
        {
            return Err(M5EffectPortError::Integrity(
                "provider proposal request, result, receipt, attestation, or proof is cross-linked"
                    .to_string(),
            ));
        }
        let backend = self
            .backend
            .effect_fact(&reference.logical_effect_id)?
            .ok_or_else(|| {
                M5EffectPortError::Integrity(format!(
                    "provider proposal '{}' has no backend CAS fact",
                    reference.logical_effect_id
                ))
            })?;
        if backend.fact_digest != reference.backend_fact_digest
            || backend.operation != FactoryEffectOperation::ProviderProposal.capability_operation()
            || backend.request_digest != proof.request.exact_request_digest
            || backend.request_bytes_digest
                != ContentDigest::from_bytes(&proof.request.exact_request_bytes)
            || backend.response_digest != fact.result.exact_response_digest
            || backend.response_bytes != fact.result.exact_response_bytes
        {
            return Err(M5EffectPortError::Integrity(
                "provider proposal backend CAS fact is missing, tampered, or cross-linked"
                    .to_string(),
            ));
        }
        Ok(())
    }

    pub fn inspect(
        &self,
        factory_id: &str,
        context_digest: &ContentDigest,
    ) -> Result<(FactoryRuntimeInspection, M5M3EffectReference), M5EffectPortError> {
        let request = FactoryInspectRequest::new(factory_id)?;
        let (inspection, reference) = self.invoke_domain(
            FactoryEffectOperation::Inspect,
            format!(
                "m5-inspect:{}:{}",
                context_digest.file_stem(),
                request.request_digest.file_stem()
            ),
            &request,
            None,
        )?;
        validate_inspection(&request, &inspection)?;
        Ok((inspection, reference))
    }

    pub fn backend_snapshot(&self) -> Result<Option<FactoryRuntimeSnapshot>, M5EffectPortError> {
        // This is a reconciliation diagnostic, never an effect path.
        Ok(self.backend.snapshot()?)
    }

    pub fn arm_fail_after_backend_commit(&self) -> Result<(), M5EffectPortError> {
        Ok(self.backend.arm_fail_after_backend_commit()?)
    }

    pub fn arm_fail_after_deployment_commit(&self) -> Result<(), M5EffectPortError> {
        Ok(self.backend.arm_fail_after_deployment_commit()?)
    }

    pub fn arm_next_observation_regression(&self) -> Result<(), M5EffectPortError> {
        Ok(self.backend.arm_next_observation_regression()?)
    }

    pub fn arm_interrupt_before_next_activation(&self) -> Result<(), M5EffectPortError> {
        persist_immutable(
            &self.faults_root,
            &self.faults_root.join(INTERRUPT_BEFORE_ACTIVATION),
            b"armed",
        )
    }

    pub fn validate_all(&self) -> Result<(), M5EffectPortError> {
        self.validate_registered_migrations()?;
        self.ledger.validate_all()?;
        self.backend.snapshot()?;
        Ok(())
    }

    /// Prove that authoritative M5 evidence and every accepted factory-effect
    /// proof form one exact, non-ambiguous crosswalk after reopen.
    ///
    /// This is deliberately stricter than `validate_all`: the ledger may be
    /// internally sound while containing a successful effect that no durable
    /// M5 fact owns. Such an orphan is rejected. Historical inspections and
    /// provider-proposal admissions are retained as read-only M3/backend facts;
    /// neither is a mutation or a claim that the separate provider-binding
    /// store was governed by M3.
    pub fn audit_reproduction_state(
        &self,
        state: &ReproductionState,
    ) -> Result<M5EffectAuditReport, M5EffectPortError> {
        self.audit_reproduction_state_with_executions(state, &[])
    }

    /// Variant of [`Self::audit_reproduction_state`] that accepts exact
    /// externally retained references returned by ad-hoc active executions.
    pub fn audit_reproduction_state_with_executions(
        &self,
        state: &ReproductionState,
        active_executions: &[M5ActiveExecutionAuditRecord],
    ) -> Result<M5EffectAuditReport, M5EffectPortError> {
        self.validate_registered_migrations()?;
        if state.factory_id != self.ledger.config().factory_id {
            return Err(M5EffectPortError::Integrity(format!(
                "reproduction factory '{}' differs from proof-ledger factory '{}'",
                state.factory_id,
                self.ledger.config().factory_id
            )));
        }
        validate_reproduction_state_anchor(state)?;
        let proofs = self.ledger.validate_all()?;
        let backend_snapshot = self.backend.snapshot()?.ok_or_else(|| {
            M5EffectPortError::Integrity(
                "effect backend has no authoritative active snapshot".to_string(),
            )
        })?;
        let backend_facts = self.backend.all_effect_facts()?;
        audit_effect_crosswalk(
            state,
            active_executions,
            &proofs,
            &backend_facts,
            &backend_snapshot,
        )
    }

    fn invoke_domain<TRequest, TResponse>(
        &self,
        operation: FactoryEffectOperation,
        logical_effect_id: String,
        request: &TRequest,
        approval_ref: Option<String>,
    ) -> Result<(TResponse, M5M3EffectReference), M5EffectPortError>
    where
        TRequest: Serialize,
        TResponse: DeserializeOwned,
    {
        let _guard = self.lock_gate()?;
        let exact_request_bytes = serde_json::to_vec(request)?;
        let proof = self.ledger.invoke(FactoryEffectInvokeRequest::new(
            operation,
            logical_effect_id,
            exact_request_bytes,
            approval_ref,
        ))?;
        let (result, attempt) = successful_result(&proof)?;
        let response: TResponse = serde_json::from_slice(&result.exact_response_bytes)?;
        let backend_fact = self
            .backend
            .effect_fact(&proof.request.logical_effect_id)?
            .ok_or_else(|| {
                M5EffectPortError::Integrity(format!(
                    "successful M3 effect '{}' has no independently retained backend CAS fact",
                    proof.request.logical_effect_id
                ))
            })?;
        if backend_fact.operation != operation.capability_operation()
            || backend_fact.request_digest != proof.request.exact_request_digest
            || backend_fact.request_bytes_digest
                != ContentDigest::from_bytes(&proof.request.exact_request_bytes)
            || backend_fact.response_digest != result.exact_response_digest
            || backend_fact.response_bytes != result.exact_response_bytes
        {
            return Err(M5EffectPortError::Integrity(format!(
                "backend CAS fact '{}' differs from successful M3 proof '{}'",
                backend_fact.fact_digest, proof.proof_digest
            )));
        }
        Ok((
            response,
            M5M3EffectReference {
                logical_effect_id: proof.request.logical_effect_id.clone(),
                invocation_id: attempt.receipt.invocation_id().to_string(),
                receipt_digest: attempt.receipt.receipt_digest().clone(),
                attestation_digest: attempt.attestation.attestation_digest.clone(),
                proof_digest: proof.proof_digest,
                backend_fact_digest: backend_fact.fact_digest,
            },
        ))
    }

    fn approved_cycle(
        &self,
        cycle_id: &str,
    ) -> Result<M5PromotionApprovalReference, M5EffectPortError> {
        self.supervisor
            .approval_for_cycle(cycle_id)?
            .ok_or_else(|| {
                M5EffectPortError::Approval(format!(
                    "cycle '{cycle_id}' has no exact approved M2 decision"
                ))
            })
    }

    fn recovery_approval_ref(
        &self,
        request: &RecoveryRequest,
    ) -> Result<String, M5EffectPortError> {
        if let Some(approval) = self.supervisor.approval_for_cycle(&request.cycle_id)? {
            return Ok(approval.approval_ref);
        }
        let authorization = self
            .supervisor
            .operator_rollback_authorization(&request.recovery_id)?
            .ok_or_else(|| {
                M5EffectPortError::Approval(format!(
                    "recovery '{}' has neither cycle approval nor operator rollback authority",
                    request.recovery_id
                ))
            })?;
        validate_rollback_recovery(request, &authorization)?;
        Ok(authorization.authorization_digest.to_string())
    }

    fn load_migration_artifacts(
        &self,
        digest: &ContentDigest,
    ) -> Result<StateMigrationArtifactBundle, M5EffectPortError> {
        let path = self.migration_artifact_path(digest);
        let bytes = read_regular(&path, MAX_ARTIFACT_BYTES)?;
        let artifacts: StateMigrationArtifactBundle = serde_json::from_slice(&bytes)?;
        artifacts.validate()?;
        if &artifacts.bundle_digest != digest {
            return Err(M5EffectPortError::Integrity(format!(
                "migration artifact file '{}' has the wrong content identity",
                path.display()
            )));
        }
        Ok(artifacts)
    }

    fn migration_artifact_path(&self, digest: &ContentDigest) -> PathBuf {
        self.migration_artifacts_root
            .join(format!("{}.json", digest.file_stem()))
    }

    fn validate_registered_migrations(&self) -> Result<(), M5EffectPortError> {
        for entry in fs::read_dir(&self.migration_artifacts_root)
            .map_err(|error| M5EffectPortError::io(&self.migration_artifacts_root, error))?
        {
            let entry = entry
                .map_err(|error| M5EffectPortError::io(&self.migration_artifacts_root, error))?;
            let path = entry.path();
            let metadata =
                fs::symlink_metadata(&path).map_err(|error| M5EffectPortError::io(&path, error))?;
            if !metadata.file_type().is_file()
                || path.extension().and_then(|value| value.to_str()) != Some("json")
            {
                return Err(M5EffectPortError::Integrity(format!(
                    "unexpected migration artifact entry '{}'",
                    path.display()
                )));
            }
            let bytes = read_regular(&path, MAX_ARTIFACT_BYTES)?;
            let artifacts: StateMigrationArtifactBundle = serde_json::from_slice(&bytes)?;
            artifacts.validate()?;
            if path != self.migration_artifact_path(&artifacts.bundle_digest) {
                return Err(M5EffectPortError::Integrity(format!(
                    "migration artifact '{}' is not named by its digest",
                    path.display()
                )));
            }
        }
        Ok(())
    }

    /// Freeze all M5 effect admission while an authoritative export is audited
    /// and sealed. Callers must acquire the reproduction-engine lock first.
    pub(crate) fn lock_gate(&self) -> Result<MutexGuard<'_, ()>, M5EffectPortError> {
        self.mutation_gate
            .lock()
            .map_err(|_| M5EffectPortError::LockPoisoned)
    }

    fn consume_activation_interrupt(&self) -> Result<bool, M5EffectPortError> {
        let path = self.faults_root.join(INTERRUPT_BEFORE_ACTIVATION);
        if !path.exists() {
            return Ok(false);
        }
        let consumed = self.faults_root.join(format!(
            "{INTERRUPT_BEFORE_ACTIVATION}.consumed.{}",
            TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::rename(&path, &consumed).map_err(|error| M5EffectPortError::io(&path, error))?;
        Ok(true)
    }
}

impl M3CapabilityPort for M5EffectCapabilityPort {
    fn execute_generation_driver(
        &self,
        request: &GenerationDriverRequest,
    ) -> Result<GenerationDriverEvidence, PortFailure> {
        let (result, reference) = self
            .execute_active(
                request.executor_package_digest.clone(),
                request.driver_contract.driver_input,
            )
            .map_err(M5EffectPortError::into_port_failure)?;
        if result.snapshot.package_bytes_digest != request.executor_package_bytes_digest
            || result.snapshot.component_digest != request.executor_component_digest
            || result.trace.component_digest != request.executor_component_digest
            || result.trace.export_name != request.driver_contract.exported_function
            || result.input != request.driver_contract.driver_input
        {
            return Err(PortFailure::failed(
                "m5_generation_driver_identity_mismatch",
                "receipted execution differs from the exact active driver request",
            ));
        }
        GenerationDriverEvidence {
            request_digest: request.request_digest.clone(),
            invocation_id: reference.invocation_id,
            executor_package_digest: request.executor_package_digest.clone(),
            executor_package_bytes_digest: request.executor_package_bytes_digest.clone(),
            executor_component_digest: request.executor_component_digest.clone(),
            instruction_digest: request.instruction_digest.clone(),
            directive: result.output,
            trace: result.trace,
            service_receipt_digest: reference.receipt_digest,
            service_attestation_digest: reference.attestation_digest,
            evidence_digest: ContentDigest::from_bytes(&[]),
        }
        .seal()
        .map_err(|error| PortFailure::failed("m5_generation_driver_seal_failed", error.to_string()))
    }

    fn run_shadow(
        &self,
        request: &ShadowExecutionRequest,
    ) -> Result<ShadowExecutionEvidence, PortFailure> {
        let (evidence, _): (ShadowExecutionEvidence, M5M3EffectReference) = self
            .invoke_domain(
                FactoryEffectOperation::Shadow,
                format!("m5-shadow:{}", request.request_digest.file_stem()),
                request,
                None,
            )
            .map_err(M5EffectPortError::into_port_failure)?;
        let expected = evidence
            .clone()
            .seal()
            .map_err(|error| PortFailure::failed("m5_shadow_seal_failed", error.to_string()))?;
        if expected != evidence {
            return Err(PortFailure::failed(
                "m5_shadow_evidence_invalid",
                "receipted shadow evidence failed its domain digest",
            ));
        }
        Ok(evidence)
    }

    fn migrate_state(&self, request: &MigrationRequest) -> Result<MigrationReceipt, PortFailure> {
        let approval = self
            .approved_cycle(&request.cycle_id)
            .map_err(M5EffectPortError::into_port_failure)?;
        if approval.package_digest != request.challenger_package_digest {
            return Err(PortFailure::failed(
                "m5_migration_approval_package_mismatch",
                "M2 approval does not name the migration challenger",
            ));
        }
        let artifacts = self
            .load_migration_artifacts(&request.plan.migration_program_digest)
            .map_err(M5EffectPortError::into_port_failure)?;
        let effect =
            FactoryMigrationEffectRequest::new(request.clone(), artifacts).map_err(|error| {
                PortFailure::failed("m5_migration_artifacts_invalid", error.to_string())
            })?;
        let (receipt, _) = self
            .invoke_domain(
                FactoryEffectOperation::StateMigrate,
                format!("m5-migrate:{}", request.request_digest.file_stem()),
                &effect,
                Some(approval.approval_ref),
            )
            .map_err(M5EffectPortError::into_port_failure)?;
        validate_sealed_migration(&receipt)?;
        Ok(receipt)
    }

    fn activate_exact(
        &self,
        request: &ActivationRequest,
    ) -> Result<ActivationReceipt, PortFailure> {
        if self
            .consume_activation_interrupt()
            .map_err(M5EffectPortError::into_port_failure)?
        {
            return Err(PortFailure::unavailable(
                "m5_activation_interrupted",
                "activation was interrupted after migration and before routing",
            ));
        }
        let approval = self
            .approved_cycle(&request.cycle_id)
            .map_err(M5EffectPortError::into_port_failure)?;
        if approval.approval_digest != request.approval_digest
            || approval.package_digest != request.challenger_package_digest
            || approval.package_bytes_digest
                != ContentDigest::from_bytes(&request.challenger_package_bytes)
        {
            return Err(PortFailure::failed(
                "m5_activation_approval_mismatch",
                "activation bytes differ from the exact M2 approval",
            ));
        }
        let (receipt, _) = self
            .invoke_domain(
                FactoryEffectOperation::Activate,
                format!("m5-activate:{}", request.request_digest.file_stem()),
                request,
                Some(approval.approval_ref),
            )
            .map_err(M5EffectPortError::into_port_failure)?;
        validate_sealed_activation(&receipt)?;
        Ok(receipt)
    }

    fn observe_active(
        &self,
        request: &PostActivationRequest,
    ) -> Result<PostActivationEvidence, PortFailure> {
        let approval = self
            .approved_cycle(&request.cycle_id)
            .map_err(M5EffectPortError::into_port_failure)?;
        if approval.package_digest != request.active_package_digest
            || approval.package_bytes_digest != request.active_package_bytes_digest
        {
            return Err(PortFailure::failed(
                "m5_observation_approval_mismatch",
                "observation target differs from the exact promoted package",
            ));
        }
        let (evidence, _): (PostActivationEvidence, M5M3EffectReference) = self
            .invoke_domain(
                FactoryEffectOperation::Observe,
                format!("m5-observe:{}", request.request_digest.file_stem()),
                request,
                Some(approval.approval_ref),
            )
            .map_err(M5EffectPortError::into_port_failure)?;
        let expected = evidence.clone().seal().map_err(|error| {
            PortFailure::failed("m5_observation_seal_failed", error.to_string())
        })?;
        if expected != evidence {
            return Err(PortFailure::failed(
                "m5_observation_evidence_invalid",
                "receipted post-activation evidence failed its domain digest",
            ));
        }
        Ok(evidence)
    }

    fn recover_to_incumbent(
        &self,
        request: &RecoveryRequest,
    ) -> Result<RecoveryReceipt, PortFailure> {
        let approval_ref = self
            .recovery_approval_ref(request)
            .map_err(M5EffectPortError::into_port_failure)?;
        let (receipt, _) = self
            .invoke_domain(
                FactoryEffectOperation::Rollback,
                format!("m5-rollback:{}", request.request_digest.file_stem()),
                request,
                Some(approval_ref),
            )
            .map_err(M5EffectPortError::into_port_failure)?;
        validate_sealed_recovery(&receipt)?;
        Ok(receipt)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct EffectKey {
    operation: FactoryEffectOperation,
    domain_request_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ExpectedPayload {
    ExactResponse(Vec<u8>),
    GenerationDriver {
        request: GenerationDriverRequest,
        evidence: GenerationDriverEvidence,
    },
    ActiveExecution(M5ActiveExecutionAuditRecord),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ExpectedEffect {
    kind: M5EffectAuditKind,
    evidence_ids: BTreeSet<String>,
    cycle_ids: BTreeSet<String>,
    payload: ExpectedPayload,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ValidatedDomainRequest {
    Initialize(FactoryInitializeRequest),
    Execute(FactoryExecuteRequest),
    ProviderProposal(FactoryProviderProposalRequest),
    Shadow(ShadowExecutionRequest),
    Migration(FactoryMigrationEffectRequest),
    Activation(ActivationRequest),
    Observation(PostActivationRequest),
    Recovery(RecoveryRequest),
    Inspection(FactoryInspectRequest),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ValidatedDomainResponse {
    Initialization(FactoryInitializationEvidence),
    Execution(FactoryExecutionResult),
    ProviderProposal(FactoryProviderProposalResult),
    Shadow(ShadowExecutionEvidence),
    Migration(MigrationReceipt),
    Activation(ActivationReceipt),
    Observation(PostActivationEvidence),
    Recovery(RecoveryReceipt),
    Inspection(FactoryRuntimeInspection),
}

struct ValidatedProofFact<'a> {
    proof: &'a FactoryEffectInvocationProof,
    attempt: &'a FactoryEffectAttemptProof,
    result: &'a crate::capability_services::FactoryEffectResult,
    key: EffectKey,
    request: ValidatedDomainRequest,
    response: ValidatedDomainResponse,
}

fn audit_effect_crosswalk(
    state: &ReproductionState,
    active_executions: &[M5ActiveExecutionAuditRecord],
    proofs: &[FactoryEffectInvocationProof],
    backend_facts: &[FactoryEffectBackendFact],
    backend_snapshot: &FactoryRuntimeSnapshot,
) -> Result<M5EffectAuditReport, M5EffectPortError> {
    let mut expected = collect_expected_effects(state, active_executions)?;
    let mut backend_by_logical_id = backend_facts
        .iter()
        .map(|fact| (fact.logical_effect_id.as_str(), fact))
        .collect::<BTreeMap<_, _>>();
    if backend_by_logical_id.len() != backend_facts.len() {
        return Err(M5EffectPortError::Integrity(
            "backend effect facts contain duplicate logical identities".to_string(),
        ));
    }
    let mut entries = Vec::new();
    let mut initialization_count = 0usize;
    let mut in_flight_claimed = false;
    let mut in_flight_succeeded_operation = None;

    for proof in proofs {
        if proof.status != FactoryEffectProofStatus::Succeeded {
            continue;
        }
        let fact = validate_succeeded_proof(proof)?;
        let backend_fact_digest = validate_backend_fact(&fact, &mut backend_by_logical_id)?;
        if fact.key.operation == FactoryEffectOperation::ProviderProposal {
            validate_provider_proposal_crosswalk(state, &fact)?;
            entries.push(audit_entry(
                M5EffectAuditKind::ProviderProposal,
                format!("provider-proposal:{}", fact.key.domain_request_digest),
                &fact,
                backend_fact_digest,
            ));
            continue;
        }
        if fact.key.operation == FactoryEffectOperation::Inspect {
            entries.push(audit_entry(
                M5EffectAuditKind::InspectionDiagnostic,
                format!("inspection:{}", fact.key.domain_request_digest),
                &fact,
                backend_fact_digest,
            ));
            continue;
        }
        if fact.key.operation == FactoryEffectOperation::Initialize {
            initialization_count = initialization_count.saturating_add(1);
            if initialization_count != 1 {
                return Err(M5EffectPortError::Integrity(
                    "more than one accepted factory-initialization proof exists".to_string(),
                ));
            }
            validate_initialization_crosswalk(state, &fact)?;
            entries.push(audit_entry(
                M5EffectAuditKind::Initialization,
                "reproduction-root".to_string(),
                &fact,
                backend_fact_digest,
            ));
            continue;
        }

        if let Some(expected_effect) = expected.remove(&fact.key) {
            validate_expected_effect(state, &expected_effect, &fact)?;
            entries.push(audit_entry(
                expected_effect.kind,
                expected_effect
                    .evidence_ids
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("|"),
                &fact,
                backend_fact_digest,
            ));
            continue;
        }

        if fact.key.operation == FactoryEffectOperation::Execute {
            validate_served_execution(state, &fact)?;
            entries.push(audit_entry(
                M5EffectAuditKind::ServedExecution,
                format!("served-work:{}", fact.proof.proof_digest),
                &fact,
                backend_fact_digest,
            ));
            continue;
        }

        if !in_flight_claimed {
            if let Some(kind) = validate_in_flight_success(state, &fact)? {
                in_flight_claimed = true;
                in_flight_succeeded_operation = Some(fact.key.operation);
                let pending = state.in_flight.as_ref().expect("validated in-flight state");
                entries.push(audit_entry(
                    kind,
                    format!("in-flight:{}", pending.cycle_id),
                    &fact,
                    backend_fact_digest,
                ));
                continue;
            }
        }

        return Err(M5EffectPortError::Integrity(format!(
            "accepted {:?} proof '{}' is orphaned from authoritative M5 evidence",
            fact.key.operation, fact.proof.proof_digest
        )));
    }

    if initialization_count != 1 {
        return Err(M5EffectPortError::Integrity(
            "authoritative M5 state has no exact accepted initialization proof".to_string(),
        ));
    }
    if !backend_by_logical_id.is_empty() {
        return Err(M5EffectPortError::Integrity(format!(
            "backend retains accepted results with no successful M3 proof: {}",
            backend_by_logical_id
                .keys()
                .copied()
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    if !expected.is_empty() {
        let missing = expected
            .iter()
            .map(|(key, value)| {
                format!(
                    "{:?}:{} ({})",
                    key.operation,
                    key.domain_request_digest,
                    value
                        .evidence_ids
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("|")
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        return Err(M5EffectPortError::Integrity(format!(
            "authoritative M5 evidence is missing accepted effect proofs: {missing}"
        )));
    }

    validate_backend_projection(state, backend_snapshot, in_flight_succeeded_operation)?;
    entries.sort_by(|left, right| {
        left.logical_effect_id
            .cmp(&right.logical_effect_id)
            .then(left.proof_digest.cmp(&right.proof_digest))
    });
    let mut report = M5EffectAuditReport {
        reproduction_state_digest: state.state_digest.clone(),
        backend_snapshot_digest: backend_snapshot.snapshot_digest.clone(),
        entries,
        report_digest: ContentDigest::from_bytes(&[]),
    };
    report.report_digest = digest_json_content(&(
        "wasm-biotic:m5-effect-audit-report:v1",
        &report.reproduction_state_digest,
        &report.backend_snapshot_digest,
        &report.entries,
    ))?;
    Ok(report)
}

fn collect_expected_effects(
    state: &ReproductionState,
    active_executions: &[M5ActiveExecutionAuditRecord],
) -> Result<BTreeMap<EffectKey, ExpectedEffect>, M5EffectPortError> {
    let mut expected = BTreeMap::new();
    let mut cycle_ids = BTreeSet::new();
    for cycle in &state.cycles {
        if !cycle_ids.insert(cycle.cycle_id.as_str()) {
            return Err(M5EffectPortError::Integrity(format!(
                "cycle '{}' occurs more than once in authoritative state",
                cycle.cycle_id
            )));
        }
        validate_cycle_record_anchor(cycle)?;
        validate_sealed_shadow(&cycle.shadow_evidence)?;
        insert_exact_expected(
            &mut expected,
            FactoryEffectOperation::Shadow,
            cycle.shadow_evidence.request_digest.clone(),
            M5EffectAuditKind::Shadow,
            format!("cycle:{}:shadow", cycle.cycle_id),
            Some(cycle.cycle_id.clone()),
            &cycle.shadow_evidence,
        )?;
        if let Some(initiation) = &cycle.initiation {
            insert_driver_expected(
                &mut expected,
                initiation,
                format!("cycle:{}:driver", cycle.cycle_id),
            )?;
        }
        if let Some(receipt) = &cycle.migration_receipt {
            validate_sealed_migration(receipt).map_err(port_failure_as_integrity)?;
            insert_exact_expected(
                &mut expected,
                FactoryEffectOperation::StateMigrate,
                receipt.request_digest.clone(),
                M5EffectAuditKind::Migration,
                format!("cycle:{}:migration", cycle.cycle_id),
                Some(cycle.cycle_id.clone()),
                receipt,
            )?;
        }
        if let Some(receipt) = &cycle.activation_receipt {
            validate_sealed_activation(receipt).map_err(port_failure_as_integrity)?;
            insert_exact_expected(
                &mut expected,
                FactoryEffectOperation::Activate,
                receipt.request_digest.clone(),
                M5EffectAuditKind::Activation,
                format!("cycle:{}:activation", cycle.cycle_id),
                Some(cycle.cycle_id.clone()),
                receipt,
            )?;
        }
        if let Some(evidence) = &cycle.observation_evidence {
            validate_sealed_observation(evidence)?;
            insert_exact_expected(
                &mut expected,
                FactoryEffectOperation::Observe,
                evidence.request_digest.clone(),
                M5EffectAuditKind::Observation,
                format!("cycle:{}:observation", cycle.cycle_id),
                Some(cycle.cycle_id.clone()),
                evidence,
            )?;
        }
        if let Some(receipt) = &cycle.recovery_receipt {
            validate_sealed_recovery(receipt).map_err(port_failure_as_integrity)?;
            insert_exact_expected(
                &mut expected,
                FactoryEffectOperation::Rollback,
                receipt.request_digest.clone(),
                M5EffectAuditKind::Recovery,
                format!("cycle:{}:recovery", cycle.cycle_id),
                Some(cycle.cycle_id.clone()),
                receipt,
            )?;
        }
    }

    for initiation in &state.generation_initiations {
        insert_driver_expected(
            &mut expected,
            initiation,
            format!("generation-initiation:{}", initiation.cycle_id),
        )?;
    }
    for prepared in &state.prepared_successors {
        insert_driver_expected(
            &mut expected,
            &prepared.initiation,
            format!("prepared-successor:{}", prepared.cycle_id),
        )?;
    }
    for receipt in &state.recovery_receipts {
        validate_sealed_recovery(receipt).map_err(port_failure_as_integrity)?;
        insert_exact_expected(
            &mut expected,
            FactoryEffectOperation::Rollback,
            receipt.request_digest.clone(),
            M5EffectAuditKind::Recovery,
            format!("recovery-journal:{}", receipt.recovery_id),
            None,
            receipt,
        )?;
    }
    for rollback in &state.operator_rollbacks {
        validate_sealed_recovery(&rollback.recovery_receipt).map_err(port_failure_as_integrity)?;
        insert_exact_expected(
            &mut expected,
            FactoryEffectOperation::Rollback,
            rollback.recovery_receipt.request_digest.clone(),
            M5EffectAuditKind::Recovery,
            format!("operator-rollback:{}", rollback.rollback_id),
            Some(rollback.rollback_id.clone()),
            &rollback.recovery_receipt,
        )?;
    }
    if let Some(pending) = &state.in_flight {
        if let Some(receipt) = &pending.migration_receipt {
            validate_sealed_migration(receipt).map_err(port_failure_as_integrity)?;
            insert_exact_expected(
                &mut expected,
                FactoryEffectOperation::StateMigrate,
                receipt.request_digest.clone(),
                M5EffectAuditKind::Migration,
                format!("in-flight:{}:migration-receipt", pending.cycle_id),
                Some(pending.cycle_id.clone()),
                receipt,
            )?;
        }
        if let Some(receipt) = &pending.activation_receipt {
            validate_sealed_activation(receipt).map_err(port_failure_as_integrity)?;
            insert_exact_expected(
                &mut expected,
                FactoryEffectOperation::Activate,
                receipt.request_digest.clone(),
                M5EffectAuditKind::Activation,
                format!("in-flight:{}:activation-receipt", pending.cycle_id),
                Some(pending.cycle_id.clone()),
                receipt,
            )?;
        }
    }

    let mut active_invocation_ids = BTreeSet::new();
    for execution in active_executions {
        if !active_invocation_ids.insert(execution.m3_invocation_id.as_str()) {
            return Err(M5EffectPortError::Integrity(format!(
                "active execution invocation '{}' was supplied more than once",
                execution.m3_invocation_id
            )));
        }
        let request = match &execution.causal_context_digest {
            Some(context) => FactoryExecuteRequest::new_with_causal_context(
                execution.package_digest.clone(),
                execution.input,
                context.clone(),
            )?,
            None => FactoryExecuteRequest::new(execution.package_digest.clone(), execution.input)?,
        };
        insert_expected(
            &mut expected,
            EffectKey {
                operation: FactoryEffectOperation::Execute,
                domain_request_digest: request.request_digest,
            },
            M5EffectAuditKind::ActiveExecution,
            format!("active-execution:{}", execution.execution_digest),
            None,
            ExpectedPayload::ActiveExecution(execution.clone()),
        )?;
    }
    Ok(expected)
}

fn insert_exact_expected<T: Serialize>(
    expected: &mut BTreeMap<EffectKey, ExpectedEffect>,
    operation: FactoryEffectOperation,
    request_digest: ContentDigest,
    kind: M5EffectAuditKind,
    evidence_id: String,
    cycle_id: Option<String>,
    response: &T,
) -> Result<(), M5EffectPortError> {
    insert_expected(
        expected,
        EffectKey {
            operation,
            domain_request_digest: request_digest,
        },
        kind,
        evidence_id,
        cycle_id,
        ExpectedPayload::ExactResponse(serde_json::to_vec(response)?),
    )
}

fn insert_driver_expected(
    expected: &mut BTreeMap<EffectKey, ExpectedEffect>,
    initiation: &GenerationInitiationRecord,
    evidence_id: String,
) -> Result<(), M5EffectPortError> {
    validate_generation_driver_anchor(&initiation.driver_request, &initiation.driver_evidence)?;
    if initiation.cycle_id != initiation.driver_request.cycle_id
        || initiation.executor_package_digest != initiation.driver_request.executor_package_digest
        || initiation.executor_package_bytes_digest
            != initiation.driver_request.executor_package_bytes_digest
        || initiation.instruction_digest != initiation.driver_request.instruction_digest
    {
        return Err(M5EffectPortError::Integrity(format!(
            "generation initiation '{}' differs from its driver request",
            initiation.cycle_id
        )));
    }
    let execute_request = FactoryExecuteRequest::new(
        initiation.driver_request.executor_package_digest.clone(),
        initiation.driver_request.driver_contract.driver_input,
    )?;
    insert_expected(
        expected,
        EffectKey {
            operation: FactoryEffectOperation::Execute,
            domain_request_digest: execute_request.request_digest,
        },
        M5EffectAuditKind::GenerationDriver,
        evidence_id,
        Some(initiation.cycle_id.clone()),
        ExpectedPayload::GenerationDriver {
            request: initiation.driver_request.clone(),
            evidence: initiation.driver_evidence.clone(),
        },
    )
}

fn insert_expected(
    expected: &mut BTreeMap<EffectKey, ExpectedEffect>,
    key: EffectKey,
    kind: M5EffectAuditKind,
    evidence_id: String,
    cycle_id: Option<String>,
    payload: ExpectedPayload,
) -> Result<(), M5EffectPortError> {
    if let Some(existing) = expected.get_mut(&key) {
        if existing.kind != kind || existing.payload != payload {
            return Err(M5EffectPortError::Integrity(format!(
                "conflicting M5 evidence claims {:?} request {}",
                key.operation, key.domain_request_digest
            )));
        }
        existing.evidence_ids.insert(evidence_id);
        if let Some(cycle_id) = cycle_id {
            existing.cycle_ids.insert(cycle_id);
        }
        return Ok(());
    }
    expected.insert(
        key,
        ExpectedEffect {
            kind,
            evidence_ids: BTreeSet::from([evidence_id]),
            cycle_ids: cycle_id.into_iter().collect(),
            payload,
        },
    );
    Ok(())
}

fn validate_succeeded_proof(
    proof: &FactoryEffectInvocationProof,
) -> Result<ValidatedProofFact<'_>, M5EffectPortError> {
    let (result, attempt) = successful_result(proof)?;
    if result.logical_effect_id != proof.request.logical_effect_id
        || result.exact_request_digest != proof.request.exact_request_digest
        || result.exact_response_digest != ContentDigest::from_bytes(&result.exact_response_bytes)
        || attempt.receipt.invocation_id() != attempt.attestation.invocation_id
        || attempt.receipt.receipt_digest() != &attempt.attestation.receipt_digest
    {
        return Err(M5EffectPortError::Integrity(format!(
            "accepted proof '{}' does not retain one exact backend result, receipt, and attestation",
            proof.proof_digest
        )));
    }

    let (key, request, response) = match proof.request.operation {
        FactoryEffectOperation::Initialize => {
            let request: FactoryInitializeRequest =
                decode_canonical(&proof.request.exact_request_bytes)?;
            if FactoryInitializeRequest::new(
                request.operation_id.clone(),
                request.factory_id.clone(),
                request.package_bytes.clone(),
                request.initial_state_schema,
                request.initial_state_bytes.clone(),
            )? != request
            {
                return Err(invalid_proof_request(proof, "initialization"));
            }
            let response: FactoryInitializationEvidence =
                serde_json::from_slice(&result.exact_response_bytes)?;
            validate_initialization_evidence(&request, &response)?;
            (
                EffectKey {
                    operation: proof.request.operation,
                    domain_request_digest: request.request_digest.clone(),
                },
                ValidatedDomainRequest::Initialize(request),
                ValidatedDomainResponse::Initialization(response),
            )
        }
        FactoryEffectOperation::Execute => {
            let request: FactoryExecuteRequest =
                decode_canonical(&proof.request.exact_request_bytes)?;
            let reconstructed = match &request.causal_context_digest {
                Some(context) => FactoryExecuteRequest::new_with_causal_context(
                    request.expected_package_digest.clone(),
                    request.input,
                    context.clone(),
                )?,
                None => FactoryExecuteRequest::new(
                    request.expected_package_digest.clone(),
                    request.input,
                )?,
            };
            if reconstructed != request {
                return Err(invalid_proof_request(proof, "execution"));
            }
            let response: FactoryExecutionResult =
                serde_json::from_slice(&result.exact_response_bytes)?;
            validate_execution_result(&request, &response)?;
            (
                EffectKey {
                    operation: proof.request.operation,
                    domain_request_digest: request.request_digest.clone(),
                },
                ValidatedDomainRequest::Execute(request),
                ValidatedDomainResponse::Execution(response),
            )
        }
        FactoryEffectOperation::ProviderProposal => {
            let request: FactoryProviderProposalRequest =
                decode_canonical(&proof.request.exact_request_bytes)?;
            if FactoryProviderProposalRequest::new(
                request.qualification_request.clone(),
                request.normalized_parser_input_bytes.clone(),
            )? != request
            {
                return Err(invalid_proof_request(proof, "provider proposal"));
            }
            let response: FactoryProviderProposalResult =
                serde_json::from_slice(&result.exact_response_bytes)?;
            response.validate_for(&request)?;
            (
                EffectKey {
                    operation: proof.request.operation,
                    domain_request_digest: request.request_digest.clone(),
                },
                ValidatedDomainRequest::ProviderProposal(request),
                ValidatedDomainResponse::ProviderProposal(response),
            )
        }
        FactoryEffectOperation::Shadow => {
            let request: ShadowExecutionRequest =
                decode_canonical(&proof.request.exact_request_bytes)?;
            validate_shadow_request(&request)?;
            let response: ShadowExecutionEvidence =
                serde_json::from_slice(&result.exact_response_bytes)?;
            validate_sealed_shadow(&response)?;
            if response.request_digest != request.request_digest {
                return Err(invalid_proof_response(proof, "shadow"));
            }
            (
                EffectKey {
                    operation: proof.request.operation,
                    domain_request_digest: request.request_digest.clone(),
                },
                ValidatedDomainRequest::Shadow(request),
                ValidatedDomainResponse::Shadow(response),
            )
        }
        FactoryEffectOperation::StateMigrate => {
            let request: FactoryMigrationEffectRequest =
                decode_canonical(&proof.request.exact_request_bytes)?;
            if FactoryMigrationEffectRequest::new(
                request.request.clone(),
                request.artifacts.clone(),
            )? != request
            {
                return Err(invalid_proof_request(proof, "migration"));
            }
            validate_migration_request(&request.request)?;
            let response: MigrationReceipt = serde_json::from_slice(&result.exact_response_bytes)?;
            validate_sealed_migration(&response).map_err(port_failure_as_integrity)?;
            if response.request_digest != request.request.request_digest {
                return Err(invalid_proof_response(proof, "migration"));
            }
            (
                EffectKey {
                    operation: proof.request.operation,
                    domain_request_digest: request.request.request_digest.clone(),
                },
                ValidatedDomainRequest::Migration(request),
                ValidatedDomainResponse::Migration(response),
            )
        }
        FactoryEffectOperation::Activate => {
            let request: ActivationRequest = decode_canonical(&proof.request.exact_request_bytes)?;
            validate_activation_request(&request)?;
            let response: ActivationReceipt = serde_json::from_slice(&result.exact_response_bytes)?;
            validate_sealed_activation(&response).map_err(port_failure_as_integrity)?;
            if response.request_digest != request.request_digest {
                return Err(invalid_proof_response(proof, "activation"));
            }
            (
                EffectKey {
                    operation: proof.request.operation,
                    domain_request_digest: request.request_digest.clone(),
                },
                ValidatedDomainRequest::Activation(request),
                ValidatedDomainResponse::Activation(response),
            )
        }
        FactoryEffectOperation::Observe => {
            let request: PostActivationRequest =
                decode_canonical(&proof.request.exact_request_bytes)?;
            validate_observation_request(&request)?;
            let response: PostActivationEvidence =
                serde_json::from_slice(&result.exact_response_bytes)?;
            validate_sealed_observation(&response)?;
            if response.request_digest != request.request_digest {
                return Err(invalid_proof_response(proof, "observation"));
            }
            (
                EffectKey {
                    operation: proof.request.operation,
                    domain_request_digest: request.request_digest.clone(),
                },
                ValidatedDomainRequest::Observation(request),
                ValidatedDomainResponse::Observation(response),
            )
        }
        FactoryEffectOperation::Rollback => {
            let request: RecoveryRequest = decode_canonical(&proof.request.exact_request_bytes)?;
            validate_recovery_request(&request)?;
            let response: RecoveryReceipt = serde_json::from_slice(&result.exact_response_bytes)?;
            validate_sealed_recovery(&response).map_err(port_failure_as_integrity)?;
            if response.request_digest != request.request_digest {
                return Err(invalid_proof_response(proof, "recovery"));
            }
            (
                EffectKey {
                    operation: proof.request.operation,
                    domain_request_digest: request.request_digest.clone(),
                },
                ValidatedDomainRequest::Recovery(request),
                ValidatedDomainResponse::Recovery(response),
            )
        }
        FactoryEffectOperation::Inspect => {
            let request: FactoryInspectRequest =
                decode_canonical(&proof.request.exact_request_bytes)?;
            if FactoryInspectRequest::new(request.factory_id.clone())? != request {
                return Err(invalid_proof_request(proof, "inspection"));
            }
            let response: FactoryRuntimeInspection =
                serde_json::from_slice(&result.exact_response_bytes)?;
            validate_inspection(&request, &response)?;
            (
                EffectKey {
                    operation: proof.request.operation,
                    domain_request_digest: request.request_digest.clone(),
                },
                ValidatedDomainRequest::Inspection(request),
                ValidatedDomainResponse::Inspection(response),
            )
        }
    };
    validate_logical_effect_id(proof, &key)?;
    Ok(ValidatedProofFact {
        proof,
        attempt,
        result,
        key,
        request,
        response,
    })
}

fn validate_backend_fact<'a>(
    fact: &ValidatedProofFact<'_>,
    backend_by_logical_id: &mut BTreeMap<&'a str, &'a FactoryEffectBackendFact>,
) -> Result<ContentDigest, M5EffectPortError> {
    let backend = backend_by_logical_id
        .remove(fact.proof.request.logical_effect_id.as_str())
        .ok_or_else(|| {
            M5EffectPortError::Integrity(format!(
                "successful M3 proof '{}' has no independently retained backend fact",
                fact.proof.proof_digest
            ))
        })?;
    if backend.operation != fact.key.operation.capability_operation()
        || backend.request_digest != fact.proof.request.exact_request_digest
        || backend.request_bytes_digest
            != ContentDigest::from_bytes(&fact.proof.request.exact_request_bytes)
        || backend.response_digest != fact.result.exact_response_digest
        || backend.response_bytes != fact.result.exact_response_bytes
    {
        return Err(M5EffectPortError::Integrity(format!(
            "backend fact '{}' differs from its exact M3 request/result proof",
            backend.fact_digest
        )));
    }
    Ok(backend.fact_digest.clone())
}

fn validate_provider_proposal_crosswalk(
    state: &ReproductionState,
    fact: &ValidatedProofFact<'_>,
) -> Result<(), M5EffectPortError> {
    let (
        ValidatedDomainRequest::ProviderProposal(request),
        ValidatedDomainResponse::ProviderProposal(result),
    ) = (&fact.request, &fact.response)
    else {
        return Err(M5EffectPortError::Integrity(
            "provider proposal classified from a different effect type".to_string(),
        ));
    };
    result.validate_for(request)?;
    if !state
        .package_index
        .contains_key(request.qualification_request.package_digest.as_str())
    {
        return Err(M5EffectPortError::Integrity(format!(
            "provider proposal qualifies package '{}' absent from reproduction lineage",
            request.qualification_request.package_digest
        )));
    }
    Ok(())
}

fn validate_served_execution(
    state: &ReproductionState,
    fact: &ValidatedProofFact<'_>,
) -> Result<(), M5EffectPortError> {
    let (ValidatedDomainRequest::Execute(request), ValidatedDomainResponse::Execution(result)) =
        (&fact.request, &fact.response)
    else {
        return Err(M5EffectPortError::Integrity(
            "served execution classified from a non-execution proof".to_string(),
        ));
    };
    let index = state
        .package_index
        .get(request.expected_package_digest.as_str())
        .ok_or_else(|| {
            M5EffectPortError::Integrity(format!(
                "served execution targets package '{}' absent from reproduction lineage",
                request.expected_package_digest
            ))
        })?;
    if result.snapshot.package_digest != request.expected_package_digest
        || result.snapshot.generation != index.generation
    {
        return Err(M5EffectPortError::Integrity(format!(
            "served execution '{}' differs from its retained package lineage",
            fact.proof.proof_digest
        )));
    }
    Ok(())
}

fn validate_expected_effect(
    state: &ReproductionState,
    expected: &ExpectedEffect,
    fact: &ValidatedProofFact<'_>,
) -> Result<(), M5EffectPortError> {
    match &expected.payload {
        ExpectedPayload::ExactResponse(bytes) => {
            if &fact.result.exact_response_bytes != bytes {
                return Err(M5EffectPortError::Integrity(format!(
                    "backend response for {:?} request {} differs from authoritative M5 evidence",
                    fact.key.operation, fact.key.domain_request_digest
                )));
            }
            validate_cycle_request_context(state, expected, fact)
        }
        ExpectedPayload::GenerationDriver { request, evidence } => {
            let (
                ValidatedDomainRequest::Execute(execute_request),
                ValidatedDomainResponse::Execution(result),
            ) = (&fact.request, &fact.response)
            else {
                return Err(M5EffectPortError::Integrity(
                    "generation-driver evidence mapped to a non-execution proof".to_string(),
                ));
            };
            validate_generation_driver_result(request, evidence, execute_request, result, fact)
        }
        ExpectedPayload::ActiveExecution(execution) => {
            let (
                ValidatedDomainRequest::Execute(execute_request),
                ValidatedDomainResponse::Execution(result),
            ) = (&fact.request, &fact.response)
            else {
                return Err(M5EffectPortError::Integrity(
                    "active-execution evidence mapped to a non-execution proof".to_string(),
                ));
            };
            validate_active_execution(execution, execute_request, result, fact)
        }
    }
}

fn validate_cycle_request_context(
    state: &ReproductionState,
    expected: &ExpectedEffect,
    fact: &ValidatedProofFact<'_>,
) -> Result<(), M5EffectPortError> {
    for cycle_id in &expected.cycle_ids {
        let cycle = state
            .cycles
            .iter()
            .find(|cycle| &cycle.cycle_id == cycle_id);
        match (&fact.request, expected.kind) {
            (ValidatedDomainRequest::Shadow(request), M5EffectAuditKind::Shadow) => {
                let cycle = cycle.ok_or_else(|| missing_cycle(cycle_id, expected.kind))?;
                if request.cycle_id != cycle.cycle_id
                    || request.incumbent_package_digest != cycle.parent_package_digest
                    || request.challenger_package_digest != cycle.challenger_package_digest
                    || ContentDigest::from_bytes(&request.incumbent_package_bytes)
                        != request.incumbent_package_digest
                    || ContentDigest::from_bytes(&request.challenger_package_bytes)
                        != cycle.challenger_package_bytes_digest
                    || request.gate.gate_digest != cycle.gate_digest
                {
                    return Err(cycle_request_mismatch(cycle_id, expected.kind));
                }
            }
            (ValidatedDomainRequest::Migration(effect), M5EffectAuditKind::Migration) => {
                let cycle = cycle.ok_or_else(|| missing_cycle(cycle_id, expected.kind))?;
                if effect.request.cycle_id != cycle.cycle_id
                    || effect.request.incumbent_package_digest != cycle.parent_package_digest
                    || effect.request.challenger_package_digest != cycle.challenger_package_digest
                    || cycle.migration_plan.as_ref() != Some(&effect.request.plan)
                {
                    return Err(cycle_request_mismatch(cycle_id, expected.kind));
                }
            }
            (ValidatedDomainRequest::Activation(request), M5EffectAuditKind::Activation) => {
                let cycle = cycle.ok_or_else(|| missing_cycle(cycle_id, expected.kind))?;
                let approval = cycle.approval.as_ref().ok_or_else(|| {
                    M5EffectPortError::Integrity(format!(
                        "cycle '{cycle_id}' activation has no authoritative approval"
                    ))
                })?;
                if request.cycle_id != cycle.cycle_id
                    || request.incumbent_package_digest != cycle.parent_package_digest
                    || request.challenger_package_digest != cycle.challenger_package_digest
                    || ContentDigest::from_bytes(&request.challenger_package_bytes)
                        != cycle.challenger_package_bytes_digest
                    || request.approval_digest != approval.approval_digest
                    || request.gate_decision_digest != cycle.gate_decision.decision_digest
                {
                    return Err(cycle_request_mismatch(cycle_id, expected.kind));
                }
            }
            (ValidatedDomainRequest::Observation(request), M5EffectAuditKind::Observation) => {
                let cycle = cycle.ok_or_else(|| missing_cycle(cycle_id, expected.kind))?;
                let activation = cycle.activation_receipt.as_ref().ok_or_else(|| {
                    M5EffectPortError::Integrity(format!(
                        "cycle '{cycle_id}' observation has no authoritative activation"
                    ))
                })?;
                if request.cycle_id != cycle.cycle_id
                    || request.activation_id != activation.activation_id
                    || request.active_package_digest != activation.active_package_digest
                    || request.active_package_bytes_digest != activation.active_package_bytes_digest
                    || request.minimum_successes
                        != state
                            .release_gate
                            .thresholds
                            .minimum_post_activation_successes
                {
                    return Err(cycle_request_mismatch(cycle_id, expected.kind));
                }
            }
            (ValidatedDomainRequest::Recovery(request), M5EffectAuditKind::Recovery) => {
                if let Some(cycle) = cycle {
                    if request.cycle_id != cycle.cycle_id
                        || request.restore_package_digest != cycle.parent_package_digest
                    {
                        return Err(cycle_request_mismatch(cycle_id, expected.kind));
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_generation_driver_result(
    request: &GenerationDriverRequest,
    evidence: &GenerationDriverEvidence,
    execute_request: &FactoryExecuteRequest,
    result: &FactoryExecutionResult,
    fact: &ValidatedProofFact<'_>,
) -> Result<(), M5EffectPortError> {
    if execute_request.expected_package_digest != request.executor_package_digest
        || execute_request.input != request.driver_contract.driver_input
        || result.snapshot.package_digest != request.executor_package_digest
        || result.snapshot.package_bytes_digest != request.executor_package_bytes_digest
        || result.snapshot.component_digest != request.executor_component_digest
        || result.trace.component_digest != request.executor_component_digest
        || result.trace.export_name != request.driver_contract.exported_function
        || result.input != request.driver_contract.driver_input
        || result.output != evidence.directive
        || result.trace != evidence.trace
        || evidence.request_digest != request.request_digest
        || evidence.invocation_id != fact.attempt.receipt.invocation_id()
        || evidence.service_receipt_digest != *fact.attempt.receipt.receipt_digest()
        || evidence.service_attestation_digest != fact.attempt.attestation.attestation_digest
    {
        return Err(M5EffectPortError::Integrity(format!(
            "generation-driver evidence for cycle '{}' differs from its exact execution proof",
            request.cycle_id
        )));
    }
    Ok(())
}

fn validate_active_execution(
    execution: &M5ActiveExecutionAuditRecord,
    request: &FactoryExecuteRequest,
    result: &FactoryExecutionResult,
    fact: &ValidatedProofFact<'_>,
) -> Result<(), M5EffectPortError> {
    let expected_digest = match &execution.causal_context_digest {
        None => digest_json_content(&(
            "wasm-biotic:m5-active-execution:v2",
            &execution.package_digest,
            &execution.package_bytes_digest,
            &execution.component_digest,
            execution.input,
            execution.output,
            &execution.m3_invocation_id,
            &execution.m3_receipt_digest,
            &execution.m3_attestation_digest,
            &execution.m3_proof_digest,
            &result.trace,
        ))?,
        Some(context) => digest_json_content(&(
            "wasm-biotic:m5-active-execution:v3",
            &execution.package_digest,
            &execution.package_bytes_digest,
            &execution.component_digest,
            execution.input,
            execution.output,
            &execution.m3_invocation_id,
            &execution.m3_receipt_digest,
            &execution.m3_attestation_digest,
            &execution.m3_proof_digest,
            context,
            &result.trace,
        ))?,
    };
    if execution.execution_digest != expected_digest
        || execution.package_digest != request.expected_package_digest
        || execution.input != request.input
        || execution.package_digest != result.snapshot.package_digest
        || execution.package_bytes_digest != result.snapshot.package_bytes_digest
        || execution.component_digest != result.snapshot.component_digest
        || execution.input != result.input
        || execution.output != result.output
        || execution.m3_invocation_id != fact.attempt.receipt.invocation_id()
        || execution.m3_receipt_digest != *fact.attempt.receipt.receipt_digest()
        || execution.m3_attestation_digest != fact.attempt.attestation.attestation_digest
        || execution.m3_proof_digest != fact.proof.proof_digest
        || execution.causal_context_digest != request.causal_context_digest
    {
        return Err(M5EffectPortError::Integrity(format!(
            "active execution '{}' differs from its exact M3-backed result",
            execution.execution_digest
        )));
    }
    Ok(())
}

fn validate_in_flight_success(
    state: &ReproductionState,
    fact: &ValidatedProofFact<'_>,
) -> Result<Option<M5EffectAuditKind>, M5EffectPortError> {
    let Some(pending) = state.in_flight.as_ref() else {
        return Ok(None);
    };
    let cycle = state
        .cycles
        .iter()
        .find(|cycle| cycle.cycle_id == pending.cycle_id);
    let kind = match (&pending.stage, &fact.request, &fact.response) {
        (
            PendingStage::MigrationRequested,
            ValidatedDomainRequest::Migration(effect),
            ValidatedDomainResponse::Migration(receipt),
        ) => {
            let cycle = cycle.ok_or_else(|| {
                M5EffectPortError::Integrity(format!(
                    "in-flight migration '{}' has no durable cycle",
                    pending.cycle_id
                ))
            })?;
            if effect.request.cycle_id != pending.cycle_id
                || effect.request.incumbent_package_digest != pending.incumbent_package_digest
                || effect.request.challenger_package_digest != pending.challenger_package_digest
                || cycle.migration_plan.as_ref() != Some(&effect.request.plan)
                || receipt.request_digest != effect.request.request_digest
            {
                return Err(in_flight_mismatch(pending, "migration"));
            }
            M5EffectAuditKind::InFlightMigration
        }
        (
            PendingStage::ActivationRequested,
            ValidatedDomainRequest::Activation(request),
            ValidatedDomainResponse::Activation(receipt),
        ) => {
            let cycle = cycle.ok_or_else(|| {
                M5EffectPortError::Integrity(format!(
                    "in-flight activation '{}' has no durable cycle",
                    pending.cycle_id
                ))
            })?;
            if request.cycle_id != pending.cycle_id
                || request.incumbent_package_digest != pending.incumbent_package_digest
                || request.challenger_package_digest != pending.challenger_package_digest
                || request.target_state_schema != pending.target_state_schema
                || ContentDigest::from_bytes(&request.challenger_package_bytes)
                    != cycle.challenger_package_bytes_digest
                || receipt.request_digest != request.request_digest
            {
                return Err(in_flight_mismatch(pending, "activation"));
            }
            M5EffectAuditKind::InFlightActivation
        }
        (
            PendingStage::ObservationRequested,
            ValidatedDomainRequest::Observation(request),
            ValidatedDomainResponse::Observation(evidence),
        ) => {
            let activation = pending.activation_receipt.as_ref().ok_or_else(|| {
                M5EffectPortError::Integrity(
                    "in-flight observation has no exact activation receipt".to_string(),
                )
            })?;
            if request.cycle_id != pending.cycle_id
                || request.activation_id != activation.activation_id
                || request.active_package_digest != pending.challenger_package_digest
                || request.active_package_bytes_digest != activation.active_package_bytes_digest
                || evidence.request_digest != request.request_digest
            {
                return Err(in_flight_mismatch(pending, "observation"));
            }
            M5EffectAuditKind::InFlightObservation
        }
        (
            PendingStage::RollbackRequested,
            ValidatedDomainRequest::Recovery(request),
            ValidatedDomainResponse::Recovery(receipt),
        ) => {
            if request.cycle_id != pending.cycle_id
                || request.restore_package_digest != pending.incumbent_package_digest
                || request.restore_state_schema != pending.incumbent_state_schema
                || request.migration_receipt != pending.migration_receipt
                || request.activation_receipt != pending.activation_receipt
                || receipt.request_digest != request.request_digest
            {
                return Err(in_flight_mismatch(pending, "recovery"));
            }
            M5EffectAuditKind::InFlightRecovery
        }
        _ => return Ok(None),
    };
    Ok(Some(kind))
}

fn validate_initialization_crosswalk(
    state: &ReproductionState,
    fact: &ValidatedProofFact<'_>,
) -> Result<(), M5EffectPortError> {
    let (
        ValidatedDomainRequest::Initialize(request),
        ValidatedDomainResponse::Initialization(evidence),
    ) = (&fact.request, &fact.response)
    else {
        return Err(M5EffectPortError::Integrity(
            "initialization proof decoded as a different domain effect".to_string(),
        ));
    };
    let package =
        FactoryPackage::from_canonical_bytes(&request.package_bytes).map_err(|error| {
            M5EffectPortError::Integrity(format!(
                "initialization package cannot be reloaded exactly: {error}"
            ))
        })?;
    let index = state
        .package_index
        .get(package.package_digest.as_str())
        .ok_or_else(|| {
            M5EffectPortError::Integrity(
                "initialized package is absent from the reproduction package index".to_string(),
            )
        })?;
    let roots = state
        .lineage
        .iter()
        .filter(|record| record.disposition == LineageDisposition::Root)
        .collect::<Vec<_>>();
    if request.factory_id != state.factory_id
        || package.payload.factory_id != state.factory_id
        || package.payload.generation != 0
        || package.payload.parent_package_digest.is_some()
        || index.generation != 0
        || index.byte_len != request.package_bytes.len() as u64
        || evidence.snapshot.package_digest != package.package_digest
        || evidence.snapshot.package_bytes_digest
            != ContentDigest::from_bytes(&request.package_bytes)
        || evidence.snapshot.component_digest != package.payload.genome.component_digest
        || evidence.snapshot.state_schema != request.initial_state_schema
        || roots.len() != 1
        || roots[0].package_digest != package.package_digest
        || roots[0].package_bytes_digest != ContentDigest::from_bytes(&request.package_bytes)
        || roots[0].genome_digest != package.payload.genome.genome_digest
    {
        return Err(M5EffectPortError::Integrity(
            "accepted initialization proof differs from the exact reproduction root".to_string(),
        ));
    }
    Ok(())
}

fn validate_backend_projection(
    state: &ReproductionState,
    snapshot: &FactoryRuntimeSnapshot,
    in_flight_succeeded_operation: Option<FactoryEffectOperation>,
) -> Result<(), M5EffectPortError> {
    validate_snapshot(snapshot)?;
    if snapshot.factory_id != state.factory_id {
        return Err(M5EffectPortError::Integrity(
            "effect backend snapshot names a different factory".to_string(),
        ));
    }
    let (expected_package, expected_schema) = match &state.in_flight {
        None => (
            state.active_package_digest.clone(),
            state.active_state_schema,
        ),
        Some(pending)
            if in_flight_succeeded_operation == Some(FactoryEffectOperation::Rollback) =>
        {
            (
                pending.incumbent_package_digest.clone(),
                pending.incumbent_state_schema,
            )
        }
        Some(pending)
            if in_flight_succeeded_operation == Some(FactoryEffectOperation::Activate)
                || matches!(
                    pending.stage,
                    PendingStage::Activated
                        | PendingStage::ObservationRequested
                        | PendingStage::RollbackRequested
                ) =>
        {
            (
                pending.challenger_package_digest.clone(),
                pending.target_state_schema,
            )
        }
        Some(_) => (
            state.active_package_digest.clone(),
            state.active_state_schema,
        ),
    };
    let index = state
        .package_index
        .get(expected_package.as_str())
        .ok_or_else(|| {
            M5EffectPortError::Integrity(format!(
                "expected backend package '{expected_package}' is absent from the package index"
            ))
        })?;
    if snapshot.package_digest != expected_package
        || snapshot.state_schema != expected_schema
        || snapshot.generation != index.generation
    {
        return Err(M5EffectPortError::Integrity(format!(
            "authoritative backend snapshot {} does not match the M5 projection",
            snapshot.snapshot_digest
        )));
    }
    Ok(())
}

fn validate_reproduction_state_anchor(state: &ReproductionState) -> Result<(), M5EffectPortError> {
    if state.schema_version != REPRODUCTION_STATE_SCHEMA_VERSION {
        return Err(M5EffectPortError::Integrity(format!(
            "unsupported reproduction-state schema {}",
            state.schema_version
        )));
    }
    let mut material = state.clone();
    material.state_digest = ContentDigest::from_bytes(&[]);
    let expected = digest_json_content(&("wasm-biotic:factory-reproduction-state:v6", material))?;
    if state.state_digest != expected {
        return Err(M5EffectPortError::Integrity(
            "reproduction-state digest does not match its exact fields".to_string(),
        ));
    }
    Ok(())
}

fn validate_cycle_record_anchor(cycle: &CycleRecord) -> Result<(), M5EffectPortError> {
    let mut material = cycle.clone();
    material.record_digest = ContentDigest::from_bytes(&[]);
    let expected = digest_json_content(&("wasm-biotic:factory-cycle-record:v1", material))?;
    if cycle.record_digest != expected {
        return Err(M5EffectPortError::Integrity(format!(
            "cycle '{}' record digest does not match its evidence",
            cycle.cycle_id
        )));
    }
    Ok(())
}

fn validate_generation_driver_anchor(
    request: &GenerationDriverRequest,
    evidence: &GenerationDriverEvidence,
) -> Result<(), M5EffectPortError> {
    let expected_request = digest_json_content(&(
        "wasm-biotic:generation-driver-request:v1",
        &request.cycle_id,
        &request.executor_package_digest,
        &request.executor_package_bytes_digest,
        &request.executor_component_digest,
        &request.stable_interface_digest,
        &request.instruction_digest,
        &request.driver_contract,
        &request.gate_digest,
        request.next_generation,
        &request.idempotency_key,
    ))?;
    if request.request_digest != expected_request
        || evidence.request_digest != request.request_digest
        || evidence.clone().seal().map_err(|error| {
            M5EffectPortError::Integrity(format!(
                "generation-driver evidence cannot be resealed: {error}"
            ))
        })? != *evidence
    {
        return Err(M5EffectPortError::Integrity(format!(
            "generation-driver evidence for '{}' failed its durable identity",
            request.cycle_id
        )));
    }
    Ok(())
}

fn validate_shadow_request(request: &ShadowExecutionRequest) -> Result<(), M5EffectPortError> {
    let expected = digest_json_content(&(
        "wasm-biotic:shadow-execution-request:v1",
        &request.cycle_id,
        &request.incumbent_package_digest,
        &request.incumbent_package_bytes,
        &request.challenger_package_digest,
        &request.challenger_package_bytes,
        &request.gate.gate_digest,
    ))?;
    if request.request_digest != expected {
        return Err(M5EffectPortError::Integrity(
            "shadow request digest does not match its exact bytes".to_string(),
        ));
    }
    Ok(())
}

fn validate_migration_request(request: &MigrationRequest) -> Result<(), M5EffectPortError> {
    let expected = digest_json_content(&(
        "wasm-biotic:migration-request:v1",
        &request.cycle_id,
        &request.incumbent_package_digest,
        &request.challenger_package_digest,
        &request.plan.plan_digest,
    ))?;
    if request.request_digest != expected {
        return Err(M5EffectPortError::Integrity(
            "migration request digest does not match its exact plan".to_string(),
        ));
    }
    Ok(())
}

fn validate_activation_request(request: &ActivationRequest) -> Result<(), M5EffectPortError> {
    let expected = digest_json_content(&(
        "wasm-biotic:activation-request:v1",
        &request.cycle_id,
        &request.incumbent_package_digest,
        &request.challenger_package_digest,
        &request.challenger_package_bytes,
        &request.approval_digest,
        &request.gate_decision_digest,
        request.target_state_schema,
    ))?;
    if request.request_digest != expected {
        return Err(M5EffectPortError::Integrity(
            "activation request digest does not match its exact package".to_string(),
        ));
    }
    Ok(())
}

fn validate_observation_request(request: &PostActivationRequest) -> Result<(), M5EffectPortError> {
    let expected = digest_json_content(&(
        "wasm-biotic:post-activation-request:v1",
        &request.cycle_id,
        &request.activation_id,
        &request.active_package_digest,
        &request.active_package_bytes_digest,
        request.minimum_successes,
    ))?;
    if request.request_digest != expected {
        return Err(M5EffectPortError::Integrity(
            "observation request digest does not match its exact activation".to_string(),
        ));
    }
    Ok(())
}

fn validate_recovery_request(request: &RecoveryRequest) -> Result<(), M5EffectPortError> {
    let expected = digest_json_content(&(
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
    ))?;
    if request.request_digest != expected {
        return Err(M5EffectPortError::Integrity(
            "recovery request digest does not match its exact rollback input".to_string(),
        ));
    }
    Ok(())
}

fn validate_sealed_shadow(evidence: &ShadowExecutionEvidence) -> Result<(), M5EffectPortError> {
    if evidence.clone().seal().map_err(|error| {
        M5EffectPortError::Integrity(format!("shadow evidence cannot be resealed: {error}"))
    })? != *evidence
    {
        return Err(M5EffectPortError::Integrity(
            "shadow evidence digest does not match its fields".to_string(),
        ));
    }
    Ok(())
}

fn validate_sealed_observation(evidence: &PostActivationEvidence) -> Result<(), M5EffectPortError> {
    if evidence.clone().seal().map_err(|error| {
        M5EffectPortError::Integrity(format!("observation evidence cannot be resealed: {error}"))
    })? != *evidence
    {
        return Err(M5EffectPortError::Integrity(
            "observation evidence digest does not match its fields".to_string(),
        ));
    }
    Ok(())
}

fn decode_canonical<T>(bytes: &[u8]) -> Result<T, M5EffectPortError>
where
    T: DeserializeOwned + Serialize,
{
    let value: T = serde_json::from_slice(bytes)?;
    if serde_json::to_vec(&value)? != bytes {
        return Err(M5EffectPortError::Integrity(
            "M3 exact request bytes are not canonical domain JSON".to_string(),
        ));
    }
    Ok(value)
}

fn validate_logical_effect_id(
    proof: &FactoryEffectInvocationProof,
    key: &EffectKey,
) -> Result<(), M5EffectPortError> {
    let expected = match key.operation {
        FactoryEffectOperation::Initialize => {
            format!("m5-initialize:{}", key.domain_request_digest.file_stem())
        }
        FactoryEffectOperation::Execute => {
            format!("m5-execute:{}", key.domain_request_digest.file_stem())
        }
        FactoryEffectOperation::ProviderProposal => {
            format!(
                "m5-provider-proposal:{}",
                key.domain_request_digest.file_stem()
            )
        }
        FactoryEffectOperation::Shadow => {
            format!("m5-shadow:{}", key.domain_request_digest.file_stem())
        }
        FactoryEffectOperation::StateMigrate => {
            format!("m5-migrate:{}", key.domain_request_digest.file_stem())
        }
        FactoryEffectOperation::Activate => {
            format!("m5-activate:{}", key.domain_request_digest.file_stem())
        }
        FactoryEffectOperation::Observe => {
            format!("m5-observe:{}", key.domain_request_digest.file_stem())
        }
        FactoryEffectOperation::Rollback => {
            format!("m5-rollback:{}", key.domain_request_digest.file_stem())
        }
        FactoryEffectOperation::Inspect => {
            let suffix = format!(":{}", key.domain_request_digest.file_stem());
            if proof.request.logical_effect_id.starts_with("m5-inspect:")
                && proof.request.logical_effect_id.ends_with(&suffix)
            {
                return Ok(());
            }
            String::new()
        }
    };
    if proof.request.logical_effect_id != expected {
        return Err(M5EffectPortError::Integrity(format!(
            "accepted {:?} proof uses noncanonical logical effect id '{}'",
            key.operation, proof.request.logical_effect_id
        )));
    }
    Ok(())
}

fn audit_entry(
    kind: M5EffectAuditKind,
    evidence_id: String,
    fact: &ValidatedProofFact<'_>,
    backend_fact_digest: ContentDigest,
) -> M5EffectAuditEntry {
    M5EffectAuditEntry {
        kind,
        evidence_id,
        logical_effect_id: fact.proof.request.logical_effect_id.clone(),
        domain_request_digest: fact.key.domain_request_digest.clone(),
        backend_response_digest: fact.result.exact_response_digest.clone(),
        backend_fact_digest,
        invocation_id: fact.attempt.receipt.invocation_id().to_string(),
        receipt_digest: fact.attempt.receipt.receipt_digest().clone(),
        attestation_digest: fact.attempt.attestation.attestation_digest.clone(),
        proof_digest: fact.proof.proof_digest.clone(),
    }
}

fn port_failure_as_integrity(failure: PortFailure) -> M5EffectPortError {
    M5EffectPortError::Integrity(format!(
        "{} ({:?}): {}",
        failure.code, failure.kind, failure.message
    ))
}

fn invalid_proof_request(proof: &FactoryEffectInvocationProof, kind: &str) -> M5EffectPortError {
    M5EffectPortError::Integrity(format!(
        "accepted {kind} proof '{}' has a noncanonical domain request",
        proof.proof_digest
    ))
}

fn invalid_proof_response(proof: &FactoryEffectInvocationProof, kind: &str) -> M5EffectPortError {
    M5EffectPortError::Integrity(format!(
        "accepted {kind} proof '{}' has a response for a different request",
        proof.proof_digest
    ))
}

fn missing_cycle(cycle_id: &str, kind: M5EffectAuditKind) -> M5EffectPortError {
    M5EffectPortError::Integrity(format!("{kind:?} evidence cites absent cycle '{cycle_id}'"))
}

fn cycle_request_mismatch(cycle_id: &str, kind: M5EffectAuditKind) -> M5EffectPortError {
    M5EffectPortError::Integrity(format!(
        "{kind:?} request differs from authoritative cycle '{cycle_id}'"
    ))
}

fn in_flight_mismatch(pending: &PendingEffect, kind: &str) -> M5EffectPortError {
    M5EffectPortError::Integrity(format!(
        "accepted in-flight {kind} proof differs from pending cycle '{}'",
        pending.cycle_id
    ))
}

fn successful_result(
    proof: &FactoryEffectInvocationProof,
) -> Result<
    (
        &crate::capability_services::FactoryEffectResult,
        &FactoryEffectAttemptProof,
    ),
    M5EffectPortError,
> {
    if proof.status == FactoryEffectProofStatus::Succeeded {
        let attempt = proof.attempts.last().ok_or_else(|| {
            M5EffectPortError::Integrity(
                "successful M3 proof contains no completed attempt".to_string(),
            )
        })?;
        let result = proof.terminal_result().ok_or_else(|| {
            M5EffectPortError::Integrity(
                "successful M3 proof contains no factory result".to_string(),
            )
        })?;
        return Ok((result, attempt));
    }
    let failure = proof
        .attempts
        .last()
        .and_then(|attempt| match attempt.receipt.outcome() {
            InvocationOutcome::Terminal { failure } => Some(failure.clone()),
            InvocationOutcome::Succeeded { .. } => None,
        })
        .unwrap_or_else(|| {
            ServiceFailure::failed(
                "m5_m3_effect_incomplete",
                format!("factory effect ended in {:?}", proof.status),
            )
        });
    Err(M5EffectPortError::Terminal(failure))
}

fn validate_initialization_evidence(
    request: &FactoryInitializeRequest,
    evidence: &FactoryInitializationEvidence,
) -> Result<(), M5EffectPortError> {
    validate_snapshot(&evidence.snapshot)?;
    let expected = digest_json_content(&(
        "wasm-biotic.m5-factory-initialize-evidence.v1",
        &evidence.request_digest,
        &evidence.snapshot,
        &evidence.deployment_record_digest,
    ))?;
    if evidence.request_digest != request.request_digest
        || evidence.snapshot.factory_id != request.factory_id
        || evidence.evidence_digest != expected
    {
        return Err(M5EffectPortError::Integrity(
            "factory initialization evidence failed exact validation".to_string(),
        ));
    }
    Ok(())
}

fn validate_execution_result(
    request: &crate::m5_effect_store::FactoryExecuteRequest,
    result: &FactoryExecutionResult,
) -> Result<(), M5EffectPortError> {
    validate_snapshot(&result.snapshot)?;
    let expected = digest_json_content(&(
        "wasm-biotic.m5-factory-execute-result.v1",
        &result.request_digest,
        &result.snapshot,
        result.input,
        result.output,
        &result.trace,
    ))?;
    if result.request_digest != request.request_digest
        || result.snapshot.package_digest != request.expected_package_digest
        || result.input != request.input
        || result.trace.input != request.input
        || result.trace.output != Some(result.output)
        || result.result_digest != expected
    {
        return Err(M5EffectPortError::Integrity(
            "factory execution result failed exact validation".to_string(),
        ));
    }
    Ok(())
}

fn validate_snapshot(snapshot: &FactoryRuntimeSnapshot) -> Result<(), M5EffectPortError> {
    let expected = digest_json_content(&(
        "wasm-biotic.m5-factory-snapshot.v1",
        &snapshot.factory_id,
        &snapshot.package_digest,
        &snapshot.package_bytes_digest,
        &snapshot.component_digest,
        snapshot.generation,
        snapshot.state_schema,
        &snapshot.state_blob_digest,
        &snapshot.activation_id,
    ))?;
    if snapshot.schema != "wasm-biotic.m5-factory-snapshot.v1"
        || snapshot.factory_id.trim().is_empty()
        || snapshot.snapshot_digest != expected
    {
        return Err(M5EffectPortError::Integrity(
            "factory runtime snapshot failed its content digest".to_string(),
        ));
    }
    Ok(())
}

fn validate_inspection(
    request: &FactoryInspectRequest,
    inspection: &FactoryRuntimeInspection,
) -> Result<(), M5EffectPortError> {
    if let Some(active) = &inspection.active {
        validate_snapshot(active)?;
    }
    let expected = digest_json_content(&(
        "wasm-biotic.m5-factory-inspection.v1",
        &inspection.factory_id,
        &inspection.active,
        inspection.mutation_count,
        inspection.migration_count,
        inspection.observation_count,
        &inspection.deployment_active_component_digest,
        inspection.in_flight,
    ))?;
    if inspection.schema != "wasm-biotic.m5-factory-inspection.v1"
        || inspection.factory_id != request.factory_id
        || inspection.inspection_digest != expected
    {
        return Err(M5EffectPortError::Integrity(
            "factory inspection failed its exact content validation".to_string(),
        ));
    }
    Ok(())
}

fn validate_sealed_migration(receipt: &MigrationReceipt) -> Result<(), PortFailure> {
    if receipt
        .clone()
        .seal()
        .map_err(|error| PortFailure::failed("m5_migration_seal_failed", error.to_string()))?
        != *receipt
    {
        return Err(PortFailure::failed(
            "m5_migration_receipt_invalid",
            "receipted migration failed its domain digest",
        ));
    }
    Ok(())
}

fn validate_sealed_activation(receipt: &ActivationReceipt) -> Result<(), PortFailure> {
    if receipt
        .clone()
        .seal()
        .map_err(|error| PortFailure::failed("m5_activation_seal_failed", error.to_string()))?
        != *receipt
    {
        return Err(PortFailure::failed(
            "m5_activation_receipt_invalid",
            "receipted activation failed its domain digest",
        ));
    }
    Ok(())
}

fn validate_sealed_recovery(receipt: &RecoveryReceipt) -> Result<(), PortFailure> {
    if receipt
        .clone()
        .seal()
        .map_err(|error| PortFailure::failed("m5_recovery_seal_failed", error.to_string()))?
        != *receipt
    {
        return Err(PortFailure::failed(
            "m5_recovery_receipt_invalid",
            "receipted rollback failed its domain digest",
        ));
    }
    Ok(())
}

fn validate_rollback_recovery(
    request: &RecoveryRequest,
    authorization: &M5OperatorRollbackAuthorizationRecord,
) -> Result<(), M5EffectPortError> {
    if authorization.rollback_id != request.recovery_id
        || authorization.restore_package_digest != request.restore_package_digest
        || authorization.restore_package_bytes_digest
            != ContentDigest::from_bytes(&request.restore_package_bytes)
        || !request.reason.ends_with(&authorization.reason_ref)
    {
        return Err(M5EffectPortError::Approval(
            "operator rollback request differs from its exact durable authority".to_string(),
        ));
    }
    Ok(())
}

#[derive(Debug)]
pub enum M5EffectPortError {
    Approval(String),
    Integrity(String),
    ResourceBound(String),
    Terminal(ServiceFailure),
    Ledger(M5M3AdapterError),
    Supervisor(crate::m5_supervisor_adapter::M5SupervisorAdapterError),
    Backend(crate::m5_effect_store::FactoryEffectStoreError),
    Serialization(serde_json::Error),
    Digest(String),
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    UnsafePath {
        path: PathBuf,
        reason: &'static str,
    },
    LockPoisoned,
}

impl M5EffectPortError {
    fn io(path: impl AsRef<Path>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.as_ref().to_path_buf(),
            source,
        }
    }

    pub fn into_port_failure(self) -> PortFailure {
        match self {
            Self::Terminal(failure) => PortFailure {
                kind: match failure.kind {
                    ServiceFailureKind::Unavailable => PortFailureKind::Unavailable,
                    ServiceFailureKind::TimedOut => PortFailureKind::TimedOut,
                    ServiceFailureKind::Cancelled => PortFailureKind::Cancelled,
                    ServiceFailureKind::ApprovalBlocked
                    | ServiceFailureKind::ScopeDenied
                    | ServiceFailureKind::Unsupported => PortFailureKind::Rejected,
                    ServiceFailureKind::Failed | ServiceFailureKind::ResourceExhausted => {
                        PortFailureKind::Failed
                    }
                },
                code: failure.code,
                message: failure.message,
            },
            other => PortFailure::failed("m5_effect_port_failed", other.to_string()),
        }
    }
}

impl Display for M5EffectPortError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Approval(message) => write!(formatter, "M5 effect approval failed: {message}"),
            Self::Integrity(message) => write!(formatter, "M5 effect integrity failed: {message}"),
            Self::ResourceBound(message) => {
                write!(formatter, "M5 effect resource bound failed: {message}")
            }
            Self::Terminal(failure) => write!(formatter, "M3 factory effect failed: {failure}"),
            Self::Ledger(error) => write!(formatter, "{error}"),
            Self::Supervisor(error) => write!(formatter, "{error}"),
            Self::Backend(error) => write!(formatter, "{error}"),
            Self::Serialization(error) => write!(formatter, "M5 effect JSON failed: {error}"),
            Self::Digest(error) => write!(formatter, "M5 effect digest failed: {error}"),
            Self::Io { path, source } => {
                write!(
                    formatter,
                    "M5 effect I/O at '{}' failed: {source}",
                    path.display()
                )
            }
            Self::UnsafePath { path, reason } => {
                write!(
                    formatter,
                    "unsafe M5 effect path '{}': {reason}",
                    path.display()
                )
            }
            Self::LockPoisoned => write!(formatter, "M5 effect lock is poisoned"),
        }
    }
}

impl Error for M5EffectPortError {}

impl From<M5M3AdapterError> for M5EffectPortError {
    fn from(value: M5M3AdapterError) -> Self {
        Self::Ledger(value)
    }
}

impl From<crate::m5_supervisor_adapter::M5SupervisorAdapterError> for M5EffectPortError {
    fn from(value: crate::m5_supervisor_adapter::M5SupervisorAdapterError) -> Self {
        Self::Supervisor(value)
    }
}

impl From<crate::m5_effect_store::FactoryEffectStoreError> for M5EffectPortError {
    fn from(value: crate::m5_effect_store::FactoryEffectStoreError) -> Self {
        Self::Backend(value)
    }
}

impl From<serde_json::Error> for M5EffectPortError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialization(value)
    }
}

impl From<crate::execution::artifact::ArtifactError> for M5EffectPortError {
    fn from(value: crate::execution::artifact::ArtifactError) -> Self {
        Self::Digest(value.to_string())
    }
}

fn secure_root(path: &Path) -> Result<PathBuf, M5EffectPortError> {
    if path.as_os_str().is_empty() {
        return Err(M5EffectPortError::UnsafePath {
            path: path.to_path_buf(),
            reason: "root is empty",
        });
    }
    fs::create_dir_all(path).map_err(|error| M5EffectPortError::io(path, error))?;
    let canonical = fs::canonicalize(path).map_err(|error| M5EffectPortError::io(path, error))?;
    let metadata = fs::symlink_metadata(&canonical)
        .map_err(|error| M5EffectPortError::io(&canonical, error))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(M5EffectPortError::UnsafePath {
            path: canonical,
            reason: "root is not a real directory",
        });
    }
    Ok(canonical)
}

fn secure_child(root: &Path, name: &str) -> Result<PathBuf, M5EffectPortError> {
    if name.is_empty()
        || Path::new(name)
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(M5EffectPortError::UnsafePath {
            path: root.join(name),
            reason: "child name is unsafe",
        });
    }
    let child = root.join(name);
    fs::create_dir_all(&child).map_err(|error| M5EffectPortError::io(&child, error))?;
    let canonical =
        fs::canonicalize(&child).map_err(|error| M5EffectPortError::io(&child, error))?;
    if !canonical.starts_with(root) {
        return Err(M5EffectPortError::UnsafePath {
            path: canonical,
            reason: "child escaped root",
        });
    }
    Ok(canonical)
}

fn read_regular(path: &Path, limit: usize) -> Result<Vec<u8>, M5EffectPortError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| M5EffectPortError::io(path, error))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(M5EffectPortError::UnsafePath {
            path: path.to_path_buf(),
            reason: "expected a regular file",
        });
    }
    if metadata.len() > limit as u64 {
        return Err(M5EffectPortError::ResourceBound(format!(
            "'{}' exceeds {limit} bytes",
            path.display()
        )));
    }
    let mut file = File::open(path).map_err(|error| M5EffectPortError::io(path, error))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|error| M5EffectPortError::io(path, error))?;
    Ok(bytes)
}

fn persist_immutable(root: &Path, path: &Path, bytes: &[u8]) -> Result<(), M5EffectPortError> {
    if !path.starts_with(root) {
        return Err(M5EffectPortError::UnsafePath {
            path: path.to_path_buf(),
            reason: "immutable target escaped root",
        });
    }
    if path.exists() {
        if read_regular(path, bytes.len().max(MAX_ARTIFACT_BYTES))? == bytes {
            return Ok(());
        }
        return Err(M5EffectPortError::Integrity(format!(
            "immutable artifact '{}' already contains different bytes",
            path.display()
        )));
    }
    let temporary = root.join(format!(
        ".m5-effect-artifact-{}-{}",
        std::process::id(),
        TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .map_err(|error| M5EffectPortError::io(&temporary, error))?;
    file.write_all(bytes)
        .map_err(|error| M5EffectPortError::io(&temporary, error))?;
    file.sync_all()
        .map_err(|error| M5EffectPortError::io(&temporary, error))?;
    fs::rename(&temporary, path).map_err(|error| M5EffectPortError::io(path, error))?;
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| M5EffectPortError::io(root, error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_exact_claims_merge_but_conflicting_claims_fail_closed() {
        let key = EffectKey {
            operation: FactoryEffectOperation::Shadow,
            domain_request_digest: ContentDigest::from_bytes(b"shadow-request"),
        };
        let mut expected = BTreeMap::new();
        insert_expected(
            &mut expected,
            key.clone(),
            M5EffectAuditKind::Shadow,
            "cycle:a:shadow".to_string(),
            Some("cycle:a".to_string()),
            ExpectedPayload::ExactResponse(b"same-response".to_vec()),
        )
        .expect("insert first exact claim");
        insert_expected(
            &mut expected,
            key.clone(),
            M5EffectAuditKind::Shadow,
            "journal:a:shadow".to_string(),
            Some("cycle:a".to_string()),
            ExpectedPayload::ExactResponse(b"same-response".to_vec()),
        )
        .expect("merge duplicate projection of the same durable fact");
        assert_eq!(expected.len(), 1);
        assert_eq!(expected[&key].evidence_ids.len(), 2);

        assert!(matches!(
            insert_expected(
                &mut expected,
                key,
                M5EffectAuditKind::Shadow,
                "cycle:conflict:shadow".to_string(),
                Some("cycle:conflict".to_string()),
                ExpectedPayload::ExactResponse(b"different-response".to_vec()),
            ),
            Err(M5EffectPortError::Integrity(_))
        ));
    }

    #[test]
    fn coordinator_request_digests_are_rederived_not_trusted() {
        let mut activation = ActivationRequest {
            cycle_id: "cycle:a".to_string(),
            incumbent_package_digest: ContentDigest::from_bytes(b"incumbent"),
            challenger_package_digest: ContentDigest::from_bytes(b"challenger"),
            challenger_package_bytes: b"challenger-package".to_vec(),
            approval_digest: ContentDigest::from_bytes(b"approval"),
            gate_decision_digest: ContentDigest::from_bytes(b"gate"),
            target_state_schema: 1,
            request_digest: ContentDigest::from_bytes(&[]),
        };
        activation.request_digest = digest_json_content(&(
            "wasm-biotic:activation-request:v1",
            &activation.cycle_id,
            &activation.incumbent_package_digest,
            &activation.challenger_package_digest,
            &activation.challenger_package_bytes,
            &activation.approval_digest,
            &activation.gate_decision_digest,
            activation.target_state_schema,
        ))
        .expect("derive activation request");
        validate_activation_request(&activation).expect("accept exact activation request");
        activation.target_state_schema = 2;
        assert!(matches!(
            validate_activation_request(&activation),
            Err(M5EffectPortError::Integrity(_))
        ));
    }

    #[test]
    fn coordinator_and_external_execution_claims_cannot_share_one_proof_key() {
        let key = EffectKey {
            operation: FactoryEffectOperation::Execute,
            domain_request_digest: ContentDigest::from_bytes(b"execute-request"),
        };
        let execution = M5ActiveExecutionAuditRecord {
            package_digest: ContentDigest::from_bytes(b"package"),
            package_bytes_digest: ContentDigest::from_bytes(b"package-bytes"),
            component_digest: ContentDigest::from_bytes(b"component"),
            input: 7,
            output: 8,
            m3_invocation_id: "invocation:a".to_string(),
            m3_receipt_digest: ContentDigest::from_bytes(b"receipt"),
            m3_attestation_digest: ContentDigest::from_bytes(b"attestation"),
            m3_proof_digest: ContentDigest::from_bytes(b"proof"),
            causal_context_digest: None,
            execution_digest: ContentDigest::from_bytes(b"execution"),
        };
        let mut expected = BTreeMap::new();
        insert_expected(
            &mut expected,
            key.clone(),
            M5EffectAuditKind::ActiveExecution,
            "external:a".to_string(),
            None,
            ExpectedPayload::ActiveExecution(execution.clone()),
        )
        .expect("insert exact external execution");
        assert!(matches!(
            insert_expected(
                &mut expected,
                key,
                M5EffectAuditKind::GenerationDriver,
                "driver:a".to_string(),
                Some("cycle:a".to_string()),
                ExpectedPayload::ActiveExecution(execution),
            ),
            Err(M5EffectPortError::Integrity(_))
        ));
    }
}
