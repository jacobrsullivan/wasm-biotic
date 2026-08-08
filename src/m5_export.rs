//! Authoritative, transport-neutral M5 → M6 handoff material.
//!
//! An export is not a claim that a receiver should trust or activate a package.
//! It is an immutable, receiver-verifiable capture of what one live M5 runtime
//! had durably adopted and was still serving while the capture was sealed.
//! Route authentication, receiver policy, quarantine, approval, and activation
//! belong to M6 and are intentionally absent here.

use crate::capability_services::{
    CAPABILITY_ATTESTATION_SCHEMA, CapabilityOperation, CapabilitySuccess, EVIDENCE_RECORD_SCHEMA,
    InvocationOutcome, InvocationProvenance, InvocationReceipt, PACKAGE_ARTIFACT_SCHEMA,
    REVIEW_RECORD_SCHEMA, ServiceFailureKind, ServiceInvocationAttestation,
};
use crate::execution::NativeServiceFamily;
use crate::execution::artifact::{ContentDigest, digest_json_content};
use crate::factory_reproduction::{
    ActivationReceipt, ApprovalDecision, CycleIntent, CycleIntentKind, CycleRecord, CycleStatus,
    ExecutionTerminal, FactoryLineageRecord, FactoryPackage, HealthStatus, LineageDisposition,
    M1BuildEvidence, MigrationReceipt, PostActivationEvidence, REFERENCE_EXPORT, ReproductionState,
    ShadowExecutionEvidence, SupervisorApprovalRecord, WorkerRole, WorkerTerminalStatus,
    WorkerWorkflowEvidence,
};
use crate::m1_validation::{
    ComparisonRecord, ExpectedI32Outcome, ProvingRecord, ValidationSuite,
    validate_comparison_record, validate_proving_record,
};
use crate::m4_runtime::{M4ActualOutput, M4ReferenceWorkflowEvidence};
use crate::m5_effect_port::{M5EffectAuditKind, M5EffectAuditReport};
use crate::m5_effect_store::FactoryRuntimeSnapshot;
use crate::m5_runtime::M5RuntimeManifest;
use crate::supervisor::JobPhase;
use crate::worker_runtime::{CoordinatorSynthesis, GovernedWorkerRole};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{Display, Formatter};

pub const M5_EXPORT_BUNDLE_SCHEMA: &str = "wasm-biotic.m5-export-bundle.v2";
pub const M5_EXPORT_RUNTIME_IDENTITY_SCHEMA: &str = "wasm-biotic.m5-export-runtime-identity.v1";
pub(crate) const M5_STORED_M4_WORKFLOW_SCHEMA: &str =
    "wasm-biotic.m5-stored-m4-workflow-evidence.v1";
const M5_EXPORT_M4_WORKFLOW_SCHEMA: &str = "wasm-biotic.m5-export-m4-workflow-evidence.v1";
const FACTORY_SNAPSHOT_SCHEMA: &str = "wasm-biotic.m5-factory-snapshot.v1";
const MAX_EXPORT_PACKAGES: usize = 256;
const MAX_PACKAGE_BYTES: usize = 16 * 1_048_576;
const MAX_RECIPE_BYTES: usize = 256 * 1_024;
const MAX_RAW_PACKAGE_CLOSURE_BYTES: usize = 64 * 1_048_576;
const MAX_EXPORT_BUNDLE_BYTES: usize = 256 * 1_048_576;
pub(crate) const MAX_STORED_M4_WORKFLOW_BYTES: usize = 32 * 1_048_576;

/// Sender-root-free projection of the exact runtime manifest validated live.
///
/// `source_manifest_digest` retains the source store's manifest identity as an
/// opaque anchor. `identity_digest` independently seals all portable identity
/// material and that anchor. No sender path or `PathBuf` crosses the boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M5ExportRuntimeIdentityV1 {
    schema: String,
    factory_id: String,
    scope_id: String,
    deployment_id: String,
    worker_max_concurrency: usize,
    validation_suite: ValidationSuite,
    release_gate: crate::factory_reproduction::ReleaseGate,
    incumbent_wat_digest: ContentDigest,
    source_manifest_digest: ContentDigest,
    identity_digest: ContentDigest,
}

impl M5ExportRuntimeIdentityV1 {
    fn from_live_manifest(manifest: &M5RuntimeManifest) -> Result<Self, M5ExportError> {
        manifest
            .validate()
            .map_err(|error| M5ExportError::Integrity(error.to_string()))?;
        let mut identity = Self {
            schema: M5_EXPORT_RUNTIME_IDENTITY_SCHEMA.to_string(),
            factory_id: manifest.config.factory_id.clone(),
            scope_id: manifest.config.scope_id.clone(),
            deployment_id: manifest.config.deployment_id.clone(),
            worker_max_concurrency: manifest.config.worker_max_concurrency,
            validation_suite: manifest.validation_suite.clone(),
            release_gate: manifest.release_gate.clone(),
            incumbent_wat_digest: manifest.incumbent_wat_digest.clone(),
            source_manifest_digest: manifest.manifest_digest.clone(),
            identity_digest: ContentDigest::from_bytes(&[]),
        };
        identity.identity_digest = identity.expected_digest()?;
        identity.validate()?;
        Ok(identity)
    }

    pub fn factory_id(&self) -> &str {
        &self.factory_id
    }

    pub fn scope_id(&self) -> &str {
        &self.scope_id
    }

    pub fn deployment_id(&self) -> &str {
        &self.deployment_id
    }

    pub fn worker_max_concurrency(&self) -> usize {
        self.worker_max_concurrency
    }

    pub fn validation_suite(&self) -> &ValidationSuite {
        &self.validation_suite
    }

    pub fn release_gate(&self) -> &crate::factory_reproduction::ReleaseGate {
        &self.release_gate
    }

    pub fn incumbent_wat_digest(&self) -> &ContentDigest {
        &self.incumbent_wat_digest
    }

    pub fn source_manifest_digest(&self) -> &ContentDigest {
        &self.source_manifest_digest
    }

    pub fn identity_digest(&self) -> &ContentDigest {
        &self.identity_digest
    }

    pub fn validate(&self) -> Result<(), M5ExportError> {
        if self.schema != M5_EXPORT_RUNTIME_IDENTITY_SCHEMA
            || self.factory_id.trim().is_empty()
            || self.scope_id.trim().is_empty()
            || self.deployment_id.trim().is_empty()
            || self.worker_max_concurrency == 0
        {
            return Err(M5ExportError::Integrity(
                "portable M5 runtime identity has invalid schema or identities".to_string(),
            ));
        }
        self.validation_suite
            .validate()
            .map_err(|error| M5ExportError::Integrity(error.to_string()))?;
        self.release_gate.validate().map_err(reproduction)?;
        validate_suite_gate_identity(&self.validation_suite, &self.release_gate)?;
        require_digest(
            "portable M5 runtime identity",
            &self.identity_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M5ExportError> {
        digest(&(
            M5_EXPORT_RUNTIME_IDENTITY_SCHEMA,
            &self.factory_id,
            &self.scope_id,
            &self.deployment_id,
            self.worker_max_concurrency,
            &self.validation_suite,
            &self.release_gate,
            &self.incumbent_wat_digest,
            &self.source_manifest_digest,
        ))
    }
}

/// Exact package material needed to reconstruct the same local package.
///
/// The canonical package embeds the compiled component. The retained WAT is
/// also carried and must compile byte-for-byte to that embedded component.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M5ExportPackageV1 {
    package_digest: ContentDigest,
    canonical_package_bytes: Vec<u8>,
    canonical_package_bytes_digest: ContentDigest,
    recipe_wat_bytes: Vec<u8>,
    recipe_wat_digest: ContentDigest,
}

impl M5ExportPackageV1 {
    pub(crate) fn from_live_package(
        package: &FactoryPackage,
        recipe_wat_bytes: Vec<u8>,
    ) -> Result<Self, M5ExportError> {
        let canonical_package_bytes = package.canonical_bytes().map_err(reproduction)?;
        let value = Self {
            package_digest: package.package_digest.clone(),
            canonical_package_bytes_digest: ContentDigest::from_bytes(&canonical_package_bytes),
            canonical_package_bytes,
            recipe_wat_digest: ContentDigest::from_bytes(&recipe_wat_bytes),
            recipe_wat_bytes,
        };
        value.parse_and_validate()?;
        Ok(value)
    }

    pub fn package_digest(&self) -> &ContentDigest {
        &self.package_digest
    }

    pub fn canonical_package_bytes(&self) -> &[u8] {
        &self.canonical_package_bytes
    }

    pub fn recipe_wat_bytes(&self) -> &[u8] {
        &self.recipe_wat_bytes
    }

    pub fn canonical_package_bytes_digest(&self) -> &ContentDigest {
        &self.canonical_package_bytes_digest
    }

    pub fn recipe_wat_digest(&self) -> &ContentDigest {
        &self.recipe_wat_digest
    }

    fn parse_and_validate(&self) -> Result<FactoryPackage, M5ExportError> {
        if self.canonical_package_bytes.is_empty()
            || self.canonical_package_bytes.len() > MAX_PACKAGE_BYTES
        {
            return Err(M5ExportError::ResourceBound(
                "exported canonical package bytes are outside bounds".to_string(),
            ));
        }
        if self.recipe_wat_bytes.is_empty() || self.recipe_wat_bytes.len() > MAX_RECIPE_BYTES {
            return Err(M5ExportError::ResourceBound(
                "exported package recipe WAT is outside bounds".to_string(),
            ));
        }
        require_digest(
            "export package canonical bytes",
            &self.canonical_package_bytes_digest,
            &ContentDigest::from_bytes(&self.canonical_package_bytes),
        )?;
        require_digest(
            "export package identity",
            &self.package_digest,
            &self.canonical_package_bytes_digest,
        )?;
        require_digest(
            "export package WAT recipe",
            &self.recipe_wat_digest,
            &ContentDigest::from_bytes(&self.recipe_wat_bytes),
        )?;
        let package = FactoryPackage::from_canonical_bytes(&self.canonical_package_bytes)
            .map_err(reproduction)?;
        if package.package_digest != self.package_digest {
            return Err(M5ExportError::Integrity(
                "exported package bytes resolve to a different package identity".to_string(),
            ));
        }
        let compiled = wat::parse_bytes(&self.recipe_wat_bytes)
            .map_err(|error| {
                M5ExportError::Integrity(format!(
                    "exported package recipe is not valid WAT: {error}"
                ))
            })?
            .into_owned();
        if compiled != package.payload.genome.component_bytes {
            return Err(M5ExportError::Integrity(
                "exported package recipe does not compile to the exact component bytes".to_string(),
            ));
        }
        Ok(package)
    }
}

/// Full path-free M4 evidence persisted at the moment the isolated workflow
/// completes.
///
/// The indexes are deliberately redundant. They let a loader select the
/// record by its immutable governance request and then prove that the selected
/// workflow, executions, and results are exactly the ones in the payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct M5StoredM4WorkflowEvidenceV1 {
    schema: String,
    governance_context_digest: ContentDigest,
    workflow_id: String,
    execution_ids: Vec<String>,
    result_digests: Vec<ContentDigest>,
    evidence: M4ReferenceWorkflowEvidence,
    validation_suite: ValidationSuite,
    service_receipts: Vec<InvocationReceipt>,
    service_attestations: Vec<ServiceInvocationAttestation>,
    evidence_digest: ContentDigest,
    record_digest: ContentDigest,
}

impl M5StoredM4WorkflowEvidenceV1 {
    pub(crate) fn new(
        evidence: M4ReferenceWorkflowEvidence,
        validation_suite: ValidationSuite,
        mut service_receipts: Vec<InvocationReceipt>,
        mut service_attestations: Vec<ServiceInvocationAttestation>,
    ) -> Result<Self, M5ExportError> {
        service_receipts.sort_by(|left, right| left.invocation_id().cmp(right.invocation_id()));
        service_attestations.sort_by(|left, right| left.invocation_id.cmp(&right.invocation_id));
        let mut record = Self {
            schema: M5_STORED_M4_WORKFLOW_SCHEMA.to_string(),
            governance_context_digest: evidence.governance_context_digest.clone(),
            workflow_id: evidence.worker.workflow_id.clone(),
            execution_ids: evidence.worker.execution_ids.clone(),
            result_digests: evidence.worker.result_digests.clone(),
            evidence,
            validation_suite,
            service_receipts,
            service_attestations,
            evidence_digest: ContentDigest::from_bytes(&[]),
            record_digest: ContentDigest::from_bytes(&[]),
        };
        record.evidence_digest = full_m4_evidence_digest(&record.evidence)?;
        record.record_digest = record.expected_record_digest()?;
        record.validate()?;
        Ok(record)
    }

    pub(crate) fn governance_context_digest(&self) -> &ContentDigest {
        &self.governance_context_digest
    }

    pub(crate) fn workflow_id(&self) -> &str {
        &self.workflow_id
    }

    pub(crate) fn execution_ids(&self) -> &[String] {
        &self.execution_ids
    }

    pub(crate) fn result_digests(&self) -> &[ContentDigest] {
        &self.result_digests
    }

    pub(crate) fn evidence(&self) -> &M4ReferenceWorkflowEvidence {
        &self.evidence
    }

    pub(crate) fn service_receipts(&self) -> &[InvocationReceipt] {
        &self.service_receipts
    }

    pub(crate) fn service_attestations(&self) -> &[ServiceInvocationAttestation] {
        &self.service_attestations
    }

    pub(crate) fn evidence_digest(&self) -> &ContentDigest {
        &self.evidence_digest
    }

    pub(crate) fn record_digest(&self) -> &ContentDigest {
        &self.record_digest
    }

    pub(crate) fn validate(&self) -> Result<(), M5ExportError> {
        if self.schema != M5_STORED_M4_WORKFLOW_SCHEMA
            || self.workflow_id.trim().is_empty()
            || self.governance_context_digest != self.evidence.governance_context_digest
            || self.workflow_id != self.evidence.worker.workflow_id
            || self.execution_ids != self.evidence.worker.execution_ids
            || self.result_digests != self.evidence.worker.result_digests
        {
            return Err(M5ExportError::Integrity(
                "stored M4 workflow indexes are missing or cross-linked".to_string(),
            ));
        }
        self.validation_suite
            .validate()
            .map_err(|error| M5ExportError::Integrity(error.to_string()))?;
        validate_full_m4_evidence(&self.evidence)?;
        validate_m4_service_evidence(
            &self.evidence,
            &self.validation_suite,
            &self.service_receipts,
            &self.service_attestations,
        )?;
        require_digest(
            "stored M4 workflow evidence",
            &self.evidence_digest,
            &full_m4_evidence_digest(&self.evidence)?,
        )?;
        require_digest(
            "stored M4 workflow record",
            &self.record_digest,
            &self.expected_record_digest()?,
        )
    }

    fn expected_record_digest(&self) -> Result<ContentDigest, M5ExportError> {
        digest(&(
            M5_STORED_M4_WORKFLOW_SCHEMA,
            &self.governance_context_digest,
            &self.workflow_id,
            &self.execution_ids,
            &self.result_digests,
            &self.validation_suite,
            &self.service_receipts,
            &self.service_attestations,
            &self.evidence_digest,
        ))
    }
}

/// The exact role a full M4 workflow played in the active adoption.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum M5ExportM4WorkflowKindV1 {
    GenerationMaterialization,
    CandidateWorkflow,
}

/// A full M4 record plus the compact M5 evidence that the adoption actually
/// cited. This prevents a valid but unrelated workflow from being substituted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M5ExportM4WorkflowEvidenceV1 {
    schema: String,
    kind: M5ExportM4WorkflowKindV1,
    compact_evidence_digest: ContentDigest,
    stored: M5StoredM4WorkflowEvidenceV1,
    projection_digest: ContentDigest,
}

impl M5ExportM4WorkflowEvidenceV1 {
    pub fn kind(&self) -> M5ExportM4WorkflowKindV1 {
        self.kind
    }

    pub fn compact_evidence_digest(&self) -> &ContentDigest {
        &self.compact_evidence_digest
    }

    pub fn workflow(&self) -> &M4ReferenceWorkflowEvidence {
        self.stored.evidence()
    }

    /// Exact successful M3 receipts whose typed outcomes contain the real
    /// patch/build/package/proving/comparison/review/verification/evidence
    /// records behind this workflow.
    pub fn service_receipts(&self) -> &[InvocationReceipt] {
        self.stored.service_receipts()
    }

    pub fn service_attestations(&self) -> &[ServiceInvocationAttestation] {
        self.stored.service_attestations()
    }

    pub fn full_evidence_digest(&self) -> &ContentDigest {
        self.stored.evidence_digest()
    }

    pub fn stored_record_digest(&self) -> &ContentDigest {
        self.stored.record_digest()
    }

    fn new(
        kind: M5ExportM4WorkflowKindV1,
        compact_evidence_digest: ContentDigest,
        stored: M5StoredM4WorkflowEvidenceV1,
    ) -> Result<Self, M5ExportError> {
        let mut value = Self {
            schema: M5_EXPORT_M4_WORKFLOW_SCHEMA.to_string(),
            kind,
            compact_evidence_digest,
            stored,
            projection_digest: ContentDigest::from_bytes(&[]),
        };
        value.projection_digest = value.expected_digest()?;
        value.validate_integrity()?;
        Ok(value)
    }

    fn validate_integrity(&self) -> Result<(), M5ExportError> {
        if self.schema != M5_EXPORT_M4_WORKFLOW_SCHEMA {
            return Err(M5ExportError::Integrity(
                "exported M4 workflow has an unsupported schema".to_string(),
            ));
        }
        self.stored.validate()?;
        require_digest(
            "exported M4 workflow projection",
            &self.projection_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, M5ExportError> {
        digest(&(
            M5_EXPORT_M4_WORKFLOW_SCHEMA,
            self.kind,
            &self.compact_evidence_digest,
            self.stored.record_digest(),
        ))
    }
}

/// The active M5 implementation does not create an M1 ComparisonRecord for
/// release authority. It uses M1 to prove the challenger and the M3 shadow
/// execution plus the deterministic release gate to compare it with the
/// incumbent. Keeping that choice explicit prevents a receiver from inferring
/// a nonexistent M1 release-comparison artifact. The real ComparisonRecord
/// produced inside each M4 review workflow is carried in that workflow's typed
/// M3 service receipts, but it is worker-review evidence rather than the M5
/// release decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "authority", rename_all = "snake_case", deny_unknown_fields)]
pub enum M5ExportReleaseAuthorityV1 {
    M3ShadowGate {
        shadow_evidence_digest: ContentDigest,
        gate_decision_digest: ContentDigest,
    },
}

/// Explicit projection of the evidence that made the current package active.
///
/// The complete cycle remains present because its record digest covers every
/// field. The named evidence is duplicated as a checked projection so a
/// receiver cannot accidentally select a stale or cross-linked nested record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M5ExportActiveCycleV1 {
    intent: CycleIntent,
    record: CycleRecord,
    lineage: FactoryLineageRecord,
    m1_evidence: M1BuildEvidence,
    m1_proving_record: ProvingRecord,
    m2_approval: SupervisorApprovalRecord,
    m3_shadow_evidence: ShadowExecutionEvidence,
    release_authority: M5ExportReleaseAuthorityV1,
    m4_worker_evidence: WorkerWorkflowEvidence,
    m4_workflows: Vec<M5ExportM4WorkflowEvidenceV1>,
    migration_receipt: Option<MigrationReceipt>,
    activation_receipt: ActivationReceipt,
    healthy_observation: PostActivationEvidence,
    recovery_receipt: Option<crate::factory_reproduction::RecoveryReceipt>,
}

impl M5ExportActiveCycleV1 {
    pub fn intent(&self) -> &CycleIntent {
        &self.intent
    }

    pub fn record(&self) -> &CycleRecord {
        &self.record
    }

    pub fn lineage(&self) -> &FactoryLineageRecord {
        &self.lineage
    }

    pub fn m1_evidence(&self) -> &M1BuildEvidence {
        &self.m1_evidence
    }

    pub fn m1_proving_record(&self) -> &ProvingRecord {
        &self.m1_proving_record
    }

    pub fn m2_approval(&self) -> &SupervisorApprovalRecord {
        &self.m2_approval
    }

    pub fn m3_shadow_evidence(&self) -> &ShadowExecutionEvidence {
        &self.m3_shadow_evidence
    }

    pub fn release_authority(&self) -> &M5ExportReleaseAuthorityV1 {
        &self.release_authority
    }

    pub fn m4_worker_evidence(&self) -> &WorkerWorkflowEvidence {
        &self.m4_worker_evidence
    }

    pub fn m4_workflows(&self) -> &[M5ExportM4WorkflowEvidenceV1] {
        &self.m4_workflows
    }

    pub fn migration_receipt(&self) -> Option<&MigrationReceipt> {
        self.migration_receipt.as_ref()
    }

    pub fn activation_receipt(&self) -> &ActivationReceipt {
        &self.activation_receipt
    }

    pub fn healthy_observation(&self) -> &PostActivationEvidence {
        &self.healthy_observation
    }

    pub fn recovery_receipt(&self) -> Option<&crate::factory_reproduction::RecoveryReceipt> {
        self.recovery_receipt.as_ref()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct M5ExportM4WorkflowReferenceV1 {
    pub(crate) kind: M5ExportM4WorkflowKindV1,
    pub(crate) governance_context_digest: ContentDigest,
    pub(crate) workflow_id: Option<String>,
    pub(crate) execution_ids: Vec<String>,
    pub(crate) result_digests: Vec<ContentDigest>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct M5ExportEvidenceReferencesV1 {
    pub(crate) m1_proving_record_digest: ContentDigest,
    pub(crate) m4_workflows: Vec<M5ExportM4WorkflowReferenceV1>,
}

/// Resolve evidence identities from the same adoption selector used to build
/// and validate the final bundle.
pub(crate) fn active_evidence_references(
    state: &ReproductionState,
) -> Result<M5ExportEvidenceReferencesV1, M5ExportError> {
    let (_, cycle, _) = select_current_adoption(state)?;
    Ok(M5ExportEvidenceReferencesV1 {
        m1_proving_record_digest: cycle.m1_evidence.proving_record_digest.clone(),
        m4_workflows: m4_references_for_cycle(cycle)?,
    })
}

fn m4_references_for_cycle(
    cycle: &CycleRecord,
) -> Result<Vec<M5ExportM4WorkflowReferenceV1>, M5ExportError> {
    let mut m4_workflows = Vec::with_capacity(if cycle.initiation.is_some() { 2 } else { 1 });
    if let Some(initiation) = &cycle.initiation {
        let materialization = &initiation.materialization_evidence;
        m4_workflows.push(M5ExportM4WorkflowReferenceV1 {
            kind: M5ExportM4WorkflowKindV1::GenerationMaterialization,
            governance_context_digest: materialization.request_digest.clone(),
            workflow_id: Some(materialization.workflow_id.clone()),
            execution_ids: materialization
                .worker_receipts
                .iter()
                .map(|receipt| receipt.execution_id.clone())
                .collect(),
            result_digests: materialization
                .worker_receipts
                .iter()
                .map(|receipt| {
                    receipt.output_digest.clone().ok_or_else(|| {
                        M5ExportError::Integrity(
                            "generation materialization receipt has no result digest".to_string(),
                        )
                    })
                })
                .collect::<Result<Vec<_>, _>>()?,
        });
    }
    m4_workflows.push(M5ExportM4WorkflowReferenceV1 {
        kind: M5ExportM4WorkflowKindV1::CandidateWorkflow,
        governance_context_digest: cycle.worker_evidence.request_digest.clone(),
        workflow_id: None,
        execution_ids: cycle
            .worker_evidence
            .receipts
            .iter()
            .map(|receipt| receipt.execution_id.clone())
            .collect(),
        result_digests: cycle
            .worker_evidence
            .receipts
            .iter()
            .map(|receipt| {
                receipt.output_digest.clone().ok_or_else(|| {
                    M5ExportError::Integrity(
                        "candidate worker receipt has no result digest".to_string(),
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
    });
    Ok(m4_workflows)
}

fn project_m4_workflows(
    cycle: &CycleRecord,
    records: Vec<M5StoredM4WorkflowEvidenceV1>,
) -> Result<Vec<M5ExportM4WorkflowEvidenceV1>, M5ExportError> {
    let references = m4_references_for_cycle(cycle)?;
    if records.len() != references.len() {
        return Err(M5ExportError::Integrity(format!(
            "active adoption requires {} full M4 workflow records, but {} were supplied",
            references.len(),
            records.len()
        )));
    }
    let mut by_context = records
        .into_iter()
        .map(|record| {
            record.validate()?;
            Ok((
                record.governance_context_digest().as_str().to_string(),
                record,
            ))
        })
        .collect::<Result<BTreeMap<_, _>, M5ExportError>>()?;
    if by_context.len() != references.len() {
        return Err(M5ExportError::Integrity(
            "full M4 workflow records duplicate a governance request".to_string(),
        ));
    }
    let mut exports = Vec::with_capacity(references.len());
    for reference in references {
        let stored = by_context
            .remove(reference.governance_context_digest.as_str())
            .ok_or_else(|| {
                M5ExportError::Integrity(format!(
                    "active adoption lacks full M4 workflow for {}",
                    reference.governance_context_digest
                ))
            })?;
        validate_m4_workflow_reference(&reference, &stored)?;
        let compact_evidence_digest = match reference.kind {
            M5ExportM4WorkflowKindV1::GenerationMaterialization => cycle
                .initiation
                .as_ref()
                .expect("reference exists only with initiation")
                .materialization_evidence
                .evidence_digest
                .clone(),
            M5ExportM4WorkflowKindV1::CandidateWorkflow => {
                cycle.worker_evidence.evidence_digest.clone()
            }
        };
        exports.push(M5ExportM4WorkflowEvidenceV1::new(
            reference.kind,
            compact_evidence_digest,
            stored,
        )?);
    }
    if !by_context.is_empty() {
        return Err(M5ExportError::Integrity(
            "unreferenced full M4 workflow record entered the active export".to_string(),
        ));
    }
    Ok(exports)
}

/// Complete, digest-sealed evidence exported from one quiescent live M5.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M5ExportBundleV1 {
    schema: String,
    runtime_identity: M5ExportRuntimeIdentityV1,
    reproduction_state: ReproductionState,
    active_package: M5ExportPackageV1,
    referenced_packages: Vec<M5ExportPackageV1>,
    active_cycle: M5ExportActiveCycleV1,
    active_runtime_snapshot: FactoryRuntimeSnapshot,
    effect_audit: M5EffectAuditReport,
    bundle_digest: ContentDigest,
}

impl M5ExportBundleV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_live_runtime(
        manifest: M5RuntimeManifest,
        reproduction_state: ReproductionState,
        mut packages: Vec<M5ExportPackageV1>,
        m1_proving_record: ProvingRecord,
        m4_workflow_records: Vec<M5StoredM4WorkflowEvidenceV1>,
        active_runtime_snapshot: FactoryRuntimeSnapshot,
        effect_audit: M5EffectAuditReport,
    ) -> Result<Self, M5ExportError> {
        if packages.len() > MAX_EXPORT_PACKAGES {
            return Err(M5ExportError::ResourceBound(format!(
                "export package closure contains {} packages; limit is {MAX_EXPORT_PACKAGES}",
                packages.len()
            )));
        }
        packages.sort_by(|left, right| left.package_digest.cmp(&right.package_digest));
        let active_index = packages
            .iter()
            .position(|package| package.package_digest == reproduction_state.active_package_digest)
            .ok_or_else(|| {
                M5ExportError::Integrity(
                    "active package is absent from the captured package closure".to_string(),
                )
            })?;
        let active_package = packages.remove(active_index);
        let (intent, record, lineage) = select_current_adoption(&reproduction_state)?;
        let m2_approval = record.approval.clone().ok_or_else(|| {
            M5ExportError::NotExportable(
                "active adoption has no exact supervisor approval".to_string(),
            )
        })?;
        let activation_receipt = record.activation_receipt.clone().ok_or_else(|| {
            M5ExportError::NotExportable(
                "active adoption has no exact activation receipt".to_string(),
            )
        })?;
        let healthy_observation = record.observation_evidence.clone().ok_or_else(|| {
            M5ExportError::NotExportable(
                "active adoption has no post-activation observation".to_string(),
            )
        })?;
        let m4_workflows = project_m4_workflows(record, m4_workflow_records)?;
        let active_cycle = M5ExportActiveCycleV1 {
            intent: intent.clone(),
            record: record.clone(),
            lineage: lineage.clone(),
            m1_evidence: record.m1_evidence.clone(),
            m1_proving_record,
            m2_approval,
            m3_shadow_evidence: record.shadow_evidence.clone(),
            release_authority: M5ExportReleaseAuthorityV1::M3ShadowGate {
                shadow_evidence_digest: record.shadow_evidence.evidence_digest.clone(),
                gate_decision_digest: record.gate_decision.decision_digest.clone(),
            },
            m4_worker_evidence: record.worker_evidence.clone(),
            m4_workflows,
            migration_receipt: record.migration_receipt.clone(),
            activation_receipt,
            healthy_observation,
            recovery_receipt: record.recovery_receipt.clone(),
        };
        let runtime_identity = M5ExportRuntimeIdentityV1::from_live_manifest(&manifest)?;
        let mut bundle = Self {
            schema: M5_EXPORT_BUNDLE_SCHEMA.to_string(),
            runtime_identity,
            reproduction_state,
            active_package,
            referenced_packages: packages,
            active_cycle,
            active_runtime_snapshot,
            effect_audit,
            bundle_digest: ContentDigest::from_bytes(&[]),
        };
        bundle.bundle_digest = bundle.expected_digest()?;
        bundle.validate_standalone()?;
        Ok(bundle)
    }

    pub fn runtime_identity(&self) -> &M5ExportRuntimeIdentityV1 {
        &self.runtime_identity
    }

    pub fn reproduction_state(&self) -> &ReproductionState {
        &self.reproduction_state
    }

    pub fn active_package(&self) -> &M5ExportPackageV1 {
        &self.active_package
    }

    pub fn referenced_packages(&self) -> &[M5ExportPackageV1] {
        &self.referenced_packages
    }

    pub fn active_cycle(&self) -> &M5ExportActiveCycleV1 {
        &self.active_cycle
    }

    pub fn active_runtime_snapshot(&self) -> &FactoryRuntimeSnapshot {
        &self.active_runtime_snapshot
    }

    pub fn effect_audit(&self) -> &M5EffectAuditReport {
        &self.effect_audit
    }

    pub fn bundle_digest(&self) -> &ContentDigest {
        &self.bundle_digest
    }

    /// Serialize the sole canonical representation accepted by a receiver.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, M5ExportError> {
        self.validate_standalone()?;
        let bytes = canonical_json(self)?;
        if bytes.len() > MAX_EXPORT_BUNDLE_BYTES {
            return Err(M5ExportError::ResourceBound(format!(
                "M5 export contains {} bytes; limit is {MAX_EXPORT_BUNDLE_BYTES}",
                bytes.len()
            )));
        }
        Ok(bytes)
    }

    /// Parse and independently validate an export without any source runtime.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, M5ExportError> {
        if bytes.is_empty() || bytes.len() > MAX_EXPORT_BUNDLE_BYTES {
            return Err(M5ExportError::ResourceBound(
                "M5 export byte length is outside bounds".to_string(),
            ));
        }
        let bundle: Self = serde_json::from_slice(bytes)
            .map_err(|error| M5ExportError::Serialization(error.to_string()))?;
        if canonical_json(&bundle)? != bytes {
            return Err(M5ExportError::Integrity(
                "M5 export is not in its canonical representation".to_string(),
            ));
        }
        bundle.validate_standalone()?;
        Ok(bundle)
    }

    /// Verify the complete bundle using only bytes carried in the bundle.
    pub fn validate_standalone(&self) -> Result<(), M5ExportError> {
        if self.schema != M5_EXPORT_BUNDLE_SCHEMA {
            return Err(M5ExportError::UnsupportedSchema(self.schema.clone()));
        }
        self.runtime_identity.validate()?;
        self.reproduction_state.validate().map_err(reproduction)?;
        self.effect_audit
            .validate()
            .map_err(|error| M5ExportError::Integrity(error.to_string()))?;
        if self.runtime_identity.factory_id != self.reproduction_state.factory_id
            || self.runtime_identity.release_gate != self.reproduction_state.release_gate
        {
            return Err(M5ExportError::Integrity(
                "runtime manifest identity differs from the exported reproduction state"
                    .to_string(),
            ));
        }
        validate_stable_state(&self.reproduction_state)?;
        let packages = self.validate_package_closure()?;
        validate_state_package_links(&self.reproduction_state, &packages)?;
        self.validate_active_adoption(&packages)?;
        validate_snapshot(
            &self.active_runtime_snapshot,
            &self.reproduction_state,
            packages
                .get(self.reproduction_state.active_package_digest.as_str())
                .expect("validated active package closure"),
            &self.active_cycle.activation_receipt,
        )?;
        validate_effect_audit(
            &self.effect_audit,
            &self.reproduction_state,
            &self.active_cycle.record,
            &self.active_runtime_snapshot,
        )?;
        require_digest(
            "M5 export bundle",
            &self.bundle_digest,
            &self.expected_digest()?,
        )?;
        let bytes = canonical_json(self)?;
        if bytes.len() > MAX_EXPORT_BUNDLE_BYTES {
            return Err(M5ExportError::ResourceBound(format!(
                "M5 export contains {} bytes; limit is {MAX_EXPORT_BUNDLE_BYTES}",
                bytes.len()
            )));
        }
        Ok(())
    }

    fn validate_package_closure(&self) -> Result<BTreeMap<String, FactoryPackage>, M5ExportError> {
        if self.referenced_packages.len() + 1 > MAX_EXPORT_PACKAGES {
            return Err(M5ExportError::ResourceBound(format!(
                "export package closure exceeds {MAX_EXPORT_PACKAGES} packages"
            )));
        }
        if self
            .referenced_packages
            .iter()
            .any(|package| package.package_digest == self.active_package.package_digest)
        {
            return Err(M5ExportError::Integrity(
                "active package is duplicated in the referenced package closure".to_string(),
            ));
        }
        if self
            .referenced_packages
            .windows(2)
            .any(|window| window[0].package_digest >= window[1].package_digest)
        {
            return Err(M5ExportError::Integrity(
                "referenced package closure is not strictly digest ordered".to_string(),
            ));
        }
        let raw_bytes = std::iter::once(&self.active_package)
            .chain(self.referenced_packages.iter())
            .try_fold(0usize, |total, package| {
                total
                    .checked_add(package.canonical_package_bytes.len())
                    .and_then(|value| value.checked_add(package.recipe_wat_bytes.len()))
                    .ok_or_else(|| {
                        M5ExportError::ResourceBound(
                            "export package closure byte count overflowed".to_string(),
                        )
                    })
            })?;
        if raw_bytes > MAX_RAW_PACKAGE_CLOSURE_BYTES {
            return Err(M5ExportError::ResourceBound(format!(
                "raw package closure contains {raw_bytes} bytes; limit is \
                 {MAX_RAW_PACKAGE_CLOSURE_BYTES}"
            )));
        }
        let mut packages = BTreeMap::new();
        for exported in std::iter::once(&self.active_package).chain(self.referenced_packages.iter())
        {
            let package = exported.parse_and_validate()?;
            if package.payload.factory_id != self.reproduction_state.factory_id {
                return Err(M5ExportError::Integrity(format!(
                    "package {} belongs to a different factory",
                    package.package_digest
                )));
            }
            if packages
                .insert(package.package_digest.as_str().to_string(), package)
                .is_some()
            {
                return Err(M5ExportError::Integrity(
                    "export package closure contains a duplicate identity".to_string(),
                ));
            }
        }
        if packages.len() != self.reproduction_state.package_index.len()
            || packages
                .keys()
                .any(|digest| !self.reproduction_state.package_index.contains_key(digest))
        {
            return Err(M5ExportError::Integrity(
                "export package bytes do not exactly close the durable package index".to_string(),
            ));
        }
        Ok(packages)
    }

    fn validate_active_adoption(
        &self,
        packages: &BTreeMap<String, FactoryPackage>,
    ) -> Result<(), M5ExportError> {
        let state = &self.reproduction_state;
        let (intent, record, lineage) = select_current_adoption(state)?;
        if &self.active_cycle.intent != intent
            || &self.active_cycle.record != record
            || &self.active_cycle.lineage != lineage
            || self.active_cycle.m1_evidence != record.m1_evidence
            || self.active_cycle.m1_proving_record.record_digest
                != record.m1_evidence.proving_record_digest
            || record.approval.as_ref() != Some(&self.active_cycle.m2_approval)
            || self.active_cycle.m3_shadow_evidence != record.shadow_evidence
            || self.active_cycle.m4_worker_evidence != record.worker_evidence
            || self.active_cycle.migration_receipt != record.migration_receipt
            || record.activation_receipt.as_ref() != Some(&self.active_cycle.activation_receipt)
            || record.observation_evidence.as_ref() != Some(&self.active_cycle.healthy_observation)
            || self.active_cycle.recovery_receipt != record.recovery_receipt
        {
            return Err(M5ExportError::Integrity(
                "active-cycle projection is missing or cross-linked".to_string(),
            ));
        }
        validate_proving_record(
            self.runtime_identity.validation_suite(),
            &self.active_cycle.m1_proving_record,
        )
        .map_err(|error| {
            M5ExportError::Integrity(format!(
                "active M1 proving record does not validate against the exported suite: {error}"
            ))
        })?;
        if self.active_cycle.m1_proving_record.component_digest
            != record.m1_evidence.component_digest
        {
            return Err(M5ExportError::Integrity(
                "active M1 proving record is cross-linked to another component".to_string(),
            ));
        }
        validate_release_authority(&self.active_cycle.release_authority, record)?;
        if self.active_cycle.m4_workflows.iter().any(|workflow| {
            workflow.stored.validation_suite != *self.runtime_identity.validation_suite()
        }) {
            return Err(M5ExportError::Integrity(
                "full M4 workflow evidence uses a different proving suite".to_string(),
            ));
        }
        validate_exported_m4_workflows(
            &self.active_cycle.m4_workflows,
            record,
            self.active_package.recipe_wat_digest(),
        )?;
        let active = packages
            .get(state.active_package_digest.as_str())
            .ok_or_else(|| {
                M5ExportError::Integrity("active package bytes are missing".to_string())
            })?;
        let parent = packages
            .get(record.parent_package_digest.as_str())
            .ok_or_else(|| {
                M5ExportError::Integrity("active parent package bytes are missing".to_string())
            })?;
        validate_active_cycle_semantics(state, intent, record, lineage, parent, active)?;
        if self.active_cycle.m1_proving_record.component_digest
            != active.payload.genome.component_digest
        {
            return Err(M5ExportError::Integrity(
                "active M1 proving record does not prove the exported active component".to_string(),
            ));
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, M5ExportError> {
        digest(&(
            M5_EXPORT_BUNDLE_SCHEMA,
            &self.runtime_identity,
            &self.reproduction_state,
            &self.active_package,
            &self.referenced_packages,
            &self.active_cycle,
            &self.active_runtime_snapshot,
            &self.effect_audit,
        ))
    }

    #[cfg(test)]
    pub(crate) fn tamper_active_recipe_for_test(&mut self) {
        if let Some(first) = self.active_package.recipe_wat_bytes.first_mut() {
            *first ^= 1;
        }
    }

    #[cfg(test)]
    pub(crate) fn remove_active_lineage_for_test(&mut self) {
        if let Some(index) = self
            .reproduction_state
            .lineage
            .iter()
            .rposition(|record| record.disposition == LineageDisposition::Adopted)
        {
            self.reproduction_state.lineage.remove(index);
        }
    }

    #[cfg(test)]
    pub(crate) fn cross_link_worker_for_test(&mut self) {
        self.active_cycle
            .m4_worker_evidence
            .challenger_package_digest = self.active_cycle.record.parent_package_digest.clone();
    }

    #[cfg(test)]
    pub(crate) fn remove_active_shadow_effect_for_test(&mut self) {
        let request_digest = &self.active_cycle.record.shadow_evidence.request_digest;
        self.effect_audit.entries.retain(|entry| {
            entry.kind != M5EffectAuditKind::Shadow
                || &entry.domain_request_digest != request_digest
        });
    }

    #[cfg(test)]
    pub(crate) fn tamper_full_m1_record_for_test(&mut self) {
        self.active_cycle.m1_proving_record.component_digest =
            ContentDigest::from_bytes(b"cross-linked-m1-component");
        self.reseal_for_test();
    }

    #[cfg(test)]
    pub(crate) fn remove_full_m4_workflow_for_test(&mut self) {
        self.active_cycle.m4_workflows.pop();
        self.reseal_for_test();
    }

    #[cfg(test)]
    pub(crate) fn cross_link_full_m4_workflow_for_test(&mut self) {
        if self.active_cycle.m4_workflows.len() >= 2 {
            let replacement = self.active_cycle.m4_workflows[0].stored.clone();
            let target = self
                .active_cycle
                .m4_workflows
                .last_mut()
                .expect("length checked");
            target.stored = replacement;
            target.projection_digest = target
                .expected_digest()
                .expect("test projection digest is serializable");
        } else if let Some(target) = self.active_cycle.m4_workflows.first_mut() {
            target.stored.governance_context_digest =
                ContentDigest::from_bytes(b"cross-linked-m4-governance");
            target.stored.record_digest = target
                .stored
                .expected_record_digest()
                .expect("test stored record digest is serializable");
            target.projection_digest = target
                .expected_digest()
                .expect("test projection digest is serializable");
        }
        self.reseal_for_test();
    }

    #[cfg(test)]
    fn reseal_for_test(&mut self) {
        self.bundle_digest = self
            .expected_digest()
            .expect("test export digest is serializable");
    }
}

fn validate_release_authority(
    authority: &M5ExportReleaseAuthorityV1,
    cycle: &CycleRecord,
) -> Result<(), M5ExportError> {
    match authority {
        M5ExportReleaseAuthorityV1::M3ShadowGate {
            shadow_evidence_digest,
            gate_decision_digest,
        } => {
            if shadow_evidence_digest != &cycle.shadow_evidence.evidence_digest
                || gate_decision_digest != &cycle.gate_decision.decision_digest
                || cycle.gate_decision.shadow_evidence_digest
                    != cycle.shadow_evidence.evidence_digest
            {
                return Err(M5ExportError::Integrity(
                    "explicit M3 shadow-gate release authority is cross-linked".to_string(),
                ));
            }
            Ok(())
        }
    }
}

fn validate_exported_m4_workflows(
    exported: &[M5ExportM4WorkflowEvidenceV1],
    cycle: &CycleRecord,
    active_recipe_wat_digest: &ContentDigest,
) -> Result<(), M5ExportError> {
    let references = m4_references_for_cycle(cycle)?;
    if exported.len() != references.len() {
        return Err(M5ExportError::Integrity(format!(
            "active adoption requires {} full M4 workflows, but the export contains {}",
            references.len(),
            exported.len()
        )));
    }
    for (item, reference) in exported.iter().zip(&references) {
        item.validate_integrity()?;
        if item.kind != reference.kind {
            return Err(M5ExportError::Integrity(
                "exported M4 workflow ordering or purpose is cross-linked".to_string(),
            ));
        }
        validate_m4_workflow_reference(reference, &item.stored)?;
        let expected_compact = match item.kind {
            M5ExportM4WorkflowKindV1::GenerationMaterialization => {
                let materialization = &cycle
                    .initiation
                    .as_ref()
                    .ok_or_else(|| {
                        M5ExportError::Integrity(
                            "generation M4 workflow exists without initiation evidence".to_string(),
                        )
                    })?
                    .materialization_evidence;
                require_digest(
                    "generation full M4 workflow",
                    &materialization.workflow_evidence_digest,
                    item.full_evidence_digest(),
                )?;
                validate_m4_component_target(
                    item.workflow(),
                    &materialization.successor_component_digest,
                    Some(&materialization.rendered_wat_digest),
                )?;
                &materialization.evidence_digest
            }
            M5ExportM4WorkflowKindV1::CandidateWorkflow => {
                validate_m4_component_target(
                    item.workflow(),
                    &cycle.m1_evidence.component_digest,
                    Some(active_recipe_wat_digest),
                )?;
                &cycle.worker_evidence.evidence_digest
            }
        };
        require_digest(
            "M4 compact adoption projection",
            &item.compact_evidence_digest,
            expected_compact,
        )?;
    }
    Ok(())
}

fn validate_m4_component_target(
    evidence: &M4ReferenceWorkflowEvidence,
    expected_component_digest: &ContentDigest,
    expected_wat_digest: Option<&ContentDigest>,
) -> Result<(), M5ExportError> {
    for execution in &evidence.executions {
        match &execution.actual {
            M4ActualOutput::Builder {
                candidate_wat_digest,
                package_digest,
                ..
            } => {
                if package_digest != expected_component_digest
                    || expected_wat_digest.is_some_and(|expected| candidate_wat_digest != expected)
                {
                    return Err(M5ExportError::Integrity(
                        "full M4 builder evidence targets a different component or WAT recipe"
                            .to_string(),
                    ));
                }
            }
            M4ActualOutput::Validator { package_digest, .. }
            | M4ActualOutput::Packager { package_digest, .. } => {
                if package_digest != expected_component_digest {
                    return Err(M5ExportError::Integrity(
                        "full M4 validation/package evidence targets a different component"
                            .to_string(),
                    ));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_m4_workflow_reference(
    reference: &M5ExportM4WorkflowReferenceV1,
    stored: &M5StoredM4WorkflowEvidenceV1,
) -> Result<(), M5ExportError> {
    stored.validate()?;
    if stored.governance_context_digest() != &reference.governance_context_digest
        || reference
            .workflow_id
            .as_ref()
            .is_some_and(|workflow_id| workflow_id != stored.workflow_id())
        || stored.execution_ids() != reference.execution_ids
        || stored.result_digests() != reference.result_digests
    {
        return Err(M5ExportError::Integrity(format!(
            "full M4 workflow '{}' is missing or cross-linked to different execution/result identities",
            stored.workflow_id()
        )));
    }
    Ok(())
}

fn full_m4_evidence_digest(
    evidence: &M4ReferenceWorkflowEvidence,
) -> Result<ContentDigest, M5ExportError> {
    digest(&(
        "wasm-biotic:m5-generation-m4-workflow-evidence:v1",
        evidence,
    ))
}

fn validate_full_m4_evidence(evidence: &M4ReferenceWorkflowEvidence) -> Result<(), M5ExportError> {
    let worker = &evidence.worker;
    let expected_roles = GovernedWorkerRole::ALL;
    if worker.workflow_id.trim().is_empty()
        || evidence.governance_context_digest != worker.governance_context_digest
        || worker.job_ids.len() != expected_roles.len()
        || worker.execution_ids.len() != expected_roles.len()
        || worker.worker_ids.len() != expected_roles.len()
        || worker.result_digests.len() != expected_roles.len()
        || evidence.executions.len() != expected_roles.len()
        || evidence.package_executions.len() != expected_roles.len()
    {
        return Err(M5ExportError::Integrity(
            "full M4 workflow does not contain one exact record for each required role".to_string(),
        ));
    }
    require_unique_nonempty("M4 job", &worker.job_ids)?;
    require_unique_nonempty("M4 execution", &worker.execution_ids)?;
    require_unique_nonempty("M4 worker", &worker.worker_ids)?;
    if worker.result_digests.iter().collect::<BTreeSet<_>>().len() != expected_roles.len() {
        return Err(M5ExportError::Integrity(
            "full M4 workflow result identities are not unique".to_string(),
        ));
    }

    validate_m4_lifecycle_anchor(&evidence.lifecycle_anchor)?;
    validate_m4_synthesis(&worker.synthesis)?;
    if worker.synthesis.cited_result_digests != worker.result_digests
        || worker.synthesis.cited_execution_ids != worker.execution_ids
        || worker.synthesis.cited_roles != expected_roles
    {
        return Err(M5ExportError::Integrity(
            "M4 synthesis does not cite the exact six exported executions and results".to_string(),
        ));
    }

    let mut attestation_ids = BTreeSet::new();
    let mut invocation_ids = BTreeSet::new();
    let mut package_digests = BTreeSet::new();
    for (ordinal, expected_role) in expected_roles.iter().copied().enumerate() {
        let execution = &evidence.executions[ordinal];
        let package = &evidence.package_executions[ordinal];
        if execution.execution_id != worker.execution_ids[ordinal]
            || execution.worker_result_digest != worker.result_digests[ordinal]
            || execution.role != expected_role
            || execution.governance_context_digest != evidence.governance_context_digest
            || m4_actual_output_role(&execution.actual) != expected_role
            || package.execution_id != worker.execution_ids[ordinal]
            || package.worker_id != worker.worker_ids[ordinal]
            || package.role != expected_role
            || package.governance_context_digest != evidence.governance_context_digest
        {
            return Err(M5ExportError::Integrity(format!(
                "full M4 {:?} execution, result, worker, or package projection is cross-linked",
                expected_role
            )));
        }
        match &execution.actual {
            M4ActualOutput::Validator { passed, .. } if !passed => {
                return Err(M5ExportError::Integrity(
                    "full M4 validator evidence records a failed validation".to_string(),
                ));
            }
            M4ActualOutput::Reviewer { approved, .. } if !approved => {
                return Err(M5ExportError::Integrity(
                    "full M4 reviewer evidence records a rejected review".to_string(),
                ));
            }
            _ => {}
        }
        if execution.service_attestations.is_empty() {
            return Err(M5ExportError::Integrity(format!(
                "full M4 {:?} execution has no native-service attestations",
                expected_role
            )));
        }
        for attestation in &execution.service_attestations {
            validate_service_attestation(attestation)?;
            if !attestation_ids.insert(attestation.attestation_id.as_str())
                || !invocation_ids.insert(attestation.invocation_id.as_str())
            {
                return Err(M5ExportError::Integrity(
                    "full M4 workflow reuses a native-service attestation".to_string(),
                ));
            }
        }
        validate_worker_package_execution(package)?;
        if !package_digests.insert(&package.package_digest) {
            return Err(M5ExportError::Integrity(
                "full M4 workflow did not execute six distinct worker package identities"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_m4_service_evidence(
    evidence: &M4ReferenceWorkflowEvidence,
    suite: &ValidationSuite,
    receipts: &[InvocationReceipt],
    attestations: &[ServiceInvocationAttestation],
) -> Result<(), M5ExportError> {
    if receipts.is_empty()
        || receipts.len() != attestations.len()
        || receipts
            .windows(2)
            .any(|window| window[0].invocation_id() >= window[1].invocation_id())
        || attestations
            .windows(2)
            .any(|window| window[0].invocation_id >= window[1].invocation_id)
    {
        return Err(M5ExportError::Integrity(
            "stored M4 service receipts and attestations are empty, misaligned, or non-canonical"
                .to_string(),
        ));
    }
    let by_invocation = attestations
        .iter()
        .map(|attestation| (attestation.invocation_id.as_str(), attestation))
        .collect::<BTreeMap<_, _>>();
    if by_invocation.len() != attestations.len() {
        return Err(M5ExportError::Integrity(
            "stored M4 service attestations contain duplicate invocation identities".to_string(),
        ));
    }
    for receipt in receipts {
        receipt.verify_integrity().map_err(|error| {
            M5ExportError::Integrity(format!(
                "stored M4 service receipt '{}' is corrupt: {error}",
                receipt.invocation_id()
            ))
        })?;
        if !matches!(receipt.outcome(), InvocationOutcome::Succeeded { .. }) {
            return Err(M5ExportError::Integrity(format!(
                "stored M4 service receipt '{}' is not successful",
                receipt.invocation_id()
            )));
        }
        let attestation = by_invocation.get(receipt.invocation_id()).ok_or_else(|| {
            M5ExportError::Integrity(format!(
                "stored M4 service receipt '{}' has no exact attestation",
                receipt.invocation_id()
            ))
        })?;
        validate_service_attestation(attestation)?;
        if attestation.service_id != receipt.service_id()
            || attestation.family != receipt.family()
            || attestation.operation != receipt.operation()
            || attestation.scope_id != receipt.scope_id()
            || attestation.implementation_digest != receipt_implementation_digest(receipt)?
            || &attestation.input_digest != receipt.input_digest()
            || &attestation.output_digest != receipt.output_digest()
            || &attestation.receipt_digest != receipt.receipt_digest()
            || &attestation.provenance != receipt.provenance()
        {
            return Err(M5ExportError::Integrity(format!(
                "stored M4 receipt and attestation '{}' are cross-linked",
                receipt.invocation_id()
            )));
        }
    }
    for embedded in std::iter::once(&evidence.lifecycle_anchor.schedule_attestation).chain(
        evidence
            .executions
            .iter()
            .flat_map(|execution| execution.service_attestations.iter()),
    ) {
        if by_invocation.get(embedded.invocation_id.as_str()) != Some(&embedded) {
            return Err(M5ExportError::Integrity(format!(
                "full M4 workflow attestation '{}' differs from its exact stored service evidence",
                embedded.invocation_id
            )));
        }
    }

    let successes = receipts
        .iter()
        .filter_map(|receipt| match receipt.outcome() {
            InvocationOutcome::Succeeded { result } => Some(result),
            InvocationOutcome::Terminal { .. } => None,
        })
        .collect::<Vec<_>>();
    let mut proving = BTreeMap::<String, &ProvingRecord>::new();
    let mut comparisons = BTreeMap::<String, &ComparisonRecord>::new();
    for success in &successes {
        validate_m4_typed_success(success)?;
        match success {
            CapabilitySuccess::Proving(record) => {
                validate_proving_record(suite, record).map_err(|error| {
                    M5ExportError::Integrity(format!(
                        "M4 service proving record is invalid: {error}"
                    ))
                })?;
                if proving
                    .insert(record.record_digest.as_str().to_string(), record)
                    .is_some()
                {
                    return Err(M5ExportError::Integrity(
                        "M4 service evidence duplicates a proving record".to_string(),
                    ));
                }
            }
            CapabilitySuccess::Comparison(record) => {
                if comparisons
                    .insert(record.record_digest.as_str().to_string(), record)
                    .is_some()
                {
                    return Err(M5ExportError::Integrity(
                        "M4 service evidence duplicates a comparison record".to_string(),
                    ));
                }
            }
            CapabilitySuccess::Package(package) => {
                if package.artifact_relative_path.is_absolute()
                    || package
                        .artifact_relative_path
                        .components()
                        .any(|component| {
                            matches!(
                                component,
                                std::path::Component::ParentDir
                                    | std::path::Component::RootDir
                                    | std::path::Component::Prefix(_)
                            )
                        })
                {
                    return Err(M5ExportError::Integrity(
                        "M4 package evidence contains an unsafe or sender-rooted artifact path"
                            .to_string(),
                    ));
                }
            }
            _ => {}
        }
    }
    for comparison in comparisons.values() {
        let incumbent = proving
            .get(comparison.incumbent_proving_digest.as_str())
            .ok_or_else(|| {
                M5ExportError::Integrity(
                    "M4 comparison omits its exact incumbent proving record".to_string(),
                )
            })?;
        let challenger = proving
            .get(comparison.challenger_proving_digest.as_str())
            .ok_or_else(|| {
                M5ExportError::Integrity(
                    "M4 comparison omits its exact challenger proving record".to_string(),
                )
            })?;
        validate_comparison_record(suite, incumbent, challenger, comparison).map_err(|error| {
            M5ExportError::Integrity(format!(
                "M4 comparison record is not derivable from its exact proving records: {error}"
            ))
        })?;
    }
    if proving.len() < 2 || comparisons.is_empty() {
        return Err(M5ExportError::Integrity(
            "M4 service evidence omits the real proving or comparison records".to_string(),
        ));
    }
    validate_m4_actual_outputs(&successes, evidence)
}

#[derive(Serialize)]
struct ExportPackageRecordDigestMaterial<'a> {
    schema: &'a str,
    scope_id: &'a str,
    package_digest: &'a ContentDigest,
    source_tree_digest: &'a ContentDigest,
    byte_len: u64,
    artifact_relative_path: &'a std::path::Path,
    build_id: &'a str,
}

#[derive(Serialize)]
struct ExportReviewRecordDigestMaterial<'a> {
    schema: &'a str,
    scope_id: &'a str,
    comparison_digest: &'a ContentDigest,
    incumbent_proving_digest: &'a ContentDigest,
    challenger_proving_digest: &'a ContentDigest,
    decision: crate::capability_services::ReviewDecision,
    rationale: &'a str,
}

#[derive(Serialize)]
struct ExportEvidenceRecordDigestMaterial<'a> {
    schema: &'a str,
    scope_id: &'a str,
    evidence_id: &'a str,
    media_type: &'a str,
    subject_refs: &'a [String],
    content_digest: &'a ContentDigest,
    byte_len: u64,
}

fn validate_m4_typed_success(success: &CapabilitySuccess) -> Result<(), M5ExportError> {
    match success {
        CapabilitySuccess::Build(build) => {
            let exact_component = ContentDigest::from_bytes(&build.component.component_bytes);
            let exact_artifact = crate::execution::artifact::ArtifactDigest::from_bytes(
                &build.component.component_bytes,
            );
            if build.workspace.tree_digest != build.source_tree_digest
                || build.package_digest != exact_component
                || build.component.component_digest != exact_artifact
                || build.component.inspection.component_digest != exact_artifact
                || !build.component.inspection.executable
            {
                return Err(M5ExportError::Integrity(
                    "M4 candidate build record is not bound to its exact source tree and component bytes"
                        .to_string(),
                ));
            }
        }
        CapabilitySuccess::Package(package) => {
            if package.schema != PACKAGE_ARTIFACT_SCHEMA
                || package.scope_id.trim().is_empty()
                || package.build_id.trim().is_empty()
                || package.byte_len == 0
            {
                return Err(M5ExportError::Integrity(
                    "M4 package record has invalid schema, scope, build, or size".to_string(),
                ));
            }
            require_digest(
                "M4 package record",
                &package.package_record_digest,
                &digest(&ExportPackageRecordDigestMaterial {
                    schema: &package.schema,
                    scope_id: &package.scope_id,
                    package_digest: &package.package_digest,
                    source_tree_digest: &package.source_tree_digest,
                    byte_len: package.byte_len,
                    artifact_relative_path: &package.artifact_relative_path,
                    build_id: &package.build_id,
                })?,
            )?;
        }
        CapabilitySuccess::PackageVerification(verification) => {
            if !verification.runnable_component || verification.byte_len == 0 {
                return Err(M5ExportError::Integrity(
                    "M4 package verification is not runnable or has zero bytes".to_string(),
                ));
            }
            require_digest(
                "M4 package verification",
                &verification.verification_digest,
                &digest(&(
                    "wasm-biotic:package-verification:v1",
                    &verification.package_digest,
                    verification.byte_len,
                    true,
                ))?,
            )?;
        }
        CapabilitySuccess::Review(review) => {
            if review.schema != REVIEW_RECORD_SCHEMA
                || review.scope_id.trim().is_empty()
                || review.rationale.trim().is_empty()
            {
                return Err(M5ExportError::Integrity(
                    "M4 review record has invalid schema, scope, or rationale".to_string(),
                ));
            }
            require_digest(
                "M4 review record",
                &review.review_digest,
                &digest(&ExportReviewRecordDigestMaterial {
                    schema: &review.schema,
                    scope_id: &review.scope_id,
                    comparison_digest: &review.comparison_digest,
                    incumbent_proving_digest: &review.incumbent_proving_digest,
                    challenger_proving_digest: &review.challenger_proving_digest,
                    decision: review.decision,
                    rationale: &review.rationale,
                })?,
            )?;
        }
        CapabilitySuccess::EvidencePublished(record) => {
            validate_m4_evidence_record(record)?;
        }
        CapabilitySuccess::EvidenceResolved(resolved) => {
            validate_m4_evidence_record(&resolved.record)?;
            if resolved.record.byte_len != resolved.payload.len() as u64
                || resolved.record.content_digest != ContentDigest::from_bytes(&resolved.payload)
            {
                return Err(M5ExportError::Integrity(
                    "M4 resolved evidence payload differs from its exact record".to_string(),
                ));
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_m4_evidence_record(
    record: &crate::capability_services::EvidenceRecord,
) -> Result<(), M5ExportError> {
    if record.schema != EVIDENCE_RECORD_SCHEMA
        || record.scope_id.trim().is_empty()
        || record.evidence_id.trim().is_empty()
        || record.media_type.trim().is_empty()
    {
        return Err(M5ExportError::Integrity(
            "M4 continuity evidence record has invalid schema or identity".to_string(),
        ));
    }
    require_digest(
        "M4 continuity evidence record",
        &record.record_digest,
        &digest(&ExportEvidenceRecordDigestMaterial {
            schema: &record.schema,
            scope_id: &record.scope_id,
            evidence_id: &record.evidence_id,
            media_type: &record.media_type,
            subject_refs: &record.subject_refs,
            content_digest: &record.content_digest,
            byte_len: record.byte_len,
        })?,
    )
}

fn receipt_implementation_digest(
    receipt: &InvocationReceipt,
) -> Result<ContentDigest, M5ExportError> {
    let value = serde_json::to_value(receipt)
        .map_err(|error| M5ExportError::Serialization(error.to_string()))?;
    serde_json::from_value(value.get("implementation_digest").cloned().ok_or_else(|| {
        M5ExportError::Integrity(
            "M4 invocation receipt omits its implementation digest".to_string(),
        )
    })?)
    .map_err(|error| M5ExportError::Integrity(error.to_string()))
}

fn validate_m4_actual_outputs(
    successes: &[&CapabilitySuccess],
    evidence: &M4ReferenceWorkflowEvidence,
) -> Result<(), M5ExportError> {
    let exact_count = |predicate: &dyn Fn(&CapabilitySuccess) -> bool| {
        successes
            .iter()
            .filter(|success| predicate(success))
            .count()
    };
    for execution in &evidence.executions {
        match &execution.actual {
            M4ActualOutput::Planner { .. } => {
                if exact_count(&|success| matches!(success, CapabilitySuccess::EvidenceResolved(_)))
                    != 1
                {
                    return Err(M5ExportError::Integrity(
                        "M4 planner omits its exact resolved evidence record".to_string(),
                    ));
                }
            }
            M4ActualOutput::Builder {
                candidate_wat_digest,
                source_tree_digest,
                package_digest,
                package_record_digest,
                ..
            } => {
                let builds = exact_count(&|success| {
                    matches!(
                        success,
                        CapabilitySuccess::Build(build)
                            if &build.wat_digest == candidate_wat_digest
                                && &build.source_tree_digest == source_tree_digest
                                && &build.package_digest == package_digest
                    )
                });
                let packages = exact_count(&|success| {
                    matches!(
                        success,
                        CapabilitySuccess::Package(package)
                            if &package.source_tree_digest == source_tree_digest
                                && &package.package_digest == package_digest
                                && &package.package_record_digest == package_record_digest
                    )
                });
                if builds != 1 || packages != 1 {
                    return Err(M5ExportError::Integrity(
                        "M4 builder output does not resolve its exact build and package records"
                            .to_string(),
                    ));
                }
            }
            M4ActualOutput::Validator {
                package_digest,
                proving_digest,
                passed,
                ..
            } => {
                if !passed
                    || exact_count(&|success| {
                        matches!(
                            success,
                            CapabilitySuccess::Proving(record)
                                if &record.component_digest == package_digest
                                    && &record.record_digest == proving_digest
                                    && record.summary.all_satisfied
                        )
                    }) != 1
                {
                    return Err(M5ExportError::Integrity(
                        "M4 validator output does not resolve its exact passing proving record"
                            .to_string(),
                    ));
                }
            }
            M4ActualOutput::Reviewer {
                comparison_digest,
                review_digest,
                approved,
            } => {
                let comparisons = exact_count(&|success| {
                    matches!(
                        success,
                        CapabilitySuccess::Comparison(record)
                            if &record.record_digest == comparison_digest
                    )
                });
                let reviews = exact_count(&|success| {
                    matches!(
                        success,
                        CapabilitySuccess::Review(record)
                            if &record.comparison_digest == comparison_digest
                                && &record.review_digest == review_digest
                                && record.decision
                                    == crate::capability_services::ReviewDecision::Approved
                    )
                });
                if !approved || comparisons != 1 || reviews != 1 {
                    return Err(M5ExportError::Integrity(
                        "M4 reviewer output does not resolve its exact approved comparison and review"
                            .to_string(),
                    ));
                }
            }
            M4ActualOutput::Packager {
                package_digest,
                verification_digest,
            } => {
                if exact_count(&|success| {
                    matches!(
                        success,
                        CapabilitySuccess::PackageVerification(record)
                            if &record.package_digest == package_digest
                                && &record.verification_digest == verification_digest
                                && record.runnable_component
                    )
                }) != 1
                {
                    return Err(M5ExportError::Integrity(
                        "M4 packager output does not resolve its exact verification record"
                            .to_string(),
                    ));
                }
            }
            M4ActualOutput::ContinuityWorker {
                evidence_id,
                content_digest,
                record_digest,
            } => {
                if exact_count(&|success| {
                    matches!(
                        success,
                        CapabilitySuccess::EvidencePublished(record)
                            if &record.evidence_id == evidence_id
                                && &record.content_digest == content_digest
                                && &record.record_digest == record_digest
                    )
                }) != 1
                {
                    return Err(M5ExportError::Integrity(
                        "M4 continuity output does not resolve its exact evidence record"
                            .to_string(),
                    ));
                }
            }
        }
    }
    Ok(())
}

fn require_unique_nonempty<'a>(
    subject: &str,
    values: impl IntoIterator<Item = &'a String>,
) -> Result<(), M5ExportError> {
    let mut unique = BTreeSet::new();
    for value in values {
        if value.trim().is_empty() || !unique.insert(value.as_str()) {
            return Err(M5ExportError::Integrity(format!(
                "{subject} identities are empty or duplicated"
            )));
        }
    }
    Ok(())
}

fn validate_m4_lifecycle_anchor(
    anchor: &crate::m4_runtime::M4LifecycleAnchor,
) -> Result<(), M5ExportError> {
    if anchor.schedule_id.trim().is_empty()
        || anchor.m2_job_id.trim().is_empty()
        || anchor.m2_job_id != anchor.terminal_job.job_id
        || anchor.terminal_job.phase != JobPhase::Succeeded
        || anchor.terminal_job.terminal_outcome.is_none()
        || anchor.terminal_job.payload_digest
            != ContentDigest::from_bytes(anchor.terminal_job.payload_json.as_bytes())
    {
        return Err(M5ExportError::Integrity(
            "full M4 lifecycle anchor is not exact terminal-success evidence".to_string(),
        ));
    }
    require_digest(
        "M4 lifecycle terminal job",
        &anchor.terminal_job_digest,
        &digest(&anchor.terminal_job)?,
    )?;
    validate_service_attestation(&anchor.schedule_attestation)?;
    if anchor.schedule_attestation.family != NativeServiceFamily::Scheduling
        || anchor.schedule_attestation.operation != CapabilityOperation::ScheduleJob
    {
        return Err(M5ExportError::Integrity(
            "full M4 lifecycle anchor lacks its exact scheduling attestation".to_string(),
        ));
    }
    Ok(())
}

#[derive(Serialize)]
struct ExportAttestationDigestMaterial<'a> {
    schema: &'a str,
    attestation_id: &'a str,
    invocation_id: &'a str,
    service_id: &'a str,
    family: NativeServiceFamily,
    operation: CapabilityOperation,
    scope_id: &'a str,
    implementation_digest: &'a ContentDigest,
    input_digest: &'a ContentDigest,
    output_digest: &'a ContentDigest,
    receipt_digest: &'a ContentDigest,
    terminal_success: bool,
    failure_kind: Option<ServiceFailureKind>,
    provenance: &'a InvocationProvenance,
}

fn validate_service_attestation(
    attestation: &ServiceInvocationAttestation,
) -> Result<(), M5ExportError> {
    if attestation.schema != CAPABILITY_ATTESTATION_SCHEMA
        || attestation.attestation_id.trim().is_empty()
        || attestation.invocation_id.trim().is_empty()
        || attestation.service_id.trim().is_empty()
        || attestation.scope_id.trim().is_empty()
        || attestation.operation.family() != attestation.family
        || !attestation.terminal_success
        || attestation.failure_kind.is_some()
        || attestation.provenance.input_ref.trim().is_empty()
        || attestation.provenance.output_ref.trim().is_empty()
        || attestation.provenance.receipt_ref.trim().is_empty()
        || attestation.attestation_id
            != format!("attestation:{}", attestation.receipt_digest.file_stem())
    {
        return Err(M5ExportError::Integrity(
            "full M4 native-service attestation is failed, malformed, or cross-linked".to_string(),
        ));
    }
    let expected = digest(&ExportAttestationDigestMaterial {
        schema: &attestation.schema,
        attestation_id: &attestation.attestation_id,
        invocation_id: &attestation.invocation_id,
        service_id: &attestation.service_id,
        family: attestation.family,
        operation: attestation.operation,
        scope_id: &attestation.scope_id,
        implementation_digest: &attestation.implementation_digest,
        input_digest: &attestation.input_digest,
        output_digest: &attestation.output_digest,
        receipt_digest: &attestation.receipt_digest,
        terminal_success: attestation.terminal_success,
        failure_kind: attestation.failure_kind,
        provenance: &attestation.provenance,
    })?;
    require_digest(
        "M4 native-service attestation",
        &attestation.attestation_digest,
        &expected,
    )
}

#[derive(Serialize)]
struct ExportSynthesisMaterial<'a> {
    synthesis_id: &'a str,
    cited_result_digests: &'a [ContentDigest],
    cited_execution_ids: &'a [String],
    cited_roles: &'a [GovernedWorkerRole],
    created_at_tick: u64,
}

fn validate_m4_synthesis(synthesis: &CoordinatorSynthesis) -> Result<(), M5ExportError> {
    if synthesis.synthesis_id.trim().is_empty()
        || synthesis.cited_result_digests.len() != GovernedWorkerRole::ALL.len()
        || synthesis.cited_execution_ids.len() != GovernedWorkerRole::ALL.len()
        || synthesis.cited_roles.len() != GovernedWorkerRole::ALL.len()
    {
        return Err(M5ExportError::Integrity(
            "full M4 synthesis has malformed citations".to_string(),
        ));
    }
    require_digest(
        "M4 coordinator synthesis",
        &synthesis.synthesis_digest,
        &digest(&ExportSynthesisMaterial {
            synthesis_id: &synthesis.synthesis_id,
            cited_result_digests: &synthesis.cited_result_digests,
            cited_execution_ids: &synthesis.cited_execution_ids,
            cited_roles: &synthesis.cited_roles,
            created_at_tick: synthesis.created_at_tick,
        })?,
    )
}

fn validate_worker_package_execution(
    record: &crate::m4_runtime::WorkerPackageExecutionRecord,
) -> Result<(), M5ExportError> {
    if record.execution_id.trim().is_empty()
        || record.worker_id.trim().is_empty()
        || record.implementation_ref.trim().is_empty()
        || record.component_input != m4_digest_marker(&record.input_digest)
        || record.component_output != record.component_input ^ m4_role_marker(record.role)
        || record.component_trace.component_digest != record.package_digest
        || record.component_trace.input != record.component_input
        || record.component_trace.output != Some(record.component_output)
        || record.component_trace.trapped
        || record.component_trace.failure_phase.is_some()
        || record.component_trace.limit_exhausted.is_some()
    {
        return Err(M5ExportError::Integrity(format!(
            "full M4 worker package execution '{}' is malformed or cross-linked",
            record.execution_id
        )));
    }
    require_digest(
        "M4 worker component trace",
        &record.component_trace_digest,
        &digest(&record.component_trace)?,
    )
}

fn m4_actual_output_role(actual: &M4ActualOutput) -> GovernedWorkerRole {
    match actual {
        M4ActualOutput::Planner { .. } => GovernedWorkerRole::Planner,
        M4ActualOutput::Builder { .. } => GovernedWorkerRole::Builder,
        M4ActualOutput::Validator { .. } => GovernedWorkerRole::Validator,
        M4ActualOutput::Reviewer { .. } => GovernedWorkerRole::Reviewer,
        M4ActualOutput::Packager { .. } => GovernedWorkerRole::Packager,
        M4ActualOutput::ContinuityWorker { .. } => GovernedWorkerRole::ContinuityWorker,
    }
}

fn m4_role_marker(role: GovernedWorkerRole) -> i32 {
    match role {
        GovernedWorkerRole::Planner => 0x11,
        GovernedWorkerRole::Builder => 0x22,
        GovernedWorkerRole::Validator => 0x33,
        GovernedWorkerRole::Reviewer => 0x44,
        GovernedWorkerRole::Packager => 0x55,
        GovernedWorkerRole::ContinuityWorker => 0x66,
    }
}

fn m4_digest_marker(digest: &ContentDigest) -> i32 {
    digest
        .as_str()
        .as_bytes()
        .iter()
        .take(4)
        .fold(0_i32, |value, byte| value.rotate_left(5) ^ i32::from(*byte))
}

fn validate_stable_state(state: &ReproductionState) -> Result<(), M5ExportError> {
    if state.active_generation == 0 {
        return Err(M5ExportError::NotExportable(
            "generation-zero or synthetic roots are not exportable".to_string(),
        ));
    }
    if state.in_flight.is_some() {
        return Err(M5ExportError::NotExportable(
            "factory has an in-flight migration, activation, observation, or recovery".to_string(),
        ));
    }
    if !state.prepared_successors.is_empty() {
        return Err(M5ExportError::NotExportable(
            "factory has a prepared but unresolved successor".to_string(),
        ));
    }
    if state.cycles.iter().any(|cycle| {
        matches!(
            cycle.status,
            CycleStatus::Evaluating | CycleStatus::Approved
        )
    }) {
        return Err(M5ExportError::NotExportable(
            "factory contains a non-terminal cycle".to_string(),
        ));
    }
    for intent in &state.cycle_intents {
        let cycle_count = state
            .cycles
            .iter()
            .filter(|cycle| cycle.cycle_id == intent.cycle_id)
            .count();
        let stop_count = state
            .stop_conditions
            .iter()
            .filter(|stop| stop.requested_cycle_id == intent.cycle_id)
            .count();
        if cycle_count + stop_count != 1 {
            return Err(M5ExportError::NotExportable(format!(
                "cycle intent '{}' is unresolved or ambiguously terminal",
                intent.cycle_id
            )));
        }
    }
    Ok(())
}

fn select_current_adoption(
    state: &ReproductionState,
) -> Result<(&CycleIntent, &CycleRecord, &FactoryLineageRecord), M5ExportError> {
    let lineage = state
        .lineage
        .iter()
        .rev()
        .find(|record| {
            matches!(
                record.disposition,
                LineageDisposition::Root
                    | LineageDisposition::Adopted
                    | LineageDisposition::OperatorRollback
            )
        })
        .ok_or_else(|| {
            M5ExportError::Integrity(
                "factory lineage has no active-changing transition".to_string(),
            )
        })?;
    if lineage.disposition != LineageDisposition::Adopted {
        return Err(M5ExportError::NotExportable(
            "current package is a root or an operator-restored package, not a live adoption"
                .to_string(),
        ));
    }
    if lineage.package_digest != state.active_package_digest
        || lineage.generation != state.active_generation
    {
        return Err(M5ExportError::Integrity(
            "latest active-changing lineage does not name the current package".to_string(),
        ));
    }
    let cycle_digest = lineage.cycle_record_digest.as_ref().ok_or_else(|| {
        M5ExportError::Integrity("active adopted lineage has no cycle record digest".to_string())
    })?;
    let mut cycles = state
        .cycles
        .iter()
        .filter(|cycle| &cycle.record_digest == cycle_digest);
    let cycle = cycles.next().ok_or_else(|| {
        M5ExportError::Integrity("active adopted lineage has no cycle record".to_string())
    })?;
    if cycles.next().is_some() {
        return Err(M5ExportError::Integrity(
            "active adopted lineage resolves to multiple cycles".to_string(),
        ));
    }
    if cycle.status != CycleStatus::Adopted
        || cycle.challenger_package_digest != state.active_package_digest
        || cycle.generation != state.active_generation
    {
        return Err(M5ExportError::NotExportable(
            "latest active lineage does not resolve to an adopted healthy cycle".to_string(),
        ));
    }
    let mut intents = state
        .cycle_intents
        .iter()
        .filter(|intent| intent.cycle_id == cycle.cycle_id);
    let intent = intents.next().ok_or_else(|| {
        M5ExportError::Integrity("active adopted cycle has no immutable intent".to_string())
    })?;
    if intents.next().is_some() {
        return Err(M5ExportError::Integrity(
            "active adopted cycle has ambiguous immutable intents".to_string(),
        ));
    }
    Ok((intent, cycle, lineage))
}

fn validate_state_package_links(
    state: &ReproductionState,
    packages: &BTreeMap<String, FactoryPackage>,
) -> Result<(), M5ExportError> {
    let mut roots = 0usize;
    for (key, index) in &state.package_index {
        if key != index.package_digest.as_str() {
            return Err(M5ExportError::Integrity(
                "package index key differs from its package identity".to_string(),
            ));
        }
        let package = packages.get(key).ok_or_else(|| {
            M5ExportError::Integrity(format!("package index entry '{key}' has no exact bytes"))
        })?;
        if package.byte_len != index.byte_len || package.payload.generation != index.generation {
            return Err(M5ExportError::Integrity(format!(
                "package index metadata for '{key}' differs from its exact bytes"
            )));
        }
        match &package.payload.parent_package_digest {
            None => {
                roots += 1;
                if package.payload.generation != 0 {
                    return Err(M5ExportError::Integrity(
                        "a parentless package has a nonzero generation".to_string(),
                    ));
                }
            }
            Some(parent_digest) => {
                let parent = packages.get(parent_digest.as_str()).ok_or_else(|| {
                    M5ExportError::Integrity(format!(
                        "package {} has no retained parent bytes",
                        package.package_digest
                    ))
                })?;
                if parent.payload.generation.checked_add(1) != Some(package.payload.generation) {
                    return Err(M5ExportError::Integrity(
                        "package generation does not immediately follow its retained parent"
                            .to_string(),
                    ));
                }
            }
        }
    }
    if roots != 1 {
        return Err(M5ExportError::Integrity(
            "package closure must contain exactly one generation-zero root".to_string(),
        ));
    }
    for intent in &state.cycle_intents {
        let incumbent = packages
            .get(intent.expected_active_package_digest.as_str())
            .ok_or_else(|| {
                M5ExportError::Integrity(format!(
                    "cycle intent '{}' references missing incumbent bytes",
                    intent.cycle_id
                ))
            })?;
        require_digest(
            "cycle intent incumbent bytes",
            &intent.expected_active_package_bytes_digest,
            &ContentDigest::from_bytes(&incumbent.canonical_bytes().map_err(reproduction)?),
        )?;
    }
    for cycle in &state.cycles {
        let parent = packages
            .get(cycle.parent_package_digest.as_str())
            .ok_or_else(|| {
                M5ExportError::Integrity(format!(
                    "cycle '{}' references missing parent bytes",
                    cycle.cycle_id
                ))
            })?;
        let challenger = packages
            .get(cycle.challenger_package_digest.as_str())
            .ok_or_else(|| {
                M5ExportError::Integrity(format!(
                    "cycle '{}' references missing challenger bytes",
                    cycle.cycle_id
                ))
            })?;
        if challenger.payload.parent_package_digest.as_ref() != Some(&parent.package_digest)
            || challenger.payload.generation != cycle.generation
            || challenger.payload.genome.genome_digest != cycle.genome_digest
        {
            return Err(M5ExportError::Integrity(format!(
                "cycle '{}' package ancestry or genome is cross-linked",
                cycle.cycle_id
            )));
        }
        require_digest(
            "cycle challenger package bytes",
            &cycle.challenger_package_bytes_digest,
            &ContentDigest::from_bytes(&challenger.canonical_bytes().map_err(reproduction)?),
        )?;
    }
    for lineage in &state.lineage {
        let package = packages
            .get(lineage.package_digest.as_str())
            .ok_or_else(|| {
                M5ExportError::Integrity(format!(
                    "lineage '{}' references missing package bytes",
                    lineage.lineage_id
                ))
            })?;
        if package.payload.generation != lineage.generation
            || package.payload.genome.genome_digest != lineage.genome_digest
            || package.payload.parent_package_digest != lineage.parent_package_digest
        {
            return Err(M5ExportError::Integrity(format!(
                "lineage '{}' differs from its exact package",
                lineage.lineage_id
            )));
        }
        require_digest(
            "lineage package bytes",
            &lineage.package_bytes_digest,
            &ContentDigest::from_bytes(&package.canonical_bytes().map_err(reproduction)?),
        )?;
    }
    for initiation in &state.generation_initiations {
        let executor = packages
            .get(initiation.executor_package_digest.as_str())
            .ok_or_else(|| {
                M5ExportError::Integrity(format!(
                    "generation initiation '{}' has no executor bytes",
                    initiation.cycle_id
                ))
            })?;
        let executor_bytes = executor.canonical_bytes().map_err(reproduction)?;
        require_digest(
            "generation executor package bytes",
            &initiation.executor_package_bytes_digest,
            &ContentDigest::from_bytes(&executor_bytes),
        )?;
        if initiation.driver_request.executor_component_digest
            != executor.payload.genome.component_digest
            || initiation.driver_request.stable_interface_digest
                != executor
                    .payload
                    .stable_interface
                    .contract_digest()
                    .map_err(reproduction)?
        {
            return Err(M5ExportError::Integrity(
                "generation initiation is cross-linked to another executor".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_active_cycle_semantics(
    state: &ReproductionState,
    intent: &CycleIntent,
    cycle: &CycleRecord,
    lineage: &FactoryLineageRecord,
    parent: &FactoryPackage,
    active: &FactoryPackage,
) -> Result<(), M5ExportError> {
    let active_bytes = active.canonical_bytes().map_err(reproduction)?;
    let active_bytes_digest = ContentDigest::from_bytes(&active_bytes);
    let parent_bytes = parent.canonical_bytes().map_err(reproduction)?;
    let parent_bytes_digest = ContentDigest::from_bytes(&parent_bytes);
    let interface_digest = active
        .payload
        .stable_interface
        .contract_digest()
        .map_err(reproduction)?;

    if intent.expected_active_package_digest != parent.package_digest
        || intent.expected_active_package_bytes_digest != parent_bytes_digest
        || intent.expected_gate_digest != state.release_gate.gate_digest
        || intent.state_compatibility != active.payload.boot_manifest.state_compatibility
        || intent.migration_plan != cycle.migration_plan
        || cycle.parent_package_digest != parent.package_digest
        || cycle.challenger_package_digest != active.package_digest
        || cycle.challenger_package_bytes_digest != active_bytes_digest
        || cycle.genome_digest != active.payload.genome.genome_digest
        || cycle.gate_digest != state.release_gate.gate_digest
        || !cycle.gate_decision.eligible
        || cycle.recovery_receipt.is_some()
    {
        return Err(M5ExportError::NotExportable(
            "active adopted cycle does not preserve exact intent, package, gate, or recovery posture"
                .to_string(),
        ));
    }
    match intent.kind {
        CycleIntentKind::Seeded => {
            if intent.seed_genome.as_ref() != Some(&active.payload.genome)
                || cycle.initiation.is_some()
            {
                return Err(M5ExportError::Integrity(
                    "seeded active cycle has cross-linked genome or initiation evidence"
                        .to_string(),
                ));
            }
        }
        CycleIntentKind::AdoptedSuccessor => {
            let initiation = cycle.initiation.as_ref().ok_or_else(|| {
                M5ExportError::Integrity(
                    "recursive active cycle lacks its generation initiation".to_string(),
                )
            })?;
            if intent.seed_genome.is_some()
                || initiation.successor_genome_digest != active.payload.genome.genome_digest
                || !state
                    .generation_initiations
                    .iter()
                    .any(|stored| stored == initiation)
            {
                return Err(M5ExportError::Integrity(
                    "recursive active cycle has missing or cross-linked generation evidence"
                        .to_string(),
                ));
            }
        }
    }
    let initiation_digest = cycle
        .initiation
        .as_ref()
        .map(|initiation| initiation.material_step_digest.clone());
    if lineage.parent_package_digest.as_ref() != Some(&parent.package_digest)
        || lineage.package_digest != active.package_digest
        || lineage.package_bytes_digest != active_bytes_digest
        || lineage.genome_digest != active.payload.genome.genome_digest
        || lineage.cycle_record_digest.as_ref() != Some(&cycle.record_digest)
        || lineage.generation_initiation_digest != initiation_digest
        || lineage.prior_state_schema
            != state
                .retained_incumbent
                .as_ref()
                .map(|retained| retained.state_schema)
                .unwrap_or_default()
        || lineage.resulting_state_schema != state.active_state_schema
        || lineage.recovery_receipt_digest.is_some()
    {
        return Err(M5ExportError::Integrity(
            "active adopted lineage is missing or cross-linked".to_string(),
        ));
    }
    let retained = state.retained_incumbent.as_ref().ok_or_else(|| {
        M5ExportError::NotExportable(
            "active adoption has no exact retained incumbent recovery target".to_string(),
        )
    })?;
    if retained.package_digest != parent.package_digest {
        return Err(M5ExportError::Integrity(
            "retained incumbent differs from the active cycle parent".to_string(),
        ));
    }
    if state
        .quarantines
        .iter()
        .any(|record| record.package_digest == active.package_digest)
    {
        return Err(M5ExportError::NotExportable(
            "current package is quarantined".to_string(),
        ));
    }

    validate_m1(cycle, active, &interface_digest)?;
    validate_workers(cycle, parent, active, &active_bytes_digest)?;
    validate_shadow_and_gate(cycle, parent, active, &parent_bytes, &active_bytes, state)?;
    let approval = validate_approval(cycle, intent, active, &active_bytes_digest)?;
    validate_migration(cycle, lineage)?;
    let activation =
        validate_activation(cycle, active, &active_bytes, &active_bytes_digest, approval)?;
    validate_healthy_observation(cycle, active, &active_bytes_digest, activation, state)
}

fn validate_m1(
    cycle: &CycleRecord,
    active: &FactoryPackage,
    interface_digest: &ContentDigest,
) -> Result<(), M5ExportError> {
    let expected_request = digest(&(
        "wasm-biotic:m1-build-request:v1",
        &cycle.cycle_id,
        &active.payload.genome.genome_digest,
        &active.payload.genome.component_digest,
        &active.payload.genome.component_bytes,
        interface_digest,
    ))?;
    let evidence = &cycle.m1_evidence;
    if evidence.request_digest != expected_request
        || evidence.component_digest != active.payload.genome.component_digest
        || &evidence.stable_interface_digest != interface_digest
        || evidence.observed_export != REFERENCE_EXPORT
        || !evidence.runnable
    {
        return Err(M5ExportError::Integrity(
            "active cycle M1 evidence is missing, failed, or cross-linked".to_string(),
        ));
    }
    Ok(())
}

fn validate_workers(
    cycle: &CycleRecord,
    parent: &FactoryPackage,
    active: &FactoryPackage,
    active_bytes_digest: &ContentDigest,
) -> Result<(), M5ExportError> {
    let required_roles = [
        WorkerRole::Planner,
        WorkerRole::Builder,
        WorkerRole::Validator,
        WorkerRole::Reviewer,
        WorkerRole::Packager,
        WorkerRole::Continuity,
    ];
    let expected_request = digest(&(
        "wasm-biotic:worker-workflow-request:v1",
        &cycle.cycle_id,
        &parent.package_digest,
        &active.package_digest,
        active_bytes_digest,
        &active.payload.genome.genome_digest,
        &cycle.gate_digest,
        &required_roles,
    ))?;
    let evidence = &cycle.worker_evidence;
    let mut roles = BTreeSet::new();
    if evidence.request_digest != expected_request
        || evidence.challenger_package_digest != active.package_digest
        || evidence.receipts.len() != required_roles.len()
    {
        return Err(M5ExportError::Integrity(
            "active cycle M4 workflow evidence is missing or cross-linked".to_string(),
        ));
    }
    for receipt in &evidence.receipts {
        if !roles.insert(receipt.role)
            || receipt.execution_id.trim().is_empty()
            || receipt.terminal_status != WorkerTerminalStatus::Succeeded
            || receipt.input_digest != expected_request
            || receipt.output_digest.is_none()
        {
            return Err(M5ExportError::Integrity(
                "active cycle M4 receipts do not prove six exact successful roles".to_string(),
            ));
        }
    }
    if roles != required_roles.into_iter().collect() {
        return Err(M5ExportError::Integrity(
            "active cycle M4 evidence omits a required worker role".to_string(),
        ));
    }
    Ok(())
}

fn validate_shadow_and_gate(
    cycle: &CycleRecord,
    parent: &FactoryPackage,
    active: &FactoryPackage,
    parent_bytes: &[u8],
    active_bytes: &[u8],
    state: &ReproductionState,
) -> Result<(), M5ExportError> {
    let expected_request = digest(&(
        "wasm-biotic:shadow-execution-request:v1",
        &cycle.cycle_id,
        &parent.package_digest,
        parent_bytes,
        &active.package_digest,
        active_bytes,
        &state.release_gate.gate_digest,
    ))?;
    let shadow = &cycle.shadow_evidence;
    if shadow.request_digest != expected_request {
        return Err(M5ExportError::Integrity(
            "active cycle M3 shadow request is cross-linked".to_string(),
        ));
    }
    let mut incumbent = BTreeMap::new();
    for observation in &shadow.incumbent_observations {
        if observation.package_digest != parent.package_digest
            || incumbent
                .insert(observation.benchmark_id.as_str(), observation)
                .is_some()
        {
            return Err(M5ExportError::Integrity(
                "incumbent shadow observations are duplicated or cross-linked".to_string(),
            ));
        }
    }
    let mut challenger = BTreeMap::new();
    for observation in &shadow.challenger_observations {
        if observation.package_digest != active.package_digest
            || challenger
                .insert(observation.benchmark_id.as_str(), observation)
                .is_some()
        {
            return Err(M5ExportError::Integrity(
                "challenger shadow observations are duplicated or cross-linked".to_string(),
            ));
        }
    }
    let gate = &state.release_gate;
    if incumbent.len() != gate.benchmarks.len() || challenger.len() != gate.benchmarks.len() {
        return Err(M5ExportError::Integrity(
            "shadow evidence does not cover every benchmark exactly once".to_string(),
        ));
    }
    let mut passed = 0u32;
    let mut regressions = 0u32;
    for benchmark in &gate.benchmarks {
        let incumbent_observation =
            incumbent
                .get(benchmark.benchmark_id.as_str())
                .ok_or_else(|| {
                    M5ExportError::Integrity("missing incumbent benchmark evidence".to_string())
                })?;
        let challenger_observation =
            challenger
                .get(benchmark.benchmark_id.as_str())
                .ok_or_else(|| {
                    M5ExportError::Integrity("missing challenger benchmark evidence".to_string())
                })?;
        let request_digest = ContentDigest::from_bytes(&benchmark.request_bytes);
        if incumbent_observation.request_digest != request_digest
            || challenger_observation.request_digest != request_digest
        {
            return Err(M5ExportError::Integrity(
                "shadow benchmark request identity is cross-linked".to_string(),
            ));
        }
        let incumbent_passed = observation_passes(incumbent_observation, benchmark);
        let challenger_passed = observation_passes(challenger_observation, benchmark);
        if challenger_passed {
            passed += 1;
        }
        if incumbent_passed && !challenger_passed {
            regressions += 1;
        }
    }
    let mut invariants = BTreeMap::new();
    for observation in &shadow.invariant_observations {
        if observation.package_digest != active.package_digest
            || invariants
                .insert(observation.invariant_id.as_str(), observation)
                .is_some()
        {
            return Err(M5ExportError::Integrity(
                "shadow invariant evidence is duplicated or cross-linked".to_string(),
            ));
        }
    }
    if invariants.len() != gate.invariants.len() {
        return Err(M5ExportError::Integrity(
            "shadow evidence does not cover every invariant exactly once".to_string(),
        ));
    }
    let required_invariants_satisfied = gate.invariants.iter().all(|invariant| {
        invariants
            .get(invariant.invariant_id.as_str())
            .is_some_and(|observation| observation.satisfied || !invariant.required)
    });
    let expected_tasks =
        (shadow.incumbent_observations.len() + shadow.challenger_observations.len()) as u32;
    let within_budgets = shadow.resource_usage.shadow_tasks == expected_tasks
        && shadow.resource_usage.shadow_tasks <= gate.budgets.max_shadow_tasks
        && shadow.resource_usage.component_bytes <= gate.budgets.max_component_bytes
        && shadow.resource_usage.state_bytes <= gate.budgets.max_state_bytes;
    let success_basis_points = ((u64::from(passed) * 10_000) / gate.benchmarks.len() as u64) as u16;
    let eligible = passed >= gate.thresholds.minimum_passed_benchmarks
        && success_basis_points >= gate.thresholds.minimum_success_basis_points
        && regressions <= gate.thresholds.maximum_regressions
        && (!gate.thresholds.require_all_required_invariants || required_invariants_satisfied)
        && within_budgets;
    let decision = &cycle.gate_decision;
    if decision.gate_digest != gate.gate_digest
        || decision.shadow_evidence_digest != shadow.evidence_digest
        || decision.passed_benchmarks != passed
        || decision.success_basis_points != success_basis_points
        || decision.regressions != regressions
        || decision.required_invariants_satisfied != required_invariants_satisfied
        || decision.within_budgets != within_budgets
        || decision.eligible != eligible
        || !eligible
    {
        return Err(M5ExportError::NotExportable(
            "active cycle shadow evidence does not independently rederive an eligible gate"
                .to_string(),
        ));
    }
    Ok(())
}

fn observation_passes(
    observation: &crate::factory_reproduction::TaskExecutionObservation,
    benchmark: &crate::factory_reproduction::BenchmarkSpec,
) -> bool {
    observation.terminal == ExecutionTerminal::Succeeded
        && observation.health == HealthStatus::Healthy
        && observation.output_digest.as_ref() == Some(&benchmark.expected_output_digest)
        && observation.duration_ms <= benchmark.max_duration_ms
}

fn validate_approval<'a>(
    cycle: &'a CycleRecord,
    intent: &CycleIntent,
    active: &FactoryPackage,
    active_bytes_digest: &ContentDigest,
) -> Result<&'a SupervisorApprovalRecord, M5ExportError> {
    let approval = cycle.approval.as_ref().ok_or_else(|| {
        M5ExportError::NotExportable("active cycle has no supervisor approval".to_string())
    })?;
    let migration_plan_digest = cycle
        .migration_plan
        .as_ref()
        .map(|plan| plan.plan_digest.clone());
    let expected_request = digest(&(
        "wasm-biotic:supervisor-approval-request:v1",
        &cycle.cycle_id,
        &cycle.parent_package_digest,
        &active.package_digest,
        active_bytes_digest,
        &cycle.gate_digest,
        &cycle.gate_decision.decision_digest,
        &cycle.m1_evidence.evidence_digest,
        &cycle.worker_evidence.evidence_digest,
        &cycle.shadow_evidence.evidence_digest,
        &migration_plan_digest,
        &intent.operator_context_digest,
    ))?;
    let expected_evidence = [
        cycle.m1_evidence.evidence_digest.clone(),
        cycle.worker_evidence.evidence_digest.clone(),
        cycle.shadow_evidence.evidence_digest.clone(),
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let actual_evidence = approval
        .evidence_digests
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if approval.decision != ApprovalDecision::Approved
        || approval.request_digest != expected_request
        || approval.approved_package_digest.as_ref() != Some(&active.package_digest)
        || approval.approved_package_bytes_digest.as_ref() != Some(active_bytes_digest)
        || approval.gate_decision_digest != cycle.gate_decision.decision_digest
        || actual_evidence != expected_evidence
        || approval.evidence_digests.len() != expected_evidence.len()
        || approval.approver_ref.trim().is_empty()
        || approval.rationale.trim().is_empty()
    {
        return Err(M5ExportError::NotExportable(
            "active cycle approval is absent, rejected, or cross-linked".to_string(),
        ));
    }
    Ok(approval)
}

fn validate_migration(
    cycle: &CycleRecord,
    lineage: &FactoryLineageRecord,
) -> Result<(), M5ExportError> {
    match (&cycle.migration_plan, &cycle.migration_receipt) {
        (None, None) => Ok(()),
        (Some(plan), Some(receipt)) => {
            let expected_request = digest(&(
                "wasm-biotic:migration-request:v1",
                &cycle.cycle_id,
                &cycle.parent_package_digest,
                &cycle.challenger_package_digest,
                &plan.plan_digest,
            ))?;
            if receipt.request_digest != expected_request
                || receipt.migration_id != plan.migration_id
                || receipt.from_schema != plan.from_schema
                || receipt.to_schema != plan.to_schema
                || plan.from_schema != lineage.prior_state_schema
                || plan.to_schema != lineage.resulting_state_schema
                || plan.rollback_schema != lineage.prior_state_schema
                || !receipt.rollback_verified
            {
                return Err(M5ExportError::Integrity(
                    "active cycle migration evidence is failed or cross-linked".to_string(),
                ));
            }
            Ok(())
        }
        _ => Err(M5ExportError::Integrity(
            "active cycle migration plan and receipt are incomplete".to_string(),
        )),
    }
}

fn validate_activation<'a>(
    cycle: &'a CycleRecord,
    active: &FactoryPackage,
    active_bytes: &[u8],
    active_bytes_digest: &ContentDigest,
    approval: &SupervisorApprovalRecord,
) -> Result<&'a ActivationReceipt, M5ExportError> {
    let activation = cycle.activation_receipt.as_ref().ok_or_else(|| {
        M5ExportError::NotExportable("active cycle has no activation receipt".to_string())
    })?;
    let target_schema = active
        .payload
        .boot_manifest
        .state_compatibility
        .written_schema;
    let expected_request = digest(&(
        "wasm-biotic:activation-request:v1",
        &cycle.cycle_id,
        &cycle.parent_package_digest,
        &active.package_digest,
        active_bytes,
        &approval.approval_digest,
        &cycle.gate_decision.decision_digest,
        target_schema,
    ))?;
    if activation.request_digest != expected_request
        || activation.previous_package_digest != cycle.parent_package_digest
        || activation.active_package_digest != active.package_digest
        || &activation.active_package_bytes_digest != active_bytes_digest
        || activation.active_state_schema != target_schema
    {
        return Err(M5ExportError::Integrity(
            "active cycle activation receipt is missing or cross-linked".to_string(),
        ));
    }
    Ok(activation)
}

fn validate_healthy_observation(
    cycle: &CycleRecord,
    active: &FactoryPackage,
    active_bytes_digest: &ContentDigest,
    activation: &ActivationReceipt,
    state: &ReproductionState,
) -> Result<(), M5ExportError> {
    let evidence = cycle.observation_evidence.as_ref().ok_or_else(|| {
        M5ExportError::NotExportable(
            "active cycle has no post-activation health evidence".to_string(),
        )
    })?;
    let minimum_successes = state
        .release_gate
        .thresholds
        .minimum_post_activation_successes;
    let expected_request = digest(&(
        "wasm-biotic:post-activation-request:v1",
        &cycle.cycle_id,
        &activation.activation_id,
        &active.package_digest,
        active_bytes_digest,
        minimum_successes,
    ))?;
    if evidence.request_digest != expected_request
        || evidence.active_package_digest != active.package_digest
        || evidence.task_observations.len() < minimum_successes as usize
        || evidence.task_observations.iter().any(|observation| {
            observation.package_digest != active.package_digest
                || observation.terminal != ExecutionTerminal::Succeeded
                || observation.health != HealthStatus::Healthy
                || observation.output_digest.is_none()
        })
        || evidence.health_observations.is_empty()
        || evidence.health_observations.iter().any(|observation| {
            observation.active_package_digest != active.package_digest
                || observation.status != HealthStatus::Healthy
        })
    {
        return Err(M5ExportError::NotExportable(
            "active package is missing exact all-healthy post-activation evidence".to_string(),
        ));
    }
    Ok(())
}

fn validate_snapshot(
    snapshot: &FactoryRuntimeSnapshot,
    state: &ReproductionState,
    active: &FactoryPackage,
    activation: &ActivationReceipt,
) -> Result<(), M5ExportError> {
    let expected = digest(&(
        FACTORY_SNAPSHOT_SCHEMA,
        &snapshot.factory_id,
        &snapshot.package_digest,
        &snapshot.package_bytes_digest,
        &snapshot.component_digest,
        snapshot.generation,
        snapshot.state_schema,
        &snapshot.state_blob_digest,
        &snapshot.activation_id,
    ))?;
    let active_bytes = active.canonical_bytes().map_err(reproduction)?;
    if snapshot.schema != FACTORY_SNAPSHOT_SCHEMA
        || snapshot.snapshot_digest != expected
        || snapshot.factory_id != state.factory_id
        || snapshot.package_digest != state.active_package_digest
        || snapshot.package_bytes_digest != ContentDigest::from_bytes(&active_bytes)
        || snapshot.component_digest != active.payload.genome.component_digest
        || snapshot.generation != state.active_generation
        || snapshot.state_schema != state.active_state_schema
        || snapshot.activation_id.as_ref() != Some(&activation.activation_id)
    {
        return Err(M5ExportError::Integrity(
            "active backend snapshot differs from the adopted package or activation".to_string(),
        ));
    }
    Ok(())
}

fn validate_effect_audit(
    audit: &M5EffectAuditReport,
    state: &ReproductionState,
    cycle: &CycleRecord,
    snapshot: &FactoryRuntimeSnapshot,
) -> Result<(), M5ExportError> {
    if audit.reproduction_state_digest != state.state_digest
        || audit.backend_snapshot_digest != snapshot.snapshot_digest
    {
        return Err(M5ExportError::Integrity(
            "M3 audit roots differ from the exported state or backend snapshot".to_string(),
        ));
    }
    if !audit
        .entries
        .iter()
        .any(|entry| entry.kind == M5EffectAuditKind::Initialization)
    {
        return Err(M5ExportError::Integrity(
            "M3 audit omits factory initialization".to_string(),
        ));
    }
    if audit.entries.iter().any(|entry| {
        matches!(
            entry.kind,
            M5EffectAuditKind::InFlightMigration
                | M5EffectAuditKind::InFlightActivation
                | M5EffectAuditKind::InFlightObservation
                | M5EffectAuditKind::InFlightRecovery
        )
    }) {
        return Err(M5ExportError::NotExportable(
            "M3 audit contains an in-flight effect".to_string(),
        ));
    }
    require_effect(
        audit,
        M5EffectAuditKind::Shadow,
        &cycle.shadow_evidence.request_digest,
        &cycle.shadow_evidence,
    )?;
    if let Some(initiation) = &cycle.initiation {
        require_generation_driver_effect(audit, initiation)?;
    }
    if let Some(receipt) = &cycle.migration_receipt {
        require_effect(
            audit,
            M5EffectAuditKind::Migration,
            &receipt.request_digest,
            receipt,
        )?;
    }
    let activation = cycle.activation_receipt.as_ref().ok_or_else(|| {
        M5ExportError::Integrity("active cycle activation disappeared".to_string())
    })?;
    require_effect(
        audit,
        M5EffectAuditKind::Activation,
        &activation.request_digest,
        activation,
    )?;
    let observation = cycle.observation_evidence.as_ref().ok_or_else(|| {
        M5ExportError::Integrity("active cycle observation disappeared".to_string())
    })?;
    require_effect(
        audit,
        M5EffectAuditKind::Observation,
        &observation.request_digest,
        observation,
    )
}

fn require_generation_driver_effect(
    audit: &M5EffectAuditReport,
    initiation: &crate::factory_reproduction::GenerationInitiationRecord,
) -> Result<(), M5ExportError> {
    // M5's generation driver is not a separate backend operation. It is the
    // exact active-package execution whose trace/directive is projected into
    // GenerationDriverEvidence. The authoritative audit therefore keys it by
    // the underlying FactoryExecuteRequest and FactoryExecutionResult.
    let execute_request = crate::m5_effect_store::FactoryExecuteRequest::new(
        initiation.driver_request.executor_package_digest.clone(),
        initiation.driver_request.driver_contract.driver_input,
    )
    .map_err(|error| M5ExportError::Integrity(error.to_string()))?;
    let evidence = &initiation.driver_evidence;
    let matches = audit
        .entries
        .iter()
        .filter(|entry| {
            entry.kind == M5EffectAuditKind::GenerationDriver
                && entry.domain_request_digest == execute_request.request_digest
                && entry.invocation_id == evidence.invocation_id
                && entry.receipt_digest == evidence.service_receipt_digest
                && entry.attestation_digest == evidence.service_attestation_digest
        })
        .count();
    if matches != 1 {
        return Err(M5ExportError::Integrity(format!(
            "M3 audit resolves generation driver '{}' to {matches} exact execution effects",
            initiation.cycle_id
        )));
    }
    Ok(())
}

fn require_effect<T: Serialize>(
    audit: &M5EffectAuditReport,
    kind: M5EffectAuditKind,
    request_digest: &ContentDigest,
    response: &T,
) -> Result<(), M5ExportError> {
    let response_digest = ContentDigest::from_bytes(&canonical_json(response)?);
    let matches = audit
        .entries
        .iter()
        .filter(|entry| {
            entry.kind == kind
                && &entry.domain_request_digest == request_digest
                && entry.backend_response_digest == response_digest
        })
        .count();
    if matches != 1 {
        return Err(M5ExportError::Integrity(format!(
            "M3 audit resolves {kind:?} request {request_digest} to {matches} exact effects"
        )));
    }
    Ok(())
}

fn validate_suite_gate_identity(
    suite: &ValidationSuite,
    gate: &crate::factory_reproduction::ReleaseGate,
) -> Result<(), M5ExportError> {
    if suite.export_name
        != crate::factory_reproduction::StableInterfaceContract::reference().exported_function
        || suite.cases.len() != gate.benchmarks.len()
    {
        return Err(M5ExportError::Integrity(
            "portable runtime proving suite and release gate describe different tasks".to_string(),
        ));
    }
    for (case, benchmark) in suite.cases.iter().zip(&gate.benchmarks) {
        let ExpectedI32Outcome::Returned(expected) = &case.expected else {
            return Err(M5ExportError::Integrity(
                "portable M5 release identity requires returned-i32 proving outcomes".to_string(),
            ));
        };
        if benchmark.request_bytes != case.input.to_le_bytes()
            || benchmark.expected_output_digest
                != ContentDigest::from_bytes(&expected.to_le_bytes())
        {
            return Err(M5ExportError::Integrity(format!(
                "portable benchmark '{}' differs from proving case '{}'",
                benchmark.benchmark_id, case.case_id
            )));
        }
    }
    Ok(())
}

fn require_digest(
    subject: &str,
    actual: &ContentDigest,
    expected: &ContentDigest,
) -> Result<(), M5ExportError> {
    if actual != expected {
        return Err(M5ExportError::Integrity(format!(
            "{subject} digest mismatch: expected {expected}, got {actual}"
        )));
    }
    Ok(())
}

fn reproduction(error: impl Display) -> M5ExportError {
    M5ExportError::Integrity(error.to_string())
}

fn digest<T: Serialize>(value: &T) -> Result<ContentDigest, M5ExportError> {
    digest_json_content(value).map_err(|error| M5ExportError::Serialization(error.to_string()))
}

fn canonical_json<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, M5ExportError> {
    serde_json::to_vec(value).map_err(|error| M5ExportError::Serialization(error.to_string()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum M5ExportError {
    UnsupportedSchema(String),
    NotExportable(String),
    Integrity(String),
    ResourceBound(String),
    Serialization(String),
}

impl Display for M5ExportError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedSchema(schema) => {
                write!(formatter, "unsupported M5 export schema '{schema}'")
            }
            Self::NotExportable(message) => {
                write!(formatter, "M5 state is not exportable: {message}")
            }
            Self::Integrity(message) => write!(formatter, "M5 export integrity failure: {message}"),
            Self::ResourceBound(message) => write!(formatter, "M5 export bound: {message}"),
            Self::Serialization(message) => {
                write!(formatter, "M5 export serialization failure: {message}")
            }
        }
    }
}

impl Error for M5ExportError {}
