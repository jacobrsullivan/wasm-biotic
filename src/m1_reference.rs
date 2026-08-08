//! Durable orchestration for the bounded M1 reference lifecycle.
//!
//! This module composes three narrower services:
//!
//! - [`crate::candidate`] owns the fixed-interface source workspace and build;
//! - [`crate::m1_validation`] derives typed proving and comparison evidence; and
//! - [`crate::deployment`] owns exact activation, observation, and rollback
//!   effects.
//!
//! The orchestrator adds a write-ahead, atomically replaced lineage record.
//! Every effectful stage persists its exact intent before invoking a service.
//! Reopening the same root completes pending intent idempotently, then verifies
//! that the candidate workspace, package files, deployment state, approval
//! references, and all SHA-256 identities agree.

use crate::candidate::{
    COMPONENT_WAT_PATH, COMPONENT_WIT_PATH, CandidateBuild, CandidateFileReplacement,
    CandidateWorkspaceError, CandidateWorkspaceService, CandidateWorkspaceSnapshot,
    MaterializedCandidatePatchset, ReconstructableFileReplacement, reference_task_execution_limits,
};
use crate::deployment::{
    ActivationRecord, ActivationRequest, DeploymentError, InitializationRecord,
    LocalDeploymentService, ObservationOutcome, ObservationRecord, ObservationRequest,
    RollbackRecord, RollbackRequest,
};
use crate::execution::artifact::{ArtifactError, ContentDigest, digest_json_content};
use crate::m1_validation::{
    ComparisonRecord, ProvingRecord, ValidationCase, ValidationError, ValidationSuite,
    compare_proving_records, prove_component_i32, validate_comparison_record,
    validate_proving_record,
};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub const REFERENCE_LINEAGE_SCHEMA_VERSION: u32 = 2;
pub const REFERENCE_COMPARISON_SUITE_ID: &str = "m1-reference-transform-increment-v1";
pub const REFERENCE_INCUMBENT_SUITE_ID: &str = "m1-reference-transform-identity-v1";

const LINEAGE_FILE_NAME: &str = "m1-reference-lineage.json";
const CANDIDATE_SERVICE_DIRECTORY: &str = "candidate-service";
const PACKAGE_DIRECTORY: &str = "packages";
const DEPLOYMENT_DIRECTORY: &str = "deployment";
const INCUMBENT_WORKSPACE_ID: &str = "m1-incumbent";
const CHALLENGER_WORKSPACE_ID: &str = "m1-challenger";
const INITIALIZATION_OPERATION_ID: &str = "m1-initialize-incumbent";
const ACTIVATION_OPERATION_ID: &str = "m1-activate-challenger";
const OBSERVATION_OPERATION_ID: &str = "m1-observe-challenger";
const ROLLBACK_OPERATION_ID: &str = "m1-rollback-challenger";
const OBSERVATION_WINDOW_REF: &str = "observation-window:m1-reference-bounded";
const ACTIVE_EVIDENCE_SCHEMA: &str = "wasm-biotic.m1-active-observation.v1";

static TEMP_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageRecord {
    pub relative_path: PathBuf,
    pub digest: ContentDigest,
    pub byte_len: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuiltArtifactLineage {
    pub build: CandidateBuild,
    pub package: PackageRecord,
    pub proving: ProvingRecord,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IncumbentLineage {
    pub initialization: InitializationRecord,
    pub artifact: BuiltArtifactLineage,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengerLineage {
    pub patchset: MaterializedCandidatePatchset,
    pub artifact: BuiltArtifactLineage,
    pub comparison: ComparisonRecord,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengerWorkspaceLineage {
    pub snapshot: CandidateWorkspaceSnapshot,
    pub snapshot_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengerPackageLineage {
    pub build: CandidateBuild,
    pub package: PackageRecord,
    pub record_digest: ContentDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    Approve,
    Reject,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Approved,
    Rejected,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRecord {
    pub approval_id: String,
    pub status: ApprovalStatus,
    pub comparison_digest: ContentDigest,
    pub incumbent_component_digest: ContentDigest,
    pub challenger_component_digest: ContentDigest,
    pub rationale: String,
    pub record_digest: ContentDigest,
    pub approval_ref: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveBehaviorEvidence {
    pub schema: String,
    pub activation_id: String,
    pub active_component_digest: ContentDigest,
    pub proving: ProvingRecord,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveObservationLineage {
    pub deployment: ObservationRecord,
    pub evidence: ActiveBehaviorEvidence,
    pub record_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackVerification {
    pub deployment: RollbackRecord,
    pub proving: ProvingRecord,
    pub record_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingCandidate {
    pub workspace_id: String,
    pub base_workspace: CandidateWorkspaceSnapshot,
    pub base_wat_bytes: Vec<u8>,
    pub replacement_bytes: Vec<u8>,
    pub replacement_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingRollback {
    pub reason_ref: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceLineage {
    pub schema_version: u32,
    pub comparison_suite: ValidationSuite,
    pub incumbent_verification_suite: ValidationSuite,
    pub pending_initialization: bool,
    pub pending_candidate: Option<PendingCandidate>,
    pub pending_activation: bool,
    pub pending_observation: bool,
    pub pending_rollback: Option<PendingRollback>,
    pub incumbent: Option<IncumbentLineage>,
    #[serde(default)]
    pub challenger_workspace: Option<ChallengerWorkspaceLineage>,
    #[serde(default)]
    pub challenger_patchset: Option<MaterializedCandidatePatchset>,
    #[serde(default)]
    pub challenger_package: Option<ChallengerPackageLineage>,
    #[serde(default)]
    pub challenger_proving: Option<ProvingRecord>,
    #[serde(default)]
    pub challenger_comparison: Option<ComparisonRecord>,
    pub challenger: Option<ChallengerLineage>,
    pub approval: Option<ApprovalRecord>,
    pub activation: Option<ActivationRecord>,
    pub active_observation: Option<ActiveObservationLineage>,
    pub rollback: Option<RollbackVerification>,
    pub lineage_digest: ContentDigest,
}

impl ReferenceLineage {
    fn empty() -> Result<Self, ReferenceLifecycleError> {
        let mut lineage = Self {
            schema_version: REFERENCE_LINEAGE_SCHEMA_VERSION,
            comparison_suite: reference_comparison_suite()?,
            incumbent_verification_suite: reference_incumbent_suite()?,
            pending_initialization: false,
            pending_candidate: None,
            pending_activation: false,
            pending_observation: false,
            pending_rollback: None,
            incumbent: None,
            challenger_workspace: None,
            challenger_patchset: None,
            challenger_package: None,
            challenger_proving: None,
            challenger_comparison: None,
            challenger: None,
            approval: None,
            activation: None,
            active_observation: None,
            rollback: None,
            lineage_digest: ContentDigest::from_bytes(b"uninitialized reference lineage"),
        };
        lineage.refresh_digest()?;
        Ok(lineage)
    }

    fn refresh_digest(&mut self) -> Result<(), ReferenceLifecycleError> {
        self.lineage_digest = lineage_digest(self)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct M1ReferenceService {
    root: PathBuf,
    template_root: PathBuf,
    package_root: PathBuf,
    candidate: CandidateWorkspaceService,
    deployment: LocalDeploymentService,
}

impl M1ReferenceService {
    pub fn open(
        root: impl AsRef<Path>,
        template_root: impl AsRef<Path>,
    ) -> Result<Self, ReferenceLifecycleError> {
        let root = create_and_canonicalize_directory(root.as_ref(), "reference lifecycle root")?;
        let template_root =
            canonicalize_existing_directory(template_root.as_ref(), "reference template root")?;
        validate_template_files(&template_root)?;

        let package_root = create_owned_child_directory(&root, PACKAGE_DIRECTORY, "package root")?;
        let candidate =
            CandidateWorkspaceService::bootstrap(root.join(CANDIDATE_SERVICE_DIRECTORY))?;
        let deployment =
            LocalDeploymentService::open(root.join(DEPLOYMENT_DIRECTORY), &package_root)?;
        let service = Self {
            root,
            template_root,
            package_root,
            candidate,
            deployment,
        };
        if !service.lineage_path().exists() {
            service.write_lineage(&ReferenceLineage::empty()?)?;
        }
        service.recover_pending()?;
        service.verify()?;
        Ok(service)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn package_root(&self) -> &Path {
        &self.package_root
    }

    pub fn active_artifact_path(&self) -> PathBuf {
        self.deployment.active_artifact_path()
    }

    pub fn state(&self) -> Result<ReferenceLineage, ReferenceLifecycleError> {
        self.verify()?;
        self.read_lineage()
    }

    pub fn initialize_incumbent(&self) -> Result<IncumbentLineage, ReferenceLifecycleError> {
        let mut lineage = self.read_lineage()?;
        if let Some(incumbent) = &lineage.incumbent {
            return Ok(incumbent.clone());
        }
        if !lineage.pending_initialization {
            lineage.pending_initialization = true;
            self.write_lineage(&lineage)?;
        }
        let mut lineage = self.read_lineage()?;
        self.complete_initialization(&mut lineage)?;
        self.write_lineage(&lineage)?;
        self.verify()?;
        lineage.incumbent.ok_or_else(|| {
            ReferenceLifecycleError::Invariant(
                "initialization completed without incumbent lineage".to_string(),
            )
        })
    }

    pub fn open_challenger_workspace(
        &self,
        workspace_id: &str,
    ) -> Result<ChallengerWorkspaceLineage, ReferenceLifecycleError> {
        validate_text("workspace_id", workspace_id)?;
        let mut lineage = self.read_lineage()?;
        require_incumbent(&lineage)?;
        if let Some(existing) = &lineage.challenger_workspace {
            if existing.snapshot.workspace_id == workspace_id {
                self.inspect_challenger_workspace(workspace_id)?;
                return Ok(existing.clone());
            }
            return Err(ReferenceLifecycleError::Conflict(
                "a different challenger workspace is already recorded".to_string(),
            ));
        }
        ensure_candidate_construction_open(&lineage)?;
        if lineage.pending_candidate.is_some()
            || lineage.challenger_patchset.is_some()
            || lineage.challenger_package.is_some()
            || lineage.challenger_proving.is_some()
            || lineage.challenger_comparison.is_some()
            || lineage.challenger.is_some()
        {
            return Err(ReferenceLifecycleError::Invariant(
                "later challenger evidence exists without a workspace boundary".to_string(),
            ));
        }
        let snapshot = self.ensure_template_workspace(workspace_id)?;
        let record = challenger_workspace_lineage(snapshot)?;
        lineage.challenger_workspace = Some(record.clone());
        self.write_lineage(&lineage)?;
        self.verify()?;
        Ok(record)
    }

    pub fn inspect_challenger_workspace(
        &self,
        workspace_id: &str,
    ) -> Result<CandidateWorkspaceSnapshot, ReferenceLifecycleError> {
        validate_text("workspace_id", workspace_id)?;
        let lineage = self.read_lineage()?;
        let opened = require_challenger_workspace(&lineage)?;
        if opened.snapshot.workspace_id != workspace_id {
            return Err(ReferenceLifecycleError::Conflict(
                "workspace id does not match the durable challenger workspace".to_string(),
            ));
        }
        let actual = self.candidate.snapshot(workspace_id)?;
        let expected = lineage
            .challenger_patchset
            .as_ref()
            .map(|patchset| &patchset.after)
            .unwrap_or(&opened.snapshot);
        if &actual != expected {
            return Err(ReferenceLifecycleError::Invariant(
                "challenger workspace bytes differ from the latest durable boundary".to_string(),
            ));
        }
        Ok(actual)
    }

    pub fn materialize_challenger_wat(
        &self,
        workspace_id: &str,
        expected_before_digest: &ContentDigest,
        replacement_wat_bytes: &[u8],
    ) -> Result<MaterializedCandidatePatchset, ReferenceLifecycleError> {
        if replacement_wat_bytes.is_empty() {
            return Err(ReferenceLifecycleError::InvalidInput(
                "challenger WAT bytes must not be empty".to_string(),
            ));
        }
        let replacement_digest = ContentDigest::from_bytes(replacement_wat_bytes);
        let mut lineage = self.read_lineage()?;
        let opened = require_challenger_workspace(&lineage)?;
        if opened.snapshot.workspace_id != workspace_id {
            return Err(ReferenceLifecycleError::Conflict(
                "workspace id does not match the opened challenger workspace".to_string(),
            ));
        }
        if let Some(existing) = &lineage.challenger_patchset {
            let change = existing.changes.first().ok_or_else(|| {
                ReferenceLifecycleError::Invariant(
                    "recorded challenger patchset has no change".to_string(),
                )
            })?;
            if change.before_digest == *expected_before_digest
                && change.after_digest == replacement_digest
                && change.after_bytes == replacement_wat_bytes
            {
                self.verify()?;
                return Ok(existing.clone());
            }
            return Err(ReferenceLifecycleError::Conflict(
                "a different challenger patchset is already recorded".to_string(),
            ));
        }
        ensure_candidate_construction_open(&lineage)?;
        if lineage.challenger_package.is_some()
            || lineage.challenger_proving.is_some()
            || lineage.challenger_comparison.is_some()
            || lineage.challenger.is_some()
        {
            return Err(ReferenceLifecycleError::Invariant(
                "later challenger evidence exists before materialization".to_string(),
            ));
        }
        let base_entry = opened.snapshot.entry(COMPONENT_WAT_PATH).ok_or_else(|| {
            ReferenceLifecycleError::Invariant(
                "opened challenger snapshot has no component.wat".to_string(),
            )
        })?;
        if base_entry.content_digest != *expected_before_digest {
            return Err(ReferenceLifecycleError::Conflict(format!(
                "expected base digest {expected_before_digest} does not match opened workspace {}",
                base_entry.content_digest
            )));
        }
        if let Some(pending) = &lineage.pending_candidate {
            if pending.workspace_id != workspace_id
                || pending
                    .base_workspace
                    .entry(COMPONENT_WAT_PATH)
                    .map(|entry| &entry.content_digest)
                    != Some(expected_before_digest)
            {
                return Err(ReferenceLifecycleError::Conflict(
                    "pending materialization is bound to a different workspace base".to_string(),
                ));
            }
            if pending.replacement_digest != replacement_digest
                || pending.replacement_bytes != replacement_wat_bytes
            {
                return Err(ReferenceLifecycleError::Conflict(
                    "a different challenger mutation is already pending".to_string(),
                ));
            }
        } else {
            let inspected = self.inspect_challenger_workspace(workspace_id)?;
            if inspected != opened.snapshot {
                return Err(ReferenceLifecycleError::Invariant(
                    "challenger workspace changed before materialization".to_string(),
                ));
            }
            let base_wat_bytes = self.read_workspace_wat(workspace_id)?;
            if ContentDigest::from_bytes(&base_wat_bytes) != *expected_before_digest {
                return Err(ReferenceLifecycleError::Invariant(
                    "workspace bytes do not match expected materialization base".to_string(),
                ));
            }
            lineage.pending_candidate = Some(PendingCandidate {
                workspace_id: workspace_id.to_string(),
                base_workspace: opened.snapshot.clone(),
                base_wat_bytes,
                replacement_bytes: replacement_wat_bytes.to_vec(),
                replacement_digest,
            });
            self.write_lineage(&lineage)?;
        }

        let mut lineage = self.read_lineage()?;
        match self.complete_materialization(&mut lineage) {
            Ok(()) => {
                self.write_lineage(&lineage)?;
                self.verify()?;
                lineage.challenger_patchset.ok_or_else(|| {
                    ReferenceLifecycleError::Invariant(
                        "materialization completed without patchset lineage".to_string(),
                    )
                })
            }
            Err(error) => {
                let cleanup = self.restore_pending_candidate(&mut lineage);
                if cleanup.is_ok() {
                    self.write_lineage(&lineage)?;
                }
                Err(match cleanup {
                    Ok(()) => error,
                    Err(cleanup_error) => ReferenceLifecycleError::Invariant(format!(
                        "candidate failed ({error}); workspace cleanup also failed ({cleanup_error})"
                    )),
                })
            }
        }
    }

    pub fn package_challenger(
        &self,
        workspace_id: &str,
        expected_source_tree_digest: &ContentDigest,
    ) -> Result<ChallengerPackageLineage, ReferenceLifecycleError> {
        let mut lineage = self.read_lineage()?;
        let patchset = require_challenger_patchset(&lineage)?;
        if patchset.workspace_id != workspace_id {
            return Err(ReferenceLifecycleError::Conflict(
                "workspace id does not match the materialized challenger".to_string(),
            ));
        }
        if patchset.after.tree_digest != *expected_source_tree_digest {
            return Err(ReferenceLifecycleError::Conflict(
                "expected source-tree digest does not match materialized bytes".to_string(),
            ));
        }
        if let Some(existing) = &lineage.challenger_package {
            if existing.build.workspace.workspace_id == workspace_id
                && existing.build.source_tree_digest == *expected_source_tree_digest
            {
                self.verify()?;
                return Ok(existing.clone());
            }
            return Err(ReferenceLifecycleError::Conflict(
                "a different challenger package is already recorded".to_string(),
            ));
        }
        ensure_candidate_construction_open(&lineage)?;
        if lineage.challenger_proving.is_some()
            || lineage.challenger_comparison.is_some()
            || lineage.challenger.is_some()
        {
            return Err(ReferenceLifecycleError::Invariant(
                "later challenger evidence exists before packaging".to_string(),
            ));
        }
        if self.inspect_challenger_workspace(workspace_id)? != patchset.after {
            return Err(ReferenceLifecycleError::Invariant(
                "workspace differs from the patchset selected for packaging".to_string(),
            ));
        }
        let build = self.candidate.build_candidate(workspace_id)?;
        if build.source_tree_digest != *expected_source_tree_digest
            || build.workspace != patchset.after
        {
            return Err(ReferenceLifecycleError::Invariant(
                "candidate build consumed a different source tree".to_string(),
            ));
        }
        let package = self.persist_package(&build.component.component_bytes)?;
        let record_digest = challenger_package_digest(&build, &package)?;
        let record = ChallengerPackageLineage {
            build,
            package,
            record_digest,
        };
        lineage.challenger_package = Some(record.clone());
        self.write_lineage(&lineage)?;
        self.verify()?;
        Ok(record)
    }

    pub fn prove_challenger(
        &self,
        package_digest: &ContentDigest,
        expected_source_tree_digest: &ContentDigest,
    ) -> Result<ProvingRecord, ReferenceLifecycleError> {
        let mut lineage = self.read_lineage()?;
        let package = require_challenger_package(&lineage)?;
        if package.package.digest != *package_digest
            || package.build.source_tree_digest != *expected_source_tree_digest
        {
            return Err(ReferenceLifecycleError::Conflict(
                "proving request is not bound to the recorded package and source tree".to_string(),
            ));
        }
        if let Some(existing) = &lineage.challenger_proving {
            if existing.component_digest == *package_digest {
                self.verify()?;
                return Ok(existing.clone());
            }
            return Err(ReferenceLifecycleError::Conflict(
                "a different challenger proving record is already persisted".to_string(),
            ));
        }
        ensure_candidate_construction_open(&lineage)?;
        if lineage.challenger_comparison.is_some() || lineage.challenger.is_some() {
            return Err(ReferenceLifecycleError::Invariant(
                "comparison evidence exists before challenger proving".to_string(),
            ));
        }
        let bytes = self.verify_package(&package.package)?;
        if bytes != package.build.component.component_bytes {
            return Err(ReferenceLifecycleError::Invariant(
                "packaged bytes differ from the recorded candidate build".to_string(),
            ));
        }
        let proving = prove_component_i32(&lineage.comparison_suite, &bytes)?;
        if proving.component_digest != *package_digest {
            return Err(ReferenceLifecycleError::Invariant(
                "proving executed bytes other than the selected package".to_string(),
            ));
        }
        lineage.challenger_proving = Some(proving.clone());
        self.write_lineage(&lineage)?;
        self.verify()?;
        Ok(proving)
    }

    pub fn compare_challenger(
        &self,
        incumbent_proving_report_digest: &ContentDigest,
        challenger_proving_report_digest: &ContentDigest,
    ) -> Result<ComparisonRecord, ReferenceLifecycleError> {
        let mut lineage = self.read_lineage()?;
        let incumbent = require_incumbent(&lineage)?;
        let proving = require_challenger_proving(&lineage)?;
        if incumbent.artifact.proving.record_digest != *incumbent_proving_report_digest
            || proving.record_digest != *challenger_proving_report_digest
        {
            return Err(ReferenceLifecycleError::Conflict(
                "comparison request is not bound to both persisted proving reports".to_string(),
            ));
        }
        if let Some(existing) = &lineage.challenger_comparison {
            self.verify()?;
            return Ok(existing.clone());
        }
        ensure_candidate_construction_open(&lineage)?;
        if lineage.challenger.is_some() {
            return Err(ReferenceLifecycleError::Invariant(
                "composite challenger exists before comparison boundary".to_string(),
            ));
        }
        let comparison = compare_proving_records(
            &lineage.comparison_suite,
            &incumbent.artifact.proving,
            proving,
        )?;
        let patchset = require_challenger_patchset(&lineage)?.clone();
        let package = require_challenger_package(&lineage)?.clone();
        let artifact = BuiltArtifactLineage {
            build: package.build,
            package: package.package,
            proving: proving.clone(),
        };
        lineage.challenger_comparison = Some(comparison.clone());
        lineage.challenger = Some(ChallengerLineage {
            patchset,
            artifact,
            comparison: comparison.clone(),
        });
        self.write_lineage(&lineage)?;
        self.verify()?;
        Ok(comparison)
    }

    pub fn prepare_challenger(
        &self,
        replacement_wat_bytes: &[u8],
    ) -> Result<ChallengerLineage, ReferenceLifecycleError> {
        if replacement_wat_bytes.is_empty() {
            return Err(ReferenceLifecycleError::InvalidInput(
                "challenger WAT bytes must not be empty".to_string(),
            ));
        }
        let before = self.read_lineage()?;
        let cleanup_allowed = before.pending_candidate.is_none()
            && before.challenger_patchset.is_none()
            && before.challenger_package.is_none()
            && before.challenger_proving.is_none()
            && before.challenger_comparison.is_none()
            && before.challenger.is_none();
        let result = (|| {
            let workspace = self.open_challenger_workspace(CHALLENGER_WORKSPACE_ID)?;
            let expected_before_digest = workspace
                .snapshot
                .entry(COMPONENT_WAT_PATH)
                .ok_or_else(|| {
                    ReferenceLifecycleError::Invariant(
                        "opened challenger snapshot has no component.wat".to_string(),
                    )
                })?
                .content_digest
                .clone();
            let patchset = self.materialize_challenger_wat(
                CHALLENGER_WORKSPACE_ID,
                &expected_before_digest,
                replacement_wat_bytes,
            )?;
            let package =
                self.package_challenger(CHALLENGER_WORKSPACE_ID, &patchset.after.tree_digest)?;
            let proving =
                self.prove_challenger(&package.package.digest, &package.build.source_tree_digest)?;
            let incumbent_digest = self
                .read_lineage()?
                .incumbent
                .ok_or_else(|| {
                    ReferenceLifecycleError::Invariant(
                        "incumbent disappeared during candidate preparation".to_string(),
                    )
                })?
                .artifact
                .proving
                .record_digest;
            self.compare_challenger(&incumbent_digest, &proving.record_digest)?;
            require_challenger(&self.read_lineage()?).cloned()
        })();
        match result {
            Ok(challenger) => Ok(challenger),
            Err(error) if cleanup_allowed => {
                let cleanup = self.cleanup_failed_composed_challenger();
                Err(match cleanup {
                    Ok(()) => error,
                    Err(cleanup_error) => ReferenceLifecycleError::Invariant(format!(
                        "candidate preparation failed ({error}); cleanup also failed ({cleanup_error})"
                    )),
                })
            }
            Err(error) => Err(error),
        }
    }

    pub fn record_approval(
        &self,
        approval_id: &str,
        decision: ApprovalDecision,
        rationale: &str,
    ) -> Result<ApprovalRecord, ReferenceLifecycleError> {
        validate_text("approval_id", approval_id)?;
        validate_text("rationale", rationale)?;
        let mut lineage = self.read_lineage()?;
        let challenger = require_challenger(&lineage)?;
        let proposed = build_approval_record(approval_id, decision, rationale, challenger)?;
        if let Some(existing) = &lineage.approval {
            if existing == &proposed {
                return Ok(existing.clone());
            }
            return Err(ReferenceLifecycleError::Conflict(
                "an approval decision is already bound to this comparison".to_string(),
            ));
        }
        if lineage.pending_activation
            || lineage.activation.is_some()
            || lineage.active_observation.is_some()
            || lineage.rollback.is_some()
        {
            return Err(ReferenceLifecycleError::InvalidTransition(
                "approval cannot change after activation begins".to_string(),
            ));
        }
        lineage.approval = Some(proposed.clone());
        self.write_lineage(&lineage)?;
        self.verify()?;
        Ok(proposed)
    }

    pub fn activate_approved(&self) -> Result<ActivationRecord, ReferenceLifecycleError> {
        let mut lineage = self.read_lineage()?;
        if let Some(activation) = &lineage.activation {
            return Ok(activation.clone());
        }
        require_approved(&lineage)?;
        if !lineage.pending_activation {
            lineage.pending_activation = true;
            self.write_lineage(&lineage)?;
        }
        let mut lineage = self.read_lineage()?;
        self.complete_activation(&mut lineage)?;
        self.write_lineage(&lineage)?;
        self.verify()?;
        lineage.activation.ok_or_else(|| {
            ReferenceLifecycleError::Invariant(
                "activation completed without activation lineage".to_string(),
            )
        })
    }

    pub fn observe_active(&self) -> Result<ActiveObservationLineage, ReferenceLifecycleError> {
        let mut lineage = self.read_lineage()?;
        if let Some(observation) = &lineage.active_observation {
            return Ok(observation.clone());
        }
        require_activation(&lineage)?;
        if lineage.rollback.is_some() || lineage.pending_rollback.is_some() {
            return Err(ReferenceLifecycleError::InvalidTransition(
                "active observation cannot begin after rollback".to_string(),
            ));
        }
        if !lineage.pending_observation {
            lineage.pending_observation = true;
            self.write_lineage(&lineage)?;
        }
        let mut lineage = self.read_lineage()?;
        self.complete_observation(&mut lineage)?;
        self.write_lineage(&lineage)?;
        self.verify()?;
        lineage.active_observation.ok_or_else(|| {
            ReferenceLifecycleError::Invariant(
                "observation completed without observation lineage".to_string(),
            )
        })
    }

    pub fn rollback_and_verify(
        &self,
        reason_ref: &str,
    ) -> Result<RollbackVerification, ReferenceLifecycleError> {
        validate_text("reason_ref", reason_ref)?;
        let mut lineage = self.read_lineage()?;
        if let Some(rollback) = &lineage.rollback {
            if rollback.deployment.reason_ref == reason_ref {
                return Ok(rollback.clone());
            }
            return Err(ReferenceLifecycleError::Conflict(
                "rollback already completed with a different reason".to_string(),
            ));
        }
        require_observation(&lineage)?;
        match &lineage.pending_rollback {
            Some(pending) if pending.reason_ref != reason_ref => {
                return Err(ReferenceLifecycleError::Conflict(
                    "rollback is pending with a different reason".to_string(),
                ));
            }
            Some(_) => {}
            None => {
                lineage.pending_rollback = Some(PendingRollback {
                    reason_ref: reason_ref.to_string(),
                });
                self.write_lineage(&lineage)?;
            }
        }
        let mut lineage = self.read_lineage()?;
        self.complete_rollback(&mut lineage)?;
        self.write_lineage(&lineage)?;
        self.verify()?;
        lineage.rollback.ok_or_else(|| {
            ReferenceLifecycleError::Invariant(
                "rollback completed without verification lineage".to_string(),
            )
        })
    }

    fn recover_pending(&self) -> Result<(), ReferenceLifecycleError> {
        let mut lineage = self.read_lineage()?;
        let mut changed = false;
        if lineage.pending_initialization {
            self.complete_initialization(&mut lineage)?;
            changed = true;
        }
        if lineage.pending_candidate.is_some() {
            match self.complete_materialization(&mut lineage) {
                Ok(()) => changed = true,
                Err(error) => {
                    self.restore_pending_candidate(&mut lineage)?;
                    self.write_lineage(&lineage)?;
                    return Err(error);
                }
            }
        }
        if lineage.pending_activation {
            self.complete_activation(&mut lineage)?;
            changed = true;
        }
        if lineage.pending_observation {
            self.complete_observation(&mut lineage)?;
            changed = true;
        }
        if lineage.pending_rollback.is_some() {
            self.complete_rollback(&mut lineage)?;
            changed = true;
        }
        if changed {
            self.write_lineage(&lineage)?;
        }
        Ok(())
    }

    fn complete_initialization(
        &self,
        lineage: &mut ReferenceLineage,
    ) -> Result<(), ReferenceLifecycleError> {
        if lineage.incumbent.is_some() {
            lineage.pending_initialization = false;
            return Ok(());
        }
        if !lineage.pending_initialization {
            return Err(ReferenceLifecycleError::InvalidTransition(
                "incumbent initialization has no durable intent".to_string(),
            ));
        }
        let workspace = self.ensure_template_workspace(INCUMBENT_WORKSPACE_ID)?;
        self.ensure_workspace_matches_template(&workspace)?;
        let build = self.candidate.build_candidate(INCUMBENT_WORKSPACE_ID)?;
        let package = self.persist_package(&build.component.component_bytes)?;
        let proving =
            prove_component_i32(&lineage.comparison_suite, &build.component.component_bytes)?;
        let initialization = self.deployment.initialize_active(
            INITIALIZATION_OPERATION_ID,
            &build.component.component_bytes,
        )?;
        if initialization.installed_artifact.digest != build.package_digest {
            return Err(ReferenceLifecycleError::Invariant(
                "deployment initialized bytes other than the built incumbent".to_string(),
            ));
        }
        lineage.incumbent = Some(IncumbentLineage {
            initialization,
            artifact: BuiltArtifactLineage {
                build,
                package,
                proving,
            },
        });
        lineage.pending_initialization = false;
        Ok(())
    }

    fn complete_materialization(
        &self,
        lineage: &mut ReferenceLineage,
    ) -> Result<(), ReferenceLifecycleError> {
        if lineage.challenger_patchset.is_some() {
            lineage.pending_candidate = None;
            return Ok(());
        }
        require_challenger_workspace(lineage)?;
        let pending = lineage.pending_candidate.clone().ok_or_else(|| {
            ReferenceLifecycleError::InvalidTransition(
                "candidate materialization has no durable intent".to_string(),
            )
        })?;
        let current = self.candidate.snapshot(&pending.workspace_id)?;
        let current_wat = current.entry(COMPONENT_WAT_PATH).ok_or_else(|| {
            ReferenceLifecycleError::Invariant(
                "candidate workspace has no component.wat entry".to_string(),
            )
        })?;
        let patchset = if current_wat.content_digest
            == ContentDigest::from_bytes(&pending.base_wat_bytes)
        {
            self.candidate.materialize_patchset(
                &pending.workspace_id,
                &[CandidateFileReplacement::new(
                    COMPONENT_WAT_PATH,
                    current_wat.content_digest.clone(),
                    pending.replacement_bytes.clone(),
                )],
            )?
        } else if current_wat.content_digest == pending.replacement_digest {
            self.reconstruct_pending_patchset(&pending, &current)?
        } else {
            return Err(ReferenceLifecycleError::Invariant(
                "pending candidate workspace contains neither base nor intended bytes".to_string(),
            ));
        };
        lineage.challenger_patchset = Some(patchset);
        lineage.pending_candidate = None;
        Ok(())
    }

    fn complete_activation(
        &self,
        lineage: &mut ReferenceLineage,
    ) -> Result<(), ReferenceLifecycleError> {
        if lineage.activation.is_some() {
            lineage.pending_activation = false;
            return Ok(());
        }
        if !lineage.pending_activation {
            return Err(ReferenceLifecycleError::InvalidTransition(
                "activation has no durable intent".to_string(),
            ));
        }
        let approval = require_approved(lineage)?.clone();
        let incumbent = require_incumbent(lineage)?.clone();
        let challenger = require_challenger(lineage)?.clone();
        self.verify_package(&challenger.artifact.package)?;
        let request = ActivationRequest {
            operation_id: ACTIVATION_OPERATION_ID.to_string(),
            candidate_path: challenger.artifact.package.relative_path.clone(),
            expected_candidate_digest: challenger.artifact.package.digest.clone(),
            expected_active_digest: incumbent.artifact.package.digest.clone(),
            approval_ref: approval.approval_ref,
            comparison_ref: comparison_ref(&challenger.comparison),
            observation_window_ref: OBSERVATION_WINDOW_REF.to_string(),
        };
        let activation = self.deployment.activate(&request)?;
        if !activation_matches_lineage(&activation, &request) {
            return Err(ReferenceLifecycleError::Invariant(
                "deployment activation is not bound to the approved comparison".to_string(),
            ));
        }
        lineage.activation = Some(activation);
        lineage.pending_activation = false;
        Ok(())
    }

    fn complete_observation(
        &self,
        lineage: &mut ReferenceLineage,
    ) -> Result<(), ReferenceLifecycleError> {
        if lineage.active_observation.is_some() {
            lineage.pending_observation = false;
            return Ok(());
        }
        if !lineage.pending_observation {
            return Err(ReferenceLifecycleError::InvalidTransition(
                "active observation has no durable intent".to_string(),
            ));
        }
        let activation = require_activation(lineage)?.clone();
        let challenger = require_challenger(lineage)?.clone();
        if let Some(existing) = self
            .deployment
            .state()?
            .observations
            .into_iter()
            .find(|record| record.observation_id == OBSERVATION_OPERATION_ID)
        {
            let evidence_bytes = self.deployment.read_blob(&existing.evidence.digest)?;
            let evidence: ActiveBehaviorEvidence = serde_json::from_slice(&evidence_bytes)
                .map_err(ReferenceLifecycleError::Serialization)?;
            let recovered = ActiveObservationLineage {
                record_digest: active_observation_digest(&existing, &evidence)?,
                deployment: existing,
                evidence,
            };
            validate_active_observation(lineage, &recovered)?;
            lineage.active_observation = Some(recovered);
            lineage.pending_observation = false;
            return Ok(());
        }
        let active_bytes = self.deployment.read_active_bytes()?;
        let active_digest = ContentDigest::from_bytes(&active_bytes);
        if active_digest != challenger.artifact.package.digest
            || active_digest != activation.activated_artifact.digest
        {
            return Err(ReferenceLifecycleError::Invariant(
                "active bytes are not the approved challenger".to_string(),
            ));
        }
        let proving = prove_component_i32(&lineage.comparison_suite, &active_bytes)?;
        let evidence = ActiveBehaviorEvidence {
            schema: ACTIVE_EVIDENCE_SCHEMA.to_string(),
            activation_id: activation.operation_id.clone(),
            active_component_digest: active_digest.clone(),
            proving,
        };
        let evidence_bytes =
            serde_json::to_vec(&evidence).map_err(ReferenceLifecycleError::Serialization)?;
        let (outcome, summary) = observation_outcome_and_summary(&evidence.proving);
        let deployment = self.deployment.record_observation(
            &ObservationRequest {
                observation_id: OBSERVATION_OPERATION_ID.to_string(),
                activation_id: activation.operation_id,
                expected_active_digest: active_digest,
                outcome,
                summary,
            },
            &evidence_bytes,
        )?;
        let record_digest = active_observation_digest(&deployment, &evidence)?;
        lineage.active_observation = Some(ActiveObservationLineage {
            deployment,
            evidence,
            record_digest,
        });
        lineage.pending_observation = false;
        Ok(())
    }

    fn complete_rollback(
        &self,
        lineage: &mut ReferenceLineage,
    ) -> Result<(), ReferenceLifecycleError> {
        if lineage.rollback.is_some() {
            lineage.pending_rollback = None;
            return Ok(());
        }
        let pending = lineage.pending_rollback.clone().ok_or_else(|| {
            ReferenceLifecycleError::InvalidTransition("rollback has no durable intent".to_string())
        })?;
        let activation = require_activation(lineage)?.clone();
        require_observation(lineage)?;
        let incumbent = require_incumbent(lineage)?.clone();
        let deployment = self.deployment.rollback(&RollbackRequest {
            operation_id: ROLLBACK_OPERATION_ID.to_string(),
            activation_id: activation.operation_id,
            reason_ref: pending.reason_ref,
        })?;
        let finalized_activation = self
            .deployment
            .state()?
            .activations
            .into_iter()
            .find(|record| record.operation_id == deployment.activation_id)
            .ok_or_else(|| {
                ReferenceLifecycleError::Invariant(
                    "deployment rollback removed its activation lineage".to_string(),
                )
            })?;
        if finalized_activation.rolled_back_by.as_deref() != Some(deployment.operation_id.as_str())
        {
            return Err(ReferenceLifecycleError::Invariant(
                "deployment activation does not name its completed rollback".to_string(),
            ));
        }
        let active_bytes = self.deployment.read_active_bytes()?;
        if ContentDigest::from_bytes(&active_bytes) != incumbent.artifact.package.digest
            || deployment.restored_artifact.digest != incumbent.artifact.package.digest
        {
            return Err(ReferenceLifecycleError::Invariant(
                "rollback did not restore the exact incumbent bytes".to_string(),
            ));
        }
        let proving = prove_component_i32(&lineage.incumbent_verification_suite, &active_bytes)?;
        if !proving.summary.all_satisfied {
            return Err(ReferenceLifecycleError::Invariant(format!(
                "restored incumbent satisfied only {}/{} identity cases",
                proving.summary.satisfied_count, proving.summary.case_count
            )));
        }
        let record_digest = rollback_verification_digest(&deployment, &proving)?;
        lineage.rollback = Some(RollbackVerification {
            deployment,
            proving,
            record_digest,
        });
        lineage.activation = Some(finalized_activation);
        lineage.pending_rollback = None;
        Ok(())
    }

    fn restore_pending_candidate(
        &self,
        lineage: &mut ReferenceLineage,
    ) -> Result<(), ReferenceLifecycleError> {
        let Some(pending) = lineage.pending_candidate.clone() else {
            return Ok(());
        };
        let current = self.candidate.snapshot(&pending.workspace_id)?;
        let current_wat = current.entry(COMPONENT_WAT_PATH).ok_or_else(|| {
            ReferenceLifecycleError::Invariant(
                "pending candidate workspace has no component.wat".to_string(),
            )
        })?;
        let base_digest = ContentDigest::from_bytes(&pending.base_wat_bytes);
        if current_wat.content_digest == pending.replacement_digest {
            self.candidate.materialize_patchset(
                &pending.workspace_id,
                &[CandidateFileReplacement::new(
                    COMPONENT_WAT_PATH,
                    pending.replacement_digest.clone(),
                    pending.base_wat_bytes,
                )],
            )?;
        } else if current_wat.content_digest != base_digest {
            return Err(ReferenceLifecycleError::Invariant(
                "cannot restore candidate workspace from unexpected bytes".to_string(),
            ));
        }
        lineage.pending_candidate = None;
        Ok(())
    }

    fn cleanup_failed_composed_challenger(&self) -> Result<(), ReferenceLifecycleError> {
        let mut lineage = self.read_lineage()?;
        if lineage.challenger.is_some()
            || lineage.approval.is_some()
            || lineage.activation.is_some()
        {
            return Ok(());
        }
        if lineage.pending_candidate.is_some() {
            self.restore_pending_candidate(&mut lineage)?;
        } else if let Some(patchset) = &lineage.challenger_patchset {
            let change = patchset.changes.first().ok_or_else(|| {
                ReferenceLifecycleError::Invariant(
                    "cannot restore a challenger patchset without its change".to_string(),
                )
            })?;
            let current = self.candidate.snapshot(&patchset.workspace_id)?;
            let current_wat = current.entry(COMPONENT_WAT_PATH).ok_or_else(|| {
                ReferenceLifecycleError::Invariant(
                    "candidate workspace has no component.wat during cleanup".to_string(),
                )
            })?;
            if current_wat.content_digest == change.after_digest {
                self.candidate.materialize_patchset(
                    &patchset.workspace_id,
                    &[CandidateFileReplacement::new(
                        COMPONENT_WAT_PATH,
                        change.after_digest.clone(),
                        change.before_bytes.clone(),
                    )],
                )?;
            } else if current_wat.content_digest != change.before_digest {
                return Err(ReferenceLifecycleError::Invariant(
                    "cannot clean up challenger workspace from unexpected bytes".to_string(),
                ));
            }
        }
        lineage.pending_candidate = None;
        lineage.challenger_patchset = None;
        lineage.challenger_package = None;
        lineage.challenger_proving = None;
        lineage.challenger_comparison = None;
        lineage.challenger = None;
        self.write_lineage(&lineage)?;
        self.verify()
    }

    fn read_workspace_wat(&self, workspace_id: &str) -> Result<Vec<u8>, ReferenceLifecycleError> {
        let path = self
            .candidate
            .workspace_path(workspace_id)?
            .join(COMPONENT_WAT_PATH);
        reject_non_regular_file(&path, "challenger component.wat")?;
        read_file(&path)
    }

    fn reconstruct_pending_patchset(
        &self,
        pending: &PendingCandidate,
        after: &CandidateWorkspaceSnapshot,
    ) -> Result<MaterializedCandidatePatchset, ReferenceLifecycleError> {
        let before_digest = ContentDigest::from_bytes(&pending.base_wat_bytes);
        if pending
            .base_workspace
            .entry(COMPONENT_WAT_PATH)
            .map(|entry| &entry.content_digest)
            != Some(&before_digest)
        {
            return Err(ReferenceLifecycleError::Invariant(
                "pending base snapshot does not match retained base bytes".to_string(),
            ));
        }
        let change = ReconstructableFileReplacement {
            relative_path: COMPONENT_WAT_PATH.to_string(),
            before_digest,
            after_digest: pending.replacement_digest.clone(),
            before_bytes: pending.base_wat_bytes.clone(),
            after_bytes: pending.replacement_bytes.clone(),
        };
        let patchset_digest = digest_json_content(&(
            pending.workspace_id.as_str(),
            &pending.base_workspace.tree_digest,
            &after.tree_digest,
            std::slice::from_ref(&change),
        ))?;
        Ok(MaterializedCandidatePatchset {
            workspace_id: pending.workspace_id.clone(),
            before: pending.base_workspace.clone(),
            after: after.clone(),
            changes: vec![change],
            patchset_digest,
        })
    }

    fn ensure_template_workspace(
        &self,
        workspace_id: &str,
    ) -> Result<CandidateWorkspaceSnapshot, ReferenceLifecycleError> {
        let snapshot = match self
            .candidate
            .open_workspace(workspace_id, &self.template_root)
        {
            Ok(snapshot) => snapshot,
            Err(CandidateWorkspaceError::WorkspaceAlreadyExists { .. }) => {
                self.candidate.snapshot(workspace_id)?
            }
            Err(error) => return Err(error.into()),
        };
        self.ensure_workspace_matches_template(&snapshot)?;
        Ok(snapshot)
    }

    fn ensure_workspace_matches_template(
        &self,
        snapshot: &CandidateWorkspaceSnapshot,
    ) -> Result<(), ReferenceLifecycleError> {
        for relative in [COMPONENT_WIT_PATH, COMPONENT_WAT_PATH] {
            let expected = ContentDigest::from_bytes(&self.read_template_file(relative)?);
            let actual = snapshot
                .entry(relative)
                .map(|entry| entry.content_digest.clone())
                .ok_or_else(|| {
                    ReferenceLifecycleError::Invariant(format!(
                        "workspace '{}' has no {relative}",
                        snapshot.workspace_id
                    ))
                })?;
            if actual != expected {
                return Err(ReferenceLifecycleError::Invariant(format!(
                    "workspace '{}' {relative} differs from the frozen template",
                    snapshot.workspace_id
                )));
            }
        }
        Ok(())
    }

    fn read_template_file(&self, relative: &str) -> Result<Vec<u8>, ReferenceLifecycleError> {
        let path = self.template_root.join(relative);
        reject_non_regular_file(&path, "reference template file")?;
        read_file(&path)
    }

    fn persist_package(&self, bytes: &[u8]) -> Result<PackageRecord, ReferenceLifecycleError> {
        if bytes.is_empty() {
            return Err(ReferenceLifecycleError::Invariant(
                "built package bytes must not be empty".to_string(),
            ));
        }
        let digest = ContentDigest::from_bytes(bytes);
        let relative_path = PathBuf::from(format!("{}.component.wasm", digest.file_stem()));
        let path = self.package_root.join(&relative_path);
        if path.exists() {
            reject_non_regular_file(&path, "candidate package")?;
            let existing = read_file(&path)?;
            if existing != bytes {
                return Err(ReferenceLifecycleError::CorruptContent {
                    role: "candidate package",
                    expected: digest,
                    actual: ContentDigest::from_bytes(&existing),
                });
            }
        } else {
            atomic_replace(&path, bytes)?;
        }
        Ok(PackageRecord {
            relative_path,
            digest,
            byte_len: bytes.len() as u64,
        })
    }

    fn verify_package(&self, package: &PackageRecord) -> Result<Vec<u8>, ReferenceLifecycleError> {
        validate_package_path(package)?;
        let path = self.package_root.join(&package.relative_path);
        reject_non_regular_file(&path, "candidate package")?;
        let bytes = read_file(&path)?;
        let actual = ContentDigest::from_bytes(&bytes);
        if actual != package.digest {
            return Err(ReferenceLifecycleError::CorruptContent {
                role: "candidate package",
                expected: package.digest.clone(),
                actual,
            });
        }
        if bytes.len() as u64 != package.byte_len {
            return Err(ReferenceLifecycleError::Invariant(
                "candidate package byte length differs from lineage".to_string(),
            ));
        }
        Ok(bytes)
    }

    fn verify(&self) -> Result<(), ReferenceLifecycleError> {
        let lineage = self.read_lineage()?;
        if lineage.pending_initialization
            || lineage.pending_candidate.is_some()
            || lineage.pending_activation
            || lineage.pending_observation
            || lineage.pending_rollback.is_some()
        {
            return Err(ReferenceLifecycleError::Invariant(
                "pending lineage remains after recovery".to_string(),
            ));
        }
        self.verify_workspace_and_packages(&lineage)?;
        self.verify_deployment_state(&lineage)
    }

    fn verify_workspace_and_packages(
        &self,
        lineage: &ReferenceLineage,
    ) -> Result<(), ReferenceLifecycleError> {
        if let Some(incumbent) = &lineage.incumbent {
            let snapshot = self.candidate.snapshot(INCUMBENT_WORKSPACE_ID)?;
            if snapshot != incumbent.artifact.build.workspace {
                return Err(ReferenceLifecycleError::Invariant(
                    "incumbent workspace differs from durable lineage".to_string(),
                ));
            }
            let bytes = self.verify_package(&incumbent.artifact.package)?;
            if bytes != incumbent.artifact.build.component.component_bytes {
                return Err(ReferenceLifecycleError::Invariant(
                    "incumbent package differs from built bytes".to_string(),
                ));
            }
        }
        if let Some(workspace) = &lineage.challenger_workspace {
            let snapshot = self.candidate.snapshot(&workspace.snapshot.workspace_id)?;
            let expected = lineage
                .challenger_patchset
                .as_ref()
                .map(|patchset| &patchset.after)
                .unwrap_or(&workspace.snapshot);
            if &snapshot != expected {
                return Err(ReferenceLifecycleError::Invariant(
                    "challenger workspace differs from durable lineage".to_string(),
                ));
            }
        }
        if let Some(package) = &lineage.challenger_package {
            let bytes = self.verify_package(&package.package)?;
            if bytes != package.build.component.component_bytes {
                return Err(ReferenceLifecycleError::Invariant(
                    "challenger package differs from built bytes".to_string(),
                ));
            }
        }
        if let Some(observation) = &lineage.active_observation {
            let bytes = self
                .deployment
                .read_blob(&observation.deployment.evidence.digest)?;
            let expected = serde_json::to_vec(&observation.evidence)
                .map_err(ReferenceLifecycleError::Serialization)?;
            if bytes != expected {
                return Err(ReferenceLifecycleError::Invariant(
                    "deployment observation evidence differs from lineage".to_string(),
                ));
            }
        }
        Ok(())
    }

    fn verify_deployment_state(
        &self,
        lineage: &ReferenceLineage,
    ) -> Result<(), ReferenceLifecycleError> {
        let deployment = self.deployment.state()?;
        let expected_initializations = lineage
            .incumbent
            .iter()
            .map(|item| item.initialization.clone())
            .collect::<Vec<_>>();
        let expected_activations = lineage.activation.iter().cloned().collect::<Vec<_>>();
        let expected_observations = lineage
            .active_observation
            .iter()
            .map(|item| item.deployment.clone())
            .collect::<Vec<_>>();
        let expected_rollbacks = lineage
            .rollback
            .iter()
            .map(|item| item.deployment.clone())
            .collect::<Vec<_>>();
        if deployment.initializations != expected_initializations
            || deployment.activations != expected_activations
            || deployment.observations != expected_observations
            || deployment.rollbacks != expected_rollbacks
            || deployment.in_flight.is_some()
        {
            return Err(ReferenceLifecycleError::Invariant(
                "deployment history contains missing, extra, or fabricated lineage".to_string(),
            ));
        }
        let expected_active = if let Some(rollback) = &lineage.rollback {
            Some(rollback.deployment.restored_artifact.clone())
        } else if let Some(activation) = &lineage.activation {
            Some(activation.activated_artifact.clone())
        } else {
            lineage
                .incumbent
                .as_ref()
                .map(|item| item.initialization.installed_artifact.clone())
        };
        if deployment.active_artifact != expected_active {
            return Err(ReferenceLifecycleError::Invariant(
                "deployment active artifact differs from lifecycle lineage".to_string(),
            ));
        }
        Ok(())
    }

    fn lineage_path(&self) -> PathBuf {
        self.root.join(LINEAGE_FILE_NAME)
    }

    fn read_lineage(&self) -> Result<ReferenceLineage, ReferenceLifecycleError> {
        let path = self.lineage_path();
        reject_non_regular_file(&path, "reference lineage")?;
        let bytes = read_file(&path)?;
        let mut lineage: ReferenceLineage =
            serde_json::from_slice(&bytes).map_err(ReferenceLifecycleError::Serialization)?;
        if lineage.schema_version == 1 {
            if lineage.challenger_workspace.is_some()
                || lineage.challenger_patchset.is_some()
                || lineage.challenger_package.is_some()
                || lineage.challenger_proving.is_some()
                || lineage.challenger_comparison.is_some()
            {
                return Err(ReferenceLifecycleError::Invariant(
                    "schema-v1 lineage contains unexpected staged challenger fields".to_string(),
                ));
            }
            if lineage.lineage_digest != legacy_lineage_digest(&lineage)? {
                return Err(ReferenceLifecycleError::Invariant(
                    "schema-v1 lineage digest does not match legacy content".to_string(),
                ));
            }
            migrate_v1_lineage(&mut lineage)?;
            self.write_lineage(&lineage)?;
            return Ok(lineage);
        }
        validate_lineage(&lineage)?;
        Ok(lineage)
    }

    fn write_lineage(&self, lineage: &ReferenceLineage) -> Result<(), ReferenceLifecycleError> {
        let mut lineage = lineage.clone();
        lineage.refresh_digest()?;
        validate_lineage(&lineage)?;
        let bytes =
            serde_json::to_vec_pretty(&lineage).map_err(ReferenceLifecycleError::Serialization)?;
        atomic_replace(&self.lineage_path(), &bytes)
    }
}

pub fn reference_comparison_suite() -> Result<ValidationSuite, ValidationError> {
    ValidationSuite::new(
        REFERENCE_COMPARISON_SUITE_ID,
        "transform",
        [(-1, 0), (0, 1), (41, 42)]
            .into_iter()
            .enumerate()
            .map(|(index, (input, output))| {
                ValidationCase::returns(format!("increment-case-{}", index + 1), input, output)
            })
            .collect(),
        reference_task_execution_limits(),
    )
}

pub fn reference_incumbent_suite() -> Result<ValidationSuite, ValidationError> {
    ValidationSuite::new(
        REFERENCE_INCUMBENT_SUITE_ID,
        "transform",
        [-1, 0, 41]
            .into_iter()
            .enumerate()
            .map(|(index, input)| {
                ValidationCase::returns(format!("identity-case-{}", index + 1), input, input)
            })
            .collect(),
        reference_task_execution_limits(),
    )
}

fn validate_lineage(lineage: &ReferenceLineage) -> Result<(), ReferenceLifecycleError> {
    if lineage.schema_version != REFERENCE_LINEAGE_SCHEMA_VERSION {
        return Err(ReferenceLifecycleError::UnsupportedSchema {
            expected: REFERENCE_LINEAGE_SCHEMA_VERSION,
            actual: lineage.schema_version,
        });
    }
    if lineage.comparison_suite != reference_comparison_suite()?
        || lineage.incumbent_verification_suite != reference_incumbent_suite()?
    {
        return Err(ReferenceLifecycleError::Invariant(
            "lineage suites differ from the bounded reference suites".to_string(),
        ));
    }
    if lineage.lineage_digest != lineage_digest(lineage)? {
        return Err(ReferenceLifecycleError::Invariant(
            "lineage digest does not match persisted content".to_string(),
        ));
    }
    validate_pending_order(lineage)?;

    if let Some(incumbent) = &lineage.incumbent {
        validate_built_artifact(
            &lineage.comparison_suite,
            &incumbent.artifact,
            INCUMBENT_WORKSPACE_ID,
        )?;
        if incumbent.initialization.operation_id != INITIALIZATION_OPERATION_ID
            || incumbent.initialization.installed_artifact.digest
                != incumbent.artifact.package.digest
            || incumbent.initialization.installed_artifact.byte_len
                != incumbent.artifact.package.byte_len
        {
            return Err(ReferenceLifecycleError::Invariant(
                "incumbent initialization is not bound to incumbent package bytes".to_string(),
            ));
        }
    }
    if let Some(workspace) = &lineage.challenger_workspace {
        let expected = challenger_workspace_lineage(workspace.snapshot.clone())?;
        if workspace != &expected || workspace.snapshot.workspace_id == INCUMBENT_WORKSPACE_ID {
            return Err(ReferenceLifecycleError::Invariant(
                "challenger workspace boundary has an invalid identity".to_string(),
            ));
        }
    }
    if let Some(patchset) = &lineage.challenger_patchset {
        validate_materialized_patchset(require_challenger_workspace(lineage)?, patchset)?;
    }
    if let Some(package) = &lineage.challenger_package {
        validate_challenger_package_stage(require_challenger_patchset(lineage)?, package)?;
    }
    if let Some(proving) = &lineage.challenger_proving {
        let package = require_challenger_package(lineage)?;
        validate_proving_record(&lineage.comparison_suite, proving)?;
        if proving.component_digest != package.package.digest {
            return Err(ReferenceLifecycleError::Invariant(
                "challenger proving is not bound to the packaged bytes".to_string(),
            ));
        }
    }
    if let Some(comparison) = &lineage.challenger_comparison {
        let incumbent = require_incumbent(lineage)?;
        let proving = require_challenger_proving(lineage)?;
        validate_comparison_record(
            &lineage.comparison_suite,
            &incumbent.artifact.proving,
            proving,
            comparison,
        )?;
    }
    if let Some(challenger) = &lineage.challenger {
        let incumbent = require_incumbent(lineage)?;
        let workspace_id = &require_challenger_workspace(lineage)?.snapshot.workspace_id;
        validate_built_artifact(
            &lineage.comparison_suite,
            &challenger.artifact,
            workspace_id,
        )?;
        validate_patchset(challenger)?;
        validate_comparison_record(
            &lineage.comparison_suite,
            &incumbent.artifact.proving,
            &challenger.artifact.proving,
            &challenger.comparison,
        )?;
        let package = require_challenger_package(lineage)?;
        if challenger.patchset != *require_challenger_patchset(lineage)?
            || challenger.artifact.build != package.build
            || challenger.artifact.package != package.package
            || challenger.artifact.proving != *require_challenger_proving(lineage)?
            || challenger.comparison
                != *lineage.challenger_comparison.as_ref().ok_or_else(|| {
                    ReferenceLifecycleError::Invariant(
                        "composite challenger has no comparison boundary".to_string(),
                    )
                })?
        {
            return Err(ReferenceLifecycleError::Invariant(
                "composite challenger differs from its persisted stage records".to_string(),
            ));
        }
    }
    if let Some(approval) = &lineage.approval {
        validate_approval(approval, require_challenger(lineage)?)?;
    }
    if let Some(activation) = &lineage.activation {
        let approval = require_approved(lineage)?;
        let incumbent = require_incumbent(lineage)?;
        let challenger = require_challenger(lineage)?;
        let request = ActivationRequest {
            operation_id: ACTIVATION_OPERATION_ID.to_string(),
            candidate_path: challenger.artifact.package.relative_path.clone(),
            expected_candidate_digest: challenger.artifact.package.digest.clone(),
            expected_active_digest: incumbent.artifact.package.digest.clone(),
            approval_ref: approval.approval_ref.clone(),
            comparison_ref: comparison_ref(&challenger.comparison),
            observation_window_ref: OBSERVATION_WINDOW_REF.to_string(),
        };
        if !activation_matches_lineage(activation, &request) {
            return Err(ReferenceLifecycleError::Invariant(
                "activation record contains fabricated approval or comparison references"
                    .to_string(),
            ));
        }
    }
    if let Some(observation) = &lineage.active_observation {
        validate_active_observation(lineage, observation)?;
    }
    if let Some(rollback) = &lineage.rollback {
        validate_rollback_verification(lineage, rollback)?;
    }
    Ok(())
}

fn validate_pending_order(lineage: &ReferenceLineage) -> Result<(), ReferenceLifecycleError> {
    if lineage.pending_initialization && lineage.incumbent.is_some() {
        return Err(ReferenceLifecycleError::Invariant(
            "completed incumbent cannot remain pending".to_string(),
        ));
    }
    if lineage.pending_candidate.is_some()
        && (lineage.incumbent.is_none()
            || lineage.challenger_workspace.is_none()
            || lineage.challenger_patchset.is_some())
    {
        return Err(ReferenceLifecycleError::Invariant(
            "pending challenger has invalid lifecycle prerequisites".to_string(),
        ));
    }
    if lineage.pending_activation
        && (lineage.approval.as_ref().map(|item| item.status) != Some(ApprovalStatus::Approved)
            || lineage.activation.is_some())
    {
        return Err(ReferenceLifecycleError::Invariant(
            "pending activation lacks an approved, unactivated comparison".to_string(),
        ));
    }
    if lineage.pending_observation
        && (lineage.activation.is_none()
            || lineage.active_observation.is_some()
            || lineage.rollback.is_some())
    {
        return Err(ReferenceLifecycleError::Invariant(
            "pending observation has invalid lifecycle prerequisites".to_string(),
        ));
    }
    if lineage.pending_rollback.is_some()
        && (lineage.active_observation.is_none() || lineage.rollback.is_some())
    {
        return Err(ReferenceLifecycleError::Invariant(
            "pending rollback has invalid lifecycle prerequisites".to_string(),
        ));
    }
    for (present, required, detail) in [
        (
            lineage.challenger_workspace.is_some(),
            lineage.incumbent.is_some(),
            "challenger workspace requires incumbent",
        ),
        (
            lineage.challenger_patchset.is_some(),
            lineage.challenger_workspace.is_some(),
            "challenger patchset requires workspace",
        ),
        (
            lineage.challenger_package.is_some(),
            lineage.challenger_patchset.is_some(),
            "challenger package requires patchset",
        ),
        (
            lineage.challenger_proving.is_some(),
            lineage.challenger_package.is_some(),
            "challenger proving requires package",
        ),
        (
            lineage.challenger_comparison.is_some(),
            lineage.challenger_proving.is_some(),
            "challenger comparison requires proving",
        ),
        (
            lineage.challenger.is_some(),
            lineage.challenger_comparison.is_some(),
            "composite challenger requires comparison",
        ),
        (
            lineage.approval.is_some(),
            lineage.challenger.is_some(),
            "approval requires challenger",
        ),
        (
            lineage.activation.is_some(),
            lineage.approval.is_some(),
            "activation requires approval",
        ),
        (
            lineage.active_observation.is_some(),
            lineage.activation.is_some(),
            "observation requires activation",
        ),
        (
            lineage.rollback.is_some(),
            lineage.active_observation.is_some(),
            "rollback requires observation",
        ),
    ] {
        if present && !required {
            return Err(ReferenceLifecycleError::Invariant(detail.to_string()));
        }
    }
    if lineage.challenger_comparison.is_some() != lineage.challenger.is_some() {
        return Err(ReferenceLifecycleError::Invariant(
            "comparison and composite challenger boundaries must be committed together".to_string(),
        ));
    }
    Ok(())
}

fn validate_built_artifact(
    suite: &ValidationSuite,
    artifact: &BuiltArtifactLineage,
    expected_workspace_id: &str,
) -> Result<(), ReferenceLifecycleError> {
    let bytes = &artifact.build.component.component_bytes;
    let digest = ContentDigest::from_bytes(bytes);
    if artifact.build.workspace.workspace_id != expected_workspace_id
        || artifact.build.package_digest != digest
        || artifact.package.digest != digest
        || artifact.package.byte_len != bytes.len() as u64
        || artifact.build.source_tree_digest != artifact.build.workspace.tree_digest
    {
        return Err(ReferenceLifecycleError::Invariant(
            "built artifact lineage contains inconsistent workspace or package identities"
                .to_string(),
        ));
    }
    validate_package_path(&artifact.package)?;
    validate_proving_record(suite, &artifact.proving)?;
    if artifact.proving.component_digest != digest {
        return Err(ReferenceLifecycleError::Invariant(
            "proving record is not bound to built component bytes".to_string(),
        ));
    }
    Ok(())
}

fn validate_patchset(challenger: &ChallengerLineage) -> Result<(), ReferenceLifecycleError> {
    let patchset = &challenger.patchset;
    if patchset.after != challenger.artifact.build.workspace {
        return Err(ReferenceLifecycleError::Invariant(
            "challenger patchset does not bind the challenger workspace".to_string(),
        ));
    }
    let workspace = challenger_workspace_lineage(patchset.before.clone())?;
    validate_materialized_patchset(&workspace, patchset)
}

fn validate_materialized_patchset(
    workspace: &ChallengerWorkspaceLineage,
    patchset: &MaterializedCandidatePatchset,
) -> Result<(), ReferenceLifecycleError> {
    if patchset.workspace_id != workspace.snapshot.workspace_id
        || patchset.before != workspace.snapshot
        || patchset.changes.len() != 1
    {
        return Err(ReferenceLifecycleError::Invariant(
            "challenger patchset does not follow the opened workspace boundary".to_string(),
        ));
    }
    let change = &patchset.changes[0];
    if change.relative_path != COMPONENT_WAT_PATH
        || ContentDigest::from_bytes(&change.before_bytes) != change.before_digest
        || ContentDigest::from_bytes(&change.after_bytes) != change.after_digest
    {
        return Err(ReferenceLifecycleError::Invariant(
            "challenger replacement bytes do not match patchset identities".to_string(),
        ));
    }
    let expected = digest_json_content(&(
        patchset.workspace_id.as_str(),
        &patchset.before.tree_digest,
        &patchset.after.tree_digest,
        patchset.changes.as_slice(),
    ))?;
    if patchset.patchset_digest != expected {
        return Err(ReferenceLifecycleError::Invariant(
            "challenger patchset digest does not match reconstructable changes".to_string(),
        ));
    }
    Ok(())
}

fn validate_challenger_package_stage(
    patchset: &MaterializedCandidatePatchset,
    package: &ChallengerPackageLineage,
) -> Result<(), ReferenceLifecycleError> {
    let bytes = &package.build.component.component_bytes;
    let digest = ContentDigest::from_bytes(bytes);
    let replacement_digest = &patchset
        .changes
        .first()
        .ok_or_else(|| {
            ReferenceLifecycleError::Invariant(
                "challenger package has no materialized source change".to_string(),
            )
        })?
        .after_digest;
    if package.build.workspace != patchset.after
        || package.build.source_tree_digest != patchset.after.tree_digest
        || package.build.wat_digest != *replacement_digest
        || package.build.package_digest != digest
        || package.package.digest != digest
        || package.package.byte_len != bytes.len() as u64
        || package.record_digest != challenger_package_digest(&package.build, &package.package)?
    {
        return Err(ReferenceLifecycleError::Invariant(
            "challenger package boundary is not bound to patchset and component bytes".to_string(),
        ));
    }
    validate_package_path(&package.package)
}

fn challenger_workspace_lineage(
    snapshot: CandidateWorkspaceSnapshot,
) -> Result<ChallengerWorkspaceLineage, ReferenceLifecycleError> {
    let snapshot_digest =
        digest_json_content(&("wasm-biotic.m1-challenger-workspace.v1", &snapshot))?;
    Ok(ChallengerWorkspaceLineage {
        snapshot,
        snapshot_digest,
    })
}

fn challenger_package_digest(
    build: &CandidateBuild,
    package: &PackageRecord,
) -> Result<ContentDigest, ReferenceLifecycleError> {
    Ok(digest_json_content(&(
        "wasm-biotic.m1-challenger-package.v1",
        build,
        package,
    ))?)
}

fn build_approval_record(
    approval_id: &str,
    decision: ApprovalDecision,
    rationale: &str,
    challenger: &ChallengerLineage,
) -> Result<ApprovalRecord, ReferenceLifecycleError> {
    if decision == ApprovalDecision::Approve && !challenger.comparison.eligible_for_activation {
        return Err(ReferenceLifecycleError::InvalidTransition(
            "comparison does not make the challenger eligible for activation".to_string(),
        ));
    }
    let status = match decision {
        ApprovalDecision::Approve => ApprovalStatus::Approved,
        ApprovalDecision::Reject => ApprovalStatus::Rejected,
    };
    let record_digest = approval_digest(
        approval_id,
        status,
        &challenger.comparison.record_digest,
        &challenger.comparison.incumbent_component_digest,
        &challenger.comparison.challenger_component_digest,
        rationale,
    )?;
    Ok(ApprovalRecord {
        approval_id: approval_id.to_string(),
        status,
        comparison_digest: challenger.comparison.record_digest.clone(),
        incumbent_component_digest: challenger.comparison.incumbent_component_digest.clone(),
        challenger_component_digest: challenger.comparison.challenger_component_digest.clone(),
        rationale: rationale.to_string(),
        approval_ref: format!("approval:{record_digest}"),
        record_digest,
    })
}

fn validate_approval(
    approval: &ApprovalRecord,
    challenger: &ChallengerLineage,
) -> Result<(), ReferenceLifecycleError> {
    validate_text("approval_id", &approval.approval_id)?;
    validate_text("rationale", &approval.rationale)?;
    let expected = approval_digest(
        &approval.approval_id,
        approval.status,
        &approval.comparison_digest,
        &approval.incumbent_component_digest,
        &approval.challenger_component_digest,
        &approval.rationale,
    )?;
    if approval.comparison_digest != challenger.comparison.record_digest
        || approval.incumbent_component_digest != challenger.comparison.incumbent_component_digest
        || approval.challenger_component_digest != challenger.comparison.challenger_component_digest
        || approval.record_digest != expected
        || approval.approval_ref != format!("approval:{expected}")
        || (approval.status == ApprovalStatus::Approved
            && !challenger.comparison.eligible_for_activation)
    {
        return Err(ReferenceLifecycleError::Invariant(
            "approval is not exactly bound to the derived comparison and component bytes"
                .to_string(),
        ));
    }
    Ok(())
}

fn validate_active_observation(
    lineage: &ReferenceLineage,
    observation: &ActiveObservationLineage,
) -> Result<(), ReferenceLifecycleError> {
    let activation = require_activation(lineage)?;
    let challenger = require_challenger(lineage)?;
    if observation.evidence.schema != ACTIVE_EVIDENCE_SCHEMA
        || observation.evidence.activation_id != activation.operation_id
        || observation.evidence.active_component_digest != challenger.artifact.package.digest
        || observation.deployment.activation_id != activation.operation_id
        || observation.deployment.observed_artifact.digest != challenger.artifact.package.digest
    {
        return Err(ReferenceLifecycleError::Invariant(
            "active observation is not bound to the active challenger".to_string(),
        ));
    }
    validate_proving_record(&lineage.comparison_suite, &observation.evidence.proving)?;
    if observation.evidence.proving.component_digest != observation.evidence.active_component_digest
    {
        return Err(ReferenceLifecycleError::Invariant(
            "active observation proving record names different component bytes".to_string(),
        ));
    }
    let (expected_outcome, expected_summary) =
        observation_outcome_and_summary(&observation.evidence.proving);
    if observation.deployment.outcome != expected_outcome
        || observation.deployment.summary != expected_summary
        || observation.record_digest
            != active_observation_digest(&observation.deployment, &observation.evidence)?
    {
        return Err(ReferenceLifecycleError::Invariant(
            "active observation outcome or digest is caller-fabricated".to_string(),
        ));
    }
    Ok(())
}

fn observation_outcome_and_summary(proving: &ProvingRecord) -> (ObservationOutcome, String) {
    if proving.summary.all_satisfied {
        (
            ObservationOutcome::Healthy,
            format!(
                "active challenger satisfied all {} typed reference cases",
                proving.summary.case_count
            ),
        )
    } else {
        (
            ObservationOutcome::Regressed,
            format!(
                "active challenger satisfied {}/{} typed reference cases",
                proving.summary.satisfied_count, proving.summary.case_count
            ),
        )
    }
}

fn validate_rollback_verification(
    lineage: &ReferenceLineage,
    rollback: &RollbackVerification,
) -> Result<(), ReferenceLifecycleError> {
    let activation = require_activation(lineage)?;
    let incumbent = require_incumbent(lineage)?;
    if rollback.deployment.operation_id != ROLLBACK_OPERATION_ID
        || rollback.deployment.activation_id != activation.operation_id
        || rollback.deployment.from_artifact != activation.activated_artifact
        || rollback.deployment.restored_artifact.digest != incumbent.artifact.package.digest
    {
        return Err(ReferenceLifecycleError::Invariant(
            "rollback record is not bound to the exact activation and incumbent".to_string(),
        ));
    }
    validate_proving_record(&lineage.incumbent_verification_suite, &rollback.proving)?;
    if rollback.proving.component_digest != incumbent.artifact.package.digest
        || !rollback.proving.summary.all_satisfied
        || rollback.record_digest
            != rollback_verification_digest(&rollback.deployment, &rollback.proving)?
    {
        return Err(ReferenceLifecycleError::Invariant(
            "rollback verification does not prove restored incumbent behavior".to_string(),
        ));
    }
    Ok(())
}

fn require_incumbent(
    lineage: &ReferenceLineage,
) -> Result<&IncumbentLineage, ReferenceLifecycleError> {
    lineage.incumbent.as_ref().ok_or_else(|| {
        ReferenceLifecycleError::InvalidTransition(
            "the incumbent must be initialized first".to_string(),
        )
    })
}

fn require_challenger_workspace(
    lineage: &ReferenceLineage,
) -> Result<&ChallengerWorkspaceLineage, ReferenceLifecycleError> {
    lineage.challenger_workspace.as_ref().ok_or_else(|| {
        ReferenceLifecycleError::InvalidTransition(
            "the challenger workspace must be opened first".to_string(),
        )
    })
}

fn require_challenger_patchset(
    lineage: &ReferenceLineage,
) -> Result<&MaterializedCandidatePatchset, ReferenceLifecycleError> {
    lineage.challenger_patchset.as_ref().ok_or_else(|| {
        ReferenceLifecycleError::InvalidTransition(
            "component.wat must be materialized before packaging".to_string(),
        )
    })
}

fn require_challenger_package(
    lineage: &ReferenceLineage,
) -> Result<&ChallengerPackageLineage, ReferenceLifecycleError> {
    lineage.challenger_package.as_ref().ok_or_else(|| {
        ReferenceLifecycleError::InvalidTransition(
            "the challenger must be packaged before proving".to_string(),
        )
    })
}

fn require_challenger_proving(
    lineage: &ReferenceLineage,
) -> Result<&ProvingRecord, ReferenceLifecycleError> {
    lineage.challenger_proving.as_ref().ok_or_else(|| {
        ReferenceLifecycleError::InvalidTransition(
            "the challenger package must be proved before comparison".to_string(),
        )
    })
}

fn ensure_candidate_construction_open(
    lineage: &ReferenceLineage,
) -> Result<(), ReferenceLifecycleError> {
    if lineage.approval.is_some()
        || lineage.pending_activation
        || lineage.activation.is_some()
        || lineage.active_observation.is_some()
        || lineage.rollback.is_some()
    {
        Err(ReferenceLifecycleError::InvalidTransition(
            "candidate construction is closed after approval begins".to_string(),
        ))
    } else {
        Ok(())
    }
}

fn require_challenger(
    lineage: &ReferenceLineage,
) -> Result<&ChallengerLineage, ReferenceLifecycleError> {
    lineage.challenger.as_ref().ok_or_else(|| {
        ReferenceLifecycleError::InvalidTransition(
            "a built and proved challenger is required".to_string(),
        )
    })
}

fn require_approved(
    lineage: &ReferenceLineage,
) -> Result<&ApprovalRecord, ReferenceLifecycleError> {
    let approval = lineage.approval.as_ref().ok_or_else(|| {
        ReferenceLifecycleError::InvalidTransition(
            "an explicit approval decision is required".to_string(),
        )
    })?;
    if approval.status != ApprovalStatus::Approved {
        return Err(ReferenceLifecycleError::InvalidTransition(
            "the recorded approval status is rejected".to_string(),
        ));
    }
    Ok(approval)
}

fn require_activation(
    lineage: &ReferenceLineage,
) -> Result<&ActivationRecord, ReferenceLifecycleError> {
    lineage.activation.as_ref().ok_or_else(|| {
        ReferenceLifecycleError::InvalidTransition(
            "the challenger must be activated first".to_string(),
        )
    })
}

fn require_observation(
    lineage: &ReferenceLineage,
) -> Result<&ActiveObservationLineage, ReferenceLifecycleError> {
    lineage.active_observation.as_ref().ok_or_else(|| {
        ReferenceLifecycleError::InvalidTransition(
            "active challenger behavior must be observed first".to_string(),
        )
    })
}

fn comparison_ref(comparison: &ComparisonRecord) -> String {
    format!("comparison:{}", comparison.record_digest)
}

fn activation_matches_lineage(record: &ActivationRecord, request: &ActivationRequest) -> bool {
    record.operation_id == request.operation_id
        && record.candidate_source == request.candidate_path
        && record.previous_artifact.digest == request.expected_active_digest
        && record.activated_artifact.digest == request.expected_candidate_digest
        && record.approval_ref == request.approval_ref
        && record.comparison_ref == request.comparison_ref
        && record.observation_window_ref == request.observation_window_ref
}

#[derive(Serialize)]
struct ApprovalDigestMaterial<'a> {
    schema: &'static str,
    approval_id: &'a str,
    status: ApprovalStatus,
    comparison_digest: &'a ContentDigest,
    incumbent_component_digest: &'a ContentDigest,
    challenger_component_digest: &'a ContentDigest,
    rationale: &'a str,
}

fn approval_digest(
    approval_id: &str,
    status: ApprovalStatus,
    comparison_digest: &ContentDigest,
    incumbent_component_digest: &ContentDigest,
    challenger_component_digest: &ContentDigest,
    rationale: &str,
) -> Result<ContentDigest, ReferenceLifecycleError> {
    Ok(digest_json_content(&ApprovalDigestMaterial {
        schema: "wasm-biotic.m1-approval.v1",
        approval_id,
        status,
        comparison_digest,
        incumbent_component_digest,
        challenger_component_digest,
        rationale,
    })?)
}

fn active_observation_digest(
    deployment: &ObservationRecord,
    evidence: &ActiveBehaviorEvidence,
) -> Result<ContentDigest, ReferenceLifecycleError> {
    Ok(digest_json_content(&(
        "wasm-biotic.m1-active-observation-lineage.v1",
        deployment,
        evidence,
    ))?)
}

fn rollback_verification_digest(
    deployment: &RollbackRecord,
    proving: &ProvingRecord,
) -> Result<ContentDigest, ReferenceLifecycleError> {
    Ok(digest_json_content(&(
        "wasm-biotic.m1-rollback-verification.v1",
        deployment,
        proving,
    ))?)
}

#[derive(Serialize)]
struct LineageDigestMaterial<'a> {
    schema: &'static str,
    schema_version: u32,
    comparison_suite: &'a ValidationSuite,
    incumbent_verification_suite: &'a ValidationSuite,
    pending_initialization: bool,
    pending_candidate: &'a Option<PendingCandidate>,
    pending_activation: bool,
    pending_observation: bool,
    pending_rollback: &'a Option<PendingRollback>,
    incumbent: &'a Option<IncumbentLineage>,
    challenger_workspace: &'a Option<ChallengerWorkspaceLineage>,
    challenger_patchset: &'a Option<MaterializedCandidatePatchset>,
    challenger_package: &'a Option<ChallengerPackageLineage>,
    challenger_proving: &'a Option<ProvingRecord>,
    challenger_comparison: &'a Option<ComparisonRecord>,
    challenger: &'a Option<ChallengerLineage>,
    approval: &'a Option<ApprovalRecord>,
    activation: &'a Option<ActivationRecord>,
    active_observation: &'a Option<ActiveObservationLineage>,
    rollback: &'a Option<RollbackVerification>,
}

#[derive(Serialize)]
struct LegacyLineageDigestMaterial<'a> {
    schema: &'static str,
    schema_version: u32,
    comparison_suite: &'a ValidationSuite,
    incumbent_verification_suite: &'a ValidationSuite,
    pending_initialization: bool,
    pending_candidate: &'a Option<PendingCandidate>,
    pending_activation: bool,
    pending_observation: bool,
    pending_rollback: &'a Option<PendingRollback>,
    incumbent: &'a Option<IncumbentLineage>,
    challenger: &'a Option<ChallengerLineage>,
    approval: &'a Option<ApprovalRecord>,
    activation: &'a Option<ActivationRecord>,
    active_observation: &'a Option<ActiveObservationLineage>,
    rollback: &'a Option<RollbackVerification>,
}

fn legacy_lineage_digest(
    lineage: &ReferenceLineage,
) -> Result<ContentDigest, ReferenceLifecycleError> {
    Ok(digest_json_content(&LegacyLineageDigestMaterial {
        schema: "wasm-biotic.m1-reference-lineage.v1",
        schema_version: 1,
        comparison_suite: &lineage.comparison_suite,
        incumbent_verification_suite: &lineage.incumbent_verification_suite,
        pending_initialization: lineage.pending_initialization,
        pending_candidate: &lineage.pending_candidate,
        pending_activation: lineage.pending_activation,
        pending_observation: lineage.pending_observation,
        pending_rollback: &lineage.pending_rollback,
        incumbent: &lineage.incumbent,
        challenger: &lineage.challenger,
        approval: &lineage.approval,
        activation: &lineage.activation,
        active_observation: &lineage.active_observation,
        rollback: &lineage.rollback,
    })?)
}

fn migrate_v1_lineage(lineage: &mut ReferenceLineage) -> Result<(), ReferenceLifecycleError> {
    if let Some(challenger) = &lineage.challenger {
        lineage.challenger_workspace = Some(challenger_workspace_lineage(
            challenger.patchset.before.clone(),
        )?);
        lineage.challenger_patchset = Some(challenger.patchset.clone());
        lineage.challenger_package = Some(ChallengerPackageLineage {
            record_digest: challenger_package_digest(
                &challenger.artifact.build,
                &challenger.artifact.package,
            )?,
            build: challenger.artifact.build.clone(),
            package: challenger.artifact.package.clone(),
        });
        lineage.challenger_proving = Some(challenger.artifact.proving.clone());
        lineage.challenger_comparison = Some(challenger.comparison.clone());
    } else if let Some(pending) = &lineage.pending_candidate {
        lineage.challenger_workspace = Some(challenger_workspace_lineage(
            pending.base_workspace.clone(),
        )?);
    }
    lineage.schema_version = REFERENCE_LINEAGE_SCHEMA_VERSION;
    lineage.refresh_digest()
}

fn lineage_digest(lineage: &ReferenceLineage) -> Result<ContentDigest, ReferenceLifecycleError> {
    Ok(digest_json_content(&LineageDigestMaterial {
        schema: "wasm-biotic.m1-reference-lineage.v1",
        schema_version: lineage.schema_version,
        comparison_suite: &lineage.comparison_suite,
        incumbent_verification_suite: &lineage.incumbent_verification_suite,
        pending_initialization: lineage.pending_initialization,
        pending_candidate: &lineage.pending_candidate,
        pending_activation: lineage.pending_activation,
        pending_observation: lineage.pending_observation,
        pending_rollback: &lineage.pending_rollback,
        incumbent: &lineage.incumbent,
        challenger_workspace: &lineage.challenger_workspace,
        challenger_patchset: &lineage.challenger_patchset,
        challenger_package: &lineage.challenger_package,
        challenger_proving: &lineage.challenger_proving,
        challenger_comparison: &lineage.challenger_comparison,
        challenger: &lineage.challenger,
        approval: &lineage.approval,
        activation: &lineage.activation,
        active_observation: &lineage.active_observation,
        rollback: &lineage.rollback,
    })?)
}

fn validate_package_path(package: &PackageRecord) -> Result<(), ReferenceLifecycleError> {
    let expected = PathBuf::from(format!("{}.component.wasm", package.digest.file_stem()));
    if package.relative_path != expected
        || package.relative_path.is_absolute()
        || package.relative_path.components().count() != 1
        || !matches!(
            package.relative_path.components().next(),
            Some(Component::Normal(_))
        )
    {
        return Err(ReferenceLifecycleError::Invariant(
            "package path is not derived from its content digest".to_string(),
        ));
    }
    Ok(())
}

fn validate_text(field: &'static str, value: &str) -> Result<(), ReferenceLifecycleError> {
    if value.is_empty() || value.trim() != value || value.chars().any(char::is_control) {
        return Err(ReferenceLifecycleError::InvalidInput(format!(
            "{field} must be non-empty, trimmed, and printable"
        )));
    }
    Ok(())
}

fn validate_template_files(root: &Path) -> Result<(), ReferenceLifecycleError> {
    let entries = fs::read_dir(root)
        .map_err(|source| ReferenceLifecycleError::io("read template directory", root, source))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| ReferenceLifecycleError::io("read template entry", root, source))?;
    if entries.len() != 2 {
        return Err(ReferenceLifecycleError::InvalidInput(
            "reference template must contain exactly component.wit and component.wat".to_string(),
        ));
    }
    for relative in [COMPONENT_WIT_PATH, COMPONENT_WAT_PATH] {
        reject_non_regular_file(&root.join(relative), "reference template file")?;
    }
    Ok(())
}

fn create_and_canonicalize_directory(
    path: &Path,
    role: &'static str,
) -> Result<PathBuf, ReferenceLifecycleError> {
    reject_symlink_if_present(path, role)?;
    fs::create_dir_all(path)
        .map_err(|source| ReferenceLifecycleError::io("create directory", path, source))?;
    canonicalize_existing_directory(path, role)
}

fn canonicalize_existing_directory(
    path: &Path,
    role: &'static str,
) -> Result<PathBuf, ReferenceLifecycleError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| ReferenceLifecycleError::io("inspect directory", path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ReferenceLifecycleError::UnsafePath {
            path: path.to_path_buf(),
            reason: format!("{role} must be a real directory"),
        });
    }
    fs::canonicalize(path)
        .map_err(|source| ReferenceLifecycleError::io("canonicalize directory", path, source))
}

fn create_owned_child_directory(
    root: &Path,
    name: &str,
    role: &'static str,
) -> Result<PathBuf, ReferenceLifecycleError> {
    let path = root.join(name);
    let canonical = create_and_canonicalize_directory(&path, role)?;
    if canonical.parent() != Some(root) {
        return Err(ReferenceLifecycleError::UnsafePath {
            path,
            reason: format!("{role} is not a direct child of the lifecycle root"),
        });
    }
    Ok(canonical)
}

fn reject_symlink_if_present(
    path: &Path,
    role: &'static str,
) -> Result<(), ReferenceLifecycleError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(ReferenceLifecycleError::UnsafePath {
                path: path.to_path_buf(),
                reason: format!("{role} must not be a symbolic link"),
            })
        }
        Ok(_) => Ok(()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ReferenceLifecycleError::io("inspect path", path, source)),
    }
}

fn reject_non_regular_file(path: &Path, role: &'static str) -> Result<(), ReferenceLifecycleError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| ReferenceLifecycleError::io("inspect file", path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ReferenceLifecycleError::UnsafePath {
            path: path.to_path_buf(),
            reason: format!("{role} must be a regular non-symlink file"),
        });
    }
    Ok(())
}

fn read_file(path: &Path) -> Result<Vec<u8>, ReferenceLifecycleError> {
    let mut file = File::open(path)
        .map_err(|source| ReferenceLifecycleError::io("open file", path, source))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|source| ReferenceLifecycleError::io("read file", path, source))?;
    Ok(bytes)
}

fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<(), ReferenceLifecycleError> {
    reject_symlink_if_present(path, "atomic replacement target")?;
    let parent = path.parent().ok_or_else(|| {
        ReferenceLifecycleError::Invariant(format!("path '{}' has no parent", path.display()))
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        ReferenceLifecycleError::Invariant(format!("path '{}' has no file name", path.display()))
    })?;
    let temporary = (0..64)
        .map(|_| {
            let sequence = TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            parent.join(format!(
                ".{}.{}.{}.tmp",
                file_name.to_string_lossy(),
                std::process::id(),
                sequence
            ))
        })
        .find(|candidate| !candidate.exists())
        .ok_or_else(|| {
            ReferenceLifecycleError::Invariant(format!(
                "could not allocate temporary file beside '{}'",
                path.display()
            ))
        })?;
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|source| {
                ReferenceLifecycleError::io("create temporary file", &temporary, source)
            })?;
        file.write_all(bytes).map_err(|source| {
            ReferenceLifecycleError::io("write temporary file", &temporary, source)
        })?;
        file.sync_all().map_err(|source| {
            ReferenceLifecycleError::io("sync temporary file", &temporary, source)
        })?;
        fs::rename(&temporary, path)
            .map_err(|source| ReferenceLifecycleError::io("rename file", path, source))?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| ReferenceLifecycleError::io("sync parent directory", parent, source))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[derive(Debug)]
pub enum ReferenceLifecycleError {
    Io {
        operation: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
    Serialization(serde_json::Error),
    Artifact(ArtifactError),
    Candidate(CandidateWorkspaceError),
    Validation(ValidationError),
    Deployment(DeploymentError),
    InvalidInput(String),
    InvalidTransition(String),
    Conflict(String),
    Invariant(String),
    UnsafePath {
        path: PathBuf,
        reason: String,
    },
    CorruptContent {
        role: &'static str,
        expected: ContentDigest,
        actual: ContentDigest,
    },
    UnsupportedSchema {
        expected: u32,
        actual: u32,
    },
}

impl ReferenceLifecycleError {
    fn io(operation: &'static str, path: &Path, source: std::io::Error) -> Self {
        Self::Io {
            operation,
            path: path.to_path_buf(),
            source,
        }
    }
}

impl From<ArtifactError> for ReferenceLifecycleError {
    fn from(value: ArtifactError) -> Self {
        Self::Artifact(value)
    }
}

impl From<CandidateWorkspaceError> for ReferenceLifecycleError {
    fn from(value: CandidateWorkspaceError) -> Self {
        Self::Candidate(value)
    }
}

impl From<ValidationError> for ReferenceLifecycleError {
    fn from(value: ValidationError) -> Self {
        Self::Validation(value)
    }
}

impl From<DeploymentError> for ReferenceLifecycleError {
    fn from(value: DeploymentError) -> Self {
        Self::Deployment(value)
    }
}

impl Display for ReferenceLifecycleError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io {
                operation,
                path,
                source,
            } => write!(formatter, "{operation} at '{}': {source}", path.display()),
            Self::Serialization(error) => {
                write!(formatter, "reference lineage serialization error: {error}")
            }
            Self::Artifact(error) => write!(formatter, "reference artifact error: {error}"),
            Self::Candidate(error) => write!(formatter, "reference candidate error: {error}"),
            Self::Validation(error) => write!(formatter, "reference validation error: {error}"),
            Self::Deployment(error) => write!(formatter, "reference deployment error: {error}"),
            Self::InvalidInput(detail) => write!(formatter, "invalid reference input: {detail}"),
            Self::InvalidTransition(detail) => {
                write!(
                    formatter,
                    "invalid reference lifecycle transition: {detail}"
                )
            }
            Self::Conflict(detail) => write!(formatter, "reference lifecycle conflict: {detail}"),
            Self::Invariant(detail) => write!(formatter, "reference lineage invariant: {detail}"),
            Self::UnsafePath { path, reason } => {
                write!(
                    formatter,
                    "unsafe reference path '{}': {reason}",
                    path.display()
                )
            }
            Self::CorruptContent {
                role,
                expected,
                actual,
            } => write!(
                formatter,
                "{role} content corruption: expected {expected}, got {actual}"
            ),
            Self::UnsupportedSchema { expected, actual } => write!(
                formatter,
                "unsupported reference lineage schema {actual}; expected {expected}"
            ),
        }
    }
}

impl Error for ReferenceLifecycleError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Serialization(source) => Some(source),
            Self::Artifact(source) => Some(source),
            Self::Candidate(source) => Some(source),
            Self::Validation(source) => Some(source),
            Self::Deployment(source) => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ACTIVATION_OPERATION_ID, ApprovalDecision, ApprovalStatus, CHALLENGER_WORKSPACE_ID,
        COMPONENT_WAT_PATH, M1ReferenceService, OBSERVATION_WINDOW_REF, PendingCandidate,
        ReferenceLifecycleError, comparison_ref,
    };
    use crate::candidate::{CandidateFileReplacement, CandidateWorkspaceError};
    use crate::deployment::{ActivationRequest, ObservationOutcome};
    use crate::execution::artifact::ContentDigest;
    use crate::m1_validation::{ComparisonDecision, ObservedI32Outcome};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory {
        root: PathBuf,
    }

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "wasm-biotic-m1-reference-{label}-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&root).expect("create isolated reference root");
            Self { root }
        }

        fn service_root(&self) -> PathBuf {
            self.root.join("service")
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn repository_root() -> PathBuf {
        let source = PathBuf::from(file!());
        let source = if source.is_absolute() {
            source
        } else {
            Path::new(env!("CARGO_MANIFEST_DIR")).join(source)
        };
        source
            .parent()
            .and_then(Path::parent)
            .expect("source file is beneath repository root")
            .to_path_buf()
    }

    fn fixture_root() -> PathBuf {
        repository_root().join("artifacts/fixtures/m1-reference-component")
    }

    fn template_root() -> PathBuf {
        fixture_root().join("template")
    }

    fn candidate_bytes(name: &str) -> Vec<u8> {
        fs::read(fixture_root().join("candidates").join(name)).expect("read candidate fixture")
    }

    fn open_service(test: &TestDirectory) -> M1ReferenceService {
        M1ReferenceService::open(test.service_root(), template_root())
            .expect("open reference lifecycle")
    }

    fn prepare_approved(
        service: &M1ReferenceService,
    ) -> (
        super::IncumbentLineage,
        super::ChallengerLineage,
        super::ApprovalRecord,
    ) {
        let incumbent = service
            .initialize_incumbent()
            .expect("initialize incumbent");
        let challenger = service
            .prepare_challenger(&candidate_bytes("increment.wat"))
            .expect("prepare challenger");
        let approval = service
            .record_approval(
                "operator-approval-1",
                ApprovalDecision::Approve,
                "fixed reference challenger passed the complete proving suite",
            )
            .expect("approve challenger");
        (incumbent, challenger, approval)
    }

    #[test]
    fn full_lifecycle_executes_real_bytes_and_survives_restart() {
        let test = TestDirectory::new("full");
        let service = open_service(&test);
        let (incumbent, challenger, approval) = prepare_approved(&service);

        assert_eq!(incumbent.artifact.proving.summary.satisfied_count, 0);
        assert_eq!(
            challenger.comparison.decision,
            ComparisonDecision::ChallengerPreferred
        );
        assert!(challenger.comparison.eligible_for_activation);
        assert_eq!(approval.status, ApprovalStatus::Approved);
        assert_eq!(
            approval.comparison_digest,
            challenger.comparison.record_digest
        );

        let activation = service.activate_approved().expect("activate challenger");
        assert_eq!(
            activation.activated_artifact.digest,
            challenger.artifact.package.digest
        );
        assert_eq!(activation.approval_ref, approval.approval_ref);
        assert_eq!(
            activation.comparison_ref,
            comparison_ref(&challenger.comparison)
        );
        assert_eq!(
            fs::read(service.active_artifact_path()).expect("read active challenger"),
            challenger.artifact.build.component.component_bytes
        );

        let observation = service.observe_active().expect("observe active behavior");
        assert_eq!(observation.deployment.outcome, ObservationOutcome::Healthy);
        assert!(observation.evidence.proving.summary.all_satisfied);
        assert_eq!(
            observation
                .evidence
                .proving
                .results
                .iter()
                .map(|result| result.observed.clone())
                .collect::<Vec<_>>(),
            vec![
                ObservedI32Outcome::Returned { value: 0 },
                ObservedI32Outcome::Returned { value: 1 },
                ObservedI32Outcome::Returned { value: 42 },
            ]
        );

        let rollback = service
            .rollback_and_verify("rehearsal:restore-incumbent")
            .expect("rollback and verify");
        assert!(rollback.proving.summary.all_satisfied);
        assert_eq!(
            rollback.deployment.restored_artifact.digest,
            incumbent.artifact.package.digest
        );
        assert_eq!(
            fs::read(service.active_artifact_path()).expect("read restored incumbent"),
            incumbent.artifact.build.component.component_bytes
        );
        let completed = service.state().expect("complete durable state");
        drop(service);

        let reopened = open_service(&test);
        assert_eq!(reopened.state().expect("reopened state"), completed);
        assert_eq!(
            reopened
                .initialize_incumbent()
                .expect("repeat initialization"),
            incumbent
        );
        assert_eq!(
            reopened
                .prepare_challenger(&candidate_bytes("increment.wat"))
                .expect("repeat challenger"),
            challenger
        );
        assert_eq!(
            reopened
                .record_approval(
                    "operator-approval-1",
                    ApprovalDecision::Approve,
                    "fixed reference challenger passed the complete proving suite",
                )
                .expect("repeat approval"),
            approval
        );
        assert_eq!(
            reopened.activate_approved().expect("repeat activation"),
            completed
                .activation
                .clone()
                .expect("completed activation lineage")
        );
        assert_eq!(
            reopened.observe_active().expect("repeat observation"),
            observation
        );
        assert_eq!(
            reopened
                .rollback_and_verify("rehearsal:restore-incumbent")
                .expect("repeat rollback"),
            rollback
        );
    }

    #[test]
    fn rejected_approval_cannot_activate_an_eligible_challenger() {
        let test = TestDirectory::new("rejected");
        let service = open_service(&test);
        let incumbent = service
            .initialize_incumbent()
            .expect("initialize incumbent");
        service
            .prepare_challenger(&candidate_bytes("increment.wat"))
            .expect("prepare challenger");
        let approval = service
            .record_approval(
                "operator-rejection-1",
                ApprovalDecision::Reject,
                "operator chose not to activate during this rehearsal",
            )
            .expect("record rejection");

        assert_eq!(approval.status, ApprovalStatus::Rejected);
        assert!(matches!(
            service.activate_approved(),
            Err(ReferenceLifecycleError::InvalidTransition(_))
        ));
        assert_eq!(
            fs::read(service.active_artifact_path()).expect("read incumbent"),
            incumbent.artifact.build.component.component_bytes
        );
        assert!(
            service
                .state()
                .expect("valid rejected state")
                .activation
                .is_none()
        );
    }

    #[test]
    fn restart_completes_an_exact_activation_after_the_effect_boundary() {
        let test = TestDirectory::new("activation-recovery");
        let service = open_service(&test);
        let (incumbent, challenger, approval) = prepare_approved(&service);
        let mut lineage = service.read_lineage().expect("read lineage");
        lineage.pending_activation = true;
        service
            .write_lineage(&lineage)
            .expect("write activation intent");

        let request = ActivationRequest {
            operation_id: ACTIVATION_OPERATION_ID.to_string(),
            candidate_path: challenger.artifact.package.relative_path.clone(),
            expected_candidate_digest: challenger.artifact.package.digest.clone(),
            expected_active_digest: incumbent.artifact.package.digest.clone(),
            approval_ref: approval.approval_ref.clone(),
            comparison_ref: comparison_ref(&challenger.comparison),
            observation_window_ref: OBSERVATION_WINDOW_REF.to_string(),
        };
        let effected = service
            .deployment
            .activate(&request)
            .expect("perform deployment effect");
        drop(service);

        let reopened = open_service(&test);
        let recovered = reopened.state().expect("recover activation lineage");
        assert_eq!(recovered.activation, Some(effected));
        assert!(!recovered.pending_activation);
        assert_eq!(
            fs::read(reopened.active_artifact_path()).expect("read recovered active bytes"),
            challenger.artifact.build.component.component_bytes
        );
    }

    #[test]
    fn fabricated_deployment_references_are_not_adopted() {
        let test = TestDirectory::new("fabricated");
        let service = open_service(&test);
        let (incumbent, challenger, _approval) = prepare_approved(&service);
        service
            .deployment
            .activate(&ActivationRequest {
                operation_id: ACTIVATION_OPERATION_ID.to_string(),
                candidate_path: challenger.artifact.package.relative_path.clone(),
                expected_candidate_digest: challenger.artifact.package.digest.clone(),
                expected_active_digest: incumbent.artifact.package.digest.clone(),
                approval_ref: "approval:fabricated".to_string(),
                comparison_ref: "comparison:fabricated".to_string(),
                observation_window_ref: OBSERVATION_WINDOW_REF.to_string(),
            })
            .expect("bypass orchestrator with fabricated refs");
        drop(service);

        assert!(matches!(
            M1ReferenceService::open(test.service_root(), template_root()),
            Err(ReferenceLifecycleError::Invariant(detail))
                if detail.contains("fabricated lineage")
        ));
    }

    #[test]
    fn package_and_lineage_digest_corruption_are_detected() {
        let package_test = TestDirectory::new("package-corruption");
        let service = open_service(&package_test);
        service
            .initialize_incumbent()
            .expect("initialize incumbent");
        let challenger = service
            .prepare_challenger(&candidate_bytes("increment.wat"))
            .expect("prepare challenger");
        fs::write(
            service
                .package_root()
                .join(&challenger.artifact.package.relative_path),
            b"corrupt package bytes",
        )
        .expect("corrupt package");
        assert!(matches!(
            service.state(),
            Err(ReferenceLifecycleError::CorruptContent { .. })
        ));

        let lineage_test = TestDirectory::new("lineage-corruption");
        let service = open_service(&lineage_test);
        service
            .initialize_incumbent()
            .expect("initialize incumbent");
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(service.lineage_path()).expect("read lineage JSON"))
                .expect("parse lineage JSON");
        value["pending_initialization"] = serde_json::Value::Bool(true);
        fs::write(
            service.lineage_path(),
            serde_json::to_vec_pretty(&value).expect("encode corrupt lineage"),
        )
        .expect("write corrupt lineage");
        assert!(matches!(
            service.state(),
            Err(ReferenceLifecycleError::Invariant(detail))
                if detail.contains("lineage digest")
        ));
    }

    #[test]
    fn restart_finishes_a_candidate_mutation_recorded_before_build() {
        let test = TestDirectory::new("candidate-recovery");
        let service = open_service(&test);
        service
            .initialize_incumbent()
            .expect("initialize incumbent");
        let base = service
            .open_challenger_workspace(CHALLENGER_WORKSPACE_ID)
            .expect("open challenger workspace")
            .snapshot;
        let base_wat = service
            .read_template_file(COMPONENT_WAT_PATH)
            .expect("read base WAT");
        let replacement = candidate_bytes("increment.wat");
        let replacement_digest = ContentDigest::from_bytes(&replacement);
        let mut lineage = service.read_lineage().expect("read lineage");
        lineage.pending_candidate = Some(PendingCandidate {
            workspace_id: CHALLENGER_WORKSPACE_ID.to_string(),
            base_workspace: base.clone(),
            base_wat_bytes: base_wat.clone(),
            replacement_bytes: replacement.clone(),
            replacement_digest: replacement_digest.clone(),
        });
        service
            .write_lineage(&lineage)
            .expect("write mutation intent");
        let base_digest = base
            .entry(COMPONENT_WAT_PATH)
            .expect("base WAT entry")
            .content_digest
            .clone();
        service
            .candidate
            .materialize_patchset(
                CHALLENGER_WORKSPACE_ID,
                &[CandidateFileReplacement::new(
                    COMPONENT_WAT_PATH,
                    base_digest,
                    replacement,
                )],
            )
            .expect("perform candidate mutation effect");
        drop(service);

        let reopened = open_service(&test);
        let recovered = reopened.state().expect("recover candidate lineage");
        let patchset = recovered
            .challenger_patchset
            .expect("recovered materialization boundary");
        assert_eq!(patchset.changes[0].after_digest, replacement_digest);
        assert!(recovered.challenger_package.is_none());
        assert!(recovered.challenger_proving.is_none());
        assert!(recovered.challenger_comparison.is_none());
        assert!(recovered.challenger.is_none());
        let package = reopened
            .package_challenger(CHALLENGER_WORKSPACE_ID, &patchset.after.tree_digest)
            .expect("package after materialization recovery");
        let proving = reopened
            .prove_challenger(&package.package.digest, &package.build.source_tree_digest)
            .expect("prove recovered package");
        let incumbent_digest = recovered
            .incumbent
            .expect("incumbent")
            .artifact
            .proving
            .record_digest;
        let comparison = reopened
            .compare_challenger(&incumbent_digest, &proving.record_digest)
            .expect("compare recovered proving records");
        assert_eq!(comparison.decision, ComparisonDecision::ChallengerPreferred);
    }

    #[test]
    fn staged_catalog_apis_persist_only_their_boundary_across_restarts() {
        let test = TestDirectory::new("staged-boundaries");
        let workspace_id = "catalog-candidate-1";
        let service = open_service(&test);
        service
            .initialize_incumbent()
            .expect("initialize incumbent");
        let fabricated = ContentDigest::from_bytes(b"fabricated");

        assert!(matches!(
            service.package_challenger(workspace_id, &fabricated),
            Err(ReferenceLifecycleError::InvalidTransition(_))
        ));
        assert!(matches!(
            service.prove_challenger(&fabricated, &fabricated),
            Err(ReferenceLifecycleError::InvalidTransition(_))
        ));
        assert!(matches!(
            service.compare_challenger(&fabricated, &fabricated),
            Err(ReferenceLifecycleError::InvalidTransition(_))
        ));

        let opened = service
            .open_challenger_workspace(workspace_id)
            .expect("open staged workspace");
        let state = service.state().expect("workspace boundary state");
        assert_eq!(state.challenger_workspace, Some(opened.clone()));
        assert!(state.challenger_patchset.is_none());
        assert!(state.challenger_package.is_none());
        drop(service);

        let service = open_service(&test);
        assert_eq!(
            service
                .inspect_challenger_workspace(workspace_id)
                .expect("inspect reopened workspace"),
            opened.snapshot
        );
        let expected_before_digest = opened
            .snapshot
            .entry(COMPONENT_WAT_PATH)
            .expect("base WAT")
            .content_digest
            .clone();
        let replacement = candidate_bytes("increment.wat");
        assert!(matches!(
            service.materialize_challenger_wat(workspace_id, &fabricated, &replacement,),
            Err(ReferenceLifecycleError::Conflict(_))
        ));
        assert!(
            service
                .state()
                .expect("unchanged workspace state")
                .challenger_patchset
                .is_none()
        );
        let patchset = service
            .materialize_challenger_wat(workspace_id, &expected_before_digest, &replacement)
            .expect("materialize staged patchset");
        let state = service.state().expect("patch boundary state");
        assert_eq!(state.challenger_patchset, Some(patchset.clone()));
        assert!(state.challenger_package.is_none());
        assert!(state.challenger_proving.is_none());
        drop(service);

        let service = open_service(&test);
        assert!(matches!(
            service.package_challenger(workspace_id, &fabricated),
            Err(ReferenceLifecycleError::Conflict(_))
        ));
        let package = service
            .package_challenger(workspace_id, &patchset.after.tree_digest)
            .expect("package staged challenger");
        let state = service.state().expect("package boundary state");
        assert_eq!(state.challenger_package, Some(package.clone()));
        assert!(state.challenger_proving.is_none());
        assert!(state.challenger_comparison.is_none());
        drop(service);

        let service = open_service(&test);
        assert!(matches!(
            service.prove_challenger(&fabricated, &package.build.source_tree_digest),
            Err(ReferenceLifecycleError::Conflict(_))
        ));
        let proving = service
            .prove_challenger(&package.package.digest, &package.build.source_tree_digest)
            .expect("prove staged package");
        let state = service.state().expect("proving boundary state");
        assert_eq!(state.challenger_proving, Some(proving.clone()));
        assert!(state.challenger_comparison.is_none());
        assert!(state.challenger.is_none());
        drop(service);

        let service = open_service(&test);
        let incumbent_digest = service
            .state()
            .expect("state with proving")
            .incumbent
            .expect("incumbent")
            .artifact
            .proving
            .record_digest;
        assert!(matches!(
            service.compare_challenger(&fabricated, &proving.record_digest),
            Err(ReferenceLifecycleError::Conflict(_))
        ));
        let comparison = service
            .compare_challenger(&incumbent_digest, &proving.record_digest)
            .expect("compare staged proofs");
        let completed = service.state().expect("comparison boundary state");
        assert_eq!(completed.challenger_comparison, Some(comparison.clone()));
        assert!(completed.challenger.is_some());
        drop(service);

        let service = open_service(&test);
        assert_eq!(
            service
                .open_challenger_workspace(workspace_id)
                .expect("repeat workspace stage"),
            opened
        );
        assert_eq!(
            service
                .materialize_challenger_wat(workspace_id, &expected_before_digest, &replacement,)
                .expect("repeat patch stage"),
            patchset
        );
        assert_eq!(
            service
                .package_challenger(workspace_id, &patchset.after.tree_digest)
                .expect("repeat package stage"),
            package
        );
        assert_eq!(
            service
                .prove_challenger(&package.package.digest, &package.build.source_tree_digest)
                .expect("repeat proving stage"),
            proving
        );
        assert_eq!(
            service
                .compare_challenger(&incumbent_digest, &proving.record_digest)
                .expect("repeat comparison stage"),
            comparison
        );
    }

    #[test]
    fn convenience_preparation_matches_explicit_stage_composition() {
        let convenience_test = TestDirectory::new("convenience");
        let convenience = open_service(&convenience_test);
        convenience
            .initialize_incumbent()
            .expect("initialize convenience incumbent");
        let replacement = candidate_bytes("increment.wat");
        let composed = convenience
            .prepare_challenger(&replacement)
            .expect("run convenience composition");

        let explicit_test = TestDirectory::new("explicit");
        let explicit = open_service(&explicit_test);
        let incumbent = explicit
            .initialize_incumbent()
            .expect("initialize explicit incumbent");
        let opened = explicit
            .open_challenger_workspace(CHALLENGER_WORKSPACE_ID)
            .expect("open explicit workspace");
        let before_digest = opened
            .snapshot
            .entry(COMPONENT_WAT_PATH)
            .expect("base WAT")
            .content_digest
            .clone();
        let patchset = explicit
            .materialize_challenger_wat(CHALLENGER_WORKSPACE_ID, &before_digest, &replacement)
            .expect("materialize explicit candidate");
        let package = explicit
            .package_challenger(CHALLENGER_WORKSPACE_ID, &patchset.after.tree_digest)
            .expect("package explicit candidate");
        let proving = explicit
            .prove_challenger(&package.package.digest, &package.build.source_tree_digest)
            .expect("prove explicit candidate");
        explicit
            .compare_challenger(
                &incumbent.artifact.proving.record_digest,
                &proving.record_digest,
            )
            .expect("compare explicit candidate");
        let staged = explicit
            .state()
            .expect("explicit state")
            .challenger
            .expect("explicit composite");

        assert_eq!(composed, staged);
    }

    #[test]
    fn legacy_lineage_migrates_and_unknown_schema_fails_explicitly() {
        let migration_test = TestDirectory::new("lineage-migration");
        let service = open_service(&migration_test);
        service
            .initialize_incumbent()
            .expect("initialize incumbent");
        service
            .prepare_challenger(&candidate_bytes("increment.wat"))
            .expect("prepare challenger");
        let expected = service.state().expect("current staged state");
        let mut legacy = expected.clone();
        legacy.schema_version = 1;
        legacy.challenger_workspace = None;
        legacy.challenger_patchset = None;
        legacy.challenger_package = None;
        legacy.challenger_proving = None;
        legacy.challenger_comparison = None;
        legacy.lineage_digest =
            super::legacy_lineage_digest(&legacy).expect("legacy lineage digest");
        let mut legacy_json = serde_json::to_value(&legacy).expect("serialize legacy lineage");
        let object = legacy_json.as_object_mut().expect("lineage object");
        for field in [
            "challenger_workspace",
            "challenger_patchset",
            "challenger_package",
            "challenger_proving",
            "challenger_comparison",
        ] {
            object.remove(field);
        }
        fs::write(
            service.lineage_path(),
            serde_json::to_vec_pretty(&legacy_json).expect("encode legacy lineage"),
        )
        .expect("write legacy lineage");
        drop(service);

        let migrated = open_service(&migration_test)
            .state()
            .expect("migrated lineage");
        assert_eq!(migrated, expected);

        let unknown_test = TestDirectory::new("unknown-schema");
        let service = open_service(&unknown_test);
        let mut unknown = service.state().expect("initial lineage");
        unknown.schema_version = 999;
        unknown.lineage_digest = super::lineage_digest(&unknown).expect("unknown-version digest");
        fs::write(
            service.lineage_path(),
            serde_json::to_vec_pretty(&unknown).expect("encode unknown lineage"),
        )
        .expect("write unknown lineage");
        drop(service);
        assert!(matches!(
            M1ReferenceService::open(unknown_test.service_root(), template_root()),
            Err(ReferenceLifecycleError::UnsupportedSchema {
                expected: super::REFERENCE_LINEAGE_SCHEMA_VERSION,
                actual: 999,
            })
        ));
    }

    #[test]
    fn broken_candidate_is_rejected_and_workspace_is_restored() {
        let test = TestDirectory::new("broken");
        let service = open_service(&test);
        service
            .initialize_incumbent()
            .expect("initialize incumbent");
        assert!(matches!(
            service.prepare_challenger(&candidate_bytes("broken.wat")),
            Err(ReferenceLifecycleError::Candidate(
                CandidateWorkspaceError::Component(_)
            ))
        ));

        let state = service.state().expect("lineage remains usable");
        assert!(state.pending_candidate.is_none());
        assert!(state.challenger.is_none());
        let snapshot = service
            .candidate
            .snapshot(CHALLENGER_WORKSPACE_ID)
            .expect("snapshot restored workspace");
        let template_digest = ContentDigest::from_bytes(
            &service
                .read_template_file(COMPONENT_WAT_PATH)
                .expect("read template WAT"),
        );
        assert_eq!(
            snapshot
                .entry(COMPONENT_WAT_PATH)
                .expect("restored WAT entry")
                .content_digest,
            template_digest
        );
    }
}
