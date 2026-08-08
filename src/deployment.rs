//! Durable, local-only activation and rollback for exact artifact bytes.
//!
//! This module deliberately owns a small effect boundary:
//!
//! - candidate paths are relative to one canonical candidate root;
//! - every activated, observed, or retained byte sequence is addressed by
//!   [`ContentDigest`];
//! - the runtime reads one stable active-artifact path beneath the deployment
//!   root;
//! - activation and rollback intent is durably recorded before that path is
//!   atomically replaced; and
//! - reopening the service completes an interrupted operation idempotently.
//!
//! It does not decide whether a candidate is valid or approved. Callers must
//! provide the immutable approval and comparison references that authorized an
//! activation; the service binds those references to the exact bytes it
//! activates.

use crate::execution::artifact::ContentDigest;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub const DEPLOYMENT_STATE_SCHEMA_VERSION: u32 = 1;

const STATE_FILE_NAME: &str = "deployment-state.json";
const ACTIVE_DIRECTORY_NAME: &str = "active";
const ACTIVE_FILE_NAME: &str = "artifact.bin";
const BLOB_DIRECTORY_NAME: &str = "blobs";

static TEMP_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactSnapshot {
    pub digest: ContentDigest,
    pub byte_len: u64,
}

impl ArtifactSnapshot {
    fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            digest: ContentDigest::from_bytes(bytes),
            byte_len: bytes.len() as u64,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InitializationRecord {
    pub operation_id: String,
    pub installed_artifact: ArtifactSnapshot,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivationRecord {
    pub operation_id: String,
    pub candidate_source: PathBuf,
    pub previous_artifact: ArtifactSnapshot,
    pub activated_artifact: ArtifactSnapshot,
    pub approval_ref: String,
    pub comparison_ref: String,
    pub observation_window_ref: String,
    pub rolled_back_by: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationOutcome {
    Healthy,
    Regressed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationRecord {
    pub observation_id: String,
    pub activation_id: String,
    pub observed_artifact: ArtifactSnapshot,
    pub evidence: ArtifactSnapshot,
    pub outcome: ObservationOutcome,
    pub summary: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackRecord {
    pub operation_id: String,
    pub activation_id: String,
    pub from_artifact: ArtifactSnapshot,
    pub restored_artifact: ArtifactSnapshot,
    pub reason_ref: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentState {
    pub schema_version: u32,
    pub active_artifact: Option<ArtifactSnapshot>,
    pub initializations: Vec<InitializationRecord>,
    pub activations: Vec<ActivationRecord>,
    pub observations: Vec<ObservationRecord>,
    pub rollbacks: Vec<RollbackRecord>,
    pub in_flight: Option<InFlightOperation>,
}

impl Default for DeploymentState {
    fn default() -> Self {
        Self {
            schema_version: DEPLOYMENT_STATE_SCHEMA_VERSION,
            active_artifact: None,
            initializations: Vec::new(),
            activations: Vec::new(),
            observations: Vec::new(),
            rollbacks: Vec::new(),
            in_flight: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InFlightOperation {
    Initialization(PendingInitialization),
    Activation(PendingActivation),
    Rollback(PendingRollback),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingInitialization {
    pub operation_id: String,
    pub target_artifact: ArtifactSnapshot,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingActivation {
    pub record: ActivationRecord,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingRollback {
    pub record: RollbackRecord,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivationRequest {
    pub operation_id: String,
    pub candidate_path: PathBuf,
    pub expected_candidate_digest: ContentDigest,
    pub expected_active_digest: ContentDigest,
    pub approval_ref: String,
    pub comparison_ref: String,
    pub observation_window_ref: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservationRequest {
    pub observation_id: String,
    pub activation_id: String,
    pub expected_active_digest: ContentDigest,
    pub outcome: ObservationOutcome,
    pub summary: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RollbackRequest {
    pub operation_id: String,
    pub activation_id: String,
    pub reason_ref: String,
}

/// A deployment service rooted in two canonical directories.
///
/// `deployment_root` is service-owned. `candidate_root` is read-only from this
/// module's perspective and supplies candidate artifact bytes. Both roots are
/// canonicalized once and every operation rechecks relevant descendants for
/// symlinks before using them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalDeploymentService {
    deployment_root: PathBuf,
    candidate_root: PathBuf,
}

impl LocalDeploymentService {
    pub fn open(
        deployment_root: impl AsRef<Path>,
        candidate_root: impl AsRef<Path>,
    ) -> Result<Self, DeploymentError> {
        let requested_deployment_root = deployment_root.as_ref();
        reject_terminal_symlink(requested_deployment_root)?;
        fs::create_dir_all(requested_deployment_root)
            .map_err(|error| DeploymentError::io(requested_deployment_root, error))?;
        let deployment_root = fs::canonicalize(requested_deployment_root)
            .map_err(|error| DeploymentError::io(requested_deployment_root, error))?;

        let requested_candidate_root = candidate_root.as_ref();
        let candidate_metadata = fs::symlink_metadata(requested_candidate_root)
            .map_err(|error| DeploymentError::io(requested_candidate_root, error))?;
        if candidate_metadata.file_type().is_symlink() {
            return Err(DeploymentError::UnsafePath {
                path: requested_candidate_root.to_path_buf(),
                reason: "candidate root must not be a symbolic link",
            });
        }
        if !candidate_metadata.is_dir() {
            return Err(DeploymentError::UnsafePath {
                path: requested_candidate_root.to_path_buf(),
                reason: "candidate root must be a directory",
            });
        }
        let candidate_root = fs::canonicalize(requested_candidate_root)
            .map_err(|error| DeploymentError::io(requested_candidate_root, error))?;

        let service = Self {
            deployment_root,
            candidate_root,
        };
        service.ensure_internal_layout()?;
        if !service.state_path().exists() {
            service.write_state(&DeploymentState::default())?;
        }
        service.recover_in_flight()?;
        service.verify_current_state()?;
        Ok(service)
    }

    pub fn deployment_root(&self) -> &Path {
        &self.deployment_root
    }

    pub fn candidate_root(&self) -> &Path {
        &self.candidate_root
    }

    /// The stable path runtime code should read or execute.
    pub fn active_artifact_path(&self) -> PathBuf {
        self.deployment_root
            .join(ACTIVE_DIRECTORY_NAME)
            .join(ACTIVE_FILE_NAME)
    }

    pub fn state(&self) -> Result<DeploymentState, DeploymentError> {
        self.ensure_internal_layout()?;
        self.read_state()
    }

    pub fn active_artifact(&self) -> Result<Option<ArtifactSnapshot>, DeploymentError> {
        Ok(self.state()?.active_artifact)
    }

    pub fn read_active_bytes(&self) -> Result<Vec<u8>, DeploymentError> {
        let state = self.state()?;
        let expected = state
            .active_artifact
            .ok_or(DeploymentError::NotInitialized)?;
        self.read_and_verify_active(&expected)
    }

    pub fn read_blob(&self, digest: &ContentDigest) -> Result<Vec<u8>, DeploymentError> {
        self.ensure_internal_layout()?;
        let path = self.blob_path(digest);
        reject_non_regular_file(&path, "content-addressed blob")?;
        let bytes = read_file(&path)?;
        let actual = ContentDigest::from_bytes(&bytes);
        if &actual != digest {
            return Err(DeploymentError::CorruptBlob {
                expected: digest.clone(),
                actual,
            });
        }
        Ok(bytes)
    }

    /// Installs the first incumbent. A different incumbent can never silently
    /// replace an initialized deployment.
    pub fn initialize_active(
        &self,
        operation_id: &str,
        incumbent_bytes: &[u8],
    ) -> Result<InitializationRecord, DeploymentError> {
        validate_identifier("operation_id", operation_id)?;
        if incumbent_bytes.is_empty() {
            return Err(DeploymentError::EmptyArtifact);
        }
        self.ensure_internal_layout()?;
        self.recover_in_flight()?;
        let mut state = self.read_state()?;
        let snapshot = self.persist_blob(incumbent_bytes)?;

        if let Some(existing) = state
            .initializations
            .iter()
            .find(|record| record.operation_id == operation_id)
        {
            if existing.installed_artifact == snapshot {
                return Ok(existing.clone());
            }
            return Err(DeploymentError::OperationConflict {
                operation_id: operation_id.to_string(),
            });
        }
        if let Some(active) = &state.active_artifact {
            if active == &snapshot {
                return Err(DeploymentError::AlreadyInitialized {
                    active: active.digest.clone(),
                });
            }
            return Err(DeploymentError::AlreadyInitialized {
                active: active.digest.clone(),
            });
        }

        state.in_flight = Some(InFlightOperation::Initialization(PendingInitialization {
            operation_id: operation_id.to_string(),
            target_artifact: snapshot.clone(),
        }));
        self.write_state(&state)?;
        self.atomic_replace_active(incumbent_bytes)?;

        let record = InitializationRecord {
            operation_id: operation_id.to_string(),
            installed_artifact: snapshot,
        };
        state.active_artifact = Some(record.installed_artifact.clone());
        state.initializations.push(record.clone());
        state.in_flight = None;
        self.write_state(&state)?;
        Ok(record)
    }

    /// Activates exact candidate bytes after binding them to the caller's
    /// expected candidate and incumbent digests.
    pub fn activate(
        &self,
        request: &ActivationRequest,
    ) -> Result<ActivationRecord, DeploymentError> {
        validate_activation_request(request)?;
        self.ensure_internal_layout()?;
        self.recover_in_flight()?;
        let mut state = self.read_state()?;
        let candidate_relative = validate_relative_candidate_path(&request.candidate_path)?;
        if let Some(existing) = state
            .activations
            .iter()
            .find(|record| record.operation_id == request.operation_id)
        {
            if activation_matches_request(existing, request, &candidate_relative) {
                return Ok(existing.clone());
            }
            return Err(DeploymentError::OperationConflict {
                operation_id: request.operation_id.clone(),
            });
        }
        ensure_operation_id_unused(&state, &request.operation_id)?;

        let current = state
            .active_artifact
            .clone()
            .ok_or(DeploymentError::NotInitialized)?;
        self.read_and_verify_active(&current)?;
        let candidate_path = self.resolve_candidate_path(&candidate_relative)?;
        let candidate_bytes = read_file(&candidate_path)?;
        if candidate_bytes.is_empty() {
            return Err(DeploymentError::EmptyArtifact);
        }
        let candidate = ArtifactSnapshot::from_bytes(&candidate_bytes);
        if candidate.digest != request.expected_candidate_digest {
            return Err(DeploymentError::CandidateDigestMismatch {
                expected: request.expected_candidate_digest.clone(),
                actual: candidate.digest,
            });
        }

        if current.digest != request.expected_active_digest {
            return Err(DeploymentError::ActiveDigestMismatch {
                expected: request.expected_active_digest.clone(),
                actual: current.digest,
            });
        }
        if current.digest == candidate.digest {
            return Err(DeploymentError::NoArtifactChange {
                digest: current.digest,
            });
        }

        // Capture the exact bytes read from the active path, not merely the
        // digest recorded in state, before changing runtime behavior.
        let previous_bytes = self.read_and_verify_active(&current)?;
        let previous = self.persist_blob(&previous_bytes)?;
        let activated = self.persist_blob(&candidate_bytes)?;
        let record = ActivationRecord {
            operation_id: request.operation_id.clone(),
            candidate_source: candidate_relative,
            previous_artifact: previous,
            activated_artifact: activated.clone(),
            approval_ref: request.approval_ref.clone(),
            comparison_ref: request.comparison_ref.clone(),
            observation_window_ref: request.observation_window_ref.clone(),
            rolled_back_by: None,
        };

        state.in_flight = Some(InFlightOperation::Activation(PendingActivation {
            record: record.clone(),
        }));
        self.write_state(&state)?;
        self.atomic_replace_active(&candidate_bytes)?;

        state.active_artifact = Some(activated);
        state.activations.push(record.clone());
        state.in_flight = None;
        self.write_state(&state)?;
        Ok(record)
    }

    /// Records evidence bytes against the exact artifact that was active at
    /// observation time.
    pub fn record_observation(
        &self,
        request: &ObservationRequest,
        evidence_bytes: &[u8],
    ) -> Result<ObservationRecord, DeploymentError> {
        validate_observation_request(request)?;
        if evidence_bytes.is_empty() {
            return Err(DeploymentError::EmptyObservationEvidence);
        }
        self.ensure_internal_layout()?;
        self.recover_in_flight()?;
        let mut state = self.read_state()?;
        let evidence = self.persist_blob(evidence_bytes)?;
        if let Some(existing) = state
            .observations
            .iter()
            .find(|item| item.observation_id == request.observation_id)
        {
            let request_matches = existing.activation_id == request.activation_id
                && existing.observed_artifact.digest == request.expected_active_digest
                && existing.evidence == evidence
                && existing.outcome == request.outcome
                && existing.summary == request.summary;
            if request_matches {
                return Ok(existing.clone());
            }
            return Err(DeploymentError::OperationConflict {
                operation_id: request.observation_id.clone(),
            });
        }
        ensure_operation_id_unused(&state, &request.observation_id)?;

        let active = state
            .active_artifact
            .clone()
            .ok_or(DeploymentError::NotInitialized)?;
        self.read_and_verify_active(&active)?;
        if active.digest != request.expected_active_digest {
            return Err(DeploymentError::ActiveDigestMismatch {
                expected: request.expected_active_digest.clone(),
                actual: active.digest,
            });
        }

        let activation = state
            .activations
            .iter()
            .find(|record| record.operation_id == request.activation_id)
            .ok_or_else(|| DeploymentError::UnknownActivation {
                activation_id: request.activation_id.clone(),
            })?;
        if activation.activated_artifact != active {
            return Err(DeploymentError::InactiveActivation {
                activation_id: request.activation_id.clone(),
                active: active.digest,
            });
        }

        let record = ObservationRecord {
            observation_id: request.observation_id.clone(),
            activation_id: request.activation_id.clone(),
            observed_artifact: active,
            evidence,
            outcome: request.outcome,
            summary: request.summary.clone(),
        };
        state.observations.push(record.clone());
        self.write_state(&state)?;
        Ok(record)
    }

    /// Restores the exact bytes captured by the named activation.
    ///
    /// Repeating a rollback for an activation returns its first durable record
    /// and never creates a second state transition.
    pub fn rollback(&self, request: &RollbackRequest) -> Result<RollbackRecord, DeploymentError> {
        validate_rollback_request(request)?;
        self.ensure_internal_layout()?;
        self.recover_in_flight()?;
        let mut state = self.read_state()?;

        if let Some(existing) = state
            .rollbacks
            .iter()
            .find(|record| record.activation_id == request.activation_id)
        {
            if existing.operation_id == request.operation_id
                || !operation_id_is_used(&state, &request.operation_id)
            {
                return Ok(existing.clone());
            }
            return Err(DeploymentError::OperationConflict {
                operation_id: request.operation_id.clone(),
            });
        }
        ensure_operation_id_unused(&state, &request.operation_id)?;

        let activation = state
            .activations
            .iter()
            .find(|record| record.operation_id == request.activation_id)
            .cloned()
            .ok_or_else(|| DeploymentError::UnknownActivation {
                activation_id: request.activation_id.clone(),
            })?;
        let current = state
            .active_artifact
            .clone()
            .ok_or(DeploymentError::NotInitialized)?;
        self.read_and_verify_active(&current)?;
        if current != activation.activated_artifact {
            return Err(DeploymentError::StaleRollback {
                activation_id: request.activation_id.clone(),
                expected_active: activation.activated_artifact.digest,
                actual_active: current.digest,
            });
        }

        let restored_bytes = self.read_blob(&activation.previous_artifact.digest)?;
        let restored = ArtifactSnapshot::from_bytes(&restored_bytes);
        if restored != activation.previous_artifact {
            return Err(DeploymentError::ArtifactLengthMismatch {
                digest: restored.digest,
                expected_len: activation.previous_artifact.byte_len,
                actual_len: restored.byte_len,
            });
        }
        let record = RollbackRecord {
            operation_id: request.operation_id.clone(),
            activation_id: request.activation_id.clone(),
            from_artifact: current,
            restored_artifact: restored.clone(),
            reason_ref: request.reason_ref.clone(),
        };

        state.in_flight = Some(InFlightOperation::Rollback(PendingRollback {
            record: record.clone(),
        }));
        self.write_state(&state)?;
        self.atomic_replace_active(&restored_bytes)?;

        finalize_rollback_state(&mut state, &record)?;
        state.in_flight = None;
        self.write_state(&state)?;
        Ok(record)
    }

    fn ensure_internal_layout(&self) -> Result<(), DeploymentError> {
        reject_terminal_symlink(&self.deployment_root)?;
        ensure_owned_directory(&self.deployment_root, ACTIVE_DIRECTORY_NAME)?;
        ensure_owned_directory(&self.deployment_root, BLOB_DIRECTORY_NAME)?;
        reject_symlink_if_present(&self.state_path())?;
        reject_symlink_if_present(&self.active_artifact_path())?;
        Ok(())
    }

    fn resolve_candidate_path(&self, relative: &Path) -> Result<PathBuf, DeploymentError> {
        let mut current = self.candidate_root.clone();
        for component in relative.components() {
            let Component::Normal(segment) = component else {
                return Err(DeploymentError::UnsafePath {
                    path: relative.to_path_buf(),
                    reason: "candidate path must contain only normal relative components",
                });
            };
            current.push(segment);
            let metadata = fs::symlink_metadata(&current)
                .map_err(|error| DeploymentError::io(&current, error))?;
            if metadata.file_type().is_symlink() {
                return Err(DeploymentError::UnsafePath {
                    path: relative.to_path_buf(),
                    reason: "candidate path must not traverse a symbolic link",
                });
            }
        }
        reject_non_regular_file(&current, "candidate artifact")?;
        let canonical =
            fs::canonicalize(&current).map_err(|error| DeploymentError::io(&current, error))?;
        if !canonical.starts_with(&self.candidate_root) {
            return Err(DeploymentError::UnsafePath {
                path: relative.to_path_buf(),
                reason: "candidate path escapes the configured candidate root",
            });
        }
        Ok(canonical)
    }

    fn state_path(&self) -> PathBuf {
        self.deployment_root.join(STATE_FILE_NAME)
    }

    fn blob_path(&self, digest: &ContentDigest) -> PathBuf {
        self.deployment_root
            .join(BLOB_DIRECTORY_NAME)
            .join(format!("{}.blob", digest.file_stem()))
    }

    fn persist_blob(&self, bytes: &[u8]) -> Result<ArtifactSnapshot, DeploymentError> {
        let snapshot = ArtifactSnapshot::from_bytes(bytes);
        let path = self.blob_path(&snapshot.digest);
        if path.exists() {
            reject_non_regular_file(&path, "content-addressed blob")?;
            let existing = read_file(&path)?;
            let actual = ArtifactSnapshot::from_bytes(&existing);
            if actual != snapshot {
                return Err(DeploymentError::CorruptBlob {
                    expected: snapshot.digest,
                    actual: actual.digest,
                });
            }
            return Ok(snapshot);
        }
        atomic_write_new(&path, bytes)?;
        Ok(snapshot)
    }

    fn read_state(&self) -> Result<DeploymentState, DeploymentError> {
        let path = self.state_path();
        reject_non_regular_file(&path, "deployment state")?;
        let bytes = read_file(&path)?;
        let state = serde_json::from_slice::<DeploymentState>(&bytes)
            .map_err(DeploymentError::StateSerialization)?;
        validate_state_structure(&state)?;
        Ok(state)
    }

    fn write_state(&self, state: &DeploymentState) -> Result<(), DeploymentError> {
        validate_state_structure(state)?;
        let bytes =
            serde_json::to_vec_pretty(state).map_err(DeploymentError::StateSerialization)?;
        atomic_replace(&self.state_path(), &bytes)
    }

    fn atomic_replace_active(&self, bytes: &[u8]) -> Result<(), DeploymentError> {
        atomic_replace(&self.active_artifact_path(), bytes)
    }

    fn read_and_verify_active(
        &self,
        expected: &ArtifactSnapshot,
    ) -> Result<Vec<u8>, DeploymentError> {
        let path = self.active_artifact_path();
        reject_non_regular_file(&path, "active artifact")?;
        let bytes = read_file(&path)?;
        let actual = ArtifactSnapshot::from_bytes(&bytes);
        if actual.digest != expected.digest {
            return Err(DeploymentError::ActiveDigestMismatch {
                expected: expected.digest.clone(),
                actual: actual.digest,
            });
        }
        if actual.byte_len != expected.byte_len {
            return Err(DeploymentError::ArtifactLengthMismatch {
                digest: actual.digest,
                expected_len: expected.byte_len,
                actual_len: actual.byte_len,
            });
        }
        Ok(bytes)
    }

    fn recover_in_flight(&self) -> Result<(), DeploymentError> {
        self.ensure_internal_layout()?;
        let mut state = self.read_state()?;
        let Some(in_flight) = state.in_flight.clone() else {
            return Ok(());
        };

        match in_flight {
            InFlightOperation::Initialization(pending) => {
                let target_bytes = self.read_blob(&pending.target_artifact.digest)?;
                match self.active_snapshot_from_disk()? {
                    None => self.atomic_replace_active(&target_bytes)?,
                    Some(actual) if actual == pending.target_artifact => {}
                    Some(actual) => {
                        return Err(DeploymentError::RecoveryConflict {
                            operation_id: pending.operation_id,
                            expected_one_of: vec![pending.target_artifact.digest],
                            actual: Some(actual.digest),
                        });
                    }
                }
                let record = InitializationRecord {
                    operation_id: pending.operation_id,
                    installed_artifact: pending.target_artifact.clone(),
                };
                if !state
                    .initializations
                    .iter()
                    .any(|item| item.operation_id == record.operation_id)
                {
                    state.initializations.push(record);
                }
                state.active_artifact = Some(pending.target_artifact);
            }
            InFlightOperation::Activation(pending) => {
                let record = pending.record;
                let target_bytes = self.read_blob(&record.activated_artifact.digest)?;
                match self.active_snapshot_from_disk()? {
                    Some(actual) if actual == record.activated_artifact => {}
                    Some(actual) if actual == record.previous_artifact => {
                        self.atomic_replace_active(&target_bytes)?;
                    }
                    actual => {
                        return Err(DeploymentError::RecoveryConflict {
                            operation_id: record.operation_id,
                            expected_one_of: vec![
                                record.previous_artifact.digest,
                                record.activated_artifact.digest,
                            ],
                            actual: actual.map(|snapshot| snapshot.digest),
                        });
                    }
                }
                if !state
                    .activations
                    .iter()
                    .any(|item| item.operation_id == record.operation_id)
                {
                    state.activations.push(record.clone());
                }
                state.active_artifact = Some(record.activated_artifact);
            }
            InFlightOperation::Rollback(pending) => {
                let record = pending.record;
                let restored_bytes = self.read_blob(&record.restored_artifact.digest)?;
                match self.active_snapshot_from_disk()? {
                    Some(actual) if actual == record.restored_artifact => {}
                    Some(actual) if actual == record.from_artifact => {
                        self.atomic_replace_active(&restored_bytes)?;
                    }
                    actual => {
                        return Err(DeploymentError::RecoveryConflict {
                            operation_id: record.operation_id,
                            expected_one_of: vec![
                                record.from_artifact.digest,
                                record.restored_artifact.digest,
                            ],
                            actual: actual.map(|snapshot| snapshot.digest),
                        });
                    }
                }
                finalize_rollback_state(&mut state, &record)?;
            }
        }

        state.in_flight = None;
        self.write_state(&state)
    }

    fn active_snapshot_from_disk(&self) -> Result<Option<ArtifactSnapshot>, DeploymentError> {
        let path = self.active_artifact_path();
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Err(DeploymentError::UnsafePath {
                        path,
                        reason: "active artifact must be a regular non-symlink file",
                    });
                }
                Ok(Some(ArtifactSnapshot::from_bytes(&read_file(&path)?)))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(DeploymentError::io(&path, error)),
        }
    }

    fn verify_current_state(&self) -> Result<(), DeploymentError> {
        let state = self.read_state()?;
        if state.in_flight.is_some() {
            return Err(DeploymentError::StateInvariant(
                "recovery left an in-flight operation".to_string(),
            ));
        }
        match (&state.active_artifact, self.active_snapshot_from_disk()?) {
            (None, None) => Ok(()),
            (Some(expected), Some(actual)) if expected == &actual => {
                self.read_blob(&expected.digest)?;
                Ok(())
            }
            (Some(expected), Some(actual)) => Err(DeploymentError::ActiveDigestMismatch {
                expected: expected.digest.clone(),
                actual: actual.digest,
            }),
            (Some(_), None) => Err(DeploymentError::StateInvariant(
                "state names an active artifact but the active file is missing".to_string(),
            )),
            (None, Some(_)) => Err(DeploymentError::StateInvariant(
                "active artifact exists without a durable state reference".to_string(),
            )),
        }
    }
}

#[derive(Debug)]
pub enum DeploymentError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    StateSerialization(serde_json::Error),
    InvalidField {
        field: &'static str,
    },
    UnsafePath {
        path: PathBuf,
        reason: &'static str,
    },
    UnsupportedSchema {
        expected: u32,
        actual: u32,
    },
    StateInvariant(String),
    EmptyArtifact,
    EmptyObservationEvidence,
    NotInitialized,
    AlreadyInitialized {
        active: ContentDigest,
    },
    CandidateDigestMismatch {
        expected: ContentDigest,
        actual: ContentDigest,
    },
    ActiveDigestMismatch {
        expected: ContentDigest,
        actual: ContentDigest,
    },
    ArtifactLengthMismatch {
        digest: ContentDigest,
        expected_len: u64,
        actual_len: u64,
    },
    NoArtifactChange {
        digest: ContentDigest,
    },
    OperationConflict {
        operation_id: String,
    },
    UnknownActivation {
        activation_id: String,
    },
    InactiveActivation {
        activation_id: String,
        active: ContentDigest,
    },
    StaleRollback {
        activation_id: String,
        expected_active: ContentDigest,
        actual_active: ContentDigest,
    },
    CorruptBlob {
        expected: ContentDigest,
        actual: ContentDigest,
    },
    RecoveryConflict {
        operation_id: String,
        expected_one_of: Vec<ContentDigest>,
        actual: Option<ContentDigest>,
    },
}

impl DeploymentError {
    fn io(path: impl AsRef<Path>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.as_ref().to_path_buf(),
            source,
        }
    }
}

impl Display for DeploymentError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(
                    formatter,
                    "deployment I/O error at '{}': {source}",
                    path.display()
                )
            }
            Self::StateSerialization(error) => {
                write!(formatter, "deployment state serialization error: {error}")
            }
            Self::InvalidField { field } => {
                write!(formatter, "deployment field '{field}' must not be blank")
            }
            Self::UnsafePath { path, reason } => {
                write!(
                    formatter,
                    "unsafe deployment path '{}': {reason}",
                    path.display()
                )
            }
            Self::UnsupportedSchema { expected, actual } => write!(
                formatter,
                "unsupported deployment state schema {actual}; expected {expected}"
            ),
            Self::StateInvariant(reason) => {
                write!(formatter, "invalid deployment state: {reason}")
            }
            Self::EmptyArtifact => write!(formatter, "deployment artifact must not be empty"),
            Self::EmptyObservationEvidence => {
                write!(formatter, "observation evidence bytes must not be empty")
            }
            Self::NotInitialized => write!(formatter, "deployment has no active incumbent"),
            Self::AlreadyInitialized { active } => {
                write!(formatter, "deployment is already initialized with {active}")
            }
            Self::CandidateDigestMismatch { expected, actual } => write!(
                formatter,
                "candidate digest mismatch: expected {expected}, got {actual}"
            ),
            Self::ActiveDigestMismatch { expected, actual } => write!(
                formatter,
                "active artifact digest mismatch: expected {expected}, got {actual}"
            ),
            Self::ArtifactLengthMismatch {
                digest,
                expected_len,
                actual_len,
            } => write!(
                formatter,
                "artifact {digest} length mismatch: expected {expected_len}, got {actual_len}"
            ),
            Self::NoArtifactChange { digest } => {
                write!(
                    formatter,
                    "candidate is identical to active artifact {digest}"
                )
            }
            Self::OperationConflict { operation_id } => write!(
                formatter,
                "operation id '{operation_id}' was already used for different inputs"
            ),
            Self::UnknownActivation { activation_id } => {
                write!(formatter, "unknown activation '{activation_id}'")
            }
            Self::InactiveActivation {
                activation_id,
                active,
            } => write!(
                formatter,
                "activation '{activation_id}' is not the active deployment (active: {active})"
            ),
            Self::StaleRollback {
                activation_id,
                expected_active,
                actual_active,
            } => write!(
                formatter,
                "rollback for '{activation_id}' is stale: expected active {expected_active}, got {actual_active}"
            ),
            Self::CorruptBlob { expected, actual } => write!(
                formatter,
                "content-addressed blob corruption: expected {expected}, got {actual}"
            ),
            Self::RecoveryConflict {
                operation_id,
                expected_one_of,
                actual,
            } => {
                let expected = expected_one_of
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(" or ");
                let actual = actual
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "no active artifact".to_string());
                write!(
                    formatter,
                    "cannot recover operation '{operation_id}': expected {expected}, got {actual}"
                )
            }
        }
    }
}

impl Error for DeploymentError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::StateSerialization(error) => Some(error),
            _ => None,
        }
    }
}

fn validate_activation_request(request: &ActivationRequest) -> Result<(), DeploymentError> {
    validate_identifier("operation_id", &request.operation_id)?;
    validate_identifier("approval_ref", &request.approval_ref)?;
    validate_identifier("comparison_ref", &request.comparison_ref)?;
    validate_identifier("observation_window_ref", &request.observation_window_ref)?;
    Ok(())
}

fn validate_observation_request(request: &ObservationRequest) -> Result<(), DeploymentError> {
    validate_identifier("observation_id", &request.observation_id)?;
    validate_identifier("activation_id", &request.activation_id)?;
    validate_identifier("summary", &request.summary)
}

fn validate_rollback_request(request: &RollbackRequest) -> Result<(), DeploymentError> {
    validate_identifier("operation_id", &request.operation_id)?;
    validate_identifier("activation_id", &request.activation_id)?;
    validate_identifier("reason_ref", &request.reason_ref)
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), DeploymentError> {
    if value.trim().is_empty() {
        Err(DeploymentError::InvalidField { field })
    } else {
        Ok(())
    }
}

fn validate_relative_candidate_path(path: &Path) -> Result<PathBuf, DeploymentError> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err(DeploymentError::UnsafePath {
            path: path.to_path_buf(),
            reason: "candidate path must be a nonempty relative path",
        });
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(segment) if segment.to_str().is_some() => normalized.push(segment),
            _ => {
                return Err(DeploymentError::UnsafePath {
                    path: path.to_path_buf(),
                    reason: "candidate path must contain only UTF-8 names without traversal or prefixes",
                });
            }
        }
    }
    if normalized.as_os_str().is_empty() {
        return Err(DeploymentError::UnsafePath {
            path: path.to_path_buf(),
            reason: "candidate path must name a file",
        });
    }
    Ok(normalized)
}

fn validate_state_structure(state: &DeploymentState) -> Result<(), DeploymentError> {
    if state.schema_version != DEPLOYMENT_STATE_SCHEMA_VERSION {
        return Err(DeploymentError::UnsupportedSchema {
            expected: DEPLOYMENT_STATE_SCHEMA_VERSION,
            actual: state.schema_version,
        });
    }
    let mut ids = BTreeSet::new();
    for id in state
        .initializations
        .iter()
        .map(|record| record.operation_id.as_str())
        .chain(
            state
                .activations
                .iter()
                .map(|record| record.operation_id.as_str()),
        )
        .chain(
            state
                .observations
                .iter()
                .map(|record| record.observation_id.as_str()),
        )
        .chain(
            state
                .rollbacks
                .iter()
                .map(|record| record.operation_id.as_str()),
        )
    {
        if id.trim().is_empty() || !ids.insert(id) {
            return Err(DeploymentError::StateInvariant(format!(
                "operation id '{id}' is blank or duplicated"
            )));
        }
    }

    for rollback in &state.rollbacks {
        let activation = state
            .activations
            .iter()
            .find(|record| record.operation_id == rollback.activation_id)
            .ok_or_else(|| {
                DeploymentError::StateInvariant(format!(
                    "rollback '{}' names missing activation '{}'",
                    rollback.operation_id, rollback.activation_id
                ))
            })?;
        if activation.rolled_back_by.as_deref() != Some(rollback.operation_id.as_str()) {
            return Err(DeploymentError::StateInvariant(format!(
                "rollback '{}' is not linked from activation '{}'",
                rollback.operation_id, rollback.activation_id
            )));
        }
    }
    for activation in &state.activations {
        if let Some(rollback_id) = &activation.rolled_back_by
            && !state.rollbacks.iter().any(|record| {
                record.operation_id == *rollback_id
                    && record.activation_id == activation.operation_id
            })
        {
            return Err(DeploymentError::StateInvariant(format!(
                "activation '{}' names missing rollback '{}'",
                activation.operation_id, rollback_id
            )));
        }
    }
    for observation in &state.observations {
        let activation_exists = state
            .activations
            .iter()
            .any(|record| record.operation_id == observation.activation_id);
        if !activation_exists {
            return Err(DeploymentError::StateInvariant(format!(
                "observation '{}' names missing activation '{}'",
                observation.observation_id, observation.activation_id
            )));
        }
    }

    if state.initializations.len() > 1 {
        return Err(DeploymentError::StateInvariant(
            "deployment may contain at most one initialization".to_string(),
        ));
    }
    if state.active_artifact.is_some() && state.initializations.is_empty() {
        return Err(DeploymentError::StateInvariant(
            "active deployment has no initialization record".to_string(),
        ));
    }
    if let Some(in_flight) = &state.in_flight {
        let operation_id = match in_flight {
            InFlightOperation::Initialization(pending) => pending.operation_id.as_str(),
            InFlightOperation::Activation(pending) => pending.record.operation_id.as_str(),
            InFlightOperation::Rollback(pending) => pending.record.operation_id.as_str(),
        };
        if operation_id.trim().is_empty() || ids.contains(operation_id) {
            return Err(DeploymentError::StateInvariant(format!(
                "in-flight operation id '{operation_id}' is blank or already completed"
            )));
        }
        match in_flight {
            InFlightOperation::Initialization(_) if state.active_artifact.is_some() => {
                return Err(DeploymentError::StateInvariant(
                    "initialization cannot be in flight after an active artifact is recorded"
                        .to_string(),
                ));
            }
            InFlightOperation::Activation(pending) => {
                if state.active_artifact.as_ref() != Some(&pending.record.previous_artifact) {
                    return Err(DeploymentError::StateInvariant(format!(
                        "in-flight activation '{}' does not start from the recorded active artifact",
                        pending.record.operation_id
                    )));
                }
            }
            InFlightOperation::Rollback(pending) => {
                let activation_exists = state.activations.iter().any(|activation| {
                    activation.operation_id == pending.record.activation_id
                        && activation.activated_artifact == pending.record.from_artifact
                        && activation.previous_artifact == pending.record.restored_artifact
                        && activation.rolled_back_by.is_none()
                });
                if !activation_exists
                    || state.active_artifact.as_ref() != Some(&pending.record.from_artifact)
                {
                    return Err(DeploymentError::StateInvariant(format!(
                        "in-flight rollback '{}' is not bound to the active activation",
                        pending.record.operation_id
                    )));
                }
            }
            InFlightOperation::Initialization(_) => {}
        }
    }
    Ok(())
}

fn activation_matches_request(
    record: &ActivationRecord,
    request: &ActivationRequest,
    candidate_relative: &Path,
) -> bool {
    record.candidate_source == candidate_relative
        && record.previous_artifact.digest == request.expected_active_digest
        && record.activated_artifact.digest == request.expected_candidate_digest
        && record.approval_ref == request.approval_ref
        && record.comparison_ref == request.comparison_ref
        && record.observation_window_ref == request.observation_window_ref
}

fn ensure_operation_id_unused(
    state: &DeploymentState,
    operation_id: &str,
) -> Result<(), DeploymentError> {
    if operation_id_is_used(state, operation_id) {
        Err(DeploymentError::OperationConflict {
            operation_id: operation_id.to_string(),
        })
    } else {
        Ok(())
    }
}

fn operation_id_is_used(state: &DeploymentState, operation_id: &str) -> bool {
    state
        .initializations
        .iter()
        .any(|record| record.operation_id == operation_id)
        || state
            .activations
            .iter()
            .any(|record| record.operation_id == operation_id)
        || state
            .observations
            .iter()
            .any(|record| record.observation_id == operation_id)
        || state
            .rollbacks
            .iter()
            .any(|record| record.operation_id == operation_id)
}

fn finalize_rollback_state(
    state: &mut DeploymentState,
    record: &RollbackRecord,
) -> Result<(), DeploymentError> {
    if !state
        .rollbacks
        .iter()
        .any(|item| item.operation_id == record.operation_id)
    {
        state.rollbacks.push(record.clone());
    }
    let activation = state
        .activations
        .iter_mut()
        .find(|item| item.operation_id == record.activation_id)
        .ok_or_else(|| DeploymentError::UnknownActivation {
            activation_id: record.activation_id.clone(),
        })?;
    match &activation.rolled_back_by {
        None => activation.rolled_back_by = Some(record.operation_id.clone()),
        Some(existing) if existing == &record.operation_id => {}
        Some(existing) => {
            return Err(DeploymentError::StateInvariant(format!(
                "activation '{}' is already linked to rollback '{}'",
                record.activation_id, existing
            )));
        }
    }
    state.active_artifact = Some(record.restored_artifact.clone());
    Ok(())
}

fn reject_terminal_symlink(path: &Path) -> Result<(), DeploymentError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(DeploymentError::UnsafePath {
            path: path.to_path_buf(),
            reason: "configured root must not be a symbolic link",
        }),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(DeploymentError::io(path, error)),
    }
}

fn reject_symlink_if_present(path: &Path) -> Result<(), DeploymentError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(DeploymentError::UnsafePath {
            path: path.to_path_buf(),
            reason: "service-owned path must not be a symbolic link",
        }),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(DeploymentError::io(path, error)),
    }
}

fn reject_non_regular_file(path: &Path, kind: &'static str) -> Result<(), DeploymentError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| DeploymentError::io(path, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(DeploymentError::UnsafePath {
            path: path.to_path_buf(),
            reason: match kind {
                "candidate artifact" => "candidate artifact must be a regular non-symlink file",
                "active artifact" => "active artifact must be a regular non-symlink file",
                "deployment state" => "deployment state must be a regular non-symlink file",
                _ => "content-addressed blob must be a regular non-symlink file",
            },
        });
    }
    Ok(())
}

fn ensure_owned_directory(root: &Path, name: &'static str) -> Result<(), DeploymentError> {
    let path = root.join(name);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            Err(DeploymentError::UnsafePath {
                path,
                reason: "service-owned directory must be a non-symlink directory",
            })
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(&path).map_err(|error| DeploymentError::io(&path, error))
        }
        Err(error) => Err(DeploymentError::io(&path, error)),
    }
}

fn read_file(path: &Path) -> Result<Vec<u8>, DeploymentError> {
    let mut file = File::open(path).map_err(|error| DeploymentError::io(path, error))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| DeploymentError::io(path, error))?;
    Ok(bytes)
}

fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<(), DeploymentError> {
    reject_symlink_if_present(path)?;
    let temporary_path = unique_temporary_path(path)?;
    let result = write_and_sync_new(&temporary_path, bytes).and_then(|()| {
        fs::rename(&temporary_path, path).map_err(|error| DeploymentError::io(path, error))?;
        sync_parent(path)
    });
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}

fn atomic_write_new(path: &Path, bytes: &[u8]) -> Result<(), DeploymentError> {
    reject_symlink_if_present(path)?;
    if path.exists() {
        return Err(DeploymentError::StateInvariant(format!(
            "refusing to overwrite immutable blob '{}'",
            path.display()
        )));
    }
    let temporary_path = unique_temporary_path(path)?;
    let result = write_and_sync_new(&temporary_path, bytes).and_then(|()| {
        // A hard link publishes the fully-synced temporary inode without ever
        // replacing an existing immutable digest path.
        match fs::hard_link(&temporary_path, path) {
            Ok(()) => {
                fs::remove_file(&temporary_path)
                    .map_err(|error| DeploymentError::io(&temporary_path, error))?;
                sync_parent(path)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                fs::remove_file(&temporary_path)
                    .map_err(|error| DeploymentError::io(&temporary_path, error))?;
                reject_non_regular_file(path, "content-addressed blob")?;
                let existing = read_file(path)?;
                if existing == bytes {
                    Ok(())
                } else {
                    Err(DeploymentError::StateInvariant(format!(
                        "immutable blob path '{}' already contains different bytes",
                        path.display()
                    )))
                }
            }
            Err(error) => Err(DeploymentError::io(path, error)),
        }
    });
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}

fn write_and_sync_new(path: &Path, bytes: &[u8]) -> Result<(), DeploymentError> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| DeploymentError::io(path, error))?;
    file.write_all(bytes)
        .map_err(|error| DeploymentError::io(path, error))?;
    file.sync_all()
        .map_err(|error| DeploymentError::io(path, error))
}

fn sync_parent(path: &Path) -> Result<(), DeploymentError> {
    let parent = path.parent().ok_or_else(|| {
        DeploymentError::StateInvariant(format!("path '{}' has no parent", path.display()))
    })?;
    let directory = File::open(parent).map_err(|error| DeploymentError::io(parent, error))?;
    directory
        .sync_all()
        .map_err(|error| DeploymentError::io(parent, error))
}

fn unique_temporary_path(path: &Path) -> Result<PathBuf, DeploymentError> {
    let parent = path.parent().ok_or_else(|| {
        DeploymentError::StateInvariant(format!("path '{}' has no parent", path.display()))
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        DeploymentError::StateInvariant(format!("path '{}' has no file name", path.display()))
    })?;
    for _ in 0..64 {
        let sequence = TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(
            ".{}.{}.{}.tmp",
            file_name.to_string_lossy(),
            std::process::id(),
            sequence
        ));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(DeploymentError::StateInvariant(format!(
        "could not allocate a temporary file beside '{}'",
        path.display()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    struct TestTree {
        root: PathBuf,
        candidates: PathBuf,
        deployment: PathBuf,
    }

    impl TestTree {
        fn new(label: &str) -> Self {
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "aiaf-deployment-{label}-{}-{sequence}",
                std::process::id()
            ));
            let candidates = root.join("candidates");
            let deployment = root.join("deployment");
            fs::create_dir_all(&candidates).unwrap();
            Self {
                root,
                candidates,
                deployment,
            }
        }

        fn service(&self) -> LocalDeploymentService {
            LocalDeploymentService::open(&self.deployment, &self.candidates).unwrap()
        }

        fn write_candidate(&self, relative: &str, bytes: &[u8]) {
            let path = self.candidates.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, bytes).unwrap();
        }
    }

    impl Drop for TestTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn activation_request(
        candidate_path: &str,
        candidate: &[u8],
        incumbent: &[u8],
    ) -> ActivationRequest {
        ActivationRequest {
            operation_id: "activation-1".to_string(),
            candidate_path: PathBuf::from(candidate_path),
            expected_candidate_digest: ContentDigest::from_bytes(candidate),
            expected_active_digest: ContentDigest::from_bytes(incumbent),
            approval_ref: "approval:1".to_string(),
            comparison_ref: "comparison:1".to_string(),
            observation_window_ref: "observation-window:1".to_string(),
        }
    }

    fn activate_fixture(
        tree: &TestTree,
        incumbent: &[u8],
        candidate: &[u8],
    ) -> (LocalDeploymentService, ActivationRecord) {
        tree.write_candidate("candidate.bin", candidate);
        let service = tree.service();
        service
            .initialize_active("initialize-1", incumbent)
            .unwrap();
        let record = service
            .activate(&activation_request("candidate.bin", candidate, incumbent))
            .unwrap();
        (service, record)
    }

    #[test]
    fn activation_captures_exact_incumbent_and_survives_reopen() {
        let tree = TestTree::new("activation");
        let incumbent = b"incumbent-exact-bytes";
        let candidate = b"candidate-exact-bytes";
        let (service, record) = activate_fixture(&tree, incumbent, candidate);

        assert_eq!(service.read_active_bytes().unwrap(), candidate);
        assert_eq!(
            service.read_blob(&record.previous_artifact.digest).unwrap(),
            incumbent
        );
        assert_eq!(
            service
                .read_blob(&record.activated_artifact.digest)
                .unwrap(),
            candidate
        );
        assert_eq!(
            record.previous_artifact.digest,
            ContentDigest::from_bytes(incumbent)
        );
        assert_eq!(
            record.activated_artifact.digest,
            ContentDigest::from_bytes(candidate)
        );

        drop(service);
        let reopened = tree.service();
        let state = reopened.state().unwrap();
        assert_eq!(state.activations, vec![record]);
        assert_eq!(reopened.read_active_bytes().unwrap(), candidate);
    }

    #[test]
    fn initialization_and_activation_are_idempotent_but_keys_are_input_bound() {
        let tree = TestTree::new("idempotency");
        let incumbent = b"incumbent";
        let candidate = b"candidate";
        tree.write_candidate("candidate.bin", candidate);
        let service = tree.service();

        let first_initialization = service
            .initialize_active("initialize-1", incumbent)
            .unwrap();
        assert_eq!(
            service
                .initialize_active("initialize-1", incumbent)
                .unwrap(),
            first_initialization
        );
        assert!(matches!(
            service.initialize_active("initialize-1", b"different"),
            Err(DeploymentError::OperationConflict { .. })
        ));

        let request = activation_request("candidate.bin", candidate, incumbent);
        let first_activation = service.activate(&request).unwrap();
        assert_eq!(service.activate(&request).unwrap(), first_activation);
        fs::remove_file(tree.candidates.join("candidate.bin")).unwrap();
        assert_eq!(service.activate(&request).unwrap(), first_activation);

        let mut conflicting = request;
        conflicting.approval_ref = "approval:different".to_string();
        assert!(matches!(
            service.activate(&conflicting),
            Err(DeploymentError::OperationConflict { .. })
        ));
        assert_eq!(service.state().unwrap().activations.len(), 1);
    }

    #[test]
    fn digest_or_incumbent_mismatch_cannot_change_active_bytes() {
        let tree = TestTree::new("digest-mismatch");
        let incumbent = b"incumbent";
        let candidate = b"candidate";
        tree.write_candidate("candidate.bin", candidate);
        let service = tree.service();
        service
            .initialize_active("initialize-1", incumbent)
            .unwrap();

        let mut candidate_mismatch = activation_request("candidate.bin", candidate, incumbent);
        candidate_mismatch.expected_candidate_digest = ContentDigest::from_bytes(b"invented");
        assert!(matches!(
            service.activate(&candidate_mismatch),
            Err(DeploymentError::CandidateDigestMismatch { .. })
        ));
        assert_eq!(service.read_active_bytes().unwrap(), incumbent);

        let mut incumbent_mismatch = activation_request("candidate.bin", candidate, incumbent);
        incumbent_mismatch.expected_active_digest = ContentDigest::from_bytes(b"stale");
        assert!(matches!(
            service.activate(&incumbent_mismatch),
            Err(DeploymentError::ActiveDigestMismatch { .. })
        ));
        assert_eq!(service.read_active_bytes().unwrap(), incumbent);
    }

    #[test]
    fn traversal_and_absolute_candidate_paths_are_rejected_without_effect() {
        let tree = TestTree::new("path-containment");
        let external = tree.root.join("external.bin");
        fs::write(&external, b"external").unwrap();
        let service = tree.service();
        service
            .initialize_active("initialize-1", b"incumbent")
            .unwrap();

        let mut traversal = activation_request("../external.bin", b"external", b"incumbent");
        assert!(matches!(
            service.activate(&traversal),
            Err(DeploymentError::UnsafePath { .. })
        ));

        traversal.candidate_path = external.clone();
        assert!(matches!(
            service.activate(&traversal),
            Err(DeploymentError::UnsafePath { .. })
        ));
        assert_eq!(service.read_active_bytes().unwrap(), b"incumbent");
        assert_eq!(fs::read(external).unwrap(), b"external");
    }

    #[cfg(unix)]
    #[test]
    fn candidate_symlink_escape_is_rejected_without_reading_target() {
        use std::os::unix::fs::symlink;

        let tree = TestTree::new("symlink");
        let external = tree.root.join("external.bin");
        fs::write(&external, b"secret-external").unwrap();
        symlink(&external, tree.candidates.join("candidate.bin")).unwrap();
        let service = tree.service();
        service
            .initialize_active("initialize-1", b"incumbent")
            .unwrap();

        let request = activation_request("candidate.bin", b"secret-external", b"incumbent");
        assert!(matches!(
            service.activate(&request),
            Err(DeploymentError::UnsafePath { .. })
        ));
        assert_eq!(service.read_active_bytes().unwrap(), b"incumbent");
    }

    #[test]
    fn observation_is_bound_to_active_and_evidence_digests_and_is_durable() {
        let tree = TestTree::new("observation");
        let candidate = b"candidate";
        let (service, activation) = activate_fixture(&tree, b"incumbent", candidate);
        let activation_id = activation.operation_id.clone();
        let request = ObservationRequest {
            observation_id: "observation-1".to_string(),
            activation_id: activation_id.clone(),
            expected_active_digest: ContentDigest::from_bytes(candidate),
            outcome: ObservationOutcome::Healthy,
            summary: "reference workload returned the expected output".to_string(),
        };
        let evidence = br#"{"input":41,"output":42,"passed":true}"#;
        let record = service.record_observation(&request, evidence).unwrap();

        assert_eq!(
            record.observed_artifact.digest,
            ContentDigest::from_bytes(candidate)
        );
        assert_eq!(record.evidence.digest, ContentDigest::from_bytes(evidence));
        assert_eq!(
            service.read_blob(&record.evidence.digest).unwrap(),
            evidence
        );
        assert_eq!(
            service.record_observation(&request, evidence).unwrap(),
            record
        );
        assert_eq!(service.state().unwrap().observations.len(), 1);

        service
            .rollback(&RollbackRequest {
                operation_id: "rollback-1".to_string(),
                activation_id,
                reason_ref: "reason:after-observation".to_string(),
            })
            .unwrap();
        assert_eq!(
            service.record_observation(&request, evidence).unwrap(),
            record
        );

        drop(service);
        assert_eq!(tree.service().state().unwrap().observations, vec![record]);
    }

    #[test]
    fn observation_refuses_inactive_or_conflicting_evidence() {
        let tree = TestTree::new("observation-refusal");
        let candidate = b"candidate";
        let (service, activation) = activate_fixture(&tree, b"incumbent", candidate);
        let mut request = ObservationRequest {
            observation_id: "observation-1".to_string(),
            activation_id: activation.operation_id,
            expected_active_digest: ContentDigest::from_bytes(candidate),
            outcome: ObservationOutcome::Healthy,
            summary: "healthy".to_string(),
        };
        service.record_observation(&request, b"evidence-a").unwrap();
        assert!(matches!(
            service.record_observation(&request, b"evidence-b"),
            Err(DeploymentError::OperationConflict { .. })
        ));

        request.observation_id = "observation-2".to_string();
        request.activation_id = "missing".to_string();
        assert!(matches!(
            service.record_observation(&request, b"evidence"),
            Err(DeploymentError::UnknownActivation { .. })
        ));
    }

    #[test]
    fn rollback_restores_exact_bytes_and_is_idempotent_across_restart() {
        let tree = TestTree::new("rollback");
        let incumbent = b"incumbent-exact";
        let candidate = b"candidate-exact";
        let (service, activation) = activate_fixture(&tree, incumbent, candidate);
        let request = RollbackRequest {
            operation_id: "rollback-1".to_string(),
            activation_id: activation.operation_id.clone(),
            reason_ref: "observation:regression".to_string(),
        };
        let first = service.rollback(&request).unwrap();
        assert_eq!(service.read_active_bytes().unwrap(), incumbent);
        assert_eq!(first.restored_artifact, activation.previous_artifact);
        assert_eq!(service.rollback(&request).unwrap(), first);

        // A fresh id for an already-completed activation is also a no-op and
        // resolves to the first durable rollback.
        let repeated = RollbackRequest {
            operation_id: "rollback-retry".to_string(),
            ..request
        };
        assert_eq!(service.rollback(&repeated).unwrap(), first);
        assert_eq!(service.state().unwrap().rollbacks.len(), 1);

        drop(service);
        let reopened = tree.service();
        assert_eq!(reopened.read_active_bytes().unwrap(), incumbent);
        assert_eq!(reopened.state().unwrap().rollbacks, vec![first]);
    }

    #[test]
    fn stale_rollback_cannot_clobber_a_later_activation() {
        let tree = TestTree::new("stale-rollback");
        tree.write_candidate("candidate-1.bin", b"candidate-1");
        tree.write_candidate("candidate-2.bin", b"candidate-2");
        let service = tree.service();
        service
            .initialize_active("initialize-1", b"incumbent")
            .unwrap();
        let first = service
            .activate(&activation_request(
                "candidate-1.bin",
                b"candidate-1",
                b"incumbent",
            ))
            .unwrap();
        let mut second_request =
            activation_request("candidate-2.bin", b"candidate-2", b"candidate-1");
        second_request.operation_id = "activation-2".to_string();
        let second = service.activate(&second_request).unwrap();

        assert!(matches!(
            service.rollback(&RollbackRequest {
                operation_id: "rollback-1".to_string(),
                activation_id: first.operation_id,
                reason_ref: "reason:stale".to_string(),
            }),
            Err(DeploymentError::StaleRollback { .. })
        ));
        assert_eq!(service.read_active_bytes().unwrap(), b"candidate-2");

        service
            .rollback(&RollbackRequest {
                operation_id: "rollback-2".to_string(),
                activation_id: second.operation_id,
                reason_ref: "reason:current".to_string(),
            })
            .unwrap();
        assert_eq!(service.read_active_bytes().unwrap(), b"candidate-1");
    }

    #[test]
    fn reopen_completes_activation_persisted_before_the_effect() {
        let tree = TestTree::new("recover-activation-before");
        let incumbent = b"incumbent";
        let candidate = b"candidate";
        tree.write_candidate("candidate.bin", candidate);
        let service = tree.service();
        service
            .initialize_active("initialize-1", incumbent)
            .unwrap();
        let mut state = service.state().unwrap();
        let record = ActivationRecord {
            operation_id: "activation-recover".to_string(),
            candidate_source: PathBuf::from("candidate.bin"),
            previous_artifact: service.persist_blob(incumbent).unwrap(),
            activated_artifact: service.persist_blob(candidate).unwrap(),
            approval_ref: "approval:recover".to_string(),
            comparison_ref: "comparison:recover".to_string(),
            observation_window_ref: "window:recover".to_string(),
            rolled_back_by: None,
        };
        state.in_flight = Some(InFlightOperation::Activation(PendingActivation {
            record: record.clone(),
        }));
        service.write_state(&state).unwrap();
        drop(service);

        let recovered = tree.service();
        assert_eq!(recovered.read_active_bytes().unwrap(), candidate);
        assert_eq!(recovered.state().unwrap().activations, vec![record]);
        assert!(recovered.state().unwrap().in_flight.is_none());
    }

    #[test]
    fn reopen_completes_initialization_persisted_before_the_effect() {
        let tree = TestTree::new("recover-initialization");
        let service = tree.service();
        let snapshot = service.persist_blob(b"incumbent").unwrap();
        let mut state = service.state().unwrap();
        state.in_flight = Some(InFlightOperation::Initialization(PendingInitialization {
            operation_id: "initialize-recover".to_string(),
            target_artifact: snapshot.clone(),
        }));
        service.write_state(&state).unwrap();
        drop(service);

        let recovered = tree.service();
        assert_eq!(recovered.read_active_bytes().unwrap(), b"incumbent");
        assert_eq!(
            recovered.state().unwrap().initializations,
            vec![InitializationRecord {
                operation_id: "initialize-recover".to_string(),
                installed_artifact: snapshot,
            }]
        );
    }

    #[test]
    fn reopen_finalizes_activation_persisted_after_the_effect() {
        let tree = TestTree::new("recover-activation-after");
        let incumbent = b"incumbent";
        let candidate = b"candidate";
        let service = tree.service();
        service
            .initialize_active("initialize-1", incumbent)
            .unwrap();
        let mut state = service.state().unwrap();
        let record = ActivationRecord {
            operation_id: "activation-recover".to_string(),
            candidate_source: PathBuf::from("candidate.bin"),
            previous_artifact: service.persist_blob(incumbent).unwrap(),
            activated_artifact: service.persist_blob(candidate).unwrap(),
            approval_ref: "approval:recover".to_string(),
            comparison_ref: "comparison:recover".to_string(),
            observation_window_ref: "window:recover".to_string(),
            rolled_back_by: None,
        };
        state.in_flight = Some(InFlightOperation::Activation(PendingActivation {
            record: record.clone(),
        }));
        service.write_state(&state).unwrap();
        service.atomic_replace_active(candidate).unwrap();
        drop(service);

        let recovered = tree.service();
        assert_eq!(recovered.read_active_bytes().unwrap(), candidate);
        assert_eq!(recovered.state().unwrap().activations, vec![record]);
    }

    #[test]
    fn reopen_completes_interrupted_rollback_once() {
        let tree = TestTree::new("recover-rollback");
        let (service, activation) = activate_fixture(&tree, b"incumbent", b"candidate");
        let mut state = service.state().unwrap();
        let record = RollbackRecord {
            operation_id: "rollback-recover".to_string(),
            activation_id: activation.operation_id,
            from_artifact: activation.activated_artifact,
            restored_artifact: activation.previous_artifact,
            reason_ref: "reason:recover".to_string(),
        };
        state.in_flight = Some(InFlightOperation::Rollback(PendingRollback {
            record: record.clone(),
        }));
        service.write_state(&state).unwrap();
        drop(service);

        let recovered = tree.service();
        assert_eq!(recovered.read_active_bytes().unwrap(), b"incumbent");
        assert_eq!(recovered.state().unwrap().rollbacks, vec![record]);
        assert!(recovered.state().unwrap().in_flight.is_none());
    }

    #[test]
    fn recovery_refuses_to_overwrite_an_unrelated_active_artifact() {
        let tree = TestTree::new("recover-conflict");
        let incumbent = b"incumbent";
        let candidate = b"candidate";
        let service = tree.service();
        service
            .initialize_active("initialize-1", incumbent)
            .unwrap();
        let mut state = service.state().unwrap();
        let record = ActivationRecord {
            operation_id: "activation-recover".to_string(),
            candidate_source: PathBuf::from("candidate.bin"),
            previous_artifact: service.persist_blob(incumbent).unwrap(),
            activated_artifact: service.persist_blob(candidate).unwrap(),
            approval_ref: "approval:recover".to_string(),
            comparison_ref: "comparison:recover".to_string(),
            observation_window_ref: "window:recover".to_string(),
            rolled_back_by: None,
        };
        state.in_flight = Some(InFlightOperation::Activation(PendingActivation { record }));
        service.write_state(&state).unwrap();
        fs::write(service.active_artifact_path(), b"unrelated").unwrap();
        drop(service);

        assert!(matches!(
            LocalDeploymentService::open(&tree.deployment, &tree.candidates),
            Err(DeploymentError::RecoveryConflict { .. })
        ));
        assert_eq!(
            fs::read(
                tree.deployment
                    .join(ACTIVE_DIRECTORY_NAME)
                    .join(ACTIVE_FILE_NAME)
            )
            .unwrap(),
            b"unrelated"
        );
    }

    #[test]
    fn external_active_tampering_is_detected_on_reopen() {
        let tree = TestTree::new("tamper");
        let service = tree.service();
        service
            .initialize_active("initialize-1", b"incumbent")
            .unwrap();
        fs::write(service.active_artifact_path(), b"tampered").unwrap();
        drop(service);

        assert!(matches!(
            LocalDeploymentService::open(&tree.deployment, &tree.candidates),
            Err(DeploymentError::ActiveDigestMismatch { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn service_owned_symlink_is_rejected() {
        use std::os::unix::fs::symlink;

        let tree = TestTree::new("owned-symlink");
        fs::create_dir_all(&tree.deployment).unwrap();
        let external = tree.root.join("external");
        fs::create_dir_all(&external).unwrap();
        symlink(&external, tree.deployment.join(BLOB_DIRECTORY_NAME)).unwrap();

        assert!(matches!(
            LocalDeploymentService::open(&tree.deployment, &tree.candidates),
            Err(DeploymentError::UnsafePath { .. })
        ));
    }

    #[test]
    fn unsupported_or_corrupt_state_is_rejected() {
        let tree = TestTree::new("state-schema");
        let service = tree.service();
        let mut state = service.state().unwrap();
        state.schema_version = DEPLOYMENT_STATE_SCHEMA_VERSION + 1;
        let bytes = serde_json::to_vec_pretty(&state).unwrap();
        atomic_replace(&service.state_path(), &bytes).unwrap();
        drop(service);

        assert!(matches!(
            LocalDeploymentService::open(&tree.deployment, &tree.candidates),
            Err(DeploymentError::UnsupportedSchema { .. })
        ));
    }
}
