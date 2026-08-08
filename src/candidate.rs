//! Effectful candidate workspaces for the bounded M1 reference task.
//!
//! This module intentionally does not provide a general-purpose source editor.
//! A workspace contains the frozen `component.wit` interface and one mutable
//! `component.wat` implementation. All workspace effects are anchored beneath a
//! service-owned root, and all identities used by this API are SHA-256 content
//! identities.

use crate::execution::artifact::{
    ArtifactDigest, ArtifactError, ContentDigest, GenerationManifest, digest_json_content,
};
use crate::execution::component::{
    ComponentBuildError, ComponentBuildOutput, ComponentBuildRequest, ComponentExecutionLimits,
    ComponentI32ExecutionTrace, build_component_package, execute_component_i32_export,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub const COMPONENT_WAT_PATH: &str = "component.wat";
pub const COMPONENT_WIT_PATH: &str = "component.wit";
pub const REFERENCE_TASK_WORLD: &str = "reference-task";
pub const REFERENCE_TASK_EXPORT: &str = "transform";
pub const REFERENCE_TASK_INTERFACE_REF: &str = "wit:wasm-biotic:reference-task/reference-task@v1";
pub const REFERENCE_TASK_CAPABILITY_REF: &str = "world:reference-task";
pub const REFERENCE_TASK_MAX_FILES: usize = 2;
pub const REFERENCE_TASK_MAX_SOURCE_BYTES: u64 = 65_536;
pub const REFERENCE_TASK_MAX_COMPONENT_BYTES: usize = 1_048_576;
pub const REFERENCE_TASK_FUEL: u64 = 1_000_000;

const TREE_DOMAIN: &[u8] = b"wasm-biotic:candidate-tree:v1\0";
const PROVING_SUITE_ID: &str = "m1-reference-transform-v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateTreeEntry {
    pub relative_path: String,
    pub byte_len: u64,
    pub content_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateWorkspaceSnapshot {
    pub workspace_id: String,
    pub workspace_ref: String,
    pub mutable_paths: Vec<String>,
    pub immutable_paths: Vec<String>,
    pub entries: Vec<CandidateTreeEntry>,
    pub total_source_bytes: u64,
    pub tree_digest: ContentDigest,
}

impl CandidateWorkspaceSnapshot {
    pub fn entry(&self, relative_path: &str) -> Option<&CandidateTreeEntry> {
        self.entries
            .iter()
            .find(|entry| entry.relative_path == relative_path)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateFileReplacement {
    pub relative_path: String,
    pub expected_before_digest: ContentDigest,
    pub replacement_bytes: Vec<u8>,
}

impl CandidateFileReplacement {
    pub fn new(
        relative_path: impl Into<String>,
        expected_before_digest: ContentDigest,
        replacement_bytes: Vec<u8>,
    ) -> Self {
        Self {
            relative_path: relative_path.into(),
            expected_before_digest,
            replacement_bytes,
        }
    }
}

/// A full-file replacement is deliberately used as the bounded patch format.
///
/// Keeping both byte sequences makes the record independently reconstructable
/// in either direction. The digests prevent applying it to an unrelated base.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconstructableFileReplacement {
    pub relative_path: String,
    pub before_digest: ContentDigest,
    pub after_digest: ContentDigest,
    pub before_bytes: Vec<u8>,
    pub after_bytes: Vec<u8>,
}

impl ReconstructableFileReplacement {
    pub fn reconstruct_after(
        &self,
        supplied_before: &[u8],
    ) -> Result<Vec<u8>, CandidateWorkspaceError> {
        let actual = ContentDigest::from_bytes(supplied_before);
        if actual != self.before_digest {
            return Err(CandidateWorkspaceError::ReconstructionDigestMismatch {
                direction: "forward",
                expected: self.before_digest.clone(),
                actual,
            });
        }
        Ok(self.after_bytes.clone())
    }

    pub fn reconstruct_before(
        &self,
        supplied_after: &[u8],
    ) -> Result<Vec<u8>, CandidateWorkspaceError> {
        let actual = ContentDigest::from_bytes(supplied_after);
        if actual != self.after_digest {
            return Err(CandidateWorkspaceError::ReconstructionDigestMismatch {
                direction: "reverse",
                expected: self.after_digest.clone(),
                actual,
            });
        }
        Ok(self.before_bytes.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaterializedCandidatePatchset {
    pub workspace_id: String,
    pub before: CandidateWorkspaceSnapshot,
    pub after: CandidateWorkspaceSnapshot,
    pub changes: Vec<ReconstructableFileReplacement>,
    pub patchset_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateBuild {
    pub workspace: CandidateWorkspaceSnapshot,
    pub source_tree_digest: ContentDigest,
    pub wit_digest: ContentDigest,
    pub wat_digest: ContentDigest,
    /// Cryptographic package identity derived from the produced component bytes.
    pub package_digest: ContentDigest,
    pub component: ComponentBuildOutput,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceProvingCase {
    pub case_id: String,
    pub input: i32,
    pub expected_output: i32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceProvingObservation {
    pub case_id: String,
    pub input: i32,
    pub expected_output: i32,
    pub actual_output: Option<i32>,
    pub passed: bool,
    pub trace: ComponentI32ExecutionTrace,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceProvingReport {
    pub suite_id: String,
    pub suite_digest: ContentDigest,
    pub component_digest: ContentDigest,
    pub observations: Vec<ReferenceProvingObservation>,
    pub passed_count: usize,
    pub overall_pass: bool,
    pub report_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CandidateComparisonDecision {
    ChallengerPreferred,
    Equivalent,
    IncumbentRetained,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateComparison {
    pub suite_digest: ContentDigest,
    pub incumbent_component_digest: ContentDigest,
    pub challenger_component_digest: ContentDigest,
    pub incumbent_passed_count: usize,
    pub challenger_passed_count: usize,
    pub decision: CandidateComparisonDecision,
    pub eligible_for_activation: bool,
    pub rationale: String,
    pub comparison_digest: ContentDigest,
}

/// Owns all filesystem effects for bounded candidate workspaces.
///
/// The canonical root, `workspaces/`, and `.staging/` directories are retained
/// as anchors. Workspace ids are safe single path components, and callers never
/// supply an absolute effect path.
#[derive(Debug)]
pub struct CandidateWorkspaceService {
    canonical_root: PathBuf,
    workspaces_root: PathBuf,
    staging_root: PathBuf,
    temporary_sequence: AtomicU64,
}

impl CandidateWorkspaceService {
    pub fn bootstrap(root: impl AsRef<Path>) -> Result<Self, CandidateWorkspaceError> {
        let requested_root = root.as_ref();
        reject_symlink_if_present(requested_root)?;
        fs::create_dir_all(requested_root)
            .map_err(|source| io_error("create candidate service root", requested_root, source))?;
        let canonical_root = fs::canonicalize(requested_root).map_err(|source| {
            io_error(
                "canonicalize candidate service root",
                requested_root,
                source,
            )
        })?;

        let workspaces_root = canonical_root.join("workspaces");
        let staging_root = canonical_root.join(".staging");
        create_real_directory(&workspaces_root)?;
        create_real_directory(&staging_root)?;

        let workspaces_root = fs::canonicalize(&workspaces_root)
            .map_err(|source| io_error("canonicalize workspace root", &workspaces_root, source))?;
        let staging_root = fs::canonicalize(&staging_root)
            .map_err(|source| io_error("canonicalize staging root", &staging_root, source))?;
        ensure_direct_child(&canonical_root, &workspaces_root)?;
        ensure_direct_child(&canonical_root, &staging_root)?;

        Ok(Self {
            canonical_root,
            workspaces_root,
            staging_root,
            temporary_sequence: AtomicU64::new(0),
        })
    }

    pub fn canonical_root(&self) -> &Path {
        &self.canonical_root
    }

    pub fn workspace_path(&self, workspace_id: &str) -> Result<PathBuf, CandidateWorkspaceError> {
        self.validated_workspace_path(workspace_id)
    }

    /// Copies the two-file frozen template into a fresh service-owned workspace.
    ///
    /// Template validation is completed before the target directory is created,
    /// so traversal, symlink, shape, and size failures have no workspace effect.
    pub fn open_workspace(
        &self,
        workspace_id: &str,
        template_root: impl AsRef<Path>,
    ) -> Result<CandidateWorkspaceSnapshot, CandidateWorkspaceError> {
        self.verify_service_roots()?;
        validate_workspace_id(workspace_id)?;
        let template_root = template_root.as_ref();
        let template = read_fixed_tree(template_root)?;
        let target = self.workspaces_root.join(workspace_id);
        ensure_lexically_beneath(&self.workspaces_root, &target)?;
        if fs::symlink_metadata(&target).is_ok() {
            return Err(CandidateWorkspaceError::WorkspaceAlreadyExists {
                workspace_id: workspace_id.to_string(),
            });
        }

        fs::create_dir(&target)
            .map_err(|source| io_error("create candidate workspace", &target, source))?;
        let copy_result = (|| {
            for (relative_path, bytes) in &template.files {
                let destination = target.join(relative_path);
                let mut destination_file = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&destination)
                    .map_err(|source| io_error("create workspace file", &destination, source))?;
                destination_file
                    .write_all(bytes)
                    .map_err(|source| io_error("write workspace file", &destination, source))?;
                destination_file
                    .sync_all()
                    .map_err(|source| io_error("sync workspace file", &destination, source))?;
            }

            let immutable_path = target.join(COMPONENT_WIT_PATH);
            let mut permissions = fs::metadata(&immutable_path)
                .map_err(|source| {
                    io_error("read immutable file permissions", &immutable_path, source)
                })?
                .permissions();
            permissions.set_readonly(true);
            fs::set_permissions(&immutable_path, permissions).map_err(|source| {
                io_error("make frozen interface read-only", &immutable_path, source)
            })?;
            File::open(&target)
                .and_then(|directory| directory.sync_all())
                .map_err(|source| io_error("sync candidate workspace", &target, source))
        })();

        if let Err(error) = copy_result {
            let _ = fs::remove_dir_all(&target);
            return Err(error);
        }

        match self.snapshot(workspace_id) {
            Ok(snapshot) => Ok(snapshot),
            Err(error) => {
                let _ = fs::remove_dir_all(&target);
                Err(error)
            }
        }
    }

    pub fn snapshot(
        &self,
        workspace_id: &str,
    ) -> Result<CandidateWorkspaceSnapshot, CandidateWorkspaceError> {
        let workspace_path = self.validated_workspace_path(workspace_id)?;
        let tree = read_fixed_tree(&workspace_path)?;
        Ok(tree.snapshot(workspace_id))
    }

    /// Materializes the sole allowed mutation as an atomic full-file replacement.
    ///
    /// Exactly one `component.wat` replacement is accepted. All policy and
    /// expected-digest checks happen before a temporary file is created.
    pub fn materialize_patchset(
        &self,
        workspace_id: &str,
        replacements: &[CandidateFileReplacement],
    ) -> Result<MaterializedCandidatePatchset, CandidateWorkspaceError> {
        if replacements.len() != 1 {
            return Err(CandidateWorkspaceError::InvalidPatchCount {
                expected: 1,
                actual: replacements.len(),
            });
        }
        let replacement = &replacements[0];
        validate_relative_path(&replacement.relative_path)?;
        if replacement.relative_path != COMPONENT_WAT_PATH {
            return Err(CandidateWorkspaceError::MutationNotAllowed {
                requested: replacement.relative_path.clone(),
                allowed: COMPONENT_WAT_PATH.to_string(),
            });
        }
        if replacement.replacement_bytes.is_empty() {
            return Err(CandidateWorkspaceError::EmptyReplacement);
        }

        let workspace_path = self.validated_workspace_path(workspace_id)?;
        let target = validated_regular_file(&workspace_path, &replacement.relative_path)?;
        let before = self.snapshot(workspace_id)?;
        let before_bytes = read_bounded_file(&target, REFERENCE_TASK_MAX_SOURCE_BYTES)?;
        let actual_before_digest = ContentDigest::from_bytes(&before_bytes);
        if actual_before_digest != replacement.expected_before_digest {
            return Err(CandidateWorkspaceError::PatchBaseDigestMismatch {
                expected: replacement.expected_before_digest.clone(),
                actual: actual_before_digest,
            });
        }
        if before_bytes == replacement.replacement_bytes {
            return Err(CandidateWorkspaceError::PatchDoesNotChangeBytes);
        }

        let immutable_bytes = before
            .entry(COMPONENT_WIT_PATH)
            .map(|entry| entry.byte_len)
            .ok_or_else(|| CandidateWorkspaceError::InvalidTreeShape {
                expected: expected_paths(),
                actual: before
                    .entries
                    .iter()
                    .map(|entry| entry.relative_path.clone())
                    .collect(),
            })?;
        let replacement_len = u64::try_from(replacement.replacement_bytes.len()).map_err(|_| {
            CandidateWorkspaceError::SourceSizeLimitExceeded {
                limit: REFERENCE_TASK_MAX_SOURCE_BYTES,
                actual: u64::MAX,
            }
        })?;
        let resulting_total = immutable_bytes.checked_add(replacement_len).ok_or(
            CandidateWorkspaceError::SourceSizeLimitExceeded {
                limit: REFERENCE_TASK_MAX_SOURCE_BYTES,
                actual: u64::MAX,
            },
        )?;
        if resulting_total > REFERENCE_TASK_MAX_SOURCE_BYTES {
            return Err(CandidateWorkspaceError::SourceSizeLimitExceeded {
                limit: REFERENCE_TASK_MAX_SOURCE_BYTES,
                actual: resulting_total,
            });
        }

        // Revalidate immediately before the rename. A concurrent stale writer
        // cannot silently replace bytes that no longer match the approved base.
        let current_target = validated_regular_file(&workspace_path, COMPONENT_WAT_PATH)?;
        let current_bytes = read_bounded_file(&current_target, REFERENCE_TASK_MAX_SOURCE_BYTES)?;
        let current_digest = ContentDigest::from_bytes(&current_bytes);
        if current_digest != replacement.expected_before_digest {
            return Err(CandidateWorkspaceError::PatchBaseDigestMismatch {
                expected: replacement.expected_before_digest.clone(),
                actual: current_digest,
            });
        }

        self.atomic_replace(workspace_id, &target, &replacement.replacement_bytes)?;
        let after = self.snapshot(workspace_id)?;
        let after_digest = ContentDigest::from_bytes(&replacement.replacement_bytes);
        let change = ReconstructableFileReplacement {
            relative_path: COMPONENT_WAT_PATH.to_string(),
            before_digest: replacement.expected_before_digest.clone(),
            after_digest,
            before_bytes,
            after_bytes: replacement.replacement_bytes.clone(),
        };
        let patchset_digest = digest_json_content(&(
            workspace_id,
            &before.tree_digest,
            &after.tree_digest,
            std::slice::from_ref(&change),
        ))?;

        Ok(MaterializedCandidatePatchset {
            workspace_id: workspace_id.to_string(),
            before,
            after,
            changes: vec![change],
            patchset_digest,
        })
    }

    /// Builds and packages the exact workspace bytes through the real component
    /// packager and Wasmtime compiler path.
    pub fn build_candidate(
        &self,
        workspace_id: &str,
    ) -> Result<CandidateBuild, CandidateWorkspaceError> {
        let workspace_path = self.validated_workspace_path(workspace_id)?;
        let workspace = self.snapshot(workspace_id)?;
        let wit_path = validated_regular_file(&workspace_path, COMPONENT_WIT_PATH)?;
        let wat_path = validated_regular_file(&workspace_path, COMPONENT_WAT_PATH)?;
        let wit_bytes = read_bounded_file(&wit_path, REFERENCE_TASK_MAX_SOURCE_BYTES)?;
        let wat_bytes = read_bounded_file(&wat_path, REFERENCE_TASK_MAX_SOURCE_BYTES)?;
        let wit_source = String::from_utf8(wit_bytes.clone()).map_err(|_| {
            CandidateWorkspaceError::InvalidUtf8 {
                path: COMPONENT_WIT_PATH.to_string(),
            }
        })?;
        let component_source = String::from_utf8(wat_bytes.clone()).map_err(|_| {
            CandidateWorkspaceError::InvalidUtf8 {
                path: COMPONENT_WAT_PATH.to_string(),
            }
        })?;
        let wit_digest = ContentDigest::from_bytes(&wit_bytes);
        let wat_digest = ContentDigest::from_bytes(&wat_bytes);
        let generation_id = format!("m1-generation-{}", workspace.tree_digest.file_stem());
        let build_id = format!("m1-build-{}", workspace.tree_digest.file_stem());
        let source_refs = workspace
            .entries
            .iter()
            .map(|entry| format!("{}@{}", entry.relative_path, entry.content_digest))
            .collect::<Vec<_>>();
        let manifest = GenerationManifest::new(
            generation_id,
            None,
            REFERENCE_TASK_INTERFACE_REF,
            REFERENCE_TASK_WORLD,
            source_refs,
            vec!["mutation-policy:component.wat-only".to_string()],
            vec![workspace.tree_digest.to_string()],
            "M1 bounded reference-task candidate",
        )?;
        let component = build_component_package(ComponentBuildRequest {
            build_id,
            manifest,
            wit_source,
            component_source,
            required_capability_world_refs: vec![REFERENCE_TASK_CAPABILITY_REF.to_string()],
        })?;
        if component.component_bytes.len() > REFERENCE_TASK_MAX_COMPONENT_BYTES {
            return Err(CandidateWorkspaceError::ComponentSizeLimitExceeded {
                limit: REFERENCE_TASK_MAX_COMPONENT_BYTES,
                actual: component.component_bytes.len(),
            });
        }
        let package_digest = ContentDigest::from_bytes(&component.component_bytes);

        Ok(CandidateBuild {
            source_tree_digest: workspace.tree_digest.clone(),
            workspace,
            wit_digest,
            wat_digest,
            package_digest,
            component,
        })
    }

    fn validated_workspace_path(
        &self,
        workspace_id: &str,
    ) -> Result<PathBuf, CandidateWorkspaceError> {
        self.verify_service_roots()?;
        validate_workspace_id(workspace_id)?;
        let path = self.workspaces_root.join(workspace_id);
        ensure_lexically_beneath(&self.workspaces_root, &path)?;
        let metadata = fs::symlink_metadata(&path).map_err(|source| {
            if source.kind() == std::io::ErrorKind::NotFound {
                CandidateWorkspaceError::WorkspaceNotFound {
                    workspace_id: workspace_id.to_string(),
                }
            } else {
                io_error("inspect candidate workspace", &path, source)
            }
        })?;
        if metadata.file_type().is_symlink() {
            return Err(CandidateWorkspaceError::SymlinkRejected { path });
        }
        if !metadata.is_dir() {
            return Err(CandidateWorkspaceError::NotDirectory { path });
        }
        let canonical = fs::canonicalize(&path)
            .map_err(|source| io_error("canonicalize candidate workspace", &path, source))?;
        ensure_direct_child(&self.workspaces_root, &canonical)?;
        Ok(canonical)
    }

    fn verify_service_roots(&self) -> Result<(), CandidateWorkspaceError> {
        for (path, role) in [
            (&self.canonical_root, "candidate service root"),
            (&self.workspaces_root, "candidate workspaces root"),
            (&self.staging_root, "candidate staging root"),
        ] {
            let metadata = fs::symlink_metadata(path)
                .map_err(|source| io_error("inspect service directory", path, source))?;
            if metadata.file_type().is_symlink() {
                return Err(CandidateWorkspaceError::SymlinkRejected {
                    path: path.to_path_buf(),
                });
            }
            if !metadata.is_dir() {
                return Err(CandidateWorkspaceError::NotDirectory {
                    path: path.to_path_buf(),
                });
            }
            let actual = fs::canonicalize(path)
                .map_err(|source| io_error("canonicalize service directory", path, source))?;
            if actual != *path {
                return Err(CandidateWorkspaceError::AnchorChanged {
                    role,
                    expected: path.to_path_buf(),
                    actual,
                });
            }
        }
        ensure_direct_child(&self.canonical_root, &self.workspaces_root)?;
        ensure_direct_child(&self.canonical_root, &self.staging_root)
    }

    fn atomic_replace(
        &self,
        workspace_id: &str,
        target: &Path,
        replacement_bytes: &[u8],
    ) -> Result<(), CandidateWorkspaceError> {
        self.verify_service_roots()?;
        let mut last_collision = None;
        for _ in 0..128 {
            let sequence = self.temporary_sequence.fetch_add(1, Ordering::Relaxed);
            let temporary_path = self.staging_root.join(format!(
                "{workspace_id}-{}-{sequence}.replacement",
                std::process::id()
            ));
            ensure_lexically_beneath(&self.staging_root, &temporary_path)?;
            let open = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary_path);
            let mut temporary_file = match open {
                Ok(file) => file,
                Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
                    last_collision = Some(source);
                    continue;
                }
                Err(source) => {
                    return Err(io_error(
                        "create staged candidate replacement",
                        &temporary_path,
                        source,
                    ));
                }
            };
            let staged_result = (|| {
                temporary_file
                    .write_all(replacement_bytes)
                    .map_err(|source| {
                        io_error(
                            "write staged candidate replacement",
                            &temporary_path,
                            source,
                        )
                    })?;
                temporary_file.sync_all().map_err(|source| {
                    io_error("sync staged candidate replacement", &temporary_path, source)
                })?;
                drop(temporary_file);
                fs::rename(&temporary_path, target).map_err(|source| {
                    io_error("activate staged candidate replacement", target, source)
                })?;
                let parent =
                    target
                        .parent()
                        .ok_or_else(|| CandidateWorkspaceError::PathEscapesAnchor {
                            anchor: self.workspaces_root.clone(),
                            requested: target.to_path_buf(),
                        })?;
                File::open(parent)
                    .and_then(|directory| directory.sync_all())
                    .map_err(|source| io_error("sync candidate workspace", parent, source))
            })();
            if staged_result.is_err() {
                let _ = fs::remove_file(&temporary_path);
            }
            return staged_result;
        }
        Err(io_error(
            "allocate staged candidate replacement",
            &self.staging_root,
            last_collision.unwrap_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "temporary replacement namespace exhausted",
                )
            }),
        ))
    }
}

/// The fixed proving cases tracked in the M1 reference-task manifest.
pub fn reference_proving_cases() -> Vec<ReferenceProvingCase> {
    [(-1, 0), (0, 1), (41, 42)]
        .into_iter()
        .enumerate()
        .map(|(index, (input, expected_output))| ReferenceProvingCase {
            case_id: format!("reference-case-{}", index + 1),
            input,
            expected_output,
        })
        .collect()
}

pub fn reference_task_execution_limits() -> ComponentExecutionLimits {
    ComponentExecutionLimits {
        fuel: REFERENCE_TASK_FUEL,
        ..ComponentExecutionLimits::default()
    }
}

/// Executes the fixed workload against produced bytes under bounded Wasmtime.
pub fn prove_reference_task(
    build: &CandidateBuild,
) -> Result<ReferenceProvingReport, CandidateWorkspaceError> {
    validate_candidate_build(build)?;
    let cases = reference_proving_cases();
    let suite_digest = digest_json_content(&(PROVING_SUITE_ID, &cases))?;
    let limits = reference_task_execution_limits();
    let mut observations = Vec::with_capacity(cases.len());
    for case in &cases {
        let trace = execute_component_i32_export(
            &build.component.component_bytes,
            REFERENCE_TASK_EXPORT,
            case.input,
            &limits,
        )?;
        if trace.component_digest != build.package_digest {
            return Err(CandidateWorkspaceError::EvidenceInvariant(
                "Wasmtime trace digest does not match the built component".to_string(),
            ));
        }
        let passed = !trace.trapped && trace.output == Some(case.expected_output);
        observations.push(ReferenceProvingObservation {
            case_id: case.case_id.clone(),
            input: case.input,
            expected_output: case.expected_output,
            actual_output: trace.output,
            passed,
            trace,
        });
    }
    let passed_count = observations
        .iter()
        .filter(|observation| observation.passed)
        .count();
    let overall_pass = passed_count == observations.len();
    let report_digest = proving_report_digest(
        &suite_digest,
        &build.package_digest,
        &observations,
        passed_count,
        overall_pass,
    )?;
    Ok(ReferenceProvingReport {
        suite_id: PROVING_SUITE_ID.to_string(),
        suite_digest,
        component_digest: build.package_digest.clone(),
        observations,
        passed_count,
        overall_pass,
        report_digest,
    })
}

/// Derives a promotion recommendation solely from validated incumbent and
/// challenger observations. No caller-supplied score or conclusion is accepted.
pub fn compare_reference_reports(
    incumbent: &ReferenceProvingReport,
    challenger: &ReferenceProvingReport,
) -> Result<CandidateComparison, CandidateWorkspaceError> {
    validate_proving_report(incumbent)?;
    validate_proving_report(challenger)?;
    if incumbent.suite_digest != challenger.suite_digest {
        return Err(CandidateWorkspaceError::ProvingSuiteMismatch {
            incumbent: incumbent.suite_digest.clone(),
            challenger: challenger.suite_digest.clone(),
        });
    }

    let decision = if challenger.overall_pass && challenger.passed_count > incumbent.passed_count {
        CandidateComparisonDecision::ChallengerPreferred
    } else if challenger.overall_pass && incumbent.overall_pass {
        CandidateComparisonDecision::Equivalent
    } else {
        CandidateComparisonDecision::IncumbentRetained
    };
    let eligible_for_activation = decision == CandidateComparisonDecision::ChallengerPreferred;
    let rationale = match decision {
        CandidateComparisonDecision::ChallengerPreferred => format!(
            "challenger passed all {} fixed cases and improved on incumbent score {}/{}",
            challenger.observations.len(),
            incumbent.passed_count,
            incumbent.observations.len()
        ),
        CandidateComparisonDecision::Equivalent => {
            "both artifacts passed the complete fixed proving suite; no improvement was shown"
                .to_string()
        }
        CandidateComparisonDecision::IncumbentRetained => format!(
            "challenger passed {}/{} fixed cases and is not eligible",
            challenger.passed_count,
            challenger.observations.len()
        ),
    };
    let comparison_digest = digest_json_content(&(
        &incumbent.suite_digest,
        &incumbent.component_digest,
        &challenger.component_digest,
        incumbent.passed_count,
        challenger.passed_count,
        &decision,
        eligible_for_activation,
        &rationale,
    ))?;
    Ok(CandidateComparison {
        suite_digest: incumbent.suite_digest.clone(),
        incumbent_component_digest: incumbent.component_digest.clone(),
        challenger_component_digest: challenger.component_digest.clone(),
        incumbent_passed_count: incumbent.passed_count,
        challenger_passed_count: challenger.passed_count,
        decision,
        eligible_for_activation,
        rationale,
        comparison_digest,
    })
}

fn validate_candidate_build(build: &CandidateBuild) -> Result<(), CandidateWorkspaceError> {
    let bytes = &build.component.component_bytes;
    if bytes.len() > REFERENCE_TASK_MAX_COMPONENT_BYTES {
        return Err(CandidateWorkspaceError::ComponentSizeLimitExceeded {
            limit: REFERENCE_TASK_MAX_COMPONENT_BYTES,
            actual: bytes.len(),
        });
    }
    let cryptographic_digest = ContentDigest::from_bytes(bytes);
    if cryptographic_digest != build.package_digest {
        return Err(CandidateWorkspaceError::EvidenceInvariant(
            "candidate package digest does not match component bytes".to_string(),
        ));
    }
    let legacy_digest = ArtifactDigest::from_bytes(bytes);
    if legacy_digest != build.component.component_digest
        || legacy_digest != build.component.inspection.component_digest
        || legacy_digest != build.component.build_closure.output_digest
        || legacy_digest != build.component.package_manifest.component_digest
    {
        return Err(CandidateWorkspaceError::EvidenceInvariant(
            "component compatibility digests do not match produced bytes".to_string(),
        ));
    }
    build.component.package_manifest.validate()?;
    if build.source_tree_digest != build.workspace.tree_digest {
        return Err(CandidateWorkspaceError::EvidenceInvariant(
            "candidate source-tree digest does not match workspace snapshot".to_string(),
        ));
    }
    Ok(())
}

fn validate_proving_report(report: &ReferenceProvingReport) -> Result<(), CandidateWorkspaceError> {
    let cases = reference_proving_cases();
    let expected_suite_digest = digest_json_content(&(PROVING_SUITE_ID, &cases))?;
    if report.suite_id != PROVING_SUITE_ID || report.suite_digest != expected_suite_digest {
        return Err(CandidateWorkspaceError::EvidenceInvariant(
            "proving report is not bound to the fixed reference suite".to_string(),
        ));
    }
    if report.observations.len() != cases.len() {
        return Err(CandidateWorkspaceError::EvidenceInvariant(
            "proving report has the wrong observation count".to_string(),
        ));
    }
    for (observation, case) in report.observations.iter().zip(&cases) {
        let expected_pass =
            !observation.trace.trapped && observation.trace.output == Some(case.expected_output);
        if observation.case_id != case.case_id
            || observation.input != case.input
            || observation.expected_output != case.expected_output
            || observation.actual_output != observation.trace.output
            || observation.trace.input != case.input
            || observation.trace.component_digest != report.component_digest
            || observation.passed != expected_pass
        {
            return Err(CandidateWorkspaceError::EvidenceInvariant(
                "proving observation is inconsistent with its Wasmtime trace".to_string(),
            ));
        }
    }
    let passed_count = report
        .observations
        .iter()
        .filter(|observation| observation.passed)
        .count();
    let overall_pass = passed_count == report.observations.len();
    if report.passed_count != passed_count || report.overall_pass != overall_pass {
        return Err(CandidateWorkspaceError::EvidenceInvariant(
            "proving report summary does not match observations".to_string(),
        ));
    }
    let expected_report_digest = proving_report_digest(
        &report.suite_digest,
        &report.component_digest,
        &report.observations,
        report.passed_count,
        report.overall_pass,
    )?;
    if report.report_digest != expected_report_digest {
        return Err(CandidateWorkspaceError::EvidenceInvariant(
            "proving report digest does not match report content".to_string(),
        ));
    }
    Ok(())
}

fn proving_report_digest(
    suite_digest: &ContentDigest,
    component_digest: &ContentDigest,
    observations: &[ReferenceProvingObservation],
    passed_count: usize,
    overall_pass: bool,
) -> Result<ContentDigest, CandidateWorkspaceError> {
    Ok(digest_json_content(&(
        suite_digest,
        component_digest,
        observations,
        passed_count,
        overall_pass,
    ))?)
}

#[derive(Debug)]
struct FixedTree {
    files: BTreeMap<String, Vec<u8>>,
    entries: Vec<CandidateTreeEntry>,
    total_source_bytes: u64,
    tree_digest: ContentDigest,
}

impl FixedTree {
    fn snapshot(&self, workspace_id: &str) -> CandidateWorkspaceSnapshot {
        CandidateWorkspaceSnapshot {
            workspace_id: workspace_id.to_string(),
            workspace_ref: format!("candidate-workspace:{workspace_id}"),
            mutable_paths: vec![COMPONENT_WAT_PATH.to_string()],
            immutable_paths: vec![COMPONENT_WIT_PATH.to_string()],
            entries: self.entries.clone(),
            total_source_bytes: self.total_source_bytes,
            tree_digest: self.tree_digest.clone(),
        }
    }
}

fn read_fixed_tree(root: &Path) -> Result<FixedTree, CandidateWorkspaceError> {
    let metadata = fs::symlink_metadata(root)
        .map_err(|source| io_error("inspect source tree", root, source))?;
    if metadata.file_type().is_symlink() {
        return Err(CandidateWorkspaceError::SymlinkRejected {
            path: root.to_path_buf(),
        });
    }
    if !metadata.is_dir() {
        return Err(CandidateWorkspaceError::NotDirectory {
            path: root.to_path_buf(),
        });
    }
    let canonical_root = fs::canonicalize(root)
        .map_err(|source| io_error("canonicalize source tree", root, source))?;
    let mut files = BTreeMap::new();
    let directory = fs::read_dir(&canonical_root)
        .map_err(|source| io_error("read source tree", root, source))?;
    for entry in directory {
        let entry = entry.map_err(|source| io_error("read source-tree entry", root, source))?;
        let path = entry.path();
        let entry_metadata = fs::symlink_metadata(&path)
            .map_err(|source| io_error("inspect source-tree entry", &path, source))?;
        if entry_metadata.file_type().is_symlink() {
            return Err(CandidateWorkspaceError::SymlinkRejected { path });
        }
        if !entry_metadata.is_file() {
            return Err(CandidateWorkspaceError::NonRegularEntry { path });
        }
        let relative = path.strip_prefix(&canonical_root).map_err(|_| {
            CandidateWorkspaceError::PathEscapesAnchor {
                anchor: canonical_root.clone(),
                requested: path.clone(),
            }
        })?;
        let relative = relative
            .to_str()
            .ok_or_else(|| CandidateWorkspaceError::NonUtf8Path { path: path.clone() })?
            .to_string();
        validate_relative_path(&relative)?;
        let bytes = read_bounded_file(&path, REFERENCE_TASK_MAX_SOURCE_BYTES)?;
        files.insert(relative, bytes);
    }

    let actual = files.keys().cloned().collect::<BTreeSet<_>>();
    let expected = expected_paths();
    if actual != expected {
        return Err(CandidateWorkspaceError::InvalidTreeShape { expected, actual });
    }
    if files.len() > REFERENCE_TASK_MAX_FILES {
        return Err(CandidateWorkspaceError::FileCountLimitExceeded {
            limit: REFERENCE_TASK_MAX_FILES,
            actual: files.len(),
        });
    }
    let mut total_source_bytes = 0u64;
    let mut canonical_encoding = Vec::new();
    canonical_encoding.extend_from_slice(TREE_DOMAIN);
    let mut entries = Vec::with_capacity(files.len());
    for (relative_path, bytes) in &files {
        let byte_len = u64::try_from(bytes.len()).map_err(|_| {
            CandidateWorkspaceError::SourceSizeLimitExceeded {
                limit: REFERENCE_TASK_MAX_SOURCE_BYTES,
                actual: u64::MAX,
            }
        })?;
        total_source_bytes = total_source_bytes.checked_add(byte_len).ok_or(
            CandidateWorkspaceError::SourceSizeLimitExceeded {
                limit: REFERENCE_TASK_MAX_SOURCE_BYTES,
                actual: u64::MAX,
            },
        )?;
        append_length_prefixed(&mut canonical_encoding, relative_path.as_bytes())?;
        append_length_prefixed(&mut canonical_encoding, bytes)?;
        entries.push(CandidateTreeEntry {
            relative_path: relative_path.clone(),
            byte_len,
            content_digest: ContentDigest::from_bytes(bytes),
        });
    }
    if total_source_bytes > REFERENCE_TASK_MAX_SOURCE_BYTES {
        return Err(CandidateWorkspaceError::SourceSizeLimitExceeded {
            limit: REFERENCE_TASK_MAX_SOURCE_BYTES,
            actual: total_source_bytes,
        });
    }
    let tree_digest = ContentDigest::from_bytes(&canonical_encoding);
    Ok(FixedTree {
        files,
        entries,
        total_source_bytes,
        tree_digest,
    })
}

fn append_length_prefixed(
    destination: &mut Vec<u8>,
    bytes: &[u8],
) -> Result<(), CandidateWorkspaceError> {
    let len = u64::try_from(bytes.len()).map_err(|_| {
        CandidateWorkspaceError::EvidenceInvariant(
            "tree identity input length exceeds u64".to_string(),
        )
    })?;
    destination.extend_from_slice(&len.to_be_bytes());
    destination.extend_from_slice(bytes);
    Ok(())
}

fn expected_paths() -> BTreeSet<String> {
    [
        COMPONENT_WAT_PATH.to_string(),
        COMPONENT_WIT_PATH.to_string(),
    ]
    .into_iter()
    .collect()
}

fn validate_workspace_id(workspace_id: &str) -> Result<(), CandidateWorkspaceError> {
    let valid = !workspace_id.is_empty()
        && workspace_id.len() <= 128
        && workspace_id != "."
        && workspace_id != ".."
        && workspace_id.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b'.'
        });
    if !valid {
        return Err(CandidateWorkspaceError::InvalidWorkspaceId {
            workspace_id: workspace_id.to_string(),
        });
    }
    Ok(())
}

fn validate_relative_path(relative_path: &str) -> Result<(), CandidateWorkspaceError> {
    let path = Path::new(relative_path);
    if relative_path.is_empty() || path.is_absolute() {
        return Err(CandidateWorkspaceError::InvalidRelativePath {
            path: relative_path.to_string(),
        });
    }
    let mut count = 0usize;
    for component in path.components() {
        match component {
            Component::Normal(_) => count += 1,
            Component::Prefix(_)
            | Component::RootDir
            | Component::CurDir
            | Component::ParentDir => {
                return Err(CandidateWorkspaceError::InvalidRelativePath {
                    path: relative_path.to_string(),
                });
            }
        }
    }
    if count != 1 {
        return Err(CandidateWorkspaceError::InvalidRelativePath {
            path: relative_path.to_string(),
        });
    }
    Ok(())
}

fn validated_regular_file(
    workspace_root: &Path,
    relative_path: &str,
) -> Result<PathBuf, CandidateWorkspaceError> {
    validate_relative_path(relative_path)?;
    let requested = workspace_root.join(relative_path);
    ensure_lexically_beneath(workspace_root, &requested)?;
    let metadata = fs::symlink_metadata(&requested)
        .map_err(|source| io_error("inspect candidate file", &requested, source))?;
    if metadata.file_type().is_symlink() {
        return Err(CandidateWorkspaceError::SymlinkRejected { path: requested });
    }
    if !metadata.is_file() {
        return Err(CandidateWorkspaceError::NonRegularEntry { path: requested });
    }
    let canonical = fs::canonicalize(&requested)
        .map_err(|source| io_error("canonicalize candidate file", &requested, source))?;
    ensure_direct_child(workspace_root, &canonical)?;
    Ok(canonical)
}

fn read_bounded_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>, CandidateWorkspaceError> {
    let metadata =
        fs::metadata(path).map_err(|source| io_error("inspect bounded file", path, source))?;
    if metadata.len() > max_bytes {
        return Err(CandidateWorkspaceError::SourceSizeLimitExceeded {
            limit: max_bytes,
            actual: metadata.len(),
        });
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
    File::open(path)
        .map_err(|source| io_error("open bounded file", path, source))?
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| io_error("read bounded file", path, source))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
        return Err(CandidateWorkspaceError::SourceSizeLimitExceeded {
            limit: max_bytes,
            actual: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        });
    }
    Ok(bytes)
}

fn create_real_directory(path: &Path) -> Result<(), CandidateWorkspaceError> {
    reject_symlink_if_present(path)?;
    fs::create_dir_all(path)
        .map_err(|source| io_error("create service directory", path, source))?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("inspect service directory", path, source))?;
    if metadata.file_type().is_symlink() {
        return Err(CandidateWorkspaceError::SymlinkRejected {
            path: path.to_path_buf(),
        });
    }
    if !metadata.is_dir() {
        return Err(CandidateWorkspaceError::NotDirectory {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn reject_symlink_if_present(path: &Path) -> Result<(), CandidateWorkspaceError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(CandidateWorkspaceError::SymlinkRejected {
                path: path.to_path_buf(),
            })
        }
        Ok(_) => Ok(()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error("inspect path", path, source)),
    }
}

fn ensure_lexically_beneath(
    anchor: &Path,
    requested: &Path,
) -> Result<(), CandidateWorkspaceError> {
    if requested.parent() != Some(anchor) || !requested.starts_with(anchor) {
        return Err(CandidateWorkspaceError::PathEscapesAnchor {
            anchor: anchor.to_path_buf(),
            requested: requested.to_path_buf(),
        });
    }
    Ok(())
}

fn ensure_direct_child(anchor: &Path, child: &Path) -> Result<(), CandidateWorkspaceError> {
    if child.parent() != Some(anchor) || !child.starts_with(anchor) {
        return Err(CandidateWorkspaceError::PathEscapesAnchor {
            anchor: anchor.to_path_buf(),
            requested: child.to_path_buf(),
        });
    }
    Ok(())
}

fn io_error(
    operation: &'static str,
    path: &Path,
    source: std::io::Error,
) -> CandidateWorkspaceError {
    CandidateWorkspaceError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

#[derive(Debug)]
pub enum CandidateWorkspaceError {
    Io {
        operation: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
    Artifact(ArtifactError),
    Component(ComponentBuildError),
    InvalidWorkspaceId {
        workspace_id: String,
    },
    WorkspaceAlreadyExists {
        workspace_id: String,
    },
    WorkspaceNotFound {
        workspace_id: String,
    },
    InvalidRelativePath {
        path: String,
    },
    MutationNotAllowed {
        requested: String,
        allowed: String,
    },
    InvalidPatchCount {
        expected: usize,
        actual: usize,
    },
    EmptyReplacement,
    PatchDoesNotChangeBytes,
    PatchBaseDigestMismatch {
        expected: ContentDigest,
        actual: ContentDigest,
    },
    ReconstructionDigestMismatch {
        direction: &'static str,
        expected: ContentDigest,
        actual: ContentDigest,
    },
    SymlinkRejected {
        path: PathBuf,
    },
    NotDirectory {
        path: PathBuf,
    },
    NonRegularEntry {
        path: PathBuf,
    },
    NonUtf8Path {
        path: PathBuf,
    },
    InvalidUtf8 {
        path: String,
    },
    InvalidTreeShape {
        expected: BTreeSet<String>,
        actual: BTreeSet<String>,
    },
    FileCountLimitExceeded {
        limit: usize,
        actual: usize,
    },
    SourceSizeLimitExceeded {
        limit: u64,
        actual: u64,
    },
    ComponentSizeLimitExceeded {
        limit: usize,
        actual: usize,
    },
    PathEscapesAnchor {
        anchor: PathBuf,
        requested: PathBuf,
    },
    AnchorChanged {
        role: &'static str,
        expected: PathBuf,
        actual: PathBuf,
    },
    ProvingSuiteMismatch {
        incumbent: ContentDigest,
        challenger: ContentDigest,
    },
    EvidenceInvariant(String),
}

impl From<ArtifactError> for CandidateWorkspaceError {
    fn from(value: ArtifactError) -> Self {
        Self::Artifact(value)
    }
}

impl From<ComponentBuildError> for CandidateWorkspaceError {
    fn from(value: ComponentBuildError) -> Self {
        Self::Component(value)
    }
}

impl Display for CandidateWorkspaceError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io {
                operation,
                path,
                source,
            } => write!(
                formatter,
                "{operation} at {} failed: {source}",
                path.display()
            ),
            Self::Artifact(error) => write!(formatter, "candidate artifact error: {error}"),
            Self::Component(error) => write!(formatter, "candidate component error: {error}"),
            Self::InvalidWorkspaceId { workspace_id } => {
                write!(
                    formatter,
                    "invalid candidate workspace id: {workspace_id:?}"
                )
            }
            Self::WorkspaceAlreadyExists { workspace_id } => {
                write!(
                    formatter,
                    "candidate workspace already exists: {workspace_id}"
                )
            }
            Self::WorkspaceNotFound { workspace_id } => {
                write!(
                    formatter,
                    "candidate workspace does not exist: {workspace_id}"
                )
            }
            Self::InvalidRelativePath { path } => {
                write!(formatter, "invalid candidate relative path: {path:?}")
            }
            Self::MutationNotAllowed { requested, allowed } => write!(
                formatter,
                "candidate mutation of {requested:?} is forbidden; only {allowed:?} is mutable"
            ),
            Self::InvalidPatchCount { expected, actual } => write!(
                formatter,
                "bounded candidate patchset requires {expected} replacement, got {actual}"
            ),
            Self::EmptyReplacement => {
                write!(formatter, "candidate replacement bytes must not be empty")
            }
            Self::PatchDoesNotChangeBytes => {
                write!(formatter, "candidate replacement does not change bytes")
            }
            Self::PatchBaseDigestMismatch { expected, actual } => write!(
                formatter,
                "candidate patch base digest mismatch: expected {expected}, got {actual}"
            ),
            Self::ReconstructionDigestMismatch {
                direction,
                expected,
                actual,
            } => write!(
                formatter,
                "candidate patch {direction} reconstruction digest mismatch: expected {expected}, got {actual}"
            ),
            Self::SymlinkRejected { path } => {
                write!(
                    formatter,
                    "candidate path is a rejected symlink: {}",
                    path.display()
                )
            }
            Self::NotDirectory { path } => {
                write!(
                    formatter,
                    "candidate path is not a directory: {}",
                    path.display()
                )
            }
            Self::NonRegularEntry { path } => write!(
                formatter,
                "candidate tree entry is not a regular file: {}",
                path.display()
            ),
            Self::NonUtf8Path { path } => {
                write!(formatter, "candidate path is not UTF-8: {}", path.display())
            }
            Self::InvalidUtf8 { path } => {
                write!(formatter, "candidate source file is not UTF-8: {path}")
            }
            Self::InvalidTreeShape { expected, actual } => write!(
                formatter,
                "candidate tree shape mismatch: expected {expected:?}, got {actual:?}"
            ),
            Self::FileCountLimitExceeded { limit, actual } => write!(
                formatter,
                "candidate file count {actual} exceeds configured limit {limit}"
            ),
            Self::SourceSizeLimitExceeded { limit, actual } => write!(
                formatter,
                "candidate source size {actual} exceeds configured limit {limit}"
            ),
            Self::ComponentSizeLimitExceeded { limit, actual } => write!(
                formatter,
                "candidate component size {actual} exceeds configured limit {limit}"
            ),
            Self::PathEscapesAnchor { anchor, requested } => write!(
                formatter,
                "candidate path {} escapes service anchor {}",
                requested.display(),
                anchor.display()
            ),
            Self::AnchorChanged {
                role,
                expected,
                actual,
            } => write!(
                formatter,
                "{role} anchor changed from {} to {}",
                expected.display(),
                actual.display()
            ),
            Self::ProvingSuiteMismatch {
                incumbent,
                challenger,
            } => write!(
                formatter,
                "cannot compare different proving suites: incumbent {incumbent}, challenger {challenger}"
            ),
            Self::EvidenceInvariant(detail) => {
                write!(formatter, "candidate evidence invariant failed: {detail}")
            }
        }
    }
}

impl Error for CandidateWorkspaceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Artifact(source) => Some(source),
            Self::Component(source) => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        COMPONENT_WAT_PATH, COMPONENT_WIT_PATH, CandidateComparisonDecision,
        CandidateFileReplacement, CandidateWorkspaceError, CandidateWorkspaceService,
        REFERENCE_TASK_MAX_SOURCE_BYTES, compare_reference_reports, prove_reference_task,
    };
    use crate::execution::artifact::ContentDigest;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "wasm-biotic-candidate-{label}-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create isolated test directory");
            Self { path }
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn fixture_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("artifacts/fixtures/m1-reference-component")
    }

    fn template_root() -> PathBuf {
        fixture_root().join("template")
    }

    fn candidate_bytes(name: &str) -> Vec<u8> {
        fs::read(fixture_root().join("candidates").join(name)).expect("read candidate fixture")
    }

    fn service(test: &TestDirectory) -> CandidateWorkspaceService {
        CandidateWorkspaceService::bootstrap(test.path.join("service"))
            .expect("bootstrap candidate workspace service")
    }

    fn replacement_for(
        service: &CandidateWorkspaceService,
        workspace_id: &str,
        bytes: Vec<u8>,
    ) -> CandidateFileReplacement {
        let snapshot = service.snapshot(workspace_id).expect("snapshot workspace");
        let digest = snapshot
            .entry(COMPONENT_WAT_PATH)
            .expect("mutable file entry")
            .content_digest
            .clone();
        CandidateFileReplacement::new(COMPONENT_WAT_PATH, digest, bytes)
    }

    #[test]
    fn fresh_workspaces_are_anchored_and_content_identical() {
        let test = TestDirectory::new("fresh");
        let service = service(&test);
        let first = service
            .open_workspace("candidate-a", template_root())
            .expect("open first workspace");
        let second = service
            .open_workspace("candidate-b", template_root())
            .expect("open second workspace");

        assert_eq!(first.tree_digest, second.tree_digest);
        assert_eq!(first.entries, second.entries);
        assert_eq!(first.entries.len(), 2);
        assert_eq!(first.mutable_paths, vec![COMPONENT_WAT_PATH]);
        assert_eq!(first.immutable_paths, vec![COMPONENT_WIT_PATH]);
        assert!(
            service
                .workspace_path("candidate-a")
                .expect("resolve workspace")
                .starts_with(service.canonical_root())
        );
    }

    #[test]
    fn traversal_and_absolute_workspace_ids_have_no_external_effect() {
        let test = TestDirectory::new("traversal");
        let service = service(&test);
        for invalid in ["../escape", "nested/workspace", "/tmp/escape", ".", ".."] {
            assert!(matches!(
                service.open_workspace(invalid, template_root()),
                Err(CandidateWorkspaceError::InvalidWorkspaceId { .. })
            ));
        }
        assert!(!test.path.join("escape").exists());
    }

    #[test]
    fn patch_policy_rejects_interface_mutation_and_stale_bases() {
        let test = TestDirectory::new("policy");
        let service = service(&test);
        let before = service
            .open_workspace("candidate", template_root())
            .expect("open workspace");
        let workspace_path = service
            .workspace_path("candidate")
            .expect("resolve workspace");
        let wit_before = fs::read(workspace_path.join(COMPONENT_WIT_PATH)).expect("read WIT");
        let forbidden = CandidateFileReplacement::new(
            COMPONENT_WIT_PATH,
            ContentDigest::from_bytes(&wit_before),
            b"forbidden".to_vec(),
        );
        assert!(matches!(
            service.materialize_patchset("candidate", &[forbidden]),
            Err(CandidateWorkspaceError::MutationNotAllowed { .. })
        ));
        assert_eq!(
            fs::read(workspace_path.join(COMPONENT_WIT_PATH)).expect("read unchanged WIT"),
            wit_before
        );

        let stale = CandidateFileReplacement::new(
            COMPONENT_WAT_PATH,
            ContentDigest::from_bytes(b"not the base"),
            candidate_bytes("increment.wat"),
        );
        assert!(matches!(
            service.materialize_patchset("candidate", &[stale]),
            Err(CandidateWorkspaceError::PatchBaseDigestMismatch { .. })
        ));
        assert_eq!(
            service.snapshot("candidate").expect("snapshot").tree_digest,
            before.tree_digest
        );
    }

    #[test]
    fn materialized_replacement_changes_real_bytes_and_reconstructs_both_directions() {
        let test = TestDirectory::new("patch");
        let service = service(&test);
        service
            .open_workspace("candidate", template_root())
            .expect("open workspace");
        let replacement = replacement_for(&service, "candidate", candidate_bytes("increment.wat"));
        let materialized = service
            .materialize_patchset("candidate", &[replacement])
            .expect("materialize candidate patch");
        let change = &materialized.changes[0];

        assert_ne!(
            materialized.before.tree_digest,
            materialized.after.tree_digest
        );
        assert_eq!(
            change
                .reconstruct_after(&change.before_bytes)
                .expect("reconstruct forward"),
            change.after_bytes
        );
        assert_eq!(
            change
                .reconstruct_before(&change.after_bytes)
                .expect("reconstruct reverse"),
            change.before_bytes
        );
        assert_eq!(
            fs::read(
                service
                    .workspace_path("candidate")
                    .expect("workspace path")
                    .join(COMPONENT_WAT_PATH)
            )
            .expect("read materialized bytes"),
            change.after_bytes
        );
    }

    #[test]
    fn oversized_patch_is_rejected_before_bytes_change() {
        let test = TestDirectory::new("size");
        let service = service(&test);
        let before = service
            .open_workspace("candidate", template_root())
            .expect("open workspace");
        let oversized = vec![b'x'; REFERENCE_TASK_MAX_SOURCE_BYTES as usize];
        let replacement = replacement_for(&service, "candidate", oversized);

        assert!(matches!(
            service.materialize_patchset("candidate", &[replacement]),
            Err(CandidateWorkspaceError::SourceSizeLimitExceeded { .. })
        ));
        assert_eq!(
            service.snapshot("candidate").expect("snapshot").tree_digest,
            before.tree_digest
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_mutation_target_cannot_escape_the_workspace() {
        use std::os::unix::fs::symlink;

        let test = TestDirectory::new("symlink-target");
        let service = service(&test);
        service
            .open_workspace("candidate", template_root())
            .expect("open workspace");
        let workspace = service.workspace_path("candidate").expect("workspace path");
        let target = workspace.join(COMPONENT_WAT_PATH);
        let outside = test.path.join("outside.wat");
        fs::write(&outside, b"outside bytes").expect("write outside sentinel");
        fs::remove_file(&target).expect("remove workspace target");
        symlink(&outside, &target).expect("create escaping symlink");
        let replacement = CandidateFileReplacement::new(
            COMPONENT_WAT_PATH,
            ContentDigest::from_bytes(b"outside bytes"),
            candidate_bytes("increment.wat"),
        );

        assert!(matches!(
            service.materialize_patchset("candidate", &[replacement]),
            Err(CandidateWorkspaceError::SymlinkRejected { .. })
        ));
        assert_eq!(
            fs::read(&outside).expect("read outside sentinel"),
            b"outside bytes"
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_template_entry_is_rejected_before_workspace_creation() {
        use std::os::unix::fs::symlink;

        let test = TestDirectory::new("symlink-template");
        let template = test.path.join("template");
        fs::create_dir(&template).expect("create template");
        fs::copy(
            template_root().join(COMPONENT_WIT_PATH),
            template.join(COMPONENT_WIT_PATH),
        )
        .expect("copy WIT");
        symlink(
            template_root().join(COMPONENT_WAT_PATH),
            template.join(COMPONENT_WAT_PATH),
        )
        .expect("create template symlink");
        let service = service(&test);

        assert!(matches!(
            service.open_workspace("candidate", &template),
            Err(CandidateWorkspaceError::SymlinkRejected { .. })
        ));
        assert!(
            !service
                .canonical_root()
                .join("workspaces/candidate")
                .exists()
        );
    }

    #[test]
    fn real_build_proving_and_comparison_prefer_the_valid_challenger() {
        let test = TestDirectory::new("vertical");
        let service = service(&test);
        service
            .open_workspace("incumbent", template_root())
            .expect("open incumbent");
        service
            .open_workspace("challenger", template_root())
            .expect("open challenger");
        let replacement = replacement_for(&service, "challenger", candidate_bytes("increment.wat"));
        service
            .materialize_patchset("challenger", &[replacement])
            .expect("materialize challenger");

        let incumbent_build = service
            .build_candidate("incumbent")
            .expect("build incumbent");
        let challenger_build = service
            .build_candidate("challenger")
            .expect("build challenger");
        let incumbent_report = prove_reference_task(&incumbent_build).expect("prove incumbent");
        let challenger_report = prove_reference_task(&challenger_build).expect("prove challenger");
        let comparison = compare_reference_reports(&incumbent_report, &challenger_report)
            .expect("compare real reports");

        assert_eq!(incumbent_report.passed_count, 0);
        assert!(!incumbent_report.overall_pass);
        assert_eq!(challenger_report.passed_count, 3);
        assert!(challenger_report.overall_pass);
        assert_eq!(
            comparison.decision,
            CandidateComparisonDecision::ChallengerPreferred
        );
        assert!(comparison.eligible_for_activation);
        assert_ne!(
            incumbent_build.package_digest,
            challenger_build.package_digest
        );
    }

    #[test]
    fn broken_candidate_fails_the_real_component_build() {
        let test = TestDirectory::new("broken");
        let service = service(&test);
        service
            .open_workspace("candidate", template_root())
            .expect("open candidate");
        let replacement = replacement_for(&service, "candidate", candidate_bytes("broken.wat"));
        service
            .materialize_patchset("candidate", &[replacement])
            .expect("materialize broken candidate");

        assert!(matches!(
            service.build_candidate("candidate"),
            Err(CandidateWorkspaceError::Component(_))
        ));
    }

    #[test]
    fn identical_candidates_rebuild_with_identical_identity_and_results() {
        let test = TestDirectory::new("reproducible");
        let service = service(&test);
        for workspace_id in ["first", "second"] {
            service
                .open_workspace(workspace_id, template_root())
                .expect("open candidate");
            let replacement =
                replacement_for(&service, workspace_id, candidate_bytes("increment.wat"));
            service
                .materialize_patchset(workspace_id, &[replacement])
                .expect("materialize candidate");
        }

        let first = service.build_candidate("first").expect("build first");
        let second = service.build_candidate("second").expect("build second");
        assert_eq!(first.source_tree_digest, second.source_tree_digest);
        assert_eq!(first.package_digest, second.package_digest);
        assert_eq!(
            first.component.component_bytes,
            second.component.component_bytes
        );
        assert_eq!(
            first.component.package_manifest.bundle_digest,
            second.component.package_manifest.bundle_digest
        );

        let first_report = prove_reference_task(&first).expect("prove first");
        let second_report = prove_reference_task(&second).expect("prove second");
        assert_eq!(first_report.report_digest, second_report.report_digest);
        assert_eq!(first_report.observations, second_report.observations);
    }

    #[test]
    fn comparison_rejects_tampered_proving_evidence() {
        let test = TestDirectory::new("tampered");
        let service = service(&test);
        service
            .open_workspace("candidate", template_root())
            .expect("open candidate");
        let replacement = replacement_for(&service, "candidate", candidate_bytes("increment.wat"));
        service
            .materialize_patchset("candidate", &[replacement])
            .expect("materialize candidate");
        let build = service
            .build_candidate("candidate")
            .expect("build candidate");
        let report = prove_reference_task(&build).expect("prove candidate");
        let mut tampered = report.clone();
        tampered.passed_count = 0;

        assert!(matches!(
            compare_reference_reports(&report, &tampered),
            Err(CandidateWorkspaceError::EvidenceInvariant(_))
        ));
    }
}
