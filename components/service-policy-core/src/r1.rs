//! Bounded, useful R1 software-work semantics.
//!
//! All workspace bytes are carried inline in a strict content-addressed JSON
//! document.  The implementation is deliberately small enough to execute in
//! an admitted `no_std` component: it has no filesystem, process, shell,
//! environment, socket, or ambient credential dependency.

use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{Invocation, Operation, PolicyError, ServiceOutput, hex_sha256, validate_sha256_hex};

pub const CHANGE_REQUEST_MEDIA_TYPE: &str = "application/vnd.wasm-biotic.r1-change-request.v1+json";
pub const WORK_STATE_MEDIA_TYPE: &str = "application/vnd.wasm-biotic.r1-work-state.v1+json";
pub const DEPLOYMENT_PLAN_MEDIA_TYPE: &str =
    "application/vnd.wasm-biotic.r1-deployment-plan.v1+json";
pub const DEPLOYMENT_STATE_MEDIA_TYPE: &str =
    "application/vnd.wasm-biotic.r1-deployment-state.v1+json";
pub const WORK_STATE_SCHEMA: &str = "wasm-biotic.r1-work-state.v1";

const CHANGE_REQUEST_SCHEMA: &str = "wasm-biotic.r1-change-request.v1";
const PROGRAM_SCHEMA: &str = "wasm-biotic.text-program.v1";
const TEST_SCHEMA: &str = "wasm-biotic.text-program-test.v1";
const DEPLOYMENT_PLAN_SCHEMA: &str = "wasm-biotic.r1-deployment-plan.v1";
const DEPLOYMENT_STATE_SCHEMA: &str = "wasm-biotic.r1-deployment-state.v1";
const PROGRAM_MEDIA_TYPE: &str = "application/vnd.wasm-biotic.text-program.v1+json";
const TEST_MEDIA_TYPE: &str = "application/vnd.wasm-biotic.text-program-test.v1+json";
const BYTECODE_MAGIC: &[u8] = b"WBTX\0\x01";
const LOCAL_MODEL: &str = "wasm-biotic:local-fixture-reviewer@1";

const MAX_DOCUMENT_BYTES: usize = 1_048_576;
const MAX_FILES: usize = 256;
const MAX_FILE_BYTES: usize = 262_144;
const MAX_TREE_BYTES: usize = 4_194_304;
const MAX_PATH_BYTES: usize = 240;
const MAX_LABEL_BYTES: usize = 64;
const MAX_INSTRUCTIONS: usize = 256;
const MAX_LITERAL_BYTES: usize = 65_536;
const MAX_TEST_CASES: usize = 256;
const MAX_VALUE_BYTES: usize = 65_536;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InlineFile {
    path: String,
    media_type: String,
    content: String,
    digest_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CasPatch {
    path: String,
    expected_digest_hex: String,
    replacement_media_type: String,
    replacement_content: String,
    replacement_digest_hex: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum ProviderMode {
    LocalFixture,
    Remote,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChangeRequest {
    schema: String,
    label: String,
    package_name: String,
    package_version: String,
    entrypoint: String,
    provider_mode: ProviderMode,
    files: Vec<InlineFile>,
    patch: CasPatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum WorkStage {
    Opened,
    Snapshotted,
    Patched,
    Built,
    Validated,
    Reviewed,
    Packaged,
    Verified,
    Evidenced,
    Resolved,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record<T> {
    digest_hex: String,
    body: T,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenRecord {
    operation: String,
    request_digest_hex: String,
    base_tree_digest_hex: String,
    file_count: u32,
    total_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotRecord {
    operation: String,
    input_state_digest_hex: String,
    tree_digest_hex: String,
    sorted_paths_digest_hex: String,
    file_count: u32,
    total_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PatchRecord {
    operation: String,
    input_state_digest_hex: String,
    path: String,
    before_digest_hex: String,
    after_digest_hex: String,
    base_tree_digest_hex: String,
    patched_tree_digest_hex: String,
    source_changed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompiledArtifact {
    language: String,
    bytecode: Vec<u8>,
    digest_hex: String,
    instruction_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BuildRecord {
    operation: String,
    input_state_digest_hex: String,
    source_tree_digest_hex: String,
    source_digest_hex: String,
    artifact_digest_hex: String,
    artifact_size_bytes: u64,
    instruction_count: u32,
    compiler: String,
    producer_component_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderRecord {
    operation: String,
    input_state_digest_hex: String,
    policy: String,
    model: String,
    request_digest_hex: String,
    response_digest_hex: String,
    recommendation: String,
    external_transport_used: bool,
    producer_component_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TestObservation {
    file: String,
    name: String,
    input: String,
    expected: String,
    actual: String,
    passed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidationRecord {
    operation: String,
    input_state_digest_hex: String,
    artifact_digest_hex: String,
    provider_record_digest_hex: String,
    discovered_test_files: Vec<String>,
    observations: Vec<TestObservation>,
    total_tests: u32,
    passed_tests: u32,
    all_passed: bool,
    producer_component_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewRecord {
    operation: String,
    input_state_digest_hex: String,
    patch_record_digest_hex: String,
    build_record_digest_hex: String,
    validation_record_digest_hex: String,
    checks: Vec<String>,
    approved: bool,
    producer_component_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageRecord {
    operation: String,
    input_state_digest_hex: String,
    package_name: String,
    package_version: String,
    tree_digest_hex: String,
    artifact_digest_hex: String,
    build_record_digest_hex: String,
    validation_record_digest_hex: String,
    review_record_digest_hex: String,
    closure_digest_hex: String,
    producer_component_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerificationRecord {
    operation: String,
    input_state_digest_hex: String,
    package_record_digest_hex: String,
    closure_digest_hex: String,
    verified: bool,
    producer_component_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceRecord {
    operation: String,
    input_state_digest_hex: String,
    request_digest_hex: String,
    snapshot_record_digest_hex: String,
    patch_record_digest_hex: String,
    build_record_digest_hex: String,
    provider_record_digest_hex: String,
    validation_record_digest_hex: String,
    review_record_digest_hex: String,
    package_record_digest_hex: String,
    verification_record_digest_hex: String,
    closure_digest_hex: String,
    producer_component_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolutionRecord {
    operation: String,
    input_state_digest_hex: String,
    evidence_record_digest_hex: String,
    package_record_digest_hex: String,
    resolved: bool,
    producer_component_hex: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkRecords {
    open: Option<Record<OpenRecord>>,
    snapshot: Option<Record<SnapshotRecord>>,
    patch: Option<Record<PatchRecord>>,
    build: Option<Record<BuildRecord>>,
    provider: Option<Record<ProviderRecord>>,
    validation: Option<Record<ValidationRecord>>,
    review: Option<Record<ReviewRecord>>,
    package: Option<Record<PackageRecord>>,
    verification: Option<Record<VerificationRecord>>,
    evidence: Option<Record<EvidenceRecord>>,
    resolution: Option<Record<ResolutionRecord>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkState {
    schema: String,
    stage: WorkStage,
    request_digest_hex: String,
    request: ChangeRequest,
    base_tree_digest_hex: String,
    current_tree_digest_hex: String,
    files: Vec<InlineFile>,
    artifact: Option<CompiledArtifact>,
    records: WorkRecords,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case", deny_unknown_fields)]
enum Instruction {
    Input,
    Literal { value: String },
    Concat,
    AsciiUpper,
    AsciiLower,
    Sha256Hex,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Program {
    schema: String,
    instructions: Vec<Instruction>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TestCase {
    name: String,
    input: String,
    expected: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TestSuite {
    schema: String,
    cases: Vec<TestCase>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum DeploymentTarget {
    Local,
    Remote,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Observation {
    Healthy,
    Unhealthy,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeploymentPlan {
    schema: String,
    deployment_id: String,
    target: DeploymentTarget,
    package_digest_hex: String,
    expected_revision: u64,
    fixture_observation: Observation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum DeploymentStatus {
    Initialized,
    Active,
    ObservedHealthy,
    ObservedUnhealthy,
    RolledBack,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeploymentTransition {
    operation: String,
    input_digest_hex: String,
    from_revision: u64,
    to_revision: u64,
    from_status: Option<DeploymentStatus>,
    to_status: DeploymentStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeploymentState {
    schema: String,
    deployment_id: String,
    target: DeploymentTarget,
    package_digest_hex: String,
    revision: u64,
    status: DeploymentStatus,
    fixture_observation: Observation,
    transitions: Vec<Record<DeploymentTransition>>,
}

/// Strict semantic summary returned only after the complete R1 closure has
/// been reconstructed and checked.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedWorkSummary {
    pub request_digest_hex: String,
    pub base_tree_digest_hex: String,
    pub patched_tree_digest_hex: String,
    pub artifact_digest_hex: String,
    pub validation_digest_hex: String,
    pub review_digest_hex: String,
    pub package_digest_hex: String,
    pub verification_digest_hex: String,
    pub evidence_digest_hex: String,
    pub resolved_digest_hex: String,
    pub source_changed: bool,
    pub bytecode_size_bytes: u64,
    pub provider_policy: String,
    pub tests_discovered: u32,
    pub passed_tests: u32,
    pub total_tests: u32,
    pub review_approved: bool,
    pub package_verified: bool,
    pub evidence_resolved: bool,
    pub operation_history: Vec<String>,
}

/// Returns true for media types reserved to the strict R1 semantic path.
/// Malformed bytes carrying one of these types must never reach legacy
/// compatibility behaviour.
#[must_use]
pub fn owns_media_type(media_type: &str) -> bool {
    media_type.starts_with("application/vnd.wasm-biotic.r1-")
}

fn error(code: &'static str, message: impl Into<String>) -> PolicyError {
    PolicyError::new(code, message)
}

fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, PolicyError> {
    serde_json::to_vec(value).map_err(|failure| {
        error(
            "r1-serialization-failed",
            format!("could not encode canonical R1 document: {failure}"),
        )
    })
}

fn parse_canonical<T>(bytes: &[u8], document: &str) -> Result<T, PolicyError>
where
    T: DeserializeOwned + Serialize,
{
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(error(
            "r1-document-too-large",
            format!("{document} exceeds the bounded document size"),
        ));
    }
    let value: T = serde_json::from_slice(bytes).map_err(|failure| {
        error(
            "invalid-r1-json",
            format!("could not decode {document}: {failure}"),
        )
    })?;
    if canonical_bytes(&value)? != bytes {
        return Err(error(
            "noncanonical-r1-json",
            format!("{document} must use its exact compact canonical JSON encoding"),
        ));
    }
    Ok(value)
}

fn record<T>(body: T) -> Result<Record<T>, PolicyError>
where
    T: Serialize,
{
    let digest_hex = hex_sha256(&canonical_bytes(&body)?);
    Ok(Record { digest_hex, body })
}

fn verify_record<T>(value: &Record<T>, field: &str) -> Result<(), PolicyError>
where
    T: Serialize,
{
    validate_sha256_hex(field, &value.digest_hex)?;
    if hex_sha256(&canonical_bytes(&value.body)?) != value.digest_hex {
        return Err(error(
            "r1-record-digest-mismatch",
            format!("{field} does not identify its exact record body"),
        ));
    }
    Ok(())
}

fn validate_label(value: &str, field: &str) -> Result<(), PolicyError> {
    if value.is_empty()
        || value.len() > MAX_LABEL_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(error(
            "invalid-r1-label",
            format!("{field} must be 1..={MAX_LABEL_BYTES} ASCII label characters"),
        ));
    }
    Ok(())
}

fn validate_path(path: &str) -> Result<(), PolicyError> {
    if path.is_empty()
        || path.len() > MAX_PATH_BYTES
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains('\\')
        || path.contains('\0')
        || path
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(error(
            "invalid-r1-path",
            format!("{path:?} is not a canonical relative workspace path"),
        ));
    }
    Ok(())
}

fn validate_files(files: &[InlineFile]) -> Result<(String, u64), PolicyError> {
    if files.is_empty() || files.len() > MAX_FILES {
        return Err(error(
            "invalid-r1-file-count",
            format!("workspace must contain 1..={MAX_FILES} files"),
        ));
    }
    let mut previous: Option<&str> = None;
    let mut total = 0usize;
    for file in files {
        validate_path(&file.path)?;
        if previous.is_some_and(|path| path >= file.path.as_str()) {
            return Err(error(
                "unsorted-r1-files",
                "workspace files must be strictly path-sorted and unique",
            ));
        }
        previous = Some(&file.path);
        if file.media_type.trim().is_empty() {
            return Err(error(
                "invalid-r1-media-type",
                format!("{} has a blank media type", file.path),
            ));
        }
        if file.content.len() > MAX_FILE_BYTES {
            return Err(error(
                "r1-file-too-large",
                format!("{} exceeds the per-file limit", file.path),
            ));
        }
        validate_sha256_hex("file.digest_hex", &file.digest_hex)?;
        if hex_sha256(file.content.as_bytes()) != file.digest_hex {
            return Err(error(
                "r1-file-digest-mismatch",
                format!("{} content does not match its digest", file.path),
            ));
        }
        total = total
            .checked_add(file.content.len())
            .ok_or_else(|| error("r1-tree-too-large", "workspace byte count overflowed"))?;
    }
    if total > MAX_TREE_BYTES {
        return Err(error(
            "r1-tree-too-large",
            "workspace exceeds the aggregate byte limit",
        ));
    }
    Ok((hex_sha256(&canonical_bytes(&files)?), total as u64))
}

fn validate_request(request: &ChangeRequest) -> Result<(String, u64), PolicyError> {
    if request.schema != CHANGE_REQUEST_SCHEMA {
        return Err(error(
            "unsupported-r1-change-schema",
            format!("expected schema {CHANGE_REQUEST_SCHEMA}"),
        ));
    }
    validate_label(&request.label, "label")?;
    validate_label(&request.package_name, "package_name")?;
    validate_label(&request.package_version, "package_version")?;
    validate_path(&request.entrypoint)?;
    validate_path(&request.patch.path)?;
    if request.patch.path != request.entrypoint {
        return Err(error(
            "r1-patch-outside-entrypoint",
            "the bounded R1 patch must replace the declared entrypoint",
        ));
    }
    validate_sha256_hex(
        "patch.expected_digest_hex",
        &request.patch.expected_digest_hex,
    )?;
    validate_sha256_hex(
        "patch.replacement_digest_hex",
        &request.patch.replacement_digest_hex,
    )?;
    if request.patch.replacement_content.len() > MAX_FILE_BYTES
        || request.patch.replacement_media_type != PROGRAM_MEDIA_TYPE
    {
        return Err(error(
            "invalid-r1-patch-replacement",
            "patch replacement must be a bounded text-program source",
        ));
    }
    if hex_sha256(request.patch.replacement_content.as_bytes())
        != request.patch.replacement_digest_hex
    {
        return Err(error(
            "r1-patch-replacement-digest-mismatch",
            "patch replacement content does not match its digest",
        ));
    }
    if request.patch.expected_digest_hex == request.patch.replacement_digest_hex {
        return Err(error(
            "r1-no-op-patch",
            "the one bounded CAS patch must make a real source change",
        ));
    }
    let (tree, total) = validate_files(&request.files)?;
    let entrypoint = request
        .files
        .iter()
        .find(|file| file.path == request.entrypoint)
        .ok_or_else(|| {
            error(
                "missing-r1-entrypoint",
                "entrypoint is absent from base tree",
            )
        })?;
    if entrypoint.media_type != PROGRAM_MEDIA_TYPE
        || entrypoint.digest_hex != request.patch.expected_digest_hex
    {
        return Err(error(
            "r1-patch-cas-mismatch",
            "patch expected digest/media does not match the base entrypoint",
        ));
    }
    Ok((tree, total))
}

fn file(path: &str, media_type: &str, content: String) -> InlineFile {
    InlineFile {
        path: path.to_string(),
        media_type: media_type.to_string(),
        digest_hex: hex_sha256(content.as_bytes()),
        content,
    }
}

/// Canonical, valid positive R1 input. The label participates in content
/// identity so repeated lifecycle cohorts can remain semantically identical
/// while retaining distinct job/source digests.
#[must_use]
pub fn canonical_positive_fixture_bytes(label: &str) -> Vec<u8> {
    assert!(validate_label(label, "fixture label").is_ok());
    let base_program = Program {
        schema: PROGRAM_SCHEMA.to_string(),
        instructions: vec![
            Instruction::Literal {
                value: "Hello, ".to_string(),
            },
            Instruction::Input,
            Instruction::Concat,
        ],
    };
    let changed_program = Program {
        schema: PROGRAM_SCHEMA.to_string(),
        instructions: vec![
            Instruction::Literal {
                value: "Hello, ".to_string(),
            },
            Instruction::Input,
            Instruction::Concat,
            Instruction::Literal {
                value: "!".to_string(),
            },
            Instruction::Concat,
        ],
    };
    let tests = TestSuite {
        schema: TEST_SCHEMA.to_string(),
        cases: vec![TestCase {
            name: "greets-factory".to_string(),
            input: "Factory".to_string(),
            expected: "Hello, Factory!".to_string(),
        }],
    };
    let base_content = String::from_utf8(canonical_bytes(&base_program).unwrap()).unwrap();
    let replacement_content =
        String::from_utf8(canonical_bytes(&changed_program).unwrap()).unwrap();
    let test_content = String::from_utf8(canonical_bytes(&tests).unwrap()).unwrap();
    let entrypoint = "src/main.wbt.json";
    let request = ChangeRequest {
        schema: CHANGE_REQUEST_SCHEMA.to_string(),
        label: label.to_string(),
        package_name: format!("r1-demo-{label}"),
        package_version: "1.0.0".to_string(),
        entrypoint: entrypoint.to_string(),
        provider_mode: ProviderMode::LocalFixture,
        files: vec![
            file(entrypoint, PROGRAM_MEDIA_TYPE, base_content.clone()),
            file(
                "tests/greeting.wbt-test.json",
                TEST_MEDIA_TYPE,
                test_content,
            ),
        ],
        patch: CasPatch {
            path: entrypoint.to_string(),
            expected_digest_hex: hex_sha256(base_content.as_bytes()),
            replacement_media_type: PROGRAM_MEDIA_TYPE.to_string(),
            replacement_digest_hex: hex_sha256(replacement_content.as_bytes()),
            replacement_content,
        },
    };
    canonical_bytes(&request).expect("positive fixture is serializable")
}

fn validate_program(program: &Program) -> Result<(), PolicyError> {
    if program.schema != PROGRAM_SCHEMA
        || program.instructions.is_empty()
        || program.instructions.len() > MAX_INSTRUCTIONS
    {
        return Err(error(
            "invalid-r1-program",
            "program schema/instruction count is outside the bounded language",
        ));
    }
    let mut depth = 0usize;
    let mut literal_bytes = 0usize;
    for instruction in &program.instructions {
        match instruction {
            Instruction::Input => depth += 1,
            Instruction::Literal { value } => {
                literal_bytes = literal_bytes.checked_add(value.len()).ok_or_else(|| {
                    error("r1-program-too-large", "literal byte count overflowed")
                })?;
                depth += 1;
            }
            Instruction::Concat => {
                if depth < 2 {
                    return Err(error(
                        "r1-program-stack-underflow",
                        "concat requires two stack values",
                    ));
                }
                depth -= 1;
            }
            Instruction::AsciiUpper | Instruction::AsciiLower | Instruction::Sha256Hex => {
                if depth < 1 {
                    return Err(error(
                        "r1-program-stack-underflow",
                        "unary instruction requires one stack value",
                    ));
                }
            }
        }
        if depth > MAX_INSTRUCTIONS {
            return Err(error(
                "r1-program-stack-limit",
                "program stack exceeds the instruction limit",
            ));
        }
    }
    if depth != 1 || literal_bytes > MAX_LITERAL_BYTES {
        return Err(error(
            "invalid-r1-program-result",
            "program must leave exactly one bounded value",
        ));
    }
    Ok(())
}

fn compile_program(program: &Program) -> Result<Vec<u8>, PolicyError> {
    validate_program(program)?;
    let count = u16::try_from(program.instructions.len()).map_err(|_| {
        error(
            "r1-program-too-large",
            "instruction count cannot be encoded as u16",
        )
    })?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(BYTECODE_MAGIC);
    bytes.extend_from_slice(&count.to_be_bytes());
    for instruction in &program.instructions {
        match instruction {
            Instruction::Input => bytes.push(1),
            Instruction::Literal { value } => {
                bytes.push(2);
                let length = u32::try_from(value.len()).map_err(|_| {
                    error("r1-literal-too-large", "literal cannot be encoded as u32")
                })?;
                bytes.extend_from_slice(&length.to_be_bytes());
                bytes.extend_from_slice(value.as_bytes());
            }
            Instruction::Concat => bytes.push(3),
            Instruction::AsciiUpper => bytes.push(4),
            Instruction::AsciiLower => bytes.push(5),
            Instruction::Sha256Hex => bytes.push(6),
        }
    }
    Ok(bytes)
}

fn take_u32(bytes: &[u8], cursor: &mut usize) -> Result<usize, PolicyError> {
    let end = cursor
        .checked_add(4)
        .ok_or_else(|| error("invalid-r1-bytecode", "bytecode cursor overflowed"))?;
    let slice = bytes
        .get(*cursor..end)
        .ok_or_else(|| error("invalid-r1-bytecode", "truncated bytecode length"))?;
    *cursor = end;
    Ok(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]) as usize)
}

fn execute_bytecode(bytecode: &[u8], input: &str) -> Result<String, PolicyError> {
    if input.len() > MAX_VALUE_BYTES
        || bytecode.len() < BYTECODE_MAGIC.len() + 2
        || !bytecode.starts_with(BYTECODE_MAGIC)
    {
        return Err(error(
            "invalid-r1-bytecode",
            "bytecode magic/size or input limit is invalid",
        ));
    }
    let mut cursor = BYTECODE_MAGIC.len();
    let count = u16::from_be_bytes([bytecode[cursor], bytecode[cursor + 1]]) as usize;
    cursor += 2;
    if count == 0 || count > MAX_INSTRUCTIONS {
        return Err(error(
            "invalid-r1-bytecode",
            "bytecode instruction count is outside its bound",
        ));
    }
    let mut stack = Vec::<String>::new();
    for _ in 0..count {
        let opcode = *bytecode
            .get(cursor)
            .ok_or_else(|| error("invalid-r1-bytecode", "truncated bytecode opcode"))?;
        cursor += 1;
        match opcode {
            1 => stack.push(input.to_string()),
            2 => {
                let length = take_u32(bytecode, &mut cursor)?;
                let end = cursor
                    .checked_add(length)
                    .ok_or_else(|| error("invalid-r1-bytecode", "literal cursor overflowed"))?;
                let literal = core::str::from_utf8(
                    bytecode
                        .get(cursor..end)
                        .ok_or_else(|| error("invalid-r1-bytecode", "truncated literal"))?,
                )
                .map_err(|_| error("invalid-r1-bytecode", "literal is not UTF-8"))?;
                cursor = end;
                stack.push(literal.to_string());
            }
            3 => {
                let right = stack.pop().ok_or_else(|| {
                    error("r1-bytecode-stack-underflow", "concat has no right value")
                })?;
                let mut left = stack.pop().ok_or_else(|| {
                    error("r1-bytecode-stack-underflow", "concat has no left value")
                })?;
                if left.len().saturating_add(right.len()) > MAX_VALUE_BYTES {
                    return Err(error(
                        "r1-program-output-limit",
                        "concat would exceed the output bound",
                    ));
                }
                left.push_str(&right);
                stack.push(left);
            }
            4 | 5 => {
                let value = stack.last_mut().ok_or_else(|| {
                    error("r1-bytecode-stack-underflow", "case operation has no value")
                })?;
                if opcode == 4 {
                    value.make_ascii_uppercase();
                } else {
                    value.make_ascii_lowercase();
                }
            }
            6 => {
                let value = stack.last_mut().ok_or_else(|| {
                    error("r1-bytecode-stack-underflow", "hash operation has no value")
                })?;
                *value = hex_sha256(value.as_bytes());
            }
            _ => {
                return Err(error(
                    "invalid-r1-bytecode",
                    format!("unsupported bytecode opcode {opcode}"),
                ));
            }
        }
        if stack.len() > MAX_INSTRUCTIONS {
            return Err(error(
                "r1-program-stack-limit",
                "bytecode stack exceeded its bound",
            ));
        }
    }
    if cursor != bytecode.len() || stack.len() != 1 {
        return Err(error(
            "invalid-r1-bytecode-result",
            "bytecode has trailing bytes or did not return exactly one value",
        ));
    }
    Ok(stack.pop().expect("checked one result"))
}

fn record_ref<'a, T>(
    value: &'a Option<Record<T>>,
    field: &str,
) -> Result<&'a Record<T>, PolicyError> {
    value
        .as_ref()
        .ok_or_else(|| error("missing-r1-record", format!("missing {field} record")))
}

fn validate_state(state: &WorkState) -> Result<(), PolicyError> {
    if state.schema != WORK_STATE_SCHEMA {
        return Err(error(
            "unsupported-r1-work-state",
            format!("expected schema {WORK_STATE_SCHEMA}"),
        ));
    }
    let (expected_base, _) = validate_request(&state.request)?;
    validate_sha256_hex("state.request_digest_hex", &state.request_digest_hex)?;
    if hex_sha256(&canonical_bytes(&state.request)?) != state.request_digest_hex {
        return Err(error(
            "r1-request-digest-mismatch",
            "work state request digest does not match the embedded request",
        ));
    }
    if state.base_tree_digest_hex != expected_base {
        return Err(error(
            "r1-base-tree-mismatch",
            "work state base tree differs from the request tree",
        ));
    }
    let (current_tree, _) = validate_files(&state.files)?;
    if state.current_tree_digest_hex != current_tree {
        return Err(error(
            "r1-current-tree-mismatch",
            "work state current tree digest is not truthful",
        ));
    }
    for (name, check) in [
        (
            "open",
            state
                .records
                .open
                .as_ref()
                .map(|value| verify_record(value, "records.open")),
        ),
        (
            "snapshot",
            state
                .records
                .snapshot
                .as_ref()
                .map(|value| verify_record(value, "records.snapshot")),
        ),
        (
            "patch",
            state
                .records
                .patch
                .as_ref()
                .map(|value| verify_record(value, "records.patch")),
        ),
        (
            "build",
            state
                .records
                .build
                .as_ref()
                .map(|value| verify_record(value, "records.build")),
        ),
        (
            "provider",
            state
                .records
                .provider
                .as_ref()
                .map(|value| verify_record(value, "records.provider")),
        ),
        (
            "validation",
            state
                .records
                .validation
                .as_ref()
                .map(|value| verify_record(value, "records.validation")),
        ),
        (
            "review",
            state
                .records
                .review
                .as_ref()
                .map(|value| verify_record(value, "records.review")),
        ),
        (
            "package",
            state
                .records
                .package
                .as_ref()
                .map(|value| verify_record(value, "records.package")),
        ),
        (
            "verification",
            state
                .records
                .verification
                .as_ref()
                .map(|value| verify_record(value, "records.verification")),
        ),
        (
            "evidence",
            state
                .records
                .evidence
                .as_ref()
                .map(|value| verify_record(value, "records.evidence")),
        ),
        (
            "resolution",
            state
                .records
                .resolution
                .as_ref()
                .map(|value| verify_record(value, "records.resolution")),
        ),
    ] {
        if let Some(result) = check {
            result
                .map_err(|failure| error(failure.code, format!("{name}: {}", failure.message)))?;
        }
    }
    if let Some(artifact) = &state.artifact {
        if artifact.language != "wasm-biotic:text-program@1"
            || hex_sha256(&artifact.bytecode) != artifact.digest_hex
            || artifact.bytecode.len() > MAX_FILE_BYTES
        {
            return Err(error(
                "r1-artifact-mismatch",
                "compiled artifact identity/language/size is invalid",
            ));
        }
        validate_sha256_hex("artifact.digest_hex", &artifact.digest_hex)?;
    }
    let presence = [
        state.records.open.is_some(),
        state.records.snapshot.is_some(),
        state.records.patch.is_some(),
        state.records.build.is_some(),
        state.records.provider.is_some(),
        state.records.validation.is_some(),
        state.records.review.is_some(),
        state.records.package.is_some(),
        state.records.verification.is_some(),
        state.records.evidence.is_some(),
        state.records.resolution.is_some(),
    ];
    let valid_phase = match state.stage {
        WorkStage::Opened => {
            presence
                == [
                    true, false, false, false, false, false, false, false, false, false, false,
                ]
                && state.artifact.is_none()
        }
        WorkStage::Snapshotted => {
            presence
                == [
                    true, true, false, false, false, false, false, false, false, false, false,
                ]
                && state.artifact.is_none()
        }
        WorkStage::Patched => {
            presence
                == [
                    true, true, true, false, false, false, false, false, false, false, false,
                ]
                && state.artifact.is_none()
        }
        WorkStage::Built => {
            presence[0..4] == [true, true, true, true]
                && !presence[5..].iter().any(|present| *present)
                && state.artifact.is_some()
        }
        WorkStage::Validated => {
            presence
                == [
                    true, true, true, true, true, true, false, false, false, false, false,
                ]
                && state.artifact.is_some()
        }
        WorkStage::Reviewed => {
            presence
                == [
                    true, true, true, true, true, true, true, false, false, false, false,
                ]
                && state.artifact.is_some()
        }
        WorkStage::Packaged => {
            presence
                == [
                    true, true, true, true, true, true, true, true, false, false, false,
                ]
                && state.artifact.is_some()
        }
        WorkStage::Verified => {
            presence
                == [
                    true, true, true, true, true, true, true, true, true, false, false,
                ]
                && state.artifact.is_some()
        }
        WorkStage::Evidenced => {
            presence
                == [
                    true, true, true, true, true, true, true, true, true, true, false,
                ]
                && state.artifact.is_some()
        }
        WorkStage::Resolved => presence.iter().all(|present| *present) && state.artifact.is_some(),
    };
    if !valid_phase {
        return Err(error(
            "r1-stage-record-inventory-mismatch",
            "work stage does not have its exact required record/artifact inventory",
        ));
    }

    let open = record_ref(&state.records.open, "open")?;
    if open.body.operation != Operation::WorkspaceOpen.as_str()
        || open.body.request_digest_hex != state.request_digest_hex
        || open.body.base_tree_digest_hex != state.base_tree_digest_hex
    {
        return Err(error(
            "r1-open-lineage-mismatch",
            "open record is not bound to the exact request/base tree",
        ));
    }
    if let Some(snapshot) = &state.records.snapshot
        && (snapshot.body.operation != Operation::WorkspaceSnapshot.as_str()
            || snapshot.body.tree_digest_hex != state.base_tree_digest_hex)
    {
        return Err(error(
            "r1-snapshot-lineage-mismatch",
            "snapshot record is not bound to the base tree",
        ));
    }
    if let Some(patch) = &state.records.patch
        && (patch.body.operation != Operation::WorkspacePatch.as_str()
            || patch.body.base_tree_digest_hex != state.base_tree_digest_hex
            || patch.body.patched_tree_digest_hex != state.current_tree_digest_hex
            || patch.body.path != state.request.patch.path
            || patch.body.before_digest_hex != state.request.patch.expected_digest_hex
            || patch.body.after_digest_hex != state.request.patch.replacement_digest_hex
            || !patch.body.source_changed)
    {
        return Err(error(
            "r1-patch-lineage-mismatch",
            "patch record is not bound to the exact CAS source change",
        ));
    }
    if let Some(build) = &state.records.build {
        let artifact = state.artifact.as_ref().ok_or_else(|| {
            error(
                "missing-r1-artifact",
                "build record exists without an artifact",
            )
        })?;
        if build.body.operation != Operation::CandidateBuild.as_str()
            || build.body.source_tree_digest_hex != state.current_tree_digest_hex
            || build.body.artifact_digest_hex != artifact.digest_hex
            || build.body.artifact_size_bytes != artifact.bytecode.len() as u64
        {
            return Err(error(
                "r1-build-lineage-mismatch",
                "build record is not bound to the exact tree/bytecode",
            ));
        }
    }
    Ok(())
}

fn parse_state(bytes: &[u8]) -> Result<WorkState, PolicyError> {
    let state: WorkState = parse_canonical(bytes, "R1 work state")?;
    validate_state(&state)?;
    Ok(state)
}

fn state_output(state: &WorkState) -> Result<ServiceOutput, PolicyError> {
    Ok(ServiceOutput {
        media_type: WORK_STATE_MEDIA_TYPE.to_string(),
        bytes: canonical_bytes(state)?,
    })
}

fn require_stage(
    state: &WorkState,
    expected: WorkStage,
    operation: &str,
) -> Result<(), PolicyError> {
    if state.stage != expected {
        return Err(error(
            "r1-stage-mismatch",
            format!("{operation} requires {expected:?}, found {:?}", state.stage),
        ));
    }
    Ok(())
}

fn workspace_open(invocation: &Invocation<'_>, input: &[u8]) -> Result<ServiceOutput, PolicyError> {
    let request: ChangeRequest = parse_canonical(input, "R1 change request")?;
    let (base_tree_digest_hex, total_bytes) = validate_request(&request)?;
    let request_digest_hex = hex_sha256(input);
    let open = record(OpenRecord {
        operation: Operation::WorkspaceOpen.as_str().to_string(),
        request_digest_hex: request_digest_hex.clone(),
        base_tree_digest_hex: base_tree_digest_hex.clone(),
        file_count: request.files.len() as u32,
        total_bytes,
    })?;
    let state = WorkState {
        schema: WORK_STATE_SCHEMA.to_string(),
        stage: WorkStage::Opened,
        request_digest_hex,
        request: request.clone(),
        base_tree_digest_hex: base_tree_digest_hex.clone(),
        current_tree_digest_hex: base_tree_digest_hex,
        files: request.files,
        artifact: None,
        records: WorkRecords {
            open: Some(open),
            ..WorkRecords::default()
        },
    };
    if invocation.input_digest_hex != hex_sha256(input) {
        return Err(error(
            "r1-invocation-input-mismatch",
            "workspace-open input identity changed during decoding",
        ));
    }
    state_output(&state)
}

fn workspace_snapshot(
    invocation: &Invocation<'_>,
    input: &[u8],
) -> Result<ServiceOutput, PolicyError> {
    let mut state = parse_state(input)?;
    require_stage(&state, WorkStage::Opened, "workspace-snapshot")?;
    let (_, total_bytes) = validate_files(&state.files)?;
    let paths = state
        .files
        .iter()
        .map(|file| file.path.as_str())
        .collect::<Vec<_>>();
    state.records.snapshot = Some(record(SnapshotRecord {
        operation: Operation::WorkspaceSnapshot.as_str().to_string(),
        input_state_digest_hex: invocation.input_digest_hex.to_string(),
        tree_digest_hex: state.current_tree_digest_hex.clone(),
        sorted_paths_digest_hex: hex_sha256(&canonical_bytes(&paths)?),
        file_count: state.files.len() as u32,
        total_bytes,
    })?);
    state.stage = WorkStage::Snapshotted;
    state_output(&state)
}

fn workspace_patch(
    invocation: &Invocation<'_>,
    input: &[u8],
) -> Result<ServiceOutput, PolicyError> {
    let mut state = parse_state(input)?;
    require_stage(&state, WorkStage::Snapshotted, "workspace-patch")?;
    let patch = &state.request.patch;
    let target = state
        .files
        .iter_mut()
        .find(|file| file.path == patch.path)
        .ok_or_else(|| error("r1-patch-target-missing", "CAS patch target is absent"))?;
    if target.digest_hex != patch.expected_digest_hex {
        return Err(error(
            "r1-patch-cas-mismatch",
            "CAS patch expected digest does not match current source",
        ));
    }
    let before = target.digest_hex.clone();
    target.media_type.clone_from(&patch.replacement_media_type);
    target.content.clone_from(&patch.replacement_content);
    target.digest_hex.clone_from(&patch.replacement_digest_hex);
    let (patched_tree_digest_hex, _) = validate_files(&state.files)?;
    state.records.patch = Some(record(PatchRecord {
        operation: Operation::WorkspacePatch.as_str().to_string(),
        input_state_digest_hex: invocation.input_digest_hex.to_string(),
        path: patch.path.clone(),
        before_digest_hex: before,
        after_digest_hex: patch.replacement_digest_hex.clone(),
        base_tree_digest_hex: state.base_tree_digest_hex.clone(),
        patched_tree_digest_hex: patched_tree_digest_hex.clone(),
        source_changed: true,
    })?);
    state.current_tree_digest_hex = patched_tree_digest_hex;
    state.stage = WorkStage::Patched;
    state_output(&state)
}

fn candidate_build(
    invocation: &Invocation<'_>,
    input: &[u8],
) -> Result<ServiceOutput, PolicyError> {
    let mut state = parse_state(input)?;
    require_stage(&state, WorkStage::Patched, "candidate-build")?;
    let source = state
        .files
        .iter()
        .find(|file| file.path == state.request.entrypoint)
        .ok_or_else(|| error("missing-r1-entrypoint", "patched entrypoint is absent"))?;
    if source.media_type != PROGRAM_MEDIA_TYPE {
        return Err(error(
            "invalid-r1-entrypoint-media",
            "entrypoint is not a text-program source",
        ));
    }
    let program: Program = parse_canonical(source.content.as_bytes(), "text program")?;
    let bytecode = compile_program(&program)?;
    let artifact = CompiledArtifact {
        language: "wasm-biotic:text-program@1".to_string(),
        digest_hex: hex_sha256(&bytecode),
        instruction_count: program.instructions.len() as u32,
        bytecode,
    };
    state.records.build = Some(record(BuildRecord {
        operation: Operation::CandidateBuild.as_str().to_string(),
        input_state_digest_hex: invocation.input_digest_hex.to_string(),
        source_tree_digest_hex: state.current_tree_digest_hex.clone(),
        source_digest_hex: source.digest_hex.clone(),
        artifact_digest_hex: artifact.digest_hex.clone(),
        artifact_size_bytes: artifact.bytecode.len() as u64,
        instruction_count: artifact.instruction_count,
        compiler: "wasm-biotic:text-compiler@1".to_string(),
        producer_component_hex: invocation.service_component_hex.to_string(),
    })?);
    state.artifact = Some(artifact);
    state.stage = WorkStage::Built;
    state_output(&state)
}

fn provider_proposal(
    invocation: &Invocation<'_>,
    input: &[u8],
) -> Result<ServiceOutput, PolicyError> {
    let mut state = parse_state(input)?;
    require_stage(&state, WorkStage::Built, "factory-provider-proposal")?;
    if state.records.provider.is_some() {
        return Err(error(
            "r1-provider-already-recorded",
            "provider policy may be evaluated only once per immutable built state",
        ));
    }
    if state.request.provider_mode != ProviderMode::LocalFixture {
        return Err(error(
            "external-transport-disabled",
            "remote provider modes are unavailable in the bounded-local R1 profile",
        ));
    }
    let artifact = state.artifact.as_ref().ok_or_else(|| {
        error(
            "missing-r1-artifact",
            "provider proposal requires an artifact",
        )
    })?;
    let material = (
        "wasm-biotic.r1-provider-request.v1",
        state.request_digest_hex.as_str(),
        state.current_tree_digest_hex.as_str(),
        artifact.digest_hex.as_str(),
        LOCAL_MODEL,
    );
    let request_digest_hex = hex_sha256(&canonical_bytes(&material)?);
    let response = format!(
        "local-fixture|validate|{}|{}",
        state.current_tree_digest_hex, artifact.digest_hex
    );
    state.records.provider = Some(record(ProviderRecord {
        operation: Operation::FactoryProviderProposal.as_str().to_string(),
        input_state_digest_hex: invocation.input_digest_hex.to_string(),
        policy: "local-fixture".to_string(),
        model: LOCAL_MODEL.to_string(),
        request_digest_hex,
        response_digest_hex: hex_sha256(response.as_bytes()),
        recommendation: "validate".to_string(),
        external_transport_used: false,
        producer_component_hex: invocation.service_component_hex.to_string(),
    })?);
    // Provider policy enriches the built candidate; it does not manufacture a
    // build or advance validation state.
    state_output(&state)
}

fn validation_body(
    state: &WorkState,
    invocation: &Invocation<'_>,
) -> Result<ValidationRecord, PolicyError> {
    let artifact = state
        .artifact
        .as_ref()
        .ok_or_else(|| error("missing-r1-artifact", "validation requires an artifact"))?;
    let provider = record_ref(&state.records.provider, "provider")?;
    if provider.body.policy != "local-fixture"
        || provider.body.model != LOCAL_MODEL
        || provider.body.recommendation != "validate"
        || provider.body.external_transport_used
    {
        return Err(error(
            "invalid-r1-provider-record",
            "validation requires the exact bounded-local provider policy record",
        ));
    }
    let mut test_files = Vec::new();
    let mut observations = Vec::new();
    let mut case_count = 0usize;
    for file in &state.files {
        if !file.path.starts_with("tests/") || !file.path.ends_with(".wbt-test.json") {
            continue;
        }
        if file.media_type != TEST_MEDIA_TYPE {
            return Err(error(
                "invalid-r1-test-media",
                format!("{} has the wrong test media type", file.path),
            ));
        }
        let suite: TestSuite = parse_canonical(file.content.as_bytes(), "text-program test")?;
        if suite.schema != TEST_SCHEMA || suite.cases.is_empty() {
            return Err(error(
                "invalid-r1-test-suite",
                format!("{} has an invalid schema or no cases", file.path),
            ));
        }
        let mut previous: Option<&str> = None;
        for case in &suite.cases {
            validate_label(&case.name, "test case name")?;
            if previous.is_some_and(|name| name >= case.name.as_str()) {
                return Err(error(
                    "unsorted-r1-test-cases",
                    "test cases must be strictly name-sorted and unique",
                ));
            }
            previous = Some(&case.name);
            if case.input.len() > MAX_VALUE_BYTES || case.expected.len() > MAX_VALUE_BYTES {
                return Err(error(
                    "r1-test-value-too-large",
                    "test input or expectation exceeds its bound",
                ));
            }
            case_count += 1;
            if case_count > MAX_TEST_CASES {
                return Err(error(
                    "r1-test-count-limit",
                    "discovered tests exceed the bounded case count",
                ));
            }
            let actual = execute_bytecode(&artifact.bytecode, &case.input)?;
            observations.push(TestObservation {
                file: file.path.clone(),
                name: case.name.clone(),
                input: case.input.clone(),
                expected: case.expected.clone(),
                passed: actual == case.expected,
                actual,
            });
        }
        test_files.push(file.path.clone());
    }
    if test_files.is_empty() || observations.is_empty() {
        return Err(error(
            "r1-tests-not-discovered",
            "validation requires at least one discovered test file and case",
        ));
    }
    let passed = observations.iter().filter(|item| item.passed).count();
    Ok(ValidationRecord {
        operation: Operation::ValidationProve.as_str().to_string(),
        input_state_digest_hex: invocation.input_digest_hex.to_string(),
        artifact_digest_hex: artifact.digest_hex.clone(),
        provider_record_digest_hex: provider.digest_hex.clone(),
        discovered_test_files: test_files,
        total_tests: observations.len() as u32,
        passed_tests: passed as u32,
        all_passed: passed == observations.len(),
        observations,
        producer_component_hex: invocation.service_component_hex.to_string(),
    })
}

fn validation_prove(
    invocation: &Invocation<'_>,
    input: &[u8],
) -> Result<ServiceOutput, PolicyError> {
    let mut state = parse_state(input)?;
    require_stage(&state, WorkStage::Built, "validation-prove")?;
    let body = validation_body(&state, invocation)?;
    state.records.validation = Some(record(body)?);
    state.stage = WorkStage::Validated;
    state_output(&state)
}

fn review_candidate(
    invocation: &Invocation<'_>,
    input: &[u8],
) -> Result<ServiceOutput, PolicyError> {
    let mut state = parse_state(input)?;
    require_stage(&state, WorkStage::Validated, "review-candidate")?;
    let patch = record_ref(&state.records.patch, "patch")?;
    let build = record_ref(&state.records.build, "build")?;
    let provider = record_ref(&state.records.provider, "provider")?;
    let validation = record_ref(&state.records.validation, "validation")?;
    let checks = vec![
        "cas-source-change".to_string(),
        "component-compiler-bytecode".to_string(),
        "local-fixture-provider-policy".to_string(),
        "discovered-tests-green".to_string(),
        "exact-content-lineage".to_string(),
    ];
    let approved = patch.body.source_changed
        && patch.body.path.starts_with("src/")
        && build.body.source_tree_digest_hex == state.current_tree_digest_hex
        && provider.body.policy == "local-fixture"
        && !provider.body.external_transport_used
        && validation.body.total_tests > 0
        && validation.body.all_passed
        && validation.body.artifact_digest_hex == build.body.artifact_digest_hex;
    state.records.review = Some(record(ReviewRecord {
        operation: Operation::ReviewCandidate.as_str().to_string(),
        input_state_digest_hex: invocation.input_digest_hex.to_string(),
        patch_record_digest_hex: patch.digest_hex.clone(),
        build_record_digest_hex: build.digest_hex.clone(),
        validation_record_digest_hex: validation.digest_hex.clone(),
        checks,
        approved,
        producer_component_hex: invocation.service_component_hex.to_string(),
    })?);
    state.stage = WorkStage::Reviewed;
    state_output(&state)
}

#[derive(Serialize)]
struct PackageClosure<'a> {
    schema: &'static str,
    request_digest_hex: &'a str,
    tree_digest_hex: &'a str,
    artifact_digest_hex: &'a str,
    patch_record_digest_hex: &'a str,
    build_record_digest_hex: &'a str,
    provider_record_digest_hex: &'a str,
    validation_record_digest_hex: &'a str,
    review_record_digest_hex: &'a str,
}

fn package_closure_digest(state: &WorkState) -> Result<String, PolicyError> {
    let artifact = state
        .artifact
        .as_ref()
        .ok_or_else(|| error("missing-r1-artifact", "package closure has no artifact"))?;
    let patch = record_ref(&state.records.patch, "patch")?;
    let build = record_ref(&state.records.build, "build")?;
    let provider = record_ref(&state.records.provider, "provider")?;
    let validation = record_ref(&state.records.validation, "validation")?;
    let review = record_ref(&state.records.review, "review")?;
    Ok(hex_sha256(&canonical_bytes(&PackageClosure {
        schema: "wasm-biotic.r1-package-closure.v1",
        request_digest_hex: &state.request_digest_hex,
        tree_digest_hex: &state.current_tree_digest_hex,
        artifact_digest_hex: &artifact.digest_hex,
        patch_record_digest_hex: &patch.digest_hex,
        build_record_digest_hex: &build.digest_hex,
        provider_record_digest_hex: &provider.digest_hex,
        validation_record_digest_hex: &validation.digest_hex,
        review_record_digest_hex: &review.digest_hex,
    })?))
}

fn package_publish(
    invocation: &Invocation<'_>,
    input: &[u8],
) -> Result<ServiceOutput, PolicyError> {
    let mut state = parse_state(input)?;
    require_stage(&state, WorkStage::Reviewed, "package-publish")?;
    let review = record_ref(&state.records.review, "review")?;
    let validation = record_ref(&state.records.validation, "validation")?;
    if !review.body.approved || !validation.body.all_passed {
        return Err(error(
            "r1-package-not-approved",
            "only a green, approved candidate can be published",
        ));
    }
    let artifact = state.artifact.as_ref().expect("validated state artifact");
    let build = state.records.build.as_ref().expect("reviewed state build");
    let closure_digest_hex = package_closure_digest(&state)?;
    state.records.package = Some(record(PackageRecord {
        operation: Operation::PackagePublish.as_str().to_string(),
        input_state_digest_hex: invocation.input_digest_hex.to_string(),
        package_name: state.request.package_name.clone(),
        package_version: state.request.package_version.clone(),
        tree_digest_hex: state.current_tree_digest_hex.clone(),
        artifact_digest_hex: artifact.digest_hex.clone(),
        build_record_digest_hex: build.digest_hex.clone(),
        validation_record_digest_hex: validation.digest_hex.clone(),
        review_record_digest_hex: review.digest_hex.clone(),
        closure_digest_hex,
        producer_component_hex: invocation.service_component_hex.to_string(),
    })?);
    state.stage = WorkStage::Packaged;
    state_output(&state)
}

fn package_verify(invocation: &Invocation<'_>, input: &[u8]) -> Result<ServiceOutput, PolicyError> {
    let mut state = parse_state(input)?;
    require_stage(&state, WorkStage::Packaged, "package-verify")?;
    let package = record_ref(&state.records.package, "package")?;
    let expected = package_closure_digest(&state)?;
    if package.body.closure_digest_hex != expected
        || package.body.tree_digest_hex != state.current_tree_digest_hex
        || state
            .artifact
            .as_ref()
            .is_none_or(|artifact| package.body.artifact_digest_hex != artifact.digest_hex)
    {
        return Err(error(
            "r1-package-verification-failed",
            "package record does not close over the exact approved artifact/tree",
        ));
    }
    state.records.verification = Some(record(VerificationRecord {
        operation: Operation::PackageVerify.as_str().to_string(),
        input_state_digest_hex: invocation.input_digest_hex.to_string(),
        package_record_digest_hex: package.digest_hex.clone(),
        closure_digest_hex: expected,
        verified: true,
        producer_component_hex: invocation.service_component_hex.to_string(),
    })?);
    state.stage = WorkStage::Verified;
    state_output(&state)
}

#[derive(Serialize)]
struct EvidenceClosure<'a> {
    schema: &'static str,
    request: &'a str,
    snapshot: &'a str,
    patch: &'a str,
    build: &'a str,
    provider: &'a str,
    validation: &'a str,
    review: &'a str,
    package: &'a str,
    verification: &'a str,
}

fn evidence_closure_digest(state: &WorkState) -> Result<String, PolicyError> {
    Ok(hex_sha256(&canonical_bytes(&EvidenceClosure {
        schema: "wasm-biotic.r1-evidence-closure.v1",
        request: &state.request_digest_hex,
        snapshot: &record_ref(&state.records.snapshot, "snapshot")?.digest_hex,
        patch: &record_ref(&state.records.patch, "patch")?.digest_hex,
        build: &record_ref(&state.records.build, "build")?.digest_hex,
        provider: &record_ref(&state.records.provider, "provider")?.digest_hex,
        validation: &record_ref(&state.records.validation, "validation")?.digest_hex,
        review: &record_ref(&state.records.review, "review")?.digest_hex,
        package: &record_ref(&state.records.package, "package")?.digest_hex,
        verification: &record_ref(&state.records.verification, "verification")?.digest_hex,
    })?))
}

fn evidence_publish(
    invocation: &Invocation<'_>,
    input: &[u8],
) -> Result<ServiceOutput, PolicyError> {
    let mut state = parse_state(input)?;
    require_stage(&state, WorkStage::Verified, "evidence-publish")?;
    let closure_digest_hex = evidence_closure_digest(&state)?;
    state.records.evidence = Some(record(EvidenceRecord {
        operation: Operation::EvidencePublish.as_str().to_string(),
        input_state_digest_hex: invocation.input_digest_hex.to_string(),
        request_digest_hex: state.request_digest_hex.clone(),
        snapshot_record_digest_hex: record_ref(&state.records.snapshot, "snapshot")?
            .digest_hex
            .clone(),
        patch_record_digest_hex: record_ref(&state.records.patch, "patch")?
            .digest_hex
            .clone(),
        build_record_digest_hex: record_ref(&state.records.build, "build")?
            .digest_hex
            .clone(),
        provider_record_digest_hex: record_ref(&state.records.provider, "provider")?
            .digest_hex
            .clone(),
        validation_record_digest_hex: record_ref(&state.records.validation, "validation")?
            .digest_hex
            .clone(),
        review_record_digest_hex: record_ref(&state.records.review, "review")?
            .digest_hex
            .clone(),
        package_record_digest_hex: record_ref(&state.records.package, "package")?
            .digest_hex
            .clone(),
        verification_record_digest_hex: record_ref(&state.records.verification, "verification")?
            .digest_hex
            .clone(),
        closure_digest_hex,
        producer_component_hex: invocation.service_component_hex.to_string(),
    })?);
    state.stage = WorkStage::Evidenced;
    state_output(&state)
}

fn evidence_resolve(
    invocation: &Invocation<'_>,
    input: &[u8],
) -> Result<ServiceOutput, PolicyError> {
    let mut state = parse_state(input)?;
    require_stage(&state, WorkStage::Evidenced, "evidence-resolve")?;
    let evidence = record_ref(&state.records.evidence, "evidence")?;
    if evidence.body.closure_digest_hex != evidence_closure_digest(&state)? {
        return Err(error(
            "r1-evidence-resolution-failed",
            "evidence record does not resolve to the exact work closure",
        ));
    }
    let package = record_ref(&state.records.package, "package")?;
    state.records.resolution = Some(record(ResolutionRecord {
        operation: Operation::EvidenceResolve.as_str().to_string(),
        input_state_digest_hex: invocation.input_digest_hex.to_string(),
        evidence_record_digest_hex: evidence.digest_hex.clone(),
        package_record_digest_hex: package.digest_hex.clone(),
        resolved: true,
        producer_component_hex: invocation.service_component_hex.to_string(),
    })?);
    state.stage = WorkStage::Resolved;
    state_output(&state)
}

fn validate_deployment_state(state: &DeploymentState) -> Result<(), PolicyError> {
    if state.schema != DEPLOYMENT_STATE_SCHEMA || state.deployment_id.trim().is_empty() {
        return Err(error(
            "invalid-r1-deployment-state",
            "deployment state schema/id is invalid",
        ));
    }
    if state.target != DeploymentTarget::Local {
        return Err(error(
            "external-transport-disabled",
            "remote deployment targets are unavailable in the bounded-local R1 profile",
        ));
    }
    validate_sha256_hex("deployment.package_digest_hex", &state.package_digest_hex)?;
    let revision_len = usize::try_from(state.revision).map_err(|_| {
        error(
            "r1-deployment-revision-overflow",
            "deployment revision cannot be represented on this target",
        )
    })?;
    if state.revision == 0 || state.transitions.len() != revision_len {
        return Err(error(
            "r1-deployment-revision-mismatch",
            "deployment revision must equal its complete transition count",
        ));
    }
    for (index, transition) in state.transitions.iter().enumerate() {
        verify_record(transition, "deployment.transition")?;
        let from_revision = u64::try_from(index).map_err(|_| {
            error(
                "r1-deployment-revision-overflow",
                "deployment transition index cannot be represented as u64",
            )
        })?;
        let to_revision = from_revision.checked_add(1).ok_or_else(|| {
            error(
                "r1-deployment-revision-overflow",
                "deployment transition revision overflowed",
            )
        })?;
        if transition.body.from_revision != from_revision
            || transition.body.to_revision != to_revision
        {
            return Err(error(
                "r1-deployment-cas-gap",
                "deployment transition revisions are not contiguous",
            ));
        }
        if index > 0
            && transition.body.from_status
                != Some(state.transitions[index - 1].body.to_status.clone())
        {
            return Err(error(
                "r1-deployment-status-gap",
                "deployment transition statuses do not form one CAS chain",
            ));
        }
    }
    if state
        .transitions
        .last()
        .is_none_or(|value| value.body.to_status != state.status)
    {
        return Err(error(
            "r1-deployment-terminal-mismatch",
            "deployment state does not match its last transition",
        ));
    }
    Ok(())
}

fn deployment_output(state: &DeploymentState) -> Result<ServiceOutput, PolicyError> {
    Ok(ServiceOutput {
        media_type: DEPLOYMENT_STATE_MEDIA_TYPE.to_string(),
        bytes: canonical_bytes(state)?,
    })
}

fn deployment_initialize(
    invocation: &Invocation<'_>,
    input: &[u8],
) -> Result<ServiceOutput, PolicyError> {
    let plan: DeploymentPlan = parse_canonical(input, "R1 deployment plan")?;
    if plan.schema != DEPLOYMENT_PLAN_SCHEMA
        || plan.deployment_id.trim().is_empty()
        || plan.expected_revision != 0
    {
        return Err(error(
            "invalid-r1-deployment-plan",
            "initial deployment plan must use revision zero and a nonblank id",
        ));
    }
    validate_sha256_hex("deployment.package_digest_hex", &plan.package_digest_hex)?;
    if plan.target != DeploymentTarget::Local {
        return Err(error(
            "external-transport-disabled",
            "remote deployment targets are unavailable in the bounded-local R1 profile",
        ));
    }
    let status = DeploymentStatus::Initialized;
    let transition = record(DeploymentTransition {
        operation: Operation::DeploymentInitialize.as_str().to_string(),
        input_digest_hex: invocation.input_digest_hex.to_string(),
        from_revision: 0,
        to_revision: 1,
        from_status: None,
        to_status: status.clone(),
    })?;
    deployment_output(&DeploymentState {
        schema: DEPLOYMENT_STATE_SCHEMA.to_string(),
        deployment_id: plan.deployment_id,
        target: plan.target,
        package_digest_hex: plan.package_digest_hex,
        revision: 1,
        status,
        fixture_observation: plan.fixture_observation,
        transitions: vec![transition],
    })
}

fn parse_deployment(input: &[u8]) -> Result<DeploymentState, PolicyError> {
    let state: DeploymentState = parse_canonical(input, "R1 deployment state")?;
    validate_deployment_state(&state)?;
    Ok(state)
}

fn deployment_transition(
    invocation: &Invocation<'_>,
    input: &[u8],
    operation: Operation,
) -> Result<ServiceOutput, PolicyError> {
    let mut state = parse_deployment(input)?;
    let expected = match operation {
        Operation::DeploymentActivate => DeploymentStatus::Initialized,
        Operation::DeploymentObserve => DeploymentStatus::Active,
        Operation::DeploymentRollback => DeploymentStatus::ObservedUnhealthy,
        _ => {
            return Err(error(
                "unsupported-r1-deployment-operation",
                "operation is not a local deployment transition",
            ));
        }
    };
    if state.status != expected {
        return Err(error(
            "r1-deployment-cas-mismatch",
            format!(
                "{} requires {expected:?} at revision {}, found {:?}",
                operation.as_str(),
                state.revision,
                state.status
            ),
        ));
    }
    let next = match operation {
        Operation::DeploymentActivate => DeploymentStatus::Active,
        Operation::DeploymentObserve => match state.fixture_observation {
            Observation::Healthy => DeploymentStatus::ObservedHealthy,
            Observation::Unhealthy => DeploymentStatus::ObservedUnhealthy,
        },
        Operation::DeploymentRollback => DeploymentStatus::RolledBack,
        _ => unreachable!(),
    };
    let next_revision = state.revision.checked_add(1).ok_or_else(|| {
        error(
            "r1-deployment-revision-overflow",
            "deployment revision cannot advance beyond u64::MAX",
        )
    })?;
    let transition = record(DeploymentTransition {
        operation: operation.as_str().to_string(),
        input_digest_hex: invocation.input_digest_hex.to_string(),
        from_revision: state.revision,
        to_revision: next_revision,
        from_status: Some(state.status.clone()),
        to_status: next.clone(),
    })?;
    state.revision = next_revision;
    state.status = next;
    state.transitions.push(transition);
    validate_deployment_state(&state)?;
    deployment_output(&state)
}

fn require_media(invocation: &Invocation<'_>, expected: &str) -> Result<(), PolicyError> {
    if invocation.input_media_type != expected {
        return Err(error(
            "r1-media-type-mismatch",
            format!(
                "{} requires {expected}, received {}",
                invocation.operation.as_str(),
                invocation.input_media_type
            ),
        ));
    }
    Ok(())
}

/// Executes one strict R1 semantic operation. Callers must route every
/// reserved R1 media type here; there is intentionally no typed fallback.
pub fn transform(invocation: &Invocation<'_>, input: &[u8]) -> Result<ServiceOutput, PolicyError> {
    match invocation.operation {
        Operation::WorkspaceOpen => {
            require_media(invocation, CHANGE_REQUEST_MEDIA_TYPE)?;
            workspace_open(invocation, input)
        }
        Operation::WorkspaceSnapshot => {
            require_media(invocation, WORK_STATE_MEDIA_TYPE)?;
            workspace_snapshot(invocation, input)
        }
        Operation::WorkspacePatch => {
            require_media(invocation, WORK_STATE_MEDIA_TYPE)?;
            workspace_patch(invocation, input)
        }
        Operation::CandidateBuild => {
            require_media(invocation, WORK_STATE_MEDIA_TYPE)?;
            candidate_build(invocation, input)
        }
        Operation::FactoryProviderProposal => {
            require_media(invocation, WORK_STATE_MEDIA_TYPE)?;
            provider_proposal(invocation, input)
        }
        Operation::ValidationProve => {
            require_media(invocation, WORK_STATE_MEDIA_TYPE)?;
            validation_prove(invocation, input)
        }
        Operation::ReviewCandidate => {
            require_media(invocation, WORK_STATE_MEDIA_TYPE)?;
            review_candidate(invocation, input)
        }
        Operation::PackagePublish => {
            require_media(invocation, WORK_STATE_MEDIA_TYPE)?;
            package_publish(invocation, input)
        }
        Operation::PackageVerify => {
            require_media(invocation, WORK_STATE_MEDIA_TYPE)?;
            package_verify(invocation, input)
        }
        Operation::EvidencePublish => {
            require_media(invocation, WORK_STATE_MEDIA_TYPE)?;
            evidence_publish(invocation, input)
        }
        Operation::EvidenceResolve => {
            require_media(invocation, WORK_STATE_MEDIA_TYPE)?;
            evidence_resolve(invocation, input)
        }
        Operation::DeploymentInitialize => {
            require_media(invocation, DEPLOYMENT_PLAN_MEDIA_TYPE)?;
            deployment_initialize(invocation, input)
        }
        Operation::DeploymentActivate
        | Operation::DeploymentObserve
        | Operation::DeploymentRollback => {
            require_media(invocation, DEPLOYMENT_STATE_MEDIA_TYPE)?;
            deployment_transition(invocation, input, invocation.operation)
        }
        _ => Err(error(
            "unsupported-r1-operation",
            format!(
                "{} has no strict bounded R1 semantic implementation",
                invocation.operation.as_str()
            ),
        )),
    }
}

fn required_operation_history(state: &WorkState) -> Result<Vec<String>, PolicyError> {
    Ok(vec![
        record_ref(&state.records.open, "open")?
            .body
            .operation
            .clone(),
        record_ref(&state.records.snapshot, "snapshot")?
            .body
            .operation
            .clone(),
        record_ref(&state.records.patch, "patch")?
            .body
            .operation
            .clone(),
        // The scheduling component intentionally returns the immutable work
        // state unchanged. Its transaction/wake receipts are verified by the
        // substrate harness; the semantic closure fixes its required position.
        Operation::ScheduleJob.as_str().to_string(),
        record_ref(&state.records.build, "build")?
            .body
            .operation
            .clone(),
        record_ref(&state.records.provider, "provider")?
            .body
            .operation
            .clone(),
        record_ref(&state.records.validation, "validation")?
            .body
            .operation
            .clone(),
        record_ref(&state.records.review, "review")?
            .body
            .operation
            .clone(),
        record_ref(&state.records.package, "package")?
            .body
            .operation
            .clone(),
        record_ref(&state.records.verification, "verification")?
            .body
            .operation
            .clone(),
        record_ref(&state.records.evidence, "evidence")?
            .body
            .operation
            .clone(),
        record_ref(&state.records.resolution, "resolution")?
            .body
            .operation
            .clone(),
    ])
}

/// Reconstructs and verifies the complete resolved R1 semantic closure.
pub fn verify_resolved_work_state(bytes: &[u8]) -> Result<ResolvedWorkSummary, PolicyError> {
    let state = parse_state(bytes)?;
    require_stage(&state, WorkStage::Resolved, "resolved-work verification")?;
    let patch = record_ref(&state.records.patch, "patch")?;
    let build = record_ref(&state.records.build, "build")?;
    let provider = record_ref(&state.records.provider, "provider")?;
    let validation = record_ref(&state.records.validation, "validation")?;
    let review = record_ref(&state.records.review, "review")?;
    let package = record_ref(&state.records.package, "package")?;
    let verification = record_ref(&state.records.verification, "verification")?;
    let evidence = record_ref(&state.records.evidence, "evidence")?;
    let resolution = record_ref(&state.records.resolution, "resolution")?;
    let artifact = state
        .artifact
        .as_ref()
        .ok_or_else(|| error("missing-r1-artifact", "resolved work has no bytecode"))?;

    if !patch.body.source_changed
        || patch.body.before_digest_hex == patch.body.after_digest_hex
        || state.base_tree_digest_hex == state.current_tree_digest_hex
        || build.body.source_tree_digest_hex != state.current_tree_digest_hex
        || build.body.artifact_digest_hex != artifact.digest_hex
        || build.body.artifact_size_bytes != artifact.bytecode.len() as u64
    {
        return Err(error(
            "r1-source-build-closure-mismatch",
            "source change/build records do not identify the exact patched artifact",
        ));
    }
    if provider.body.policy != "local-fixture"
        || provider.body.model != LOCAL_MODEL
        || provider.body.recommendation != "validate"
        || provider.body.external_transport_used
        || validation.body.provider_record_digest_hex != provider.digest_hex
    {
        return Err(error(
            "r1-provider-closure-mismatch",
            "resolved work lacks the exact bounded-local provider/model policy",
        ));
    }
    let expected_provider_material = (
        "wasm-biotic.r1-provider-request.v1",
        state.request_digest_hex.as_str(),
        state.current_tree_digest_hex.as_str(),
        artifact.digest_hex.as_str(),
        LOCAL_MODEL,
    );
    let expected_provider_response = format!(
        "local-fixture|validate|{}|{}",
        state.current_tree_digest_hex, artifact.digest_hex
    );
    if provider.body.request_digest_hex
        != hex_sha256(&canonical_bytes(&expected_provider_material)?)
        || provider.body.response_digest_hex != hex_sha256(expected_provider_response.as_bytes())
    {
        return Err(error(
            "r1-provider-digest-mismatch",
            "provider request/response digests are not reproducible",
        ));
    }

    let test_paths = state
        .files
        .iter()
        .filter(|file| file.path.starts_with("tests/") && file.path.ends_with(".wbt-test.json"))
        .map(|file| file.path.clone())
        .collect::<Vec<_>>();
    let mut expected_cases = 0usize;
    for file in state
        .files
        .iter()
        .filter(|file| test_paths.contains(&file.path))
    {
        let suite: TestSuite = parse_canonical(file.content.as_bytes(), "resolved test")?;
        expected_cases += suite.cases.len();
    }
    if validation.body.discovered_test_files != test_paths
        || expected_cases != validation.body.observations.len()
        || validation.body.total_tests != expected_cases as u32
        || validation.body.passed_tests != expected_cases as u32
        || !validation.body.all_passed
        || validation.body.observations.iter().any(|observation| {
            !observation.passed
                || observation.actual != observation.expected
                || execute_bytecode(&artifact.bytecode, &observation.input)
                    .map_or(true, |actual| actual != observation.actual)
        })
    {
        return Err(error(
            "r1-validation-closure-mismatch",
            "resolved test discovery/execution record is not wholly green and reproducible",
        ));
    }
    if !review.body.approved
        || review.body.patch_record_digest_hex != patch.digest_hex
        || review.body.build_record_digest_hex != build.digest_hex
        || review.body.validation_record_digest_hex != validation.digest_hex
    {
        return Err(error(
            "r1-review-closure-mismatch",
            "review does not approve the exact source/build/validation lineage",
        ));
    }
    let expected_package_closure = package_closure_digest(&state)?;
    if package.body.closure_digest_hex != expected_package_closure
        || verification.body.package_record_digest_hex != package.digest_hex
        || verification.body.closure_digest_hex != expected_package_closure
        || !verification.body.verified
    {
        return Err(error(
            "r1-package-closure-mismatch",
            "package publication/verification closure is not exact",
        ));
    }
    if evidence.body.closure_digest_hex != evidence_closure_digest(&state)?
        || resolution.body.evidence_record_digest_hex != evidence.digest_hex
        || resolution.body.package_record_digest_hex != package.digest_hex
        || !resolution.body.resolved
    {
        return Err(error(
            "r1-evidence-closure-mismatch",
            "evidence publication/resolution closure is not exact",
        ));
    }
    let operation_history = required_operation_history(&state)?;
    let expected_history = [
        "workspace-open",
        "workspace-snapshot",
        "workspace-patch",
        "schedule-job",
        "candidate-build",
        "factory-provider-proposal",
        "validation-prove",
        "review-candidate",
        "package-publish",
        "package-verify",
        "evidence-publish",
        "evidence-resolve",
    ];
    if operation_history
        .iter()
        .map(String::as_str)
        .ne(expected_history)
    {
        return Err(error(
            "r1-operation-history-mismatch",
            "resolved work did not execute the exact component-owned R1 operation sequence",
        ));
    }
    Ok(ResolvedWorkSummary {
        request_digest_hex: state.request_digest_hex,
        base_tree_digest_hex: state.base_tree_digest_hex,
        patched_tree_digest_hex: state.current_tree_digest_hex,
        artifact_digest_hex: artifact.digest_hex.clone(),
        validation_digest_hex: validation.digest_hex.clone(),
        review_digest_hex: review.digest_hex.clone(),
        package_digest_hex: package.digest_hex.clone(),
        verification_digest_hex: verification.digest_hex.clone(),
        evidence_digest_hex: evidence.digest_hex.clone(),
        resolved_digest_hex: hex_sha256(bytes),
        source_changed: true,
        bytecode_size_bytes: artifact.bytecode.len() as u64,
        provider_policy: provider.body.policy.clone(),
        tests_discovered: validation.body.discovered_test_files.len() as u32,
        passed_tests: validation.body.passed_tests,
        total_tests: validation.body.total_tests,
        review_approved: true,
        package_verified: true,
        evidence_resolved: true,
        operation_history,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AuthorityClass, CapabilityDecisionMaterial, ServiceFamily, capability_decision_digest_hex,
        operation_policy, transform_service,
    };

    const CALLER: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const SERVICE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn invoke(
        operation: Operation,
        media_type: &str,
        input: &[u8],
    ) -> Result<ServiceOutput, PolicyError> {
        let input_digest = hex_sha256(input);
        let policy = operation_policy(operation);
        let request_id = format!("test:{}", operation.as_str());
        let idempotency = capability_decision_digest_hex(&CapabilityDecisionMaterial {
            request_id: &request_id,
            job_id: "r1-test-job",
            caller_id: "r1-test-worker",
            caller_component_hex: CALLER,
            service_component_hex: SERVICE,
            family: policy.family.as_str(),
            operation: operation.as_str(),
            input_digest_hex: &input_digest,
            input_size: input.len() as u64,
            input_media_type: media_type,
            authority: policy.minimum_authority.as_str(),
            deadline_ms: None,
        });
        let invocation = Invocation {
            expected_family: policy.family,
            declared_family: policy.family,
            operation,
            authority: policy.minimum_authority,
            has_approval: policy.approval_required,
            request_id: &request_id,
            job_id: "r1-test-job",
            caller_id: "r1-test-worker",
            caller_component_hex: CALLER,
            service_component_hex: SERVICE,
            idempotency_key_hex: &idempotency,
            input_digest_hex: &input_digest,
            input_size: input.len() as u64,
            input_media_type: media_type,
        };
        transform_service(&invocation, policy, input)
    }

    fn pipeline_until(stop_after: Operation, label: &str) -> Result<Vec<u8>, PolicyError> {
        let mut bytes = canonical_positive_fixture_bytes(label);
        let mut media = CHANGE_REQUEST_MEDIA_TYPE;
        for operation in [
            Operation::WorkspaceOpen,
            Operation::WorkspaceSnapshot,
            Operation::WorkspacePatch,
            Operation::CandidateBuild,
            Operation::FactoryProviderProposal,
            Operation::ValidationProve,
            Operation::ReviewCandidate,
            Operation::PackagePublish,
            Operation::PackageVerify,
            Operation::EvidencePublish,
            Operation::EvidenceResolve,
        ] {
            let first = invoke(operation, media, &bytes)?;
            let replay = invoke(operation, media, &bytes)?;
            assert_eq!(first, replay, "{} replay must be exact", operation.as_str());
            assert_eq!(first.media_type, WORK_STATE_MEDIA_TYPE);
            bytes = first.bytes;
            media = WORK_STATE_MEDIA_TYPE;
            if operation == stop_after {
                return Ok(bytes);
            }
        }
        unreachable!("requested operation is in the pipeline")
    }

    fn resolved(label: &str) -> Vec<u8> {
        pipeline_until(Operation::EvidenceResolve, label).unwrap()
    }

    #[test]
    fn positive_fixture_runs_real_component_only_pipeline_and_replays_exactly() {
        let bytes = resolved("positive-a");
        let summary = verify_resolved_work_state(&bytes).unwrap();
        assert!(summary.source_changed);
        assert!(summary.bytecode_size_bytes > BYTECODE_MAGIC.len() as u64);
        assert_eq!(summary.provider_policy, "local-fixture");
        assert_eq!(summary.tests_discovered, 1);
        assert_eq!(summary.passed_tests, summary.total_tests);
        assert_eq!(summary.total_tests, 1);
        assert!(summary.review_approved);
        assert!(summary.package_verified);
        assert!(summary.evidence_resolved);
        assert_eq!(summary.operation_history.len(), 12);
        assert_eq!(summary.operation_history[3], "schedule-job");
        assert_ne!(
            summary.base_tree_digest_hex,
            summary.patched_tree_digest_hex
        );
    }

    #[test]
    fn fixture_labels_change_job_identity_without_changing_useful_semantics() {
        let first = verify_resolved_work_state(&resolved("cohort-a")).unwrap();
        let second = verify_resolved_work_state(&resolved("cohort-b")).unwrap();
        assert_ne!(first.request_digest_hex, second.request_digest_hex);
        assert_ne!(first.package_digest_hex, second.package_digest_hex);
        assert_eq!(first.passed_tests, second.passed_tests);
        assert_eq!(first.provider_policy, second.provider_policy);
    }

    #[test]
    fn malformed_reserved_media_never_falls_back_to_legacy_envelope() {
        let failure = invoke(
            Operation::WorkspaceOpen,
            CHANGE_REQUEST_MEDIA_TYPE,
            b"not-json",
        )
        .unwrap_err();
        assert_eq!(failure.code, "invalid-r1-json");

        let legacy = invoke(
            Operation::WorkspaceOpen,
            "application/octet-stream",
            b"frozen-r0-corpus",
        )
        .unwrap();
        assert_eq!(legacy.media_type, crate::RESULT_MEDIA_TYPE);
        assert!(legacy.bytes.starts_with(crate::RESULT_MAGIC));
    }

    #[test]
    fn canonical_json_and_exact_cas_are_enforced() {
        let fixture = canonical_positive_fixture_bytes("canonical");
        let mut padded = fixture.clone();
        padded.push(b' ');
        assert_eq!(
            invoke(Operation::WorkspaceOpen, CHANGE_REQUEST_MEDIA_TYPE, &padded)
                .unwrap_err()
                .code,
            "noncanonical-r1-json"
        );

        let mut request: ChangeRequest = parse_canonical(&fixture, "fixture").unwrap();
        request.patch.expected_digest_hex = "f".repeat(64);
        let tampered = canonical_bytes(&request).unwrap();
        assert_eq!(
            invoke(
                Operation::WorkspaceOpen,
                CHANGE_REQUEST_MEDIA_TYPE,
                &tampered
            )
            .unwrap_err()
            .code,
            "r1-patch-cas-mismatch"
        );
    }

    #[test]
    fn traversal_duplicate_and_digest_forgery_are_rejected() {
        let fixture = canonical_positive_fixture_bytes("paths");
        let mut request: ChangeRequest = parse_canonical(&fixture, "fixture").unwrap();
        request.files[0].path = "../escape".to_string();
        request.entrypoint = "../escape".to_string();
        request.patch.path = "../escape".to_string();
        let bad_path = canonical_bytes(&request).unwrap();
        assert_eq!(
            invoke(
                Operation::WorkspaceOpen,
                CHANGE_REQUEST_MEDIA_TYPE,
                &bad_path
            )
            .unwrap_err()
            .code,
            "invalid-r1-path"
        );

        let mut request: ChangeRequest = parse_canonical(&fixture, "fixture").unwrap();
        request.files.push(request.files[1].clone());
        let duplicate = canonical_bytes(&request).unwrap();
        assert_eq!(
            invoke(
                Operation::WorkspaceOpen,
                CHANGE_REQUEST_MEDIA_TYPE,
                &duplicate
            )
            .unwrap_err()
            .code,
            "unsorted-r1-files"
        );

        let mut request: ChangeRequest = parse_canonical(&fixture, "fixture").unwrap();
        request.files[1].digest_hex = "0".repeat(64);
        let forged = canonical_bytes(&request).unwrap();
        assert_eq!(
            invoke(Operation::WorkspaceOpen, CHANGE_REQUEST_MEDIA_TYPE, &forged)
                .unwrap_err()
                .code,
            "r1-file-digest-mismatch"
        );
    }

    #[test]
    fn invalid_stack_program_fails_build_inside_component_semantics() {
        let fixture = canonical_positive_fixture_bytes("stack");
        let mut request: ChangeRequest = parse_canonical(&fixture, "fixture").unwrap();
        let invalid = Program {
            schema: PROGRAM_SCHEMA.to_string(),
            instructions: vec![Instruction::Concat],
        };
        request.patch.replacement_content =
            String::from_utf8(canonical_bytes(&invalid).unwrap()).unwrap();
        request.patch.replacement_digest_hex =
            hex_sha256(request.patch.replacement_content.as_bytes());
        let input = canonical_bytes(&request).unwrap();
        let opened = invoke(Operation::WorkspaceOpen, CHANGE_REQUEST_MEDIA_TYPE, &input).unwrap();
        let snapshot = invoke(
            Operation::WorkspaceSnapshot,
            WORK_STATE_MEDIA_TYPE,
            &opened.bytes,
        )
        .unwrap();
        let patched = invoke(
            Operation::WorkspacePatch,
            WORK_STATE_MEDIA_TYPE,
            &snapshot.bytes,
        )
        .unwrap();
        assert_eq!(
            invoke(
                Operation::CandidateBuild,
                WORK_STATE_MEDIA_TYPE,
                &patched.bytes
            )
            .unwrap_err()
            .code,
            "r1-program-stack-underflow"
        );
    }

    #[test]
    fn remote_provider_rejects_closed_before_validation() {
        let fixture = canonical_positive_fixture_bytes("remote-provider");
        let mut request: ChangeRequest = parse_canonical(&fixture, "fixture").unwrap();
        request.provider_mode = ProviderMode::Remote;
        let mut bytes = canonical_bytes(&request).unwrap();
        let mut media = CHANGE_REQUEST_MEDIA_TYPE;
        for operation in [
            Operation::WorkspaceOpen,
            Operation::WorkspaceSnapshot,
            Operation::WorkspacePatch,
            Operation::CandidateBuild,
        ] {
            let output = invoke(operation, media, &bytes).unwrap();
            bytes = output.bytes;
            media = WORK_STATE_MEDIA_TYPE;
        }
        assert_eq!(
            invoke(Operation::FactoryProviderProposal, media, &bytes)
                .unwrap_err()
                .code,
            "external-transport-disabled"
        );
    }

    #[test]
    fn failing_discovered_test_is_reviewed_but_cannot_be_packaged() {
        let fixture = canonical_positive_fixture_bytes("red-test");
        let mut request: ChangeRequest = parse_canonical(&fixture, "fixture").unwrap();
        let test_file = request
            .files
            .iter_mut()
            .find(|file| file.path.starts_with("tests/"))
            .unwrap();
        let mut suite: TestSuite = parse_canonical(test_file.content.as_bytes(), "test").unwrap();
        suite.cases[0].expected = "wrong".to_string();
        test_file.content = String::from_utf8(canonical_bytes(&suite).unwrap()).unwrap();
        test_file.digest_hex = hex_sha256(test_file.content.as_bytes());
        let mut bytes = canonical_bytes(&request).unwrap();
        let mut media = CHANGE_REQUEST_MEDIA_TYPE;
        for operation in [
            Operation::WorkspaceOpen,
            Operation::WorkspaceSnapshot,
            Operation::WorkspacePatch,
            Operation::CandidateBuild,
            Operation::FactoryProviderProposal,
            Operation::ValidationProve,
            Operation::ReviewCandidate,
        ] {
            let output = invoke(operation, media, &bytes).unwrap();
            bytes = output.bytes;
            media = WORK_STATE_MEDIA_TYPE;
        }
        let state = parse_state(&bytes).unwrap();
        assert!(!state.records.validation.unwrap().body.all_passed);
        assert!(!state.records.review.unwrap().body.approved);
        assert_eq!(
            invoke(Operation::PackagePublish, media, &bytes)
                .unwrap_err()
                .code,
            "r1-package-not-approved"
        );
    }

    #[test]
    fn final_verifier_rejects_rehashed_but_unapproved_review() {
        let bytes = resolved("tamper-final");
        let mut state = parse_state(&bytes).unwrap();
        let mut review = state.records.review.take().unwrap().body;
        review.approved = false;
        state.records.review = Some(record(review).unwrap());
        let forged = canonical_bytes(&state).unwrap();
        assert_eq!(
            verify_resolved_work_state(&forged).unwrap_err().code,
            "r1-review-closure-mismatch"
        );
    }

    fn deployment_plan(target: DeploymentTarget) -> Vec<u8> {
        canonical_bytes(&DeploymentPlan {
            schema: DEPLOYMENT_PLAN_SCHEMA.to_string(),
            deployment_id: "local-demo".to_string(),
            target,
            package_digest_hex: "a".repeat(64),
            expected_revision: 0,
            fixture_observation: Observation::Unhealthy,
        })
        .unwrap()
    }

    #[test]
    fn local_deployment_is_an_exact_replayable_cas_state_machine() {
        let mut bytes = deployment_plan(DeploymentTarget::Local);
        let mut media = DEPLOYMENT_PLAN_MEDIA_TYPE;
        for (expected_revision, operation) in [
            (1, Operation::DeploymentInitialize),
            (2, Operation::DeploymentActivate),
            (3, Operation::DeploymentObserve),
            (4, Operation::DeploymentRollback),
        ] {
            let first = invoke(operation, media, &bytes).unwrap();
            let replay = invoke(operation, media, &bytes).unwrap();
            assert_eq!(first, replay);
            let state: DeploymentState = parse_canonical(&first.bytes, "deployment").unwrap();
            validate_deployment_state(&state).unwrap();
            assert_eq!(state.revision, expected_revision);
            bytes = first.bytes;
            media = DEPLOYMENT_STATE_MEDIA_TYPE;
        }
        let state = parse_deployment(&bytes).unwrap();
        assert_eq!(state.status, DeploymentStatus::RolledBack);
    }

    #[test]
    fn deployment_rejects_remote_target_and_stale_transition() {
        assert_eq!(
            invoke(
                Operation::DeploymentInitialize,
                DEPLOYMENT_PLAN_MEDIA_TYPE,
                &deployment_plan(DeploymentTarget::Remote),
            )
            .unwrap_err()
            .code,
            "external-transport-disabled"
        );

        let initialized = invoke(
            Operation::DeploymentInitialize,
            DEPLOYMENT_PLAN_MEDIA_TYPE,
            &deployment_plan(DeploymentTarget::Local),
        )
        .unwrap();
        assert_eq!(
            invoke(
                Operation::DeploymentObserve,
                DEPLOYMENT_STATE_MEDIA_TYPE,
                &initialized.bytes,
            )
            .unwrap_err()
            .code,
            "r1-deployment-cas-mismatch"
        );
    }

    #[test]
    fn operation_family_and_approval_policy_still_wrap_r1_semantics() {
        assert_eq!(
            operation_policy(Operation::WorkspaceOpen).family,
            ServiceFamily::Build
        );
        assert_eq!(
            operation_policy(Operation::FactoryProviderProposal).family,
            ServiceFamily::Validation
        );
        assert_eq!(
            operation_policy(Operation::DeploymentActivate).minimum_authority,
            AuthorityClass::PromotionControl
        );
        assert!(operation_policy(Operation::DeploymentActivate).approval_required);
    }
}
