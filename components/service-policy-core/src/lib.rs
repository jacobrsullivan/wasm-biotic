#![cfg_attr(all(target_arch = "wasm32", not(test)), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

//! Shared policy for the seven bounded capability-service components.
//!
//! This crate owns the complete 27-operation-to-family map, minimum authority
//! and approval checks, content verification, and deterministic service-result
//! encoding. It is `no_std` on Wasm and performs no effects. Component adapters
//! call only the substrate interfaces declared by their canonical WIT worlds.

extern crate alloc;

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};
use sha2::{Digest as _, Sha256};

pub mod r1;

pub const RESULT_MEDIA_TYPE: &str = "application/vnd.wasm-biotic.capability-result.v1+octet-stream";
const RESULT_MAGIC: &[u8] = b"WASM-BIOTIC-CAPABILITY-RESULT\0\x01";

/// Bytes and media type produced by a capability service. R0 compatibility
/// results retain the legacy octet-stream type; strict R1 operations return a
/// canonical, schema-labelled JSON work state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceOutput {
    pub media_type: String,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ServiceFamily {
    Build,
    Packaging,
    Validation,
    Review,
    Continuity,
    Scheduling,
    Operations,
}

impl ServiceFamily {
    pub const ALL: [Self; 7] = [
        Self::Build,
        Self::Packaging,
        Self::Validation,
        Self::Review,
        Self::Continuity,
        Self::Scheduling,
        Self::Operations,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Build => "build",
            Self::Packaging => "packaging",
            Self::Validation => "validation",
            Self::Review => "review",
            Self::Continuity => "continuity",
            Self::Scheduling => "scheduling",
            Self::Operations => "operations",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuthorityClass {
    Observe,
    LocalMutate,
    AutomationControl,
    PromotionControl,
}

impl AuthorityClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::LocalMutate => "local-mutate",
            Self::AutomationControl => "automation-control",
            Self::PromotionControl => "promotion-control",
        }
    }

    const fn rank(self) -> u8 {
        match self {
            Self::Observe => 0,
            Self::LocalMutate => 1,
            Self::AutomationControl => 2,
            Self::PromotionControl => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Operation {
    WorkspaceOpen,
    WorkspaceSnapshot,
    WorkspacePatch,
    CandidateBuild,
    CommandExecute,
    PackagePublish,
    PackageVerify,
    ValidationProve,
    ValidationCompare,
    ReviewCandidate,
    EvidencePublish,
    EvidenceResolve,
    ScheduleJob,
    DeploymentInitialize,
    DeploymentActivate,
    DeploymentObserve,
    DeploymentRollback,
    OperationsInspect,
    FactoryExecute,
    FactoryProviderProposal,
    FactoryShadow,
    FactoryInitialize,
    FactoryStateMigrate,
    FactoryActivate,
    FactoryObserve,
    FactoryRollback,
    FactoryInspect,
}

impl Operation {
    pub const ALL: [Self; 27] = [
        Self::WorkspaceOpen,
        Self::WorkspaceSnapshot,
        Self::WorkspacePatch,
        Self::CandidateBuild,
        Self::CommandExecute,
        Self::PackagePublish,
        Self::PackageVerify,
        Self::ValidationProve,
        Self::ValidationCompare,
        Self::ReviewCandidate,
        Self::EvidencePublish,
        Self::EvidenceResolve,
        Self::ScheduleJob,
        Self::DeploymentInitialize,
        Self::DeploymentActivate,
        Self::DeploymentObserve,
        Self::DeploymentRollback,
        Self::OperationsInspect,
        Self::FactoryExecute,
        Self::FactoryProviderProposal,
        Self::FactoryShadow,
        Self::FactoryInitialize,
        Self::FactoryStateMigrate,
        Self::FactoryActivate,
        Self::FactoryObserve,
        Self::FactoryRollback,
        Self::FactoryInspect,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WorkspaceOpen => "workspace-open",
            Self::WorkspaceSnapshot => "workspace-snapshot",
            Self::WorkspacePatch => "workspace-patch",
            Self::CandidateBuild => "candidate-build",
            Self::CommandExecute => "command-execute",
            Self::PackagePublish => "package-publish",
            Self::PackageVerify => "package-verify",
            Self::ValidationProve => "validation-prove",
            Self::ValidationCompare => "validation-compare",
            Self::ReviewCandidate => "review-candidate",
            Self::EvidencePublish => "evidence-publish",
            Self::EvidenceResolve => "evidence-resolve",
            Self::ScheduleJob => "schedule-job",
            Self::DeploymentInitialize => "deployment-initialize",
            Self::DeploymentActivate => "deployment-activate",
            Self::DeploymentObserve => "deployment-observe",
            Self::DeploymentRollback => "deployment-rollback",
            Self::OperationsInspect => "operations-inspect",
            Self::FactoryExecute => "factory-execute",
            Self::FactoryProviderProposal => "factory-provider-proposal",
            Self::FactoryShadow => "factory-shadow",
            Self::FactoryInitialize => "factory-initialize",
            Self::FactoryStateMigrate => "factory-state-migrate",
            Self::FactoryActivate => "factory-activate",
            Self::FactoryObserve => "factory-observe",
            Self::FactoryRollback => "factory-rollback",
            Self::FactoryInspect => "factory-inspect",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperationPolicy {
    pub family: ServiceFamily,
    pub minimum_authority: AuthorityClass,
    pub approval_required: bool,
    pub transformation: &'static str,
}

pub const fn operation_policy(operation: Operation) -> OperationPolicy {
    use AuthorityClass::{AutomationControl, LocalMutate, Observe, PromotionControl};
    use ServiceFamily::{Build, Continuity, Operations, Packaging, Review, Scheduling, Validation};
    match operation {
        Operation::WorkspaceOpen => policy(Build, Observe, false, "workspace-descriptor"),
        Operation::WorkspaceSnapshot => policy(Build, Observe, false, "workspace-snapshot"),
        Operation::WorkspacePatch => policy(Build, LocalMutate, false, "workspace-patch-plan"),
        Operation::CandidateBuild => policy(Build, LocalMutate, false, "component-build-plan"),
        Operation::CommandExecute => policy(
            Build,
            AutomationControl,
            false,
            "admitted-component-run-plan",
        ),
        Operation::PackagePublish => {
            policy(Packaging, LocalMutate, false, "published-package-envelope")
        }
        Operation::PackageVerify => {
            policy(Packaging, Observe, false, "package-verification-record")
        }
        Operation::ValidationProve => {
            policy(Validation, AutomationControl, false, "proving-record")
        }
        Operation::ValidationCompare => policy(Validation, Observe, false, "comparison-record"),
        Operation::FactoryExecute => policy(
            Validation,
            AutomationControl,
            false,
            "factory-execution-record",
        ),
        Operation::FactoryProviderProposal => {
            policy(Validation, LocalMutate, false, "provider-proposal-record")
        }
        Operation::FactoryShadow => policy(
            Validation,
            AutomationControl,
            false,
            "factory-shadow-record",
        ),
        Operation::ReviewCandidate => policy(Review, Observe, false, "review-record"),
        Operation::EvidencePublish => policy(
            Continuity,
            LocalMutate,
            false,
            "evidence-publication-record",
        ),
        Operation::EvidenceResolve => {
            policy(Continuity, Observe, false, "evidence-resolution-record")
        }
        Operation::ScheduleJob => policy(
            Scheduling,
            AutomationControl,
            false,
            "durable-schedule-intent",
        ),
        Operation::DeploymentInitialize => policy(
            Operations,
            AutomationControl,
            false,
            "deployment-initialization-record",
        ),
        Operation::DeploymentActivate => policy(
            Operations,
            PromotionControl,
            true,
            "deployment-activation-record",
        ),
        Operation::DeploymentObserve => {
            policy(Operations, Observe, false, "deployment-observation-record")
        }
        Operation::DeploymentRollback => policy(
            Operations,
            PromotionControl,
            true,
            "deployment-rollback-record",
        ),
        Operation::OperationsInspect => {
            policy(Operations, Observe, false, "operations-inspection-record")
        }
        Operation::FactoryInitialize => policy(
            Operations,
            AutomationControl,
            false,
            "factory-initialization-record",
        ),
        Operation::FactoryStateMigrate => policy(
            Operations,
            PromotionControl,
            true,
            "factory-migration-record",
        ),
        Operation::FactoryActivate => policy(
            Operations,
            PromotionControl,
            true,
            "factory-activation-record",
        ),
        Operation::FactoryObserve => {
            policy(Operations, Observe, false, "factory-observation-record")
        }
        Operation::FactoryRollback => policy(
            Operations,
            PromotionControl,
            true,
            "factory-rollback-record",
        ),
        Operation::FactoryInspect => {
            policy(Operations, Observe, false, "factory-inspection-record")
        }
    }
}

const fn policy(
    family: ServiceFamily,
    minimum_authority: AuthorityClass,
    approval_required: bool,
    transformation: &'static str,
) -> OperationPolicy {
    OperationPolicy {
        family,
        minimum_authority,
        approval_required,
        transformation,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyError {
    pub code: &'static str,
    pub message: String,
}

impl PolicyError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Invocation<'a> {
    pub expected_family: ServiceFamily,
    pub declared_family: ServiceFamily,
    pub operation: Operation,
    pub authority: AuthorityClass,
    pub has_approval: bool,
    pub request_id: &'a str,
    pub job_id: &'a str,
    pub caller_id: &'a str,
    pub caller_component_hex: &'a str,
    pub service_component_hex: &'a str,
    pub idempotency_key_hex: &'a str,
    pub input_digest_hex: &'a str,
    pub input_size: u64,
    pub input_media_type: &'a str,
}

/// Exact domain material whose SHA-256 is the capability decision and
/// idempotency identity. Routers recompute it rather than trusting a
/// caller-selected digest; workers use the same function when constructing a
/// request.
#[derive(Clone, Copy, Debug)]
pub struct CapabilityDecisionMaterial<'a> {
    pub request_id: &'a str,
    pub job_id: &'a str,
    pub caller_id: &'a str,
    pub caller_component_hex: &'a str,
    pub service_component_hex: &'a str,
    pub family: &'a str,
    pub operation: &'a str,
    pub input_digest_hex: &'a str,
    pub input_size: u64,
    pub input_media_type: &'a str,
    pub authority: &'a str,
    pub deadline_ms: Option<u64>,
}

/// Computes the canonical request identity without JSON, clock or host state.
/// Every field is length-delimited so concatenation cannot create aliases.
pub fn capability_decision_digest_hex(material: &CapabilityDecisionMaterial<'_>) -> String {
    let mut hash = Sha256::new();
    hash.update(b"wasm-biotic:capability-decision:v1\0");
    for field in [
        material.request_id,
        material.job_id,
        material.caller_id,
        material.caller_component_hex,
        material.service_component_hex,
        material.family,
        material.operation,
        material.input_digest_hex,
        material.input_media_type,
        material.authority,
    ] {
        hash.update(u64::try_from(field.len()).unwrap_or(u64::MAX).to_be_bytes());
        hash.update(field.as_bytes());
    }
    hash.update(material.input_size.to_be_bytes());
    match material.deadline_ms {
        Some(deadline) => {
            hash.update([1]);
            hash.update(deadline.to_be_bytes());
        }
        None => hash.update([0]),
    }
    digest_to_hex(hash.finalize())
}

pub fn validate_invocation(invocation: &Invocation<'_>) -> Result<OperationPolicy, PolicyError> {
    if invocation.request_id.trim().is_empty() || invocation.job_id.trim().is_empty() {
        return Err(PolicyError::new(
            "invalid-request-identity",
            "request-id and job-id must not be blank",
        ));
    }
    if invocation.caller_id.trim().is_empty() {
        return Err(PolicyError::new(
            "invalid-caller",
            "caller principal id must not be blank",
        ));
    }
    validate_sha256_hex("caller.component-digest", invocation.caller_component_hex)?;
    validate_sha256_hex("service-component", invocation.service_component_hex)?;
    validate_sha256_hex("idempotency-key", invocation.idempotency_key_hex)?;
    validate_sha256_hex("input.content-digest", invocation.input_digest_hex)?;
    if invocation.input_media_type.trim().is_empty() {
        return Err(PolicyError::new(
            "invalid-input-media-type",
            "input media type must not be blank",
        ));
    }
    if invocation.declared_family != invocation.expected_family {
        return Err(PolicyError::new(
            "wrong-service-family",
            format!(
                "{} component rejects request for {} family",
                invocation.expected_family.as_str(),
                invocation.declared_family.as_str()
            ),
        ));
    }
    let policy = operation_policy(invocation.operation);
    if policy.family != invocation.expected_family {
        return Err(PolicyError::new(
            "operation-not-owned",
            format!(
                "{} operation belongs to {} service, not {} service",
                invocation.operation.as_str(),
                policy.family.as_str(),
                invocation.expected_family.as_str()
            ),
        ));
    }
    if invocation.authority.rank() < policy.minimum_authority.rank() {
        return Err(PolicyError::new(
            "insufficient-authority",
            format!(
                "{} requires {:?} authority",
                invocation.operation.as_str(),
                policy.minimum_authority
            ),
        ));
    }
    if policy.approval_required && !invocation.has_approval {
        return Err(PolicyError::new(
            "approval-required",
            format!(
                "{} requires an approval proof",
                invocation.operation.as_str()
            ),
        ));
    }
    Ok(policy)
}

pub fn verify_input_bytes(invocation: &Invocation<'_>, bytes: &[u8]) -> Result<(), PolicyError> {
    let length = u64::try_from(bytes.len()).map_err(|_| {
        PolicyError::new(
            "input-too-large",
            "input length cannot be represented as u64",
        )
    })?;
    if length != invocation.input_size {
        return Err(PolicyError::new(
            "input-size-mismatch",
            format!(
                "declared {} bytes but blob store returned {length}",
                invocation.input_size
            ),
        ));
    }
    let actual = hex_sha256(bytes);
    if actual != invocation.input_digest_hex {
        return Err(PolicyError::new(
            "input-digest-mismatch",
            "blob store bytes do not match the requested content digest",
        ));
    }
    Ok(())
}

/// Produce a deterministic, operation-labelled envelope containing the exact
/// immutable input bytes. This bounded v1 transformation is intentionally not
/// a claim of legacy build/validation behaviour.
pub fn transform_blob(
    invocation: &Invocation<'_>,
    policy: OperationPolicy,
    input: &[u8],
) -> Result<Vec<u8>, PolicyError> {
    verify_input_bytes(invocation, input)?;
    let mut output = Vec::with_capacity(RESULT_MAGIC.len() + input.len() + 512);
    output.extend_from_slice(RESULT_MAGIC);
    field(&mut output, invocation.expected_family.as_str())?;
    field(&mut output, invocation.operation.as_str())?;
    field(&mut output, policy.transformation)?;
    field(&mut output, invocation.request_id)?;
    field(&mut output, invocation.job_id)?;
    field(&mut output, invocation.caller_id)?;
    field(&mut output, invocation.caller_component_hex)?;
    field(&mut output, invocation.service_component_hex)?;
    field(&mut output, invocation.idempotency_key_hex)?;
    field(&mut output, invocation.input_digest_hex)?;
    field(&mut output, invocation.input_media_type)?;
    bytes_field(&mut output, input)?;
    Ok(output)
}

/// Selects the strict semantic R1 path for reserved media types and otherwise
/// preserves the frozen R0 compatibility envelope. A malformed R1 document
/// can never fall through to a legacy success-shaped result.
pub fn transform_service(
    invocation: &Invocation<'_>,
    policy: OperationPolicy,
    input: &[u8],
) -> Result<ServiceOutput, PolicyError> {
    verify_input_bytes(invocation, input)?;
    if r1::owns_media_type(invocation.input_media_type) {
        return r1::transform(invocation, input);
    }
    Ok(ServiceOutput {
        media_type: RESULT_MEDIA_TYPE.to_string(),
        bytes: transform_blob(invocation, policy, input)?,
    })
}

fn field(output: &mut Vec<u8>, value: &str) -> Result<(), PolicyError> {
    bytes_field(output, value.as_bytes())
}

fn bytes_field(output: &mut Vec<u8>, value: &[u8]) -> Result<(), PolicyError> {
    let length = u32::try_from(value.len())
        .map_err(|_| PolicyError::new("field-too-large", "result field exceeds u32 length"))?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

pub fn validate_sha256_hex(field: &str, value: &str) -> Result<(), PolicyError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PolicyError::new(
            "invalid-digest",
            format!("{field} must be 64 lower-case hexadecimal characters"),
        ));
    }
    Ok(())
}

pub fn hex_sha256(bytes: &[u8]) -> String {
    digest_to_hex(Sha256::digest(bytes))
}

fn digest_to_hex(digest: impl AsRef<[u8]>) -> String {
    let mut output = String::with_capacity(64);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in digest.as_ref() {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(all(target_arch = "wasm32", not(test), feature = "component-abi"))]
#[global_allocator]
static ALLOCATOR: dlmalloc::GlobalDlmalloc = dlmalloc::GlobalDlmalloc;

#[cfg(all(target_arch = "wasm32", not(test), feature = "component-abi"))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}

#[cfg(all(target_arch = "wasm32", not(test), feature = "component-abi"))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cabi_realloc(
    old_pointer: *mut u8,
    old_length: usize,
    alignment: usize,
    new_length: usize,
) -> *mut u8 {
    use alloc::alloc::{Layout, alloc, dealloc, handle_alloc_error, realloc};

    let alignment = alignment.max(1);
    if old_pointer.is_null() {
        if new_length == 0 {
            return core::ptr::null_mut();
        }
        let layout = Layout::from_size_align(new_length, alignment)
            .unwrap_or_else(|_| core::arch::wasm32::unreachable());
        // SAFETY: layout is valid and allocation failure traps.
        let pointer = unsafe { alloc(layout) };
        if pointer.is_null() {
            handle_alloc_error(layout);
        }
        pointer
    } else {
        let old_layout = Layout::from_size_align(old_length.max(1), alignment)
            .unwrap_or_else(|_| core::arch::wasm32::unreachable());
        if new_length == 0 {
            // SAFETY: Canonical ABI supplies the allocation's original layout.
            unsafe { dealloc(old_pointer, old_layout) };
            core::ptr::null_mut()
        } else {
            // SAFETY: same Canonical ABI provenance as deallocation.
            let pointer = unsafe { realloc(old_pointer, old_layout, new_length) };
            if pointer.is_null() {
                let new_layout = Layout::from_size_align(new_length, alignment)
                    .unwrap_or_else(|_| core::arch::wasm32::unreachable());
                handle_alloc_error(new_layout);
            }
            pointer
        }
    }
}

#[cfg(all(target_arch = "wasm32", not(test), feature = "component-abi"))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcmp(left: *const u8, right: *const u8, length: usize) -> i32 {
    for offset in 0..length {
        // SAFETY: compiler caller guarantees both readable regions.
        let left_byte = unsafe { *left.add(offset) };
        // SAFETY: same contract for the right-hand region.
        let right_byte = unsafe { *right.add(offset) };
        if left_byte != right_byte {
            return i32::from(left_byte) - i32::from(right_byte);
        }
    }
    0
}

/// Generate a blob-transforming capability service for one canonical WIT world.
#[macro_export]
macro_rules! define_blob_service_component {
    (world: $world:literal, interface: $interface:ident, family: $family:ident) => {
        #[cfg(target_arch = "wasm32")]
        mod component {
            extern crate alloc;

            use alloc::{format, string::{String, ToString}, vec, vec::Vec};
            use wasm_biotic_service_policy_core as policy;

            wit_bindgen::generate!({
                path: "../../../wit/wasm-biotic",
                world: $world,
            });

            use exports::wasm_biotic::factory::$interface::Guest;
            use wasm_biotic::factory::capability_contract::{
                AuthorityClass as WitAuthority, CapabilityRequest, CapabilityResponse,
                Operation as WitOperation, ServiceFamily as WitFamily, ServiceOutcome,
            };
            use wasm_biotic::factory::foundation::{Failure, HashAlgorithm};

            struct ServiceComponent;

            impl Guest for ServiceComponent {
                fn invoke(request: CapabilityRequest) -> CapabilityResponse {
                    let invocation = match invocation(&request) {
                        Ok(invocation) => invocation,
                        Err(failure) => return rejected(&request, failure),
                    };
                    let operation_policy = match policy::validate_invocation(&invocation) {
                        Ok(operation_policy) => operation_policy,
                        Err(error) => return rejected(&request, policy_failure(error)),
                    };
                    let input = match wasm_biotic::factory::blob_store::get(&request.input) {
                        Ok(input) => input,
                        Err(failure) => return failed(&request, failure),
                    };
                    let output = match policy::transform_service(&invocation, operation_policy, &input)
                    {
                        Ok(output) => output,
                        Err(error) => return failed(&request, policy_failure(error)),
                    };
                    let expected_hex = policy::hex_sha256(&output.bytes);
                    let output_ref = match wasm_biotic::factory::blob_store::put(
                        &output.media_type,
                        &output.bytes,
                    ) {
                        Ok(reference) => reference,
                        Err(failure) => return failed(&request, failure),
                    };
                    let expected_size = u64::try_from(output.bytes.len()).unwrap_or(u64::MAX);
                    if output_ref.size_bytes != expected_size
                        || output_ref.media_type != output.media_type
                        || !matches!(
                            output_ref.content_digest.algorithm,
                            HashAlgorithm::Sha256
                        )
                        || output_ref.content_digest.hex != expected_hex
                    {
                        return failed(
                            &request,
                            failure(
                                "untruthful-blob-store-receipt",
                                "blob-store put result does not identify the exact output bytes",
                            ),
                        );
                    }
                    CapabilityResponse {
                        request_id: request.request_id,
                        service_component: request.service_component,
                        outcome: ServiceOutcome::Succeeded(output_ref.clone()),
                        effect_receipts: Vec::new(),
                        evidence: vec![request.input, output_ref],
                    }
                }
            }

            fn invocation(request: &CapabilityRequest) -> Result<policy::Invocation<'_>, Failure> {
                let declared_family = family(&request.family)?;
                let operation = operation(&request.operation)?;
                let authority = authority(&request.authority)?;
                if !matches!(
                    request.caller.component_digest.algorithm,
                    HashAlgorithm::Sha256
                ) || !matches!(
                    request.service_component.algorithm,
                    HashAlgorithm::Sha256
                ) || !matches!(request.idempotency_key.algorithm, HashAlgorithm::Sha256)
                    || !matches!(request.input.content_digest.algorithm, HashAlgorithm::Sha256)
                {
                    return Err(failure(
                        "unsupported-digest",
                        "caller, service, idempotency and input digests must use sha256",
                    ));
                }
                Ok(policy::Invocation {
                    expected_family: policy::ServiceFamily::$family,
                    declared_family,
                    operation,
                    authority,
                    has_approval: request.approval.is_some(),
                    request_id: &request.request_id,
                    job_id: &request.job_id,
                    caller_id: &request.caller.id,
                    caller_component_hex: &request.caller.component_digest.hex,
                    service_component_hex: &request.service_component.hex,
                    idempotency_key_hex: &request.idempotency_key.hex,
                    input_digest_hex: &request.input.content_digest.hex,
                    input_size: request.input.size_bytes,
                    input_media_type: &request.input.media_type,
                })
            }

            fn family(value: &WitFamily) -> Result<policy::ServiceFamily, Failure> {
                match value {
                    WitFamily::Build => Ok(policy::ServiceFamily::Build),
                    WitFamily::Packaging => Ok(policy::ServiceFamily::Packaging),
                    WitFamily::Validation => Ok(policy::ServiceFamily::Validation),
                    WitFamily::Review => Ok(policy::ServiceFamily::Review),
                    WitFamily::Continuity => Ok(policy::ServiceFamily::Continuity),
                    WitFamily::Scheduling => Ok(policy::ServiceFamily::Scheduling),
                    WitFamily::Operations => Ok(policy::ServiceFamily::Operations),
                    _ => Err(failure("unsupported-family", "unknown service family")),
                }
            }

            fn authority(value: &WitAuthority) -> Result<policy::AuthorityClass, Failure> {
                match value {
                    WitAuthority::Observe => Ok(policy::AuthorityClass::Observe),
                    WitAuthority::LocalMutate => Ok(policy::AuthorityClass::LocalMutate),
                    WitAuthority::AutomationControl => {
                        Ok(policy::AuthorityClass::AutomationControl)
                    }
                    WitAuthority::PromotionControl => {
                        Ok(policy::AuthorityClass::PromotionControl)
                    }
                    _ => Err(failure("unsupported-authority", "unknown authority class")),
                }
            }

            fn operation(value: &WitOperation) -> Result<policy::Operation, Failure> {
                match value {
                    WitOperation::WorkspaceOpen => Ok(policy::Operation::WorkspaceOpen),
                    WitOperation::WorkspaceSnapshot => Ok(policy::Operation::WorkspaceSnapshot),
                    WitOperation::WorkspacePatch => Ok(policy::Operation::WorkspacePatch),
                    WitOperation::CandidateBuild => Ok(policy::Operation::CandidateBuild),
                    WitOperation::CommandExecute => Ok(policy::Operation::CommandExecute),
                    WitOperation::PackagePublish => Ok(policy::Operation::PackagePublish),
                    WitOperation::PackageVerify => Ok(policy::Operation::PackageVerify),
                    WitOperation::ValidationProve => Ok(policy::Operation::ValidationProve),
                    WitOperation::ValidationCompare => Ok(policy::Operation::ValidationCompare),
                    WitOperation::ReviewCandidate => Ok(policy::Operation::ReviewCandidate),
                    WitOperation::EvidencePublish => Ok(policy::Operation::EvidencePublish),
                    WitOperation::EvidenceResolve => Ok(policy::Operation::EvidenceResolve),
                    WitOperation::ScheduleJob => Ok(policy::Operation::ScheduleJob),
                    WitOperation::DeploymentInitialize => {
                        Ok(policy::Operation::DeploymentInitialize)
                    }
                    WitOperation::DeploymentActivate => {
                        Ok(policy::Operation::DeploymentActivate)
                    }
                    WitOperation::DeploymentObserve => {
                        Ok(policy::Operation::DeploymentObserve)
                    }
                    WitOperation::DeploymentRollback => {
                        Ok(policy::Operation::DeploymentRollback)
                    }
                    WitOperation::OperationsInspect => Ok(policy::Operation::OperationsInspect),
                    WitOperation::FactoryExecute => Ok(policy::Operation::FactoryExecute),
                    WitOperation::FactoryProviderProposal => {
                        Ok(policy::Operation::FactoryProviderProposal)
                    }
                    WitOperation::FactoryShadow => Ok(policy::Operation::FactoryShadow),
                    WitOperation::FactoryInitialize => Ok(policy::Operation::FactoryInitialize),
                    WitOperation::FactoryStateMigrate => {
                        Ok(policy::Operation::FactoryStateMigrate)
                    }
                    WitOperation::FactoryActivate => Ok(policy::Operation::FactoryActivate),
                    WitOperation::FactoryObserve => Ok(policy::Operation::FactoryObserve),
                    WitOperation::FactoryRollback => Ok(policy::Operation::FactoryRollback),
                    WitOperation::FactoryInspect => Ok(policy::Operation::FactoryInspect),
                    _ => Err(failure("unsupported-operation", "unknown capability operation")),
                }
            }

            fn rejected(request: &CapabilityRequest, failure: Failure) -> CapabilityResponse {
                CapabilityResponse {
                    request_id: request.request_id.clone(),
                    service_component: request.service_component.clone(),
                    outcome: ServiceOutcome::Rejected(failure),
                    effect_receipts: Vec::new(),
                    evidence: Vec::new(),
                }
            }

            fn failed(request: &CapabilityRequest, failure: Failure) -> CapabilityResponse {
                CapabilityResponse {
                    request_id: request.request_id.clone(),
                    service_component: request.service_component.clone(),
                    outcome: ServiceOutcome::Failed(failure),
                    effect_receipts: Vec::new(),
                    evidence: Vec::new(),
                }
            }

            fn policy_failure(error: policy::PolicyError) -> Failure {
                failure(error.code, error.message)
            }

            fn failure(code: impl Into<String>, message: impl Into<String>) -> Failure {
                Failure {
                    code: code.into(),
                    message: message.into(),
                    retryable: false,
                    evidence: None,
                }
            }

            export!(ServiceComponent);
        }
    };
}

/// Selects the exact durable wake time without consulting ambient clock state.
///
/// An omitted deadline means "immediately eligible" and is encoded as zero.
/// Replaying the same capability request therefore reconstructs byte-identical
/// wake material even when wall time advanced after the first attempt. An
/// explicit deadline is passed through unchanged; the substrate remains
/// responsible for enforcing its configured future horizon.
#[must_use]
pub const fn schedule_not_before_ms(deadline_ms: Option<u64>) -> u64 {
    match deadline_ms {
        Some(deadline_ms) => deadline_ms,
        None => 0,
    }
}

#[cfg(test)]
mod scheduling_replay_tests {
    use super::schedule_not_before_ms;

    #[test]
    fn omitted_deadline_is_clock_independent_and_replay_stable() {
        let first_attempt = schedule_not_before_ms(None);
        let replay_after_clock_advance = schedule_not_before_ms(None);
        assert_eq!(first_attempt, 0);
        assert_eq!(replay_after_clock_advance, first_attempt);
    }

    #[test]
    fn explicit_deadline_passes_through_exactly() {
        assert_eq!(schedule_not_before_ms(Some(42_000)), 42_000);
        assert_eq!(schedule_not_before_ms(Some(u64::MAX)), u64::MAX);
    }
}

/// Generate the scheduling service. Its canonical world deliberately has no
/// blob-store: it converts a validated immutable reference into an idempotent
/// transaction-store intent and durable clock wake, then returns that reference.
#[macro_export]
macro_rules! define_scheduling_service_component {
    (world: $world:literal, interface: $interface:ident) => {
        #[cfg(target_arch = "wasm32")]
        mod component {
            extern crate alloc;

            use alloc::{format, string::{String, ToString}, vec, vec::Vec};
            use wasm_biotic_service_policy_core as policy;

            wit_bindgen::generate!({
                path: "../../../wit/wasm-biotic",
                world: $world,
            });

            use exports::wasm_biotic::factory::$interface::Guest;
            use wasm_biotic::factory::capability_contract::{
                AuthorityClass, CapabilityRequest, CapabilityResponse, Operation, ServiceFamily,
                ServiceOutcome,
            };
            use wasm_biotic::factory::clock::WakeRequest;
            use wasm_biotic::factory::foundation::{Failure, HashAlgorithm};
            use wasm_biotic::factory::transaction_store::{CommitRequest, Mutation};

            struct ServiceComponent;

            impl Guest for ServiceComponent {
                fn invoke(request: CapabilityRequest) -> CapabilityResponse {
                    let invocation = match invocation(&request) {
                        Ok(invocation) => invocation,
                        Err(failure) => {
                            return response(&request, ServiceOutcome::Rejected(failure));
                        }
                    };
                    if let Err(error) = policy::validate_invocation(&invocation) {
                        return response(
                            &request,
                            ServiceOutcome::Rejected(failure(error.code, error.message)),
                        );
                    }
                    let not_before_ms = policy::schedule_not_before_ms(request.deadline_ms);
                    let commit = CommitRequest {
                        transaction_id: request.request_id.clone(),
                        assertions: Vec::new(),
                        mutations: vec![Mutation::Put((
                            "wasm-biotic.schedule.v1".to_string(),
                            request.job_id.clone(),
                            request.input.clone(),
                        ))],
                        idempotency_key: request.idempotency_key.clone(),
                    };
                    if let Err(failure) = wasm_biotic::factory::transaction_store::commit(&commit) {
                        return response(&request, ServiceOutcome::Failed(failure));
                    }
                    let wake = WakeRequest {
                        wake_id: request.request_id.clone(),
                        not_before_ms,
                        target_component: request.caller.component_digest.clone(),
                        payload_digest: request.input.content_digest.clone(),
                        idempotency_key: request.idempotency_key.clone(),
                    };
                    if let Err(failure) = wasm_biotic::factory::clock::schedule_wake(&wake) {
                        return response(&request, ServiceOutcome::Failed(failure));
                    }
                    CapabilityResponse {
                        request_id: request.request_id,
                        service_component: request.service_component,
                        outcome: ServiceOutcome::Succeeded(request.input.clone()),
                        effect_receipts: Vec::new(),
                        evidence: vec![request.input],
                    }
                }
            }

            fn invocation(request: &CapabilityRequest) -> Result<policy::Invocation<'_>, Failure> {
                if !matches!(request.family, ServiceFamily::Scheduling) {
                    return Err(failure(
                        "wrong-service-family",
                        "scheduling service requires scheduling family",
                    ));
                }
                if !matches!(request.operation, Operation::ScheduleJob) {
                    return Err(failure(
                        "operation-not-owned",
                        "scheduling service owns only schedule-job",
                    ));
                }
                if !matches!(
                    request.authority,
                    AuthorityClass::AutomationControl | AuthorityClass::PromotionControl
                ) {
                    return Err(failure(
                        "insufficient-authority",
                        "schedule-job requires automation-control authority",
                    ));
                }
                if !matches!(request.caller.component_digest.algorithm, HashAlgorithm::Sha256)
                    || !matches!(request.service_component.algorithm, HashAlgorithm::Sha256)
                    || !matches!(request.idempotency_key.algorithm, HashAlgorithm::Sha256)
                    || !matches!(request.input.content_digest.algorithm, HashAlgorithm::Sha256)
                {
                    return Err(failure(
                        "unsupported-digest",
                        "caller, service, idempotency and input digests must use sha256",
                    ));
                }
                Ok(policy::Invocation {
                    expected_family: policy::ServiceFamily::Scheduling,
                    declared_family: policy::ServiceFamily::Scheduling,
                    operation: policy::Operation::ScheduleJob,
                    authority: policy::AuthorityClass::AutomationControl,
                    has_approval: request.approval.is_some(),
                    request_id: &request.request_id,
                    job_id: &request.job_id,
                    caller_id: &request.caller.id,
                    caller_component_hex: &request.caller.component_digest.hex,
                    service_component_hex: &request.service_component.hex,
                    idempotency_key_hex: &request.idempotency_key.hex,
                    input_digest_hex: &request.input.content_digest.hex,
                    input_size: request.input.size_bytes,
                    input_media_type: &request.input.media_type,
                })
            }

            fn response(
                request: &CapabilityRequest,
                outcome: ServiceOutcome,
            ) -> CapabilityResponse {
                CapabilityResponse {
                    request_id: request.request_id.clone(),
                    service_component: request.service_component.clone(),
                    outcome,
                    effect_receipts: Vec::new(),
                    evidence: Vec::new(),
                }
            }

            fn failure(code: impl Into<String>, message: impl Into<String>) -> Failure {
                Failure {
                    code: code.into(),
                    message: message.into(),
                    retryable: false,
                    evidence: None,
                }
            }

            export!(ServiceComponent);
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    fn invocation(operation: Operation) -> Invocation<'static> {
        let policy = operation_policy(operation);
        Invocation {
            expected_family: policy.family,
            declared_family: policy.family,
            operation,
            authority: policy.minimum_authority,
            has_approval: policy.approval_required,
            request_id: "request-1",
            job_id: "job-1",
            caller_id: "worker-1",
            caller_component_hex: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            service_component_hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            idempotency_key_hex: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            input_digest_hex: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            input_size: 0,
            input_media_type: "application/octet-stream",
        }
    }

    #[test]
    fn all_27_operations_have_one_complete_family_owner() {
        let mut by_family = BTreeMap::<ServiceFamily, usize>::new();
        let mut names = BTreeSet::new();
        for operation in Operation::ALL {
            assert!(names.insert(operation.as_str()));
            *by_family
                .entry(operation_policy(operation).family)
                .or_default() += 1;
        }
        assert_eq!(names.len(), 27);
        assert_eq!(by_family.get(&ServiceFamily::Build), Some(&5));
        assert_eq!(by_family.get(&ServiceFamily::Packaging), Some(&2));
        assert_eq!(by_family.get(&ServiceFamily::Validation), Some(&5));
        assert_eq!(by_family.get(&ServiceFamily::Review), Some(&1));
        assert_eq!(by_family.get(&ServiceFamily::Continuity), Some(&2));
        assert_eq!(by_family.get(&ServiceFamily::Scheduling), Some(&1));
        assert_eq!(by_family.get(&ServiceFamily::Operations), Some(&11));
    }

    #[test]
    fn wrong_family_and_operation_fail_before_any_effect() {
        let mut request = invocation(Operation::WorkspaceOpen);
        request.declared_family = ServiceFamily::Review;
        assert_eq!(
            validate_invocation(&request).unwrap_err().code,
            "wrong-service-family"
        );

        request.declared_family = ServiceFamily::Build;
        request.expected_family = ServiceFamily::Review;
        assert_eq!(
            validate_invocation(&request).unwrap_err().code,
            "wrong-service-family"
        );
    }

    #[test]
    fn promotion_operations_require_authority_and_approval() {
        let mut request = invocation(Operation::FactoryActivate);
        request.has_approval = false;
        assert_eq!(
            validate_invocation(&request).unwrap_err().code,
            "approval-required"
        );
        request.has_approval = true;
        request.authority = AuthorityClass::AutomationControl;
        assert_eq!(
            validate_invocation(&request).unwrap_err().code,
            "insufficient-authority"
        );
    }

    #[test]
    fn transformation_is_deterministic_input_sensitive_and_digest_checked() {
        let empty = invocation(Operation::ReviewCandidate);
        let policy = validate_invocation(&empty).unwrap();
        let first = transform_blob(&empty, policy, b"").unwrap();
        let second = transform_blob(&empty, policy, b"").unwrap();
        assert_eq!(first, second);
        assert!(first.starts_with(RESULT_MAGIC));

        let nonempty_digest = hex_sha256(b"x");
        let nonempty = Invocation {
            input_digest_hex: &nonempty_digest,
            input_size: 1,
            ..empty
        };
        let changed = transform_blob(&nonempty, policy, b"x").unwrap();
        assert_ne!(first, changed);

        let mut wrong = empty;
        wrong.input_size = 1;
        assert_eq!(
            transform_blob(&wrong, policy, b"").unwrap_err().code,
            "input-size-mismatch"
        );
    }

    #[test]
    fn graph_bound_caller_and_service_identities_must_be_sha256() {
        let mut request = invocation(Operation::ReviewCandidate);
        request.caller_component_hex = "not-a-digest";
        assert_eq!(
            validate_invocation(&request).unwrap_err().code,
            "invalid-digest"
        );

        request.caller_component_hex =
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        request.service_component_hex = "also-not-a-digest";
        assert_eq!(
            validate_invocation(&request).unwrap_err().code,
            "invalid-digest"
        );

        request.service_component_hex =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        request.idempotency_key_hex = "bad-idempotency-key";
        assert_eq!(
            validate_invocation(&request).unwrap_err().code,
            "invalid-digest"
        );
    }

    #[test]
    fn decision_digest_binds_every_request_field_without_aliases() {
        let base = CapabilityDecisionMaterial {
            request_id: "request-1",
            job_id: "job-1",
            caller_id: "caller-1",
            caller_component_hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            service_component_hex: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            family: "build",
            operation: "candidate-build",
            input_digest_hex: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            input_size: 8,
            input_media_type: "application/octet-stream",
            authority: "local-mutate",
            deadline_ms: Some(100),
        };
        let first = capability_decision_digest_hex(&base);
        assert_eq!(first.len(), 64);
        assert_eq!(first, capability_decision_digest_hex(&base));
        assert_ne!(
            first,
            capability_decision_digest_hex(&CapabilityDecisionMaterial {
                operation: "workspace-patch",
                ..base
            })
        );
        assert_ne!(
            first,
            capability_decision_digest_hex(&CapabilityDecisionMaterial {
                deadline_ms: None,
                ..base
            })
        );
    }
}
