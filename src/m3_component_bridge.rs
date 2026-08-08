//! Fail-closed bridge from a Wasmtime component import to one bounded M3
//! capability invocation.
//!
//! A component import is not allowed to choose a service, operation, request,
//! scope, authority, approval, or idempotency key at call time. Each import is
//! pre-bound to one complete [`CapabilityInvocation`]. The bridge validates
//! that mapping against the live M3 catalog, invokes the actual M3 host, then
//! reloads and verifies the durable receipt and its attestation before
//! returning component-visible effect evidence.
//!
//! There is deliberately no synthetic success path. A missing service,
//! malformed mapping, terminal capability receipt, corrupt durable receipt, or
//! mismatched attestation traps the component import.

use crate::capability_services::{
    CAPABILITY_ATTESTATION_SCHEMA, CancellationToken, CapabilityInvocation, CapabilityOperation,
    CapabilityServiceDescriptor, IdempotencyContract, InvocationApproval, InvocationOutcome,
    InvocationProvenance, InvocationReceipt, ServiceFailure, ServiceFailureKind,
    ServiceInvocationAttestation, TimeoutBehavior,
};
use crate::execution::component::{
    ComponentBuildError, ComponentExecutionContext, ComponentImportBinding,
    ComponentImportEffectHandler, ComponentImportEffectReceipt, EffectfulComponentExecutionTrace,
    execute_component_export_with_effects,
};
use crate::execution::{
    ApprovalClass, AuthorityClass, CapabilityWorld, ContentDigest, NativeServiceFamily,
    digest_json_content,
};
use crate::m3_runtime::{
    BUILD_SERVICE_ID, CONTINUITY_RESOLVE_SERVICE_ID, CONTINUITY_SERVICE_ID,
    FACTORY_EXECUTION_SERVICE_ID, FACTORY_INSPECT_SERVICE_ID, FACTORY_PROMOTION_SERVICE_ID,
    M3CapabilityRuntime, M3RuntimeError, OPERATIONS_CONTROL_SERVICE_ID,
    OPERATIONS_INSPECT_SERVICE_ID, PACKAGING_SERVICE_ID, REVIEW_SERVICE_ID, SCHEDULING_SERVICE_ID,
    VALIDATION_SERVICE_ID,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::sync::Arc;

const BUILD_OPERATIONS: &[CapabilityOperation] = &[
    CapabilityOperation::WorkspaceOpen,
    CapabilityOperation::WorkspaceSnapshot,
    CapabilityOperation::WorkspacePatch,
    CapabilityOperation::CandidateBuild,
];
const VALIDATION_OPERATIONS: &[CapabilityOperation] = &[
    CapabilityOperation::ValidationProve,
    CapabilityOperation::ValidationCompare,
];
const REVIEW_OPERATIONS: &[CapabilityOperation] = &[CapabilityOperation::ReviewCandidate];
const PACKAGING_OPERATIONS: &[CapabilityOperation] = &[
    CapabilityOperation::PackagePublish,
    CapabilityOperation::PackageVerify,
];
const CONTINUITY_PUBLISH_OPERATIONS: &[CapabilityOperation] =
    &[CapabilityOperation::EvidencePublish];
const CONTINUITY_RESOLVE_OPERATIONS: &[CapabilityOperation] =
    &[CapabilityOperation::EvidenceResolve];
const SCHEDULING_OPERATIONS: &[CapabilityOperation] = &[CapabilityOperation::ScheduleJob];
const OPERATIONS_CONTROL_OPERATIONS: &[CapabilityOperation] = &[
    CapabilityOperation::DeploymentInitialize,
    CapabilityOperation::DeploymentActivate,
    CapabilityOperation::DeploymentObserve,
    CapabilityOperation::DeploymentRollback,
];
const OPERATIONS_INSPECT_OPERATIONS: &[CapabilityOperation] =
    &[CapabilityOperation::OperationsInspect];
const FACTORY_EXECUTION_OPERATIONS: &[CapabilityOperation] = &[
    CapabilityOperation::FactoryExecute,
    CapabilityOperation::FactoryProviderProposal,
    CapabilityOperation::FactoryShadow,
];
const FACTORY_PROMOTION_OPERATIONS: &[CapabilityOperation] = &[
    CapabilityOperation::FactoryInitialize,
    CapabilityOperation::FactoryStateMigrate,
    CapabilityOperation::FactoryActivate,
    CapabilityOperation::FactoryObserve,
    CapabilityOperation::FactoryRollback,
];
const FACTORY_INSPECT_OPERATIONS: &[CapabilityOperation] = &[CapabilityOperation::FactoryInspect];

/// One exact component import to one complete typed M3 request.
///
/// Fields are public so this value can be assembled from a durable component
/// manifest. [`M3ComponentEffectBridge::new`] is the trust boundary: it rejects
/// any mapping that is broader than, or inconsistent with, the live service.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M3ComponentImportInvocation {
    pub binding: ComponentImportBinding,
    pub invocation: CapabilityInvocation,
}

impl M3ComponentImportInvocation {
    pub fn new(binding: ComponentImportBinding, invocation: CapabilityInvocation) -> Self {
        Self {
            binding,
            invocation,
        }
    }
}

#[derive(Clone)]
struct PreparedImportInvocation {
    mapping: M3ComponentImportInvocation,
    implementation_digest: ContentDigest,
}

/// Trusted effect handler for component imports.
///
/// The map is immutable after construction. Component calls can therefore
/// select only an import name; they cannot alter the pre-bound M3 invocation.
#[derive(Clone)]
pub struct M3ComponentEffectBridge {
    runtime: Arc<M3CapabilityRuntime>,
    mappings: BTreeMap<String, PreparedImportInvocation>,
}

impl M3ComponentEffectBridge {
    pub fn new(
        runtime: Arc<M3CapabilityRuntime>,
        mappings: impl IntoIterator<Item = M3ComponentImportInvocation>,
    ) -> Result<Self, M3ComponentBridgeError> {
        let mut prepared = BTreeMap::new();
        for mapping in mappings {
            let implementation_digest = validate_mapping(&runtime, &mapping)?;
            let import_name = mapping.binding.import_name.clone();
            if prepared
                .insert(
                    import_name.clone(),
                    PreparedImportInvocation {
                        mapping,
                        implementation_digest,
                    },
                )
                .is_some()
            {
                return Err(M3ComponentBridgeError::DuplicateImport { import_name });
            }
        }
        if prepared.is_empty() {
            return Err(M3ComponentBridgeError::NoMappings);
        }
        Ok(Self {
            runtime,
            mappings: prepared,
        })
    }

    pub fn binding_count(&self) -> usize {
        self.mappings.len()
    }

    pub fn mapping(&self, import_name: &str) -> Option<&M3ComponentImportInvocation> {
        self.mappings
            .get(import_name)
            .map(|prepared| &prepared.mapping)
    }

    fn invoke_prepared(
        &self,
        binding: &ComponentImportBinding,
    ) -> Result<ComponentImportEffectReceipt, M3ComponentBridgeError> {
        let prepared = self.mappings.get(&binding.import_name).ok_or_else(|| {
            M3ComponentBridgeError::UnboundImport {
                import_name: binding.import_name.clone(),
            }
        })?;
        if &prepared.mapping.binding != binding {
            return Err(M3ComponentBridgeError::BindingMismatch {
                import_name: binding.import_name.clone(),
            });
        }

        // Revalidate on every boundary crossing. The mapping is immutable, but
        // this also fails closed if a restarted runtime exposes a different
        // service catalog or scope under a retained bridge.
        let expected_implementation = validate_mapping(&self.runtime, &prepared.mapping)?;
        if expected_implementation != prepared.implementation_digest {
            return Err(M3ComponentBridgeError::EvidenceMismatch(
                "the expected implementation identity changed after bridge construction"
                    .to_string(),
            ));
        }

        let returned = self
            .runtime
            .invoke(&prepared.mapping.invocation, CancellationToken::new())?;
        let stored = self
            .runtime
            .receipt(&prepared.mapping.invocation.identity.invocation_id)?;
        let attestation = self
            .runtime
            .attestation(&prepared.mapping.invocation.identity.invocation_id)?;
        verify_host_evidence(prepared, &returned, &stored, &attestation)?;

        if let InvocationOutcome::Terminal { failure } = returned.outcome() {
            return Err(M3ComponentBridgeError::TerminalCapability(failure.clone()));
        }

        let binding_bytes = serde_json::to_vec(binding)?;
        Ok(ComponentImportEffectReceipt {
            import_name: binding.import_name.clone(),
            binding_digest: ContentDigest::from_bytes(&binding_bytes),
            service_id: attestation.service_id,
            invocation_id: attestation.invocation_id,
            implementation_digest: attestation.implementation_digest,
            input_digest: attestation.input_digest,
            output_digest: attestation.output_digest,
            receipt_digest: attestation.receipt_digest,
            attestation_digest: attestation.attestation_digest,
            terminal_success: true,
        })
    }
}

impl ComponentImportEffectHandler for M3ComponentEffectBridge {
    fn invoke(
        &self,
        binding: &ComponentImportBinding,
    ) -> Result<ComponentImportEffectReceipt, String> {
        self.invoke_prepared(binding)
            .map_err(|error| error.to_string())
    }
}

/// Execute a component export with the M3 bridge as its sole effect owner.
///
/// Component envelope validation in
/// [`execute_component_export_with_effects`] runs while the linker is built,
/// before any import callback can reach M3.
pub fn execute_component_export_with_m3_effects(
    component_bytes: &[u8],
    export_name: impl Into<String>,
    context: &ComponentExecutionContext,
    bridge: Arc<M3ComponentEffectBridge>,
) -> Result<EffectfulComponentExecutionTrace, ComponentBuildError> {
    execute_component_export_with_effects(component_bytes, export_name, context, bridge)
}

fn validate_mapping(
    runtime: &M3CapabilityRuntime,
    mapping: &M3ComponentImportInvocation,
) -> Result<ContentDigest, M3ComponentBridgeError> {
    let import_name = mapping.binding.import_name.as_str();
    if import_name.trim().is_empty() {
        return invalid_mapping(import_name, "import name must not be blank");
    }
    let invocation = &mapping.invocation;
    for (field, value) in [
        ("invocation id", invocation.identity.invocation_id.as_str()),
        (
            "idempotency key",
            invocation.identity.idempotency_key.as_str(),
        ),
        ("caller id", invocation.identity.caller_id.as_str()),
    ] {
        if value.trim().is_empty() {
            return invalid_mapping(import_name, format!("{field} must not be blank"));
        }
    }

    let operation = invocation.request.operation();
    let policy = service_policy(&invocation.identity.service_id).ok_or_else(|| {
        M3ComponentBridgeError::InvalidMapping {
            import_name: import_name.to_string(),
            reason: format!(
                "service '{}' is not in the bounded M3 catalog",
                invocation.identity.service_id
            ),
        }
    })?;
    if !policy.operations.contains(&operation) {
        return invalid_mapping(
            import_name,
            format!(
                "service '{}' does not support operation '{operation:?}'",
                invocation.identity.service_id
            ),
        );
    }

    let registration = runtime
        .services()
        .iter()
        .find(|service| service.service_id == invocation.identity.service_id)
        .ok_or_else(|| M3ComponentBridgeError::InvalidMapping {
            import_name: import_name.to_string(),
            reason: format!(
                "service '{}' is not registered in the live runtime",
                invocation.identity.service_id
            ),
        })?;
    if registration.family != policy.family
        || !registration.supported_operations.contains(&operation)
    {
        return invalid_mapping(
            import_name,
            "the live service registration does not match the bounded bridge policy",
        );
    }

    let scope = runtime.config().scope_id.as_str();
    if mapping.binding.resource_scope != scope
        || invocation.identity.scope_id != scope
        || invocation.request.scope_id() != scope
    {
        return invalid_mapping(
            import_name,
            format!("binding, invocation, request, and runtime must all use exact scope '{scope}'"),
        );
    }

    let expected_world = component_world(operation);
    if mapping.binding.world != expected_world {
        return invalid_mapping(
            import_name,
            format!("operation '{operation:?}' requires component world '{expected_world:?}'"),
        );
    }
    let expected_operation = component_operation_name(operation);
    if mapping.binding.operation != expected_operation {
        return invalid_mapping(
            import_name,
            format!(
                "binding operation '{}' does not equal canonical '{expected_operation}'",
                mapping.binding.operation
            ),
        );
    }
    if mapping.binding.required_authority_class != policy.authority
        || invocation.identity.authority != policy.authority
    {
        return invalid_mapping(
            import_name,
            format!(
                "binding and invocation must use exact least authority '{:?}'",
                policy.authority
            ),
        );
    }
    if !approval_matches(&invocation.identity.approval, &policy.approval) {
        return invalid_mapping(
            import_name,
            format!(
                "invocation approval does not exactly satisfy '{:?}'",
                policy.approval
            ),
        );
    }

    let descriptor = policy.descriptor(scope, &invocation.identity.service_id)?;
    Ok(descriptor.implementation_digest().clone())
}

fn invalid_mapping<T>(
    import_name: &str,
    reason: impl Into<String>,
) -> Result<T, M3ComponentBridgeError> {
    Err(M3ComponentBridgeError::InvalidMapping {
        import_name: import_name.to_string(),
        reason: reason.into(),
    })
}

fn verify_host_evidence(
    prepared: &PreparedImportInvocation,
    returned: &InvocationReceipt,
    stored: &InvocationReceipt,
    attestation: &ServiceInvocationAttestation,
) -> Result<(), M3ComponentBridgeError> {
    returned
        .verify_integrity()
        .map_err(|error| M3ComponentBridgeError::EvidenceMismatch(error.to_string()))?;
    stored
        .verify_integrity()
        .map_err(|error| M3ComponentBridgeError::EvidenceMismatch(error.to_string()))?;
    if returned != stored {
        return evidence_mismatch("returned receipt differs from the reloaded durable receipt");
    }

    let invocation = &prepared.mapping.invocation;
    let operation = invocation.request.operation();
    let expected_input = ContentDigest::from_bytes(
        &serde_json::to_vec(invocation).map_err(M3ComponentBridgeError::Serialization)?,
    );
    if returned.invocation_id() != invocation.identity.invocation_id
        || returned.service_id() != invocation.identity.service_id
        || returned.family() != operation.family()
        || returned.operation() != operation
        || returned.scope_id() != invocation.identity.scope_id
        || returned.input_digest() != &expected_input
    {
        return evidence_mismatch(
            "durable receipt identity does not match the pre-bound invocation",
        );
    }

    if attestation.schema != CAPABILITY_ATTESTATION_SCHEMA
        || attestation.attestation_id
            != format!("attestation:{}", returned.receipt_digest().file_stem())
        || attestation.invocation_id != invocation.identity.invocation_id
        || attestation.service_id != invocation.identity.service_id
        || attestation.family != operation.family()
        || attestation.operation != operation
        || attestation.scope_id != invocation.identity.scope_id
        || attestation.implementation_digest != prepared.implementation_digest
        || &attestation.input_digest != returned.input_digest()
        || &attestation.output_digest != returned.output_digest()
        || &attestation.receipt_digest != returned.receipt_digest()
        || attestation.terminal_success != returned.outcome().is_success()
        || attestation.failure_kind != returned.outcome().failure_kind()
        || &attestation.provenance != returned.provenance()
    {
        return evidence_mismatch(
            "service attestation does not match receipt, implementation, or invocation identity",
        );
    }

    let expected_attestation_digest =
        digest_json_content(&AttestationDigestMaterial::from(attestation))
            .map_err(|error| M3ComponentBridgeError::EvidenceMismatch(error.to_string()))?;
    if attestation.attestation_digest != expected_attestation_digest {
        return evidence_mismatch("service attestation digest does not match its fields");
    }
    Ok(())
}

fn evidence_mismatch<T>(reason: impl Into<String>) -> Result<T, M3ComponentBridgeError> {
    Err(M3ComponentBridgeError::EvidenceMismatch(reason.into()))
}

#[derive(Serialize)]
struct AttestationDigestMaterial<'a> {
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

impl<'a> From<&'a ServiceInvocationAttestation> for AttestationDigestMaterial<'a> {
    fn from(attestation: &'a ServiceInvocationAttestation) -> Self {
        Self {
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
        }
    }
}

struct ServicePolicy {
    family: NativeServiceFamily,
    authority: AuthorityClass,
    approval: ApprovalClass,
    operations: &'static [CapabilityOperation],
    idempotency: IdempotencyContract,
}

impl ServicePolicy {
    fn descriptor(
        &self,
        scope_id: &str,
        service_id: &str,
    ) -> Result<CapabilityServiceDescriptor, M3ComponentBridgeError> {
        CapabilityServiceDescriptor::new(
            service_id,
            self.family,
            scope_id,
            self.authority.clone(),
            self.approval.clone(),
            self.operations.iter().copied(),
            self.idempotency,
            TimeoutBehavior::Cooperative,
            format!("m3-runtime:{service_id}"),
        )
        .map_err(|error| M3ComponentBridgeError::EvidenceMismatch(error.to_string()))
    }
}

fn service_policy(service_id: &str) -> Option<ServicePolicy> {
    let policy = match service_id {
        BUILD_SERVICE_ID => ServicePolicy {
            family: NativeServiceFamily::Build,
            authority: AuthorityClass::LocalMutate,
            approval: ApprovalClass::AutoAllowed,
            operations: BUILD_OPERATIONS,
            idempotency: IdempotencyContract::SingleAttemptNoAutomaticRetry,
        },
        VALIDATION_SERVICE_ID => ServicePolicy {
            family: NativeServiceFamily::Validation,
            authority: AuthorityClass::Observe,
            approval: ApprovalClass::AutoAllowed,
            operations: VALIDATION_OPERATIONS,
            idempotency: IdempotencyContract::IdempotentAtLeastOnce,
        },
        REVIEW_SERVICE_ID => ServicePolicy {
            family: NativeServiceFamily::Review,
            authority: AuthorityClass::Observe,
            approval: ApprovalClass::AutoAllowed,
            operations: REVIEW_OPERATIONS,
            idempotency: IdempotencyContract::ReadOnlyReplayable,
        },
        PACKAGING_SERVICE_ID => ServicePolicy {
            family: NativeServiceFamily::Packaging,
            authority: AuthorityClass::LocalMutate,
            approval: ApprovalClass::AutoAllowed,
            operations: PACKAGING_OPERATIONS,
            idempotency: IdempotencyContract::IdempotentAtLeastOnce,
        },
        CONTINUITY_SERVICE_ID => ServicePolicy {
            family: NativeServiceFamily::Continuity,
            authority: AuthorityClass::LocalMutate,
            approval: ApprovalClass::AutoAllowed,
            operations: CONTINUITY_PUBLISH_OPERATIONS,
            idempotency: IdempotencyContract::IdempotentAtLeastOnce,
        },
        CONTINUITY_RESOLVE_SERVICE_ID => ServicePolicy {
            family: NativeServiceFamily::Continuity,
            authority: AuthorityClass::Observe,
            approval: ApprovalClass::AutoAllowed,
            operations: CONTINUITY_RESOLVE_OPERATIONS,
            idempotency: IdempotencyContract::ReadOnlyReplayable,
        },
        SCHEDULING_SERVICE_ID => ServicePolicy {
            family: NativeServiceFamily::Scheduling,
            authority: AuthorityClass::AutomationControl,
            approval: ApprovalClass::SupervisorAllowed,
            operations: SCHEDULING_OPERATIONS,
            idempotency: IdempotencyContract::IdempotentAtLeastOnce,
        },
        OPERATIONS_CONTROL_SERVICE_ID => ServicePolicy {
            family: NativeServiceFamily::Operations,
            authority: AuthorityClass::PromotionControl,
            approval: ApprovalClass::HumanRequired,
            operations: OPERATIONS_CONTROL_OPERATIONS,
            idempotency: IdempotencyContract::IdempotentAtLeastOnce,
        },
        OPERATIONS_INSPECT_SERVICE_ID => ServicePolicy {
            family: NativeServiceFamily::Operations,
            authority: AuthorityClass::Observe,
            approval: ApprovalClass::AutoAllowed,
            operations: OPERATIONS_INSPECT_OPERATIONS,
            idempotency: IdempotencyContract::ReadOnlyReplayable,
        },
        FACTORY_EXECUTION_SERVICE_ID => ServicePolicy {
            family: NativeServiceFamily::Validation,
            authority: AuthorityClass::Observe,
            approval: ApprovalClass::AutoAllowed,
            operations: FACTORY_EXECUTION_OPERATIONS,
            idempotency: IdempotencyContract::IdempotentAtLeastOnce,
        },
        FACTORY_PROMOTION_SERVICE_ID => ServicePolicy {
            family: NativeServiceFamily::Operations,
            authority: AuthorityClass::PromotionControl,
            approval: ApprovalClass::HumanRequired,
            operations: FACTORY_PROMOTION_OPERATIONS,
            idempotency: IdempotencyContract::IdempotentAtLeastOnce,
        },
        FACTORY_INSPECT_SERVICE_ID => ServicePolicy {
            family: NativeServiceFamily::Operations,
            authority: AuthorityClass::Observe,
            approval: ApprovalClass::AutoAllowed,
            operations: FACTORY_INSPECT_OPERATIONS,
            idempotency: IdempotencyContract::ReadOnlyReplayable,
        },
        _ => return None,
    };
    Some(policy)
}

fn approval_matches(actual: &InvocationApproval, required: &ApprovalClass) -> bool {
    match (actual, required) {
        (InvocationApproval::Automatic, ApprovalClass::AutoAllowed) => true,
        (
            InvocationApproval::Granted { class, .. },
            ApprovalClass::SupervisorAllowed | ApprovalClass::HumanRequired,
        ) => class == required,
        _ => false,
    }
}

/// Canonical operation token placed in a component capability envelope.
pub const fn component_operation_name(operation: CapabilityOperation) -> &'static str {
    match operation {
        CapabilityOperation::WorkspaceOpen => "workspace_open",
        CapabilityOperation::WorkspaceSnapshot => "workspace_snapshot",
        CapabilityOperation::WorkspacePatch => "workspace_patch",
        CapabilityOperation::CandidateBuild => "candidate_build",
        CapabilityOperation::CommandExecute => "command_execute",
        CapabilityOperation::PackagePublish => "package_publish",
        CapabilityOperation::PackageVerify => "package_verify",
        CapabilityOperation::ValidationProve => "validation_prove",
        CapabilityOperation::ValidationCompare => "validation_compare",
        CapabilityOperation::ReviewCandidate => "review_candidate",
        CapabilityOperation::EvidencePublish => "evidence_publish",
        CapabilityOperation::EvidenceResolve => "evidence_resolve",
        CapabilityOperation::ScheduleJob => "schedule_job",
        CapabilityOperation::DeploymentInitialize => "deployment_initialize",
        CapabilityOperation::DeploymentActivate => "deployment_activate",
        CapabilityOperation::DeploymentObserve => "deployment_observe",
        CapabilityOperation::DeploymentRollback => "deployment_rollback",
        CapabilityOperation::OperationsInspect => "operations_inspect",
        CapabilityOperation::FactoryExecute => "factory_execute",
        CapabilityOperation::FactoryProviderProposal => "factory_provider_proposal",
        CapabilityOperation::FactoryShadow => "factory_shadow",
        CapabilityOperation::FactoryInitialize => "factory_initialize",
        CapabilityOperation::FactoryStateMigrate => "factory_state_migrate",
        CapabilityOperation::FactoryActivate => "factory_activate",
        CapabilityOperation::FactoryObserve => "factory_observe",
        CapabilityOperation::FactoryRollback => "factory_rollback",
        CapabilityOperation::FactoryInspect => "factory_inspect",
    }
}

/// Narrow component world associated with one typed M3 operation.
pub const fn component_world(operation: CapabilityOperation) -> CapabilityWorld {
    match operation {
        CapabilityOperation::WorkspaceOpen
        | CapabilityOperation::WorkspacePatch
        | CapabilityOperation::CandidateBuild
        | CapabilityOperation::CommandExecute => CapabilityWorld::WorkspaceMutate,
        CapabilityOperation::WorkspaceSnapshot => CapabilityWorld::WorkspaceObserve,
        CapabilityOperation::PackagePublish
        | CapabilityOperation::PackageVerify
        | CapabilityOperation::ValidationProve
        | CapabilityOperation::OperationsInspect
        | CapabilityOperation::FactoryExecute
        | CapabilityOperation::FactoryProviderProposal
        | CapabilityOperation::FactoryShadow
        | CapabilityOperation::FactoryInspect => CapabilityWorld::ServiceOrganelle,
        CapabilityOperation::ValidationCompare
        | CapabilityOperation::ReviewCandidate
        | CapabilityOperation::DeploymentInitialize
        | CapabilityOperation::DeploymentActivate
        | CapabilityOperation::DeploymentObserve
        | CapabilityOperation::DeploymentRollback
        | CapabilityOperation::FactoryInitialize
        | CapabilityOperation::FactoryStateMigrate
        | CapabilityOperation::FactoryActivate
        | CapabilityOperation::FactoryObserve
        | CapabilityOperation::FactoryRollback => CapabilityWorld::ReviewPromotion,
        CapabilityOperation::EvidencePublish | CapabilityOperation::EvidenceResolve => {
            CapabilityWorld::MemoryAccess
        }
        CapabilityOperation::ScheduleJob => CapabilityWorld::ScheduleTick,
    }
}

#[derive(Debug)]
pub enum M3ComponentBridgeError {
    NoMappings,
    DuplicateImport { import_name: String },
    UnboundImport { import_name: String },
    BindingMismatch { import_name: String },
    InvalidMapping { import_name: String, reason: String },
    TerminalCapability(ServiceFailure),
    EvidenceMismatch(String),
    Runtime(M3RuntimeError),
    Serialization(serde_json::Error),
}

impl From<M3RuntimeError> for M3ComponentBridgeError {
    fn from(value: M3RuntimeError) -> Self {
        Self::Runtime(value)
    }
}

impl From<serde_json::Error> for M3ComponentBridgeError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialization(value)
    }
}

impl Display for M3ComponentBridgeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoMappings => formatter.write_str("M3 component bridge has no import mappings"),
            Self::DuplicateImport { import_name } => {
                write!(
                    formatter,
                    "duplicate M3 component import mapping '{import_name}'"
                )
            }
            Self::UnboundImport { import_name } => {
                write!(
                    formatter,
                    "component import '{import_name}' is not pre-bound"
                )
            }
            Self::BindingMismatch { import_name } => write!(
                formatter,
                "component import '{import_name}' does not match its exact pre-bound capability"
            ),
            Self::InvalidMapping {
                import_name,
                reason,
            } => write!(
                formatter,
                "invalid M3 mapping for component import '{import_name}': {reason}"
            ),
            Self::TerminalCapability(failure) => {
                write!(formatter, "M3 capability completed terminally: {failure}")
            }
            Self::EvidenceMismatch(reason) => {
                write!(formatter, "M3 effect evidence mismatch: {reason}")
            }
            Self::Runtime(error) => write!(formatter, "M3 effect runtime failed: {error}"),
            Self::Serialization(error) => {
                write!(formatter, "M3 effect evidence encoding failed: {error}")
            }
        }
    }
}

impl Error for M3ComponentBridgeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::TerminalCapability(failure) => Some(failure),
            Self::Runtime(error) => Some(error),
            Self::Serialization(error) => Some(error),
            Self::NoMappings
            | Self::DuplicateImport { .. }
            | Self::UnboundImport { .. }
            | Self::BindingMismatch { .. }
            | Self::InvalidMapping { .. }
            | Self::EvidenceMismatch(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability_services::{
        CapabilityRequest, InvocationBudget, InvocationIdentity, PublishEvidenceRequest,
        ResolveEvidenceRequest,
    };
    use crate::execution::component::ComponentBuildError;
    use crate::execution::{
        CapabilityEnvelope, CapabilityOperationApproval, CapabilityWorldGrant, IsolationProfile,
    };
    use crate::m2_runtime::{M2Runtime, M2RuntimeConfig};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    const SCOPE: &str = "component-bridge-scope";
    const DEPLOYMENT: &str = "component-bridge-deployment";
    const IMPORT_NAME: &str = "continuity-publish";
    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    struct TestDirectory {
        root: PathBuf,
    }

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "wasm-biotic-m3-component-{label}-{}-{sequence}",
                std::process::id()
            ));
            if root.exists() {
                fs::remove_dir_all(&root).expect("remove stale component bridge fixture");
            }
            fs::create_dir(&root).expect("create component bridge fixture");
            Self { root }
        }

        fn template(&self) -> PathBuf {
            let template = self.root.join("template");
            fs::create_dir(&template).expect("create template directory");
            fs::write(
                template.join("component.wit"),
                "package wasm-biotic:reference-task;\n\nworld reference-task {\n    export transform: func(input: s32) -> s32;\n}\n",
            )
            .expect("write template WIT");
            fs::write(
                template.join("component.wat"),
                "(component\n  (core module $incumbent\n    (func (export \"transform\") (param i32) (result i32)\n      local.get 0))\n  (core instance $incumbent-instance (instantiate $incumbent))\n  (func (export \"transform\") (param \"input\" s32) (result s32)\n    (canon lift (core func $incumbent-instance \"transform\"))))\n",
            )
            .expect("write template component");
            template
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn runtime(
        test: &TestDirectory,
        label: &str,
    ) -> (
        crate::m3_runtime::M3RuntimeConfig,
        Arc<M2Runtime>,
        Arc<M3CapabilityRuntime>,
    ) {
        let template = test.template();
        let m2 = Arc::new(
            M2Runtime::new(M2RuntimeConfig {
                supervisor_root: test.root.join(format!("{label}-supervisor")),
                lifecycle_root: test.root.join(format!("{label}-lifecycle")),
                template_root: template.clone(),
                owner_id: format!("component-bridge-{label}"),
                max_idle_wait_ms: 10,
            })
            .expect("construct M2"),
        );
        let config = crate::m3_runtime::M3RuntimeConfig::new(
            test.root.join(format!("{label}-m3")),
            template,
            SCOPE,
            DEPLOYMENT,
        );
        let runtime =
            Arc::new(M3CapabilityRuntime::open(config.clone(), Arc::clone(&m2)).expect("open M3"));
        (config, m2, runtime)
    }

    fn publish_invocation(
        invocation_id: &str,
        evidence_id: &str,
        payload: &[u8],
        expected_digest: ContentDigest,
    ) -> CapabilityInvocation {
        CapabilityInvocation {
            identity: InvocationIdentity {
                invocation_id: invocation_id.to_string(),
                idempotency_key: format!("idempotency:{invocation_id}"),
                service_id: CONTINUITY_SERVICE_ID.to_string(),
                scope_id: SCOPE.to_string(),
                caller_id: "component:continuity-publisher".to_string(),
                authority: AuthorityClass::LocalMutate,
                approval: InvocationApproval::Automatic,
            },
            budget: InvocationBudget::bounded(30_000),
            request: CapabilityRequest::PublishEvidence(PublishEvidenceRequest {
                scope_id: SCOPE.to_string(),
                evidence_id: evidence_id.to_string(),
                media_type: "application/json".to_string(),
                subject_refs: vec!["component:test".to_string()],
                payload: payload.to_vec(),
                expected_digest: Some(expected_digest),
            }),
        }
    }

    fn resolve_invocation(
        invocation_id: &str,
        evidence_id: &str,
        expected_digest: ContentDigest,
    ) -> CapabilityInvocation {
        CapabilityInvocation {
            identity: InvocationIdentity {
                invocation_id: invocation_id.to_string(),
                idempotency_key: format!("idempotency:{invocation_id}"),
                service_id: CONTINUITY_RESOLVE_SERVICE_ID.to_string(),
                scope_id: SCOPE.to_string(),
                caller_id: "test:continuity-reader".to_string(),
                authority: AuthorityClass::Observe,
                approval: InvocationApproval::Automatic,
            },
            budget: InvocationBudget::bounded(30_000),
            request: CapabilityRequest::ResolveEvidence(ResolveEvidenceRequest {
                scope_id: SCOPE.to_string(),
                evidence_id: evidence_id.to_string(),
                expected_digest,
            }),
        }
    }

    fn publish_mapping(invocation: CapabilityInvocation) -> M3ComponentImportInvocation {
        M3ComponentImportInvocation::new(
            ComponentImportBinding {
                import_name: IMPORT_NAME.to_string(),
                world: CapabilityWorld::MemoryAccess,
                operation: component_operation_name(CapabilityOperation::EvidencePublish)
                    .to_string(),
                resource_scope: SCOPE.to_string(),
                required_authority_class: AuthorityClass::LocalMutate,
            },
            invocation,
        )
    }

    fn context(resource_scopes: Vec<String>, approval: ApprovalClass) -> ComponentExecutionContext {
        ComponentExecutionContext {
            capability_envelope: CapabilityEnvelope {
                envelope_id: "envelope:m3-component-test".to_string(),
                actor_scope: "component:test".to_string(),
                world_grants: vec![CapabilityWorldGrant {
                    world: CapabilityWorld::MemoryAccess,
                    allowed_operations: vec![
                        component_operation_name(CapabilityOperation::EvidencePublish).to_string(),
                    ],
                    default_authority_class: AuthorityClass::LocalMutate,
                    default_approval_class: approval,
                    operation_approval_overrides: Vec::<CapabilityOperationApproval>::new(),
                }],
                authority_ceiling: AuthorityClass::LocalMutate,
                isolation_profile: IsolationProfile::ArtifactSandbox,
                allowed_resource_scopes: resource_scopes,
                approval_overrides: Vec::new(),
                quota_policy: None,
                campaign_scope: None,
                epoch_scope: None,
            },
            import_bindings: vec![
                publish_mapping(publish_invocation(
                    "context-placeholder",
                    "context-placeholder",
                    b"{}",
                    ContentDigest::from_bytes(b"{}"),
                ))
                .binding,
            ],
        }
    }

    fn component_bytes() -> Vec<u8> {
        wat::parse_str(
            r#"
                (component
                    (import "continuity-publish" (func $continuity-publish))
                    (core func $continuity-publish-core
                        (canon lower (func $continuity-publish)))
                    (core module $m
                        (import "" "continuity-publish" (func $continuity-publish))
                        (func (export "run")
                            call $continuity-publish))
                    (core instance $i (instantiate $m
                        (with "" (instance
                            (export "continuity-publish"
                                (func $continuity-publish-core))))))
                    (func $run (canon lift (core func $i "run")))
                    (export "run" (func $run)))
            "#,
        )
        .expect("lower component WAT")
    }

    fn receipt_absent(runtime: &M3CapabilityRuntime, invocation_id: &str) {
        assert!(
            runtime.receipt(invocation_id).is_err(),
            "no host receipt may exist before an effect callback"
        );
    }

    fn assert_terminal(receipt: &InvocationReceipt, kind: ServiceFailureKind) {
        match receipt.outcome() {
            InvocationOutcome::Terminal { failure } => assert_eq!(failure.kind, kind),
            InvocationOutcome::Succeeded { .. } => panic!("expected terminal receipt"),
        }
    }

    #[test]
    fn real_component_import_persists_and_reloads_continuity_effect_evidence() {
        let test = TestDirectory::new("real-effect");
        let (config, m2, runtime) = runtime(&test, "real-effect");
        let payload = br#"{"proof":"component-called-m3"}"#;
        let payload_digest = ContentDigest::from_bytes(payload);
        let invocation = publish_invocation(
            "component-publish-real",
            "component-evidence-real",
            payload,
            payload_digest.clone(),
        );
        let bridge = Arc::new(
            M3ComponentEffectBridge::new(
                Arc::clone(&runtime),
                [publish_mapping(invocation.clone())],
            )
            .expect("construct exact bridge"),
        );
        let execution = execute_component_export_with_m3_effects(
            &component_bytes(),
            "run",
            &context(vec![SCOPE.to_string()], ApprovalClass::AutoAllowed),
            Arc::clone(&bridge),
        )
        .expect("component must execute the real effect");

        assert_eq!(execution.execution.invoked_imports, [IMPORT_NAME]);
        assert_eq!(execution.effects.len(), 1);
        let effect = &execution.effects[0];
        assert_eq!(effect.service_id, CONTINUITY_SERVICE_ID);
        assert_eq!(effect.invocation_id, invocation.identity.invocation_id);
        assert!(effect.terminal_success);
        let durable_receipt = runtime
            .receipt(&invocation.identity.invocation_id)
            .expect("reload receipt through live host");
        let durable_attestation = runtime
            .attestation(&invocation.identity.invocation_id)
            .expect("derive attestation from durable receipt");
        assert_eq!(effect.receipt_digest, *durable_receipt.receipt_digest());
        assert_eq!(
            effect.attestation_digest,
            durable_attestation.attestation_digest
        );

        runtime.stop().expect("stop original M3 host");
        drop(bridge);
        drop(runtime);
        let reopened =
            M3CapabilityRuntime::open(config, m2).expect("reopen M3 from the same durable root");
        let reopened_receipt = reopened
            .receipt(&invocation.identity.invocation_id)
            .expect("receipt must survive restart");
        assert_eq!(reopened_receipt, durable_receipt);
        let resolve = reopened
            .invoke(
                &resolve_invocation(
                    "resolve-component-evidence",
                    "component-evidence-real",
                    payload_digest,
                ),
                CancellationToken::new(),
            )
            .expect("resolve persisted continuity evidence");
        match resolve.outcome() {
            InvocationOutcome::Succeeded {
                result: crate::capability_services::CapabilitySuccess::EvidenceResolved(resolved),
            } => assert_eq!(resolved.payload, payload),
            other => panic!("unexpected continuity resolve outcome: {other:?}"),
        }
    }

    #[test]
    fn wrong_binding_scope_and_service_are_rejected_without_effect() {
        let test = TestDirectory::new("wrong-map");
        let (_config, _m2, runtime) = runtime(&test, "wrong-map");
        let payload = b"binding-check";
        let invocation = publish_invocation(
            "wrong-map-effect",
            "wrong-map-evidence",
            payload,
            ContentDigest::from_bytes(payload),
        );
        let valid = publish_mapping(invocation.clone());
        let bridge = M3ComponentEffectBridge::new(Arc::clone(&runtime), [valid.clone()])
            .expect("valid bridge");

        let mut wrong_binding = valid.binding.clone();
        wrong_binding.world = CapabilityWorld::ServiceOrganelle;
        let error = ComponentImportEffectHandler::invoke(&bridge, &wrong_binding)
            .expect_err("different binding must not select a pre-bound invocation");
        assert!(error.contains("does not match"));
        receipt_absent(&runtime, &invocation.identity.invocation_id);

        let mut wrong_scope = valid.clone();
        wrong_scope.binding.resource_scope = "another-scope".to_string();
        assert!(matches!(
            M3ComponentEffectBridge::new(Arc::clone(&runtime), [wrong_scope]),
            Err(M3ComponentBridgeError::InvalidMapping { .. })
        ));

        let mut wrong_service = valid;
        wrong_service.invocation.identity.service_id = CONTINUITY_RESOLVE_SERVICE_ID.to_string();
        assert!(matches!(
            M3ComponentEffectBridge::new(Arc::clone(&runtime), [wrong_service]),
            Err(M3ComponentBridgeError::InvalidMapping { .. })
        ));
        receipt_absent(&runtime, &invocation.identity.invocation_id);
    }

    #[test]
    fn failed_and_unsupported_capabilities_cannot_become_component_success() {
        let test = TestDirectory::new("terminal");
        let (_config, _m2, runtime) = runtime(&test, "terminal");
        let payload = b"actual-payload";
        let failed = publish_invocation(
            "component-publish-fails",
            "component-evidence-fails",
            payload,
            ContentDigest::from_bytes(b"different-payload"),
        );
        let bridge = Arc::new(
            M3ComponentEffectBridge::new(Arc::clone(&runtime), [publish_mapping(failed.clone())])
                .expect("construct failing invocation bridge"),
        );
        let error = execute_component_export_with_m3_effects(
            &component_bytes(),
            "run",
            &context(vec![SCOPE.to_string()], ApprovalClass::AutoAllowed),
            bridge,
        )
        .expect_err("terminal M3 receipt must trap the component");
        assert!(matches!(error, ComponentBuildError::Wasmtime(_)));
        let failed_receipt = runtime
            .receipt(&failed.identity.invocation_id)
            .expect("terminal receipt remains durable");
        assert_terminal(&failed_receipt, ServiceFailureKind::Failed);

        let unsupported_id = "component-unsupported-operation";
        let unsupported = M3ComponentImportInvocation::new(
            ComponentImportBinding {
                import_name: "continuity-resolve-through-publisher".to_string(),
                world: CapabilityWorld::MemoryAccess,
                operation: component_operation_name(CapabilityOperation::EvidenceResolve)
                    .to_string(),
                resource_scope: SCOPE.to_string(),
                required_authority_class: AuthorityClass::Observe,
            },
            CapabilityInvocation {
                identity: InvocationIdentity {
                    invocation_id: unsupported_id.to_string(),
                    idempotency_key: format!("idempotency:{unsupported_id}"),
                    service_id: CONTINUITY_SERVICE_ID.to_string(),
                    scope_id: SCOPE.to_string(),
                    caller_id: "component:test".to_string(),
                    authority: AuthorityClass::Observe,
                    approval: InvocationApproval::Automatic,
                },
                budget: InvocationBudget::bounded(30_000),
                request: CapabilityRequest::ResolveEvidence(ResolveEvidenceRequest {
                    scope_id: SCOPE.to_string(),
                    evidence_id: "not-present".to_string(),
                    expected_digest: ContentDigest::from_bytes(b"not-present"),
                }),
            },
        );
        assert!(matches!(
            M3ComponentEffectBridge::new(Arc::clone(&runtime), [unsupported]),
            Err(M3ComponentBridgeError::InvalidMapping { .. })
        ));
        receipt_absent(&runtime, unsupported_id);
    }

    #[test]
    fn forged_or_cross_invocation_receipt_and_attestation_evidence_is_rejected() {
        let test = TestDirectory::new("forgery");
        let (_config, _m2, runtime) = runtime(&test, "forgery");
        let first_payload = b"first-proof";
        let first = publish_invocation(
            "forgery-first",
            "forgery-evidence-first",
            first_payload,
            ContentDigest::from_bytes(first_payload),
        );
        let bridge =
            M3ComponentEffectBridge::new(Arc::clone(&runtime), [publish_mapping(first.clone())])
                .expect("construct verified bridge");
        let prepared = bridge
            .mappings
            .get(IMPORT_NAME)
            .expect("prepared import mapping");
        let first_receipt = runtime
            .invoke(&first, CancellationToken::new())
            .expect("invoke first capability");
        let first_stored = runtime
            .receipt(&first.identity.invocation_id)
            .expect("reload first receipt");
        let first_attestation = runtime
            .attestation(&first.identity.invocation_id)
            .expect("attest first receipt");
        verify_host_evidence(prepared, &first_receipt, &first_stored, &first_attestation)
            .expect("unaltered evidence must verify");

        let second_payload = b"second-proof";
        let second = publish_invocation(
            "forgery-second",
            "forgery-evidence-second",
            second_payload,
            ContentDigest::from_bytes(second_payload),
        );
        let second_receipt = runtime
            .invoke(&second, CancellationToken::new())
            .expect("invoke second capability");
        let error = verify_host_evidence(
            prepared,
            &second_receipt,
            &second_receipt,
            &first_attestation,
        )
        .expect_err("another invocation's genuine receipt must not verify");
        assert!(matches!(error, M3ComponentBridgeError::EvidenceMismatch(_)));

        let mut forged_receipt_json =
            serde_json::to_value(&first_receipt).expect("encode receipt for forgery test");
        forged_receipt_json["service_id"] =
            serde_json::Value::String(CONTINUITY_RESOLVE_SERVICE_ID.to_string());
        let forged_receipt: InvocationReceipt =
            serde_json::from_value(forged_receipt_json).expect("decode structurally valid forgery");
        assert!(
            verify_host_evidence(
                prepared,
                &forged_receipt,
                &forged_receipt,
                &first_attestation
            )
            .is_err()
        );

        let mut forged_implementation = first_attestation.clone();
        forged_implementation.implementation_digest =
            ContentDigest::from_bytes(b"forged-implementation");
        let mut forged_output = first_attestation.clone();
        forged_output.output_digest = ContentDigest::from_bytes(b"forged-output");
        let mut forged_receipt = first_attestation.clone();
        forged_receipt.receipt_digest = ContentDigest::from_bytes(b"forged-receipt");
        for forged_attestation in [forged_implementation, forged_output, forged_receipt] {
            assert!(
                verify_host_evidence(prepared, &first_receipt, &first_stored, &forged_attestation)
                    .is_err()
            );
        }
    }

    #[test]
    fn resource_scope_and_approval_envelopes_reject_before_effect_callback() {
        let test = TestDirectory::new("envelope");
        let (_config, _m2, runtime) = runtime(&test, "envelope");
        let payload = b"must-not-be-published";
        let invocation = publish_invocation(
            "envelope-preflight-effect",
            "envelope-preflight-evidence",
            payload,
            ContentDigest::from_bytes(payload),
        );
        let bridge = Arc::new(
            M3ComponentEffectBridge::new(
                Arc::clone(&runtime),
                [publish_mapping(invocation.clone())],
            )
            .expect("construct exact bridge"),
        );
        let bytes = component_bytes();

        let scope_error = execute_component_export_with_m3_effects(
            &bytes,
            "run",
            &context(
                vec!["another-resource-scope".to_string()],
                ApprovalClass::AutoAllowed,
            ),
            Arc::clone(&bridge),
        )
        .expect_err("resource scope must be rejected while linking");
        assert!(matches!(
            scope_error,
            ComponentBuildError::ImportResourceScopeNotAllowed { .. }
        ));
        receipt_absent(&runtime, &invocation.identity.invocation_id);

        let approval_error = execute_component_export_with_m3_effects(
            &bytes,
            "run",
            &context(vec![SCOPE.to_string()], ApprovalClass::HumanRequired),
            bridge,
        )
        .expect_err("blocking approval must be rejected while linking");
        assert!(matches!(
            approval_error,
            ComponentBuildError::ImportApprovalBlocked { .. }
        ));
        receipt_absent(&runtime, &invocation.identity.invocation_id);
        let health = runtime
            .health(CONTINUITY_SERVICE_ID)
            .expect("read continuity health");
        assert_eq!(health.successful_invocations, 0);
        assert_eq!(health.failed_invocations, 0);
    }

    #[test]
    fn duplicate_empty_and_overprivileged_mappings_fail_closed() {
        let test = TestDirectory::new("construction");
        let (_config, _m2, runtime) = runtime(&test, "construction");
        assert!(matches!(
            M3ComponentEffectBridge::new(Arc::clone(&runtime), []),
            Err(M3ComponentBridgeError::NoMappings)
        ));

        let payload = b"construction";
        let invocation = publish_invocation(
            "construction-effect",
            "construction-evidence",
            payload,
            ContentDigest::from_bytes(payload),
        );
        let valid = publish_mapping(invocation.clone());
        assert!(matches!(
            M3ComponentEffectBridge::new(Arc::clone(&runtime), [valid.clone(), valid.clone()]),
            Err(M3ComponentBridgeError::DuplicateImport { .. })
        ));

        let mut overprivileged = valid;
        overprivileged.invocation.identity.authority = AuthorityClass::PromotionControl;
        overprivileged.binding.required_authority_class = AuthorityClass::PromotionControl;
        assert!(matches!(
            M3ComponentEffectBridge::new(Arc::clone(&runtime), [overprivileged]),
            Err(M3ComponentBridgeError::InvalidMapping { .. })
        ));
        receipt_absent(&runtime, &invocation.identity.invocation_id);
    }
}
