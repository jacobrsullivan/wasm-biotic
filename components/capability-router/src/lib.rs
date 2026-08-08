#![cfg_attr(all(target_arch = "wasm32", not(test)), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

//! Component-owned capability routing, authority and approval policy.

extern crate alloc;

#[cfg(target_arch = "wasm32")]
use alloc::string::{String, ToString};
use alloc::vec::Vec;

pub const APPROVAL_NAMESPACE: &str = "wasm-biotic.approvals.v1";
pub const APPROVAL_USE_MEDIA_TYPE: &str =
    "application/vnd.wasm-biotic.approval-use.v1+octet-stream";
const APPROVAL_USE_MAGIC: &[u8] = b"WASM-BIOTIC-APPROVAL-USE\0\x01";

/// Seven canonical service families.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    Build,
    Packaging,
    Validation,
    Review,
    Continuity,
    Scheduling,
    Operations,
}

impl Family {
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

/// Four ordered authority classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Authority {
    Observe,
    LocalMutate,
    AutomationControl,
    PromotionControl,
}

impl Authority {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::LocalMutate => "local-mutate",
            Self::AutomationControl => "automation-control",
            Self::PromotionControl => "promotion-control",
        }
    }
}

/// Exhaustive operation vocabulary mirrored from the versioned WIT contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    pub const fn as_str(self) -> &'static str {
        operation_to_core(self).as_str()
    }
}

/// Canonical durable binding for one authenticated approval use. Exact replay
/// is idempotent; reusing an approval id with any changed field is rejected.
pub fn approval_binding_bytes(
    approval_id: &str,
    decision_digest_hex: &str,
    approver: &str,
    recorded_at_ms: u64,
    signature: &[u8],
) -> Vec<u8> {
    let mut output = Vec::with_capacity(
        APPROVAL_USE_MAGIC.len()
            + approval_id.len()
            + decision_digest_hex.len()
            + approver.len()
            + signature.len()
            + 64,
    );
    output.extend_from_slice(APPROVAL_USE_MAGIC);
    append_field(&mut output, approval_id.as_bytes());
    append_field(&mut output, decision_digest_hex.as_bytes());
    append_field(&mut output, approver.as_bytes());
    output.extend_from_slice(&recorded_at_ms.to_be_bytes());
    append_field(&mut output, signature);
    output
}

fn append_field(output: &mut Vec<u8>, field: &[u8]) {
    output.extend_from_slice(&u64::try_from(field.len()).unwrap_or(u64::MAX).to_be_bytes());
    output.extend_from_slice(field);
}

/// Static policy attached to an operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoutePolicy {
    pub family: Family,
    pub minimum_authority: Authority,
    pub approval_required: bool,
}

/// Returns the exhaustive bounded-v1 policy for one operation.
#[must_use]
pub const fn policy(operation: Operation) -> RoutePolicy {
    let source = wasm_biotic_service_policy_core::operation_policy(operation_to_core(operation));
    RoutePolicy {
        family: family_from_core(source.family),
        minimum_authority: authority_from_core(source.minimum_authority),
        approval_required: source.approval_required,
    }
}

const fn family_from_core(value: wasm_biotic_service_policy_core::ServiceFamily) -> Family {
    use wasm_biotic_service_policy_core::ServiceFamily as Core;
    match value {
        Core::Build => Family::Build,
        Core::Packaging => Family::Packaging,
        Core::Validation => Family::Validation,
        Core::Review => Family::Review,
        Core::Continuity => Family::Continuity,
        Core::Scheduling => Family::Scheduling,
        Core::Operations => Family::Operations,
    }
}

const fn authority_from_core(value: wasm_biotic_service_policy_core::AuthorityClass) -> Authority {
    use wasm_biotic_service_policy_core::AuthorityClass as Core;
    match value {
        Core::Observe => Authority::Observe,
        Core::LocalMutate => Authority::LocalMutate,
        Core::AutomationControl => Authority::AutomationControl,
        Core::PromotionControl => Authority::PromotionControl,
    }
}

const fn operation_to_core(value: Operation) -> wasm_biotic_service_policy_core::Operation {
    use wasm_biotic_service_policy_core::Operation as Core;
    match value {
        Operation::WorkspaceOpen => Core::WorkspaceOpen,
        Operation::WorkspaceSnapshot => Core::WorkspaceSnapshot,
        Operation::WorkspacePatch => Core::WorkspacePatch,
        Operation::CandidateBuild => Core::CandidateBuild,
        Operation::CommandExecute => Core::CommandExecute,
        Operation::PackagePublish => Core::PackagePublish,
        Operation::PackageVerify => Core::PackageVerify,
        Operation::ValidationProve => Core::ValidationProve,
        Operation::ValidationCompare => Core::ValidationCompare,
        Operation::ReviewCandidate => Core::ReviewCandidate,
        Operation::EvidencePublish => Core::EvidencePublish,
        Operation::EvidenceResolve => Core::EvidenceResolve,
        Operation::ScheduleJob => Core::ScheduleJob,
        Operation::DeploymentInitialize => Core::DeploymentInitialize,
        Operation::DeploymentActivate => Core::DeploymentActivate,
        Operation::DeploymentObserve => Core::DeploymentObserve,
        Operation::DeploymentRollback => Core::DeploymentRollback,
        Operation::OperationsInspect => Core::OperationsInspect,
        Operation::FactoryExecute => Core::FactoryExecute,
        Operation::FactoryProviderProposal => Core::FactoryProviderProposal,
        Operation::FactoryShadow => Core::FactoryShadow,
        Operation::FactoryInitialize => Core::FactoryInitialize,
        Operation::FactoryStateMigrate => Core::FactoryStateMigrate,
        Operation::FactoryActivate => Core::FactoryActivate,
        Operation::FactoryObserve => Core::FactoryObserve,
        Operation::FactoryRollback => Core::FactoryRollback,
        Operation::FactoryInspect => Core::FactoryInspect,
    }
}

/// Pure routing admission. Approval digest binding is checked by the component
/// adapter because the pure policy intentionally does not own cryptography.
pub fn admit(
    operation: Operation,
    supplied_family: Family,
    supplied_authority: Authority,
    approval_present: bool,
) -> Result<(), &'static str> {
    let expected = policy(operation);
    if supplied_family != expected.family {
        return Err("operation-family-mismatch");
    }
    if supplied_authority < expected.minimum_authority {
        return Err("insufficient-authority");
    }
    if expected.approval_required && !approval_present {
        return Err("approval-required");
    }
    Ok(())
}

#[cfg(target_arch = "wasm32")]
mod component {
    use super::*;

    wit_bindgen::generate!({
        path: "../../wit/wasm-biotic",
        world: "capability-router-component",
    });

    use exports::wasm_biotic::factory::capability_router::Guest;
    use wasm_biotic::factory::capability_contract::{
        CapabilityRequest, CapabilityResponse, Operation as WitOperation, ServiceFamily,
        ServiceOutcome,
    };
    use wasm_biotic::factory::foundation::{AuthorityClass, Digest, Failure, HashAlgorithm};
    use wasm_biotic::factory::key_service::{Signature, SignatureAlgorithm};
    use wasm_biotic::factory::transaction_store::{Assertion, CommitRequest, Mutation};

    struct CapabilityRouterComponent;

    impl Guest for CapabilityRouterComponent {
        fn route(request: CapabilityRequest) -> CapabilityResponse {
            let operation = operation_from_wit(request.operation);
            let family = family_from_wit(request.family);
            let authority = authority_from_wit(request.authority);
            let expected_decision = wasm_biotic_service_policy_core::capability_decision_digest_hex(
                &wasm_biotic_service_policy_core::CapabilityDecisionMaterial {
                    request_id: &request.request_id,
                    job_id: &request.job_id,
                    caller_id: &request.caller.id,
                    caller_component_hex: &request.caller.component_digest.hex,
                    service_component_hex: &request.service_component.hex,
                    family: family.as_str(),
                    operation: operation.as_str(),
                    input_digest_hex: &request.input.content_digest.hex,
                    input_size: request.input.size_bytes,
                    input_media_type: &request.input.media_type,
                    authority: authority.as_str(),
                    deadline_ms: request.deadline_ms,
                },
            );
            if !matches!(request.idempotency_key.algorithm, HashAlgorithm::Sha256)
                || request.idempotency_key.hex != expected_decision
            {
                return rejected(
                    &request,
                    "capability-decision-digest-mismatch",
                    "idempotency key must bind the exact capability decision material",
                );
            }
            let route = admit(operation, family, authority, request.approval.is_some());
            if let Err(code) = route {
                return rejected(&request, code, code);
            }
            if let Err(error) = verify_and_record_approval(&request) {
                return match error {
                    ApprovalCheckError::Rejected(failure) => rejected_failure(&request, failure),
                    ApprovalCheckError::Failed(failure) => failed(&request, failure),
                };
            }

            let expected_digest = request.service_component.clone();
            let request_id = request.request_id.clone();
            let mut response = match request.family {
                ServiceFamily::Build => wasm_biotic::factory::build_service::invoke(&request),
                ServiceFamily::Packaging => {
                    wasm_biotic::factory::packaging_service::invoke(&request)
                }
                ServiceFamily::Validation => {
                    wasm_biotic::factory::validation_service::invoke(&request)
                }
                ServiceFamily::Review => wasm_biotic::factory::review_service::invoke(&request),
                ServiceFamily::Continuity => {
                    wasm_biotic::factory::continuity_service::invoke(&request)
                }
                ServiceFamily::Scheduling => {
                    wasm_biotic::factory::scheduling_service::invoke(&request)
                }
                ServiceFamily::Operations => {
                    wasm_biotic::factory::operations_service::invoke(&request)
                }
            };
            if response.request_id != request_id
                || response.service_component.algorithm != expected_digest.algorithm
                || response.service_component.hex != expected_digest.hex
            {
                response = CapabilityResponse {
                    request_id,
                    service_component: expected_digest,
                    outcome: ServiceOutcome::Rejected(Failure {
                        code: "service-identity-mismatch".into(),
                        message:
                            "bound service returned a response for a different request or digest"
                                .into(),
                        retryable: false,
                        evidence: None,
                    }),
                    effect_receipts: alloc::vec::Vec::new(),
                    evidence: alloc::vec::Vec::new(),
                };
            }
            response
        }
    }

    enum ApprovalCheckError {
        Rejected(Failure),
        Failed(Failure),
    }

    fn verify_and_record_approval(request: &CapabilityRequest) -> Result<(), ApprovalCheckError> {
        let Some(approval) = &request.approval else {
            return Ok(());
        };
        if approval.approval_id.trim().is_empty()
            || approval.approver.trim().is_empty()
            || approval.recorded_at_ms == 0
            || approval.signature.is_empty()
            || approval.decision_digest.algorithm != request.idempotency_key.algorithm
            || approval.decision_digest.hex != request.idempotency_key.hex
        {
            return Err(ApprovalCheckError::Rejected(failure(
                "invalid-approval-binding",
                "approval identity, signer, time, signature and exact decision digest are required",
            )));
        }
        let signature = Signature {
            key_id: approval.approver.clone(),
            algorithm: SignatureAlgorithm::Ed25519,
            bytes: approval.signature.clone(),
        };
        let verified = wasm_biotic::factory::key_service::verify_digest(
            &approval.approver,
            &approval.decision_digest,
            &signature,
        )
        .map_err(ApprovalCheckError::Failed)?;
        if !verified {
            return Err(ApprovalCheckError::Rejected(failure(
                "invalid-approval-signature",
                "approval signature does not verify for the declared signer and decision",
            )));
        }

        let binding = approval_binding_bytes(
            &approval.approval_id,
            &approval.decision_digest.hex,
            &approval.approver,
            approval.recorded_at_ms,
            &approval.signature,
        );
        if let Some(existing) =
            wasm_biotic::factory::transaction_store::read(APPROVAL_NAMESPACE, &approval.approval_id)
                .map_err(ApprovalCheckError::Failed)?
        {
            let bytes = wasm_biotic::factory::blob_store::get(&existing.value)
                .map_err(ApprovalCheckError::Failed)?;
            return if bytes == binding {
                Ok(())
            } else {
                Err(ApprovalCheckError::Rejected(failure(
                    "approval-reused",
                    "approval id is already bound to different decision material",
                )))
            };
        }

        let reference = wasm_biotic::factory::blob_store::put(APPROVAL_USE_MEDIA_TYPE, &binding)
            .map_err(ApprovalCheckError::Failed)?;
        let expected_hex = wasm_biotic_service_policy_core::hex_sha256(&binding);
        if reference.media_type != APPROVAL_USE_MEDIA_TYPE
            || reference.size_bytes != u64::try_from(binding.len()).unwrap_or(u64::MAX)
            || !matches!(reference.content_digest.algorithm, HashAlgorithm::Sha256)
            || reference.content_digest.hex != expected_hex
        {
            return Err(ApprovalCheckError::Failed(failure(
                "untruthful-blob-store-receipt",
                "approval binding blob receipt does not identify the exact bytes",
            )));
        }
        let transaction_id = alloc::format!("approval-use:{expected_hex}");
        let commit = CommitRequest {
            transaction_id: transaction_id.clone(),
            assertions: alloc::vec![Assertion {
                namespace: APPROVAL_NAMESPACE.to_string(),
                key: approval.approval_id.clone(),
                expected_version: None,
            }],
            mutations: alloc::vec![Mutation::Put((
                APPROVAL_NAMESPACE.to_string(),
                approval.approval_id.clone(),
                reference,
            ))],
            idempotency_key: Digest {
                algorithm: HashAlgorithm::Sha256,
                hex: expected_hex,
            },
        };
        let receipt = wasm_biotic::factory::transaction_store::commit(&commit)
            .map_err(ApprovalCheckError::Failed)?;
        if receipt.transaction_id != transaction_id {
            return Err(ApprovalCheckError::Failed(failure(
                "transaction-receipt-identity-violation",
                "approval binding commit returned a receipt for another transaction",
            )));
        }
        Ok(())
    }

    fn rejected(request: &CapabilityRequest, code: &str, message: &str) -> CapabilityResponse {
        rejected_failure(request, failure(code, message))
    }

    fn rejected_failure(request: &CapabilityRequest, failure: Failure) -> CapabilityResponse {
        CapabilityResponse {
            request_id: request.request_id.clone(),
            service_component: request.service_component.clone(),
            outcome: ServiceOutcome::Rejected(failure),
            effect_receipts: alloc::vec::Vec::new(),
            evidence: alloc::vec::Vec::new(),
        }
    }

    fn failed(request: &CapabilityRequest, failure: Failure) -> CapabilityResponse {
        CapabilityResponse {
            request_id: request.request_id.clone(),
            service_component: request.service_component.clone(),
            outcome: ServiceOutcome::Failed(failure),
            effect_receipts: alloc::vec::Vec::new(),
            evidence: alloc::vec::Vec::new(),
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

    fn family_from_wit(family: ServiceFamily) -> Family {
        match family {
            ServiceFamily::Build => Family::Build,
            ServiceFamily::Packaging => Family::Packaging,
            ServiceFamily::Validation => Family::Validation,
            ServiceFamily::Review => Family::Review,
            ServiceFamily::Continuity => Family::Continuity,
            ServiceFamily::Scheduling => Family::Scheduling,
            ServiceFamily::Operations => Family::Operations,
        }
    }

    fn authority_from_wit(authority: AuthorityClass) -> Authority {
        match authority {
            AuthorityClass::Observe => Authority::Observe,
            AuthorityClass::LocalMutate => Authority::LocalMutate,
            AuthorityClass::AutomationControl => Authority::AutomationControl,
            AuthorityClass::PromotionControl => Authority::PromotionControl,
        }
    }

    fn operation_from_wit(operation: WitOperation) -> Operation {
        match operation {
            WitOperation::WorkspaceOpen => Operation::WorkspaceOpen,
            WitOperation::WorkspaceSnapshot => Operation::WorkspaceSnapshot,
            WitOperation::WorkspacePatch => Operation::WorkspacePatch,
            WitOperation::CandidateBuild => Operation::CandidateBuild,
            WitOperation::CommandExecute => Operation::CommandExecute,
            WitOperation::PackagePublish => Operation::PackagePublish,
            WitOperation::PackageVerify => Operation::PackageVerify,
            WitOperation::ValidationProve => Operation::ValidationProve,
            WitOperation::ValidationCompare => Operation::ValidationCompare,
            WitOperation::ReviewCandidate => Operation::ReviewCandidate,
            WitOperation::EvidencePublish => Operation::EvidencePublish,
            WitOperation::EvidenceResolve => Operation::EvidenceResolve,
            WitOperation::ScheduleJob => Operation::ScheduleJob,
            WitOperation::DeploymentInitialize => Operation::DeploymentInitialize,
            WitOperation::DeploymentActivate => Operation::DeploymentActivate,
            WitOperation::DeploymentObserve => Operation::DeploymentObserve,
            WitOperation::DeploymentRollback => Operation::DeploymentRollback,
            WitOperation::OperationsInspect => Operation::OperationsInspect,
            WitOperation::FactoryExecute => Operation::FactoryExecute,
            WitOperation::FactoryProviderProposal => Operation::FactoryProviderProposal,
            WitOperation::FactoryShadow => Operation::FactoryShadow,
            WitOperation::FactoryInitialize => Operation::FactoryInitialize,
            WitOperation::FactoryStateMigrate => Operation::FactoryStateMigrate,
            WitOperation::FactoryActivate => Operation::FactoryActivate,
            WitOperation::FactoryObserve => Operation::FactoryObserve,
            WitOperation::FactoryRollback => Operation::FactoryRollback,
            WitOperation::FactoryInspect => Operation::FactoryInspect,
        }
    }

    export!(CapabilityRouterComponent);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_27_operations_have_a_policy() {
        let operations = [
            Operation::WorkspaceOpen,
            Operation::WorkspaceSnapshot,
            Operation::WorkspacePatch,
            Operation::CandidateBuild,
            Operation::CommandExecute,
            Operation::PackagePublish,
            Operation::PackageVerify,
            Operation::ValidationProve,
            Operation::ValidationCompare,
            Operation::ReviewCandidate,
            Operation::EvidencePublish,
            Operation::EvidenceResolve,
            Operation::ScheduleJob,
            Operation::DeploymentInitialize,
            Operation::DeploymentActivate,
            Operation::DeploymentObserve,
            Operation::DeploymentRollback,
            Operation::OperationsInspect,
            Operation::FactoryExecute,
            Operation::FactoryProviderProposal,
            Operation::FactoryShadow,
            Operation::FactoryInitialize,
            Operation::FactoryStateMigrate,
            Operation::FactoryActivate,
            Operation::FactoryObserve,
            Operation::FactoryRollback,
            Operation::FactoryInspect,
        ];
        assert_eq!(operations.len(), 27);
        assert!(operations.into_iter().all(|operation| {
            let route = policy(operation);
            admit(
                operation,
                route.family,
                route.minimum_authority,
                route.approval_required,
            )
            .is_ok()
        }));
    }

    #[test]
    fn mismatched_family_and_weak_authority_fail_closed() {
        assert_eq!(
            admit(
                Operation::CandidateBuild,
                Family::Review,
                Authority::PromotionControl,
                false
            ),
            Err("operation-family-mismatch")
        );
        assert_eq!(
            admit(
                Operation::CandidateBuild,
                Family::Build,
                Authority::Observe,
                false
            ),
            Err("insufficient-authority")
        );
    }

    #[test]
    fn promotion_and_migration_policy_require_approval() {
        assert_eq!(
            admit(
                Operation::FactoryActivate,
                Family::Operations,
                Authority::PromotionControl,
                false
            ),
            Err("approval-required")
        );
        assert_eq!(
            admit(
                Operation::FactoryStateMigrate,
                Family::Operations,
                Authority::PromotionControl,
                false
            ),
            Err("approval-required")
        );
    }

    #[test]
    fn approval_use_binding_is_deterministic_and_replay_sensitive() {
        let first = approval_binding_bytes("approval-1", &"a".repeat(64), "key-1", 10, b"sig");
        assert_eq!(
            first,
            approval_binding_bytes("approval-1", &"a".repeat(64), "key-1", 10, b"sig")
        );
        assert_ne!(
            first,
            approval_binding_bytes("approval-1", &"b".repeat(64), "key-1", 10, b"sig")
        );
        assert!(first.starts_with(APPROVAL_USE_MAGIC));
    }
}
