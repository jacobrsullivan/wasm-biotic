#![cfg_attr(target_arch = "wasm32", no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

//! Shared typed guest adapter. Cargo features select exactly one WIT world and
//! role, so each resulting component contains only its declared service calls.

#[cfg(target_arch = "wasm32")]
mod wasm_component {
    extern crate alloc;

    use alloc::{format, string::ToString, vec::Vec};
    use wasm_biotic_worker_guest::policy::{
        self, Authority, BlobPointer, CapabilityRequestValue, CapabilityResponseValue, DigestValue,
        EffectReceiptValue, FailureValue, Operation, PrincipalValue, Role, ServiceBindingValue,
        ServiceFamily, ServiceOutcomeValue, WorkerOutcomeValue, WorkerRequestValue,
        WorkerResponseValue,
    };

    #[cfg(feature = "planner")]
    wit_bindgen::generate!({
        path: "../../../wit/wasm-biotic",
        world: "planner-worker-component",
    });
    #[cfg(feature = "builder")]
    wit_bindgen::generate!({
        path: "../../../wit/wasm-biotic",
        world: "builder-worker-component",
    });
    #[cfg(feature = "validator")]
    wit_bindgen::generate!({
        path: "../../../wit/wasm-biotic",
        world: "validator-worker-component",
    });
    #[cfg(feature = "reviewer")]
    wit_bindgen::generate!({
        path: "../../../wit/wasm-biotic",
        world: "reviewer-worker-component",
    });
    #[cfg(feature = "packager")]
    wit_bindgen::generate!({
        path: "../../../wit/wasm-biotic",
        world: "packager-worker-component",
    });
    #[cfg(feature = "continuity")]
    wit_bindgen::generate!({
        path: "../../../wit/wasm-biotic",
        world: "continuity-worker-component",
    });

    use exports::wasm_biotic::factory::component_task::Guest as ComponentTaskGuest;
    use exports::wasm_biotic::factory::worker_workflow::{
        Guest as WorkerWorkflowGuest, WorkerOutcome, WorkerRequest, WorkerResponse, WorkerRole,
    };
    use wasm_biotic::factory::capability_contract::{
        CapabilityRequest, CapabilityResponse, Operation as WitOperation, ServiceBinding,
        ServiceFamily as WitServiceFamily, ServiceOutcome,
    };
    use wasm_biotic::factory::foundation::{
        AuthorityClass, BlobRef, Digest, EffectReceipt, Failure, HashAlgorithm, Principal,
    };

    wasm_biotic_worker_guest::install_component_abi!();

    struct WorkerComponent;

    impl WorkerWorkflowGuest for WorkerComponent {
        fn execute(request: WorkerRequest) -> WorkerResponse {
            worker_response_to_wit(run_policy(worker_request_from_wit(request)))
        }
    }

    impl ComponentTaskGuest for WorkerComponent {
        fn run(input: BlobRef) -> Result<BlobRef, Failure> {
            let bytes = wasm_biotic::factory::blob_store::get(&input)?;
            let request = policy::decode_task_request(&bytes).map_err(failure_to_wit)?;
            let response = run_policy(request);
            let encoded = policy::encode_task_response(response).map_err(failure_to_wit)?;
            wasm_biotic::factory::blob_store::put(policy::JSON_MEDIA_TYPE, &encoded)
        }
    }

    fn run_policy(request: WorkerRequestValue) -> WorkerResponseValue {
        policy::execute_worker(expected_role(), request, |family, request| {
            let response = invoke_declared_service(family, capability_request_to_wit(request));
            capability_response_from_wit(response)
        })
    }

    const fn expected_role() -> Role {
        #[cfg(feature = "planner")]
        return Role::Planner;
        #[cfg(feature = "builder")]
        return Role::Builder;
        #[cfg(feature = "validator")]
        return Role::Validator;
        #[cfg(feature = "reviewer")]
        return Role::Reviewer;
        #[cfg(feature = "packager")]
        return Role::Packager;
        #[cfg(feature = "continuity")]
        return Role::ContinuityWorker;
        #[allow(unreachable_code)]
        Role::Planner
    }

    fn invoke_declared_service(
        family: ServiceFamily,
        request: CapabilityRequest,
    ) -> CapabilityResponse {
        #[cfg(feature = "planner")]
        match family {
            ServiceFamily::Build => {
                return wasm_biotic::factory::build_service::invoke(&request);
            }
            ServiceFamily::Scheduling => {
                return wasm_biotic::factory::scheduling_service::invoke(&request);
            }
            _ => {}
        }
        #[cfg(feature = "builder")]
        if family == ServiceFamily::Build {
            return wasm_biotic::factory::build_service::invoke(&request);
        }
        #[cfg(feature = "validator")]
        if family == ServiceFamily::Validation {
            return wasm_biotic::factory::validation_service::invoke(&request);
        }
        #[cfg(feature = "reviewer")]
        if family == ServiceFamily::Review {
            return wasm_biotic::factory::review_service::invoke(&request);
        }
        #[cfg(feature = "packager")]
        if family == ServiceFamily::Packaging {
            return wasm_biotic::factory::packaging_service::invoke(&request);
        }
        #[cfg(feature = "continuity")]
        if family == ServiceFamily::Continuity {
            return wasm_biotic::factory::continuity_service::invoke(&request);
        }
        undeclared_service_response(request, family)
    }

    fn undeclared_service_response(
        request: CapabilityRequest,
        family: ServiceFamily,
    ) -> CapabilityResponse {
        CapabilityResponse {
            request_id: request.request_id,
            service_component: request.service_component,
            outcome: ServiceOutcome::Failed(Failure {
                code: "undeclared-service-family".to_string(),
                message: format!(
                    "{} component has no {:?} service import",
                    expected_role().as_str(),
                    family
                ),
                retryable: false,
                evidence: None,
            }),
            effect_receipts: Vec::new(),
            evidence: Vec::new(),
        }
    }

    fn worker_request_from_wit(request: WorkerRequest) -> WorkerRequestValue {
        WorkerRequestValue {
            execution_id: request.execution_id,
            job_id: request.job_id,
            role: role_from_wit(request.role),
            worker: principal_from_wit(request.worker),
            service_bindings: request
                .service_bindings
                .into_iter()
                .map(service_binding_from_wit)
                .collect(),
            input: blob_from_wit(request.input),
            checkpoint: request.checkpoint.map(blob_from_wit),
            lease_digest: digest_from_wit(request.lease_digest),
            attempt: request.attempt,
            deadline_ms: request.deadline_ms,
        }
    }

    fn worker_response_to_wit(response: WorkerResponseValue) -> WorkerResponse {
        WorkerResponse {
            execution_id: response.execution_id,
            worker_component: digest_to_wit(response.worker_component),
            outcome: match response.outcome {
                WorkerOutcomeValue::Completed(output) => {
                    WorkerOutcome::Completed(blob_to_wit(output))
                }
                WorkerOutcomeValue::Blocked(request) => {
                    WorkerOutcome::Blocked(blob_to_wit(request))
                }
                WorkerOutcomeValue::Rejected(failure) => {
                    WorkerOutcome::Rejected(failure_to_wit(failure))
                }
                WorkerOutcomeValue::Failed(failure) => {
                    WorkerOutcome::Failed(failure_to_wit(failure))
                }
                WorkerOutcomeValue::Cancelled => WorkerOutcome::Cancelled,
            },
            checkpoint: response.checkpoint.map(blob_to_wit),
            receipts: response
                .receipts
                .into_iter()
                .map(effect_receipt_to_wit)
                .collect(),
            evidence: response.evidence.into_iter().map(blob_to_wit).collect(),
        }
    }

    fn capability_request_to_wit(request: CapabilityRequestValue) -> CapabilityRequest {
        CapabilityRequest {
            request_id: request.request_id,
            job_id: request.job_id,
            caller: principal_to_wit(request.caller),
            service_component: digest_to_wit(request.service_component),
            family: service_family_to_wit(request.family),
            operation: operation_to_wit(request.operation),
            input: blob_to_wit(request.input),
            authority: authority_to_wit(request.authority),
            approval: None,
            deadline_ms: request.deadline_ms,
            idempotency_key: digest_to_wit(request.idempotency_key),
        }
    }

    fn capability_response_from_wit(response: CapabilityResponse) -> CapabilityResponseValue {
        CapabilityResponseValue {
            request_id: response.request_id,
            service_component: digest_from_wit(response.service_component),
            outcome: match response.outcome {
                ServiceOutcome::Succeeded(output) => {
                    ServiceOutcomeValue::Succeeded(blob_from_wit(output))
                }
                ServiceOutcome::Rejected(failure) => {
                    ServiceOutcomeValue::Rejected(failure_from_wit(failure))
                }
                ServiceOutcome::Failed(failure) => {
                    ServiceOutcomeValue::Failed(failure_from_wit(failure))
                }
                ServiceOutcome::Cancelled => ServiceOutcomeValue::Cancelled,
                ServiceOutcome::Exhausted(failure) => {
                    ServiceOutcomeValue::Exhausted(failure_from_wit(failure))
                }
            },
            effect_receipts: response
                .effect_receipts
                .into_iter()
                .map(effect_receipt_from_wit)
                .collect(),
            evidence: response.evidence.into_iter().map(blob_from_wit).collect(),
        }
    }

    fn role_from_wit(role: WorkerRole) -> Role {
        match role {
            WorkerRole::Planner => Role::Planner,
            WorkerRole::Builder => Role::Builder,
            WorkerRole::Validator => Role::Validator,
            WorkerRole::Reviewer => Role::Reviewer,
            WorkerRole::Packager => Role::Packager,
            WorkerRole::ContinuityWorker => Role::ContinuityWorker,
        }
    }

    fn service_binding_from_wit(binding: ServiceBinding) -> ServiceBindingValue {
        ServiceBindingValue {
            family: service_family_from_wit(binding.family),
            component_digest: digest_from_wit(binding.component_digest),
        }
    }

    fn service_family_from_wit(family: WitServiceFamily) -> ServiceFamily {
        match family {
            WitServiceFamily::Build => ServiceFamily::Build,
            WitServiceFamily::Packaging => ServiceFamily::Packaging,
            WitServiceFamily::Validation => ServiceFamily::Validation,
            WitServiceFamily::Review => ServiceFamily::Review,
            WitServiceFamily::Continuity => ServiceFamily::Continuity,
            WitServiceFamily::Scheduling => ServiceFamily::Scheduling,
            WitServiceFamily::Operations => ServiceFamily::Operations,
        }
    }

    fn service_family_to_wit(family: ServiceFamily) -> WitServiceFamily {
        match family {
            ServiceFamily::Build => WitServiceFamily::Build,
            ServiceFamily::Packaging => WitServiceFamily::Packaging,
            ServiceFamily::Validation => WitServiceFamily::Validation,
            ServiceFamily::Review => WitServiceFamily::Review,
            ServiceFamily::Continuity => WitServiceFamily::Continuity,
            ServiceFamily::Scheduling => WitServiceFamily::Scheduling,
            ServiceFamily::Operations => WitServiceFamily::Operations,
        }
    }

    fn operation_to_wit(operation: Operation) -> WitOperation {
        match operation {
            Operation::WorkspaceOpen => WitOperation::WorkspaceOpen,
            Operation::WorkspaceSnapshot => WitOperation::WorkspaceSnapshot,
            Operation::WorkspacePatch => WitOperation::WorkspacePatch,
            Operation::CandidateBuild => WitOperation::CandidateBuild,
            Operation::PackagePublish => WitOperation::PackagePublish,
            Operation::PackageVerify => WitOperation::PackageVerify,
            Operation::ValidationProve => WitOperation::ValidationProve,
            Operation::FactoryProviderProposal => WitOperation::FactoryProviderProposal,
            Operation::ReviewCandidate => WitOperation::ReviewCandidate,
            Operation::EvidencePublish => WitOperation::EvidencePublish,
            Operation::EvidenceResolve => WitOperation::EvidenceResolve,
            Operation::ScheduleJob => WitOperation::ScheduleJob,
        }
    }

    fn authority_to_wit(authority: Authority) -> AuthorityClass {
        match authority {
            Authority::Observe => AuthorityClass::Observe,
            Authority::LocalMutate => AuthorityClass::LocalMutate,
            Authority::AutomationControl => AuthorityClass::AutomationControl,
            Authority::PromotionControl => AuthorityClass::PromotionControl,
        }
    }

    fn principal_from_wit(principal: Principal) -> PrincipalValue {
        PrincipalValue {
            id: principal.id,
            component_digest: digest_from_wit(principal.component_digest),
        }
    }

    fn principal_to_wit(principal: PrincipalValue) -> Principal {
        Principal {
            id: principal.id,
            component_digest: digest_to_wit(principal.component_digest),
        }
    }

    fn digest_from_wit(digest: Digest) -> DigestValue {
        DigestValue {
            algorithm: match digest.algorithm {
                HashAlgorithm::Sha256 => "sha256".to_string(),
            },
            hex: digest.hex,
        }
    }

    fn digest_to_wit(digest: DigestValue) -> Digest {
        Digest {
            algorithm: HashAlgorithm::Sha256,
            hex: digest.hex,
        }
    }

    fn blob_from_wit(reference: BlobRef) -> BlobPointer {
        BlobPointer {
            content_digest: digest_from_wit(reference.content_digest),
            size_bytes: reference.size_bytes,
            media_type: reference.media_type,
        }
    }

    fn blob_to_wit(pointer: BlobPointer) -> BlobRef {
        BlobRef {
            content_digest: digest_to_wit(pointer.content_digest),
            size_bytes: pointer.size_bytes,
            media_type: pointer.media_type,
        }
    }

    fn failure_from_wit(failure: Failure) -> FailureValue {
        FailureValue {
            code: failure.code,
            message: failure.message,
            retryable: failure.retryable,
            evidence: failure.evidence.map(blob_from_wit),
        }
    }

    fn failure_to_wit(failure: FailureValue) -> Failure {
        Failure {
            code: failure.code,
            message: failure.message,
            retryable: failure.retryable,
            evidence: failure.evidence.map(blob_to_wit),
        }
    }

    fn effect_receipt_from_wit(receipt: EffectReceipt) -> EffectReceiptValue {
        EffectReceiptValue {
            receipt_id: receipt.receipt_id,
            request_digest: digest_from_wit(receipt.request_digest),
            executor_digest: digest_from_wit(receipt.executor_digest),
            started_at_ms: receipt.started_at_ms,
            finished_at_ms: receipt.finished_at_ms,
            outcome_digest: digest_from_wit(receipt.outcome_digest),
            audit_sequence: receipt.audit_sequence,
        }
    }

    fn effect_receipt_to_wit(receipt: EffectReceiptValue) -> EffectReceipt {
        EffectReceipt {
            receipt_id: receipt.receipt_id,
            request_digest: digest_to_wit(receipt.request_digest),
            executor_digest: digest_to_wit(receipt.executor_digest),
            started_at_ms: receipt.started_at_ms,
            finished_at_ms: receipt.finished_at_ms,
            outcome_digest: digest_to_wit(receipt.outcome_digest),
            audit_sequence: receipt.audit_sequence,
        }
    }

    export!(WorkerComponent);
}
