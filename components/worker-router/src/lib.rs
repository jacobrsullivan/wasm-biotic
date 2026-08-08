#![cfg_attr(all(target_arch = "wasm32", not(test)), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

//! Component-owned exact-digest worker dispatch.

extern crate alloc;

/// Fixed uniform worker execution policy for bounded v1.
pub const WORKER_FUEL: u64 = 20_000_000;
pub const WORKER_MEMORY_BYTES: u64 = 32 * 1024 * 1024;
pub const WORKER_OUTPUT_BYTES: u64 = 4 * 1024 * 1024;
pub const WORKER_WALL_TIME_MS: u64 = 30_000;

/// Returns the primitive grants a composed worker requires. This is domain
/// selection policy and intentionally lives in this component crate.
#[must_use]
pub fn primitive_grants(role: wasm_biotic_worker_policy::Role) -> &'static [&'static str] {
    use wasm_biotic_worker_policy::Role;
    match role {
        Role::Planner => &["blob-store", "clock", "transaction-store"],
        Role::Builder
        | Role::Validator
        | Role::Reviewer
        | Role::Packager
        | Role::ContinuityWorker => &["blob-store"],
    }
}

/// Exact generic scope carried for a primitive grant. The native substrate
/// treats transaction namespaces as opaque bytes and does not know why this
/// component selected them.
#[must_use]
pub fn primitive_scope(interface: &str) -> &'static str {
    match interface {
        "blob-store" => "read-write",
        "transaction-store" => "wasm-biotic.schedule.v1",
        "clock" => "wake",
        _ => "invalid",
    }
}

#[cfg(all(target_arch = "wasm32", not(test)))]
#[global_allocator]
static ALLOCATOR: dlmalloc::GlobalDlmalloc = dlmalloc::GlobalDlmalloc;

#[cfg(all(target_arch = "wasm32", not(test)))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}

#[cfg(all(target_arch = "wasm32", not(test)))]
#[unsafe(no_mangle)]
unsafe extern "C" fn cabi_realloc(
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
        let pointer = unsafe { alloc(layout) };
        if pointer.is_null() {
            handle_alloc_error(layout);
        }
        pointer
    } else {
        let old_layout = Layout::from_size_align(old_length.max(1), alignment)
            .unwrap_or_else(|_| core::arch::wasm32::unreachable());
        if new_length == 0 {
            unsafe { dealloc(old_pointer, old_layout) };
            core::ptr::null_mut()
        } else {
            let pointer = unsafe { realloc(old_pointer, old_layout, new_length) };
            if pointer.is_null() {
                let layout = Layout::from_size_align(new_length, alignment)
                    .unwrap_or_else(|_| core::arch::wasm32::unreachable());
                handle_alloc_error(layout);
            }
            pointer
        }
    }
}

#[cfg(all(target_arch = "wasm32", not(test)))]
#[unsafe(no_mangle)]
unsafe extern "C" fn memcmp(left: *const u8, right: *const u8, length: usize) -> i32 {
    for offset in 0..length {
        let left_byte = unsafe { *left.add(offset) };
        let right_byte = unsafe { *right.add(offset) };
        if left_byte != right_byte {
            return i32::from(left_byte) - i32::from(right_byte);
        }
    }
    0
}

#[cfg(target_arch = "wasm32")]
mod component {
    use super::*;
    use alloc::{string::ToString, vec::Vec};
    use wasm_biotic_worker_policy as policy;

    wit_bindgen::generate!({ path: "../../wit/wasm-biotic", world: "worker-router-component" });

    use exports::wasm_biotic::factory::worker_router::Guest;
    use wasm_biotic::factory::capability_contract::{ServiceBinding, ServiceFamily};
    use wasm_biotic::factory::component_runner::{RunCompletion, RunRequest};
    use wasm_biotic::factory::foundation::{
        BlobRef, CapabilityGrant, Digest, EffectReceipt, Failure, HashAlgorithm, ResourceLimits,
        TerminalOutcome,
    };
    use wasm_biotic::factory::worker_workflow::{
        WorkerOutcome, WorkerRequest, WorkerResponse, WorkerRole,
    };

    struct WorkerRouterComponent;

    impl Guest for WorkerRouterComponent {
        fn dispatch(request: WorkerRequest) -> WorkerResponse {
            let expected_digest = request.worker.component_digest.clone();
            let expected_execution = request.execution_id.clone();
            let request_value = request_to_policy(&request);
            let role = request_value.role;
            let task_bytes = match policy::encode_task_request(request_value) {
                Ok(bytes) => bytes,
                Err(error) => return failed_response(&request, error),
            };
            let task_ref =
                match wasm_biotic::factory::blob_store::put(policy::JSON_MEDIA_TYPE, &task_bytes) {
                    Ok(reference) => reference,
                    Err(error) => return host_failed_response(&request, error),
                };
            let grants = primitive_grants(role)
                .iter()
                .map(|name| CapabilityGrant {
                    capability: (*name).to_string(),
                    scope: primitive_scope(name).to_string(),
                    constraints: None,
                })
                .collect();
            let run = RunRequest {
                run_id: expected_execution.clone(),
                component_digest: expected_digest.clone(),
                input: task_ref,
                grants,
                limits: ResourceLimits {
                    fuel: WORKER_FUEL,
                    memory_bytes: WORKER_MEMORY_BYTES,
                    output_bytes: WORKER_OUTPUT_BYTES,
                    wall_time_ms: WORKER_WALL_TIME_MS,
                },
                idempotency_key: request.lease_digest.clone(),
            };
            let operation_id = match wasm_biotic::factory::component_runner::start(&run) {
                Ok(id) => id,
                Err(error) => return host_failed_response(&request, error),
            };
            let completion = match wasm_biotic::factory::component_runner::poll(&operation_id) {
                Ok(Some(completion)) => completion,
                Ok(None) => {
                    return synthetic_failure(
                        &request,
                        "worker-pending",
                        "bounded v1 worker must complete on its first poll",
                        true,
                    );
                }
                Err(error) => return host_failed_response(&request, error),
            };
            decode_completion(&request, completion, &expected_execution, &expected_digest)
        }
    }

    fn decode_completion(
        request: &WorkerRequest,
        completion: RunCompletion,
        expected_execution: &str,
        expected_digest: &Digest,
    ) -> WorkerResponse {
        if completion.run_id != expected_execution {
            return synthetic_failure(
                request,
                "worker-run-mismatch",
                "runner returned a different run id",
                false,
            );
        }
        let response_ref = match completion.outcome {
            TerminalOutcome::Succeeded(reference) => reference,
            TerminalOutcome::Rejected(error) => {
                return rejected_with_receipt(request, error, completion.receipt);
            }
            TerminalOutcome::Failed(error) | TerminalOutcome::Exhausted(error) => {
                return failed_with_receipt(request, error, completion.receipt);
            }
            TerminalOutcome::Cancelled => {
                return cancelled_with_receipt(request, completion.receipt);
            }
        };
        let bytes = match wasm_biotic::factory::blob_store::get(&response_ref) {
            Ok(bytes) => bytes,
            Err(error) => return host_failed_response(request, error),
        };
        let value = match policy::decode_task_response(&bytes) {
            Ok(value) => value,
            Err(error) => return failed_response(request, error),
        };
        if value.execution_id != expected_execution
            || value.worker_component.algorithm != "sha256"
            || value.worker_component.hex != expected_digest.hex
        {
            return synthetic_failure(
                request,
                "worker-identity-mismatch",
                "worker response does not match graph-bound execution identity",
                false,
            );
        }
        response_from_policy(value)
    }

    fn request_to_policy(request: &WorkerRequest) -> policy::WorkerRequestValue {
        policy::WorkerRequestValue {
            execution_id: request.execution_id.clone(),
            job_id: request.job_id.clone(),
            role: role_to_policy(request.role),
            worker: policy::PrincipalValue {
                id: request.worker.id.clone(),
                component_digest: digest_to_policy(&request.worker.component_digest),
            },
            service_bindings: request
                .service_bindings
                .iter()
                .map(binding_to_policy)
                .collect(),
            input: blob_to_policy(&request.input),
            checkpoint: request.checkpoint.as_ref().map(blob_to_policy),
            lease_digest: digest_to_policy(&request.lease_digest),
            attempt: request.attempt,
            deadline_ms: request.deadline_ms,
        }
    }

    fn response_from_policy(value: policy::WorkerResponseValue) -> WorkerResponse {
        WorkerResponse {
            execution_id: value.execution_id,
            worker_component: digest_from_policy(value.worker_component),
            outcome: match value.outcome {
                policy::WorkerOutcomeValue::Completed(blob) => {
                    WorkerOutcome::Completed(blob_from_policy(blob))
                }
                policy::WorkerOutcomeValue::Blocked(blob) => {
                    WorkerOutcome::Blocked(blob_from_policy(blob))
                }
                policy::WorkerOutcomeValue::Rejected(error) => {
                    WorkerOutcome::Rejected(failure_from_policy(error))
                }
                policy::WorkerOutcomeValue::Failed(error) => {
                    WorkerOutcome::Failed(failure_from_policy(error))
                }
                policy::WorkerOutcomeValue::Cancelled => WorkerOutcome::Cancelled,
            },
            checkpoint: value.checkpoint.map(blob_from_policy),
            receipts: value
                .receipts
                .into_iter()
                .map(receipt_from_policy)
                .collect(),
            evidence: value.evidence.into_iter().map(blob_from_policy).collect(),
        }
    }

    fn role_to_policy(role: WorkerRole) -> policy::Role {
        match role {
            WorkerRole::Planner => policy::Role::Planner,
            WorkerRole::Builder => policy::Role::Builder,
            WorkerRole::Validator => policy::Role::Validator,
            WorkerRole::Reviewer => policy::Role::Reviewer,
            WorkerRole::Packager => policy::Role::Packager,
            WorkerRole::ContinuityWorker => policy::Role::ContinuityWorker,
        }
    }

    fn binding_to_policy(binding: &ServiceBinding) -> policy::ServiceBindingValue {
        policy::ServiceBindingValue {
            family: match binding.family {
                ServiceFamily::Build => policy::ServiceFamily::Build,
                ServiceFamily::Packaging => policy::ServiceFamily::Packaging,
                ServiceFamily::Validation => policy::ServiceFamily::Validation,
                ServiceFamily::Review => policy::ServiceFamily::Review,
                ServiceFamily::Continuity => policy::ServiceFamily::Continuity,
                ServiceFamily::Scheduling => policy::ServiceFamily::Scheduling,
                ServiceFamily::Operations => policy::ServiceFamily::Operations,
            },
            component_digest: digest_to_policy(&binding.component_digest),
        }
    }

    fn digest_to_policy(value: &Digest) -> policy::DigestValue {
        policy::DigestValue {
            algorithm: match value.algorithm {
                HashAlgorithm::Sha256 => "sha256",
            }
            .to_string(),
            hex: value.hex.clone(),
        }
    }
    fn digest_from_policy(value: policy::DigestValue) -> Digest {
        Digest {
            algorithm: HashAlgorithm::Sha256,
            hex: value.hex,
        }
    }
    fn blob_to_policy(value: &BlobRef) -> policy::BlobPointer {
        policy::BlobPointer {
            content_digest: digest_to_policy(&value.content_digest),
            size_bytes: value.size_bytes,
            media_type: value.media_type.clone(),
        }
    }
    fn blob_from_policy(value: policy::BlobPointer) -> BlobRef {
        BlobRef {
            content_digest: digest_from_policy(value.content_digest),
            size_bytes: value.size_bytes,
            media_type: value.media_type,
        }
    }
    fn failure_from_policy(value: policy::FailureValue) -> Failure {
        Failure {
            code: value.code,
            message: value.message,
            retryable: value.retryable,
            evidence: value.evidence.map(blob_from_policy),
        }
    }
    fn receipt_from_policy(value: policy::EffectReceiptValue) -> EffectReceipt {
        EffectReceipt {
            receipt_id: value.receipt_id,
            request_digest: digest_from_policy(value.request_digest),
            executor_digest: digest_from_policy(value.executor_digest),
            started_at_ms: value.started_at_ms,
            finished_at_ms: value.finished_at_ms,
            outcome_digest: digest_from_policy(value.outcome_digest),
            audit_sequence: value.audit_sequence,
        }
    }

    fn failed_response(request: &WorkerRequest, error: policy::FailureValue) -> WorkerResponse {
        WorkerResponse {
            execution_id: request.execution_id.clone(),
            worker_component: request.worker.component_digest.clone(),
            outcome: WorkerOutcome::Failed(failure_from_policy(error)),
            checkpoint: request.checkpoint.clone(),
            receipts: Vec::new(),
            evidence: Vec::new(),
        }
    }
    fn host_failed_response(request: &WorkerRequest, error: Failure) -> WorkerResponse {
        WorkerResponse {
            execution_id: request.execution_id.clone(),
            worker_component: request.worker.component_digest.clone(),
            outcome: WorkerOutcome::Failed(error),
            checkpoint: request.checkpoint.clone(),
            receipts: Vec::new(),
            evidence: Vec::new(),
        }
    }
    fn synthetic_failure(
        request: &WorkerRequest,
        code: &str,
        message: &str,
        retryable: bool,
    ) -> WorkerResponse {
        host_failed_response(
            request,
            Failure {
                code: code.to_string(),
                message: message.to_string(),
                retryable,
                evidence: None,
            },
        )
    }
    fn rejected_with_receipt(
        request: &WorkerRequest,
        error: Failure,
        receipt: EffectReceipt,
    ) -> WorkerResponse {
        WorkerResponse {
            execution_id: request.execution_id.clone(),
            worker_component: request.worker.component_digest.clone(),
            outcome: WorkerOutcome::Rejected(error),
            checkpoint: request.checkpoint.clone(),
            receipts: alloc::vec![receipt],
            evidence: Vec::new(),
        }
    }
    fn failed_with_receipt(
        request: &WorkerRequest,
        error: Failure,
        receipt: EffectReceipt,
    ) -> WorkerResponse {
        WorkerResponse {
            execution_id: request.execution_id.clone(),
            worker_component: request.worker.component_digest.clone(),
            outcome: WorkerOutcome::Failed(error),
            checkpoint: request.checkpoint.clone(),
            receipts: alloc::vec![receipt],
            evidence: Vec::new(),
        }
    }
    fn cancelled_with_receipt(request: &WorkerRequest, receipt: EffectReceipt) -> WorkerResponse {
        WorkerResponse {
            execution_id: request.execution_id.clone(),
            worker_component: request.worker.component_digest.clone(),
            outcome: WorkerOutcome::Cancelled,
            checkpoint: request.checkpoint.clone(),
            receipts: alloc::vec![receipt],
            evidence: Vec::new(),
        }
    }

    export!(WorkerRouterComponent);
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_biotic_worker_policy::Role;

    #[test]
    fn grants_are_component_policy_and_least_authority_per_role() {
        assert_eq!(
            primitive_grants(Role::Planner),
            &["blob-store", "clock", "transaction-store"]
        );
        for role in [
            Role::Builder,
            Role::Validator,
            Role::Reviewer,
            Role::Packager,
            Role::ContinuityWorker,
        ] {
            assert_eq!(primitive_grants(role), &["blob-store"]);
        }
        assert_eq!(primitive_scope("blob-store"), "read-write");
        assert_eq!(
            primitive_scope("transaction-store"),
            "wasm-biotic.schedule.v1"
        );
        assert_eq!(primitive_scope("clock"), "wake");
    }

    #[test]
    fn worker_limits_are_finite_and_nonzero() {
        const {
            assert!(
                WORKER_FUEL > 0
                    && WORKER_MEMORY_BYTES > 0
                    && WORKER_OUTPUT_BYTES > 0
                    && WORKER_WALL_TIME_MS > 0
            );
            assert!(WORKER_MEMORY_BYTES <= 64 * 1024 * 1024);
        }
    }
}
