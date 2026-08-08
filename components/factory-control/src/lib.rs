#![cfg_attr(all(target_arch = "wasm32", not(test)), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

//! Durable, component-owned root driver for the bounded v1 factory.
//!
//! The host supplies only generic persistence and enforcement primitives. This
//! component owns recovery, outbox ordering, workflow dispatch and API routing.

extern crate alloc;

pub mod policy;

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
        // SAFETY: `layout` is valid and allocation failure traps.
        let pointer = unsafe { alloc(layout) };
        if pointer.is_null() {
            handle_alloc_error(layout);
        }
        pointer
    } else {
        let old_layout = Layout::from_size_align(old_length.max(1), alignment)
            .unwrap_or_else(|_| core::arch::wasm32::unreachable());
        if new_length == 0 {
            // SAFETY: Canonical ABI supplies the original allocation.
            unsafe { dealloc(old_pointer, old_layout) };
            core::ptr::null_mut()
        } else {
            // SAFETY: Canonical ABI supplies the original allocation.
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

#[cfg(target_arch = "wasm32")]
mod component {
    use super::policy::*;
    use alloc::{
        format,
        string::{String, ToString},
        vec,
        vec::Vec,
    };

    wit_bindgen::generate!({
        path: "../../wit/wasm-biotic",
        world: "factory-control-component",
    });

    use exports::wasm_biotic::factory::factory_api::{
        Guest as FactoryApiGuest, IngressRequest, IngressResponse,
    };
    use exports::wasm_biotic::factory::factory_control::Guest as FactoryControlGuest;
    use wasm_biotic::factory::activation::{ActivationRequest, ActivationState, ActivationStatus};
    use wasm_biotic::factory::audit_log::{AuditEntry, AuditReceipt};
    use wasm_biotic::factory::capability_contract::{
        CapabilityRequest, CapabilityResponse, Operation, ServiceFamily, ServiceOutcome,
    };
    use wasm_biotic::factory::foundation::{
        ApprovalProof, AuthorityClass, BlobRef, Digest, Document, EffectReceipt, Failure,
        HashAlgorithm, Principal,
    };
    use wasm_biotic::factory::state_migration::StateMigrationRequest;
    use wasm_biotic::factory::supervisor_reducer::{
        Reduction, ReductionRequest, SupervisorCommand, SupervisorEvent,
    };
    use wasm_biotic::factory::transaction_store::{
        Assertion, CommitRequest, Mutation, VersionedValue,
    };
    use wasm_biotic::factory::worker_workflow::{
        WorkerOutcome, WorkerRequest, WorkerResponse, WorkerRole,
    };

    struct FactoryControlComponent;

    impl FactoryControlGuest for FactoryControlComponent {
        fn submit(event: BlobRef) -> Result<String, Failure> {
            submit_job(event)
        }

        fn inspect(job_id: String) -> Result<BlobRef, Failure> {
            inspect_job(&job_id)
        }

        fn cancel(job_id: String, reason: BlobRef) -> Result<BlobRef, Failure> {
            cancel_job(&job_id, reason)
        }

        fn recover(recovery_request: BlobRef) -> Result<BlobRef, Failure> {
            recover_job(recovery_request)
        }
    }

    impl FactoryApiGuest for FactoryControlComponent {
        fn handle(request: IngressRequest) -> Result<IngressResponse, Failure> {
            handle_api(request)
        }
    }

    fn submit_job(event: BlobRef) -> Result<String, Failure> {
        let submit_bytes = read_verified(&event)?;
        let submit = SubmitEnvelopeV1::decode(&submit_bytes).map_err(policy_failure)?;
        let _ = read_verified(&blob_from_value(submit.source.clone()))?;
        let initial_state_bytes =
            read_verified(&blob_from_value(submit.initial_state.blob.clone()))?;
        let active_manifest =
            wasm_biotic::factory::activation::active_manifest()?.ok_or_else(|| {
                failure(
                    "no-active-factory-graph",
                    "the substrate has not selected a verified active graph manifest",
                )
            })?;
        let active_manifest_bytes = read_verified(&active_manifest)?;
        validate_active_submission(
            &active_manifest_bytes,
            &digest_to_value(&active_manifest.content_digest),
            &initial_state_bytes,
            &submit,
        )
        .map_err(policy_failure)?;
        let job_id = submit.job_id();

        if let Some(existing) = read_record_pointer(&job_id)? {
            let record = decode_record_pointer(&existing.value)?;
            if record.graph_digest != submit.graph_digest || record.source != submit.source {
                return Err(failure(
                    "job-submit-conflict",
                    "content-derived job already exists with different graph or source metadata",
                ));
            }
            drive(&job_id)?;
            return Ok(job_id);
        }

        let mut record = ControlRecordV1::initial(&submit);
        apply_reduction(
            &mut record,
            None,
            SupervisorEvent::JobSubmitted(blob_from_value(submit.source)),
            None,
        )?;
        drive(&job_id)?;
        Ok(job_id)
    }

    fn inspect_job(job_id: &str) -> Result<BlobRef, Failure> {
        validate_job_id(job_id)?;
        let versioned = read_record_pointer(job_id)?.ok_or_else(|| {
            failure(
                "unknown-job",
                format!("no durable record exists for {job_id}"),
            )
        })?;
        let record = decode_record_pointer(&versioned.value)?;
        Ok(record
            .result
            .map(blob_from_value)
            .unwrap_or(versioned.value))
    }

    fn recover_job(recovery_request: BlobRef) -> Result<BlobRef, Failure> {
        let bytes = read_verified(&recovery_request)?;
        let request = RecoveryEnvelopeV1::decode(&bytes).map_err(policy_failure)?;
        drive(&request.job_id)?;
        inspect_job(&request.job_id)
    }

    fn cancel_job(job_id: &str, reason: BlobRef) -> Result<BlobRef, Failure> {
        validate_job_id(job_id)?;
        let reason_value = blob_to_value(&reason);
        let _ = read_verified(&reason)?;
        let versioned = read_record_pointer(job_id)?.ok_or_else(|| {
            failure(
                "unknown-job",
                format!("no durable record exists for {job_id}"),
            )
        })?;
        let mut record = decode_record_pointer(&versioned.value)?;
        if record.status.is_terminal() || record.status == ControlStatus::Blocked {
            return inspect_job(job_id);
        }
        let cancellation = record
            .cancellation_response(reason_value)
            .map_err(policy_failure)?;
        record
            .record_worker_return(cancellation)
            .map_err(policy_failure)?;
        persist_record(&record, Some(versioned.version))?;
        drive(job_id)?;
        inspect_job(job_id)
    }

    fn drive(job_id: &str) -> Result<(), Failure> {
        for _ in 0..32 {
            let versioned = read_record_pointer(job_id)?.ok_or_else(|| {
                failure(
                    "unknown-job",
                    format!("no durable record exists for {job_id}"),
                )
            })?;
            let mut record = decode_record_pointer(&versioned.value)?;
            match record.outbox.clone() {
                Some(OutboxValue::DispatchPending(request)) => {
                    let response = wasm_biotic::factory::worker_router::dispatch(
                        &worker_request_from_value(request),
                    );
                    record
                        .record_worker_return(worker_response_to_value(response))
                        .map_err(policy_failure)?;
                    persist_record(&record, Some(versioned.version))?;
                }
                Some(OutboxValue::WorkerReturned(response)) => {
                    record.outbox = None;
                    let event = SupervisorEvent::WorkerFinished(worker_response_from_value(
                        response.clone(),
                    ));
                    apply_reduction(&mut record, Some(versioned.version), event, Some(response))?;
                }
                Some(OutboxValue::EmitPending(_)) => {
                    if record.status != ControlStatus::Completed || record.result.is_none() {
                        return Err(failure(
                            "invalid-emit-outbox",
                            "emit-response was journalled without a completed job result",
                        ));
                    }
                    record.outbox = None;
                    persist_record(&record, Some(versioned.version))?;
                    return Ok(());
                }
                Some(OutboxValue::ApprovalPending(_)) => {
                    if record.status != ControlStatus::Blocked || record.result.is_none() {
                        return Err(failure(
                            "invalid-approval-outbox",
                            "approval request was journalled without a blocked job result",
                        ));
                    }
                    record.outbox = None;
                    persist_record(&record, Some(versioned.version))?;
                    return Ok(());
                }
                None if record.status.is_terminal() || record.status == ControlStatus::Blocked => {
                    return Ok(());
                }
                None => {
                    return Err(failure(
                        "durable-driver-stalled",
                        "running job has no reducer event or outbox command to recover",
                    ));
                }
            }
        }
        Err(failure(
            "driver-step-limit",
            "bounded v1 exceeded 32 durable driver transitions",
        ))
    }

    fn apply_reduction(
        record: &mut ControlRecordV1,
        expected_version: Option<u64>,
        event: SupervisorEvent,
        triggering_response: Option<WorkerResponseValue>,
    ) -> Result<(), Failure> {
        if record.outbox.is_some() {
            return Err(failure(
                "outbox-not-drained",
                "reducer cannot run while a durable outbox entry is pending",
            ));
        }
        let state_bytes = read_verified(&blob_from_value(record.supervisor_state.blob.clone()))?;
        let next_sequence = record
            .event_sequence
            .checked_add(1)
            .ok_or_else(|| failure("event-sequence-exhausted", "event sequence cannot advance"))?;
        let request = ReductionRequest {
            graph_digest: digest_from_value(record.graph_digest.clone()),
            state: Document {
                schema: record.supervisor_state.schema.clone(),
                media_type: record.supervisor_state.blob.media_type.clone(),
                body: state_bytes.clone(),
            },
            event_sequence: next_sequence,
            event,
        };
        let reduction = wasm_biotic::factory::supervisor_reducer::reduce(&request)?;
        validate_reduction(&reduction, &state_bytes, next_sequence)?;
        let Reduction {
            previous_state_digest: _,
            next_state,
            commands,
            decision_digest,
        } = reduction;
        if commands.len() > 1 {
            return Err(failure(
                "unsupported-command-batch",
                "bounded v1 reducer may emit at most one command per transition",
            ));
        }
        let command = commands
            .into_iter()
            .next()
            .map(command_to_value)
            .transpose()?;
        let state_ref = put_verified(&next_state.media_type, &next_state.body)?;
        record
            .journal_reduction(
                StateDocumentRef {
                    schema: next_state.schema,
                    blob: blob_to_value(&state_ref),
                },
                next_sequence,
                digest_to_value(&decision_digest),
                command,
            )
            .map_err(policy_failure)?;

        if let Some(OutboxValue::DispatchPending(request)) = &record.outbox {
            request.validate().map_err(policy_failure)?;
            if request.job_id != record.job_id {
                return Err(failure(
                    "reducer-job-identity-violation",
                    "reducer dispatched a worker for a different job",
                ));
            }
        }

        if triggering_response.is_none() {
            match &record.outbox {
                Some(OutboxValue::DispatchPending(request))
                    if request.role == WorkerRoleValue::Planner
                        && request.input == record.source => {}
                _ => {
                    return Err(failure(
                        "invalid-submit-reduction",
                        "job submission must durably dispatch the graph-bound planner over the exact source",
                    ));
                }
            }
        }

        if let Some(response) = triggering_response {
            if let Some(result) =
                JobResultV1::from_worker(record, &response).map_err(policy_failure)?
            {
                let status = result.status;
                let result_bytes = result.encode().map_err(policy_failure)?;
                let result_ref = put_verified(JOB_RESULT_MEDIA_TYPE, &result_bytes)?;
                record.status = status;
                record.result = Some(blob_to_value(&result_ref));
            }
        }
        persist_record(record, expected_version)?;
        Ok(())
    }

    fn validate_reduction(
        reduction: &Reduction,
        previous_state: &[u8],
        _event_sequence: u64,
    ) -> Result<(), Failure> {
        let expected = DigestValue::sha256(previous_state);
        if digest_to_value(&reduction.previous_state_digest) != expected {
            return Err(failure(
                "reducer-state-identity-violation",
                "reducer reported a false previous-state digest",
            ));
        }
        if reduction.next_state.schema != SUPERVISOR_STATE_SCHEMA
            || reduction.next_state.media_type != JSON_MEDIA_TYPE
        {
            return Err(failure(
                "invalid-reducer-state-document",
                "reducer returned an unsupported state document",
            ));
        }
        digest_to_value(&reduction.decision_digest)
            .validate("reduction.decision_digest")
            .map_err(policy_failure)
    }

    fn command_to_value(command: SupervisorCommand) -> Result<SupervisorCommandValue, Failure> {
        match command {
            SupervisorCommand::DispatchWorker(request) => Ok(
                SupervisorCommandValue::DispatchWorker(worker_request_to_value(request)),
            ),
            SupervisorCommand::EmitResponse(output) => {
                Ok(SupervisorCommandValue::EmitResponse(blob_to_value(&output)))
            }
            SupervisorCommand::RequireApproval(request) => Ok(
                SupervisorCommandValue::RequireApproval(blob_to_value(&request)),
            ),
            SupervisorCommand::Stop(reason) => Err(failure(
                "reducer-stop",
                format!(
                    "reducer stopped bounded v1: {}: {}",
                    reason.code, reason.message
                ),
            )),
            _ => Err(failure(
                "unsupported-supervisor-command",
                "bounded v1 root does not silently execute this reducer command",
            )),
        }
    }

    fn read_record_pointer(job_id: &str) -> Result<Option<VersionedValue>, Failure> {
        wasm_biotic::factory::transaction_store::read(NAMESPACE, job_id)
    }

    fn decode_record_pointer(reference: &BlobRef) -> Result<ControlRecordV1, Failure> {
        if reference.media_type != CONTROL_RECORD_MEDIA_TYPE {
            return Err(failure(
                "invalid-control-record-media-type",
                "durable job pointer is not a factory-control record",
            ));
        }
        let bytes = read_verified(reference)?;
        ControlRecordV1::decode(&bytes).map_err(policy_failure)
    }

    fn persist_record(
        record: &ControlRecordV1,
        expected_version: Option<u64>,
    ) -> Result<(), Failure> {
        let bytes = record.encode().map_err(policy_failure)?;
        let reference = put_verified(CONTROL_RECORD_MEDIA_TYPE, &bytes)?;
        let transaction_id = format!(
            "{}:{}:{}",
            record.job_id,
            record.event_sequence,
            DigestValue::sha256(&bytes).hex,
        );
        let request = CommitRequest {
            transaction_id: transaction_id.clone(),
            assertions: vec![Assertion {
                namespace: NAMESPACE.to_string(),
                key: record.job_id.clone(),
                expected_version,
            }],
            mutations: vec![Mutation::Put((
                NAMESPACE.to_string(),
                record.job_id.clone(),
                reference,
            ))],
            idempotency_key: digest_from_value(DigestValue::sha256(transaction_id.as_bytes())),
        };
        let receipt = wasm_biotic::factory::transaction_store::commit(&request)?;
        if receipt.transaction_id != transaction_id {
            return Err(failure(
                "transaction-receipt-identity-violation",
                "transaction store returned a receipt for a different commit",
            ));
        }
        Ok(())
    }

    fn read_verified(reference: &BlobRef) -> Result<Vec<u8>, Failure> {
        let bytes = wasm_biotic::factory::blob_store::get(reference)?;
        let actual = BlobValue::for_bytes(reference.media_type.clone(), &bytes);
        if actual != blob_to_value(reference) {
            return Err(failure(
                "blob-store-identity-violation",
                "blob store returned bytes that do not match their reference",
            ));
        }
        Ok(bytes)
    }

    fn put_verified(media_type: &str, bytes: &[u8]) -> Result<BlobRef, Failure> {
        let reference = wasm_biotic::factory::blob_store::put(media_type, bytes)?;
        let expected = BlobValue::for_bytes(media_type, bytes);
        if blob_to_value(&reference) != expected {
            return Err(failure(
                "blob-store-receipt-identity-violation",
                "blob store returned a false content-addressed put receipt",
            ));
        }
        Ok(reference)
    }

    fn validate_job_id(job_id: &str) -> Result<(), Failure> {
        let digest = job_id.strip_prefix("job-sha256-").ok_or_else(|| {
            failure(
                "invalid-job-id",
                "job id must use the job-sha256- identity form",
            )
        })?;
        DigestValue {
            algorithm: "sha256".to_string(),
            hex: digest.to_string(),
        }
        .validate("job_id")
        .map_err(policy_failure)
    }

    fn handle_api(request: IngressRequest) -> Result<IngressResponse, Failure> {
        if request.method == "GET"
            && request.path == "/__wasm-biotic/component-boundary-probe"
            && request.body.is_none()
        {
            return Ok(IngressResponse {
                status: 200,
                headers: vec![("x-wasm-biotic-component-root".to_string(), b"ok".to_vec())],
                body: None,
            });
        }
        if request.method == "POST" && request.path == "/v1/jobs" {
            let body = required_body(request.body)?;
            let job_id = submit_job(body)?;
            let bytes = encode_api_value(job_id).map_err(policy_failure)?;
            return Ok(api_response(
                202,
                Some(put_verified(JSON_MEDIA_TYPE, &bytes)?),
            ));
        }
        if request.method == "POST" && request.path == "/v1/recover" {
            let body = recover_job(required_body(request.body)?)?;
            return Ok(api_response(200, Some(body)));
        }
        if request.method == "POST" && request.path == "/v1/closure/evaluate" {
            let body = required_body(request.body)?;
            let result = wasm_biotic::factory::closure_evaluator::evaluate(&body)?;
            return Ok(api_response(200, Some(result)));
        }
        if request.method == "POST" && request.path == "/v1/state/migrate" {
            let result = route_migration(required_body(request.body)?)?;
            return Ok(api_response(200, Some(result)));
        }
        if request.method == "POST" && request.path == "/v1/capabilities/route" {
            let result = route_capability(required_body(request.body)?)?;
            return Ok(api_response(200, Some(result)));
        }
        if request.path.starts_with("/v1/exchange/") {
            return route_exchange(request);
        }
        if request.path.starts_with("/v1/evolution/") {
            return route_evolution(request);
        }
        if request.path.starts_with("/v1/activation") {
            return route_activation(request);
        }
        if request.path.starts_with("/v1/audit") {
            return route_audit(request);
        }
        if let Some(rest) = request.path.strip_prefix("/v1/jobs/") {
            if request.method == "POST" {
                if let Some(job_id) = rest.strip_suffix("/cancel") {
                    let result = cancel_job(job_id, required_body(request.body)?)?;
                    return Ok(api_response(200, Some(result)));
                }
            }
            if request.method == "GET" && request.body.is_none() {
                return Ok(api_response(200, Some(inspect_job(rest)?)));
            }
        }
        Err(failure(
            "unsupported-api-route",
            format!(
                "bounded v1 has no {} {} route",
                request.method, request.path
            ),
        ))
    }

    fn required_body(body: Option<BlobRef>) -> Result<BlobRef, Failure> {
        body.ok_or_else(|| {
            failure(
                "request-body-required",
                "this component-owned route requires a body blob",
            )
        })
    }

    fn api_response(status: u16, body: Option<BlobRef>) -> IngressResponse {
        IngressResponse {
            status,
            headers: vec![(
                "content-type".to_string(),
                JSON_MEDIA_TYPE.as_bytes().to_vec(),
            )],
            body,
        }
    }

    fn route_exchange(request: IngressRequest) -> Result<IngressResponse, Failure> {
        let result = match (request.method.as_str(), request.path.as_str()) {
            ("POST", "/v1/exchange/envelopes") => {
                wasm_biotic::factory::exchange_service::create_envelope(&required_body(
                    request.body,
                )?)?
            }
            ("POST", "/v1/exchange/receive") => {
                wasm_biotic::factory::exchange_service::receive_envelope(&required_body(
                    request.body,
                )?)?
            }
            ("POST", "/v1/exchange/revoke") => {
                wasm_biotic::factory::exchange_service::revoke_authority(&required_body(
                    request.body,
                )?)?
            }
            ("GET", path) if request.body.is_none() => {
                let transfer_id = path
                    .strip_prefix("/v1/exchange/transfers/")
                    .ok_or_else(|| failure("unsupported-api-route", "unknown exchange route"))?;
                wasm_biotic::factory::exchange_service::inspect_transfer(transfer_id)?
            }
            _ => return Err(failure("unsupported-api-route", "unknown exchange route")),
        };
        Ok(api_response(200, Some(result)))
    }

    fn route_evolution(request: IngressRequest) -> Result<IngressResponse, Failure> {
        if request.method != "POST" {
            return Err(failure(
                "unsupported-api-route",
                "evolution routes require POST",
            ));
        }
        let body = required_body(request.body)?;
        let result = match request.path.as_str() {
            "/v1/evolution/propose" => wasm_biotic::factory::factory_evolution::propose(&body)?,
            "/v1/evolution/shadow" => wasm_biotic::factory::factory_evolution::shadow(&body)?,
            "/v1/evolution/assess" => wasm_biotic::factory::factory_evolution::assess(&body)?,
            "/v1/evolution/apply" => apply_factory_upgrade(&body)?,
            "/v1/evolution/observe" => observe_factory_upgrade(&body)?,
            _ => return Err(failure("unsupported-api-route", "unknown evolution route")),
        };
        Ok(api_response(200, Some(result)))
    }

    fn apply_factory_upgrade(request: &BlobRef) -> Result<BlobRef, Failure> {
        let request_bytes = read_verified(request)?;
        let envelope = FactoryUpgradeEnvelopeV1::decode(&request_bytes).map_err(policy_failure)?;
        let active_manifest =
            wasm_biotic::factory::activation::active_manifest()?.ok_or_else(|| {
                failure(
                    "no-active-factory-graph",
                    "upgrade requires an exact active graph manifest",
                )
            })?;
        let active_graph = digest_to_value(&active_manifest.content_digest);
        if active_graph != envelope.expected_active_graph {
            return Err(failure(
                "inactive-upgrade-source",
                "upgrade expected graph does not match the selected active graph",
            ));
        }
        let active_state = wasm_biotic::factory::activation::active_state()?;
        let active_state_value = active_state.as_ref().map(blob_to_value);
        if active_state_value != envelope.expected_active_state {
            return Err(failure(
                "active-state-conflict",
                "upgrade expected state does not match the selected opaque state pointer",
            ));
        }
        if let Some(expected) = &active_state_value {
            if &envelope.previous_state.blob != expected {
                return Err(failure(
                    "migration-source-state-mismatch",
                    "migration input is not the exact active opaque state",
                ));
            }
        } else if envelope.candidate_graph.content_digest != active_graph {
            return Err(failure(
                "active-state-not-initialized",
                "a successor switch requires component-owned initialization of the incumbent state pointer",
            ));
        }

        let active_manifest_bytes = read_verified(&active_manifest)?;
        let candidate_manifest = blob_from_value(envelope.candidate_graph.clone());
        let candidate_manifest_bytes = read_verified(&candidate_manifest)?;
        validate_upgrade_manifests(
            &active_manifest_bytes,
            &active_graph,
            &candidate_manifest_bytes,
            &envelope.candidate_graph.content_digest,
            &envelope.migration_component,
        )
        .map_err(policy_failure)?;

        let previous_state_bytes =
            read_verified(&blob_from_value(envelope.previous_state.blob.clone()))?;
        let migrated = wasm_biotic::factory::state_migration::migrate(&StateMigrationRequest {
            previous_state: Document {
                schema: envelope.previous_state.schema,
                media_type: envelope.previous_state.blob.media_type,
                body: previous_state_bytes,
            },
            target_graph: digest_from_value(envelope.candidate_graph.content_digest.clone()),
            target_manifest: Document {
                schema: FACTORY_GRAPH_SCHEMA.to_string(),
                media_type: envelope.candidate_graph.media_type.clone(),
                body: candidate_manifest_bytes,
            },
        })?;
        let migrated_state = put_verified(&migrated.media_type, &migrated.body)?;
        let migrated_state_value = blob_to_value(&migrated_state);
        let staged = wasm_biotic::factory::activation::stage(&ActivationRequest {
            activation_id: envelope.activation_id.clone(),
            graph_manifest: candidate_manifest,
            expected_active_graph: Some(digest_from_value(active_graph.clone())),
            expected_active_state: active_state.clone(),
            state_migration: Some(digest_from_value(envelope.migration_component.clone())),
            migrated_state: Some(migrated_state.clone()),
            idempotency_key: digest_from_value(envelope.idempotency_key.clone()),
        })?;
        if !matches!(staged.state, ActivationState::Staged)
            || staged.active_graph.as_ref().map(digest_to_value)
                != Some(envelope.candidate_graph.content_digest.clone())
            || staged.active_state.as_ref().map(blob_to_value) != Some(migrated_state_value.clone())
        {
            return Err(failure(
                "untruthful-activation-stage",
                "activation stage did not bind the exact target graph and migrated state",
            ));
        }
        let committed = wasm_biotic::factory::activation::commit(&envelope.activation_id)?;
        if !matches!(committed.state, ActivationState::Active)
            || committed.active_graph.as_ref().map(digest_to_value)
                != staged.active_graph.as_ref().map(digest_to_value)
            || committed.active_state.as_ref().map(blob_to_value)
                != Some(migrated_state_value.clone())
            || committed.receipt.is_none()
        {
            return Err(failure(
                "untruthful-activation-commit",
                "activation commit did not atomically select the staged graph and state",
            ));
        }
        let response = FactoryUpgradeResultV1 {
            schema: FACTORY_UPGRADE_RESULT_SCHEMA.to_string(),
            activation_id: envelope.activation_id,
            previous_graph: active_graph,
            target_graph: envelope.candidate_graph.content_digest,
            previous_state: active_state_value,
            migrated_state: migrated_state_value,
            migration_component: envelope.migration_component,
            staged: activation_status_to_value(staged),
            committed: activation_status_to_value(committed),
        };
        let response_bytes = encode_json(&response, "factory-upgrade-result-serialization-failed")
            .map_err(policy_failure)?;
        put_verified(JSON_MEDIA_TYPE, &response_bytes)
    }

    fn observe_factory_upgrade(request: &BlobRef) -> Result<BlobRef, Failure> {
        let request_bytes = read_verified(request)?;
        let envelope =
            FactoryObservationRequestV1::decode(&request_bytes).map_err(policy_failure)?;
        let active_manifest =
            wasm_biotic::factory::activation::active_manifest()?.ok_or_else(|| {
                failure(
                    "no-active-factory-graph",
                    "observation requires an exact active graph manifest",
                )
            })?;
        let active_graph = digest_to_value(&active_manifest.content_digest);
        if active_graph != envelope.expected_active_graph {
            return Err(failure(
                "observation-graph-conflict",
                "observation does not target the selected active graph",
            ));
        }
        let observation_bytes = read_verified(&blob_from_value(envelope.observation.clone()))?;
        let observation =
            FactoryObservationV1::decode(&observation_bytes).map_err(policy_failure)?;
        if observation.graph_digest != active_graph {
            return Err(failure(
                "observation-evidence-graph-mismatch",
                "observation evidence is not bound to the selected graph",
            ));
        }
        let (action, status) = match observation.health {
            FactoryHealth::Healthy => (
                FactoryObservationAction::Retained,
                wasm_biotic::factory::activation::status(&envelope.activation_id)?,
            ),
            FactoryHealth::Unhealthy => (
                FactoryObservationAction::RolledBack,
                wasm_biotic::factory::activation::rollback(
                    &envelope.activation_id,
                    &digest_from_value(envelope.incumbent_graph.clone()),
                )?,
            ),
        };
        if matches!(action, FactoryObservationAction::RolledBack)
            && (!matches!(status.state, ActivationState::RolledBack)
                || status.active_graph.as_ref().map(digest_to_value)
                    != Some(envelope.incumbent_graph.clone())
                || status.receipt.is_none())
        {
            return Err(failure(
                "untruthful-activation-rollback",
                "rollback did not restore the component-selected incumbent graph",
            ));
        }
        let response = FactoryObservationResultV1 {
            schema: FACTORY_OBSERVATION_RESULT_SCHEMA.to_string(),
            activation_id: envelope.activation_id,
            observed_graph: active_graph,
            action,
            status: activation_status_to_value(status),
            observation: envelope.observation,
        };
        let response_bytes =
            encode_json(&response, "factory-observation-result-serialization-failed")
                .map_err(policy_failure)?;
        put_verified(JSON_MEDIA_TYPE, &response_bytes)
    }

    fn route_migration(request: BlobRef) -> Result<BlobRef, Failure> {
        let bytes = read_verified(&request)?;
        let envelope = MigrationRequestEnvelopeV1::decode(&bytes).map_err(policy_failure)?;
        let state_bytes = read_verified(&blob_from_value(envelope.previous_state.blob.clone()))?;
        let manifest_bytes = read_verified(&blob_from_value(envelope.target_manifest.clone()))?;
        let migrated = wasm_biotic::factory::state_migration::migrate(&StateMigrationRequest {
            previous_state: Document {
                schema: envelope.previous_state.schema,
                media_type: envelope.previous_state.blob.media_type,
                body: state_bytes,
            },
            target_graph: digest_from_value(envelope.target_graph),
            target_manifest: Document {
                schema: FACTORY_GRAPH_SCHEMA.to_string(),
                media_type: envelope.target_manifest.media_type,
                body: manifest_bytes,
            },
        })?;
        let body = put_verified(&migrated.media_type, &migrated.body)?;
        let response = StateDocumentRef {
            schema: migrated.schema,
            blob: blob_to_value(&body),
        };
        let response_bytes = encode_api_value(response).map_err(policy_failure)?;
        put_verified(JSON_MEDIA_TYPE, &response_bytes)
    }

    fn route_capability(request: BlobRef) -> Result<BlobRef, Failure> {
        let bytes = read_verified(&request)?;
        let envelope = CapabilityRouteEnvelopeV1::decode(&bytes).map_err(policy_failure)?;
        let response = wasm_biotic::factory::capability_router::route(
            &capability_request_from_value(envelope.request),
        );
        let bytes =
            encode_api_value(capability_response_to_value(response)).map_err(policy_failure)?;
        put_verified(JSON_MEDIA_TYPE, &bytes)
    }

    fn route_activation(request: IngressRequest) -> Result<IngressResponse, Failure> {
        let status = if request.method == "POST" && request.path == "/v1/activation/stage" {
            let bytes = read_verified(&required_body(request.body)?)?;
            let envelope = ActivationStageEnvelopeV1::decode(&bytes).map_err(policy_failure)?;
            wasm_biotic::factory::activation::stage(&activation_request_from_value(
                envelope.request,
            ))?
        } else if let Some(rest) = request.path.strip_prefix("/v1/activation/") {
            if request.method == "POST" {
                if let Some(id) = rest.strip_suffix("/commit") {
                    wasm_biotic::factory::activation::commit(id)?
                } else if let Some(id) = rest.strip_suffix("/rollback") {
                    let bytes = read_verified(&required_body(request.body)?)?;
                    let rollback =
                        ActivationRollbackEnvelopeV1::decode(&bytes).map_err(policy_failure)?;
                    wasm_biotic::factory::activation::rollback(
                        id,
                        &digest_from_value(rollback.target_graph),
                    )?
                } else {
                    return Err(failure("unsupported-api-route", "unknown activation route"));
                }
            } else if request.method == "GET" && request.body.is_none() {
                wasm_biotic::factory::activation::status(rest)?
            } else {
                return Err(failure("unsupported-api-route", "unknown activation route"));
            }
        } else {
            return Err(failure("unsupported-api-route", "unknown activation route"));
        };
        let bytes = encode_api_value(activation_status_to_value(status)).map_err(policy_failure)?;
        Ok(api_response(
            200,
            Some(put_verified(JSON_MEDIA_TYPE, &bytes)?),
        ))
    }

    fn route_audit(request: IngressRequest) -> Result<IngressResponse, Failure> {
        let bytes = if request.method == "POST" && request.path == "/v1/audit" {
            let body = read_verified(&required_body(request.body)?)?;
            let envelope = AuditAppendEnvelopeV1::decode(&body).map_err(policy_failure)?;
            let receipt =
                wasm_biotic::factory::audit_log::append(&audit_entry_from_value(envelope.entry))?;
            encode_api_value(audit_receipt_to_value(receipt)).map_err(policy_failure)?
        } else if request.method == "GET" && request.body.is_none() {
            let sequence = request
                .path
                .strip_prefix("/v1/audit/")
                .ok_or_else(|| failure("unsupported-api-route", "unknown audit route"))?
                .parse::<u64>()
                .map_err(|_| {
                    failure(
                        "invalid-audit-sequence",
                        "audit sequence must be an unsigned integer",
                    )
                })?;
            let entry = wasm_biotic::factory::audit_log::resolve(sequence)?;
            encode_api_value(entry.map(audit_entry_to_value)).map_err(policy_failure)?
        } else {
            return Err(failure("unsupported-api-route", "unknown audit route"));
        };
        Ok(api_response(
            200,
            Some(put_verified(JSON_MEDIA_TYPE, &bytes)?),
        ))
    }

    fn worker_request_to_value(value: WorkerRequest) -> WorkerRequestValue {
        WorkerRequestValue {
            execution_id: value.execution_id,
            job_id: value.job_id,
            role: match value.role {
                WorkerRole::Planner => WorkerRoleValue::Planner,
                WorkerRole::Builder => WorkerRoleValue::Builder,
                WorkerRole::Validator => WorkerRoleValue::Validator,
                WorkerRole::Reviewer => WorkerRoleValue::Reviewer,
                WorkerRole::Packager => WorkerRoleValue::Packager,
                WorkerRole::ContinuityWorker => WorkerRoleValue::ContinuityWorker,
            },
            worker: principal_to_value(value.worker),
            service_bindings: value
                .service_bindings
                .into_iter()
                .map(|binding| ServiceBindingValue {
                    family: service_family_to_value(binding.family),
                    component_digest: digest_to_value(&binding.component_digest),
                })
                .collect(),
            input: blob_to_value(&value.input),
            checkpoint: value.checkpoint.as_ref().map(blob_to_value),
            lease_digest: digest_to_value(&value.lease_digest),
            attempt: value.attempt,
            deadline_ms: value.deadline_ms,
        }
    }

    fn worker_request_from_value(value: WorkerRequestValue) -> WorkerRequest {
        WorkerRequest {
            execution_id: value.execution_id,
            job_id: value.job_id,
            role: match value.role {
                WorkerRoleValue::Planner => WorkerRole::Planner,
                WorkerRoleValue::Builder => WorkerRole::Builder,
                WorkerRoleValue::Validator => WorkerRole::Validator,
                WorkerRoleValue::Reviewer => WorkerRole::Reviewer,
                WorkerRoleValue::Packager => WorkerRole::Packager,
                WorkerRoleValue::ContinuityWorker => WorkerRole::ContinuityWorker,
            },
            worker: principal_from_value(value.worker),
            service_bindings: value
                .service_bindings
                .into_iter()
                .map(
                    |binding| wasm_biotic::factory::capability_contract::ServiceBinding {
                        family: service_family_from_value(binding.family),
                        component_digest: digest_from_value(binding.component_digest),
                    },
                )
                .collect(),
            input: blob_from_value(value.input),
            checkpoint: value.checkpoint.map(blob_from_value),
            lease_digest: digest_from_value(value.lease_digest),
            attempt: value.attempt,
            deadline_ms: value.deadline_ms,
        }
    }

    fn worker_response_to_value(value: WorkerResponse) -> WorkerResponseValue {
        WorkerResponseValue {
            execution_id: value.execution_id,
            worker_component: digest_to_value(&value.worker_component),
            outcome: match value.outcome {
                WorkerOutcome::Completed(blob) => {
                    WorkerOutcomeValue::Completed(blob_to_value(&blob))
                }
                WorkerOutcome::Blocked(blob) => WorkerOutcomeValue::Blocked(blob_to_value(&blob)),
                WorkerOutcome::Rejected(error) => {
                    WorkerOutcomeValue::Rejected(failure_to_value(error))
                }
                WorkerOutcome::Failed(error) => WorkerOutcomeValue::Failed(failure_to_value(error)),
                WorkerOutcome::Cancelled => WorkerOutcomeValue::Cancelled,
            },
            checkpoint: value.checkpoint.as_ref().map(blob_to_value),
            receipts: value
                .receipts
                .into_iter()
                .map(effect_receipt_to_value)
                .collect(),
            evidence: value.evidence.iter().map(blob_to_value).collect(),
        }
    }

    fn worker_response_from_value(value: WorkerResponseValue) -> WorkerResponse {
        WorkerResponse {
            execution_id: value.execution_id,
            worker_component: digest_from_value(value.worker_component),
            outcome: match value.outcome {
                WorkerOutcomeValue::Completed(blob) => {
                    WorkerOutcome::Completed(blob_from_value(blob))
                }
                WorkerOutcomeValue::Blocked(blob) => WorkerOutcome::Blocked(blob_from_value(blob)),
                WorkerOutcomeValue::Rejected(error) => {
                    WorkerOutcome::Rejected(failure_from_value(error))
                }
                WorkerOutcomeValue::Failed(error) => {
                    WorkerOutcome::Failed(failure_from_value(error))
                }
                WorkerOutcomeValue::Cancelled => WorkerOutcome::Cancelled,
            },
            checkpoint: value.checkpoint.map(blob_from_value),
            receipts: value
                .receipts
                .into_iter()
                .map(effect_receipt_from_value)
                .collect(),
            evidence: value.evidence.into_iter().map(blob_from_value).collect(),
        }
    }

    fn capability_request_from_value(value: CapabilityRequestValue) -> CapabilityRequest {
        CapabilityRequest {
            request_id: value.request_id,
            job_id: value.job_id,
            caller: principal_from_value(value.caller),
            service_component: digest_from_value(value.service_component),
            family: service_family_from_value(value.family),
            operation: operation_from_value(value.operation),
            input: blob_from_value(value.input),
            authority: match value.authority {
                AuthorityValue::Observe => AuthorityClass::Observe,
                AuthorityValue::LocalMutate => AuthorityClass::LocalMutate,
                AuthorityValue::AutomationControl => AuthorityClass::AutomationControl,
                AuthorityValue::PromotionControl => AuthorityClass::PromotionControl,
            },
            approval: value.approval.map(|proof| ApprovalProof {
                approval_id: proof.approval_id,
                decision_digest: digest_from_value(proof.decision_digest),
                approver: proof.approver,
                recorded_at_ms: proof.recorded_at_ms,
                signature: proof.signature,
            }),
            deadline_ms: value.deadline_ms,
            idempotency_key: digest_from_value(value.idempotency_key),
        }
    }

    fn capability_response_to_value(value: CapabilityResponse) -> CapabilityResponseValue {
        CapabilityResponseValue {
            request_id: value.request_id,
            service_component: digest_to_value(&value.service_component),
            outcome: match value.outcome {
                ServiceOutcome::Succeeded(blob) => {
                    ServiceOutcomeValue::Succeeded(blob_to_value(&blob))
                }
                ServiceOutcome::Rejected(error) => {
                    ServiceOutcomeValue::Rejected(failure_to_value(error))
                }
                ServiceOutcome::Failed(error) => {
                    ServiceOutcomeValue::Failed(failure_to_value(error))
                }
                ServiceOutcome::Cancelled => ServiceOutcomeValue::Cancelled,
                ServiceOutcome::Exhausted(error) => {
                    ServiceOutcomeValue::Exhausted(failure_to_value(error))
                }
            },
            effect_receipts: value
                .effect_receipts
                .into_iter()
                .map(effect_receipt_to_value)
                .collect(),
            evidence: value.evidence.iter().map(blob_to_value).collect(),
        }
    }

    fn activation_request_from_value(value: ActivationRequestValue) -> ActivationRequest {
        ActivationRequest {
            activation_id: value.activation_id,
            graph_manifest: blob_from_value(value.graph_manifest),
            expected_active_graph: value.expected_active_graph.map(digest_from_value),
            expected_active_state: value.expected_active_state.map(blob_from_value),
            state_migration: value.state_migration.map(digest_from_value),
            migrated_state: value.migrated_state.map(blob_from_value),
            idempotency_key: digest_from_value(value.idempotency_key),
        }
    }

    fn activation_status_to_value(value: ActivationStatus) -> ActivationStatusValue {
        ActivationStatusValue {
            activation_id: value.activation_id,
            state: match value.state {
                ActivationState::Staged => ActivationStateValue::Staged,
                ActivationState::Active => ActivationStateValue::Active,
                ActivationState::RolledBack => ActivationStateValue::RolledBack,
                ActivationState::Failed => ActivationStateValue::Failed,
            },
            active_graph: value.active_graph.as_ref().map(digest_to_value),
            active_state: value.active_state.as_ref().map(blob_to_value),
            receipt: value.receipt.map(effect_receipt_to_value),
        }
    }

    fn audit_entry_from_value(value: AuditEntryValue) -> AuditEntry {
        AuditEntry {
            event_id: value.event_id,
            actor: principal_from_value(value.actor),
            event_type: value.event_type,
            payload: blob_from_value(value.payload),
            previous_entry: value.previous_entry.map(digest_from_value),
            occurred_at_ms: value.occurred_at_ms,
            idempotency_key: digest_from_value(value.idempotency_key),
        }
    }

    fn audit_entry_to_value(value: AuditEntry) -> AuditEntryValue {
        AuditEntryValue {
            event_id: value.event_id,
            actor: principal_to_value(value.actor),
            event_type: value.event_type,
            payload: blob_to_value(&value.payload),
            previous_entry: value.previous_entry.as_ref().map(digest_to_value),
            occurred_at_ms: value.occurred_at_ms,
            idempotency_key: digest_to_value(&value.idempotency_key),
        }
    }

    fn audit_receipt_to_value(value: AuditReceipt) -> AuditReceiptValue {
        AuditReceiptValue {
            sequence: value.sequence,
            entry_digest: digest_to_value(&value.entry_digest),
        }
    }

    fn operation_from_value(value: OperationValue) -> Operation {
        match value {
            OperationValue::WorkspaceOpen => Operation::WorkspaceOpen,
            OperationValue::WorkspaceSnapshot => Operation::WorkspaceSnapshot,
            OperationValue::WorkspacePatch => Operation::WorkspacePatch,
            OperationValue::CandidateBuild => Operation::CandidateBuild,
            OperationValue::CommandExecute => Operation::CommandExecute,
            OperationValue::PackagePublish => Operation::PackagePublish,
            OperationValue::PackageVerify => Operation::PackageVerify,
            OperationValue::ValidationProve => Operation::ValidationProve,
            OperationValue::ValidationCompare => Operation::ValidationCompare,
            OperationValue::ReviewCandidate => Operation::ReviewCandidate,
            OperationValue::EvidencePublish => Operation::EvidencePublish,
            OperationValue::EvidenceResolve => Operation::EvidenceResolve,
            OperationValue::ScheduleJob => Operation::ScheduleJob,
            OperationValue::DeploymentInitialize => Operation::DeploymentInitialize,
            OperationValue::DeploymentActivate => Operation::DeploymentActivate,
            OperationValue::DeploymentObserve => Operation::DeploymentObserve,
            OperationValue::DeploymentRollback => Operation::DeploymentRollback,
            OperationValue::OperationsInspect => Operation::OperationsInspect,
            OperationValue::FactoryExecute => Operation::FactoryExecute,
            OperationValue::FactoryProviderProposal => Operation::FactoryProviderProposal,
            OperationValue::FactoryShadow => Operation::FactoryShadow,
            OperationValue::FactoryInitialize => Operation::FactoryInitialize,
            OperationValue::FactoryStateMigrate => Operation::FactoryStateMigrate,
            OperationValue::FactoryActivate => Operation::FactoryActivate,
            OperationValue::FactoryObserve => Operation::FactoryObserve,
            OperationValue::FactoryRollback => Operation::FactoryRollback,
            OperationValue::FactoryInspect => Operation::FactoryInspect,
        }
    }

    fn service_family_to_value(value: ServiceFamily) -> ServiceFamilyValue {
        match value {
            ServiceFamily::Build => ServiceFamilyValue::Build,
            ServiceFamily::Packaging => ServiceFamilyValue::Packaging,
            ServiceFamily::Validation => ServiceFamilyValue::Validation,
            ServiceFamily::Review => ServiceFamilyValue::Review,
            ServiceFamily::Continuity => ServiceFamilyValue::Continuity,
            ServiceFamily::Scheduling => ServiceFamilyValue::Scheduling,
            ServiceFamily::Operations => ServiceFamilyValue::Operations,
        }
    }

    fn service_family_from_value(value: ServiceFamilyValue) -> ServiceFamily {
        match value {
            ServiceFamilyValue::Build => ServiceFamily::Build,
            ServiceFamilyValue::Packaging => ServiceFamily::Packaging,
            ServiceFamilyValue::Validation => ServiceFamily::Validation,
            ServiceFamilyValue::Review => ServiceFamily::Review,
            ServiceFamilyValue::Continuity => ServiceFamily::Continuity,
            ServiceFamilyValue::Scheduling => ServiceFamily::Scheduling,
            ServiceFamilyValue::Operations => ServiceFamily::Operations,
        }
    }

    fn digest_to_value(value: &Digest) -> DigestValue {
        DigestValue {
            algorithm: match value.algorithm {
                HashAlgorithm::Sha256 => "sha256",
            }
            .to_string(),
            hex: value.hex.clone(),
        }
    }

    fn digest_from_value(value: DigestValue) -> Digest {
        Digest {
            algorithm: HashAlgorithm::Sha256,
            hex: value.hex,
        }
    }

    fn blob_to_value(value: &BlobRef) -> BlobValue {
        BlobValue {
            content_digest: digest_to_value(&value.content_digest),
            size_bytes: value.size_bytes,
            media_type: value.media_type.clone(),
        }
    }

    fn blob_from_value(value: BlobValue) -> BlobRef {
        BlobRef {
            content_digest: digest_from_value(value.content_digest),
            size_bytes: value.size_bytes,
            media_type: value.media_type,
        }
    }

    fn principal_to_value(value: Principal) -> PrincipalValue {
        PrincipalValue {
            id: value.id,
            component_digest: digest_to_value(&value.component_digest),
        }
    }

    fn principal_from_value(value: PrincipalValue) -> Principal {
        Principal {
            id: value.id,
            component_digest: digest_from_value(value.component_digest),
        }
    }

    fn failure_to_value(value: Failure) -> FailureValue {
        FailureValue {
            code: value.code,
            message: value.message,
            retryable: value.retryable,
            evidence: value.evidence.as_ref().map(blob_to_value),
        }
    }

    fn failure_from_value(value: FailureValue) -> Failure {
        Failure {
            code: value.code,
            message: value.message,
            retryable: value.retryable,
            evidence: value.evidence.map(blob_from_value),
        }
    }

    fn effect_receipt_to_value(value: EffectReceipt) -> EffectReceiptValue {
        EffectReceiptValue {
            receipt_id: value.receipt_id,
            request_digest: digest_to_value(&value.request_digest),
            executor_digest: digest_to_value(&value.executor_digest),
            started_at_ms: value.started_at_ms,
            finished_at_ms: value.finished_at_ms,
            outcome_digest: digest_to_value(&value.outcome_digest),
            audit_sequence: value.audit_sequence,
        }
    }

    fn effect_receipt_from_value(value: EffectReceiptValue) -> EffectReceipt {
        EffectReceipt {
            receipt_id: value.receipt_id,
            request_digest: digest_from_value(value.request_digest),
            executor_digest: digest_from_value(value.executor_digest),
            started_at_ms: value.started_at_ms,
            finished_at_ms: value.finished_at_ms,
            outcome_digest: digest_from_value(value.outcome_digest),
            audit_sequence: value.audit_sequence,
        }
    }

    fn policy_failure(error: PolicyError) -> Failure {
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

    export!(FactoryControlComponent);
}
