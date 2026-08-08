#![cfg_attr(target_arch = "wasm32", no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_arch = "wasm32")]
extern crate alloc;

#[cfg(target_arch = "wasm32")]
mod guest {
    use alloc::string::ToString;
    use alloc::vec;
    use alloc::vec::Vec;

    wit_bindgen::generate!({
        path: "../../../wit/wasm-biotic",
        world: "admitted-task-component",
    });

    use exports::wasm_biotic::factory::component_task::Guest;
    use wasm_biotic::factory::activation::ActivationRequest;
    use wasm_biotic::factory::clock::WakeRequest;
    use wasm_biotic::factory::component_runner::RunRequest;
    use wasm_biotic::factory::foundation::{BlobRef, CapabilityGrant, Failure, ResourceLimits};
    use wasm_biotic::factory::http_transport::{Header, Method, Request};
    use wasm_biotic::factory::transaction_store::{CommitRequest, Mutation};

    const FORGED_SHA256: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    struct AdversarialTaskFixture;

    impl Guest for AdversarialTaskFixture {
        fn run(input: BlobRef) -> Result<BlobRef, Failure> {
            let bytes = wasm_biotic::factory::blob_store::get(&input)?;
            match bytes.first().copied().unwrap_or(b'E') {
                b'E' => wasm_biotic::factory::blob_store::put(&input.media_type, &bytes),
                b'T' => core::arch::wasm32::unreachable(),
                b'L' => loop {
                    core::hint::spin_loop();
                },
                b'M' => {
                    let allocation_bytes = 32 * 1024 * 1024 + bytes.len();
                    let pressure = vec![0xa5; allocation_bytes];
                    wasm_biotic::factory::blob_store::put("application/octet-stream", &pressure)
                }
                b'O' => {
                    let oversized = vec![0x5a; 4096];
                    wasm_biotic::factory::blob_store::put("application/octet-stream", &oversized)
                }
                b'F' => {
                    let mut forged = input;
                    forged.content_digest.hex = FORGED_SHA256.to_string();
                    Ok(forged)
                }
                b'J' => wasm_biotic::factory::blob_store::put(
                    "application/json",
                    &[0xff, 0x00, b'{', b'\n'],
                ),
                b'K' => {
                    let signature = wasm_biotic::factory::key_service::sign_digest(
                        "adversarial-key",
                        &input.content_digest,
                    )?;
                    wasm_biotic::factory::blob_store::put(
                        "application/vnd.wasm-biotic.signature",
                        &signature.bytes,
                    )
                }
                b'B' => {
                    let oversized = vec![0x42; 4096];
                    wasm_biotic::factory::blob_store::put("application/octet-stream", &oversized)
                }
                b'X' => {
                    let copied =
                        wasm_biotic::factory::blob_store::put("application/octet-stream", &bytes)?;
                    let request = CommitRequest {
                        transaction_id: "adversarial-namespace-escape".to_string(),
                        assertions: vec![],
                        mutations: vec![Mutation::Put((
                            "outside-grant".to_string(),
                            "opaque-key".to_string(),
                            copied,
                        ))],
                        idempotency_key: input.content_digest.clone(),
                    };
                    let _ = wasm_biotic::factory::transaction_store::commit(&request)?;
                    Ok(input)
                }
                b'W' => {
                    let mut target = input.content_digest.clone();
                    target.hex = FORGED_SHA256.to_string();
                    let request = WakeRequest {
                        wake_id: "adversarial-wake-target".to_string(),
                        not_before_ms: wasm_biotic::factory::clock::now_ms(),
                        target_component: target,
                        payload_digest: input.content_digest.clone(),
                        idempotency_key: input.content_digest.clone(),
                    };
                    let _ = wasm_biotic::factory::clock::schedule_wake(&request)?;
                    Ok(input)
                }
                b'C' => {
                    let mut target = input.content_digest.clone();
                    target.hex = FORGED_SHA256.to_string();
                    let request = RunRequest {
                        run_id: "adversarial-unlisted-target".to_string(),
                        component_digest: target,
                        input: input.clone(),
                        grants: Vec::<CapabilityGrant>::new(),
                        limits: ResourceLimits {
                            fuel: 100_000,
                            memory_bytes: 4 * 1024 * 1024,
                            output_bytes: 1024,
                            wall_time_ms: 100,
                        },
                        idempotency_key: input.content_digest.clone(),
                    };
                    let _ = wasm_biotic::factory::component_runner::start(&request)?;
                    Ok(input)
                }
                b'H' => {
                    let request = Request {
                        request_id: "adversarial-http-envelope".to_string(),
                        method: Method::Post,
                        url: "http://169.254.169.254/latest/meta-data/".to_string(),
                        headers: vec![Header {
                            name: "authorization".to_string(),
                            value: vec![0xff, 0x00, 0x41],
                        }],
                        body: Some(input.clone()),
                        timeout_ms: 100,
                        idempotency_key: input.content_digest.clone(),
                        credential_handle: Some("opaque-credential-handle".to_string()),
                    };
                    let _ = wasm_biotic::factory::http_transport::start(&request)?;
                    Ok(input)
                }
                b'A' => {
                    let active =
                        wasm_biotic::factory::activation::active_manifest()?.ok_or_else(|| {
                            Failure {
                                code: "no-active-manifest".to_string(),
                                message: "the activation escape fixture requires an active graph"
                                    .to_string(),
                                retryable: false,
                                evidence: None,
                            }
                        })?;
                    let mut stale = active.content_digest.clone();
                    stale.hex = FORGED_SHA256.to_string();
                    let request = ActivationRequest {
                        activation_id: "adversarial-stale-expected".to_string(),
                        graph_manifest: active,
                        expected_active_graph: Some(stale),
                        expected_active_state: None,
                        state_migration: None,
                        migrated_state: None,
                        idempotency_key: input.content_digest.clone(),
                    };
                    let _ = wasm_biotic::factory::activation::stage(&request)?;
                    Ok(input)
                }
                _ => Err(Failure {
                    code: "unknown-adversarial-mode".to_string(),
                    message: "the test fixture mode byte is not recognized".to_string(),
                    retryable: false,
                    evidence: None,
                }),
            }
        }
    }

    export!(AdversarialTaskFixture);
}

#[cfg(target_arch = "wasm32")]
#[global_allocator]
static ALLOCATOR: dlmalloc::GlobalDlmalloc = dlmalloc::GlobalDlmalloc;

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}

#[cfg(target_arch = "wasm32")]
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
                let new_layout = Layout::from_size_align(new_length, alignment)
                    .unwrap_or_else(|_| core::arch::wasm32::unreachable());
                handle_alloc_error(new_layout);
            }
            pointer
        }
    }
}

#[cfg(target_arch = "wasm32")]
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
