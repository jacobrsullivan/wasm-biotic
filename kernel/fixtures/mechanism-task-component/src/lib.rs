#![cfg_attr(target_arch = "wasm32", no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_arch = "wasm32")]
extern crate alloc;

#[cfg(target_arch = "wasm32")]
mod guest {
    use alloc::string::ToString;
    use alloc::vec;

    wit_bindgen::generate!({
        path: "../../../wit/wasm-biotic",
        world: "admitted-task-component",
    });

    use exports::wasm_biotic::factory::component_task::Guest;
    use wasm_biotic::factory::foundation::{BlobRef, Failure};
    use wasm_biotic::factory::transaction_store::{CommitRequest, Mutation};

    struct MechanismTaskFixture;

    impl Guest for MechanismTaskFixture {
        fn run(input: BlobRef) -> Result<BlobRef, Failure> {
            if wasm_biotic::factory::clock::now_ms() == 0 {
                return Err(Failure {
                    code: "clock-not-granted".to_string(),
                    message: "clock grant was not available".to_string(),
                    retryable: false,
                    evidence: None,
                });
            }
            let bytes = wasm_biotic::factory::blob_store::get(&input)?;
            let output = wasm_biotic::factory::blob_store::put(&input.media_type, &bytes)?;
            let request = CommitRequest {
                transaction_id: "mechanism-task-fixture".to_string(),
                assertions: vec![],
                mutations: vec![Mutation::Put((
                    "wasm-biotic.schedule.v1".to_string(),
                    "last-input".to_string(),
                    output.clone(),
                ))],
                idempotency_key: input.content_digest.clone(),
            };
            let _ = wasm_biotic::factory::transaction_store::commit(&request)?;
            Ok(output)
        }
    }

    export!(MechanismTaskFixture);
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
