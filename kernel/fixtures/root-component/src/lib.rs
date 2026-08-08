#![cfg_attr(target_arch = "wasm32", no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_arch = "wasm32")]
extern crate alloc;

#[cfg(target_arch = "wasm32")]
mod guest {
    use alloc::string::String;
    use alloc::vec::Vec;

    wit_bindgen::generate!({
        path: "../../../wit/wasm-biotic",
        world: "factory-root",
    });

    use exports::wasm_biotic::factory::factory_api::{
        Guest as ApiGuest, IngressRequest, IngressResponse,
    };
    use exports::wasm_biotic::factory::factory_control::Guest as ControlGuest;
    use wasm_biotic::factory::blob_store;
    use wasm_biotic::factory::foundation::{BlobRef, Failure};

    struct RootFixture;

    impl ControlGuest for RootFixture {
        fn submit(event: BlobRef) -> Result<String, Failure> {
            let _ = blob_store::get(&event)?;
            Ok(event.content_digest.hex)
        }

        fn inspect(id: String) -> Result<BlobRef, Failure> {
            blob_store::put("application/octet-stream", id.as_bytes())
        }

        fn cancel(id: String, reason: BlobRef) -> Result<BlobRef, Failure> {
            let _ = wasm_biotic::factory::component_runner::poll(&id)?;
            Ok(reason)
        }

        fn recover(request: BlobRef) -> Result<BlobRef, Failure> {
            let bytes = blob_store::get(&request)?;
            blob_store::put(&request.media_type, &bytes)
        }
    }

    impl ApiGuest for RootFixture {
        fn handle(request: IngressRequest) -> Result<IngressResponse, Failure> {
            let body = blob_store::put("text/plain", request.path.as_bytes())?;
            Ok(IngressResponse {
                status: 200,
                headers: Vec::new(),
                body: Some(body),
            })
        }
    }

    export!(RootFixture);
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
