#![cfg_attr(all(target_arch = "wasm32", not(test)), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

//! A deliberately small admitted tool. It is not a native command: it is a
//! `component-task` implementation that resolves immutable input bytes and
//! returns a deterministic JSON probe through the generic blob mechanism.

extern crate alloc;

use alloc::{format, vec::Vec};

pub const PROBE_SCHEMA: &str = "wasm-biotic.admitted-tool-probe.v1";
pub const JSON_MEDIA_TYPE: &str = "application/json";

/// Generates the exact deterministic probe payload.
pub fn probe_payload(source_digest: &str, source_bytes: &[u8]) -> Vec<u8> {
    format!(
        "{{\"ok\":true,\"schema\":\"{PROBE_SCHEMA}\",\"source_digest\":\"{source_digest}\",\"source_size_bytes\":{}}}",
        source_bytes.len()
    )
    .into_bytes()
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

    wit_bindgen::generate!({
        path: "../../wit/wasm-biotic",
        world: "admitted-tool-component"
    });

    use exports::wasm_biotic::factory::component_task::Guest;
    use wasm_biotic::factory::foundation::{BlobRef, Failure};

    struct AdmittedToolProbe;

    impl Guest for AdmittedToolProbe {
        fn run(input: BlobRef) -> Result<BlobRef, Failure> {
            let bytes = wasm_biotic::factory::blob_store::get(&input)?;
            let payload = probe_payload(&input.content_digest.hex, &bytes);
            wasm_biotic::factory::blob_store::put(JSON_MEDIA_TYPE, &payload)
        }
    }

    export!(AdmittedToolProbe);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_is_stable_and_plain_json() {
        assert_eq!(
            probe_payload("abc", b"input"),
            br#"{"ok":true,"schema":"wasm-biotic.admitted-tool-probe.v1","source_digest":"abc","source_size_bytes":5}"#
        );
    }
}
