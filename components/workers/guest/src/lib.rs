#![no_std]

pub use dlmalloc::GlobalDlmalloc;
pub use wasm_biotic_worker_policy as policy;

/// Installs the private no-std allocator and the two symbols required by the
/// wasm32-wasip2 and Canonical ABI linkers without importing WASI.
#[macro_export]
macro_rules! install_component_abi {
    () => {
        #[global_allocator]
        static ALLOCATOR: $crate::GlobalDlmalloc = $crate::GlobalDlmalloc;

        #[panic_handler]
        fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
            core::arch::wasm32::unreachable()
        }

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
                // SAFETY: the layout is valid and allocation failure traps.
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
                        let new_layout = Layout::from_size_align(new_length, alignment)
                            .unwrap_or_else(|_| core::arch::wasm32::unreachable());
                        handle_alloc_error(new_layout);
                    }
                    pointer
                }
            }
        }

        #[unsafe(no_mangle)]
        unsafe extern "C" fn memcmp(left: *const u8, right: *const u8, length: usize) -> i32 {
            for offset in 0..length {
                // SAFETY: the caller guarantees readable regions of `length`.
                let left_byte = unsafe { *left.add(offset) };
                // SAFETY: the caller guarantees readable regions of `length`.
                let right_byte = unsafe { *right.add(offset) };
                if left_byte != right_byte {
                    return i32::from(left_byte) - i32::from(right_byte);
                }
            }
            0
        }
    };
}
