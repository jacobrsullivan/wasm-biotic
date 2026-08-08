#![cfg_attr(all(target_arch = "wasm32", not(test)), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

//! Bounded proving, comparison, provider-proposal, execution and shadow policy
//! component for the validation service family.

wasm_biotic_service_policy_core::define_blob_service_component!(
    world: "validation-service-component",
    interface: validation_service,
    family: Validation
);
