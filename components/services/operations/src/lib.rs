#![cfg_attr(all(target_arch = "wasm32", not(test)), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

//! Bounded deployment and factory operations service component.

wasm_biotic_service_policy_core::define_blob_service_component!(
    world: "operations-service-component",
    interface: operations_service,
    family: Operations
);
