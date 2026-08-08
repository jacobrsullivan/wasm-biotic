#![cfg_attr(all(target_arch = "wasm32", not(test)), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

//! Bounded build-service component. Build policy and its five-operation
//! ownership map execute inside this component, never in a native adapter.

wasm_biotic_service_policy_core::define_blob_service_component!(
    world: "build-service-component",
    interface: build_service,
    family: Build
);
