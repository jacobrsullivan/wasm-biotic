#![cfg_attr(all(target_arch = "wasm32", not(test)), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

//! Bounded evidence publication and resolution service component.

wasm_biotic_service_policy_core::define_blob_service_component!(
    world: "continuity-service-component",
    interface: continuity_service,
    family: Continuity
);
