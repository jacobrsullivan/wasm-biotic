#![cfg_attr(all(target_arch = "wasm32", not(test)), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

//! Bounded candidate-review service component.

wasm_biotic_service_policy_core::define_blob_service_component!(
    world: "review-service-component",
    interface: review_service,
    family: Review
);
