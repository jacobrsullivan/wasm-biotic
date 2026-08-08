#![cfg_attr(all(target_arch = "wasm32", not(test)), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

//! Bounded durable scheduling service component.

wasm_biotic_service_policy_core::define_scheduling_service_component!(
    world: "scheduling-service-component",
    interface: scheduling_service
);
