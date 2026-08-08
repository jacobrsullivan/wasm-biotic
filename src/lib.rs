#![forbid(unsafe_code)]

//! Transitional native AIAF v1 reference oracle plus offline component-graph
//! validation.
//!
//! This crate is not the production factory runtime.  The component-only
//! launch path is the independent `wasm-biotic-kernel` crate under `kernel/`;
//! it has no dependency on this crate or its native domain modules.
//!
//! This crate preserves the archived RC-05-derived bounded `v1` execution
//! model as reference behaviour at the repository root. It is canonical only
//! for transitional-oracle compatibility, never for production launch.

pub mod candidate;
pub mod capability_services;
pub mod component_factory;
pub mod component_graph;
pub mod deployment;
pub mod execution;
pub mod factory_reproduction;
pub mod local_runtime;
pub mod m1_reference;
pub mod m1_tool_catalog;
pub mod m1_validation;
pub mod m2_runtime;
pub mod m3_component_bridge;
pub mod m3_runtime;
pub mod m4_runtime;
pub mod m5_effect_port;
pub mod m5_effect_store;
pub mod m5_export;
pub mod m5_m3_adapter;
pub mod m5_provider_binding;
pub mod m5_provider_execution;
pub mod m5_provider_precommit;
pub mod m5_runtime;
pub mod m5_supervisor_adapter;
pub mod m6_authority;
pub mod m6_completion;
pub mod m6_identity;
pub mod m6_import;
pub mod m6_receiver_runtime;
pub mod m6_revocation;
pub mod m6_revocation_sender_runtime;
pub mod m6_sender_ack_runtime;
pub mod m6_sender_runtime;
pub mod m6_transactions;
pub mod m7_closure;
pub mod m7_operator;
pub mod m7_runtime;
pub mod supervisor;
pub mod worker_runtime;
