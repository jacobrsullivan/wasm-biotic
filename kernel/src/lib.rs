#![deny(unsafe_code)]
#![deny(missing_docs)]
//! A policy-neutral native substrate for content-addressed component graphs.
//!
//! This crate deliberately has a small vocabulary. It verifies bytes and
//! manifests, links declared typed edges, applies uniform resource limits, and
//! invokes an exact manifest entry point. All interpretation of application
//! values remains inside components.

mod certification;
mod digest;
mod error;
mod host;
mod http_transport;
mod local;
mod manifest;
mod root_runtime;
mod runtime;

/// Types and linker glue generated from the normative Component Model package.
pub mod bindings;

pub use certification::{
    RELEASE_CERTIFICATION_SCHEMA, RELEASE_CERTIFICATION_STATEMENT_SCHEMA,
    ReleaseCertificationSignature, ReleaseCertificationStatement, SignedReleaseCertification,
    TrustedCertifier, canonical_json_bytes, compiled_native_tcb_inventory_digest,
};
pub use digest::{DigestParseError, Sha256Digest};
pub use error::KernelError;
pub use host::{HOST_INTERFACE_ALLOWLIST, HostInterface};
pub use local::{
    DurabilityFaultController, DurabilityFaultPoint, DurabilityFaultSpec, LocalConfig,
    LocalMechanisms, SystemTimeSource, TimeSource,
};
pub use manifest::{
    ABI_S32_PAIR_TO_S32_V1, ComponentBlob, ComponentNode, EdgeBinding, EntryPoint, GraphManifest,
    GraphPackage, HostBinding, MANIFEST_SCHEMA_V1,
};
pub use root_runtime::{
    AdmittedComponent, AuthorityTrace, ContentArtifact, ExecutionProvenance, OpaqueRootEngine,
    OpaqueRootManager, RootAdmission, RootBinding, RootEvidence,
};
pub use runtime::{
    EdgeCallTrace, ExecutionInput, ExecutionTrace, GraphBinding, GraphRuntime, NodeCallTrace,
    ResourceLimits,
};
