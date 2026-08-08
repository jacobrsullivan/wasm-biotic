//! Strict admission for a component-complete Wasm-Biotic factory graph.
//!
//! [`ComponentGraphManifestV1`] is the exact Rust representation of
//! `contracts/component-complete/factory-graph.schema.json`; it is the only wire
//! manifest defined here. [`AddressedComponentGraphV1`] carries its external
//! SHA-256 identity without inventing an embedded self-digest field forbidden by
//! that schema.
//!
//! Validation does not trust declarations. It hashes the supplied bytes,
//! compiles every workload as a Component Model component, observes its actual
//! imports and exports, parses its digest-bound WIT world, resolves every import
//! binding, and proves exhaustive factory-semantic coverage. Native code is
//! permitted only behind the eight closed, policy-neutral host interfaces.

use crate::execution::artifact::ContentDigest;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{Display, Formatter};
use wasmparser::{Encoding, Parser, Payload};
use wasmtime::component::{Component, types::ComponentItem};
use wit_parser::{
    InterfaceId, Resolve, Type, TypeDefKind, TypeId, UnresolvedPackage, UnresolvedPackageGroup,
    WorldItem, WorldKey,
};

pub const COMPONENT_GRAPH_SCHEMA_V1: &str = "wasm-biotic.factory-graph.v1";
pub const FACTORY_WIT_PACKAGE_V1: &str = "wasm-biotic:factory@0.1.0";
pub const GRAPH_METADATA_SCHEMA_V1: &str = "wasm-biotic.factory-graph-metadata.v1";
pub const SUBSTRATE_PROFILE_SCHEMA_V1: &str = "wasm-biotic.factory-substrate-profile.v1";
pub const SUBSTRATE_PROFILE_SCHEMA_V2: &str = "wasm-biotic.factory-substrate-profile.v2";
pub const SUBSTRATE_PROFILE_SCHEMA_V3: &str = "wasm-biotic.factory-substrate-profile.v3";
pub const DERIVATION_DESCRIPTOR_SCHEMA_V1: &str = "wasm-biotic.component-derivation-descriptor.v1";
pub const DERIVATION_DESCRIPTOR_SCHEMA_V2: &str = "wasm-biotic.component-derivation-descriptor.v2";
pub const CAPABILITY_CONSTRAINTS_SCHEMA_V1: &str = "wasm-biotic.capability-constraints.v1";
pub const HTTP_TRANSPORT_CONSTRAINTS_SCHEMA_V1: &str = "wasm-biotic.http-transport-constraints.v1";
pub const HOST_IMPORT_ALIAS_SCHEME_V1: &str = "wasm-biotic.per-consumer-host-import.v1";
pub const GRAPH_NODE_PRINCIPAL_SCHEME_V1: &str = "wasm-biotic.graph-node-principal.v1";
pub const PRINCIPAL_SEED_SCHEMA_V1: &str = "wasm-biotic.principal-seed.v1";
pub const HOST_IMPORT_ALIAS_MATERIAL_SCHEMA_V1: &str = "wasm-biotic.host-import-alias-material.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum WorkerRole {
    Planner,
    Builder,
    Validator,
    Reviewer,
    Packager,
    Continuity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CapabilityServiceFamily {
    Build,
    Packaging,
    Validation,
    Review,
    Continuity,
    Scheduling,
    Operations,
}

/// Exact `node_kind` enum from the normative JSON schema.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FactoryComponentKind {
    Root,
    SupervisorReducer,
    WorkerRouter,
    CapabilityRouter,
    PlannerWorker,
    BuilderWorker,
    ValidatorWorker,
    ReviewerWorker,
    PackagerWorker,
    ContinuityWorker,
    BuildService,
    PackagingService,
    ValidationService,
    ReviewService,
    ContinuityService,
    SchedulingService,
    OperationsService,
    ExchangeService,
    FactoryEvolution,
    StateMigration,
    ClosureEvaluator,
    AdmittedTool,
}

impl FactoryComponentKind {
    pub const fn expected_world(self) -> &'static str {
        match self {
            Self::Root => "wasm-biotic:factory/factory-control-component@0.1.0",
            Self::SupervisorReducer => "wasm-biotic:factory/supervisor-reducer-component@0.1.0",
            Self::WorkerRouter => "wasm-biotic:factory/worker-router-component@0.1.0",
            Self::CapabilityRouter => "wasm-biotic:factory/capability-router-component@0.1.0",
            Self::PlannerWorker => "wasm-biotic:factory/planner-worker-component@0.1.0",
            Self::BuilderWorker => "wasm-biotic:factory/builder-worker-component@0.1.0",
            Self::ValidatorWorker => "wasm-biotic:factory/validator-worker-component@0.1.0",
            Self::ReviewerWorker => "wasm-biotic:factory/reviewer-worker-component@0.1.0",
            Self::PackagerWorker => "wasm-biotic:factory/packager-worker-component@0.1.0",
            Self::ContinuityWorker => "wasm-biotic:factory/continuity-worker-component@0.1.0",
            Self::BuildService => "wasm-biotic:factory/build-service-component@0.1.0",
            Self::PackagingService => "wasm-biotic:factory/packaging-service-component@0.1.0",
            Self::ValidationService => "wasm-biotic:factory/validation-service-component@0.1.0",
            Self::ReviewService => "wasm-biotic:factory/review-service-component@0.1.0",
            Self::ContinuityService => "wasm-biotic:factory/continuity-service-component@0.1.0",
            Self::SchedulingService => "wasm-biotic:factory/scheduling-service-component@0.1.0",
            Self::OperationsService => "wasm-biotic:factory/operations-service-component@0.1.0",
            Self::ExchangeService => "wasm-biotic:factory/exchange-service-component@0.1.0",
            Self::FactoryEvolution => "wasm-biotic:factory/factory-evolution-component@0.1.0",
            Self::StateMigration => "wasm-biotic:factory/state-migration-component@0.1.0",
            Self::ClosureEvaluator => "wasm-biotic:factory/closure-evaluator-component@0.1.0",
            Self::AdmittedTool => "wasm-biotic:factory/admitted-tool-component@0.1.0",
        }
    }

    pub const fn worker_role(self) -> Option<WorkerRole> {
        match self {
            Self::PlannerWorker => Some(WorkerRole::Planner),
            Self::BuilderWorker => Some(WorkerRole::Builder),
            Self::ValidatorWorker => Some(WorkerRole::Validator),
            Self::ReviewerWorker => Some(WorkerRole::Reviewer),
            Self::PackagerWorker => Some(WorkerRole::Packager),
            Self::ContinuityWorker => Some(WorkerRole::Continuity),
            _ => None,
        }
    }

    pub const fn service_family(self) -> Option<CapabilityServiceFamily> {
        match self {
            Self::BuildService => Some(CapabilityServiceFamily::Build),
            Self::PackagingService => Some(CapabilityServiceFamily::Packaging),
            Self::ValidationService => Some(CapabilityServiceFamily::Validation),
            Self::ReviewService => Some(CapabilityServiceFamily::Review),
            Self::ContinuityService => Some(CapabilityServiceFamily::Continuity),
            Self::SchedulingService => Some(CapabilityServiceFamily::Scheduling),
            Self::OperationsService => Some(CapabilityServiceFamily::Operations),
            _ => None,
        }
    }

    fn is_required(self) -> bool {
        self != Self::AdmittedTool
    }
}

/// Exact semantic coverage required for a component-complete factory.
pub const REQUIRED_FACTORY_COMPONENT_KINDS: [FactoryComponentKind; 21] = [
    FactoryComponentKind::Root,
    FactoryComponentKind::SupervisorReducer,
    FactoryComponentKind::WorkerRouter,
    FactoryComponentKind::CapabilityRouter,
    FactoryComponentKind::PlannerWorker,
    FactoryComponentKind::BuilderWorker,
    FactoryComponentKind::ValidatorWorker,
    FactoryComponentKind::ReviewerWorker,
    FactoryComponentKind::PackagerWorker,
    FactoryComponentKind::ContinuityWorker,
    FactoryComponentKind::BuildService,
    FactoryComponentKind::PackagingService,
    FactoryComponentKind::ValidationService,
    FactoryComponentKind::ReviewService,
    FactoryComponentKind::ContinuityService,
    FactoryComponentKind::SchedulingService,
    FactoryComponentKind::OperationsService,
    FactoryComponentKind::ExchangeService,
    FactoryComponentKind::FactoryEvolution,
    FactoryComponentKind::StateMigration,
    FactoryComponentKind::ClosureEvaluator,
];

/// Exact `host_capability` enum from the normative JSON schema.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SubstratePrimitive {
    BlobStore,
    TransactionStore,
    Clock,
    ComponentRunner,
    HttpTransport,
    KeyService,
    Activation,
    AuditLog,
}

impl SubstratePrimitive {
    pub const fn interface_name(self) -> &'static str {
        match self {
            Self::BlobStore => "wasm-biotic:factory/blob-store@0.1.0",
            Self::TransactionStore => "wasm-biotic:factory/transaction-store@0.1.0",
            Self::Clock => "wasm-biotic:factory/clock@0.1.0",
            Self::ComponentRunner => "wasm-biotic:factory/component-runner@0.1.0",
            Self::HttpTransport => "wasm-biotic:factory/http-transport@0.1.0",
            Self::KeyService => "wasm-biotic:factory/key-service@0.1.0",
            Self::Activation => "wasm-biotic:factory/activation@0.1.0",
            Self::AuditLog => "wasm-biotic:factory/audit-log@0.1.0",
        }
    }

    /// Canonical v1 scope vocabulary enforced by the generic native host.
    pub const fn canonical_scope(self) -> &'static str {
        match self {
            Self::BlobStore => "read-write",
            Self::TransactionStore => "namespaces",
            Self::Clock => "wake",
            Self::ComponentRunner => "run",
            Self::HttpTransport => "request",
            Self::KeyService => "use",
            Self::Activation => "switch",
            Self::AuditLog => "append-read",
        }
    }
}

pub const REQUIRED_SUBSTRATE_PRIMITIVES: [SubstratePrimitive; 8] = [
    SubstratePrimitive::BlobStore,
    SubstratePrimitive::TransactionStore,
    SubstratePrimitive::Clock,
    SubstratePrimitive::ComponentRunner,
    SubstratePrimitive::HttpTransport,
    SubstratePrimitive::KeyService,
    SubstratePrimitive::Activation,
    SubstratePrimitive::AuditLog,
];

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentCapabilityGrant {
    pub capability: SubstratePrimitive,
    pub scope: String,
    pub constraints: ContentDigest,
}

/// Exact `node` object from the normative JSON schema.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactoryComponentV1 {
    pub id: String,
    pub kind: FactoryComponentKind,
    pub component_digest: ContentDigest,
    pub world: String,
    pub exports: Vec<String>,
    pub grants: Vec<ComponentCapabilityGrant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_schema: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum ComponentBindingProvider {
    Component { node: String, export: String },
    Host { capability: SubstratePrimitive },
}

/// Exact `binding` object from the normative JSON schema.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentImportBinding {
    pub consumer: String,
    #[serde(rename = "import")]
    pub import_name: String,
    pub provider: ComponentBindingProvider,
}

/// Exact-digest dynamic execution edge. The consumer chooses no implementation
/// at runtime: admission resolves `target` to the raw component digest already
/// sealed into this manifest, while `component-runner` supplies only generic
/// instantiation and metering.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentInvocationEdge {
    pub consumer: String,
    pub target: String,
    pub export: String,
}

/// Exact top-level normative wire manifest. No self-digest is embedded.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentGraphManifestV1 {
    pub schema: String,
    pub wit_package: String,
    pub root_node: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_graph: Option<ContentDigest>,
    pub state_schema: String,
    pub nodes: Vec<FactoryComponentV1>,
    pub bindings: Vec<ComponentImportBinding>,
    pub invocations: Vec<ComponentInvocationEdge>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ContentDigest>,
}

impl ComponentGraphManifestV1 {
    /// RFC-8785-compatible canonical JSON for this schema's value domain.
    ///
    /// The manifest contains no floating point numbers, so recursive object-key
    /// ordering plus `serde_json` string/primitive encoding covers its complete
    /// JCS domain.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ComponentGraphDigestError> {
        canonical_json_bytes(self)
    }

    pub fn content_digest(&self) -> Result<ContentDigest, ComponentGraphDigestError> {
        Ok(ContentDigest::from_bytes(&self.canonical_bytes()?))
    }
}

/// External content address paired with the exact normative wire manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AddressedComponentGraphV1 {
    pub manifest: ComponentGraphManifestV1,
    pub manifest_digest: ContentDigest,
}

impl AddressedComponentGraphV1 {
    pub fn seal(manifest: ComponentGraphManifestV1) -> Result<Self, ComponentGraphDigestError> {
        let manifest_digest = manifest.content_digest()?;
        Ok(Self {
            manifest,
            manifest_digest,
        })
    }

    pub fn reseal(&mut self) -> Result<(), ComponentGraphDigestError> {
        self.manifest_digest = self.manifest.content_digest()?;
        Ok(())
    }
}

/// Digest-bound metadata reached through the normative manifest's `metadata`.
/// This internal artifact binds exact WIT world sources and the substrate
/// profile without adding competing fields to the v1 wire manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentGraphMetadataV1 {
    pub schema: String,
    pub wit_package_digest: ContentDigest,
    pub wit_world_digests: BTreeMap<String, ContentDigest>,
    pub substrate_profile_digest: ContentDigest,
    pub derivation_descriptor_digest: ContentDigest,
}

impl ComponentGraphMetadataV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ComponentGraphDigestError> {
        canonical_json_bytes(self)
    }

    pub fn content_digest(&self) -> Result<ContentDigest, ComponentGraphDigestError> {
        Ok(ContentDigest::from_bytes(&self.canonical_bytes()?))
    }
}

/// One authoritative raw node named by the derivation descriptor.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivationSourceV1 {
    pub node_id: String,
    pub component_digest: ContentDigest,
    pub world: String,
}

/// One derived executable cache. `authority_digest` remains the request and
/// receipt identity; `executable_digest` is separately recorded provenance.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedExecutableV1 {
    pub authority_node: String,
    pub authority_digest: ContentDigest,
    pub executable_digest: ContentDigest,
    pub source_digests: Vec<ContentDigest>,
    pub world: String,
    pub configuration_digest: ContentDigest,
    /// Complete ceiling for the residual substrate imports of this executable.
    /// These grants must exactly equal the authority node's manifest grants.
    pub grants: Vec<ComponentCapabilityGrant>,
}

/// R2 executable provenance. Raw source identities remain authoritative while
/// `scoped_source_digests` bind the deterministic import-renamed artifacts
/// that were actually composed. Each retained principal seed identifies one
/// independently linked host principal in the executable closure.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedExecutableV2 {
    pub authority_node: String,
    pub authority_digest: ContentDigest,
    pub executable_digest: ContentDigest,
    pub source_digests: Vec<ContentDigest>,
    pub scoped_source_digests: Vec<ContentDigest>,
    pub principal_seeds: Vec<ContentDigest>,
    pub world: String,
    pub configuration_digest: ContentDigest,
}

/// Exact external composition tool recipe, with no machine-local paths.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompositionToolV1 {
    pub name: String,
    pub version: String,
    pub options: Vec<String>,
}

/// Manifest-bound derivation authority. It deliberately excludes the final
/// graph digest: the manifest embeds this descriptor's digest, and therefore
/// adding the enclosing digest here would create a hash cycle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentDerivationDescriptorV1 {
    pub schema: String,
    pub wit_package_digest: ContentDigest,
    pub sources: Vec<DerivationSourceV1>,
    pub executables: Vec<DerivedExecutableV1>,
    pub tool: CompositionToolV1,
}

impl ComponentDerivationDescriptorV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ComponentGraphDigestError> {
        canonical_json_bytes(self)
    }

    pub fn content_digest(&self) -> Result<ContentDigest, ComponentGraphDigestError> {
        Ok(ContentDigest::from_bytes(&self.canonical_bytes()?))
    }
}

/// R2 derivation authority for per-consumer import-alias membranes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentDerivationDescriptorV2 {
    pub schema: String,
    pub wit_package_digest: ContentDigest,
    pub sources: Vec<DerivationSourceV1>,
    pub executables: Vec<DerivedExecutableV2>,
    pub tool: CompositionToolV1,
}

impl ComponentDerivationDescriptorV2 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ComponentGraphDigestError> {
        canonical_json_bytes(self)
    }

    pub fn content_digest(&self) -> Result<ContentDigest, ComponentGraphDigestError> {
        Ok(ContentDigest::from_bytes(&self.canonical_bytes()?))
    }
}

/// Canonical, machine-independent ceilings understood by the native mechanism
/// layer. This document contains resource/scoping facts only; it contains no
/// factory role, workflow, service or policy decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityConstraintsV1 {
    pub schema: String,
    pub max_blob_bytes: u64,
    pub max_total_blob_bytes: u64,
    pub max_random_bytes: u32,
    pub max_wake_delay_ms: u64,
    pub max_http_timeout_ms: u64,
    pub max_component_fuel: u64,
    pub max_component_memory_bytes: u64,
    pub max_component_output_bytes: u64,
    pub max_component_wall_time_ms: u64,
    pub transaction_namespaces: Vec<String>,
}

impl CapabilityConstraintsV1 {
    /// Bounded local-first ceiling used by the reproducible v1 package.
    pub fn bounded_local_default() -> Self {
        Self {
            schema: CAPABILITY_CONSTRAINTS_SCHEMA_V1.to_string(),
            max_blob_bytes: 16 * 1024 * 1024,
            max_total_blob_bytes: 256 * 1024 * 1024,
            max_random_bytes: 4_096,
            max_wake_delay_ms: 30 * 24 * 60 * 60 * 1_000,
            max_http_timeout_ms: 30_000,
            max_component_fuel: 50_000_000,
            max_component_memory_bytes: 64 * 1024 * 1024,
            max_component_output_bytes: 16 * 1024 * 1024,
            max_component_wall_time_ms: 30_000,
            transaction_namespaces: vec![
                "exchange-v1".to_string(),
                "wasm-biotic.approvals.v1".to_string(),
                "wasm-biotic.factory-control.v1".to_string(),
                "wasm-biotic.schedule.v1".to_string(),
            ],
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ComponentGraphDigestError> {
        canonical_json_bytes(self)
    }

    pub fn content_digest(&self) -> Result<ContentDigest, ComponentGraphDigestError> {
        Ok(ContentDigest::from_bytes(&self.canonical_bytes()?))
    }
}

/// Closed R3 method vocabulary for byte-oriented transport. Variant order is
/// the canonical wire-name order used when validating signed arrays.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HttpMethodV1 {
    Delete,
    Get,
    Head,
    Patch,
    Post,
    Put,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HttpTransportSchemeV1 {
    Https,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HttpDnsPolicyV1 {
    ExactCidrs,
    PublicOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum HttpTlsMinimumVersionV1 {
    #[serde(rename = "tls-1.3")]
    Tls13,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HttpRedirectPolicyV1 {
    Deny,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HttpCredentialPlacementV1 {
    AppendToHeaderValue,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpDnsConstraintsV1 {
    pub policy: HttpDnsPolicyV1,
    pub cidrs: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpTlsConstraintsV1 {
    pub minimum_version: HttpTlsMinimumVersionV1,
    pub server_name: String,
    pub peer_spki_sha256: Vec<ContentDigest>,
}

/// One exact HTTPS authority and path envelope. `id` is only an immutable
/// local reference used by credential bindings; it has no provider meaning.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpTransportOriginV1 {
    pub id: String,
    pub scheme: HttpTransportSchemeV1,
    pub host: String,
    pub port: u16,
    pub path_prefixes: Vec<String>,
    pub dns: HttpDnsConstraintsV1,
    pub tls: HttpTlsConstraintsV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpRequestHeaderConstraintsV1 {
    pub allowed_names: Vec<String>,
    pub max_count: u32,
    pub max_total_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpResponseHeaderConstraintsV1 {
    pub exposed_names: Vec<String>,
    pub max_count: u32,
    pub max_total_bytes: u64,
}

/// Exact placement of one non-exportable credential. The component supplies a
/// header whose value is exactly `value_prefix`; the substrate may append the
/// secret selected by `handle` only after destination and TLS authorization.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpCredentialBindingV1 {
    pub handle: String,
    pub origin_id: String,
    pub header_name: String,
    pub value_prefix: String,
    pub placement: HttpCredentialPlacementV1,
}

/// Immutable, content-addressed R3 transport envelope. It contains only
/// generic network confinement and resource bounds, never provider identity,
/// prompts, parsing, retries, fallback, workflow or success policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpTransportConstraintsV1 {
    pub schema: String,
    pub origins: Vec<HttpTransportOriginV1>,
    pub methods: Vec<HttpMethodV1>,
    pub request_headers: HttpRequestHeaderConstraintsV1,
    pub response_headers: HttpResponseHeaderConstraintsV1,
    pub max_url_bytes: u64,
    pub max_request_body_bytes: u64,
    pub max_response_body_bytes: u64,
    pub max_timeout_ms: u64,
    pub max_concurrency: u32,
    pub redirects: HttpRedirectPolicyV1,
    pub credential_bindings: Vec<HttpCredentialBindingV1>,
}

impl HttpTransportConstraintsV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ComponentGraphDigestError> {
        canonical_json_bytes(self)
    }

    pub fn content_digest(&self) -> Result<ContentDigest, ComponentGraphDigestError> {
        Ok(ContentDigest::from_bytes(&self.canonical_bytes()?))
    }

    /// Validate the signed transport document against the generic R2 ceilings
    /// that remain the upper bound for every R3 capability grant.
    pub fn validate_against(&self, ceilings: &CapabilityConstraintsV1) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        if self.schema != HTTP_TRANSPORT_CONSTRAINTS_SCHEMA_V1 {
            errors.push(format!(
                "schema must be {HTTP_TRANSPORT_CONSTRAINTS_SCHEMA_V1}"
            ));
        }
        if self.origins.is_empty()
            || !strictly_sorted_by(&self.origins, |origin| origin.id.as_str())
        {
            errors.push("origins must be non-empty and strictly sorted by id".to_string());
        }
        if self.methods.is_empty() || !strictly_sorted_values(&self.methods) {
            errors.push("methods must be non-empty, unique and in wire-name order".to_string());
        }
        if !strictly_sorted_strings(&self.request_headers.allowed_names)
            || !strictly_sorted_strings(&self.response_headers.exposed_names)
        {
            errors.push("header-name arrays must be unique and strictly sorted".to_string());
        }
        if self.request_headers.max_count == 0
            || self.request_headers.max_total_bytes == 0
            || self.response_headers.max_count == 0
            || self.response_headers.max_total_bytes == 0
            || self.max_url_bytes == 0
            || self.max_request_body_bytes == 0
            || self.max_response_body_bytes == 0
            || self.max_timeout_ms == 0
            || self.max_concurrency == 0
        {
            errors.push(
                "transport size, time, header and concurrency bounds must be positive".to_string(),
            );
        }
        if self.max_timeout_ms > ceilings.max_http_timeout_ms
            || self.max_request_body_bytes > ceilings.max_blob_bytes
            || self.max_response_body_bytes > ceilings.max_blob_bytes
            || self.max_url_bytes > ceilings.max_blob_bytes
            || self.request_headers.max_total_bytes > ceilings.max_blob_bytes
            || self.response_headers.max_total_bytes > ceilings.max_blob_bytes
        {
            errors.push(
                "transport bounds must not exceed the shared capability ceilings".to_string(),
            );
        }

        let forbidden_headers = permanently_forbidden_request_headers();
        for name in &self.request_headers.allowed_names {
            if !is_canonical_header_name(name) || forbidden_headers.contains(name.as_str()) {
                errors.push(format!(
                    "request header name {name:?} is invalid or permanently forbidden"
                ));
            }
        }
        for name in &self.response_headers.exposed_names {
            if !is_canonical_header_name(name) {
                errors.push(format!("response header name {name:?} is not canonical"));
            }
        }

        let mut origin_ids = BTreeSet::new();
        let mut origin_authorities = BTreeSet::new();
        for origin in &self.origins {
            if !is_canonical_contract_id(&origin.id) {
                errors.push(format!("origin id {:?} is not canonical", origin.id));
            }
            origin_ids.insert(origin.id.as_str());
            if !is_canonical_http_host(&origin.host) || origin.port == 0 {
                errors.push(format!(
                    "origin {} has a non-canonical host or zero port",
                    origin.id
                ));
            }
            if !origin_authorities.insert((origin.scheme, origin.host.as_str(), origin.port)) {
                errors.push(format!(
                    "origin {} duplicates an HTTPS authority",
                    origin.id
                ));
            }
            if origin.path_prefixes.is_empty()
                || !strictly_sorted_strings(&origin.path_prefixes)
                || origin
                    .path_prefixes
                    .iter()
                    .any(|path| !is_canonical_http_path_prefix(path))
            {
                errors.push(format!(
                    "origin {} path prefixes are not canonical",
                    origin.id
                ));
            }
            match origin.dns.policy {
                HttpDnsPolicyV1::PublicOnly if !origin.dns.cidrs.is_empty() => {
                    errors.push(format!(
                        "origin {} public-only DNS policy must have no CIDRs",
                        origin.id
                    ))
                }
                HttpDnsPolicyV1::ExactCidrs if origin.dns.cidrs.is_empty() => errors.push(format!(
                    "origin {} exact-cidrs DNS policy requires at least one CIDR",
                    origin.id
                )),
                _ => {}
            }
            if !strictly_sorted_strings(&origin.dns.cidrs)
                || origin.dns.cidrs.iter().any(|cidr| !is_canonical_cidr(cidr))
            {
                errors.push(format!(
                    "origin {} CIDRs are not canonical networks",
                    origin.id
                ));
            }
            if !is_canonical_http_host(&origin.tls.server_name)
                || origin.tls.server_name != origin.host
                || origin.tls.peer_spki_sha256.is_empty()
                || !strictly_sorted_values(&origin.tls.peer_spki_sha256)
            {
                errors.push(format!(
                    "origin {} TLS server name must equal its host and SPKI pins must be canonical",
                    origin.id
                ));
            }
        }

        if !self.credential_bindings.windows(2).all(|pair| {
            (&pair[0].handle, &pair[0].origin_id, &pair[0].header_name)
                < (&pair[1].handle, &pair[1].origin_id, &pair[1].header_name)
        }) {
            errors.push(
                "credential bindings must be unique and sorted by handle, origin and header"
                    .to_string(),
            );
        }
        let mut credential_handles = BTreeSet::new();
        for binding in &self.credential_bindings {
            if !is_visible_ascii_token(&binding.handle, 256)
                || !origin_ids.contains(binding.origin_id.as_str())
                || !is_canonical_header_name(&binding.header_name)
                || forbidden_headers.contains(binding.header_name.as_str())
                || self
                    .request_headers
                    .allowed_names
                    .binary_search(&binding.header_name)
                    .is_err()
                || binding.value_prefix.is_empty()
                || binding.value_prefix.len() > 1_024
                || !binding
                    .value_prefix
                    .as_bytes()
                    .iter()
                    .all(|byte| (0x20..=0x7e).contains(byte))
            {
                errors.push(format!(
                    "credential binding for handle {:?} is not a valid exact header placement",
                    binding.handle
                ));
            }
            if !credential_handles.insert(binding.handle.as_str()) {
                errors.push(format!(
                    "credential handle {:?} has more than one signed placement",
                    binding.handle
                ));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

/// Exact enforcement principal used for a statically composed graph.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StaticGrantModelV1 {
    ComposedRootGraphUnion,
}

/// Digest-bound declaration of the complete and only native boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubstrateProfileV1 {
    pub schema: String,
    pub wit_package: String,
    pub primitives: Vec<SubstratePrimitive>,
    pub static_grant_model: StaticGrantModelV1,
    pub root_node: String,
    pub root_grants: Vec<ComponentCapabilityGrant>,
    pub ceilings: CapabilityConstraintsV1,
}

impl SubstrateProfileV1 {
    pub fn component_complete(
        root_node: impl Into<String>,
        root_grants: Vec<ComponentCapabilityGrant>,
        ceilings: CapabilityConstraintsV1,
    ) -> Self {
        Self {
            schema: SUBSTRATE_PROFILE_SCHEMA_V1.to_string(),
            wit_package: FACTORY_WIT_PACKAGE_V1.to_string(),
            primitives: REQUIRED_SUBSTRATE_PRIMITIVES.to_vec(),
            static_grant_model: StaticGrantModelV1::ComposedRootGraphUnion,
            root_node: root_node.into(),
            root_grants,
            ceilings,
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ComponentGraphDigestError> {
        canonical_json_bytes(self)
    }

    pub fn content_digest(&self) -> Result<ContentDigest, ComponentGraphDigestError> {
        Ok(ContentDigest::from_bytes(&self.canonical_bytes()?))
    }
}

/// Canonical material for an R2 graph-node principal. It deliberately excludes
/// the enclosing graph digest to avoid a content-addressing cycle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalSeedMaterialV1 {
    pub schema: String,
    pub consumer: String,
    pub authority_component_digest: ContentDigest,
}

impl PrincipalSeedMaterialV1 {
    pub fn for_node(node: &FactoryComponentV1) -> Self {
        Self {
            schema: PRINCIPAL_SEED_SCHEMA_V1.to_string(),
            consumer: node.id.clone(),
            authority_component_digest: node.component_digest.clone(),
        }
    }

    pub fn principal_seed(&self) -> Result<ContentDigest, ComponentGraphDigestError> {
        Ok(ContentDigest::from_bytes(&canonical_json_bytes(self)?))
    }
}

/// Canonical material whose digest becomes the unique Component Model import
/// instance name for one consumer/capability binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostImportAliasMaterialV1 {
    pub schema: String,
    pub consumer: String,
    pub authority_component_digest: ContentDigest,
    pub capability: SubstratePrimitive,
    pub source_import: String,
}

impl HostImportAliasMaterialV1 {
    pub fn for_binding(node: &FactoryComponentV1, capability: SubstratePrimitive) -> Self {
        Self {
            schema: HOST_IMPORT_ALIAS_MATERIAL_SCHEMA_V1.to_string(),
            consumer: node.id.clone(),
            authority_component_digest: node.component_digest.clone(),
            capability,
            source_import: capability.interface_name().to_string(),
        }
    }

    pub fn alias(&self) -> Result<String, ComponentGraphDigestError> {
        let digest = ContentDigest::from_bytes(&canonical_json_bytes(self)?);
        Ok(format!(
            "wasm-biotic:factory/host-{}@0.1.0",
            digest.as_str().trim_start_matches("sha256:")
        ))
    }
}

/// One direct host import exposed through a principal-specific link name.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalHostImportV2 {
    pub alias: String,
    pub source_import: String,
    pub capability: SubstratePrimitive,
    pub scope: String,
    pub constraints: ContentDigest,
}

/// Complete R2 identity and direct authority of one manifest node. Pure nodes
/// are retained with an empty `host_imports` list so the principal inventory is
/// exhaustive and canonical for all graph nodes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphNodePrincipalV2 {
    pub consumer: String,
    pub authority_component_digest: ContentDigest,
    pub principal_seed: ContentDigest,
    pub scoped_component_digest: ContentDigest,
    pub host_imports: Vec<PrincipalHostImportV2>,
}

/// R2 static grant model. The native substrate links each generated import
/// name to one immutable principal row and never receives a forgeable caller
/// token from component memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StaticGrantModelV2 {
    PerConsumerImportAlias,
}

/// R2 profile retaining the same eight mechanism types while exposing a
/// distinct Component Model import instance for every direct consumer grant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubstrateProfileV2 {
    pub schema: String,
    pub wit_package: String,
    pub primitives: Vec<SubstratePrimitive>,
    pub static_grant_model: StaticGrantModelV2,
    pub root_node: String,
    pub import_alias_scheme: String,
    pub principal_id_scheme: String,
    pub principals: Vec<GraphNodePrincipalV2>,
    pub ceilings: CapabilityConstraintsV1,
}

impl SubstrateProfileV2 {
    pub fn component_complete(
        root_node: impl Into<String>,
        principals: Vec<GraphNodePrincipalV2>,
        ceilings: CapabilityConstraintsV1,
    ) -> Self {
        Self {
            schema: SUBSTRATE_PROFILE_SCHEMA_V2.to_string(),
            wit_package: FACTORY_WIT_PACKAGE_V1.to_string(),
            primitives: REQUIRED_SUBSTRATE_PRIMITIVES.to_vec(),
            static_grant_model: StaticGrantModelV2::PerConsumerImportAlias,
            root_node: root_node.into(),
            import_alias_scheme: HOST_IMPORT_ALIAS_SCHEME_V1.to_string(),
            principal_id_scheme: GRAPH_NODE_PRINCIPAL_SCHEME_V1.to_string(),
            principals,
            ceilings,
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ComponentGraphDigestError> {
        canonical_json_bytes(self)
    }

    pub fn content_digest(&self) -> Result<ContentDigest, ComponentGraphDigestError> {
        Ok(ContentDigest::from_bytes(&self.canonical_bytes()?))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HttpTransportModeV1 {
    BoundedExternal,
}

/// Digest binding for one principal-specific HTTP import alias. It repeats no
/// destination policy: those closed bytes live solely in `constraints`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpTransportBindingV1 {
    pub consumer: String,
    pub alias: String,
    pub constraints: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpTransportProfileV1 {
    pub mode: HttpTransportModeV1,
    pub bindings: Vec<HttpTransportBindingV1>,
}

/// Canonical projection used independently by packagers and validators. It is
/// deliberately a pure function of the signed principal inventory.
pub fn project_http_transport_bindings_v1(
    principals: &[GraphNodePrincipalV2],
) -> Vec<HttpTransportBindingV1> {
    let mut bindings = principals
        .iter()
        .flat_map(|principal| {
            principal
                .host_imports
                .iter()
                .filter(|host_import| host_import.capability == SubstratePrimitive::HttpTransport)
                .map(|host_import| HttpTransportBindingV1 {
                    consumer: principal.consumer.clone(),
                    alias: host_import.alias.clone(),
                    constraints: host_import.constraints.clone(),
                })
        })
        .collect::<Vec<_>>();
    bindings.sort();
    bindings
}

/// R3 profile: the R2 principal/scoped-component authority model plus an exact
/// projection from enabled HTTP aliases to separate, signed transport bounds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubstrateProfileV3 {
    pub schema: String,
    pub wit_package: String,
    pub primitives: Vec<SubstratePrimitive>,
    pub static_grant_model: StaticGrantModelV2,
    pub root_node: String,
    pub import_alias_scheme: String,
    pub principal_id_scheme: String,
    pub principals: Vec<GraphNodePrincipalV2>,
    pub ceilings: CapabilityConstraintsV1,
    pub http_transport: HttpTransportProfileV1,
}

impl SubstrateProfileV3 {
    pub fn component_complete(
        root_node: impl Into<String>,
        principals: Vec<GraphNodePrincipalV2>,
        ceilings: CapabilityConstraintsV1,
        http_transport_bindings: Vec<HttpTransportBindingV1>,
    ) -> Self {
        Self {
            schema: SUBSTRATE_PROFILE_SCHEMA_V3.to_string(),
            wit_package: FACTORY_WIT_PACKAGE_V1.to_string(),
            primitives: REQUIRED_SUBSTRATE_PRIMITIVES.to_vec(),
            static_grant_model: StaticGrantModelV2::PerConsumerImportAlias,
            root_node: root_node.into(),
            import_alias_scheme: HOST_IMPORT_ALIAS_SCHEME_V1.to_string(),
            principal_id_scheme: GRAPH_NODE_PRINCIPAL_SCHEME_V1.to_string(),
            principals,
            ceilings,
            http_transport: HttpTransportProfileV1 {
                mode: HttpTransportModeV1::BoundedExternal,
                bindings: http_transport_bindings,
            },
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ComponentGraphDigestError> {
        canonical_json_bytes(self)
    }

    pub fn content_digest(&self) -> Result<ContentDigest, ComponentGraphDigestError> {
        Ok(ContentDigest::from_bytes(&self.canonical_bytes()?))
    }
}

fn canonical_json_bytes<T: Serialize + ?Sized>(
    value: &T,
) -> Result<Vec<u8>, ComponentGraphDigestError> {
    let value = serde_json::to_value(value)
        .map_err(|error| ComponentGraphDigestError::Serialization(error.to_string()))?;
    let mut output = Vec::new();
    write_canonical_value(&value, &mut output)?;
    Ok(output)
}

fn write_canonical_value(
    value: &Value,
    output: &mut Vec<u8>,
) -> Result<(), ComponentGraphDigestError> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(value) => output.extend_from_slice(if *value { b"true" } else { b"false" }),
        Value::Number(number) => output.extend_from_slice(number.to_string().as_bytes()),
        Value::String(string) => {
            let encoded = serde_json::to_vec(string)
                .map_err(|error| ComponentGraphDigestError::Serialization(error.to_string()))?;
            output.extend_from_slice(&encoded);
        }
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_value(value, output)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            output.push(b'{');
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort();
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_value(&Value::String(key.clone()), output)?;
                output.push(b':');
                write_canonical_value(&values[key], output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ComponentGraphDigestError {
    Serialization(String),
}

impl Display for ComponentGraphDigestError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Serialization(error) => {
                write!(f, "component graph canonical serialization failed: {error}")
            }
        }
    }
}

impl Error for ComponentGraphDigestError {}

/// Exact immutable artifacts supplied for graph admission.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ComponentGraphArtifacts {
    pub component_bytes: BTreeMap<String, Vec<u8>>,
    pub scoped_component_bytes: BTreeMap<ContentDigest, Vec<u8>>,
    pub derived_component_bytes: BTreeMap<ContentDigest, Vec<u8>>,
    pub derivation_descriptor_bytes: BTreeMap<ContentDigest, Vec<u8>>,
    pub composition_config_bytes: BTreeMap<ContentDigest, Vec<u8>>,
    pub metadata_bytes: BTreeMap<ContentDigest, Vec<u8>>,
    pub wit_package_bytes: BTreeMap<ContentDigest, Vec<u8>>,
    pub wit_world_bytes: BTreeMap<ContentDigest, Vec<u8>>,
    pub substrate_profile_bytes: BTreeMap<ContentDigest, Vec<u8>>,
    pub constraint_bytes: BTreeMap<ContentDigest, Vec<u8>>,
}

impl ComponentGraphArtifacts {
    pub fn insert_component(&mut self, id: impl Into<String>, bytes: Vec<u8>) {
        self.component_bytes.insert(id.into(), bytes);
    }

    pub fn insert_derived_component(&mut self, bytes: Vec<u8>) -> ContentDigest {
        let digest = ContentDigest::from_bytes(&bytes);
        self.derived_component_bytes.insert(digest.clone(), bytes);
        digest
    }

    pub fn insert_scoped_component(&mut self, bytes: Vec<u8>) -> ContentDigest {
        let digest = ContentDigest::from_bytes(&bytes);
        self.scoped_component_bytes.insert(digest.clone(), bytes);
        digest
    }

    pub fn insert_derivation_descriptor(
        &mut self,
        descriptor: &ComponentDerivationDescriptorV1,
    ) -> Result<ContentDigest, ComponentGraphDigestError> {
        let bytes = descriptor.canonical_bytes()?;
        let digest = ContentDigest::from_bytes(&bytes);
        self.derivation_descriptor_bytes
            .insert(digest.clone(), bytes);
        Ok(digest)
    }

    pub fn insert_derivation_descriptor_v2(
        &mut self,
        descriptor: &ComponentDerivationDescriptorV2,
    ) -> Result<ContentDigest, ComponentGraphDigestError> {
        let bytes = descriptor.canonical_bytes()?;
        let digest = ContentDigest::from_bytes(&bytes);
        self.derivation_descriptor_bytes
            .insert(digest.clone(), bytes);
        Ok(digest)
    }

    pub fn insert_composition_config(&mut self, bytes: Vec<u8>) -> ContentDigest {
        let digest = ContentDigest::from_bytes(&bytes);
        self.composition_config_bytes.insert(digest.clone(), bytes);
        digest
    }

    pub fn insert_metadata(
        &mut self,
        metadata: &ComponentGraphMetadataV1,
    ) -> Result<ContentDigest, ComponentGraphDigestError> {
        let bytes = metadata.canonical_bytes()?;
        let digest = ContentDigest::from_bytes(&bytes);
        self.metadata_bytes.insert(digest.clone(), bytes);
        Ok(digest)
    }

    pub fn insert_substrate_profile(
        &mut self,
        profile: &SubstrateProfileV1,
    ) -> Result<ContentDigest, ComponentGraphDigestError> {
        let bytes = profile.canonical_bytes()?;
        let digest = ContentDigest::from_bytes(&bytes);
        self.substrate_profile_bytes.insert(digest.clone(), bytes);
        Ok(digest)
    }

    pub fn insert_substrate_profile_v2(
        &mut self,
        profile: &SubstrateProfileV2,
    ) -> Result<ContentDigest, ComponentGraphDigestError> {
        let bytes = profile.canonical_bytes()?;
        let digest = ContentDigest::from_bytes(&bytes);
        self.substrate_profile_bytes.insert(digest.clone(), bytes);
        Ok(digest)
    }

    pub fn insert_substrate_profile_v3(
        &mut self,
        profile: &SubstrateProfileV3,
    ) -> Result<ContentDigest, ComponentGraphDigestError> {
        let bytes = profile.canonical_bytes()?;
        let digest = ContentDigest::from_bytes(&bytes);
        self.substrate_profile_bytes.insert(digest.clone(), bytes);
        Ok(digest)
    }

    pub fn insert_wit_world(&mut self, bytes: Vec<u8>) -> ContentDigest {
        let digest = ContentDigest::from_bytes(&bytes);
        self.wit_world_bytes.insert(digest.clone(), bytes);
        digest
    }

    pub fn insert_wit_package(&mut self, bytes: Vec<u8>) -> ContentDigest {
        let digest = ContentDigest::from_bytes(&bytes);
        self.wit_package_bytes.insert(digest.clone(), bytes);
        digest
    }

    pub fn insert_constraints(&mut self, bytes: Vec<u8>) -> ContentDigest {
        let digest = ContentDigest::from_bytes(&bytes);
        self.constraint_bytes.insert(digest.clone(), bytes);
        digest
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedComponentGraph {
    pub manifest_digest: ContentDigest,
    pub component_digests: BTreeMap<String, ContentDigest>,
    pub wit_package_digest: ContentDigest,
    pub substrate_profile_digest: ContentDigest,
    pub derivation_descriptor_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ComponentGraphViolation {
    SchemaMismatch {
        subject: String,
        expected: String,
        actual: String,
    },
    InvalidNodeId {
        field: String,
        value: String,
    },
    EmptyValue {
        field: String,
    },
    NonCanonicalOrder {
        field: String,
    },
    ManifestDigestMismatch {
        expected: ContentDigest,
        actual: ContentDigest,
    },
    MissingMetadata,
    MissingArtifact {
        subject: String,
        digest: ContentDigest,
    },
    ArtifactDigestMismatch {
        subject: String,
        expected: ContentDigest,
        actual: ContentDigest,
    },
    InvalidArtifact {
        subject: String,
        reason: String,
    },
    DuplicateNodeId {
        node_id: String,
    },
    UnknownRoot {
        node_id: String,
    },
    RootKindMismatch {
        node_id: String,
        kind: FactoryComponentKind,
    },
    KindWorldMismatch {
        node_id: String,
        expected: String,
        actual: String,
    },
    MissingRequiredSemantic {
        kind: FactoryComponentKind,
    },
    DuplicateRequiredSemantic {
        kind: FactoryComponentKind,
        node_ids: Vec<String>,
    },
    MissingComponentBytes {
        node_id: String,
    },
    UnexpectedComponentBytes {
        node_id: String,
    },
    ComponentDigestMismatch {
        node_id: String,
        expected: ContentDigest,
        actual: ContentDigest,
    },
    NonComponentExecutable {
        node_id: String,
    },
    InvalidComponent {
        node_id: String,
        reason: String,
    },
    MissingWorldDigest {
        node_id: String,
        world: String,
    },
    WitSurfaceMismatch {
        node_id: String,
        surface: String,
        wit: Vec<String>,
        component: Vec<String>,
    },
    DeclaredExportMismatch {
        node_id: String,
        declared: Vec<String>,
        actual: Vec<String>,
    },
    DuplicateBinding {
        consumer: String,
        import_name: String,
    },
    UnknownBindingConsumer {
        consumer: String,
        import_name: String,
    },
    UndeclaredImport {
        node_id: String,
        import_name: String,
    },
    BindingWithoutImport {
        node_id: String,
        import_name: String,
    },
    UnknownComponentProvider {
        consumer: String,
        provider: String,
    },
    MissingProviderExport {
        consumer: String,
        provider: String,
        export_name: String,
    },
    DuplicateInvocation {
        consumer: String,
        target: String,
        export_name: String,
    },
    UnknownInvocationConsumer {
        consumer: String,
    },
    UnknownInvocationTarget {
        consumer: String,
        target: String,
    },
    MissingInvocationExport {
        consumer: String,
        target: String,
        export_name: String,
    },
    InvocationWithoutRunnerImport {
        consumer: String,
    },
    InvocationWithoutRunnerBinding {
        consumer: String,
    },
    InvocationWithoutRunnerGrant {
        consumer: String,
    },
    RunnerImportWithoutInvocation {
        consumer: String,
    },
    MissingWorkerInvocation {
        worker_kind: FactoryComponentKind,
    },
    DuplicateWorkerInvocation {
        worker_kind: FactoryComponentKind,
        target_ids: Vec<String>,
    },
    InvalidWorkerInvocation {
        target: String,
        export_name: String,
    },
    InvalidHostImportName {
        consumer: String,
        import_name: String,
        capability: SubstratePrimitive,
        expected: String,
    },
    MissingHostGrant {
        consumer: String,
        capability: SubstratePrimitive,
    },
    DuplicateGrant {
        node_id: String,
        capability: SubstratePrimitive,
        scope: String,
    },
    MissingConstraintBytes {
        node_id: String,
        digest: ContentDigest,
    },
    DependencyCycle {
        node_ids: Vec<String>,
    },
    UnreachableNode {
        node_id: String,
    },
    SubstrateProfileMismatch {
        expected: Vec<SubstratePrimitive>,
        actual: Vec<SubstratePrimitive>,
    },
    StaticGrantProfileMismatch {
        node_id: String,
        capability: SubstratePrimitive,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComponentGraphValidationError {
    pub violations: Vec<ComponentGraphViolation>,
}

impl ComponentGraphValidationError {
    pub fn contains(&self, predicate: impl Fn(&ComponentGraphViolation) -> bool) -> bool {
        self.violations.iter().any(predicate)
    }
}

impl Display for ComponentGraphValidationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "component graph validation failed with {} violation(s)",
            self.violations.len()
        )
    }
}

impl Error for ComponentGraphValidationError {}

#[derive(Clone, Debug, Default)]
struct ObservedSurface {
    imports: BTreeSet<String>,
    exports: BTreeSet<String>,
}

/// Actual Component Model effect surface observed from exact binary bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentSurfaceEvidenceV1 {
    pub imports: Vec<String>,
    pub exports: Vec<String>,
}

/// Compiles exact bytes and returns their non-type-only Component Model
/// imports and exports. Release tooling uses this to seal a human-readable
/// import-resolution report in addition to strict admission.
pub fn inspect_component_surface(bytes: &[u8]) -> Result<ComponentSurfaceEvidenceV1, String> {
    component_encoding(bytes).map_err(|error| format!("{error:?}"))?;
    let engine = component_engine()?;
    let observed = observe_component_surface(bytes, &engine)?;
    Ok(ComponentSurfaceEvidenceV1 {
        imports: observed.imports.into_iter().collect(),
        exports: observed.exports.into_iter().collect(),
    })
}

pub fn validate_component_graph(
    graph: &AddressedComponentGraphV1,
    artifacts: &ComponentGraphArtifacts,
) -> Result<ValidatedComponentGraph, ComponentGraphValidationError> {
    let mut validator = GraphValidator::new(graph, artifacts);
    validator.validate();
    if !validator.violations.is_empty() {
        return Err(ComponentGraphValidationError {
            violations: validator.violations,
        });
    }
    let metadata = validator.metadata.expect("metadata validated");
    Ok(ValidatedComponentGraph {
        manifest_digest: graph.manifest_digest.clone(),
        component_digests: graph
            .manifest
            .nodes
            .iter()
            .map(|node| (node.id.clone(), node.component_digest.clone()))
            .collect(),
        wit_package_digest: metadata.wit_package_digest,
        substrate_profile_digest: metadata.substrate_profile_digest,
        derivation_descriptor_digest: metadata.derivation_descriptor_digest,
    })
}

#[derive(Clone, Debug)]
enum LoadedDerivationDescriptor {
    V1(ComponentDerivationDescriptorV1),
    V2(ComponentDerivationDescriptorV2),
}

#[derive(Clone, Debug)]
enum LoadedSubstrateProfile {
    V1(SubstrateProfileV1),
    V2(SubstrateProfileV2),
    V3(SubstrateProfileV3),
}

struct GraphValidator<'a> {
    graph: &'a AddressedComponentGraphV1,
    artifacts: &'a ComponentGraphArtifacts,
    nodes: BTreeMap<&'a str, &'a FactoryComponentV1>,
    observed: BTreeMap<&'a str, ObservedSurface>,
    metadata: Option<ComponentGraphMetadataV1>,
    derivation: Option<LoadedDerivationDescriptor>,
    substrate_profile: Option<LoadedSubstrateProfile>,
    violations: Vec<ComponentGraphViolation>,
}

impl<'a> GraphValidator<'a> {
    fn new(graph: &'a AddressedComponentGraphV1, artifacts: &'a ComponentGraphArtifacts) -> Self {
        Self {
            graph,
            artifacts,
            nodes: BTreeMap::new(),
            observed: BTreeMap::new(),
            metadata: None,
            derivation: None,
            substrate_profile: None,
            violations: Vec::new(),
        }
    }

    fn validate(&mut self) {
        self.validate_manifest_identity();
        self.index_and_validate_nodes();
        self.validate_semantic_coverage();
        self.load_metadata_and_substrate();
        self.validate_components_and_worlds();
        self.validate_bindings_and_grants();
        self.validate_static_grant_profile();
        self.validate_derivation_descriptor();
        self.validate_reachability();
    }

    fn validate_manifest_identity(&mut self) {
        let manifest = &self.graph.manifest;
        if manifest.schema != COMPONENT_GRAPH_SCHEMA_V1 {
            self.schema_mismatch("factory graph", COMPONENT_GRAPH_SCHEMA_V1, &manifest.schema);
        }
        if manifest.wit_package != FACTORY_WIT_PACKAGE_V1 {
            self.schema_mismatch("WIT package", FACTORY_WIT_PACKAGE_V1, &manifest.wit_package);
        }
        check_node_id(&mut self.violations, "root_node", &manifest.root_node);
        check_nonempty(&mut self.violations, "state_schema", &manifest.state_schema);
        if !strictly_sorted_by(&manifest.nodes, |node| node.id.as_str()) {
            noncanonical(&mut self.violations, "nodes");
        }
        if !strictly_sorted_binding(&manifest.bindings) {
            noncanonical(&mut self.violations, "bindings");
        }
        if !strictly_sorted_invocations(&manifest.invocations) {
            noncanonical(&mut self.violations, "invocations");
        }
        match manifest.content_digest() {
            Ok(actual) if actual != self.graph.manifest_digest => {
                self.violations
                    .push(ComponentGraphViolation::ManifestDigestMismatch {
                        expected: self.graph.manifest_digest.clone(),
                        actual,
                    });
            }
            Err(error) => self
                .violations
                .push(ComponentGraphViolation::InvalidArtifact {
                    subject: "factory graph".to_string(),
                    reason: error.to_string(),
                }),
            Ok(_) => {}
        }
    }

    fn index_and_validate_nodes(&mut self) {
        for node in &self.graph.manifest.nodes {
            if self.nodes.insert(node.id.as_str(), node).is_some() {
                self.violations
                    .push(ComponentGraphViolation::DuplicateNodeId {
                        node_id: node.id.clone(),
                    });
            }
            check_node_id(&mut self.violations, "node.id", &node.id);
            if node.world != node.kind.expected_world() {
                self.violations
                    .push(ComponentGraphViolation::KindWorldMismatch {
                        node_id: node.id.clone(),
                        expected: node.kind.expected_world().to_string(),
                        actual: node.world.clone(),
                    });
            }
            if !strictly_sorted_strings(&node.exports) {
                noncanonical(&mut self.violations, &format!("node[{}].exports", node.id));
            }
            if !strictly_sorted_grants(&node.grants) {
                noncanonical(&mut self.violations, &format!("node[{}].grants", node.id));
            }
            if let Some(state_schema) = &node.state_schema {
                check_nonempty(
                    &mut self.violations,
                    &format!("node[{}].state_schema", node.id),
                    state_schema,
                );
            }
            let mut grants = BTreeSet::new();
            for grant in &node.grants {
                check_nonempty(
                    &mut self.violations,
                    &format!("node[{}].grant.scope", node.id),
                    &grant.scope,
                );
                if !grants.insert((grant.capability, grant.scope.as_str())) {
                    self.violations
                        .push(ComponentGraphViolation::DuplicateGrant {
                            node_id: node.id.clone(),
                            capability: grant.capability,
                            scope: grant.scope.clone(),
                        });
                }
                match self.artifacts.constraint_bytes.get(&grant.constraints) {
                    Some(bytes) if ContentDigest::from_bytes(bytes) == grant.constraints => {
                        let subject = format!("constraints for {}", node.id);
                        let schema = serde_json::from_slice::<Value>(bytes)
                            .ok()
                            .and_then(|value| value.get("schema")?.as_str().map(str::to_string));
                        match schema.as_deref() {
                            Some(CAPABILITY_CONSTRAINTS_SCHEMA_V1) => {
                                match serde_json::from_slice::<CapabilityConstraintsV1>(bytes) {
                                    Ok(constraints) => {
                                        if constraints
                                            .canonical_bytes()
                                            .is_ok_and(|canonical| canonical != *bytes)
                                        {
                                            self.violations.push(
                                                ComponentGraphViolation::InvalidArtifact {
                                                    subject: subject.clone(),
                                                    reason:
                                                        "constraint bytes are not canonical JSON"
                                                            .to_string(),
                                                },
                                            );
                                        }
                                        self.validate_constraint_document(&subject, &constraints);
                                    }
                                    Err(error) => self.violations.push(
                                        ComponentGraphViolation::InvalidArtifact {
                                            subject: subject.clone(),
                                            reason: error.to_string(),
                                        },
                                    ),
                                }
                            }
                            Some(HTTP_TRANSPORT_CONSTRAINTS_SCHEMA_V1) => {
                                match serde_json::from_slice::<HttpTransportConstraintsV1>(bytes) {
                                    Ok(constraints) => {
                                        if constraints
                                            .canonical_bytes()
                                            .is_ok_and(|canonical| canonical != *bytes)
                                        {
                                            self.violations.push(
                                                ComponentGraphViolation::InvalidArtifact {
                                                    subject: subject.clone(),
                                                    reason:
                                                        "constraint bytes are not canonical JSON"
                                                            .to_string(),
                                                },
                                            );
                                        }
                                        if grant.capability != SubstratePrimitive::HttpTransport {
                                            self.violations.push(
                                                ComponentGraphViolation::InvalidArtifact {
                                                    subject: subject.clone(),
                                                    reason: "HTTP transport constraints may bind only an http-transport grant"
                                                        .to_string(),
                                                },
                                            );
                                        }
                                    }
                                    Err(error) => self.violations.push(
                                        ComponentGraphViolation::InvalidArtifact {
                                            subject: subject.clone(),
                                            reason: error.to_string(),
                                        },
                                    ),
                                }
                            }
                            _ => self
                                .violations
                                .push(ComponentGraphViolation::InvalidArtifact {
                                    subject,
                                    reason: "unsupported constraint document schema".to_string(),
                                }),
                        }
                    }
                    Some(bytes) => {
                        self.violations
                            .push(ComponentGraphViolation::ArtifactDigestMismatch {
                                subject: format!("constraints for {}", node.id),
                                expected: grant.constraints.clone(),
                                actual: ContentDigest::from_bytes(bytes),
                            })
                    }
                    None => self
                        .violations
                        .push(ComponentGraphViolation::MissingConstraintBytes {
                            node_id: node.id.clone(),
                            digest: grant.constraints.clone(),
                        }),
                }
            }
        }
        let referenced_constraints = self
            .graph
            .manifest
            .nodes
            .iter()
            .flat_map(|node| node.grants.iter().map(|grant| grant.constraints.clone()))
            .collect::<BTreeSet<_>>();
        let supplied_constraints = self
            .artifacts
            .constraint_bytes
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        if referenced_constraints != supplied_constraints {
            self.violations
                .push(ComponentGraphViolation::InvalidArtifact {
                    subject: "constraint artifact set".to_string(),
                    reason:
                        "constraint artifacts must exactly equal the unique manifest grant digests"
                            .to_string(),
                });
        }
        match self.nodes.get(self.graph.manifest.root_node.as_str()) {
            None => self.violations.push(ComponentGraphViolation::UnknownRoot {
                node_id: self.graph.manifest.root_node.clone(),
            }),
            Some(node) if node.kind != FactoryComponentKind::Root => {
                self.violations
                    .push(ComponentGraphViolation::RootKindMismatch {
                        node_id: node.id.clone(),
                        kind: node.kind,
                    });
            }
            Some(_) => {}
        }
    }

    fn validate_semantic_coverage(&mut self) {
        let mut owners = BTreeMap::<FactoryComponentKind, Vec<String>>::new();
        for node in &self.graph.manifest.nodes {
            if node.kind.is_required() {
                owners.entry(node.kind).or_default().push(node.id.clone());
            }
        }
        for kind in REQUIRED_FACTORY_COMPONENT_KINDS {
            match owners.get(&kind) {
                None => self
                    .violations
                    .push(ComponentGraphViolation::MissingRequiredSemantic { kind }),
                Some(node_ids) if node_ids.len() > 1 => {
                    self.violations
                        .push(ComponentGraphViolation::DuplicateRequiredSemantic {
                            kind,
                            node_ids: node_ids.clone(),
                        })
                }
                Some(_) => {}
            }
        }
    }

    fn validate_constraint_document(
        &mut self,
        subject: &str,
        constraints: &CapabilityConstraintsV1,
    ) {
        if constraints.schema != CAPABILITY_CONSTRAINTS_SCHEMA_V1 {
            self.schema_mismatch(
                subject,
                CAPABILITY_CONSTRAINTS_SCHEMA_V1,
                &constraints.schema,
            );
        }
        if constraints.max_blob_bytes == 0
            || constraints.max_total_blob_bytes < constraints.max_blob_bytes
            || constraints.max_random_bytes == 0
            || constraints.max_wake_delay_ms == 0
            || constraints.max_http_timeout_ms == 0
            || constraints.max_component_fuel == 0
            || constraints.max_component_memory_bytes == 0
            || constraints.max_component_output_bytes == 0
            || constraints.max_component_wall_time_ms == 0
            || !strictly_sorted_strings(&constraints.transaction_namespaces)
            || constraints
                .transaction_namespaces
                .iter()
                .any(|namespace| namespace.trim().is_empty())
        {
            self.violations.push(ComponentGraphViolation::InvalidArtifact {
                subject: subject.to_string(),
                reason: "constraint ceilings must be positive, cumulative blob quota must cover one blob, and namespaces must be non-empty/canonical"
                    .to_string(),
            });
        }
    }

    fn load_metadata_and_substrate(&mut self) {
        let Some(metadata_digest) = &self.graph.manifest.metadata else {
            self.violations
                .push(ComponentGraphViolation::MissingMetadata);
            return;
        };
        let Some(metadata_bytes) = verified_artifact(
            &mut self.violations,
            "graph metadata",
            metadata_digest,
            &self.artifacts.metadata_bytes,
        ) else {
            return;
        };
        let metadata: ComponentGraphMetadataV1 = match serde_json::from_slice(metadata_bytes) {
            Ok(metadata) => metadata,
            Err(error) => {
                self.violations
                    .push(ComponentGraphViolation::InvalidArtifact {
                        subject: "graph metadata".to_string(),
                        reason: error.to_string(),
                    });
                return;
            }
        };
        if metadata.schema != GRAPH_METADATA_SCHEMA_V1 {
            self.schema_mismatch("graph metadata", GRAPH_METADATA_SCHEMA_V1, &metadata.schema);
        }
        verified_artifact(
            &mut self.violations,
            "WIT package",
            &metadata.wit_package_digest,
            &self.artifacts.wit_package_bytes,
        );
        if let Some(descriptor_bytes) = verified_artifact(
            &mut self.violations,
            "component derivation descriptor",
            &metadata.derivation_descriptor_digest,
            &self.artifacts.derivation_descriptor_bytes,
        ) {
            let schema = serde_json::from_slice::<Value>(descriptor_bytes)
                .ok()
                .and_then(|value| value.get("schema")?.as_str().map(str::to_string));
            let parsed = match schema.as_deref() {
                Some(DERIVATION_DESCRIPTOR_SCHEMA_V1) => {
                    serde_json::from_slice::<ComponentDerivationDescriptorV1>(descriptor_bytes)
                        .map(LoadedDerivationDescriptor::V1)
                }
                Some(DERIVATION_DESCRIPTOR_SCHEMA_V2) => {
                    serde_json::from_slice::<ComponentDerivationDescriptorV2>(descriptor_bytes)
                        .map(LoadedDerivationDescriptor::V2)
                }
                _ => Err(serde_json::Error::io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unsupported component derivation descriptor schema",
                ))),
            };
            match parsed {
                Ok(descriptor) => {
                    let (canonical, wit_digest) = match &descriptor {
                        LoadedDerivationDescriptor::V1(value) => {
                            (value.canonical_bytes(), &value.wit_package_digest)
                        }
                        LoadedDerivationDescriptor::V2(value) => {
                            (value.canonical_bytes(), &value.wit_package_digest)
                        }
                    };
                    if canonical.is_ok_and(|canonical| canonical != descriptor_bytes) {
                        self.violations
                            .push(ComponentGraphViolation::InvalidArtifact {
                                subject: "component derivation descriptor".to_string(),
                                reason: "descriptor bytes are not canonical JSON".to_string(),
                            });
                    }
                    if *wit_digest != metadata.wit_package_digest {
                        self.violations
                            .push(ComponentGraphViolation::InvalidArtifact {
                                subject: "component derivation descriptor".to_string(),
                                reason:
                                    "descriptor WIT package digest does not match graph metadata"
                                        .to_string(),
                            });
                    }
                    self.derivation = Some(descriptor);
                }
                Err(error) => self
                    .violations
                    .push(ComponentGraphViolation::InvalidArtifact {
                        subject: "component derivation descriptor".to_string(),
                        reason: error.to_string(),
                    }),
            }
        }
        if let Some(profile_bytes) = verified_artifact(
            &mut self.violations,
            "substrate profile",
            &metadata.substrate_profile_digest,
            &self.artifacts.substrate_profile_bytes,
        ) {
            let schema = serde_json::from_slice::<Value>(profile_bytes)
                .ok()
                .and_then(|value| value.get("schema")?.as_str().map(str::to_string));
            let parsed = match schema.as_deref() {
                Some(SUBSTRATE_PROFILE_SCHEMA_V1) => {
                    serde_json::from_slice::<SubstrateProfileV1>(profile_bytes)
                        .map(LoadedSubstrateProfile::V1)
                }
                Some(SUBSTRATE_PROFILE_SCHEMA_V2) => {
                    serde_json::from_slice::<SubstrateProfileV2>(profile_bytes)
                        .map(LoadedSubstrateProfile::V2)
                }
                Some(SUBSTRATE_PROFILE_SCHEMA_V3) => {
                    serde_json::from_slice::<SubstrateProfileV3>(profile_bytes)
                        .map(LoadedSubstrateProfile::V3)
                }
                _ => Err(serde_json::Error::io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unsupported substrate profile schema",
                ))),
            };
            match parsed {
                Ok(profile) => {
                    let (canonical, wit_package, primitives, ceilings) = match &profile {
                        LoadedSubstrateProfile::V1(value) => (
                            value.canonical_bytes(),
                            &value.wit_package,
                            &value.primitives,
                            &value.ceilings,
                        ),
                        LoadedSubstrateProfile::V2(value) => (
                            value.canonical_bytes(),
                            &value.wit_package,
                            &value.primitives,
                            &value.ceilings,
                        ),
                        LoadedSubstrateProfile::V3(value) => (
                            value.canonical_bytes(),
                            &value.wit_package,
                            &value.primitives,
                            &value.ceilings,
                        ),
                    };
                    if canonical.is_ok_and(|canonical| canonical != profile_bytes) {
                        self.violations
                            .push(ComponentGraphViolation::InvalidArtifact {
                                subject: "substrate profile".to_string(),
                                reason: "profile bytes are not canonical JSON".to_string(),
                            });
                    }
                    if wit_package != FACTORY_WIT_PACKAGE_V1 {
                        self.schema_mismatch(
                            "substrate profile WIT package",
                            FACTORY_WIT_PACKAGE_V1,
                            wit_package,
                        );
                    }
                    if *primitives != REQUIRED_SUBSTRATE_PRIMITIVES {
                        self.violations
                            .push(ComponentGraphViolation::SubstrateProfileMismatch {
                                expected: REQUIRED_SUBSTRATE_PRIMITIVES.to_vec(),
                                actual: primitives.clone(),
                            });
                    }
                    self.validate_constraint_document("substrate profile ceilings", ceilings);
                    self.substrate_profile = Some(profile);
                }
                Err(error) => self
                    .violations
                    .push(ComponentGraphViolation::InvalidArtifact {
                        subject: "substrate profile".to_string(),
                        reason: error.to_string(),
                    }),
            }
        }
        self.metadata = Some(metadata);
    }

    fn validate_components_and_worlds(&mut self) {
        let engine = match component_engine() {
            Ok(engine) => Some(engine),
            Err(reason) => {
                self.violations
                    .push(ComponentGraphViolation::InvalidComponent {
                        node_id: "<engine>".to_string(),
                        reason,
                    });
                None
            }
        };
        for node in &self.graph.manifest.nodes {
            let Some(bytes) = self.artifacts.component_bytes.get(&node.id) else {
                self.violations
                    .push(ComponentGraphViolation::MissingComponentBytes {
                        node_id: node.id.clone(),
                    });
                continue;
            };
            let actual_digest = ContentDigest::from_bytes(bytes);
            if actual_digest != node.component_digest {
                self.violations
                    .push(ComponentGraphViolation::ComponentDigestMismatch {
                        node_id: node.id.clone(),
                        expected: node.component_digest.clone(),
                        actual: actual_digest,
                    });
            }
            match component_encoding(bytes) {
                Ok(()) => {}
                Err(ComponentEncodingError::CoreModule) => {
                    self.violations
                        .push(ComponentGraphViolation::NonComponentExecutable {
                            node_id: node.id.clone(),
                        });
                    continue;
                }
                Err(ComponentEncodingError::Invalid(reason)) => {
                    self.violations
                        .push(ComponentGraphViolation::InvalidComponent {
                            node_id: node.id.clone(),
                            reason,
                        });
                    continue;
                }
            }
            if let Some(engine) = &engine {
                match Component::new(engine, bytes) {
                    Ok(component) => {
                        let ty = component.component_type();
                        let observed = ObservedSurface {
                            imports: ty
                                .imports(engine)
                                .filter_map(|(name, item)| {
                                    (!component_item_is_type_only(&item, engine))
                                        .then(|| name.to_string())
                                })
                                .collect(),
                            exports: ty
                                .exports(engine)
                                .map(|(name, _)| name.to_string())
                                .collect(),
                        };
                        let declared = node.exports.iter().cloned().collect::<BTreeSet<_>>();
                        if declared != observed.exports {
                            self.violations
                                .push(ComponentGraphViolation::DeclaredExportMismatch {
                                    node_id: node.id.clone(),
                                    declared: declared.into_iter().collect(),
                                    actual: observed.exports.iter().cloned().collect(),
                                });
                        }
                        self.observed.insert(node.id.as_str(), observed);
                    }
                    Err(error) => self
                        .violations
                        .push(ComponentGraphViolation::InvalidComponent {
                            node_id: node.id.clone(),
                            reason: error.to_string(),
                        }),
                }
            }
            self.validate_node_world(node);
        }
        for node_id in self.artifacts.component_bytes.keys() {
            if !self.nodes.contains_key(node_id.as_str()) {
                self.violations
                    .push(ComponentGraphViolation::UnexpectedComponentBytes {
                        node_id: node_id.clone(),
                    });
            }
        }
    }

    fn validate_node_world(&mut self, node: &FactoryComponentV1) {
        let Some(metadata) = &self.metadata else {
            return;
        };
        let Some(world_digest) = metadata.wit_world_digests.get(&node.world) else {
            self.violations
                .push(ComponentGraphViolation::MissingWorldDigest {
                    node_id: node.id.clone(),
                    world: node.world.clone(),
                });
            return;
        };
        let Some(world_bytes) = verified_artifact(
            &mut self.violations,
            &format!("WIT world for {}", node.id),
            world_digest,
            &self.artifacts.wit_world_bytes,
        ) else {
            return;
        };
        let Some(short_world) = world_name_from_ref(&node.world) else {
            self.violations
                .push(ComponentGraphViolation::InvalidArtifact {
                    subject: format!("WIT world reference for {}", node.id),
                    reason: format!("invalid factory world reference: {}", node.world),
                });
            return;
        };
        match parse_wit_surface(world_bytes, short_world) {
            Ok(wit) => {
                if wit.package != FACTORY_WIT_PACKAGE_V1 {
                    self.schema_mismatch(
                        &format!("WIT world package for {}", node.id),
                        FACTORY_WIT_PACKAGE_V1,
                        &wit.package,
                    );
                }
                if let Some(observed) = self.observed.get(node.id.as_str()) {
                    compare_surface(
                        &mut self.violations,
                        &node.id,
                        "imports",
                        &wit.surface.imports,
                        &observed.imports,
                    );
                    compare_surface(
                        &mut self.violations,
                        &node.id,
                        "exports",
                        &wit.surface.exports,
                        &observed.exports,
                    );
                }
            }
            Err(reason) => self
                .violations
                .push(ComponentGraphViolation::InvalidArtifact {
                    subject: format!("WIT world for {}", node.id),
                    reason,
                }),
        }
    }

    fn validate_bindings_and_grants(&mut self) {
        let mut bindings = BTreeMap::<(&str, &str), &ComponentImportBinding>::new();
        for binding in &self.graph.manifest.bindings {
            if bindings
                .insert(
                    (binding.consumer.as_str(), binding.import_name.as_str()),
                    binding,
                )
                .is_some()
            {
                self.violations
                    .push(ComponentGraphViolation::DuplicateBinding {
                        consumer: binding.consumer.clone(),
                        import_name: binding.import_name.clone(),
                    });
            }
            let Some(consumer) = self.nodes.get(binding.consumer.as_str()) else {
                self.violations
                    .push(ComponentGraphViolation::UnknownBindingConsumer {
                        consumer: binding.consumer.clone(),
                        import_name: binding.import_name.clone(),
                    });
                continue;
            };
            match &binding.provider {
                ComponentBindingProvider::Component { node, export } => {
                    match self.nodes.get(node.as_str()) {
                        None => self.violations.push(
                            ComponentGraphViolation::UnknownComponentProvider {
                                consumer: binding.consumer.clone(),
                                provider: node.clone(),
                            },
                        ),
                        Some(provider) if !provider.exports.contains(export) => {
                            self.violations
                                .push(ComponentGraphViolation::MissingProviderExport {
                                    consumer: binding.consumer.clone(),
                                    provider: node.clone(),
                                    export_name: export.clone(),
                                });
                        }
                        Some(_) => {}
                    }
                }
                ComponentBindingProvider::Host { capability } => {
                    let expected = capability.interface_name();
                    if binding.import_name != expected {
                        self.violations
                            .push(ComponentGraphViolation::InvalidHostImportName {
                                consumer: binding.consumer.clone(),
                                import_name: binding.import_name.clone(),
                                capability: *capability,
                                expected: expected.to_string(),
                            });
                    }
                    if !consumer
                        .grants
                        .iter()
                        .any(|grant| grant.capability == *capability)
                    {
                        self.violations
                            .push(ComponentGraphViolation::MissingHostGrant {
                                consumer: binding.consumer.clone(),
                                capability: *capability,
                            });
                    }
                }
            }
        }
        self.validate_invocations(&bindings);
        for node in &self.graph.manifest.nodes {
            if let Some(observed) = self.observed.get(node.id.as_str()) {
                for import_name in &observed.imports {
                    if !bindings.contains_key(&(node.id.as_str(), import_name.as_str())) {
                        self.violations
                            .push(ComponentGraphViolation::UndeclaredImport {
                                node_id: node.id.clone(),
                                import_name: import_name.clone(),
                            });
                    }
                }
                for ((consumer, import_name), _) in
                    bindings.range((node.id.as_str(), "")..=(node.id.as_str(), "\u{10ffff}"))
                {
                    if *consumer == node.id && !observed.imports.contains(*import_name) {
                        self.violations
                            .push(ComponentGraphViolation::BindingWithoutImport {
                                node_id: node.id.clone(),
                                import_name: (*import_name).to_string(),
                            });
                    }
                }
            }
        }
    }

    fn validate_invocations(&mut self, bindings: &BTreeMap<(&str, &str), &ComponentImportBinding>) {
        const COMPONENT_TASK_EXPORT: &str = "wasm-biotic:factory/component-task@0.1.0";
        let runner_import = SubstratePrimitive::ComponentRunner.interface_name();
        let mut seen = BTreeSet::new();

        for invocation in &self.graph.manifest.invocations {
            if !seen.insert((
                invocation.consumer.as_str(),
                invocation.target.as_str(),
                invocation.export.as_str(),
            )) {
                self.violations
                    .push(ComponentGraphViolation::DuplicateInvocation {
                        consumer: invocation.consumer.clone(),
                        target: invocation.target.clone(),
                        export_name: invocation.export.clone(),
                    });
            }

            let Some(consumer) = self.nodes.get(invocation.consumer.as_str()) else {
                self.violations
                    .push(ComponentGraphViolation::UnknownInvocationConsumer {
                        consumer: invocation.consumer.clone(),
                    });
                continue;
            };
            let Some(target) = self.nodes.get(invocation.target.as_str()) else {
                self.violations
                    .push(ComponentGraphViolation::UnknownInvocationTarget {
                        consumer: invocation.consumer.clone(),
                        target: invocation.target.clone(),
                    });
                continue;
            };

            if !target.exports.contains(&invocation.export) {
                self.violations
                    .push(ComponentGraphViolation::MissingInvocationExport {
                        consumer: invocation.consumer.clone(),
                        target: invocation.target.clone(),
                        export_name: invocation.export.clone(),
                    });
            }
            if self
                .observed
                .get(consumer.id.as_str())
                .is_some_and(|surface| !surface.imports.contains(runner_import))
            {
                self.violations
                    .push(ComponentGraphViolation::InvocationWithoutRunnerImport {
                        consumer: invocation.consumer.clone(),
                    });
            }
            let runner_is_bound = bindings
                .get(&(invocation.consumer.as_str(), runner_import))
                .is_some_and(|binding| {
                    matches!(
                        &binding.provider,
                        ComponentBindingProvider::Host {
                            capability: SubstratePrimitive::ComponentRunner
                        }
                    )
                });
            if !runner_is_bound {
                self.violations
                    .push(ComponentGraphViolation::InvocationWithoutRunnerBinding {
                        consumer: invocation.consumer.clone(),
                    });
            }
            if !consumer
                .grants
                .iter()
                .any(|grant| grant.capability == SubstratePrimitive::ComponentRunner)
            {
                self.violations
                    .push(ComponentGraphViolation::InvocationWithoutRunnerGrant {
                        consumer: invocation.consumer.clone(),
                    });
            }

            if consumer.kind == FactoryComponentKind::WorkerRouter
                && (target.kind.worker_role().is_none()
                    || invocation.export != COMPONENT_TASK_EXPORT)
            {
                self.violations
                    .push(ComponentGraphViolation::InvalidWorkerInvocation {
                        target: invocation.target.clone(),
                        export_name: invocation.export.clone(),
                    });
            }
        }

        for router in self
            .nodes
            .values()
            .filter(|node| node.kind == FactoryComponentKind::WorkerRouter)
        {
            for worker_kind in [
                FactoryComponentKind::PlannerWorker,
                FactoryComponentKind::BuilderWorker,
                FactoryComponentKind::ValidatorWorker,
                FactoryComponentKind::ReviewerWorker,
                FactoryComponentKind::PackagerWorker,
                FactoryComponentKind::ContinuityWorker,
            ] {
                let target_ids = self
                    .graph
                    .manifest
                    .invocations
                    .iter()
                    .filter(|invocation| invocation.consumer == router.id)
                    .filter_map(|invocation| self.nodes.get(invocation.target.as_str()))
                    .filter(|target| target.kind == worker_kind)
                    .map(|target| target.id.clone())
                    .collect::<Vec<_>>();
                match target_ids.len() {
                    0 => self
                        .violations
                        .push(ComponentGraphViolation::MissingWorkerInvocation { worker_kind }),
                    1 => {}
                    _ => self
                        .violations
                        .push(ComponentGraphViolation::DuplicateWorkerInvocation {
                            worker_kind,
                            target_ids,
                        }),
                }
            }
        }

        for (consumer, surface) in &self.observed {
            if surface.imports.contains(runner_import)
                && !self
                    .graph
                    .manifest
                    .invocations
                    .iter()
                    .any(|edge| edge.consumer == **consumer)
            {
                self.violations
                    .push(ComponentGraphViolation::RunnerImportWithoutInvocation {
                        consumer: (*consumer).to_string(),
                    });
            }
        }
    }

    fn validate_static_grant_profile(&mut self) {
        let Some(profile) = self.substrate_profile.clone() else {
            return;
        };
        match profile {
            LoadedSubstrateProfile::V1(profile) => self.validate_static_grant_profile_v1(&profile),
            LoadedSubstrateProfile::V2(profile) => self.validate_static_grant_profile_v2(&profile),
            LoadedSubstrateProfile::V3(profile) => self.validate_static_grant_profile_v3(&profile),
        }
    }

    fn validate_static_grant_profile_v1(&mut self, profile: &SubstrateProfileV1) {
        let Some(root) = self.nodes.get(self.graph.manifest.root_node.as_str()) else {
            return;
        };

        if profile.root_grants != root.grants {
            self.violations
                .push(ComponentGraphViolation::InvalidArtifact {
                    subject: "substrate profile root grants".to_string(),
                    reason: "profile grants must exactly equal the root authority node grants"
                        .to_string(),
                });
        }
        let profile_capabilities = profile
            .root_grants
            .iter()
            .map(|grant| grant.capability)
            .collect::<Vec<_>>();
        if profile_capabilities != REQUIRED_SUBSTRATE_PRIMITIVES {
            self.violations
                .push(ComponentGraphViolation::InvalidArtifact {
                    subject: "substrate profile root grants".to_string(),
                    reason: "root grant union must contain each substrate primitive exactly once"
                        .to_string(),
                });
        }
        if profile
            .root_grants
            .iter()
            .any(|grant| grant.scope != grant.capability.canonical_scope())
        {
            self.violations
                .push(ComponentGraphViolation::InvalidArtifact {
                    subject: "substrate profile root grants".to_string(),
                    reason: "root grants must use the canonical generic mechanism scopes"
                        .to_string(),
                });
        }

        let ceiling_bytes = profile.ceilings.canonical_bytes().ok();
        for grant in &profile.root_grants {
            match self.artifacts.constraint_bytes.get(&grant.constraints) {
                Some(bytes) if ceiling_bytes.as_deref() == Some(bytes.as_slice()) => {}
                _ => self
                    .violations
                    .push(ComponentGraphViolation::InvalidArtifact {
                        subject: format!("substrate profile root grant {:?}", grant.capability),
                        reason: "root grant must reference the exact canonical profile ceilings"
                            .to_string(),
                    }),
            }
        }

        let static_nodes = self.static_component_node_closure(root.id.as_str());
        for binding in &self.graph.manifest.bindings {
            if !static_nodes.contains(binding.consumer.as_str()) {
                continue;
            }
            let ComponentBindingProvider::Host { capability } = &binding.provider else {
                continue;
            };
            let expected = profile
                .root_grants
                .iter()
                .find(|grant| grant.capability == *capability);
            let actual = self.nodes.get(binding.consumer.as_str()).and_then(|node| {
                node.grants
                    .iter()
                    .find(|grant| grant.capability == *capability)
            });
            if actual != expected {
                self.violations
                    .push(ComponentGraphViolation::StaticGrantProfileMismatch {
                        node_id: binding.consumer.clone(),
                        capability: *capability,
                    });
            }
        }
    }

    fn validate_static_grant_profile_v2(&mut self, profile: &SubstrateProfileV2) {
        self.validate_per_consumer_profile(
            &profile.root_node,
            &profile.import_alias_scheme,
            &profile.principal_id_scheme,
            &profile.principals,
            &profile.ceilings,
            None,
            "R2",
        );
    }

    fn validate_static_grant_profile_v3(&mut self, profile: &SubstrateProfileV3) {
        self.validate_per_consumer_profile(
            &profile.root_node,
            &profile.import_alias_scheme,
            &profile.principal_id_scheme,
            &profile.principals,
            &profile.ceilings,
            Some(&profile.http_transport),
            "R3",
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn validate_per_consumer_profile(
        &mut self,
        root_node: &str,
        import_alias_scheme: &str,
        principal_id_scheme: &str,
        principals: &[GraphNodePrincipalV2],
        ceilings: &CapabilityConstraintsV1,
        http_transport: Option<&HttpTransportProfileV1>,
        profile_version: &str,
    ) {
        if root_node != self.graph.manifest.root_node
            || import_alias_scheme != HOST_IMPORT_ALIAS_SCHEME_V1
            || principal_id_scheme != GRAPH_NODE_PRINCIPAL_SCHEME_V1
            || !strictly_sorted_by(principals, |principal| principal.consumer.as_str())
        {
            self.violations.push(ComponentGraphViolation::InvalidArtifact {
                subject: "substrate profile".to_string(),
                reason: format!("{profile_version} profile must use the canonical per-consumer import-alias schemes and sorted principal inventory"),
            });
        }

        let principal_consumers = principals
            .iter()
            .map(|principal| principal.consumer.as_str())
            .collect::<BTreeSet<_>>();
        let node_consumers = self.nodes.keys().copied().collect::<BTreeSet<_>>();
        if principal_consumers != node_consumers || principals.len() != self.nodes.len() {
            self.violations
                .push(ComponentGraphViolation::InvalidArtifact {
                    subject: "substrate profile principals".to_string(),
                    reason: "principal inventory must cover every manifest node exactly once"
                        .to_string(),
                });
        }

        let ceiling_bytes = ceilings.canonical_bytes().ok();
        let mut aliases = BTreeSet::new();
        let mut expected_scoped_digests = BTreeSet::new();
        for principal in principals {
            let Some(node) = self.nodes.get(principal.consumer.as_str()) else {
                continue;
            };
            let expected_seed = PrincipalSeedMaterialV1::for_node(node).principal_seed();
            if principal.authority_component_digest != node.component_digest
                || expected_seed.as_ref() != Ok(&principal.principal_seed)
                || !principal
                    .host_imports
                    .windows(2)
                    .all(|pair| pair[0] < pair[1])
            {
                self.violations
                    .push(ComponentGraphViolation::InvalidArtifact {
                        subject: format!("principal {}", node.id),
                        reason:
                            "principal authority, seed or host-import ordering is not canonical"
                                .to_string(),
                    });
            }

            let mut expected_imports = Vec::new();
            let mut expected_grants = Vec::new();
            for binding in self
                .graph
                .manifest
                .bindings
                .iter()
                .filter(|binding| binding.consumer == node.id)
            {
                let ComponentBindingProvider::Host { capability } = binding.provider else {
                    continue;
                };
                let Some(grant) = node
                    .grants
                    .iter()
                    .find(|grant| grant.capability == capability)
                else {
                    continue;
                };
                expected_grants.push(grant.clone());
                let material = HostImportAliasMaterialV1::for_binding(node, capability);
                match material.alias() {
                    Ok(alias) => expected_imports.push(PrincipalHostImportV2 {
                        alias,
                        source_import: capability.interface_name().to_string(),
                        capability,
                        scope: grant.scope.clone(),
                        constraints: grant.constraints.clone(),
                    }),
                    Err(error) => self
                        .violations
                        .push(ComponentGraphViolation::InvalidArtifact {
                            subject: format!("principal {}", node.id),
                            reason: error.to_string(),
                        }),
                }
            }
            expected_imports.sort();
            expected_grants.sort();
            let mut actual_grants = node.grants.clone();
            actual_grants.sort();
            if principal.host_imports != expected_imports || actual_grants != expected_grants {
                self.violations.push(ComponentGraphViolation::InvalidArtifact {
                    subject: format!("principal {} direct grants", node.id),
                    reason: "principal host imports and node grants must exactly equal direct host bindings"
                        .to_string(),
                });
            }

            for host_import in &principal.host_imports {
                if !aliases.insert(host_import.alias.as_str()) {
                    self.violations
                        .push(ComponentGraphViolation::InvalidArtifact {
                            subject: "substrate profile aliases".to_string(),
                            reason: format!("duplicate host import alias {}", host_import.alias),
                        });
                }
                if http_transport.is_some()
                    && host_import.capability == SubstratePrimitive::HttpTransport
                {
                    match self
                        .artifacts
                        .constraint_bytes
                        .get(&host_import.constraints)
                    {
                        Some(bytes) => {
                            match serde_json::from_slice::<HttpTransportConstraintsV1>(bytes) {
                                Ok(constraints) => {
                                    if constraints
                                        .canonical_bytes()
                                        .is_ok_and(|canonical| canonical != *bytes)
                                    {
                                        self.violations.push(
                                            ComponentGraphViolation::InvalidArtifact {
                                                subject: format!(
                                                    "principal {} HTTP transport constraints",
                                                    node.id
                                                ),
                                                reason: "HTTP transport constraint bytes are not canonical JSON"
                                                    .to_string(),
                                            },
                                        );
                                    }
                                    if let Err(reasons) = constraints.validate_against(ceilings) {
                                        self.violations.push(
                                            ComponentGraphViolation::InvalidArtifact {
                                                subject: format!(
                                                    "principal {} HTTP transport constraints",
                                                    node.id
                                                ),
                                                reason: reasons.join("; "),
                                            },
                                        );
                                    }
                                }
                                Err(error) => {
                                    self.violations
                                        .push(ComponentGraphViolation::InvalidArtifact {
                                            subject: format!(
                                                "principal {} HTTP transport constraints",
                                                node.id
                                            ),
                                            reason: error.to_string(),
                                        })
                                }
                            }
                        }
                        None => self
                            .violations
                            .push(ComponentGraphViolation::InvalidArtifact {
                                subject: format!(
                                    "principal {} HTTP transport constraints",
                                    node.id
                                ),
                                reason: "enabled HTTP import has no constraint bytes".to_string(),
                            }),
                    }
                } else {
                    match self.artifacts.constraint_bytes.get(&host_import.constraints) {
                        Some(bytes) if ceiling_bytes.as_deref() == Some(bytes.as_slice()) => {}
                        _ => self.violations.push(ComponentGraphViolation::InvalidArtifact {
                            subject: format!("principal {} host import", node.id),
                            reason: "non-HTTP host imports and all R2 imports must bind the exact profile ceiling document"
                                .to_string(),
                        }),
                    }
                }
            }

            expected_scoped_digests.insert(principal.scoped_component_digest.clone());
            let Some(scoped_bytes) = verified_artifact(
                &mut self.violations,
                &format!("scoped component for {}", node.id),
                &principal.scoped_component_digest,
                &self.artifacts.scoped_component_bytes,
            ) else {
                continue;
            };
            let Ok(scoped_surface) = inspect_component_surface(scoped_bytes) else {
                self.violations
                    .push(ComponentGraphViolation::InvalidArtifact {
                        subject: format!("scoped component for {}", node.id),
                        reason: "scoped bytes are not a valid Component Model component"
                            .to_string(),
                    });
                continue;
            };
            let Some(raw_surface) = self.observed.get(node.id.as_str()) else {
                continue;
            };
            let mut expected_surface_imports = raw_surface.imports.clone();
            for host_import in &principal.host_imports {
                expected_surface_imports.remove(&host_import.source_import);
                expected_surface_imports.insert(host_import.alias.clone());
            }
            let scoped_imports = scoped_surface.imports.into_iter().collect::<BTreeSet<_>>();
            let scoped_exports = scoped_surface.exports.into_iter().collect::<BTreeSet<_>>();
            if scoped_imports != expected_surface_imports || scoped_exports != raw_surface.exports {
                self.violations.push(ComponentGraphViolation::InvalidArtifact {
                    subject: format!("scoped component for {}", node.id),
                    reason: "scoped surface is not the exact raw surface with only direct host import names replaced"
                        .to_string(),
                });
            }
            if principal.host_imports.iter().any(|host_import| {
                scoped_imports.contains(&host_import.source_import)
                    || !scoped_imports.contains(&host_import.alias)
            }) {
                self.violations
                    .push(ComponentGraphViolation::InvalidArtifact {
                        subject: format!("scoped component for {}", node.id),
                        reason:
                            "canonical host import survived scoping or required alias is absent"
                                .to_string(),
                    });
            }
        }

        if let Some(http_transport) = http_transport {
            let projected_http_bindings = project_http_transport_bindings_v1(principals);
            if !strictly_sorted_values(&http_transport.bindings)
                || http_transport.bindings != projected_http_bindings
            {
                self.violations
                    .push(ComponentGraphViolation::InvalidArtifact {
                        subject: "substrate profile HTTP transport bindings".to_string(),
                        reason: "R3 HTTP bindings must be the exact unique sorted projection of principal http-transport imports"
                            .to_string(),
                    });
            }
            if http_transport.bindings.len() != 1
                || http_transport.bindings[0].consumer != "exchange-service"
                || self
                    .nodes
                    .get(http_transport.bindings[0].consumer.as_str())
                    .is_none_or(|node| node.kind != FactoryComponentKind::ExchangeService)
            {
                self.violations
                    .push(ComponentGraphViolation::InvalidArtifact {
                        subject: "substrate profile HTTP transport bindings".to_string(),
                        reason: "bounded R3 enables exactly the exchange-service HTTP alias"
                            .to_string(),
                    });
            }
        }

        if self
            .artifacts
            .scoped_component_bytes
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>()
            != expected_scoped_digests
        {
            self.violations
                .push(ComponentGraphViolation::InvalidArtifact {
                    subject: "scoped component artifact set".to_string(),
                    reason: "scoped artifacts must exactly equal the principal inventory"
                        .to_string(),
                });
        }
    }

    fn validate_derivation_descriptor(&mut self) {
        let Some(descriptor) = self.derivation.clone() else {
            return;
        };
        match descriptor {
            LoadedDerivationDescriptor::V1(descriptor) => {
                self.validate_derivation_descriptor_v1(&descriptor)
            }
            LoadedDerivationDescriptor::V2(descriptor) => {
                self.validate_derivation_descriptor_v2(&descriptor)
            }
        }
    }

    fn validate_derivation_descriptor_v1(&mut self, descriptor: &ComponentDerivationDescriptorV1) {
        if !matches!(self.substrate_profile, Some(LoadedSubstrateProfile::V1(_))) {
            self.violations
                .push(ComponentGraphViolation::InvalidArtifact {
                    subject: "v1 derivation descriptor".to_string(),
                    reason: "descriptor v1 requires substrate profile v1".to_string(),
                });
            return;
        }
        let expected_sources = self
            .graph
            .manifest
            .nodes
            .iter()
            .map(|node| DerivationSourceV1 {
                node_id: node.id.clone(),
                component_digest: node.component_digest.clone(),
                world: node.world.clone(),
            })
            .collect::<Vec<_>>();
        if descriptor.sources != expected_sources {
            self.violations
                .push(ComponentGraphViolation::InvalidArtifact {
                    subject: "component derivation descriptor sources".to_string(),
                    reason: "source set must exactly match sorted authoritative manifest nodes"
                        .to_string(),
                });
        }
        if descriptor.tool.name.trim().is_empty()
            || descriptor.tool.version.trim().is_empty()
            || descriptor
                .tool
                .options
                .iter()
                .any(|option| option.trim().is_empty())
        {
            self.violations
                .push(ComponentGraphViolation::InvalidArtifact {
                    subject: "component derivation tool".to_string(),
                    reason: "tool name, version and every normalized option must be non-empty"
                        .to_string(),
                });
        }
        if !strictly_sorted_by(&descriptor.executables, |item| item.authority_node.as_str()) {
            noncanonical(&mut self.violations, "derivation.executables");
        }

        let mut expected_authorities = self
            .graph
            .manifest
            .invocations
            .iter()
            .map(|edge| edge.target.clone())
            .chain(std::iter::once(self.graph.manifest.root_node.clone()))
            .collect::<Vec<_>>();
        expected_authorities.sort();
        expected_authorities.dedup();
        let actual_authorities = descriptor
            .executables
            .iter()
            .map(|item| item.authority_node.clone())
            .collect::<Vec<_>>();
        if actual_authorities != expected_authorities {
            self.violations.push(ComponentGraphViolation::InvalidArtifact {
                subject: "component derivation descriptor executables".to_string(),
                reason: "descriptor must contain exactly the root and every dynamic invocation target authority"
                    .to_string(),
            });
        }

        let engine = component_engine().ok();
        let allowed_host_imports = REQUIRED_SUBSTRATE_PRIMITIVES
            .iter()
            .map(|primitive| primitive.interface_name().to_string())
            .collect::<BTreeSet<_>>();
        let mut referenced_executables = BTreeSet::new();
        let mut referenced_configs = BTreeSet::new();
        for executable in &descriptor.executables {
            referenced_executables.insert(executable.executable_digest.clone());
            referenced_configs.insert(executable.configuration_digest.clone());
            let Some(authority) = self.nodes.get(executable.authority_node.as_str()) else {
                self.violations
                    .push(ComponentGraphViolation::InvalidArtifact {
                        subject: format!(
                            "derived executable authority {}",
                            executable.authority_node
                        ),
                        reason: "authority node is absent from manifest".to_string(),
                    });
                continue;
            };
            if executable.authority_digest != authority.component_digest
                || executable.world != authority.world
            {
                self.violations
                    .push(ComponentGraphViolation::InvalidArtifact {
                        subject: format!("derived executable for {}", authority.id),
                        reason: "authority digest or world differs from raw manifest node"
                            .to_string(),
                    });
            }
            if executable.grants != authority.grants || !strictly_sorted_grants(&executable.grants)
            {
                self.violations.push(ComponentGraphViolation::InvalidArtifact {
                    subject: format!("derived executable grants for {}", authority.id),
                    reason: "descriptor grants must be canonical and exactly equal the authority node grants"
                        .to_string(),
                });
            }
            let expected_closure = self.static_component_closure(authority.id.as_str());
            if executable.source_digests != expected_closure {
                self.violations
                    .push(ComponentGraphViolation::InvalidArtifact {
                        subject: format!("derived executable closure for {}", authority.id),
                        reason: "source digests are not the complete sorted static binding closure"
                            .to_string(),
                    });
            }
            verified_artifact(
                &mut self.violations,
                &format!("composition config for {}", authority.id),
                &executable.configuration_digest,
                &self.artifacts.composition_config_bytes,
            );
            let Some(bytes) = verified_artifact(
                &mut self.violations,
                &format!("derived executable for {}", authority.id),
                &executable.executable_digest,
                &self.artifacts.derived_component_bytes,
            ) else {
                continue;
            };
            if let Err(error) = component_encoding(bytes) {
                self.violations
                    .push(ComponentGraphViolation::InvalidArtifact {
                        subject: format!("derived executable for {}", authority.id),
                        reason: format!("not a Component Model component: {error:?}"),
                    });
                continue;
            }
            let Some(engine) = &engine else {
                continue;
            };
            match observe_component_surface(bytes, engine) {
                Ok(surface) => {
                    let declared_exports =
                        authority.exports.iter().cloned().collect::<BTreeSet<_>>();
                    if surface.exports != declared_exports {
                        self.violations
                            .push(ComponentGraphViolation::InvalidArtifact {
                                subject: format!("derived executable for {}", authority.id),
                                reason: "derived exports differ from raw authority exports"
                                    .to_string(),
                            });
                    }
                    if !surface.imports.is_subset(&allowed_host_imports) {
                        self.violations
                            .push(ComponentGraphViolation::InvalidArtifact {
                                subject: format!("derived executable for {}", authority.id),
                                reason: format!(
                                    "derived executable retains non-substrate imports: {:?}",
                                    surface
                                        .imports
                                        .difference(&allowed_host_imports)
                                        .collect::<Vec<_>>()
                                ),
                            });
                    }
                    let residual_capabilities = surface
                        .imports
                        .iter()
                        .filter_map(|name| {
                            REQUIRED_SUBSTRATE_PRIMITIVES
                                .iter()
                                .copied()
                                .find(|primitive| primitive.interface_name() == name)
                        })
                        .collect::<BTreeSet<_>>();
                    let granted_capabilities = executable
                        .grants
                        .iter()
                        .map(|grant| grant.capability)
                        .collect::<BTreeSet<_>>();
                    if residual_capabilities != granted_capabilities {
                        self.violations
                            .push(ComponentGraphViolation::InvalidArtifact {
                            subject: format!("derived executable grants for {}", authority.id),
                            reason:
                                "grant capabilities must exactly equal residual substrate imports"
                                    .to_string(),
                        });
                    }
                    if authority.kind == FactoryComponentKind::Root
                        && surface.imports != allowed_host_imports
                    {
                        self.violations
                            .push(ComponentGraphViolation::InvalidArtifact {
                                subject: "derived factory root".to_string(),
                                reason:
                                    "factory root must expose exactly the eight substrate imports"
                                        .to_string(),
                            });
                    }
                }
                Err(reason) => self
                    .violations
                    .push(ComponentGraphViolation::InvalidArtifact {
                        subject: format!("derived executable for {}", authority.id),
                        reason,
                    }),
            }
        }
        for digest in self.artifacts.derived_component_bytes.keys() {
            if !referenced_executables.contains(digest) {
                self.violations
                    .push(ComponentGraphViolation::InvalidArtifact {
                        subject: "derived component artifact set".to_string(),
                        reason: format!("unreferenced derived executable {digest}"),
                    });
            }
        }
        for digest in self.artifacts.composition_config_bytes.keys() {
            if !referenced_configs.contains(digest) {
                self.violations
                    .push(ComponentGraphViolation::InvalidArtifact {
                        subject: "composition config artifact set".to_string(),
                        reason: format!("unreferenced composition config {digest}"),
                    });
            }
        }
    }

    fn validate_derivation_descriptor_v2(&mut self, descriptor: &ComponentDerivationDescriptorV2) {
        let principal_inventory = match self.substrate_profile.clone() {
            Some(LoadedSubstrateProfile::V2(profile)) => profile.principals,
            Some(LoadedSubstrateProfile::V3(profile)) => profile.principals,
            _ => {
                self.violations
                    .push(ComponentGraphViolation::InvalidArtifact {
                        subject: "per-consumer derivation descriptor".to_string(),
                        reason: "descriptor v2 requires substrate profile v2 or v3".to_string(),
                    });
                return;
            }
        };
        let expected_sources = self
            .graph
            .manifest
            .nodes
            .iter()
            .map(|node| DerivationSourceV1 {
                node_id: node.id.clone(),
                component_digest: node.component_digest.clone(),
                world: node.world.clone(),
            })
            .collect::<Vec<_>>();
        if descriptor.sources != expected_sources {
            self.violations
                .push(ComponentGraphViolation::InvalidArtifact {
                    subject: "component derivation descriptor sources".to_string(),
                    reason: "source set must exactly match sorted authoritative manifest nodes"
                        .to_string(),
                });
        }
        if descriptor.tool.name.trim().is_empty()
            || descriptor.tool.version.trim().is_empty()
            || descriptor
                .tool
                .options
                .iter()
                .any(|option| option.trim().is_empty())
            || !strictly_sorted_by(&descriptor.executables, |item| item.authority_node.as_str())
        {
            self.violations
                .push(ComponentGraphViolation::InvalidArtifact {
                    subject: "component derivation descriptor".to_string(),
                    reason: "R2 derivation tool fields and executable ordering must be canonical"
                        .to_string(),
                });
        }

        let mut expected_authorities = self
            .graph
            .manifest
            .invocations
            .iter()
            .map(|edge| edge.target.clone())
            .chain(std::iter::once(self.graph.manifest.root_node.clone()))
            .collect::<Vec<_>>();
        expected_authorities.sort();
        expected_authorities.dedup();
        let actual_authorities = descriptor
            .executables
            .iter()
            .map(|item| item.authority_node.clone())
            .collect::<Vec<_>>();
        if actual_authorities != expected_authorities {
            self.violations
                .push(ComponentGraphViolation::InvalidArtifact {
                    subject: "component derivation descriptor executables".to_string(),
                    reason: "descriptor must contain exactly the root and every dynamic target"
                        .to_string(),
                });
        }

        let principals = principal_inventory
            .iter()
            .map(|principal| (principal.consumer.as_str(), principal))
            .collect::<BTreeMap<_, _>>();
        let engine = component_engine().ok();
        let canonical_host_imports = REQUIRED_SUBSTRATE_PRIMITIVES
            .iter()
            .map(|primitive| primitive.interface_name().to_string())
            .collect::<BTreeSet<_>>();
        let mut referenced_executables = BTreeSet::new();
        let mut referenced_configs = BTreeSet::new();
        for executable in &descriptor.executables {
            referenced_executables.insert(executable.executable_digest.clone());
            referenced_configs.insert(executable.configuration_digest.clone());
            let Some(authority) = self.nodes.get(executable.authority_node.as_str()) else {
                self.violations
                    .push(ComponentGraphViolation::InvalidArtifact {
                        subject: format!("derived executable {}", executable.authority_node),
                        reason: "authority node is absent from manifest".to_string(),
                    });
                continue;
            };
            if executable.authority_digest != authority.component_digest
                || executable.world != authority.world
            {
                self.violations
                    .push(ComponentGraphViolation::InvalidArtifact {
                        subject: format!("derived executable for {}", authority.id),
                        reason: "authority digest or world differs from the raw manifest node"
                            .to_string(),
                    });
            }

            let closure = self.static_component_node_closure(authority.id.as_str());
            let mut expected_raw = closure
                .iter()
                .filter_map(|node_id| self.nodes.get(node_id.as_str()))
                .map(|node| node.component_digest.clone())
                .collect::<Vec<_>>();
            expected_raw.sort();
            expected_raw.dedup();
            let mut expected_scoped = closure
                .iter()
                .filter_map(|node_id| principals.get(node_id.as_str()))
                .map(|principal| principal.scoped_component_digest.clone())
                .collect::<Vec<_>>();
            expected_scoped.sort();
            expected_scoped.dedup();
            let mut expected_seeds = closure
                .iter()
                .filter_map(|node_id| principals.get(node_id.as_str()))
                .map(|principal| principal.principal_seed.clone())
                .collect::<Vec<_>>();
            expected_seeds.sort();
            expected_seeds.dedup();
            if executable.source_digests != expected_raw
                || executable.scoped_source_digests != expected_scoped
                || executable.principal_seeds != expected_seeds
            {
                self.violations.push(ComponentGraphViolation::InvalidArtifact {
                    subject: format!("derived executable closure for {}", authority.id),
                    reason: "raw, scoped and principal provenance must exactly cover the sorted static closure"
                        .to_string(),
                });
            }

            verified_artifact(
                &mut self.violations,
                &format!("composition config for {}", authority.id),
                &executable.configuration_digest,
                &self.artifacts.composition_config_bytes,
            );
            let Some(bytes) = verified_artifact(
                &mut self.violations,
                &format!("derived executable for {}", authority.id),
                &executable.executable_digest,
                &self.artifacts.derived_component_bytes,
            ) else {
                continue;
            };
            let Some(engine) = &engine else {
                continue;
            };
            let Ok(surface) = observe_component_surface(bytes, engine) else {
                self.violations
                    .push(ComponentGraphViolation::InvalidArtifact {
                        subject: format!("derived executable for {}", authority.id),
                        reason: "derived bytes are not a Component Model component".to_string(),
                    });
                continue;
            };
            let expected_exports = authority.exports.iter().cloned().collect::<BTreeSet<_>>();
            let expected_aliases = closure
                .iter()
                .filter_map(|node_id| principals.get(node_id.as_str()))
                .flat_map(|principal| {
                    principal
                        .host_imports
                        .iter()
                        .map(|host_import| host_import.alias.clone())
                })
                .collect::<BTreeSet<_>>();
            if surface.exports != expected_exports || surface.imports != expected_aliases {
                self.violations.push(ComponentGraphViolation::InvalidArtifact {
                    subject: format!("derived executable surface for {}", authority.id),
                    reason: "derived surface must contain exactly its exports and the closure's principal-specific host aliases"
                        .to_string(),
                });
            }
            if !surface.imports.is_disjoint(&canonical_host_imports) {
                self.violations
                    .push(ComponentGraphViolation::InvalidArtifact {
                        subject: format!("derived executable surface for {}", authority.id),
                        reason: "canonical graph-union host import survived R2 composition"
                            .to_string(),
                    });
            }
        }
        if self
            .artifacts
            .derived_component_bytes
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>()
            != referenced_executables
        {
            self.violations
                .push(ComponentGraphViolation::InvalidArtifact {
                    subject: "derived component artifact set".to_string(),
                    reason: "derived artifacts must exactly match descriptor v2".to_string(),
                });
        }
        if self
            .artifacts
            .composition_config_bytes
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>()
            != referenced_configs
        {
            self.violations
                .push(ComponentGraphViolation::InvalidArtifact {
                    subject: "composition config artifact set".to_string(),
                    reason: "composition configs must exactly match descriptor v2".to_string(),
                });
        }
    }

    fn static_component_closure(&self, authority: &str) -> Vec<ContentDigest> {
        let mut digests = self
            .static_component_node_closure(authority)
            .into_iter()
            .filter_map(|node_id| self.nodes.get(node_id.as_str()))
            .map(|node| node.component_digest.clone())
            .collect::<Vec<_>>();
        digests.sort();
        digests.dedup();
        digests
    }

    fn static_component_node_closure(&self, authority: &str) -> BTreeSet<String> {
        let mut pending = vec![authority.to_string()];
        let mut reached = BTreeSet::new();
        while let Some(node_id) = pending.pop() {
            if !reached.insert(node_id.clone()) {
                continue;
            }
            for binding in self
                .graph
                .manifest
                .bindings
                .iter()
                .filter(|binding| binding.consumer == node_id)
            {
                if let ComponentBindingProvider::Component { node, .. } = &binding.provider {
                    pending.push(node.clone());
                }
            }
        }
        reached
    }

    fn validate_reachability(&mut self) {
        let mut adjacency = self
            .nodes
            .keys()
            .map(|id| (*id, Vec::new()))
            .collect::<BTreeMap<_, _>>();
        for binding in &self.graph.manifest.bindings {
            if let ComponentBindingProvider::Component { node, .. } = &binding.provider {
                if self.nodes.contains_key(binding.consumer.as_str())
                    && self.nodes.contains_key(node.as_str())
                {
                    adjacency
                        .entry(binding.consumer.as_str())
                        .or_default()
                        .push(node.as_str());
                }
            }
        }
        for invocation in &self.graph.manifest.invocations {
            if self.nodes.contains_key(invocation.consumer.as_str())
                && self.nodes.contains_key(invocation.target.as_str())
            {
                adjacency
                    .entry(invocation.consumer.as_str())
                    .or_default()
                    .push(invocation.target.as_str());
            }
        }
        let mut reached = BTreeSet::new();
        mark_reachable(
            self.graph.manifest.root_node.as_str(),
            &adjacency,
            &mut reached,
        );
        for node in &self.graph.manifest.nodes {
            if !reached.contains(node.id.as_str()) {
                self.violations
                    .push(ComponentGraphViolation::UnreachableNode {
                        node_id: node.id.clone(),
                    });
            }
        }
        let mut permanent = BTreeSet::new();
        let mut temporary = Vec::new();
        for id in adjacency.keys() {
            if let Some(cycle) = find_cycle(id, &adjacency, &mut permanent, &mut temporary) {
                self.violations
                    .push(ComponentGraphViolation::DependencyCycle { node_ids: cycle });
                break;
            }
        }
    }

    fn schema_mismatch(&mut self, subject: &str, expected: &str, actual: &str) {
        self.violations
            .push(ComponentGraphViolation::SchemaMismatch {
                subject: subject.to_string(),
                expected: expected.to_string(),
                actual: actual.to_string(),
            });
    }
}

fn verified_artifact<'a>(
    violations: &mut Vec<ComponentGraphViolation>,
    subject: &str,
    digest: &ContentDigest,
    artifacts: &'a BTreeMap<ContentDigest, Vec<u8>>,
) -> Option<&'a [u8]> {
    match artifacts.get(digest) {
        Some(bytes) => {
            let actual = ContentDigest::from_bytes(bytes);
            if actual != *digest {
                violations.push(ComponentGraphViolation::ArtifactDigestMismatch {
                    subject: subject.to_string(),
                    expected: digest.clone(),
                    actual,
                });
                None
            } else {
                Some(bytes)
            }
        }
        None => {
            violations.push(ComponentGraphViolation::MissingArtifact {
                subject: subject.to_string(),
                digest: digest.clone(),
            });
            None
        }
    }
}

fn component_engine() -> Result<wasmtime::Engine, String> {
    let mut config = wasmtime::Config::new();
    config.wasm_component_model(true);
    wasmtime::Engine::new(&config).map_err(|error| error.to_string())
}

#[derive(Debug)]
enum ComponentEncodingError {
    CoreModule,
    Invalid(String),
}

fn component_item_is_type_only(item: &ComponentItem, engine: &wasmtime::Engine) -> bool {
    match item {
        ComponentItem::Type(_) => true,
        ComponentItem::ComponentInstance(instance) => instance
            .exports(engine)
            .all(|(_, item)| component_item_is_type_only(&item, engine)),
        ComponentItem::ComponentFunc(_)
        | ComponentItem::CoreFunc(_)
        | ComponentItem::Module(_)
        | ComponentItem::Component(_)
        | ComponentItem::Resource(_) => false,
    }
}

fn observe_component_surface(
    bytes: &[u8],
    engine: &wasmtime::Engine,
) -> Result<ObservedSurface, String> {
    let component = Component::new(engine, bytes).map_err(|error| error.to_string())?;
    let ty = component.component_type();
    Ok(ObservedSurface {
        imports: ty
            .imports(engine)
            .filter_map(|(name, item)| {
                (!component_item_is_type_only(&item, engine)).then(|| name.to_string())
            })
            .collect(),
        exports: ty
            .exports(engine)
            .map(|(name, _)| name.to_string())
            .collect(),
    })
}

fn component_encoding(bytes: &[u8]) -> Result<(), ComponentEncodingError> {
    let mut saw_header = false;
    for payload in Parser::new(0).parse_all(bytes) {
        let payload =
            payload.map_err(|error| ComponentEncodingError::Invalid(error.to_string()))?;
        if let Payload::Version { encoding, .. } = payload {
            if saw_header {
                continue;
            }
            saw_header = true;
            match encoding {
                Encoding::Component => {}
                Encoding::Module => return Err(ComponentEncodingError::CoreModule),
            }
        }
    }
    if !saw_header {
        return Err(ComponentEncodingError::Invalid(
            "missing WebAssembly header".to_string(),
        ));
    }
    Ok(())
}

struct ParsedWitSurface {
    package: String,
    surface: ObservedSurface,
}

fn parse_wit_surface(bytes: &[u8], expected_world: &str) -> Result<ParsedWitSurface, String> {
    let source = std::str::from_utf8(bytes).map_err(|error| error.to_string())?;
    // Retain the source-declared boundary before `Resolve` elaborates type
    // dependencies into synthetic world imports.
    let unresolved = UnresolvedPackageGroup::parse("component-world.wit", source)
        .map_err(|error| error.to_string())?;
    let unresolved_world = unresolved
        .main
        .worlds
        .iter()
        .find_map(|(_, world)| (world.name == expected_world).then_some(world))
        .ok_or_else(|| format!("unresolved WIT world {expected_world:?} not found"))?;
    let direct_import_names =
        unresolved_interface_names(&unresolved.main, unresolved_world.imports.values())?;
    let boundary_names = unresolved_interface_names(
        &unresolved.main,
        unresolved_world
            .imports
            .values()
            .chain(unresolved_world.exports.values()),
    )?;

    let mut resolve = Resolve::default();
    let package_id = resolve
        .push_str("component-world.wit", source)
        .map_err(|error| error.to_string())?;
    let package = &resolve.packages[package_id];
    let world_id = package.worlds.get(expected_world).copied().ok_or_else(|| {
        format!(
            "WIT world {expected_world:?} not found; available worlds: {:?}",
            package.worlds.keys().collect::<Vec<_>>()
        )
    })?;
    let world = &resolve.worlds[world_id];
    let direct_import_interfaces = direct_import_names
        .iter()
        .filter_map(|name| package.interfaces.get(name).copied())
        .collect::<Vec<_>>();
    let boundary_interfaces = boundary_names
        .iter()
        .filter_map(|name| package.interfaces.get(name).copied())
        .collect::<Vec<_>>();
    let package_name = &package.name;
    let version = package_name
        .version
        .as_ref()
        .map(|version| format!("@{version}"))
        .unwrap_or_default();
    Ok(ParsedWitSurface {
        package: format!(
            "{}:{}{}",
            package_name.namespace, package_name.name, version
        ),
        surface: ObservedSurface {
            imports: world
                .imports
                .iter()
                .filter(|(_, item)| {
                    !wit_world_item_is_type_only(
                        &resolve,
                        &boundary_interfaces,
                        &direct_import_interfaces,
                        item,
                    )
                })
                .map(|(key, _)| resolved_world_key_name(&resolve, key))
                .collect::<Result<_, _>>()?,
            exports: world
                .exports
                .keys()
                .map(|key| resolved_world_key_name(&resolve, key))
                .collect::<Result<_, _>>()?,
        },
    })
}

fn unresolved_interface_names<'a>(
    package: &UnresolvedPackage,
    items: impl Iterator<Item = &'a WorldItem>,
) -> Result<Vec<String>, String> {
    items
        .filter_map(|item| match item {
            WorldItem::Interface { id, .. } => Some(
                package.interfaces[*id]
                    .name
                    .clone()
                    .ok_or_else(|| "anonymous source-declared boundary interface".to_string()),
            ),
            WorldItem::Function(_) | WorldItem::Type { .. } => None,
        })
        .collect()
}

/// WIT resolution makes type dependencies explicit in a world's import map,
/// while a compiled Component Model binary elides interface instances that
/// contain only structural types. Compare the same effectful boundary on both
/// sides: functions and resources remain imports; ordinary data types do not.
fn wit_world_item_is_type_only(
    resolve: &Resolve,
    boundary_interfaces: &[InterfaceId],
    direct_import_interfaces: &[InterfaceId],
    item: &WorldItem,
) -> bool {
    match item {
        WorldItem::Type { .. } => true,
        WorldItem::Function(_) => false,
        WorldItem::Interface { id, .. } => {
            if direct_import_interfaces.contains(id) {
                let interface = &resolve.interfaces[*id];
                return interface.functions.is_empty()
                    && interface
                        .types
                        .values()
                        .all(|id| wit_type_id_is_structural(resolve, *id, &mut Vec::new()));
            }
            // `Resolve::push_str` elaborates structural type dependencies of
            // imported/exported interfaces into synthetic world imports.
            // The exception is based on the independently parsed source
            // boundary, not on synthetic span metadata: walk the actual alias
            // path and recursively reject resources, handles, futures/streams.
            // Callable members elsewhere on the dependency interface are not
            // exposed by that type-alias path; independently observed component
            // imports still reject any binary that attempts to import them.
            synthetic_type_dependency_is_structural(resolve, boundary_interfaces, *id)
        }
    }
}

fn synthetic_type_dependency_is_structural(
    resolve: &Resolve,
    boundary_interfaces: &[InterfaceId],
    target: InterfaceId,
) -> bool {
    let mut pending = boundary_interfaces.to_vec();
    let mut visited = Vec::new();
    let mut reached_target = false;
    while let Some(interface_id) = pending.pop() {
        if visited.contains(&interface_id) {
            continue;
        }
        visited.push(interface_id);
        for type_id in resolve.interfaces[interface_id].types.values() {
            let Some(dependency) = resolve.type_interface_dep(*type_id) else {
                continue;
            };
            let structural = wit_type_id_is_structural(resolve, *type_id, &mut Vec::new());
            if dependency == target {
                reached_target = true;
                if !structural {
                    return false;
                }
            }
            if structural {
                pending.push(dependency);
            }
        }
    }
    reached_target
}

fn wit_type_id_is_structural(resolve: &Resolve, id: TypeId, visiting: &mut Vec<TypeId>) -> bool {
    if visiting.contains(&id) {
        return false;
    }
    visiting.push(id);
    let structural = match &resolve.types[id].kind {
        TypeDefKind::Record(record) => record
            .fields
            .iter()
            .all(|field| wit_type_is_structural(resolve, field.ty, visiting)),
        TypeDefKind::Flags(_) | TypeDefKind::Enum(_) => true,
        TypeDefKind::Tuple(tuple) => tuple
            .types
            .iter()
            .all(|ty| wit_type_is_structural(resolve, *ty, visiting)),
        TypeDefKind::Variant(variant) => variant.cases.iter().all(|case| {
            case.ty
                .is_none_or(|ty| wit_type_is_structural(resolve, ty, visiting))
        }),
        TypeDefKind::Option(ty) | TypeDefKind::List(ty) | TypeDefKind::FixedLengthList(ty, _) => {
            wit_type_is_structural(resolve, *ty, visiting)
        }
        TypeDefKind::Result(result) => result
            .ok
            .into_iter()
            .chain(result.err)
            .all(|ty| wit_type_is_structural(resolve, ty, visiting)),
        TypeDefKind::Map(key, value) => {
            wit_type_is_structural(resolve, *key, visiting)
                && wit_type_is_structural(resolve, *value, visiting)
        }
        TypeDefKind::Type(ty) => wit_type_is_structural(resolve, *ty, visiting),
        TypeDefKind::Resource
        | TypeDefKind::Handle(_)
        | TypeDefKind::Future(_)
        | TypeDefKind::Stream(_)
        | TypeDefKind::Unknown => false,
    };
    visiting.pop();
    structural
}

fn wit_type_is_structural(resolve: &Resolve, ty: Type, visiting: &mut Vec<TypeId>) -> bool {
    match ty {
        Type::Id(id) => wit_type_id_is_structural(resolve, id, visiting),
        Type::Bool
        | Type::U8
        | Type::U16
        | Type::U32
        | Type::U64
        | Type::S8
        | Type::S16
        | Type::S32
        | Type::S64
        | Type::F32
        | Type::F64
        | Type::Char
        | Type::String
        | Type::ErrorContext => true,
    }
}

fn resolved_world_key_name(resolve: &Resolve, key: &WorldKey) -> Result<String, String> {
    match key {
        WorldKey::Name(name) => Ok(name.clone()),
        WorldKey::Interface(interface_id) => {
            let interface = &resolve.interfaces[*interface_id];
            let interface_name = interface
                .name
                .as_deref()
                .ok_or_else(|| "anonymous WIT boundary interface".to_string())?;
            let package_id = interface
                .package
                .ok_or_else(|| "WIT boundary interface has no package".to_string())?;
            let package_name = &resolve.packages[package_id].name;
            let version = package_name
                .version
                .as_ref()
                .map(|version| format!("@{version}"))
                .unwrap_or_default();
            Ok(format!(
                "{}:{}/{}{}",
                package_name.namespace, package_name.name, interface_name, version
            ))
        }
    }
}

fn compare_surface(
    violations: &mut Vec<ComponentGraphViolation>,
    node_id: &str,
    surface: &str,
    wit: &BTreeSet<String>,
    component: &BTreeSet<String>,
) {
    if wit != component {
        violations.push(ComponentGraphViolation::WitSurfaceMismatch {
            node_id: node_id.to_string(),
            surface: surface.to_string(),
            wit: wit.iter().cloned().collect(),
            component: component.iter().cloned().collect(),
        });
    }
}

fn world_name_from_ref(reference: &str) -> Option<&str> {
    reference
        .strip_prefix("wasm-biotic:factory/")?
        .strip_suffix("@0.1.0")
}

fn check_node_id(violations: &mut Vec<ComponentGraphViolation>, field: &str, value: &str) {
    let valid = (1..=127).contains(&value.len())
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    if !valid {
        violations.push(ComponentGraphViolation::InvalidNodeId {
            field: field.to_string(),
            value: value.to_string(),
        });
    }
}

fn check_nonempty(violations: &mut Vec<ComponentGraphViolation>, field: &str, value: &str) {
    if value.trim().is_empty() {
        violations.push(ComponentGraphViolation::EmptyValue {
            field: field.to_string(),
        });
    }
}

fn noncanonical(violations: &mut Vec<ComponentGraphViolation>, field: &str) {
    violations.push(ComponentGraphViolation::NonCanonicalOrder {
        field: field.to_string(),
    });
}

fn strictly_sorted_by<T, K: Ord + ?Sized>(values: &[T], key: impl Fn(&T) -> &K) -> bool {
    values.windows(2).all(|pair| key(&pair[0]) < key(&pair[1]))
}

fn strictly_sorted_strings(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn strictly_sorted_values<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn is_canonical_contract_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 127
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

fn is_visible_ascii_token(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value
            .as_bytes()
            .iter()
            .all(|byte| (0x21..=0x7e).contains(byte))
}

fn is_canonical_header_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.as_bytes().iter().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn permanently_forbidden_request_headers() -> BTreeSet<&'static str> {
    [
        "connection",
        "content-length",
        "host",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "via",
    ]
    .into_iter()
    .collect()
}

fn is_canonical_http_host(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 253
        || !value.is_ascii()
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return false;
    }
    if let Ok(address) = value.parse::<std::net::IpAddr>() {
        return address.to_string() == value;
    }
    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.as_bytes()[0] != b'-'
            && label.as_bytes()[label.len() - 1] != b'-'
            && label
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
    })
}

fn is_canonical_http_path_prefix(value: &str) -> bool {
    value.starts_with('/')
        && value.len() <= 4_096
        && value.is_ascii()
        && value
            .as_bytes()
            .iter()
            .all(|byte| (0x21..=0x7e).contains(byte))
        && !value.contains(['\\', '?', '#', '%'])
        && !value.contains("//")
        && !value
            .split('/')
            .any(|segment| segment == "." || segment == "..")
}

fn is_canonical_cidr(value: &str) -> bool {
    let Some((address, prefix)) = value.split_once('/') else {
        return false;
    };
    if address.is_empty()
        || prefix.is_empty()
        || (prefix.len() > 1 && prefix.starts_with('0'))
        || !prefix.bytes().all(|byte| byte.is_ascii_digit())
    {
        return false;
    }
    let Ok(address) = address.parse::<std::net::IpAddr>() else {
        return false;
    };
    if address.to_string() != value.split_once('/').expect("split above").0 {
        return false;
    }
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    match address {
        std::net::IpAddr::V4(address) if (1..=32).contains(&prefix) => {
            let value = u32::from(address);
            let mask = u32::MAX << (32 - prefix);
            value & mask == value
        }
        std::net::IpAddr::V6(address) if (1..=128).contains(&prefix) => {
            let value = u128::from(address);
            let mask = u128::MAX << (128 - prefix);
            value & mask == value
        }
        _ => false,
    }
}

fn strictly_sorted_grants(values: &[ComponentCapabilityGrant]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn strictly_sorted_binding(values: &[ComponentImportBinding]) -> bool {
    values.windows(2).all(|pair| {
        (&pair[0].consumer, &pair[0].import_name) < (&pair[1].consumer, &pair[1].import_name)
    })
}

fn strictly_sorted_invocations(values: &[ComponentInvocationEdge]) -> bool {
    values.windows(2).all(|pair| {
        (&pair[0].consumer, &pair[0].target, &pair[0].export)
            < (&pair[1].consumer, &pair[1].target, &pair[1].export)
    })
}

fn mark_reachable<'a>(
    id: &'a str,
    adjacency: &BTreeMap<&'a str, Vec<&'a str>>,
    reached: &mut BTreeSet<&'a str>,
) {
    if !reached.insert(id) {
        return;
    }
    if let Some(dependencies) = adjacency.get(id) {
        for dependency in dependencies {
            mark_reachable(dependency, adjacency, reached);
        }
    }
}

fn find_cycle<'a>(
    id: &'a str,
    adjacency: &BTreeMap<&'a str, Vec<&'a str>>,
    permanent: &mut BTreeSet<&'a str>,
    temporary: &mut Vec<&'a str>,
) -> Option<Vec<String>> {
    if permanent.contains(id) {
        return None;
    }
    if let Some(start) = temporary.iter().position(|candidate| *candidate == id) {
        let mut cycle = temporary[start..]
            .iter()
            .map(|id| (*id).to_string())
            .collect::<Vec<_>>();
        cycle.push(id.to_string());
        return Some(cycle);
    }
    temporary.push(id);
    if let Some(dependencies) = adjacency.get(id) {
        for dependency in dependencies {
            if let Some(cycle) = find_cycle(dependency, adjacency, permanent, temporary) {
                return Some(cycle);
            }
        }
    }
    temporary.pop();
    permanent.insert(id);
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bounded_http_constraint_fixture() -> HttpTransportConstraintsV1 {
        serde_json::from_value(serde_json::json!({
            "credential_bindings": [{
                "handle": "exchange-api",
                "header_name": "authorization",
                "origin_id": "exchange-origin",
                "placement": "append-to-header-value",
                "value_prefix": "Bearer "
            }],
            "max_concurrency": 2,
            "max_request_body_bytes": 1048576,
            "max_response_body_bytes": 1048576,
            "max_timeout_ms": 10000,
            "max_url_bytes": 2048,
            "methods": ["post"],
            "origins": [{
                "dns": {
                    "cidrs": ["127.0.0.1/32"],
                    "policy": "exact-cidrs"
                },
                "host": "127.0.0.1",
                "id": "exchange-origin",
                "path_prefixes": ["/exchange"],
                "port": 443,
                "scheme": "https",
                "tls": {
                    "minimum_version": "tls-1.3",
                    "peer_spki_sha256": [ContentDigest::from_bytes(b"fixture-spki")],
                    "server_name": "127.0.0.1"
                }
            }],
            "redirects": "deny",
            "request_headers": {
                "allowed_names": ["authorization", "content-type"],
                "max_count": 8,
                "max_total_bytes": 8192
            },
            "response_headers": {
                "exposed_names": ["content-type"],
                "max_count": 16,
                "max_total_bytes": 16384
            },
            "schema": HTTP_TRANSPORT_CONSTRAINTS_SCHEMA_V1
        }))
        .expect("closed HTTP fixture")
    }

    fn forwarding_component() -> Vec<u8> {
        wat::parse_str(
            r#"(component
                (import "next" (func $next))
                (core func $next-core (canon lower (func $next)))
                (core module $adapter
                    (import "" "next" (func $next))
                    (func (export "run") call $next))
                (core instance $instance (instantiate $adapter
                    (with "" (instance
                        (export "next" (func $next-core))))))
                (func $run (canon lift (core func $instance "run")))
                (export "run" (func $run)))"#,
        )
        .expect("forwarding component")
    }

    fn forwarding_worker_router_component() -> Vec<u8> {
        wat::parse_str(
            r#"(component
                (import "next" (func $next))
                (import "wasm-biotic:factory/component-runner@0.1.0"
                    (instance $runner (export "start" (func))))
                (core func $next-core (canon lower (func $next)))
                (core module $adapter
                    (import "" "next" (func $next))
                    (func (export "run") call $next))
                (core instance $instance (instantiate $adapter
                    (with "" (instance
                        (export "next" (func $next-core))))))
                (func $run (canon lift (core func $instance "run")))
                (export "run" (func $run)))"#,
        )
        .expect("worker router component")
    }

    fn forwarding_worker_component() -> Vec<u8> {
        wat::parse_str(
            r#"(component
                (import "next" (func $next))
                (core func $next-core (canon lower (func $next)))
                (core module $adapter
                    (import "" "next" (func $next))
                    (func (export "run") call $next))
                (core instance $instance (instantiate $adapter
                    (with "" (instance
                        (export "next" (func $next-core))))))
                (func $run (canon lift (core func $instance "run")))
                (instance $task (export "run" (func $run)))
                (export "run" (func $run))
                (export "wasm-biotic:factory/component-task@0.1.0"
                    (instance $task)))"#,
        )
        .expect("worker component")
    }

    fn leaf_component() -> Vec<u8> {
        wat::parse_str(
            r#"(component
                (core module $leaf (func (export "run")))
                (core instance $instance (instantiate $leaf))
                (func $run (canon lift (core func $instance "run")))
                (export "run" (func $run)))"#,
        )
        .expect("leaf component")
    }

    fn derived_root_component() -> Vec<u8> {
        let imports = REQUIRED_SUBSTRATE_PRIMITIVES
            .iter()
            .map(|primitive| {
                format!(
                    "(import \"{}\" (instance (export \"mechanism\" (func))))",
                    primitive.interface_name()
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        wat::parse_str(format!(
            r#"(component
                {imports}
                (core module $leaf (func (export "run")))
                (core instance $instance (instantiate $leaf))
                (func $run (canon lift (core func $instance "run")))
                (export "run" (func $run)))"#
        ))
        .expect("derived root")
    }

    fn derived_task_component() -> Vec<u8> {
        wat::parse_str(
            r#"(component
                (core module $leaf (func (export "run")))
                (core instance $instance (instantiate $leaf))
                (func $run (canon lift (core func $instance "run")))
                (instance $task (export "run" (func $run)))
                (export "run" (func $run))
                (export "wasm-biotic:factory/component-task@0.1.0"
                    (instance $task)))"#,
        )
        .expect("derived task")
    }

    fn world_source(kind: FactoryComponentKind, has_import: bool) -> Vec<u8> {
        let world = world_name_from_ref(kind.expected_world()).expect("known world");
        let import = if has_import {
            "import next: func();"
        } else {
            ""
        };
        let runner = if kind == FactoryComponentKind::WorkerRouter {
            "import component-runner;"
        } else {
            ""
        };
        let task = if kind.worker_role().is_some() {
            "export component-task;"
        } else {
            ""
        };
        format!(
            "package wasm-biotic:factory@0.1.0;
             interface component-runner {{ start: func(); }}
             interface component-task {{ run: func(); }}
             world {world} {{ {runner} {import} export run: func(); {task} }}"
        )
        .into_bytes()
    }

    fn complete_fixture() -> (AddressedComponentGraphV1, ComponentGraphArtifacts) {
        let kinds = REQUIRED_FACTORY_COMPONENT_KINDS;
        let ids = (0..kinds.len())
            .map(|index| format!("node-{index:02}"))
            .collect::<Vec<_>>();
        let mut artifacts = ComponentGraphArtifacts::default();
        let mut component_digests = Vec::new();
        let mut world_digests = BTreeMap::new();

        for (index, kind) in kinds.iter().copied().enumerate() {
            let has_import = index + 1 != kinds.len();
            let component = if kind == FactoryComponentKind::WorkerRouter {
                forwarding_worker_router_component()
            } else if kind.worker_role().is_some() {
                forwarding_worker_component()
            } else if has_import {
                forwarding_component()
            } else {
                leaf_component()
            };
            component_digests.push(ContentDigest::from_bytes(&component));
            artifacts.insert_component(ids[index].clone(), component);
            let digest = artifacts.insert_wit_world(world_source(kind, has_import));
            world_digests.insert(kind.expected_world().to_string(), digest);
        }

        let ceilings = CapabilityConstraintsV1::bounded_local_default();
        let runner_constraints = artifacts
            .insert_constraints(ceilings.canonical_bytes().expect("canonical constraints"));
        let root_grants = REQUIRED_SUBSTRATE_PRIMITIVES
            .iter()
            .copied()
            .map(|capability| ComponentCapabilityGrant {
                capability,
                scope: capability.canonical_scope().to_string(),
                constraints: runner_constraints.clone(),
            })
            .collect::<Vec<_>>();
        let nodes = kinds
            .iter()
            .copied()
            .enumerate()
            .map(|(index, kind)| FactoryComponentV1 {
                id: ids[index].clone(),
                kind,
                component_digest: component_digests[index].clone(),
                world: kind.expected_world().to_string(),
                exports: if kind.worker_role().is_some() {
                    vec![
                        "run".to_string(),
                        "wasm-biotic:factory/component-task@0.1.0".to_string(),
                    ]
                } else {
                    vec!["run".to_string()]
                },
                grants: if kind == FactoryComponentKind::Root {
                    root_grants.clone()
                } else if kind == FactoryComponentKind::WorkerRouter {
                    vec![ComponentCapabilityGrant {
                        capability: SubstratePrimitive::ComponentRunner,
                        scope: SubstratePrimitive::ComponentRunner
                            .canonical_scope()
                            .to_string(),
                        constraints: runner_constraints.clone(),
                    }]
                } else {
                    vec![]
                },
                state_schema: None,
            })
            .collect::<Vec<_>>();
        let mut bindings = (0..kinds.len() - 1)
            .map(|index| ComponentImportBinding {
                consumer: ids[index].clone(),
                import_name: "next".to_string(),
                provider: ComponentBindingProvider::Component {
                    node: ids[index + 1].clone(),
                    export: "run".to_string(),
                },
            })
            .collect::<Vec<_>>();
        bindings.push(ComponentImportBinding {
            consumer: ids[2].clone(),
            import_name: SubstratePrimitive::ComponentRunner
                .interface_name()
                .to_string(),
            provider: ComponentBindingProvider::Host {
                capability: SubstratePrimitive::ComponentRunner,
            },
        });
        bindings.sort();
        let invocations = (4..=9)
            .map(|index| ComponentInvocationEdge {
                consumer: ids[2].clone(),
                target: ids[index].clone(),
                export: "wasm-biotic:factory/component-task@0.1.0".to_string(),
            })
            .collect::<Vec<_>>();

        let profile_digest = artifacts
            .insert_substrate_profile(&SubstrateProfileV1::component_complete(
                ids[0].clone(),
                root_grants,
                ceilings,
            ))
            .expect("profile");
        let wit_package_digest =
            artifacts.insert_wit_package(b"wasm-biotic:factory@0.1.0 test package".to_vec());

        let static_closure = |authority: &str| {
            let mut pending = vec![authority.to_string()];
            let mut reached = BTreeSet::new();
            while let Some(node_id) = pending.pop() {
                if !reached.insert(node_id.clone()) {
                    continue;
                }
                for binding in bindings
                    .iter()
                    .filter(|binding| binding.consumer == node_id)
                {
                    if let ComponentBindingProvider::Component { node, .. } = &binding.provider {
                        pending.push(node.clone());
                    }
                }
            }
            let mut digests = reached
                .into_iter()
                .filter_map(|node_id| {
                    nodes
                        .iter()
                        .find(|node| node.id == node_id)
                        .map(|node| node.component_digest.clone())
                })
                .collect::<Vec<_>>();
            digests.sort();
            digests.dedup();
            digests
        };
        let mut executables = Vec::new();
        for authority_index in std::iter::once(0).chain(4..=9) {
            let authority = &nodes[authority_index];
            let config = format!(
                "{{\"authority\":\"{}\",\"schema\":\"wasm-biotic.compose-config.v1\"}}",
                authority.id
            )
            .into_bytes();
            let configuration_digest = artifacts.insert_composition_config(config);
            let executable_digest = artifacts.insert_derived_component(if authority_index == 0 {
                derived_root_component()
            } else {
                derived_task_component()
            });
            executables.push(DerivedExecutableV1 {
                authority_node: authority.id.clone(),
                authority_digest: authority.component_digest.clone(),
                executable_digest,
                source_digests: static_closure(&authority.id),
                world: authority.world.clone(),
                configuration_digest,
                grants: authority.grants.clone(),
            });
        }
        executables.sort_by(|left, right| left.authority_node.cmp(&right.authority_node));
        let descriptor_digest = artifacts
            .insert_derivation_descriptor(&ComponentDerivationDescriptorV1 {
                schema: DERIVATION_DESCRIPTOR_SCHEMA_V1.to_string(),
                wit_package_digest: wit_package_digest.clone(),
                sources: nodes
                    .iter()
                    .map(|node| DerivationSourceV1 {
                        node_id: node.id.clone(),
                        component_digest: node.component_digest.clone(),
                        world: node.world.clone(),
                    })
                    .collect(),
                executables,
                tool: CompositionToolV1 {
                    name: "wasm-tools compose".to_string(),
                    version: "fixture".to_string(),
                    options: vec!["--config=<content-addressed>".to_string()],
                },
            })
            .expect("descriptor");
        let metadata_digest = artifacts
            .insert_metadata(&ComponentGraphMetadataV1 {
                schema: GRAPH_METADATA_SCHEMA_V1.to_string(),
                wit_package_digest,
                wit_world_digests: world_digests,
                substrate_profile_digest: profile_digest,
                derivation_descriptor_digest: descriptor_digest,
            })
            .expect("metadata");
        let graph = AddressedComponentGraphV1::seal(ComponentGraphManifestV1 {
            schema: COMPONENT_GRAPH_SCHEMA_V1.to_string(),
            wit_package: FACTORY_WIT_PACKAGE_V1.to_string(),
            root_node: ids[0].clone(),
            previous_graph: None,
            state_schema: "wasm-biotic:factory-state@0.1.0".to_string(),
            nodes,
            bindings,
            invocations,
            metadata: Some(metadata_digest),
        })
        .expect("graph");
        (graph, artifacts)
    }

    fn reject(
        graph: &AddressedComponentGraphV1,
        artifacts: &ComponentGraphArtifacts,
        predicate: impl Fn(&ComponentGraphViolation) -> bool,
    ) {
        let error = validate_component_graph(graph, artifacts).expect_err("graph must fail");
        assert!(
            error.contains(predicate),
            "violations: {:?}",
            error.violations
        );
    }

    #[test]
    fn validates_a_complete_digest_bound_component_graph() {
        let (graph, artifacts) = complete_fixture();
        let validated = validate_component_graph(&graph, &artifacts).expect("valid graph");
        assert_eq!(validated.manifest_digest, graph.manifest_digest);
        assert_eq!(validated.component_digests.len(), 21);
        assert_eq!(REQUIRED_SUBSTRATE_PRIMITIVES.len(), 8);
    }

    #[test]
    fn rejects_unreferenced_constraint_artifacts() {
        let (graph, mut artifacts) = complete_fixture();
        artifacts.insert_constraints(
            bounded_http_constraint_fixture()
                .canonical_bytes()
                .expect("canonical HTTP constraints"),
        );
        reject(&graph, &artifacts, |violation| {
            matches!(
                violation,
                ComponentGraphViolation::InvalidArtifact { subject, .. }
                    if subject == "constraint artifact set"
            )
        });
    }

    #[test]
    fn wire_manifest_is_exactly_compatible_with_the_normative_schema_shape() {
        let (graph, _) = complete_fixture();
        let value = serde_json::to_value(&graph.manifest).expect("serialize");
        let object = value.as_object().expect("manifest object");
        assert_eq!(
            object.keys().cloned().collect::<BTreeSet<_>>(),
            [
                "bindings",
                "invocations",
                "metadata",
                "nodes",
                "root_node",
                "schema",
                "state_schema",
                "wit_package",
            ]
            .into_iter()
            .map(str::to_string)
            .collect()
        );
        let node = object["nodes"][0].as_object().expect("node object");
        assert_eq!(
            node.keys().cloned().collect::<BTreeSet<_>>(),
            [
                "component_digest",
                "exports",
                "grants",
                "id",
                "kind",
                "world"
            ]
            .into_iter()
            .map(str::to_string)
            .collect()
        );
        let binding = object["bindings"][0].as_object().expect("binding object");
        assert_eq!(
            binding.keys().cloned().collect::<BTreeSet<_>>(),
            ["consumer", "import", "provider"]
                .into_iter()
                .map(str::to_string)
                .collect()
        );
        assert_eq!(binding["provider"]["kind"], "component");
        let invocation = object["invocations"][0]
            .as_object()
            .expect("invocation object");
        assert_eq!(
            invocation.keys().cloned().collect::<BTreeSet<_>>(),
            ["consumer", "export", "target"]
                .into_iter()
                .map(str::to_string)
                .collect()
        );
        assert_eq!(object["schema"], COMPONENT_GRAPH_SCHEMA_V1);
        assert_eq!(object["wit_package"], FACTORY_WIT_PACKAGE_V1);

        let mut with_unknown = value;
        with_unknown.as_object_mut().unwrap().insert(
            "manifest_digest".to_string(),
            serde_json::json!(graph.manifest_digest),
        );
        assert!(serde_json::from_value::<ComponentGraphManifestV1>(with_unknown).is_err());
    }

    #[test]
    fn manifest_digest_uses_sorted_canonical_json_and_binds_every_wire_field() {
        let (graph, _) = complete_fixture();
        let canonical = graph.manifest.canonical_bytes().expect("canonical");
        assert_eq!(canonical.first(), Some(&b'{'));
        assert_eq!(ContentDigest::from_bytes(&canonical), graph.manifest_digest);
        assert!(canonical.starts_with(b"{\"bindings\":"));

        let mut changed = graph.clone();
        changed.manifest.nodes[0].kind = FactoryComponentKind::AdmittedTool;
        changed.reseal().expect("reseal");
        assert_ne!(changed.manifest_digest, graph.manifest_digest);

        let mut changed = graph.clone();
        changed.manifest.bindings[0].import_name = "other".to_string();
        changed.reseal().expect("reseal");
        assert_ne!(changed.manifest_digest, graph.manifest_digest);
    }

    #[test]
    fn rejects_manifest_component_and_wit_digest_tamper() {
        let (mut graph, mut artifacts) = complete_fixture();
        graph.manifest.state_schema.push_str("-tampered");
        artifacts
            .component_bytes
            .insert("node-00".to_string(), leaf_component());
        let metadata_digest = graph.manifest.metadata.as_ref().unwrap();
        let metadata: ComponentGraphMetadataV1 =
            serde_json::from_slice(&artifacts.metadata_bytes[metadata_digest]).unwrap();
        let world_digest = &metadata.wit_world_digests[FactoryComponentKind::Root.expected_world()];
        artifacts.wit_world_bytes.insert(
            world_digest.clone(),
            b"package wasm-biotic:factory@0.1.0; world wrong {}".to_vec(),
        );
        let error = validate_component_graph(&graph, &artifacts).expect_err("tamper");
        assert!(error.contains(|violation| matches!(
            violation,
            ComponentGraphViolation::ManifestDigestMismatch { .. }
        )));
        assert!(error.contains(|violation| matches!(
            violation,
            ComponentGraphViolation::ComponentDigestMismatch { node_id, .. } if node_id == "node-00"
        )));
        assert!(error.contains(|violation| matches!(
            violation,
            ComponentGraphViolation::ArtifactDigestMismatch { subject, .. }
                if subject.contains("WIT world")
        )));
    }

    #[test]
    fn rejects_native_and_core_wasm_factory_executables() {
        let (mut graph, mut artifacts) = complete_fixture();
        let core_module = wat::parse_str("(module)").unwrap();
        graph.manifest.nodes[0].component_digest = ContentDigest::from_bytes(&core_module);
        artifacts.insert_component("node-00", core_module);
        graph.reseal().unwrap();
        reject(&graph, &artifacts, |violation| {
            matches!(
                violation,
                ComponentGraphViolation::NonComponentExecutable { node_id } if node_id == "node-00"
            )
        });

        let native = b"\x7fELF native transitional supervisor".to_vec();
        graph.manifest.nodes[0].component_digest = ContentDigest::from_bytes(&native);
        artifacts.insert_component("node-00", native);
        graph.reseal().unwrap();
        reject(&graph, &artifacts, |violation| {
            matches!(
                violation,
                ComponentGraphViolation::InvalidComponent { node_id, .. } if node_id == "node-00"
            )
        });
    }

    #[test]
    fn rejects_an_actual_import_without_a_declared_binding() {
        let (mut graph, artifacts) = complete_fixture();
        graph.manifest.bindings.remove(0);
        graph.reseal().unwrap();
        reject(&graph, &artifacts, |violation| {
            matches!(
                violation,
                ComponentGraphViolation::UndeclaredImport { node_id, import_name }
                    if node_id == "node-00" && import_name == "next"
            )
        });
    }

    #[test]
    fn rejects_missing_or_swapped_digest_bound_worker_dependencies() {
        let (mut missing, artifacts) = complete_fixture();
        missing
            .manifest
            .invocations
            .retain(|edge| edge.target != "node-04");
        missing.reseal().unwrap();
        reject(&missing, &artifacts, |violation| {
            matches!(
                violation,
                ComponentGraphViolation::MissingWorkerInvocation {
                    worker_kind: FactoryComponentKind::PlannerWorker
                }
            )
        });

        let (mut swapped, artifacts) = complete_fixture();
        let planner = swapped
            .manifest
            .invocations
            .iter_mut()
            .find(|edge| edge.target == "node-04")
            .expect("planner edge");
        planner.target = "node-05".to_string();
        swapped.reseal().unwrap();
        let error = validate_component_graph(&swapped, &artifacts).expect_err("swapped edge");
        assert!(error.contains(|violation| matches!(
            violation,
            ComponentGraphViolation::MissingWorkerInvocation {
                worker_kind: FactoryComponentKind::PlannerWorker
            }
        )));
        assert!(error.contains(|violation| matches!(
            violation,
            ComponentGraphViolation::DuplicateWorkerInvocation {
                worker_kind: FactoryComponentKind::BuilderWorker,
                ..
            }
        )));
    }

    #[test]
    fn rejects_dynamic_invocation_without_runner_binding_and_raw_digest_mismatch() {
        let (mut graph, artifacts) = complete_fixture();
        graph.manifest.bindings.retain(|binding| {
            !(binding.consumer == "node-02"
                && binding.import_name == SubstratePrimitive::ComponentRunner.interface_name())
        });
        graph.reseal().unwrap();
        reject(&graph, &artifacts, |violation| {
            matches!(
                violation,
                ComponentGraphViolation::InvocationWithoutRunnerBinding { consumer }
                    if consumer == "node-02"
            )
        });

        let (graph, mut artifacts) = complete_fixture();
        artifacts.insert_component("node-04", leaf_component());
        reject(&graph, &artifacts, |violation| {
            matches!(
                violation,
                ComponentGraphViolation::ComponentDigestMismatch { node_id, .. }
                    if node_id == "node-04"
            )
        });
    }

    #[test]
    fn rejects_missing_or_duplicate_factory_semantics() {
        let (mut graph, artifacts) = complete_fixture();
        graph.manifest.nodes[4].kind = FactoryComponentKind::AdmittedTool;
        graph.manifest.nodes[4].world = FactoryComponentKind::AdmittedTool
            .expected_world()
            .to_string();
        graph.reseal().unwrap();
        reject(&graph, &artifacts, |violation| {
            matches!(
                violation,
                ComponentGraphViolation::MissingRequiredSemantic {
                    kind: FactoryComponentKind::PlannerWorker
                }
            )
        });

        let (mut graph, artifacts) = complete_fixture();
        graph.manifest.nodes[5].kind = FactoryComponentKind::PlannerWorker;
        graph.manifest.nodes[5].world = FactoryComponentKind::PlannerWorker
            .expected_world()
            .to_string();
        graph.reseal().unwrap();
        reject(&graph, &artifacts, |violation| {
            matches!(
                violation,
                ComponentGraphViolation::DuplicateRequiredSemantic {
                    kind: FactoryComponentKind::PlannerWorker,
                    ..
                }
            )
        });
    }

    #[test]
    fn rejects_a_wrong_world_or_missing_provider_export() {
        let (mut graph, artifacts) = complete_fixture();
        graph.manifest.nodes[0].world = FactoryComponentKind::SupervisorReducer
            .expected_world()
            .to_string();
        graph.manifest.bindings[0].provider = ComponentBindingProvider::Component {
            node: "node-01".to_string(),
            export: "not-exported".to_string(),
        };
        graph.reseal().unwrap();
        let error = validate_component_graph(&graph, &artifacts).expect_err("invalid graph");
        assert!(error.contains(|violation| matches!(
            violation,
            ComponentGraphViolation::KindWorldMismatch { node_id, .. } if node_id == "node-00"
        )));
        assert!(error.contains(|violation| matches!(
            violation,
            ComponentGraphViolation::MissingProviderExport { export_name, .. }
                if export_name == "not-exported"
        )));
    }

    #[test]
    fn host_provider_wire_enum_cannot_express_native_domain_services() {
        let digest = ContentDigest::from_bytes(b"component");
        let constraints = ContentDigest::from_bytes(b"constraints");
        let json = serde_json::json!({
            "schema": COMPONENT_GRAPH_SCHEMA_V1,
            "wit_package": FACTORY_WIT_PACKAGE_V1,
            "root_node": "root",
            "state_schema": "state-v1",
            "nodes": [{
                "id": "root",
                "kind": "root",
                "component_digest": digest,
                "world": FactoryComponentKind::Root.expected_world(),
                "exports": ["run"],
                "grants": [{
                    "capability": "review-service",
                    "scope": "all",
                    "constraints": constraints
                }]
            }],
            "bindings": [{
                "consumer": "root",
                "import": "review-service",
                "provider": { "kind": "host", "capability": "review-service" }
            }],
            "invocations": []
        });
        assert!(serde_json::from_value::<ComponentGraphManifestV1>(json).is_err());
    }

    #[test]
    fn substrate_profile_is_exactly_the_eight_normative_interfaces() {
        let (graph, artifacts) = complete_fixture();
        let metadata: ComponentGraphMetadataV1 = serde_json::from_slice(
            &artifacts.metadata_bytes[graph.manifest.metadata.as_ref().unwrap()],
        )
        .unwrap();
        let profile: SubstrateProfileV1 = serde_json::from_slice(
            &artifacts.substrate_profile_bytes[&metadata.substrate_profile_digest],
        )
        .unwrap();
        assert_eq!(profile.primitives, REQUIRED_SUBSTRATE_PRIMITIVES);
        assert_eq!(
            SubstratePrimitive::BlobStore.interface_name(),
            "wasm-biotic:factory/blob-store@0.1.0"
        );
        assert_eq!(
            SubstratePrimitive::AuditLog.interface_name(),
            "wasm-biotic:factory/audit-log@0.1.0"
        );

        let (mut graph, mut artifacts) = complete_fixture();
        let mut invalid_profile = profile;
        invalid_profile.primitives.pop();
        let invalid_profile_digest = artifacts
            .insert_substrate_profile(&invalid_profile)
            .expect("profile");
        let old_metadata_digest = graph.manifest.metadata.clone().unwrap();
        let mut metadata: ComponentGraphMetadataV1 =
            serde_json::from_slice(&artifacts.metadata_bytes[&old_metadata_digest]).unwrap();
        metadata.substrate_profile_digest = invalid_profile_digest;
        let new_metadata_digest = artifacts.insert_metadata(&metadata).expect("metadata");
        graph.manifest.metadata = Some(new_metadata_digest);
        graph.reseal().unwrap();
        reject(&graph, &artifacts, |violation| {
            matches!(
                violation,
                ComponentGraphViolation::SubstrateProfileMismatch { .. }
            )
        });
    }

    #[test]
    fn r2_principal_seeds_and_host_aliases_are_content_bound_and_consumer_unique() {
        let constraints = ContentDigest::from_bytes(b"constraints");
        let node = FactoryComponentV1 {
            id: "consumer-a".to_string(),
            kind: FactoryComponentKind::BuildService,
            component_digest: ContentDigest::from_bytes(b"component-a"),
            world: FactoryComponentKind::BuildService
                .expected_world()
                .to_string(),
            exports: vec!["run".to_string()],
            grants: vec![ComponentCapabilityGrant {
                capability: SubstratePrimitive::BlobStore,
                scope: "read-write".to_string(),
                constraints: constraints.clone(),
            }],
            state_schema: None,
        };
        let seed = PrincipalSeedMaterialV1::for_node(&node)
            .principal_seed()
            .expect("principal seed");
        assert_eq!(
            seed,
            PrincipalSeedMaterialV1::for_node(&node)
                .principal_seed()
                .expect("stable principal seed")
        );
        let alias = HostImportAliasMaterialV1::for_binding(&node, SubstratePrimitive::BlobStore)
            .alias()
            .expect("host alias");
        assert!(alias.starts_with("wasm-biotic:factory/host-"));
        assert!(alias.ends_with("@0.1.0"));

        let mut other_consumer = node.clone();
        other_consumer.id = "consumer-b".to_string();
        assert_ne!(
            seed,
            PrincipalSeedMaterialV1::for_node(&other_consumer)
                .principal_seed()
                .expect("consumer-bound seed")
        );
        assert_ne!(
            alias,
            HostImportAliasMaterialV1::for_binding(&other_consumer, SubstratePrimitive::BlobStore,)
                .alias()
                .expect("consumer-bound alias")
        );

        let principal = GraphNodePrincipalV2 {
            consumer: node.id.clone(),
            authority_component_digest: node.component_digest.clone(),
            principal_seed: seed,
            scoped_component_digest: ContentDigest::from_bytes(b"scoped-a"),
            host_imports: vec![PrincipalHostImportV2 {
                alias,
                source_import: SubstratePrimitive::BlobStore.interface_name().to_string(),
                capability: SubstratePrimitive::BlobStore,
                scope: "read-write".to_string(),
                constraints,
            }],
        };
        let profile = SubstrateProfileV2::component_complete(
            node.id,
            vec![principal],
            CapabilityConstraintsV1::bounded_local_default(),
        );
        assert_eq!(profile.schema, SUBSTRATE_PROFILE_SCHEMA_V2);
        assert_eq!(
            profile.static_grant_model,
            StaticGrantModelV2::PerConsumerImportAlias
        );
        assert_eq!(profile.import_alias_scheme, HOST_IMPORT_ALIAS_SCHEME_V1);
        assert_eq!(profile.principal_id_scheme, GRAPH_NODE_PRINCIPAL_SCHEME_V1);
    }

    #[test]
    fn r3_http_constraint_is_closed_canonical_and_bounded_by_shared_ceilings() {
        let constraints = bounded_http_constraint_fixture();
        let ceilings = CapabilityConstraintsV1::bounded_local_default();
        constraints
            .validate_against(&ceilings)
            .expect("bounded fixture");
        let canonical = constraints.canonical_bytes().expect("canonical bytes");
        assert_eq!(
            serde_json::from_slice::<HttpTransportConstraintsV1>(&canonical)
                .expect("canonical round trip"),
            constraints
        );
        assert_eq!(
            ContentDigest::from_bytes(&canonical),
            constraints.content_digest().expect("constraint digest")
        );
        assert_eq!(
            constraints
                .content_digest()
                .expect("stable constraint digest")
                .as_str(),
            "sha256:bc54aaa9f58bc86e5a1fc5c941b6334a283a4074d53806832a675dd860b9a634"
        );

        let mut unknown = serde_json::to_value(&constraints).expect("constraint value");
        unknown
            .as_object_mut()
            .expect("constraint object")
            .insert("provider".to_string(), serde_json::json!("forbidden"));
        assert!(serde_json::from_value::<HttpTransportConstraintsV1>(unknown).is_err());
    }

    #[test]
    fn r3_http_constraint_rejects_ambiguous_network_and_credential_authority() {
        let ceilings = CapabilityConstraintsV1::bounded_local_default();

        let mut constraints = bounded_http_constraint_fixture();
        constraints.origins[0].tls.server_name = "different.example".to_string();
        assert!(
            constraints
                .validate_against(&ceilings)
                .expect_err("SNI mismatch must fail")
                .iter()
                .any(|reason| reason.contains("server name"))
        );

        let mut constraints = bounded_http_constraint_fixture();
        constraints.origins[0].dns.cidrs = vec!["0.0.0.0/0".to_string()];
        assert!(
            constraints
                .validate_against(&ceilings)
                .expect_err("zero-prefix exact CIDR must fail")
                .iter()
                .any(|reason| reason.contains("CIDRs"))
        );

        let mut constraints = bounded_http_constraint_fixture();
        let mut duplicate = constraints.credential_bindings[0].clone();
        duplicate.origin_id = "other-origin".to_string();
        constraints.origins.push(HttpTransportOriginV1 {
            id: "other-origin".to_string(),
            host: "127.0.0.2".to_string(),
            tls: HttpTlsConstraintsV1 {
                server_name: "127.0.0.2".to_string(),
                ..constraints.origins[0].tls.clone()
            },
            ..constraints.origins[0].clone()
        });
        constraints.credential_bindings.push(duplicate);
        assert!(
            constraints
                .validate_against(&ceilings)
                .expect_err("one handle cannot span origins")
                .iter()
                .any(|reason| reason.contains("more than one signed placement"))
        );
    }

    #[test]
    fn r3_profile_adds_only_the_exact_http_alias_projection_to_r2_authority() {
        let constraint_digest = bounded_http_constraint_fixture()
            .content_digest()
            .expect("HTTP constraint digest");
        let principal = GraphNodePrincipalV2 {
            consumer: "exchange-service".to_string(),
            authority_component_digest: ContentDigest::from_bytes(b"exchange-service"),
            principal_seed: ContentDigest::from_bytes(b"exchange-principal"),
            scoped_component_digest: ContentDigest::from_bytes(b"exchange-scoped"),
            host_imports: vec![PrincipalHostImportV2 {
                alias: "wasm-biotic:factory/host-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@0.1.0".to_string(),
                source_import: SubstratePrimitive::HttpTransport.interface_name().to_string(),
                capability: SubstratePrimitive::HttpTransport,
                scope: SubstratePrimitive::HttpTransport.canonical_scope().to_string(),
                constraints: constraint_digest.clone(),
            }],
        };
        let binding = HttpTransportBindingV1 {
            consumer: principal.consumer.clone(),
            alias: principal.host_imports[0].alias.clone(),
            constraints: constraint_digest,
        };
        let profile = SubstrateProfileV3::component_complete(
            "factory-control",
            vec![principal],
            CapabilityConstraintsV1::bounded_local_default(),
            vec![binding.clone()],
        );
        assert_eq!(profile.schema, SUBSTRATE_PROFILE_SCHEMA_V3);
        assert_eq!(
            profile.http_transport.mode,
            HttpTransportModeV1::BoundedExternal
        );
        assert_eq!(profile.http_transport.bindings, vec![binding]);
        assert_eq!(
            profile.http_transport.bindings,
            project_http_transport_bindings_v1(&profile.principals)
        );
        let value: Value =
            serde_json::from_slice(&profile.canonical_bytes().expect("canonical profile v3"))
                .expect("profile JSON");
        assert_eq!(
            value["http_transport"]["mode"],
            serde_json::json!("bounded-external")
        );
    }

    #[test]
    fn wit_synthetic_import_exception_is_structural_and_rejects_callable_or_resource_authority() {
        let structural = br#"
            package test:surface@1.0.0;
            interface dependency {
                record payload { value: u32 }
                callable-but-not-imported: func();
            }
            interface boundary {
                use dependency.{payload};
                emit: func(value: payload);
            }
            world example { export boundary; }
        "#;
        let surface = parse_wit_surface(structural, "example").expect("structural WIT");
        let dependency = "test:surface/dependency@1.0.0".to_string();
        assert!(!surface.surface.imports.contains(&dependency));

        // A binary cannot smuggle the callable member through the structural
        // exception: independently observed runtime imports remain unequal and
        // therefore reject admission.
        let mut violations = Vec::new();
        compare_surface(
            &mut violations,
            "node",
            "imports",
            &surface.surface.imports,
            &BTreeSet::from([dependency.clone()]),
        );
        assert!(matches!(
            violations.as_slice(),
            [ComponentGraphViolation::WitSurfaceMismatch { .. }]
        ));

        let resource = br#"
            package test:surface@1.0.0;
            interface dependency { resource token; }
            interface boundary {
                use dependency.{token};
                consume: func(value: borrow<token>);
            }
            world example { export boundary; }
        "#;
        let surface = parse_wit_surface(resource, "example").expect("resource WIT");
        assert!(surface.surface.imports.contains(&dependency));

        let explicit_callable = br#"
            package test:surface@1.0.0;
            interface dependency { call: func(); }
            world example { import dependency; }
        "#;
        let surface = parse_wit_surface(explicit_callable, "example").expect("callable WIT");
        assert!(surface.surface.imports.contains(&dependency));
    }
}
