//! Reproducible builder for the bounded component-complete factory release.

use aiaf_v1::component_graph::{
    AddressedComponentGraphV1, COMPONENT_GRAPH_SCHEMA_V1, CapabilityConstraintsV1,
    ComponentBindingProvider, ComponentCapabilityGrant, ComponentDerivationDescriptorV2,
    ComponentGraphArtifacts, ComponentGraphManifestV1, ComponentGraphMetadataV1,
    ComponentImportBinding, ComponentInvocationEdge, CompositionToolV1,
    DERIVATION_DESCRIPTOR_SCHEMA_V2, DerivationSourceV1, DerivedExecutableV2,
    FACTORY_WIT_PACKAGE_V1, FactoryComponentKind, FactoryComponentV1, GRAPH_METADATA_SCHEMA_V1,
    GraphNodePrincipalV2, HostImportAliasMaterialV1, HttpTransportBindingV1,
    HttpTransportConstraintsV1, PrincipalHostImportV2, PrincipalSeedMaterialV1,
    SUBSTRATE_PROFILE_SCHEMA_V2, SUBSTRATE_PROFILE_SCHEMA_V3, StaticGrantModelV2,
    SubstratePrimitive, SubstrateProfileV2, SubstrateProfileV3, project_http_transport_bindings_v1,
};
use aiaf_v1::execution::artifact::ContentDigest;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use wasm_biotic_factory_control::policy::{
    ActivationStateValue, BlobValue, DigestValue, FACTORY_OBSERVATION_REQUEST_SCHEMA,
    FACTORY_OBSERVATION_RESULT_SCHEMA, FACTORY_OBSERVATION_SCHEMA, FACTORY_UPGRADE_RESULT_SCHEMA,
    FACTORY_UPGRADE_SCHEMA, FactoryHealth, FactoryObservationAction, FactoryObservationRequestV1,
    FactoryObservationResultV1, FactoryObservationV1, FactoryUpgradeEnvelopeV1,
    FactoryUpgradeResultV1, JSON_MEDIA_TYPE, JobResultV1, SUPERVISOR_STATE_SCHEMA,
    StateDocumentRef,
};
use wasm_biotic_kernel::bindings::root::exports::wasm_biotic::factory::factory_api::IngressRequest;
use wasm_biotic_kernel::{
    AuthorityTrace, ExecutionProvenance, LocalConfig, LocalMechanisms, OpaqueRootEngine,
    OpaqueRootManager, RELEASE_CERTIFICATION_STATEMENT_SCHEMA, ReleaseCertificationStatement,
    ResourceLimits, RootAdmission, Sha256Digest, SignedReleaseCertification, TrustedCertifier,
    canonical_json_bytes,
};
use wasm_biotic_service_policy_core::{Operation, operation_policy};
use wasm_encoder::reencode::{Error as ReencodeError, Reencode, ReencodeComponent};

type DynError = Box<dyn Error + Send + Sync>;
type Result<T> = std::result::Result<T, DynError>;
type KernelBlobRef = wasm_biotic_kernel::bindings::root::wasm_biotic::factory::foundation::BlobRef;
type WitArtifacts = (Vec<u8>, Vec<u8>, BTreeMap<String, ContentDigest>);
type CompositionArtifacts = (
    Vec<DerivedExecutableV2>,
    BTreeMap<ContentDigest, Vec<u8>>,
    BTreeMap<ContentDigest, Vec<u8>>,
    Vec<u8>,
);

const PACKAGE_SCHEMA: &str = "wasm-biotic.component-graph-package.v1";
const WIT_PACKAGE_SCHEMA: &str = "wasm-biotic.wit-package.v1";
const COMPOSE_CONFIG_SCHEMA: &str = "wasm-biotic.compose-config.v1";
const COMPONENT_TASK_EXPORT: &str = "wasm-biotic:factory/component-task@0.1.0";
const PRINCIPAL_OPERATION_SCHEMA: &str = "wasm-biotic.principal-operation.v1";

enum ReleaseProfileConfig {
    R2,
    R3(HttpTransportConstraintsV1),
}

#[derive(Clone, Copy)]
enum BuildGroup {
    Components,
    Workers,
    Supervisor,
}

#[derive(Clone)]
struct NodeSpec {
    id: &'static str,
    kind: FactoryComponentKind,
    world: &'static str,
    exports: Vec<&'static str>,
    group: BuildGroup,
    artifact: &'static str,
    state_schema: Option<&'static str>,
}

#[derive(Clone, Copy)]
enum ProviderSpec {
    Component {
        node: &'static str,
        export: &'static str,
    },
    Host(SubstratePrimitive),
}

#[derive(Clone, Copy)]
struct BindingSpec {
    consumer: &'static str,
    import: &'static str,
    provider: ProviderSpec,
}

struct BuiltNode {
    spec: NodeSpec,
    bytes: Vec<u8>,
    digest: ContentDigest,
}

struct ScopedNode {
    bytes: Vec<u8>,
    digest: ContentDigest,
    principal_seed: ContentDigest,
}

#[derive(Serialize)]
struct WitFileArtifact {
    content: String,
    content_digest: ContentDigest,
    path: String,
}

#[derive(Serialize)]
struct WitPackageArtifact {
    files: Vec<WitFileArtifact>,
    package: String,
    schema: String,
}

#[derive(Serialize)]
struct CompositionEvidence {
    descriptor_digest: ContentDigest,
    graph_manifest_digest: ContentDigest,
    package_schema: String,
    raw_nodes: BTreeMap<String, ContentDigest>,
    scoped_nodes: BTreeMap<String, ContentDigest>,
    principal_seeds: BTreeMap<String, ContentDigest>,
    reproducible_composition: bool,
    tool: String,
    validated: bool,
}

#[derive(Serialize)]
struct ValidationEvidence {
    activated_service_nodes: BTreeMap<String, String>,
    bindings: Vec<ComponentImportBinding>,
    component_count: usize,
    derived_surfaces: BTreeMap<String, aiaf_v1::component_graph::ComponentSurfaceEvidenceV1>,
    graph_manifest_digest: ContentDigest,
    invocation_enforcement: String,
    native_boundary: Vec<String>,
    operation_owners: BTreeMap<String, String>,
    outcome: String,
    principal_enforcement: PrincipalEnforcementEvidence,
    principal_inventory_digest: ContentDigest,
    raw_surfaces: BTreeMap<String, aiaf_v1::component_graph::ComponentSurfaceEvidenceV1>,
    scoped_surfaces: BTreeMap<String, aiaf_v1::component_graph::ComponentSurfaceEvidenceV1>,
    principals: Vec<GraphNodePrincipalV2>,
    required_semantic_owners: BTreeMap<String, String>,
    schema: String,
    strict_validator: String,
    validator_identity: String,
    validator_version: String,
}

#[derive(Serialize)]
struct PrincipalEnforcementEvidence {
    aliases_unique: bool,
    all_direct_host_bindings_aliased: bool,
    all_manifest_nodes_covered: bool,
    grants_exact: bool,
    graph_union_absent: bool,
    no_unaliased_host_imports: bool,
    result: String,
}

#[derive(Serialize)]
struct PrincipalInventoryEvidence {
    graph_manifest_digest: ContentDigest,
    import_alias_scheme: String,
    principal_id_scheme: String,
    principals: Vec<GraphNodePrincipalV2>,
    schema: String,
}

#[derive(Serialize)]
struct AuthorityTraceSummary {
    aliases: Vec<String>,
    call_count: usize,
    consumers: Vec<String>,
    graph_manifest_digests: Vec<Sha256Digest>,
    phase: String,
    profile_mapping_verified: bool,
    trace_digest: ContentDigest,
}

#[derive(Serialize)]
struct PackageIndex {
    certification_digest: ContentDigest,
    certified_kernel_tcb_inventory_digest: ContentDigest,
    graph_manifest_digest: ContentDigest,
    package_schema: String,
    root_authority_digest: ContentDigest,
    root_executable_digest: ContentDigest,
    validation_report_digest: ContentDigest,
}

#[derive(Serialize)]
struct ExecutionEvidence {
    exact_replay: ExactReplayEvidence,
    evolution_shadow_matched: bool,
    final_output_digest: ContentDigest,
    graph_manifest_digest: ContentDigest,
    job_id: String,
    probe_status: u16,
    provenance: BTreeMap<String, ExecutionProvenance>,
    restart_recovery_inspect_equal: bool,
    r1_semantics: R1SemanticEvidence,
    schema: String,
    terminal_result_digest: ContentDigest,
}

#[derive(Serialize)]
struct FactoryCycleEvidence {
    exact_replay: ExactReplayEvidence,
    execution_completions: BTreeMap<String, serde_json::Value>,
    final_output_digest: ContentDigest,
    graph_manifest_digest: ContentDigest,
    job_id: String,
    provenance: BTreeMap<String, ExecutionProvenance>,
    r1_semantics: R1SemanticEvidence,
    source_digest: ContentDigest,
    terminal_result: serde_json::Value,
    terminal_result_digest: ContentDigest,
}

#[derive(Serialize)]
struct R1SemanticEvidence {
    artifact_digest_hex: String,
    base_tree_digest_hex: String,
    bytecode_size_bytes: u64,
    evidence_digest_hex: String,
    evidence_resolved: bool,
    fixture_label: String,
    input_digest: ContentDigest,
    input_media_type: String,
    operation_history: Vec<String>,
    output_digest: ContentDigest,
    output_media_type: String,
    package_digest_hex: String,
    package_verified: bool,
    passed_tests: u32,
    patched_tree_digest_hex: String,
    provider_policy: String,
    request_digest_hex: String,
    resolved_digest_hex: String,
    review_approved: bool,
    review_digest_hex: String,
    source_changed: bool,
    tests_discovered: u32,
    total_tests: u32,
    validation_digest_hex: String,
    verification_digest_hex: String,
}

#[derive(Serialize)]
struct ExactReplayEvidence {
    inspect_blob_equal: bool,
    inspect_bytes_equal: bool,
    job_id_equal: bool,
    mechanism_counters_after: ReplayMechanismCounters,
    mechanism_counters_before: ReplayMechanismCounters,
    mechanism_counters_unchanged: bool,
    mechanism_state_digest_after: ContentDigest,
    mechanism_state_digest_before: ContentDigest,
    mechanism_state_unchanged: bool,
    output_blob_equal: bool,
    output_bytes_equal: bool,
    resubmitted_exact_submit_blob: bool,
    submit_blob: serde_json::Value,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
struct ReplayMechanismCounters {
    committed_transaction_count: u64,
    transaction_version: u64,
    wake_count: u64,
    wake_idempotency_count: u64,
}

struct CompletedJob {
    final_output: KernelBlobRef,
    final_output_bytes: Vec<u8>,
    inspect_bytes: Vec<u8>,
    inspect_reference: KernelBlobRef,
    value: serde_json::Value,
}

struct ExecutedFactoryCycle {
    evidence: FactoryCycleEvidence,
    result: wasm_biotic_kernel::bindings::root::wasm_biotic::factory::foundation::BlobRef,
}

#[derive(Serialize)]
struct LifecycleExecutionEvidence {
    all_factory_semantics_executed_as_components: bool,
    authority_trace_summaries: Vec<AuthorityTraceSummary>,
    component_decided_initial_state_binding: bool,
    component_decided_rollback: bool,
    component_decided_successor_activation: bool,
    graph_qualified_activation_ownership_handoff_verified: bool,
    incumbent_cycle: FactoryCycleEvidence,
    incumbent_graph_manifest_digest: ContentDigest,
    incumbent_state: BlobValue,
    initialization_result: FactoryUpgradeResultV1,
    initialization_result_digest: ContentDigest,
    native_substrate_responsibility: String,
    post_rollback_cycle: FactoryCycleEvidence,
    principal_inventory_digests: BTreeMap<String, ContentDigest>,
    principal_mapping_stable_across_restart_activation_and_rollback: bool,
    restart_preserved_rollback_pair: bool,
    rollback_observation_result: FactoryObservationResultV1,
    rollback_observation_result_digest: ContentDigest,
    schema: String,
    successor_cycle: FactoryCycleEvidence,
    successor_graph_manifest_digest: ContentDigest,
    successor_state: BlobValue,
    upgrade_result: FactoryUpgradeResultV1,
    upgrade_result_digest: ContentDigest,
}

#[derive(Serialize)]
struct PublicKeyLifecyclePackageEvidence {
    graph_manifest_digest: ContentDigest,
    previous_graph_manifest_digest: Option<ContentDigest>,
    signature_and_exact_closure_verified_by_production_admission: bool,
}

#[derive(Serialize)]
struct InactiveSuccessorAdmissionEvidence {
    active_manifest_after_admission: ContentDigest,
    active_manifest_before_admission: ContentDigest,
    active_manifest_unchanged: bool,
    admitted_successor_manifest_digest: ContentDigest,
}

#[derive(Serialize)]
struct PublicKeyLifecycleStateEvidence {
    final_active_manifest_digest: ContentDigest,
    final_active_state: BlobValue,
    final_mechanism_state_digest: ContentDigest,
    fresh_state_directory_required: bool,
    incumbent_bootstrap_manifest_digest: ContentDigest,
    restart_reopened_persisted_state: bool,
}

#[derive(Serialize)]
struct PublicKeyOnlyLifecycleReport {
    build_performed: bool,
    certifier_algorithm: String,
    certifier_key_id: Sha256Digest,
    claim_scope: String,
    component_complete_claim: bool,
    incumbent: PublicKeyLifecyclePackageEvidence,
    inactive_successor_admission: InactiveSuccessorAdmissionEvidence,
    lifecycle: LifecycleExecutionEvidence,
    operator_capacity_sha256: ContentDigest,
    outcome: String,
    private_signing_key_required_or_read: bool,
    public_key_hex: String,
    schema: String,
    signing_performed: bool,
    state: PublicKeyLifecycleStateEvidence,
    successor: PublicKeyLifecyclePackageEvidence,
}

struct ComponentLifecycleRun {
    evidence: LifecycleExecutionEvidence,
    facts: ComponentLifecycleRunFacts,
}

struct ComponentLifecycleRunFacts {
    final_active_manifest_digest: ContentDigest,
    final_active_state: BlobValue,
    final_mechanism_state_digest: ContentDigest,
    inactive_active_manifest_after: ContentDigest,
    inactive_active_manifest_before: ContentDigest,
    incumbent_bootstrap_manifest_digest: ContentDigest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseInventory {
    schema: String,
    root: String,
    required_node_count: usize,
    nodes: Vec<String>,
    dynamic_targets: Vec<String>,
    native_boundary: Vec<String>,
    authority: String,
}

struct OfflineCertifier {
    identity: String,
    key_pair: Ed25519KeyPair,
    version: String,
}

impl OfflineCertifier {
    fn load(path: &Path, identity: String, version: String) -> Result<Self> {
        if identity.trim().is_empty() || version.trim().is_empty() {
            return Err("certifier identity and validator version must be non-empty".into());
        }
        let pkcs8 = fs::read(path)?;
        // OpenSSL emits standards-compliant PKCS#8 v1 for Ed25519, which has
        // no redundant public-key field. Ring derives that public key from the
        // seed; when a v2 document is supplied it still verifies the embedded
        // public key against the private key.
        let key_pair = Ed25519KeyPair::from_pkcs8_maybe_unchecked(&pkcs8)
            .map_err(|_| "certifier key is not Ed25519 PKCS#8 v1 or v2")?;
        Ok(Self {
            identity,
            key_pair,
            version,
        })
    }

    fn public_key_hex(&self) -> String {
        encode_hex(self.key_pair.public_key().as_ref())
    }
}

/// Builds, composes, validates, packages and executes the release.
pub fn run_from_env() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let mut output = PathBuf::from("/tmp/wasm-biotic-component-graph");
    let mut wasm_tools = std::env::var_os("WASM_TOOLS")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("wasm-tools"));
    let mut certifier_pkcs8 = std::env::var_os("WASM_BIOTIC_CERTIFIER_PKCS8").map(PathBuf::from);
    let mut certifier_identity = std::env::var("WASM_BIOTIC_CERTIFIER_IDENTITY").ok();
    let mut validator_version = env!("CARGO_PKG_VERSION").to_string();
    let mut r3_http_constraints = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out" => output = PathBuf::from(args.next().ok_or("--out requires a path")?),
            "--wasm-tools" => {
                wasm_tools = PathBuf::from(args.next().ok_or("--wasm-tools requires a path")?)
            }
            "--certifier-pkcs8" => {
                certifier_pkcs8 = Some(PathBuf::from(
                    args.next().ok_or("--certifier-pkcs8 requires a path")?,
                ));
            }
            "--certifier-identity" => {
                certifier_identity =
                    Some(args.next().ok_or("--certifier-identity requires a value")?);
            }
            "--validator-version" => {
                validator_version = args.next().ok_or("--validator-version requires a value")?;
            }
            "--r3-http-constraints" => {
                r3_http_constraints = Some(PathBuf::from(
                    args.next()
                        .ok_or("--r3-http-constraints requires a JSON config path")?,
                ));
            }
            "--help" | "-h" => {
                println!(
                    "usage: component-graph-package --certifier-pkcs8 PATH --certifier-identity ID [--validator-version VERSION] [--out PATH] [--wasm-tools PATH] [--r3-http-constraints CONFIG_JSON]"
                );
                return Ok(());
            }
            other => return Err(format!("unknown argument: {other}").into()),
        }
    }
    let cargo = std::env::var_os("CARGO")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("cargo"));
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("tool manifest is not two levels below the repository")?
        .to_path_buf();
    let staging = std::env::temp_dir().join(format!(
        "wasm-biotic-component-graph-build-{}",
        std::process::id()
    ));
    if staging.exists() {
        fs::remove_dir_all(&staging)?;
    }
    fs::create_dir_all(&staging)?;

    let certifier = OfflineCertifier::load(
        &certifier_pkcs8.ok_or("--certifier-pkcs8 (or WASM_BIOTIC_CERTIFIER_PKCS8) is required")?,
        certifier_identity
            .ok_or("--certifier-identity (or WASM_BIOTIC_CERTIFIER_IDENTITY) is required")?,
        validator_version,
    )?;
    let release_profile = match r3_http_constraints {
        Some(path) => ReleaseProfileConfig::R3(load_r3_http_constraints(&path)?),
        None => ReleaseProfileConfig::R2,
    };

    let initial = build_package(
        &repo,
        &staging.join("initial"),
        &cargo,
        &wasm_tools,
        None,
        &release_profile,
    )?;
    let initial_validation = strict_validation_report(&initial, &certifier)?;
    let initial_certification = certify_release(&initial, &initial_validation, &certifier)?;
    let initial_dir = output.join(initial.graph.manifest_digest.file_stem());
    write_package(
        &initial_dir,
        &initial,
        &initial_validation,
        &initial_certification,
    )?;

    let successor = build_package(
        &repo,
        &staging.join("successor"),
        &cargo,
        &wasm_tools,
        Some(initial.graph.manifest_digest.clone()),
        &release_profile,
    )?;
    let successor_validation = strict_validation_report(&successor, &certifier)?;
    let successor_certification = certify_release(&successor, &successor_validation, &certifier)?;
    let successor_dir = output.join(successor.graph.manifest_digest.file_stem());
    write_package(
        &successor_dir,
        &successor,
        &successor_validation,
        &successor_certification,
    )?;

    execute_kernel_probe(&initial_dir, &initial, &certifier.public_key_hex())?;
    let lifecycle_digest = execute_component_lifecycle(
        &initial_dir,
        &successor_dir,
        &initial,
        &successor,
        &certifier.public_key_hex(),
    )?;
    println!("graph_manifest_digest={}", initial.graph.manifest_digest);
    println!(
        "initial_graph_manifest_digest={}",
        initial.graph.manifest_digest
    );
    println!(
        "successor_graph_manifest_digest={}",
        successor.graph.manifest_digest
    );
    println!(
        "validation_report_digest={}",
        ContentDigest::from_bytes(&initial_validation)
    );
    println!(
        "certification_digest={}",
        ContentDigest::from_bytes(&initial_certification)
    );
    println!(
        "successor_certification_digest={}",
        ContentDigest::from_bytes(&successor_certification)
    );
    println!("component_lifecycle_evidence_digest={lifecycle_digest}");
    println!(
        "certifier_key_id={}",
        ContentDigest::from_bytes(certifier.key_pair.public_key().as_ref())
    );
    println!("certifier_public_key_hex={}", certifier.public_key_hex());
    println!("release_directory={}", initial_dir.display());
    println!("successor_release_directory={}", successor_dir.display());
    Ok(())
}

/// Executes the retained incumbent/successor lifecycle using public trust only.
///
/// This entry point never builds a component, reads a signing key or emits a
/// release signature. The supplied state directory must be absent or empty,
/// and the report path must not already exist.
pub fn run_public_key_lifecycle(
    incumbent_directory: &Path,
    successor_directory: &Path,
    public_key_hex: &str,
    operator_capacity: &Path,
    state_directory: &Path,
    report_path: &Path,
) -> Result<ContentDigest> {
    if fs::symlink_metadata(report_path).is_ok() {
        return Err(format!("report path {} already exists", report_path.display()).into());
    }
    let incumbent = load_retained_lifecycle_package(incumbent_directory)?;
    let successor = load_retained_lifecycle_package(successor_directory)?;
    if successor.graph.manifest.previous_graph.as_ref() != Some(&incumbent.graph.manifest_digest) {
        return Err("successor package is not linked to the exact incumbent graph".into());
    }
    let trusted_certifier = TrustedCertifier::from_public_key_hex(public_key_hex)?;
    let operator_capacity_sha256 = ContentDigest::from_bytes(&fs::read(operator_capacity)?);
    prepare_fresh_state_directory(state_directory)?;
    let run = execute_component_lifecycle_at(
        state_directory,
        incumbent_directory,
        successor_directory,
        &incumbent,
        &successor,
        public_key_hex,
        Some(operator_capacity),
    )?;
    if run.facts.final_active_manifest_digest != incumbent.graph.manifest_digest {
        return Err("public lifecycle did not finish on the exact incumbent graph".into());
    }
    let active_unchanged = run.facts.inactive_active_manifest_before
        == run.facts.inactive_active_manifest_after
        && run.facts.inactive_active_manifest_after == incumbent.graph.manifest_digest;
    if !active_unchanged {
        return Err("inactive successor admission changed the active graph".into());
    }
    let report = PublicKeyOnlyLifecycleReport {
        build_performed: false,
        certifier_algorithm: "ed25519".to_string(),
        certifier_key_id: trusted_certifier.key_id(),
        claim_scope: "Public-key-only execution of one exact retained incumbent/successor package lifecycle: initialization, incumbent bootstrap, inactive successor admission, component-directed upgrade, component-directed unhealthy-observation rollback, restart, final incumbent execution and exact replay. Aggregate component completeness remains release-bundle authority.".to_string(),
        component_complete_claim: false,
        incumbent: PublicKeyLifecyclePackageEvidence {
            graph_manifest_digest: incumbent.graph.manifest_digest.clone(),
            previous_graph_manifest_digest: incumbent.graph.manifest.previous_graph.clone(),
            signature_and_exact_closure_verified_by_production_admission: true,
        },
        inactive_successor_admission: InactiveSuccessorAdmissionEvidence {
            active_manifest_after_admission: run
                .facts
                .inactive_active_manifest_after
                .clone(),
            active_manifest_before_admission: run
                .facts
                .inactive_active_manifest_before
                .clone(),
            active_manifest_unchanged: active_unchanged,
            admitted_successor_manifest_digest: successor.graph.manifest_digest.clone(),
        },
        lifecycle: run.evidence,
        outcome: "pass".to_string(),
        operator_capacity_sha256,
        private_signing_key_required_or_read: false,
        public_key_hex: public_key_hex.to_string(),
        schema: "wasm-biotic.public-key-only-component-lifecycle.v1".to_string(),
        signing_performed: false,
        state: PublicKeyLifecycleStateEvidence {
            final_active_manifest_digest: run.facts.final_active_manifest_digest,
            final_active_state: run.facts.final_active_state,
            final_mechanism_state_digest: run.facts.final_mechanism_state_digest,
            fresh_state_directory_required: true,
            incumbent_bootstrap_manifest_digest: run
                .facts
                .incumbent_bootstrap_manifest_digest,
            restart_reopened_persisted_state: true,
        },
        successor: PublicKeyLifecyclePackageEvidence {
            graph_manifest_digest: successor.graph.manifest_digest.clone(),
            previous_graph_manifest_digest: successor.graph.manifest.previous_graph.clone(),
            signature_and_exact_closure_verified_by_production_admission: true,
        },
    };
    let report_bytes = canonical_json_bytes(&report)?;
    write_bytes(report_path, &report_bytes)?;
    Ok(ContentDigest::from_bytes(&report_bytes))
}

/// Parses the dedicated public-key lifecycle binary's closed argument set.
pub fn run_public_key_lifecycle_from_env() -> Result<()> {
    let mut arguments = std::env::args().skip(1);
    let mut incumbent = None;
    let mut successor = None;
    let mut public_key_hex = None;
    let mut operator_capacity = None;
    let mut state_directory = None;
    let mut report_path = None;
    while let Some(argument) = arguments.next() {
        let (slot, label): (&mut Option<String>, &str) = match argument.as_str() {
            "--incumbent" => (&mut incumbent, "--incumbent"),
            "--successor" => (&mut successor, "--successor"),
            "--public-key-hex" => (&mut public_key_hex, "--public-key-hex"),
            "--operator-capacity" => (&mut operator_capacity, "--operator-capacity"),
            "--state-dir" => (&mut state_directory, "--state-dir"),
            "--out" => (&mut report_path, "--out"),
            "--help" | "-h" => {
                println!(
                    "usage: public-key-lifecycle --incumbent PACKAGE --successor PACKAGE --public-key-hex HEX --operator-capacity OPERATOR_CONFIG_JSON --state-dir FRESH_STATE --out REPORT_JSON"
                );
                return Ok(());
            }
            other => return Err(format!("unknown argument: {other}").into()),
        };
        if slot.is_some() {
            return Err(format!("{label} may be supplied only once").into());
        }
        *slot = Some(
            arguments
                .next()
                .ok_or_else(|| format!("{label} requires a value"))?,
        );
    }
    let incumbent = PathBuf::from(incumbent.ok_or("--incumbent is required")?);
    let successor = PathBuf::from(successor.ok_or("--successor is required")?);
    let public_key_hex = public_key_hex.ok_or("--public-key-hex is required")?;
    let operator_capacity =
        PathBuf::from(operator_capacity.ok_or("--operator-capacity is required")?);
    let state_directory = PathBuf::from(state_directory.ok_or("--state-dir is required")?);
    let report_path = PathBuf::from(report_path.ok_or("--out is required")?);
    let digest = run_public_key_lifecycle(
        &incumbent,
        &successor,
        &public_key_hex,
        &operator_capacity,
        &state_directory,
        &report_path,
    )?;
    println!("public_key_lifecycle_report_digest={digest}");
    println!("public_key_lifecycle_report={}", report_path.display());
    Ok(())
}

fn prepare_fresh_state_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(format!(
                    "state path {} must be an empty non-symlink directory",
                    path.display()
                )
                .into());
            }
            if fs::read_dir(path)?.next().is_some() {
                return Err(format!("state directory {} is not fresh", path.display()).into());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(path)?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

enum ReleaseSubstrateProfile {
    R2(SubstrateProfileV2),
    R3(SubstrateProfileV3),
}

impl ReleaseSubstrateProfile {
    fn canonical_bytes(&self) -> Result<Vec<u8>> {
        match self {
            Self::R2(profile) => profile.canonical_bytes().map_err(Into::into),
            Self::R3(profile) => profile.canonical_bytes().map_err(Into::into),
        }
    }

    fn principals(&self) -> &[GraphNodePrincipalV2] {
        match self {
            Self::R2(profile) => &profile.principals,
            Self::R3(profile) => &profile.principals,
        }
    }

    fn import_alias_scheme(&self) -> &str {
        match self {
            Self::R2(profile) => &profile.import_alias_scheme,
            Self::R3(profile) => &profile.import_alias_scheme,
        }
    }

    fn principal_id_scheme(&self) -> &str {
        match self {
            Self::R2(profile) => &profile.principal_id_scheme,
            Self::R3(profile) => &profile.principal_id_scheme,
        }
    }

    fn static_grant_model(&self) -> StaticGrantModelV2 {
        match self {
            Self::R2(profile) => profile.static_grant_model,
            Self::R3(profile) => profile.static_grant_model,
        }
    }

    fn insert_artifact(&self, artifacts: &mut ComponentGraphArtifacts) -> Result<ContentDigest> {
        match self {
            Self::R2(profile) => artifacts
                .insert_substrate_profile_v2(profile)
                .map_err(Into::into),
            Self::R3(profile) => artifacts
                .insert_substrate_profile_v3(profile)
                .map_err(Into::into),
        }
    }
}

fn load_r3_http_constraints(path: &Path) -> Result<HttpTransportConstraintsV1> {
    let bytes = fs::read(path).map_err(|error| {
        format!(
            "cannot read R3 HTTP constraint document {}: {error}",
            path.display()
        )
    })?;
    let constraints: HttpTransportConstraintsV1 =
        serde_json::from_slice(&bytes).map_err(|error| {
            format!(
                "R3 HTTP constraint document {} is not closed schema v1: {error}",
                path.display()
            )
        })?;
    constraints
        .validate_against(&CapabilityConstraintsV1::bounded_local_default())
        .map_err(|reasons| {
            format!(
                "R3 HTTP constraint document {} is invalid: {}",
                path.display(),
                reasons.join("; ")
            )
        })?;
    Ok(constraints)
}

struct ReleasePackage {
    graph: AddressedComponentGraphV1,
    artifacts: ComponentGraphArtifacts,
    descriptor: ComponentDerivationDescriptorV2,
    metadata: ComponentGraphMetadataV1,
    profile: ReleaseSubstrateProfile,
    raw: BTreeMap<String, Vec<u8>>,
    scoped: BTreeMap<String, Vec<u8>>,
    composed_root: Vec<u8>,
    native_tcb_inventory: Vec<u8>,
    native_tcb_inventory_digest: ContentDigest,
    wasm_tools_version: String,
}

trait LifecyclePackageView {
    fn graph(&self) -> &AddressedComponentGraphV1;
    fn descriptor(&self) -> &ComponentDerivationDescriptorV2;
    fn profile(&self) -> &ReleaseSubstrateProfile;
}

impl LifecyclePackageView for ReleasePackage {
    fn graph(&self) -> &AddressedComponentGraphV1 {
        &self.graph
    }

    fn descriptor(&self) -> &ComponentDerivationDescriptorV2 {
        &self.descriptor
    }

    fn profile(&self) -> &ReleaseSubstrateProfile {
        &self.profile
    }
}

struct RetainedLifecyclePackage {
    graph: AddressedComponentGraphV1,
    descriptor: ComponentDerivationDescriptorV2,
    profile: ReleaseSubstrateProfile,
}

impl LifecyclePackageView for RetainedLifecyclePackage {
    fn graph(&self) -> &AddressedComponentGraphV1 {
        &self.graph
    }

    fn descriptor(&self) -> &ComponentDerivationDescriptorV2 {
        &self.descriptor
    }

    fn profile(&self) -> &ReleaseSubstrateProfile {
        &self.profile
    }
}

fn read_canonical_json<T>(path: &Path, label: &str) -> Result<T>
where
    T: DeserializeOwned + Serialize,
{
    let bytes = fs::read(path)
        .map_err(|error| format!("cannot read {label} {}: {error}", path.display()))?;
    let value: T = serde_json::from_slice(&bytes)
        .map_err(|error| format!("cannot decode {label} {}: {error}", path.display()))?;
    let canonical = canonical_json_bytes(&value)?;
    if bytes != canonical {
        return Err(format!("{label} {} is not canonical JSON", path.display()).into());
    }
    Ok(value)
}

fn load_retained_lifecycle_package(directory: &Path) -> Result<RetainedLifecyclePackage> {
    if !directory.is_dir() || directory.is_symlink() {
        return Err(format!(
            "retained package {} must be a non-symlink directory",
            directory.display()
        )
        .into());
    }
    let manifest: ComponentGraphManifestV1 =
        read_canonical_json(&directory.join("manifest.json"), "graph manifest")?;
    let graph = AddressedComponentGraphV1::seal(manifest)?;
    if directory.file_name().and_then(|name| name.to_str())
        != Some(graph.manifest_digest.file_stem().as_str())
    {
        return Err(format!(
            "retained package directory {} does not match manifest {}",
            directory.display(),
            graph.manifest_digest
        )
        .into());
    }
    let descriptor: ComponentDerivationDescriptorV2 = read_canonical_json(
        &directory.join("derivation-descriptor.json"),
        "derivation descriptor",
    )?;
    if descriptor.schema != DERIVATION_DESCRIPTOR_SCHEMA_V2 {
        return Err("public lifecycle requires a per-consumer v2 derivation descriptor".into());
    }
    let profile_path = directory.join("substrate-profile.json");
    let profile_value: serde_json::Value = read_canonical_json(&profile_path, "substrate profile")?;
    let profile = match profile_value
        .get("schema")
        .and_then(serde_json::Value::as_str)
    {
        Some(SUBSTRATE_PROFILE_SCHEMA_V2) => ReleaseSubstrateProfile::R2(
            serde_json::from_value(profile_value)
                .map_err(|error| format!("cannot decode R2 substrate profile: {error}"))?,
        ),
        Some(SUBSTRATE_PROFILE_SCHEMA_V3) => ReleaseSubstrateProfile::R3(
            serde_json::from_value(profile_value)
                .map_err(|error| format!("cannot decode R3 substrate profile: {error}"))?,
        ),
        Some(schema) => {
            return Err(format!("unsupported retained substrate profile {schema}").into());
        }
        None => return Err("retained substrate profile has no schema".into()),
    };
    Ok(RetainedLifecyclePackage {
        graph,
        descriptor,
        profile,
    })
}

struct EphemeralKernelState(PathBuf);

impl EphemeralKernelState {
    fn create() -> Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "wasm-biotic-kernel-execution-{}",
            std::process::id()
        ));
        if path.exists() {
            fs::remove_dir_all(&path)?;
        }
        fs::create_dir_all(&path)?;
        Ok(Self(path))
    }
}

impl Drop for EphemeralKernelState {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn build_package(
    repo: &Path,
    staging: &Path,
    cargo: &Path,
    wasm_tools: &Path,
    previous_graph: Option<ContentDigest>,
    release_profile: &ReleaseProfileConfig,
) -> Result<ReleasePackage> {
    // Keep Cargo's compilation cache outside the disposable composition
    // staging directory. A failed admission run must be cheap to repeat, and
    // none of these mutable build products are part of the sealed release.
    let build_cache = std::env::var_os("WASM_BIOTIC_COMPONENT_BUILD_CACHE")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("wasm-biotic-component-graph-cache"));
    let target_components = build_cache.join("components");
    let target_workers = build_cache.join("workers");
    let target_supervisor = build_cache.join("supervisor");
    validate_release_inventory()?;
    build_components(
        repo,
        cargo,
        &target_components,
        &target_workers,
        &target_supervisor,
    )?;

    let specs = node_specs();
    let mut built = BTreeMap::new();
    for spec in specs {
        let target = match spec.group {
            BuildGroup::Components => &target_components,
            BuildGroup::Workers => &target_workers,
            BuildGroup::Supervisor => &target_supervisor,
        };
        let path = target.join("wasm32-wasip2/release").join(spec.artifact);
        let bytes = fs::read(&path)
            .map_err(|error| format!("cannot read built component {}: {error}", path.display()))?;
        let digest = ContentDigest::from_bytes(&bytes);
        built.insert(
            spec.id.to_string(),
            BuiltNode {
                spec,
                bytes,
                digest,
            },
        );
    }

    let bindings = manifest_bindings();
    let invocations = manifest_invocations();
    let constraints = CapabilityConstraintsV1::bounded_local_default();
    let constraints_bytes = constraints.canonical_bytes()?;
    let constraints_digest = ContentDigest::from_bytes(&constraints_bytes);
    let r3_http_constraint = match release_profile {
        ReleaseProfileConfig::R2 => None,
        ReleaseProfileConfig::R3(http_constraints) => {
            http_constraints
                .validate_against(&constraints)
                .map_err(|reasons| {
                    format!("R3 HTTP constraints are invalid: {}", reasons.join("; "))
                })?;
            let bytes = http_constraints.canonical_bytes()?;
            Some((ContentDigest::from_bytes(&bytes), bytes))
        }
    };
    let nodes = manifest_nodes(
        &built,
        &bindings,
        &constraints_digest,
        r3_http_constraint.as_ref().map(|(digest, _)| digest),
    )?;
    let (scoped, principals) = scope_nodes(&built, &nodes, &bindings)?;
    let profile = match release_profile {
        ReleaseProfileConfig::R2 => ReleaseSubstrateProfile::R2(
            SubstrateProfileV2::component_complete("factory-control", principals, constraints),
        ),
        ReleaseProfileConfig::R3(_) => {
            let http_bindings = bounded_r3_http_bindings(&principals)?;
            ReleaseSubstrateProfile::R3(SubstrateProfileV3::component_complete(
                "factory-control",
                principals,
                constraints,
                http_bindings,
            ))
        }
    };

    let (wit_package_bytes, wit_world_bytes, world_digests) = wit_artifacts(repo)?;
    let wit_package_digest = ContentDigest::from_bytes(&wit_package_bytes);
    let raw_dir = staging.join("raw");
    let scoped_dir = staging.join("scoped");
    fs::create_dir_all(&raw_dir)?;
    fs::create_dir_all(&scoped_dir)?;
    for (id, node) in &built {
        fs::write(raw_dir.join(format!("{id}.wasm")), &node.bytes)?;
    }
    for (id, node) in &scoped {
        fs::write(scoped_dir.join(format!("{id}.wasm")), &node.bytes)?;
    }

    let wasm_tools_version = command_output(wasm_tools, &["--version"], repo)?;
    let (executables, derived, configurations, composed_root) = compose_authorities(
        staging,
        wasm_tools,
        &built,
        &scoped,
        profile.principals(),
        CompositionGraph {
            nodes: &nodes,
            bindings: &bindings,
            invocations: &invocations,
        },
    )?;
    let descriptor = ComponentDerivationDescriptorV2 {
        schema: DERIVATION_DESCRIPTOR_SCHEMA_V2.to_string(),
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
            version: wasm_tools_version.clone(),
            options: vec![
                "--config=<content-addressed-config>".to_string(),
                "--output=<content-addressed-component>".to_string(),
            ],
        },
    };
    let descriptor_bytes = descriptor.canonical_bytes()?;
    let descriptor_digest = ContentDigest::from_bytes(&descriptor_bytes);
    let profile_bytes = profile.canonical_bytes()?;
    let profile_digest = ContentDigest::from_bytes(&profile_bytes);
    let metadata = ComponentGraphMetadataV1 {
        schema: GRAPH_METADATA_SCHEMA_V1.to_string(),
        wit_package_digest: wit_package_digest.clone(),
        wit_world_digests: world_digests,
        substrate_profile_digest: profile_digest,
        derivation_descriptor_digest: descriptor_digest,
    };
    let metadata_bytes = metadata.canonical_bytes()?;
    let metadata_digest = ContentDigest::from_bytes(&metadata_bytes);
    let graph = AddressedComponentGraphV1::seal(ComponentGraphManifestV1 {
        schema: COMPONENT_GRAPH_SCHEMA_V1.to_string(),
        wit_package: FACTORY_WIT_PACKAGE_V1.to_string(),
        root_node: "factory-control".to_string(),
        previous_graph,
        state_schema: "wasm-biotic.supervisor-state.v1".to_string(),
        nodes,
        bindings,
        invocations,
        metadata: Some(metadata_digest),
    })?;

    let mut artifacts = ComponentGraphArtifacts::default();
    for (id, node) in &built {
        artifacts.insert_component(id, node.bytes.clone());
    }
    artifacts.insert_constraints(constraints_bytes);
    if let Some((_, bytes)) = r3_http_constraint {
        artifacts.insert_constraints(bytes);
    }
    artifacts.insert_wit_package(wit_package_bytes);
    artifacts.insert_wit_world(wit_world_bytes);
    profile.insert_artifact(&mut artifacts)?;
    artifacts.insert_derivation_descriptor_v2(&descriptor)?;
    artifacts.insert_metadata(&metadata)?;
    for node in scoped.values() {
        artifacts.insert_scoped_component(node.bytes.clone());
    }
    for bytes in derived.values() {
        artifacts.insert_derived_component(bytes.clone());
    }
    for bytes in configurations.values() {
        artifacts.insert_composition_config(bytes.clone());
    }
    aiaf_v1::component_graph::validate_component_graph(&graph, &artifacts)
        .map_err(|error| format!("release graph rejected: {:?}", error.violations))?;
    let native_tcb_inventory = fs::read(repo.join("kernel/native-tcb.json"))?;
    let native_tcb_inventory_digest = ContentDigest::from_bytes(&native_tcb_inventory);

    Ok(ReleasePackage {
        graph,
        artifacts,
        descriptor,
        metadata,
        profile,
        raw: built
            .into_iter()
            .map(|(id, node)| (id, node.bytes))
            .collect(),
        scoped: scoped
            .into_iter()
            .map(|(id, node)| (id, node.bytes))
            .collect(),
        composed_root,
        native_tcb_inventory,
        native_tcb_inventory_digest,
        wasm_tools_version,
    })
}

fn validate_release_inventory() -> Result<()> {
    let inventory: ReleaseInventory = serde_json::from_str(include_str!("../release-v1.json"))?;
    let nodes = node_specs()
        .into_iter()
        .map(|node| node.id.to_string())
        .collect::<Vec<_>>();
    let targets = manifest_invocations()
        .into_iter()
        .map(|edge| edge.target)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let boundary = aiaf_v1::component_graph::REQUIRED_SUBSTRATE_PRIMITIVES
        .iter()
        .map(|primitive| primitive.interface_name().to_string())
        .collect::<Vec<_>>();
    let declared_boundary = inventory
        .native_boundary
        .iter()
        .map(|name| iface(name).to_string())
        .collect::<Vec<_>>();
    if inventory.schema != "wasm-biotic.component-release-source.v1"
        || inventory.root != "factory-control"
        || inventory.required_node_count != nodes.len()
        || inventory.nodes != nodes
        || inventory.dynamic_targets != targets
        || declared_boundary != boundary
        || inventory.authority.trim().is_empty()
    {
        return Err("release-v1.json does not match the compiled release definition".into());
    }
    Ok(())
}

fn build_components(
    repo: &Path,
    cargo: &Path,
    components_target: &Path,
    workers_target: &Path,
    supervisor_target: &Path,
) -> Result<()> {
    let common = ["--locked", "--release", "--target", "wasm32-wasip2"];

    let mut command = Command::new(cargo);
    command
        .current_dir(repo)
        .arg("build")
        .arg("--manifest-path")
        .arg("components/Cargo.toml")
        .arg("--workspace")
        // The worker router deliberately links the shared policy crate without
        // its service-component ABI. Build that component as its own Cargo
        // root so workspace feature unification cannot graft another
        // component's allocator/panic exports into its binary.
        .args(["--exclude", "wasm-biotic-worker-router"])
        .args(common)
        .arg("--target-dir")
        .arg(components_target);
    run_checked(&mut command, "build component workspace")?;

    let mut command = Command::new(cargo);
    command
        .current_dir(repo)
        .arg("build")
        .arg("--manifest-path")
        .arg("components/Cargo.toml")
        .args(["-p", "wasm-biotic-worker-router"])
        .args(common)
        .arg("--target-dir")
        .arg(components_target);
    run_checked(&mut command, "build isolated worker-router component")?;

    let mut command = Command::new(cargo);
    command
        .current_dir(repo)
        .arg("build")
        .arg("--manifest-path")
        .arg("components/workers/Cargo.toml")
        .args([
            "-p",
            "wasm-biotic-planner-worker",
            "-p",
            "wasm-biotic-builder-worker",
            "-p",
            "wasm-biotic-validator-worker",
            "-p",
            "wasm-biotic-reviewer-worker",
            "-p",
            "wasm-biotic-packager-worker",
            "-p",
            "wasm-biotic-continuity-worker",
        ])
        .args(common)
        .arg("--target-dir")
        .arg(workers_target);
    run_checked(&mut command, "build six worker components")?;

    let mut command = Command::new(cargo);
    command
        .current_dir(repo)
        .arg("build")
        .arg("--manifest-path")
        .arg("components/supervisor-reducer/Cargo.toml")
        .args(common)
        .arg("--target-dir")
        .arg(supervisor_target);
    run_checked(&mut command, "build supervisor reducer component")
}

fn iface(name: &str) -> &'static str {
    match name {
        "activation" => "wasm-biotic:factory/activation@0.1.0",
        "audit-log" => "wasm-biotic:factory/audit-log@0.1.0",
        "blob-store" => "wasm-biotic:factory/blob-store@0.1.0",
        "build-service" => "wasm-biotic:factory/build-service@0.1.0",
        "capability-router" => "wasm-biotic:factory/capability-router@0.1.0",
        "clock" => "wasm-biotic:factory/clock@0.1.0",
        "closure-evaluator" => "wasm-biotic:factory/closure-evaluator@0.1.0",
        "component-runner" => "wasm-biotic:factory/component-runner@0.1.0",
        "continuity-service" => "wasm-biotic:factory/continuity-service@0.1.0",
        "exchange-service" => "wasm-biotic:factory/exchange-service@0.1.0",
        "factory-api" => "wasm-biotic:factory/factory-api@0.1.0",
        "factory-control" => "wasm-biotic:factory/factory-control@0.1.0",
        "factory-evolution" => "wasm-biotic:factory/factory-evolution@0.1.0",
        "http-transport" => "wasm-biotic:factory/http-transport@0.1.0",
        "key-service" => "wasm-biotic:factory/key-service@0.1.0",
        "operations-service" => "wasm-biotic:factory/operations-service@0.1.0",
        "packaging-service" => "wasm-biotic:factory/packaging-service@0.1.0",
        "review-service" => "wasm-biotic:factory/review-service@0.1.0",
        "scheduling-service" => "wasm-biotic:factory/scheduling-service@0.1.0",
        "state-migration" => "wasm-biotic:factory/state-migration@0.1.0",
        "supervisor-reducer" => "wasm-biotic:factory/supervisor-reducer@0.1.0",
        "transaction-store" => "wasm-biotic:factory/transaction-store@0.1.0",
        "validation-service" => "wasm-biotic:factory/validation-service@0.1.0",
        "worker-router" => "wasm-biotic:factory/worker-router@0.1.0",
        "worker-workflow" => "wasm-biotic:factory/worker-workflow@0.1.0",
        other => panic!("unknown frozen interface {other}"),
    }
}

fn node_specs() -> Vec<NodeSpec> {
    let mut specs = vec![
        node(
            "admitted-tool-probe",
            FactoryComponentKind::AdmittedTool,
            BuildGroup::Components,
            "wasm_biotic_admitted_tool_probe.wasm",
            vec![COMPONENT_TASK_EXPORT],
        ),
        node(
            "build-service",
            FactoryComponentKind::BuildService,
            BuildGroup::Components,
            "wasm_biotic_build_service.wasm",
            vec![iface("build-service")],
        ),
        node(
            "builder-worker",
            FactoryComponentKind::BuilderWorker,
            BuildGroup::Workers,
            "wasm_biotic_builder_worker.wasm",
            vec![COMPONENT_TASK_EXPORT, iface("worker-workflow")],
        ),
        node(
            "capability-router",
            FactoryComponentKind::CapabilityRouter,
            BuildGroup::Components,
            "wasm_biotic_capability_router.wasm",
            vec![iface("capability-router")],
        ),
        node(
            "closure-evaluator",
            FactoryComponentKind::ClosureEvaluator,
            BuildGroup::Components,
            "wasm_biotic_closure_evaluator.wasm",
            vec![iface("closure-evaluator"), COMPONENT_TASK_EXPORT],
        ),
        node(
            "continuity-service",
            FactoryComponentKind::ContinuityService,
            BuildGroup::Components,
            "wasm_biotic_continuity_service.wasm",
            vec![iface("continuity-service")],
        ),
        node(
            "continuity-worker",
            FactoryComponentKind::ContinuityWorker,
            BuildGroup::Workers,
            "wasm_biotic_continuity_worker.wasm",
            vec![COMPONENT_TASK_EXPORT, iface("worker-workflow")],
        ),
        node(
            "exchange-service",
            FactoryComponentKind::ExchangeService,
            BuildGroup::Components,
            "wasm_biotic_exchange_service.wasm",
            vec![iface("exchange-service")],
        ),
        node(
            "factory-control",
            FactoryComponentKind::Root,
            BuildGroup::Components,
            "wasm_biotic_factory_control.wasm",
            vec![iface("factory-api"), iface("factory-control")],
        ),
        node(
            "factory-evolution",
            FactoryComponentKind::FactoryEvolution,
            BuildGroup::Components,
            "wasm_biotic_factory_evolution.wasm",
            vec![COMPONENT_TASK_EXPORT, iface("factory-evolution")],
        ),
        node(
            "operations-service",
            FactoryComponentKind::OperationsService,
            BuildGroup::Components,
            "wasm_biotic_operations_service.wasm",
            vec![iface("operations-service")],
        ),
        node(
            "packager-worker",
            FactoryComponentKind::PackagerWorker,
            BuildGroup::Workers,
            "wasm_biotic_packager_worker.wasm",
            vec![COMPONENT_TASK_EXPORT, iface("worker-workflow")],
        ),
        node(
            "packaging-service",
            FactoryComponentKind::PackagingService,
            BuildGroup::Components,
            "wasm_biotic_packaging_service.wasm",
            vec![iface("packaging-service")],
        ),
        node(
            "planner-worker",
            FactoryComponentKind::PlannerWorker,
            BuildGroup::Workers,
            "wasm_biotic_planner_worker.wasm",
            vec![COMPONENT_TASK_EXPORT, iface("worker-workflow")],
        ),
        node(
            "review-service",
            FactoryComponentKind::ReviewService,
            BuildGroup::Components,
            "wasm_biotic_review_service.wasm",
            vec![iface("review-service")],
        ),
        node(
            "reviewer-worker",
            FactoryComponentKind::ReviewerWorker,
            BuildGroup::Workers,
            "wasm_biotic_reviewer_worker.wasm",
            vec![COMPONENT_TASK_EXPORT, iface("worker-workflow")],
        ),
        node(
            "scheduling-service",
            FactoryComponentKind::SchedulingService,
            BuildGroup::Components,
            "wasm_biotic_scheduling_service.wasm",
            vec![iface("scheduling-service")],
        ),
        node(
            "state-migration",
            FactoryComponentKind::StateMigration,
            BuildGroup::Components,
            "wasm_biotic_state_migration.wasm",
            vec![COMPONENT_TASK_EXPORT, iface("state-migration")],
        ),
        node(
            "supervisor-reducer",
            FactoryComponentKind::SupervisorReducer,
            BuildGroup::Supervisor,
            "wasm_biotic_supervisor_reducer.wasm",
            vec![iface("supervisor-reducer")],
        ),
        node(
            "validation-service",
            FactoryComponentKind::ValidationService,
            BuildGroup::Components,
            "wasm_biotic_validation_service.wasm",
            vec![iface("validation-service")],
        ),
        node(
            "validator-worker",
            FactoryComponentKind::ValidatorWorker,
            BuildGroup::Workers,
            "wasm_biotic_validator_worker.wasm",
            vec![COMPONENT_TASK_EXPORT, iface("worker-workflow")],
        ),
        node(
            "worker-router",
            FactoryComponentKind::WorkerRouter,
            BuildGroup::Components,
            "wasm_biotic_worker_router.wasm",
            vec![iface("worker-router")],
        ),
    ];
    if let Some(root) = specs.iter_mut().find(|node| node.id == "factory-control") {
        root.state_schema = Some("wasm-biotic.supervisor-state.v1");
    }
    specs.sort_by_key(|node| node.id);
    specs
}

fn node(
    id: &'static str,
    kind: FactoryComponentKind,
    group: BuildGroup,
    artifact: &'static str,
    exports: Vec<&'static str>,
) -> NodeSpec {
    NodeSpec {
        id,
        kind,
        world: kind.expected_world(),
        exports,
        group,
        artifact,
        state_schema: None,
    }
}

fn manifest_bindings() -> Vec<ComponentImportBinding> {
    let specs = vec![
        host("admitted-tool-probe", SubstratePrimitive::BlobStore),
        host("build-service", SubstratePrimitive::BlobStore),
        component("builder-worker", "build-service", "build-service"),
        host("builder-worker", SubstratePrimitive::BlobStore),
        component("capability-router", "build-service", "build-service"),
        component(
            "capability-router",
            "continuity-service",
            "continuity-service",
        ),
        component(
            "capability-router",
            "operations-service",
            "operations-service",
        ),
        component(
            "capability-router",
            "packaging-service",
            "packaging-service",
        ),
        component("capability-router", "review-service", "review-service"),
        component(
            "capability-router",
            "scheduling-service",
            "scheduling-service",
        ),
        component(
            "capability-router",
            "validation-service",
            "validation-service",
        ),
        host("capability-router", SubstratePrimitive::BlobStore),
        host("capability-router", SubstratePrimitive::TransactionStore),
        host("capability-router", SubstratePrimitive::KeyService),
        host("closure-evaluator", SubstratePrimitive::BlobStore),
        host("continuity-service", SubstratePrimitive::BlobStore),
        component(
            "continuity-worker",
            "continuity-service",
            "continuity-service",
        ),
        host("continuity-worker", SubstratePrimitive::BlobStore),
        host("exchange-service", SubstratePrimitive::BlobStore),
        host("exchange-service", SubstratePrimitive::Clock),
        host("exchange-service", SubstratePrimitive::HttpTransport),
        host("exchange-service", SubstratePrimitive::KeyService),
        host("exchange-service", SubstratePrimitive::TransactionStore),
        host("factory-control", SubstratePrimitive::Activation),
        host("factory-control", SubstratePrimitive::AuditLog),
        host("factory-control", SubstratePrimitive::BlobStore),
        component("factory-control", "capability-router", "capability-router"),
        component("factory-control", "closure-evaluator", "closure-evaluator"),
        component("factory-control", "exchange-service", "exchange-service"),
        component("factory-control", "factory-evolution", "factory-evolution"),
        component("factory-control", "state-migration", "state-migration"),
        component(
            "factory-control",
            "supervisor-reducer",
            "supervisor-reducer",
        ),
        host("factory-control", SubstratePrimitive::TransactionStore),
        component("factory-control", "worker-router", "worker-router"),
        host("factory-evolution", SubstratePrimitive::BlobStore),
        host("factory-evolution", SubstratePrimitive::ComponentRunner),
        host("factory-evolution", SubstratePrimitive::Activation),
        host("operations-service", SubstratePrimitive::BlobStore),
        host("packager-worker", SubstratePrimitive::BlobStore),
        component("packager-worker", "packaging-service", "packaging-service"),
        host("packaging-service", SubstratePrimitive::BlobStore),
        host("planner-worker", SubstratePrimitive::BlobStore),
        component("planner-worker", "build-service", "build-service"),
        component("planner-worker", "scheduling-service", "scheduling-service"),
        host("review-service", SubstratePrimitive::BlobStore),
        host("reviewer-worker", SubstratePrimitive::BlobStore),
        component("reviewer-worker", "review-service", "review-service"),
        host("scheduling-service", SubstratePrimitive::Clock),
        host("scheduling-service", SubstratePrimitive::TransactionStore),
        host("state-migration", SubstratePrimitive::BlobStore),
        host("validation-service", SubstratePrimitive::BlobStore),
        host("validator-worker", SubstratePrimitive::BlobStore),
        component(
            "validator-worker",
            "validation-service",
            "validation-service",
        ),
        host("worker-router", SubstratePrimitive::BlobStore),
        host("worker-router", SubstratePrimitive::ComponentRunner),
    ];
    let mut bindings = specs
        .into_iter()
        .map(|spec| ComponentImportBinding {
            consumer: spec.consumer.to_string(),
            import_name: spec.import.to_string(),
            provider: match spec.provider {
                ProviderSpec::Component { node, export } => ComponentBindingProvider::Component {
                    node: node.to_string(),
                    export: export.to_string(),
                },
                ProviderSpec::Host(capability) => ComponentBindingProvider::Host { capability },
            },
        })
        .collect::<Vec<_>>();
    bindings.sort();
    bindings
}

fn host(consumer: &'static str, capability: SubstratePrimitive) -> BindingSpec {
    BindingSpec {
        consumer,
        import: capability.interface_name(),
        provider: ProviderSpec::Host(capability),
    }
}

fn component(consumer: &'static str, import: &'static str, provider: &'static str) -> BindingSpec {
    BindingSpec {
        consumer,
        import: iface(import),
        provider: ProviderSpec::Component {
            node: provider,
            export: iface(import),
        },
    }
}

fn manifest_invocations() -> Vec<ComponentInvocationEdge> {
    let mut edges = [
        ("factory-evolution", "admitted-tool-probe"),
        ("worker-router", "builder-worker"),
        ("worker-router", "continuity-worker"),
        ("worker-router", "packager-worker"),
        ("worker-router", "planner-worker"),
        ("worker-router", "reviewer-worker"),
        ("worker-router", "validator-worker"),
    ]
    .into_iter()
    .map(|(consumer, target)| ComponentInvocationEdge {
        consumer: consumer.to_string(),
        target: target.to_string(),
        export: COMPONENT_TASK_EXPORT.to_string(),
    })
    .collect::<Vec<_>>();
    edges.sort();
    edges
}

fn bounded_r3_http_bindings(
    principals: &[GraphNodePrincipalV2],
) -> Result<Vec<HttpTransportBindingV1>> {
    let bindings = project_http_transport_bindings_v1(principals);
    if bindings.len() != 1 || bindings[0].consumer != "exchange-service" {
        return Err("R3 package must expose exactly the exchange-service HTTP import alias".into());
    }
    Ok(bindings)
}

fn manifest_nodes(
    built: &BTreeMap<String, BuiltNode>,
    bindings: &[ComponentImportBinding],
    constraints: &ContentDigest,
    http_transport_constraints: Option<&ContentDigest>,
) -> Result<Vec<FactoryComponentV1>> {
    let mut nodes = Vec::new();
    for (id, built_node) in built {
        let mut grants = bindings
            .iter()
            .filter(|binding| binding.consumer == *id)
            .filter_map(|binding| match binding.provider {
                ComponentBindingProvider::Host { capability } => Some(capability),
                ComponentBindingProvider::Component { .. } => None,
            })
            .map(|capability| ComponentCapabilityGrant {
                capability,
                scope: direct_capability_scope(id, capability).to_string(),
                constraints: if capability == SubstratePrimitive::HttpTransport {
                    http_transport_constraints.unwrap_or(constraints).clone()
                } else {
                    constraints.clone()
                },
            })
            .collect::<Vec<_>>();
        grants.sort();
        nodes.push(FactoryComponentV1 {
            id: id.clone(),
            kind: built_node.spec.kind,
            component_digest: built_node.digest.clone(),
            world: built_node.spec.world.to_string(),
            exports: built_node
                .spec
                .exports
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            grants,
            state_schema: built_node.spec.state_schema.map(str::to_string),
        });
    }
    nodes.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(nodes)
}

fn direct_capability_scope(id: &str, capability: SubstratePrimitive) -> &'static str {
    match (id, capability) {
        ("capability-router", SubstratePrimitive::TransactionStore) => "wasm-biotic.approvals.v1",
        ("exchange-service", SubstratePrimitive::TransactionStore) => "exchange-v1",
        ("factory-control", SubstratePrimitive::TransactionStore) => {
            "wasm-biotic.factory-control.v1"
        }
        ("scheduling-service", SubstratePrimitive::TransactionStore) => "wasm-biotic.schedule.v1",
        _ => capability.canonical_scope(),
    }
}

fn static_nodes(authority: &str, bindings: &[ComponentImportBinding]) -> BTreeSet<String> {
    let mut pending = vec![authority.to_string()];
    let mut reached = BTreeSet::new();
    while let Some(id) = pending.pop() {
        if !reached.insert(id.clone()) {
            continue;
        }
        for binding in bindings.iter().filter(|binding| binding.consumer == id) {
            if let ComponentBindingProvider::Component { node, .. } = &binding.provider {
                pending.push(node.clone());
            }
        }
    }
    reached
}

struct HostImportReencoder<'a> {
    aliases: &'a BTreeMap<String, String>,
    depth: usize,
    seen: BTreeSet<String>,
}

impl Reencode for HostImportReencoder<'_> {
    type Error = Infallible;
}

impl ReencodeComponent for HostImportReencoder<'_> {
    fn push_depth(&mut self) {
        self.depth += 1;
    }

    fn pop_depth(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn parse_component_import_section(
        &mut self,
        imports: &mut wasm_encoder::ComponentImportSection,
        section: wasmparser::ComponentImportSectionReader<'_>,
    ) -> std::result::Result<(), ReencodeError<Self::Error>> {
        for import in section {
            let import = import?;
            let source = import.name.0;
            let replacement = if self.depth == 0 {
                self.aliases.get(source).cloned()
            } else {
                None
            };
            if replacement.is_some() {
                self.seen.insert(source.to_string());
            }
            let ty = self.component_type_ref(import.ty)?;
            imports.import(replacement.as_deref().unwrap_or(source), ty);
        }
        Ok(())
    }
}

fn rewrite_host_imports(bytes: &[u8], aliases: &BTreeMap<String, String>) -> Result<Vec<u8>> {
    let mut output = wasm_encoder::Component::new();
    let mut reencoder = HostImportReencoder {
        aliases,
        depth: 0,
        seen: BTreeSet::new(),
    };
    reencoder
        .parse_component(&mut output, wasmparser::Parser::new(0), bytes)
        .map_err(|error| format!("cannot deterministically scope component imports: {error:?}"))?;
    let expected = aliases.keys().cloned().collect::<BTreeSet<_>>();
    if reencoder.depth != 0 || reencoder.seen != expected {
        return Err(format!(
            "component import scoping saw {:?}, expected {expected:?}",
            reencoder.seen
        )
        .into());
    }
    Ok(output.finish())
}

fn scope_nodes(
    built: &BTreeMap<String, BuiltNode>,
    nodes: &[FactoryComponentV1],
    bindings: &[ComponentImportBinding],
) -> Result<(BTreeMap<String, ScopedNode>, Vec<GraphNodePrincipalV2>)> {
    let mut scoped = BTreeMap::new();
    let mut principals = Vec::new();
    for node in nodes {
        let raw = built
            .get(&node.id)
            .ok_or_else(|| format!("missing raw bytes for {}", node.id))?;
        let mut aliases = BTreeMap::new();
        let mut host_imports = Vec::new();
        for binding in bindings
            .iter()
            .filter(|binding| binding.consumer == node.id)
        {
            let ComponentBindingProvider::Host { capability } = binding.provider else {
                continue;
            };
            let grant = node
                .grants
                .iter()
                .find(|grant| grant.capability == capability)
                .ok_or_else(|| {
                    format!(
                        "node {} has host binding {} without direct grant",
                        node.id, binding.import_name
                    )
                })?;
            let material = HostImportAliasMaterialV1::for_binding(node, capability);
            let alias = material.alias()?;
            if aliases
                .insert(binding.import_name.clone(), alias.clone())
                .is_some()
            {
                return Err(format!(
                    "node {} has duplicate host import {}",
                    node.id, binding.import_name
                )
                .into());
            }
            host_imports.push(PrincipalHostImportV2 {
                alias,
                source_import: binding.import_name.clone(),
                capability,
                scope: grant.scope.clone(),
                constraints: grant.constraints.clone(),
            });
        }
        host_imports.sort();
        let first = rewrite_host_imports(&raw.bytes, &aliases)?;
        let second = rewrite_host_imports(&raw.bytes, &aliases)?;
        if first != second {
            return Err(format!(
                "component import scoping for {} is not reproducible",
                node.id
            )
            .into());
        }
        let scoped_digest = ContentDigest::from_bytes(&first);
        let principal_seed = PrincipalSeedMaterialV1::for_node(node).principal_seed()?;
        principals.push(GraphNodePrincipalV2 {
            consumer: node.id.clone(),
            authority_component_digest: node.component_digest.clone(),
            principal_seed: principal_seed.clone(),
            scoped_component_digest: scoped_digest.clone(),
            host_imports,
        });
        scoped.insert(
            node.id.clone(),
            ScopedNode {
                bytes: first,
                digest: scoped_digest,
                principal_seed,
            },
        );
    }
    principals.sort_by(|left, right| left.consumer.cmp(&right.consumer));
    Ok((scoped, principals))
}

fn wit_artifacts(repo: &Path) -> Result<WitArtifacts> {
    let wit_dir = repo.join("wit/wasm-biotic");
    let mut paths = fs::read_dir(&wit_dir)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    paths.retain(|path| path.extension().is_some_and(|extension| extension == "wit"));
    paths.sort();

    let mut files = Vec::new();
    let mut merged = format!("package {FACTORY_WIT_PACKAGE_V1};\n").into_bytes();
    for path in paths {
        let content = fs::read_to_string(&path)?;
        let relative = path
            .strip_prefix(repo)?
            .to_string_lossy()
            .replace('\\', "/");
        let body = content
            .strip_prefix(&format!("package {FACTORY_WIT_PACKAGE_V1};"))
            .ok_or_else(|| format!("{} has a different WIT package", path.display()))?;
        merged.extend_from_slice(format!("\n// --- {relative} ---\n").as_bytes());
        merged.extend_from_slice(body.trim_start_matches(['\r', '\n']).as_bytes());
        if !merged.ends_with(b"\n") {
            merged.push(b'\n');
        }
        files.push(WitFileArtifact {
            content_digest: ContentDigest::from_bytes(content.as_bytes()),
            content,
            path: relative,
        });
    }
    let package_bytes = serde_json::to_vec(&WitPackageArtifact {
        files,
        package: FACTORY_WIT_PACKAGE_V1.to_string(),
        schema: WIT_PACKAGE_SCHEMA.to_string(),
    })?;
    let world_digest = ContentDigest::from_bytes(&merged);
    let worlds = node_specs()
        .into_iter()
        .map(|node| (node.world.to_string(), world_digest.clone()))
        .collect();
    Ok((package_bytes, merged, worlds))
}

struct CompositionGraph<'a> {
    nodes: &'a [FactoryComponentV1],
    bindings: &'a [ComponentImportBinding],
    invocations: &'a [ComponentInvocationEdge],
}

fn compose_authorities(
    staging: &Path,
    wasm_tools: &Path,
    built: &BTreeMap<String, BuiltNode>,
    scoped: &BTreeMap<String, ScopedNode>,
    principals: &[GraphNodePrincipalV2],
    graph: CompositionGraph<'_>,
) -> Result<CompositionArtifacts> {
    let CompositionGraph {
        nodes,
        bindings,
        invocations,
    } = graph;
    let mut authorities = invocations
        .iter()
        .map(|edge| edge.target.clone())
        .chain(std::iter::once("factory-control".to_string()))
        .collect::<Vec<_>>();
    authorities.sort();
    authorities.dedup();
    let mut descriptors = Vec::new();
    let mut derived = BTreeMap::new();
    let mut configurations = BTreeMap::new();
    let mut composed_root = None;

    for authority_id in authorities {
        let authority = nodes
            .iter()
            .find(|node| node.id == authority_id)
            .ok_or_else(|| format!("unknown executable authority {authority_id}"))?;
        let closure = static_nodes(&authority_id, bindings);
        let component_bindings = bindings
            .iter()
            .filter(|binding| closure.contains(&binding.consumer))
            .filter_map(|binding| match &binding.provider {
                ComponentBindingProvider::Component { node, .. } => {
                    Some((binding.import_name.clone(), node.clone()))
                }
                ComponentBindingProvider::Host { .. } => None,
            })
            .collect::<BTreeMap<_, _>>();

        let (configuration_bytes, executable_bytes) = if component_bindings.is_empty() {
            let config = format!(
                "{{\"authority\":\"{authority_id}\",\"mode\":\"identity\",\"schema\":\"{COMPOSE_CONFIG_SCHEMA}\"}}"
            )
            .into_bytes();
            (config, scoped[&authority_id].bytes.clone())
        } else {
            let compose_dir = staging.join("compose").join(&authority_id);
            fs::create_dir_all(&compose_dir)?;
            let mut config = String::from("dependencies:\n");
            for (import, provider) in component_bindings {
                config.push_str(&format!(
                    "  {}: {}\n",
                    serde_json::to_string(&import)?,
                    serde_json::to_string(&format!("../../scoped/{provider}.wasm"))?
                ));
            }
            let config_bytes = config.into_bytes();
            let config_path = compose_dir.join("compose.yaml");
            fs::write(&config_path, &config_bytes)?;
            let input = staging.join("scoped").join(format!("{authority_id}.wasm"));
            let first = compose_dir.join("first.wasm");
            let second = compose_dir.join("second.wasm");
            compose_once(wasm_tools, &config_path, &input, &first)?;
            compose_once(wasm_tools, &config_path, &input, &second)?;
            let first_bytes = fs::read(&first)?;
            let second_bytes = fs::read(&second)?;
            if first_bytes != second_bytes {
                return Err(format!(
                    "wasm-tools composition for {authority_id} is not byte reproducible"
                )
                .into());
            }
            (config_bytes, first_bytes)
        };

        let configuration_digest = ContentDigest::from_bytes(&configuration_bytes);
        let executable_digest = ContentDigest::from_bytes(&executable_bytes);
        configurations.insert(configuration_digest.clone(), configuration_bytes);
        derived.insert(executable_digest.clone(), executable_bytes.clone());
        if authority_id == "factory-control" {
            composed_root = Some(executable_bytes);
        }
        let mut source_digests = closure
            .iter()
            .map(|id| built[id].digest.clone())
            .collect::<Vec<_>>();
        source_digests.sort();
        source_digests.dedup();
        let mut scoped_source_digests = closure
            .iter()
            .map(|id| scoped[id].digest.clone())
            .collect::<Vec<_>>();
        scoped_source_digests.sort();
        scoped_source_digests.dedup();
        let mut principal_seeds = closure
            .iter()
            .map(|id| scoped[id].principal_seed.clone())
            .collect::<Vec<_>>();
        principal_seeds.sort();
        principal_seeds.dedup();
        for id in &closure {
            if !principals.iter().any(|principal| {
                principal.consumer == *id
                    && principal.principal_seed == scoped[id].principal_seed
                    && principal.scoped_component_digest == scoped[id].digest
            }) {
                return Err(format!("principal inventory does not bind scoped node {id}").into());
            }
        }
        descriptors.push(DerivedExecutableV2 {
            authority_node: authority_id,
            authority_digest: authority.component_digest.clone(),
            executable_digest,
            source_digests,
            scoped_source_digests,
            principal_seeds,
            world: authority.world.clone(),
            configuration_digest,
        });
    }
    descriptors.sort_by(|left, right| left.authority_node.cmp(&right.authority_node));
    Ok((
        descriptors,
        derived,
        configurations,
        composed_root.ok_or("composed root was not produced")?,
    ))
}

fn compose_once(wasm_tools: &Path, config: &Path, input: &Path, output: &Path) -> Result<()> {
    let mut command = Command::new(wasm_tools);
    command
        .arg("compose")
        .arg("--config")
        .arg(config)
        .arg(input)
        .arg("--output")
        .arg(output)
        .arg("--color")
        .arg("never");
    run_checked(&mut command, "compose component graph")
}

fn run_checked(command: &mut Command, label: &str) -> Result<()> {
    let status = command.status()?;
    if !status.success() {
        return Err(format!("{label} failed with {status}").into());
    }
    Ok(())
}

fn command_output(program: &Path, args: &[&str], directory: &Path) -> Result<String> {
    let output = Command::new(program)
        .current_dir(directory)
        .args(args)
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "{} {:?} failed: {}",
            program.display(),
            args,
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

fn principal_inventory_bytes(package: &impl LifecyclePackageView) -> Result<Vec<u8>> {
    canonical_json_bytes(&PrincipalInventoryEvidence {
        graph_manifest_digest: package.graph().manifest_digest.clone(),
        import_alias_scheme: package.profile().import_alias_scheme().to_string(),
        principal_id_scheme: package.profile().principal_id_scheme().to_string(),
        principals: package.profile().principals().to_vec(),
        schema: "wasm-biotic.principal-inventory-evidence.v1".to_string(),
    })
    .map_err(Into::into)
}

fn principal_enforcement_evidence(
    package: &ReleasePackage,
    scoped_surfaces: &BTreeMap<String, aiaf_v1::component_graph::ComponentSurfaceEvidenceV1>,
    derived_surfaces: &BTreeMap<String, aiaf_v1::component_graph::ComponentSurfaceEvidenceV1>,
) -> Result<PrincipalEnforcementEvidence> {
    let node_ids = package
        .graph
        .manifest
        .nodes
        .iter()
        .map(|node| node.id.as_str())
        .collect::<BTreeSet<_>>();
    let principal_ids = package
        .profile
        .principals()
        .iter()
        .map(|principal| principal.consumer.as_str())
        .collect::<BTreeSet<_>>();
    let all_manifest_nodes_covered = node_ids == principal_ids
        && package.profile.principals().len() == package.graph.manifest.nodes.len();

    let mut aliases = BTreeSet::new();
    let mut alias_count = 0usize;
    let mut all_direct_host_bindings_aliased = true;
    let mut grants_exact = true;
    for node in &package.graph.manifest.nodes {
        let principal = package
            .profile
            .principals()
            .iter()
            .find(|principal| principal.consumer == node.id);
        let mut expected_grants = Vec::new();
        let mut expected_host_imports = Vec::new();
        for binding in package
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
                grants_exact = false;
                all_direct_host_bindings_aliased = false;
                continue;
            };
            expected_grants.push(grant.clone());
            expected_host_imports.push(PrincipalHostImportV2 {
                alias: HostImportAliasMaterialV1::for_binding(node, capability).alias()?,
                source_import: binding.import_name.clone(),
                capability,
                scope: grant.scope.clone(),
                constraints: grant.constraints.clone(),
            });
        }
        expected_grants.sort();
        expected_host_imports.sort();
        let mut actual_grants = node.grants.clone();
        actual_grants.sort();
        grants_exact &= actual_grants == expected_grants;
        all_direct_host_bindings_aliased &=
            principal.is_some_and(|principal| principal.host_imports == expected_host_imports);
        if let Some(principal) = principal {
            for host_import in &principal.host_imports {
                alias_count += 1;
                aliases.insert(host_import.alias.as_str());
            }
        }
    }
    let aliases_unique = aliases.len() == alias_count;
    let canonical_host_imports = aiaf_v1::component_graph::REQUIRED_SUBSTRATE_PRIMITIVES
        .iter()
        .map(|primitive| primitive.interface_name())
        .collect::<BTreeSet<_>>();
    let no_unaliased_host_imports = scoped_surfaces
        .values()
        .chain(derived_surfaces.values())
        .all(|surface| {
            surface
                .imports
                .iter()
                .all(|import| !canonical_host_imports.contains(import.as_str()))
        });
    let graph_union_absent = matches!(
        package.profile.static_grant_model(),
        StaticGrantModelV2::PerConsumerImportAlias
    ) && grants_exact;
    let passed = graph_union_absent
        && all_manifest_nodes_covered
        && all_direct_host_bindings_aliased
        && no_unaliased_host_imports
        && aliases_unique
        && grants_exact;
    if !passed {
        return Err("derived R2 principal enforcement flags did not all pass".into());
    }
    Ok(PrincipalEnforcementEvidence {
        aliases_unique,
        all_direct_host_bindings_aliased,
        all_manifest_nodes_covered,
        grants_exact,
        graph_union_absent,
        no_unaliased_host_imports,
        result: "pass".to_string(),
    })
}

fn strict_validation_report(
    package: &ReleasePackage,
    certifier: &OfflineCertifier,
) -> Result<Vec<u8>> {
    // Re-run the strict validator immediately before evidence emission. Its
    // semantic conclusions remain offline report bytes; the kernel hashes but
    // never interprets them.
    aiaf_v1::component_graph::validate_component_graph(&package.graph, &package.artifacts)
        .map_err(|error| format!("release graph rejected: {:?}", error.violations))?;

    let raw_surfaces = package
        .graph
        .manifest
        .nodes
        .iter()
        .map(|node| {
            Ok((
                node.id.clone(),
                aiaf_v1::component_graph::inspect_component_surface(&package.raw[&node.id])?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let scoped_surfaces = package
        .profile
        .principals()
        .iter()
        .map(|principal| {
            Ok((
                principal.consumer.clone(),
                aiaf_v1::component_graph::inspect_component_surface(
                    &package.scoped[&principal.consumer],
                )?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let derived_surfaces = package
        .descriptor
        .executables
        .iter()
        .map(|executable| {
            let bytes = package
                .artifacts
                .derived_component_bytes
                .get(&executable.executable_digest)
                .ok_or_else(|| {
                    format!("missing derived bytes for {}", executable.authority_node)
                })?;
            Ok((
                executable.authority_node.clone(),
                aiaf_v1::component_graph::inspect_component_surface(bytes)?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;

    let mut required_semantic_owners = BTreeMap::new();
    for kind in aiaf_v1::component_graph::REQUIRED_FACTORY_COMPONENT_KINDS {
        let owners = package
            .graph
            .manifest
            .nodes
            .iter()
            .filter(|node| node.kind == kind)
            .map(|node| node.id.clone())
            .collect::<Vec<_>>();
        if owners.len() != 1 {
            return Err(format!("required semantic {kind:?} has owners {owners:?}").into());
        }
        let name = serde_json::to_value(kind)?
            .as_str()
            .ok_or("component kind did not serialize as a string")?
            .to_string();
        required_semantic_owners.insert(name, owners[0].clone());
    }

    let mut activated_service_nodes = BTreeMap::new();
    for node in &package.graph.manifest.nodes {
        let family = match node.kind {
            FactoryComponentKind::BuildService => Some("build"),
            FactoryComponentKind::PackagingService => Some("packaging"),
            FactoryComponentKind::ValidationService => Some("validation"),
            FactoryComponentKind::ReviewService => Some("review"),
            FactoryComponentKind::ContinuityService => Some("continuity"),
            FactoryComponentKind::SchedulingService => Some("scheduling"),
            FactoryComponentKind::OperationsService => Some("operations"),
            _ => None,
        };
        if let Some(family) = family
            && activated_service_nodes
                .insert(family.to_string(), node.id.clone())
                .is_some()
        {
            return Err(format!("service family {family} has multiple owners").into());
        }
    }
    if activated_service_nodes.len() != 7 {
        return Err("release graph does not activate exactly seven service families".into());
    }

    let operation_owners = Operation::ALL
        .into_iter()
        .map(|operation| {
            (
                operation.as_str().to_string(),
                operation_policy(operation).family.as_str().to_string(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    if operation_owners.len() != 27
        || operation_owners
            .values()
            .any(|family| !activated_service_nodes.contains_key(family))
    {
        return Err("27-operation ownership is not exactly covered by activated services".into());
    }

    let native_boundary = aiaf_v1::component_graph::REQUIRED_SUBSTRATE_PRIMITIVES
        .iter()
        .map(|primitive| primitive.interface_name().to_string())
        .collect::<Vec<_>>();
    let principal_inventory_digest =
        ContentDigest::from_bytes(&principal_inventory_bytes(package)?);
    let principal_enforcement =
        principal_enforcement_evidence(package, &scoped_surfaces, &derived_surfaces)?;
    canonical_json_bytes(&ValidationEvidence {
        activated_service_nodes,
        bindings: package.graph.manifest.bindings.clone(),
        component_count: package.graph.manifest.nodes.len(),
        derived_surfaces,
        graph_manifest_digest: package.graph.manifest_digest.clone(),
        invocation_enforcement: "per-consumer immutable Component Model import aliases: every host link is bound to one graph-node principal and its direct grant; canonical substrate imports are rejected"
            .to_string(),
        native_boundary,
        operation_owners,
        outcome: "pass".to_string(),
        principal_enforcement,
        principal_inventory_digest,
        raw_surfaces,
        scoped_surfaces,
        principals: package.profile.principals().to_vec(),
        required_semantic_owners,
        schema: "wasm-biotic.component-strict-validation-report.v2".to_string(),
        strict_validator: "aiaf_v1::component_graph::validate_component_graph".to_string(),
        validator_identity: certifier.identity.clone(),
        validator_version: certifier.version.clone(),
    })
    .map_err(Into::into)
}

fn certify_release(
    package: &ReleasePackage,
    validation_report: &[u8],
    certifier: &OfflineCertifier,
) -> Result<Vec<u8>> {
    let raw_artifacts = package
        .graph
        .manifest
        .nodes
        .iter()
        .map(|node| Ok((node.id.clone(), kernel_digest(&node.component_digest)?)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let mut derived_artifacts = package
        .descriptor
        .executables
        .iter()
        .map(|item| {
            Ok((
                item.authority_node.clone(),
                kernel_digest(&item.executable_digest)?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    for principal in package.profile.principals() {
        let previous = derived_artifacts.insert(
            format!("scoped:{}", principal.consumer),
            kernel_digest(&principal.scoped_component_digest)?,
        );
        if previous.is_some() {
            return Err(format!(
                "scoped artifact certification key collided for {}",
                principal.consumer
            )
            .into());
        }
    }
    let wit_world_digests = package
        .metadata
        .wit_world_digests
        .iter()
        .map(|(world, digest)| Ok((world.clone(), kernel_digest(digest)?)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let mut composition_configuration_digests = package
        .descriptor
        .executables
        .iter()
        .map(|item| kernel_digest(&item.configuration_digest))
        .collect::<Result<Vec<_>>>()?;
    composition_configuration_digests.sort_unstable();
    composition_configuration_digests.dedup();
    let mut constraint_digests = package
        .graph
        .manifest
        .nodes
        .iter()
        .flat_map(|node| node.grants.iter())
        .map(|grant| kernel_digest(&grant.constraints))
        .collect::<Result<Vec<_>>>()?;
    constraint_digests.sort_unstable();
    constraint_digests.dedup();
    let statement = ReleaseCertificationStatement {
        schema: RELEASE_CERTIFICATION_STATEMENT_SCHEMA.to_string(),
        graph_manifest_digest: kernel_digest(&package.graph.manifest_digest)?,
        native_tcb_inventory_digest: kernel_digest(&package.native_tcb_inventory_digest)?,
        wit_package_digest: kernel_digest(&package.metadata.wit_package_digest)?,
        metadata_digest: kernel_digest(
            package
                .graph
                .manifest
                .metadata
                .as_ref()
                .ok_or("release manifest has no metadata digest")?,
        )?,
        raw_artifacts,
        derived_artifacts,
        derivation_descriptor_digest: kernel_digest(
            &package.metadata.derivation_descriptor_digest,
        )?,
        substrate_profile_digest: kernel_digest(&package.metadata.substrate_profile_digest)?,
        wit_world_digests,
        composition_configuration_digests,
        constraint_digests,
        validation_report_digest: Sha256Digest::from_bytes(validation_report),
        validator_identity: certifier.identity.clone(),
        validator_version: certifier.version.clone(),
    };
    let public_key = certifier.key_pair.public_key().as_ref();
    let key_id = Sha256Digest::from_bytes(public_key);
    let payload = SignedReleaseCertification::signing_payload_bytes(&statement, key_id)?;
    let signature = certifier.key_pair.sign(&payload);
    let certificate =
        SignedReleaseCertification::assemble(key_id, statement, encode_hex(signature.as_ref()))?;
    certificate.canonical_bytes().map_err(Into::into)
}

fn write_package(
    directory: &Path,
    package: &ReleasePackage,
    validation_report: &[u8],
    certification: &[u8],
) -> Result<()> {
    if directory.exists() {
        fs::remove_dir_all(directory)?;
    }
    fs::create_dir_all(directory)?;
    write_bytes(
        &directory.join("manifest.json"),
        &package.graph.manifest.canonical_bytes()?,
    )?;
    write_bytes(
        &directory.join("metadata.json"),
        &package.metadata.canonical_bytes()?,
    )?;
    write_bytes(
        &directory.join("derivation-descriptor.json"),
        &package.descriptor.canonical_bytes()?,
    )?;
    write_bytes(
        &directory.join("substrate-profile.json"),
        &package.profile.canonical_bytes()?,
    )?;
    write_bytes(
        &directory.join("certified-kernel-tcb").join(format!(
            "{}.json",
            package.native_tcb_inventory_digest.file_stem()
        )),
        &package.native_tcb_inventory,
    )?;
    write_bytes(&directory.join("factory-root.wasm"), &package.composed_root)?;

    for node in &package.graph.manifest.nodes {
        write_bytes(
            &directory
                .join("components")
                .join(format!("{}.wasm", node.component_digest.file_stem())),
            &package.raw[&node.id],
        )?;
    }
    for principal in package.profile.principals() {
        write_bytes(
            &directory.join("scoped-components").join(format!(
                "{}.wasm",
                principal.scoped_component_digest.file_stem()
            )),
            &package.scoped[&principal.consumer],
        )?;
    }
    for (digest, bytes) in &package.artifacts.derived_component_bytes {
        write_bytes(
            &directory
                .join("derived")
                .join(format!("{}.wasm", digest.file_stem())),
            bytes,
        )?;
    }
    for (digest, bytes) in &package.artifacts.composition_config_bytes {
        write_bytes(
            &directory
                .join("composition-configs")
                .join(format!("{}.config", digest.file_stem())),
            bytes,
        )?;
    }
    for (digest, bytes) in &package.artifacts.wit_package_bytes {
        write_bytes(
            &directory
                .join("wit")
                .join(format!("{}-package.json", digest.file_stem())),
            bytes,
        )?;
    }
    for (digest, bytes) in &package.artifacts.wit_world_bytes {
        write_bytes(
            &directory
                .join("wit")
                .join(format!("{}-worlds.wit", digest.file_stem())),
            bytes,
        )?;
    }
    for (digest, bytes) in &package.artifacts.constraint_bytes {
        write_bytes(
            &directory
                .join("constraints")
                .join(format!("{}.json", digest.file_stem())),
            bytes,
        )?;
    }

    let root = package
        .graph
        .manifest
        .nodes
        .iter()
        .find(|node| node.id == package.graph.manifest.root_node)
        .ok_or("root node missing during package write")?;
    let root_executable = package
        .descriptor
        .executables
        .iter()
        .find(|item| item.authority_node == root.id)
        .ok_or("root executable missing during package write")?;
    write_bytes(
        &directory.join("package.json"),
        &serde_json::to_vec(&PackageIndex {
            certification_digest: ContentDigest::from_bytes(certification),
            certified_kernel_tcb_inventory_digest: package.native_tcb_inventory_digest.clone(),
            graph_manifest_digest: package.graph.manifest_digest.clone(),
            package_schema: PACKAGE_SCHEMA.to_string(),
            root_authority_digest: root.component_digest.clone(),
            root_executable_digest: root_executable.executable_digest.clone(),
            validation_report_digest: ContentDigest::from_bytes(validation_report),
        })?,
    )?;

    let raw_nodes = package
        .graph
        .manifest
        .nodes
        .iter()
        .map(|node| (node.id.clone(), node.component_digest.clone()))
        .collect::<BTreeMap<_, _>>();
    let scoped_nodes = package
        .profile
        .principals()
        .iter()
        .map(|principal| {
            (
                principal.consumer.clone(),
                principal.scoped_component_digest.clone(),
            )
        })
        .collect();
    let principal_seeds = package
        .profile
        .principals()
        .iter()
        .map(|principal| (principal.consumer.clone(), principal.principal_seed.clone()))
        .collect();
    write_bytes(
        &directory.join("evidence/composition.json"),
        &serde_json::to_vec(&CompositionEvidence {
            descriptor_digest: package.metadata.derivation_descriptor_digest.clone(),
            graph_manifest_digest: package.graph.manifest_digest.clone(),
            package_schema: PACKAGE_SCHEMA.to_string(),
            raw_nodes,
            scoped_nodes,
            principal_seeds,
            reproducible_composition: true,
            tool: package.wasm_tools_version.clone(),
            validated: true,
        })?,
    )?;

    write_bytes(
        &directory.join("evidence/import-resolution.json"),
        validation_report,
    )?;
    write_bytes(
        &directory.join("evidence/principal-inventory.json"),
        &principal_inventory_bytes(package)?,
    )?;
    write_bytes(
        &directory.join("evidence/strict-validation.json"),
        validation_report,
    )?;
    write_bytes(
        &directory.join("certification/release-certification.json"),
        certification,
    )?;
    Ok(())
}

fn write_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, bytes)?;
    Ok(())
}

fn execute_kernel_probe(
    directory: &Path,
    package: &ReleasePackage,
    certifier_public_key_hex: &str,
) -> Result<()> {
    // Persistent mechanism state can contain non-exportable private key bytes.
    // Keep it outside the release and destroy it after emitting redacted proof.
    let ephemeral_state = EphemeralKernelState::create()?;
    let state_dir = &ephemeral_state.0;
    // Exercise the same production package loader and exact artifact filtering
    // used by the standalone kernel CLI. The manifest-bound substrate profile,
    // not this packaging tool, defines the local mechanism ceiling.
    let admission = RootAdmission::from_package_directory(directory)?;
    let local_config = admission.local_config_ceiling()?;
    let trusted_bootstrap_manifest = kernel_digest(&package.graph.manifest_digest)?;
    let trusted_certifier = TrustedCertifier::from_public_key_hex(certifier_public_key_hex)?;
    let mechanisms = LocalMechanisms::initialize(
        state_dir,
        local_config,
        trusted_bootstrap_manifest,
        trusted_certifier,
    )?;
    let mut manager = OpaqueRootManager::bootstrap(admission, mechanisms.clone(), root_limits())?;

    let probe = manager
        .root()
        .handle(&IngressRequest {
            request_id: "component-boundary-probe".to_string(),
            method: "GET".to_string(),
            path: "/__wasm-biotic/component-boundary-probe".to_string(),
            headers: Vec::new(),
            body: None,
        })?
        .map_err(failure_message)?;
    if probe.status != 200
        || !probe
            .headers
            .iter()
            .any(|(name, value)| name == "x-wasm-biotic-component-root" && value == b"ok")
    {
        return Err("composed component-root boundary probe failed".into());
    }

    let graph_hex = hex(package.graph.manifest_digest.as_str()).to_string();
    let initial_state_bytes = initial_supervisor_state(package, &graph_hex)?;
    let initial_state = mechanisms
        .put_blob("application/json".to_string(), initial_state_bytes)
        .map_err(failure_message)?;
    let fixture_label = "kernel-probe";
    let source_bytes =
        wasm_biotic_service_policy_core::r1::canonical_positive_fixture_bytes(fixture_label);
    let source = mechanisms
        .put_blob(
            wasm_biotic_service_policy_core::r1::CHANGE_REQUEST_MEDIA_TYPE.to_string(),
            source_bytes.clone(),
        )
        .map_err(failure_message)?;
    let submit_bytes = serde_json::to_vec(&serde_json::json!({
        "schema": "wasm-biotic.factory-submit.v1",
        "graph_digest": {"algorithm": "sha256", "hex": graph_hex},
        "initial_state": {
            "schema": "wasm-biotic.supervisor-state.v1",
            "blob": blob_json(&initial_state),
        },
        "source": blob_json(&source),
    }))?;
    let submit = mechanisms
        .put_blob("application/json".to_string(), submit_bytes)
        .map_err(failure_message)?;
    let job_id = manager.root().submit(&submit)?.map_err(failure_message)?;
    let result_ref = manager.root().inspect(&job_id)?.map_err(failure_message)?;
    let completed = completed_job(&mechanisms, result_ref)?;
    let terminal_result_digest = ContentDigest::from_bytes(&completed.inspect_bytes);
    let final_output_digest = ContentDigest::from_bytes(&completed.final_output_bytes);
    let r1_semantics = verify_r1_semantics(fixture_label, &source_bytes, &completed)?;
    let exact_replay = verify_exact_submit_replay(
        &mut manager,
        &mechanisms,
        state_dir,
        &submit,
        &job_id,
        &completed,
    )?;

    let mut provenance = BTreeMap::new();
    let worker_router_principal = package_principal_seed(package, "worker-router")?;
    for (stage, node_id) in [
        ("planner", "planner-worker"),
        ("builder", "builder-worker"),
        ("validator", "validator-worker"),
        ("reviewer", "reviewer-worker"),
        ("packager", "packager-worker"),
        ("continuity-worker", "continuity-worker"),
    ] {
        let lease = ContentDigest::from_bytes(
            format!("lease-v1|{graph_hex}|{job_id}|{stage}|1").as_bytes(),
        );
        let operation = component_operation_id(package, "worker-router", &lease)?;
        let item = mechanisms
            .execution_provenance(&operation)?
            .ok_or_else(|| format!("missing execution provenance for {stage}"))?;
        let expected = package
            .graph
            .manifest
            .nodes
            .iter()
            .find(|node| node.id == node_id)
            .ok_or_else(|| format!("missing worker node {node_id}"))?;
        if item.authority_component_digest != kernel_digest(&expected.component_digest)?
            || item.caller_principal_seed != Some(worker_router_principal)
        {
            return Err(format!("{stage} provenance has the wrong raw or caller authority").into());
        }
        provenance.insert(stage.to_string(), item);
    }

    let tool_input_bytes = b"admitted tool shadow input".to_vec();
    let tool_input = mechanisms
        .put_blob(
            "application/octet-stream".to_string(),
            tool_input_bytes.clone(),
        )
        .map_err(failure_message)?;
    let probe_payload = format!(
        "{{\"ok\":true,\"schema\":\"wasm-biotic.admitted-tool-probe.v1\",\"source_digest\":\"{}\",\"source_size_bytes\":{}}}",
        tool_input.content_digest.hex,
        tool_input_bytes.len()
    )
    .into_bytes();
    let expected_tool_output = ContentDigest::from_bytes(&probe_payload);
    let tool = package
        .graph
        .manifest
        .nodes
        .iter()
        .find(|node| node.id == "admitted-tool-probe")
        .ok_or("admitted tool node missing")?;
    let shadow_idempotency = ContentDigest::from_bytes(b"component-graph-shadow-v1");
    let shadow_bytes = serde_json::to_vec(&serde_json::json!({
        "schema": "wasm-biotic.shadow-request.v1",
        "run_id": "component-graph-shadow-v1",
        "candidate_component_digest": hex(tool.component_digest.as_str()),
        "input": {
            "digest": tool_input.content_digest.hex,
            "size_bytes": tool_input.size_bytes,
            "media_type": tool_input.media_type,
        },
        "expected_output_digest": hex(expected_tool_output.as_str()),
        "idempotency_key": hex(shadow_idempotency.as_str()),
        "fuel": 1_000_000_u64,
        "memory_bytes": 8 * 1024 * 1024_u64,
        "output_bytes": 1024 * 1024_u64,
        "wall_time_ms": 5_000_u64,
    }))?;
    let shadow_body = mechanisms
        .put_blob("application/json".to_string(), shadow_bytes)
        .map_err(failure_message)?;
    let shadow_response = manager
        .root()
        .handle(&IngressRequest {
            request_id: "evolution-shadow".to_string(),
            method: "POST".to_string(),
            path: "/v1/evolution/shadow".to_string(),
            headers: Vec::new(),
            body: Some(shadow_body),
        })?
        .map_err(failure_message)?;
    if shadow_response.status != 200 {
        return Err(format!("evolution shadow returned {}", shadow_response.status).into());
    }
    let shadow_ref = shadow_response
        .body
        .ok_or("evolution shadow returned no body")?;
    let shadow_evidence: serde_json::Value =
        serde_json::from_slice(&mechanisms.get_blob(shadow_ref).map_err(failure_message)?)?;
    let evolution_shadow_matched = shadow_evidence
        .get("matched")
        .and_then(serde_json::Value::as_bool)
        == Some(true);
    if !evolution_shadow_matched {
        return Err(format!("admitted tool shadow did not match: {shadow_evidence}").into());
    }
    let tool_operation = component_operation_id(package, "factory-evolution", &shadow_idempotency)?;
    let tool_provenance = mechanisms
        .execution_provenance(&tool_operation)?
        .ok_or("missing admitted-tool execution provenance")?;
    if tool_provenance.authority_component_digest != kernel_digest(&tool.component_digest)?
        || tool_provenance.caller_principal_seed
            != Some(package_principal_seed(package, "factory-evolution")?)
    {
        return Err("admitted tool provenance has the wrong raw or caller authority".into());
    }
    provenance.insert("admitted-tool-probe".to_string(), tool_provenance);

    drop(manager);
    drop(mechanisms);
    let reopened = LocalMechanisms::open_existing(state_dir)?;
    let mut recovered_manager = OpaqueRootManager::boot(reopened.clone(), root_limits())?;
    let recovery_bytes = serde_json::to_vec(&serde_json::json!({
        "schema": "wasm-biotic.factory-recovery.v1",
        "job_id": job_id,
    }))?;
    let recovery = reopened
        .put_blob("application/json".to_string(), recovery_bytes)
        .map_err(failure_message)?;
    recovered_manager
        .root()
        .recover(&recovery)?
        .map_err(failure_message)?;
    let recovered_result = recovered_manager
        .root()
        .inspect(&job_id)?
        .map_err(failure_message)?;
    let recovered_bytes = reopened
        .get_blob(recovered_result)
        .map_err(failure_message)?;
    let restart_recovery_inspect_equal = recovered_bytes == completed.inspect_bytes;
    if !restart_recovery_inspect_equal {
        return Err("restart/recovery changed the terminal inspect result".into());
    }

    write_bytes(
        &directory.join("evidence/kernel-execution.json"),
        &serde_json::to_vec(&ExecutionEvidence {
            exact_replay,
            evolution_shadow_matched,
            final_output_digest,
            graph_manifest_digest: package.graph.manifest_digest.clone(),
            job_id,
            probe_status: probe.status,
            provenance,
            restart_recovery_inspect_equal,
            r1_semantics,
            schema: "wasm-biotic.component-kernel-execution.v1".to_string(),
            terminal_result_digest,
        })?,
    )?;
    Ok(())
}

fn authority_trace_summary<P: LifecyclePackageView>(
    phase: &str,
    trace: &[AuthorityTrace],
    initial: &P,
    successor: &P,
) -> Result<AuthorityTraceSummary> {
    if trace.is_empty() {
        return Err(format!("R2 authority trace phase {phase} is empty").into());
    }
    for entry in trace {
        validate_authority_trace_entry(entry, initial, successor)?;
    }
    let mut aliases = trace
        .iter()
        .map(|entry| entry.alias.clone())
        .collect::<Vec<_>>();
    aliases.sort();
    aliases.dedup();
    let mut consumers = trace
        .iter()
        .map(|entry| entry.consumer.clone())
        .collect::<Vec<_>>();
    consumers.sort();
    consumers.dedup();
    let mut graph_manifest_digests = trace
        .iter()
        .map(|entry| entry.graph_manifest_digest)
        .collect::<Vec<_>>();
    graph_manifest_digests.sort_unstable();
    graph_manifest_digests.dedup();
    let trace_bytes = canonical_json_bytes(&trace)?;
    Ok(AuthorityTraceSummary {
        aliases,
        call_count: trace.len(),
        consumers,
        graph_manifest_digests,
        phase: phase.to_string(),
        profile_mapping_verified: true,
        trace_digest: ContentDigest::from_bytes(&trace_bytes),
    })
}

fn validate_authority_trace_entry<P: LifecyclePackageView>(
    entry: &AuthorityTrace,
    initial: &P,
    successor: &P,
) -> Result<()> {
    let package = if entry.graph_manifest_digest == kernel_digest(&initial.graph().manifest_digest)?
    {
        initial
    } else if entry.graph_manifest_digest == kernel_digest(&successor.graph().manifest_digest)? {
        successor
    } else {
        return Err(format!(
            "authority trace names unknown graph {}",
            entry.graph_manifest_digest
        )
        .into());
    };
    let principal = package
        .profile()
        .principals()
        .iter()
        .find(|principal| principal.consumer == entry.consumer)
        .ok_or_else(|| format!("authority trace names unknown consumer {}", entry.consumer))?;
    let host_import = principal
        .host_imports
        .iter()
        .find(|host_import| host_import.alias == entry.alias)
        .ok_or_else(|| {
            format!(
                "authority trace alias {} is not owned by {}",
                entry.alias, entry.consumer
            )
        })?;
    let capability = serde_json::to_value(host_import.capability)?
        .as_str()
        .ok_or("substrate capability did not serialize as a string")?
        .to_string();
    let expected_runtime_principal =
        Sha256Digest::from_bytes(&canonical_json_bytes(&serde_json::json!({
            "graph_manifest_digest": entry.graph_manifest_digest,
            "principal_seed": entry.principal_seed,
            "schema": "wasm-biotic.runtime-principal.v1",
        }))?);
    let executable_matches = package.descriptor().executables.iter().any(|executable| {
        kernel_digest(&executable.executable_digest).is_ok_and(|digest| {
            digest == entry.executable_component_digest
                && executable.principal_seeds.iter().any(|seed| {
                    kernel_digest(seed).is_ok_and(|digest| digest == entry.principal_seed)
                })
        })
    });
    if entry.authority_component_digest != kernel_digest(&principal.authority_component_digest)?
        || entry.principal_seed != kernel_digest(&principal.principal_seed)?
        || entry.runtime_principal_digest != expected_runtime_principal
        || entry.scoped_component_digest != kernel_digest(&principal.scoped_component_digest)?
        || entry.capability != capability
        || entry.scope != host_import.scope
        || entry.constraint_digest != kernel_digest(&host_import.constraints)?
        || !executable_matches
        || entry.method.trim().is_empty()
        || entry.outcome.trim().is_empty()
    {
        return Err(format!(
            "authority trace entry for {} alias {} does not match the signed R2 mapping",
            entry.consumer, entry.alias
        )
        .into());
    }
    Ok(())
}

fn graph_qualified_activation_handoff_verified<P: LifecyclePackageView>(
    trace: &[AuthorityTrace],
    initial: &P,
    successor: &P,
) -> Result<bool> {
    let initial_graph = kernel_digest(&initial.graph().manifest_digest)?;
    let successor_graph = kernel_digest(&successor.graph().manifest_digest)?;
    let initial_seed = package_principal_seed(initial, "factory-control")?;
    let successor_seed = package_principal_seed(successor, "factory-control")?;
    if initial_seed != successor_seed {
        return Err("factory-control principal changed across the activation handoff".into());
    }
    let initial_alias = package_activation_alias(initial)?;
    let successor_alias = package_activation_alias(successor)?;
    if initial_alias != successor_alias {
        return Err("factory-control activation alias changed across the handoff".into());
    }
    if !trace_proves_graph_qualified_activation_handoff(
        trace,
        initial_graph,
        successor_graph,
        initial_seed,
        initial_alias,
    ) {
        return Err(
            "authority trace omitted an exact graph-qualified activation-owner handoff".into(),
        );
    }
    Ok(true)
}

fn package_activation_alias(package: &impl LifecyclePackageView) -> Result<&str> {
    let principal = package
        .profile()
        .principals()
        .iter()
        .find(|principal| principal.consumer == "factory-control")
        .ok_or("package has no factory-control principal")?;
    let mut imports = principal.host_imports.iter().filter(|import| {
        import.capability == SubstratePrimitive::Activation
            && import.scope == "switch"
            && import.source_import == "wasm-biotic:factory/activation@0.1.0"
    });
    let activation = imports
        .next()
        .ok_or("factory-control principal has no activation switch import")?;
    if imports.next().is_some() {
        return Err("factory-control principal has duplicate activation switch imports".into());
    }
    Ok(activation.alias.as_str())
}

fn trace_proves_graph_qualified_activation_handoff(
    trace: &[AuthorityTrace],
    initial_graph: Sha256Digest,
    successor_graph: Sha256Digest,
    principal_seed: Sha256Digest,
    activation_alias: &str,
) -> bool {
    let committed = trace.iter().enumerate().find(|(_, entry)| {
        entry.graph_manifest_digest == initial_graph
            && entry.consumer == "factory-control"
            && entry.alias == activation_alias
            && entry.capability == "activation"
            && entry.method == "commit"
            && entry.outcome == "success"
            && entry.principal_seed == principal_seed
    });
    let rolled_back = trace.iter().enumerate().find(|(_, entry)| {
        entry.graph_manifest_digest == successor_graph
            && entry.consumer == "factory-control"
            && entry.alias == activation_alias
            && entry.capability == "activation"
            && entry.method == "rollback"
            && entry.outcome == "success"
            && entry.principal_seed == principal_seed
    });
    committed
        .zip(rolled_back)
        .is_some_and(|((commit_index, source), (rollback_index, target))| {
            commit_index < rollback_index
                && source.runtime_principal_digest != target.runtime_principal_digest
        })
}

fn execute_component_lifecycle(
    initial_directory: &Path,
    successor_directory: &Path,
    initial: &ReleasePackage,
    successor: &ReleasePackage,
    certifier_public_key_hex: &str,
) -> Result<ContentDigest> {
    let ephemeral_state = EphemeralKernelState::create()?;
    let run = execute_component_lifecycle_at(
        &ephemeral_state.0,
        initial_directory,
        successor_directory,
        initial,
        successor,
        certifier_public_key_hex,
        None,
    )?;
    let evidence_bytes = canonical_json_bytes(&run.evidence)?;
    let evidence_digest = ContentDigest::from_bytes(&evidence_bytes);
    write_bytes(
        &initial_directory.join("evidence/component-lifecycle.json"),
        &evidence_bytes,
    )?;
    write_bytes(
        &successor_directory.join("evidence/component-lifecycle.json"),
        &evidence_bytes,
    )?;
    Ok(evidence_digest)
}

fn execute_component_lifecycle_at<P: LifecyclePackageView>(
    state_dir: &Path,
    initial_directory: &Path,
    successor_directory: &Path,
    initial: &P,
    successor: &P,
    certifier_public_key_hex: &str,
    operator_capacity: Option<&Path>,
) -> Result<ComponentLifecycleRun> {
    if successor.graph().manifest.previous_graph.as_ref() != Some(&initial.graph().manifest_digest)
    {
        return Err("successor package is not linked to the exact incumbent graph".into());
    }

    let initial_admission = RootAdmission::from_package_directory(initial_directory)?;
    let local_config = match operator_capacity {
        Some(path) => LocalConfig::from_canonical_json_file(path)?,
        None => initial_admission.local_config_ceiling()?,
    };
    let trusted_certifier = TrustedCertifier::from_public_key_hex(certifier_public_key_hex)?;
    let mechanisms = LocalMechanisms::initialize(
        state_dir,
        local_config,
        kernel_digest(&initial.graph().manifest_digest)?,
        trusted_certifier,
    )?;
    let mut manager =
        OpaqueRootManager::bootstrap(initial_admission, mechanisms.clone(), root_limits())?;

    let incumbent_bootstrap_manifest_digest = active_manifest_content_digest(&mechanisms)?;
    if incumbent_bootstrap_manifest_digest != initial.graph().manifest_digest {
        return Err("bootstrap selected a graph other than the exact incumbent".into());
    }

    let initial_graph = policy_digest(&initial.graph().manifest_digest);
    let successor_graph = policy_digest(&successor.graph().manifest_digest);
    let initial_graph_hex = initial_graph.hex.clone();
    let initial_state_bytes = initial_supervisor_state(initial, &initial_graph_hex)?;
    let initial_state = mechanisms
        .put_blob(JSON_MEDIA_TYPE.to_string(), initial_state_bytes)
        .map_err(failure_message)?;
    let incumbent_cycle = execute_factory_cycle(
        &mut manager,
        &mechanisms,
        state_dir,
        initial,
        &initial_state,
        "lifecycle-incumbent",
    )?;
    let incumbent_trace_end = mechanisms.authority_trace()?.len();

    // The first component-owned transition binds an opaque state pointer to
    // the already-active graph. The substrate sees only digest-addressed bytes.
    let active_manifest = mechanisms
        .active_manifest_reference()
        .map_err(failure_message)?
        .ok_or("bootstrap did not select an active manifest")?;
    let initial_migration = migration_component(initial)?;
    let initialization = upgrade_envelope(
        "component-state-initialization-v1",
        blob_value(&active_manifest),
        initial_graph.clone(),
        None,
        &initial_state,
        initial_migration.clone(),
    )?;
    let initialization_bytes = call_root_api(
        &mut manager,
        &mechanisms,
        "component-state-initialization-v1",
        "/v1/evolution/apply",
        &serde_json::to_vec(&initialization)?,
    )?;
    let initialization_result: FactoryUpgradeResultV1 =
        serde_json::from_slice(&initialization_bytes)?;
    let initialized_state = mechanisms
        .active_state_reference()
        .map_err(failure_message)?
        .ok_or("component state initialization did not select a state")?;
    let initialized_state_value = blob_value(&initialized_state);
    if initialization_result.schema != FACTORY_UPGRADE_RESULT_SCHEMA
        || initialization_result.previous_graph != initial_graph
        || initialization_result.target_graph != initial_graph
        || initialization_result.previous_state.is_some()
        || initialization_result.migrated_state != initialized_state_value
        || initialization_result.committed.state != ActivationStateValue::Active
        || initialization_result.committed.active_graph != Some(initial_graph.clone())
        || initialization_result.committed.active_state != Some(initialized_state_value.clone())
        || initialization_result.committed.receipt.is_none()
    {
        return Err("component state-initialization receipt was not exact and truthful".into());
    }

    // Verify and instantiate the signed successor without selecting it. This
    // is generic admission only; the incumbent component owns the decision to
    // migrate and commit the successor graph/state pair.
    let inactive_active_manifest_before = active_manifest_content_digest(&mechanisms)?;
    let successor_admission = RootAdmission::from_package_directory(successor_directory)?;
    let successor_limits = successor_admission.bounded_root_limits(&root_limits())?;
    let admitted_successor =
        OpaqueRootEngine::load(successor_admission, mechanisms.clone(), successor_limits)?;
    if admitted_successor.binding().manifest_digest
        != kernel_digest(&successor.graph().manifest_digest)?
    {
        return Err("admitted successor root has the wrong graph binding".into());
    }
    drop(admitted_successor);
    let inactive_active_manifest_after = active_manifest_content_digest(&mechanisms)?;
    if inactive_active_manifest_before != initial.graph().manifest_digest
        || inactive_active_manifest_after != inactive_active_manifest_before
    {
        return Err("inactive successor admission changed the active graph".into());
    }

    let successor_manifest = mechanisms
        .put_blob(
            "application/vnd.wasm-biotic.graph+json".to_string(),
            successor.graph().manifest.canonical_bytes()?,
        )
        .map_err(failure_message)?;
    let successor_upgrade = upgrade_envelope(
        "component-successor-activation-v1",
        blob_value(&successor_manifest),
        initial_graph.clone(),
        Some(initialized_state_value.clone()),
        &initialized_state,
        initial_migration,
    )?;
    let upgrade_bytes = call_root_api(
        &mut manager,
        &mechanisms,
        "component-successor-activation-v1",
        "/v1/evolution/apply",
        &serde_json::to_vec(&successor_upgrade)?,
    )?;
    let upgrade_result: FactoryUpgradeResultV1 = serde_json::from_slice(&upgrade_bytes)?;
    let successor_state = mechanisms
        .active_state_reference()
        .map_err(failure_message)?
        .ok_or("successor activation did not select migrated state")?;
    let successor_state_value = blob_value(&successor_state);
    if upgrade_result.schema != FACTORY_UPGRADE_RESULT_SCHEMA
        || upgrade_result.previous_graph != initial_graph
        || upgrade_result.target_graph != successor_graph
        || upgrade_result.previous_state != Some(initialized_state_value.clone())
        || upgrade_result.migrated_state != successor_state_value
        || upgrade_result.committed.state != ActivationStateValue::Active
        || upgrade_result.committed.active_graph != Some(successor_graph.clone())
        || upgrade_result.committed.active_state != Some(successor_state_value.clone())
        || upgrade_result.committed.receipt.is_none()
    {
        return Err("component successor-activation receipt was not exact and truthful".into());
    }
    if !manager.reload_if_changed()?
        || manager.binding().manifest_digest != kernel_digest(&successor.graph().manifest_digest)?
    {
        return Err("manager did not instantiate the component-selected successor".into());
    }

    let successor_cycle = execute_factory_cycle(
        &mut manager,
        &mechanisms,
        state_dir,
        successor,
        &successor_state,
        "lifecycle-successor",
    )?;
    let successor_trace_end = mechanisms.authority_trace()?.len();

    // Health interpretation and rollback choice are both component policy.
    // The host merely restores the exact last-known-good graph/state pair.
    let observation = FactoryObservationV1 {
        schema: FACTORY_OBSERVATION_SCHEMA.to_string(),
        graph_digest: successor_graph.clone(),
        health: FactoryHealth::Unhealthy,
        evidence: vec![blob_value(&successor_cycle.result)],
    };
    let observation_document = mechanisms
        .put_blob(
            JSON_MEDIA_TYPE.to_string(),
            serde_json::to_vec(&observation)?,
        )
        .map_err(failure_message)?;
    let observation_request = FactoryObservationRequestV1 {
        schema: FACTORY_OBSERVATION_REQUEST_SCHEMA.to_string(),
        activation_id: successor_upgrade.activation_id.clone(),
        expected_active_graph: successor_graph.clone(),
        incumbent_graph: initial_graph.clone(),
        observation: blob_value(&observation_document),
    };
    let observation_result_bytes = call_root_api(
        &mut manager,
        &mechanisms,
        "component-successor-observation-v1",
        "/v1/evolution/observe",
        &serde_json::to_vec(&observation_request)?,
    )?;
    let observation_result: FactoryObservationResultV1 =
        serde_json::from_slice(&observation_result_bytes)?;
    let restored_state = mechanisms
        .active_state_reference()
        .map_err(failure_message)?
        .ok_or("component rollback removed the incumbent state pointer")?;
    if observation_result.schema != FACTORY_OBSERVATION_RESULT_SCHEMA
        || observation_result.action != FactoryObservationAction::RolledBack
        || observation_result.observed_graph != successor_graph
        || observation_result.status.state != ActivationStateValue::RolledBack
        || observation_result.status.active_graph != Some(initial_graph.clone())
        || observation_result.status.active_state != Some(initialized_state_value.clone())
        || observation_result.status.receipt.is_none()
        || blob_value(&restored_state) != initialized_state_value
    {
        return Err("component rollback receipt did not restore the exact incumbent pair".into());
    }
    if !manager.reload_if_changed()?
        || manager.binding().manifest_digest != kernel_digest(&initial.graph().manifest_digest)?
    {
        return Err("manager did not instantiate the component-selected rollback target".into());
    }

    let pre_restart_authority_trace = mechanisms.authority_trace()?;
    if incumbent_trace_end > successor_trace_end
        || successor_trace_end > pre_restart_authority_trace.len()
    {
        return Err("R2 authority trace checkpoints are not monotonic".into());
    }

    drop(manager);
    drop(mechanisms);
    let reopened = LocalMechanisms::open_existing(state_dir)?;
    let reopened_state = reopened
        .active_state_reference()
        .map_err(failure_message)?
        .ok_or("restart lost the rolled-back state pointer")?;
    let mut recovered_manager = OpaqueRootManager::boot(reopened.clone(), root_limits())?;
    let restart_preserved_rollback_pair = recovered_manager.binding().manifest_digest
        == kernel_digest(&initial.graph().manifest_digest)?
        && blob_value(&reopened_state) == initialized_state_value;
    if !restart_preserved_rollback_pair {
        return Err("restart did not preserve the exact rolled-back graph/state pair".into());
    }
    let post_rollback_cycle = execute_factory_cycle(
        &mut recovered_manager,
        &reopened,
        state_dir,
        initial,
        &reopened_state,
        "lifecycle-post-rollback",
    )?;
    let post_restart_authority_trace = reopened.authority_trace()?;

    let lifecycle_job_ids = BTreeSet::from([
        incumbent_cycle.evidence.job_id.as_str(),
        successor_cycle.evidence.job_id.as_str(),
        post_rollback_cycle.evidence.job_id.as_str(),
    ]);
    if lifecycle_job_ids.len() != 3 {
        return Err("distinct R1 lifecycle fixtures produced a reused job identity".into());
    }

    let authority_trace_summaries = vec![
        authority_trace_summary(
            "incumbent-cycle",
            &pre_restart_authority_trace[..incumbent_trace_end],
            initial,
            successor,
        )?,
        authority_trace_summary(
            "activation-and-successor-cycle",
            &pre_restart_authority_trace[incumbent_trace_end..successor_trace_end],
            initial,
            successor,
        )?,
        authority_trace_summary(
            "rollback",
            &pre_restart_authority_trace[successor_trace_end..],
            initial,
            successor,
        )?,
        authority_trace_summary(
            "restart-post-rollback-cycle",
            &post_restart_authority_trace,
            initial,
            successor,
        )?,
    ];
    let initial_graph_digest = kernel_digest(&initial.graph().manifest_digest)?;
    let successor_graph_digest = kernel_digest(&successor.graph().manifest_digest)?;
    let pre_trace_graphs = pre_restart_authority_trace
        .iter()
        .map(|entry| entry.graph_manifest_digest)
        .collect::<BTreeSet<_>>();
    let post_trace_graphs = post_restart_authority_trace
        .iter()
        .map(|entry| entry.graph_manifest_digest)
        .collect::<BTreeSet<_>>();
    let principal_mapping_stable = initial.profile().principals()
        == successor.profile().principals()
        && pre_trace_graphs.contains(&initial_graph_digest)
        && pre_trace_graphs.contains(&successor_graph_digest)
        && post_trace_graphs == BTreeSet::from([initial_graph_digest]);
    if !principal_mapping_stable {
        return Err(
            "principal mappings were not stable across activation, rollback and restart".into(),
        );
    }
    let graph_qualified_activation_ownership_handoff_verified =
        graph_qualified_activation_handoff_verified(
            &pre_restart_authority_trace,
            initial,
            successor,
        )?;
    let principal_inventory_digests = BTreeMap::from([
        (
            "incumbent".to_string(),
            ContentDigest::from_bytes(&principal_inventory_bytes(initial)?),
        ),
        (
            "successor".to_string(),
            ContentDigest::from_bytes(&principal_inventory_bytes(successor)?),
        ),
    ]);
    let final_active_manifest_digest = active_manifest_content_digest(&reopened)?;
    let final_active_state = reopened
        .active_state_reference()
        .map_err(failure_message)?
        .ok_or("final lifecycle state has no active state pointer")?;
    if final_active_manifest_digest != initial.graph().manifest_digest
        || blob_value(&final_active_state) != initialized_state_value
    {
        return Err("final lifecycle state is not the exact incumbent graph/state pair".into());
    }
    let final_mechanism_state_digest = mechanism_replay_snapshot(state_dir)?.0;

    let evidence = LifecycleExecutionEvidence {
        all_factory_semantics_executed_as_components: true,
        authority_trace_summaries,
        component_decided_initial_state_binding: true,
        component_decided_rollback: true,
        component_decided_successor_activation: true,
        graph_qualified_activation_ownership_handoff_verified,
        incumbent_cycle: incumbent_cycle.evidence,
        incumbent_graph_manifest_digest: initial.graph().manifest_digest.clone(),
        incumbent_state: initialized_state_value,
        initialization_result,
        initialization_result_digest: ContentDigest::from_bytes(&initialization_bytes),
        native_substrate_responsibility:
            "verified admission, instantiation, metering, opaque persistence, communication and declared-capability enforcement only"
                .to_string(),
        post_rollback_cycle: post_rollback_cycle.evidence,
        principal_inventory_digests,
        principal_mapping_stable_across_restart_activation_and_rollback:
            principal_mapping_stable,
        restart_preserved_rollback_pair,
        rollback_observation_result: observation_result,
        rollback_observation_result_digest: ContentDigest::from_bytes(&observation_result_bytes),
        schema: "wasm-biotic.component-lifecycle-execution.v2".to_string(),
        successor_cycle: successor_cycle.evidence,
        successor_graph_manifest_digest: successor.graph().manifest_digest.clone(),
        successor_state: successor_state_value,
        upgrade_result,
        upgrade_result_digest: ContentDigest::from_bytes(&upgrade_bytes),
    };
    Ok(ComponentLifecycleRun {
        evidence,
        facts: ComponentLifecycleRunFacts {
            final_active_manifest_digest,
            final_active_state: blob_value(&final_active_state),
            final_mechanism_state_digest,
            inactive_active_manifest_after,
            inactive_active_manifest_before,
            incumbent_bootstrap_manifest_digest,
        },
    })
}

fn execute_factory_cycle<P: LifecyclePackageView>(
    manager: &mut OpaqueRootManager,
    mechanisms: &LocalMechanisms,
    state_dir: &Path,
    package: &P,
    state: &KernelBlobRef,
    fixture_label: &str,
) -> Result<ExecutedFactoryCycle> {
    let graph_hex = hex(package.graph().manifest_digest.as_str()).to_string();
    let source_bytes =
        wasm_biotic_service_policy_core::r1::canonical_positive_fixture_bytes(fixture_label);
    let source_digest = ContentDigest::from_bytes(&source_bytes);
    let source = mechanisms
        .put_blob(
            wasm_biotic_service_policy_core::r1::CHANGE_REQUEST_MEDIA_TYPE.to_string(),
            source_bytes.clone(),
        )
        .map_err(failure_message)?;
    let submit_bytes = serde_json::to_vec(&serde_json::json!({
        "schema": "wasm-biotic.factory-submit.v1",
        "graph_digest": {"algorithm": "sha256", "hex": graph_hex},
        "initial_state": {
            "schema": SUPERVISOR_STATE_SCHEMA,
            "blob": blob_json(state),
        },
        "source": blob_json(&source),
    }))?;
    let submit = mechanisms
        .put_blob(JSON_MEDIA_TYPE.to_string(), submit_bytes)
        .map_err(failure_message)?;
    let job_id = manager.root().submit(&submit)?.map_err(failure_message)?;
    let result = manager.root().inspect(&job_id)?.map_err(failure_message)?;
    let completed = completed_job(mechanisms, result.clone())?;
    let r1_semantics = verify_r1_semantics(fixture_label, &source_bytes, &completed)?;
    let exact_replay =
        verify_exact_submit_replay(manager, mechanisms, state_dir, &submit, &job_id, &completed)?;

    let mut execution_completions = BTreeMap::new();
    let mut provenance = BTreeMap::new();
    let worker_router_principal = package_principal_seed(package, "worker-router")?;
    for (stage, node_id) in [
        ("planner", "planner-worker"),
        ("builder", "builder-worker"),
        ("validator", "validator-worker"),
        ("reviewer", "reviewer-worker"),
        ("packager", "packager-worker"),
        ("continuity-worker", "continuity-worker"),
    ] {
        let lease = ContentDigest::from_bytes(
            format!("lease-v1|{graph_hex}|{job_id}|{stage}|1").as_bytes(),
        );
        let operation = component_operation_id(package, "worker-router", &lease)?;
        let item = mechanisms
            .execution_provenance(&operation)?
            .ok_or_else(|| format!("missing execution provenance for {stage}"))?;
        let expected = package
            .graph()
            .manifest
            .nodes
            .iter()
            .find(|node| node.id == node_id)
            .ok_or_else(|| format!("missing worker node {node_id}"))?;
        if item.authority_component_digest != kernel_digest(&expected.component_digest)?
            || item.graph_manifest_digest != Some(kernel_digest(&package.graph().manifest_digest)?)
            || item.caller_principal_seed != Some(worker_router_principal)
        {
            return Err(
                format!("{stage} provenance has the wrong graph, raw or caller authority").into(),
            );
        }
        // Lifecycle evidence is collected through the substrate's read-only
        // operator inspection surface. Calling the guest-facing `poll` import
        // without the worker-router principal would (correctly) be rejected
        // and must never become an ownership bypass.
        let completion = mechanisms
            .execution_completion(&operation)?
            .ok_or_else(|| format!("missing generic mechanism completion for {stage}"))?;
        execution_completions.insert(stage.to_string(), completion_json(&completion));
        provenance.insert(stage.to_string(), item);
    }
    Ok(ExecutedFactoryCycle {
        evidence: FactoryCycleEvidence {
            exact_replay,
            execution_completions,
            final_output_digest: ContentDigest::from_bytes(&completed.final_output_bytes),
            graph_manifest_digest: package.graph().manifest_digest.clone(),
            job_id,
            provenance,
            r1_semantics,
            source_digest,
            terminal_result: completed.value,
            terminal_result_digest: ContentDigest::from_bytes(&completed.inspect_bytes),
        },
        result,
    })
}

fn call_root_api(
    manager: &mut OpaqueRootManager,
    mechanisms: &LocalMechanisms,
    request_id: &str,
    path: &str,
    body: &[u8],
) -> Result<Vec<u8>> {
    let body = mechanisms
        .put_blob(JSON_MEDIA_TYPE.to_string(), body.to_vec())
        .map_err(failure_message)?;
    let response = manager
        .root()
        .handle(&IngressRequest {
            request_id: request_id.to_string(),
            method: "POST".to_string(),
            path: path.to_string(),
            headers: Vec::new(),
            body: Some(body),
        })?
        .map_err(|failure| {
            format!(
                "component route {path} request {request_id} failed: {}: {}",
                failure.code, failure.message
            )
        })?;
    if response.status != 200 {
        return Err(format!("component route {path} returned {}", response.status).into());
    }
    mechanisms
        .get_blob(
            response
                .body
                .ok_or_else(|| format!("component route {path} returned no body"))?,
        )
        .map_err(failure_message)
}

fn upgrade_envelope(
    activation_id: &str,
    candidate_graph: BlobValue,
    expected_active_graph: DigestValue,
    expected_active_state: Option<BlobValue>,
    previous_state: &KernelBlobRef,
    migration_component: DigestValue,
) -> Result<FactoryUpgradeEnvelopeV1> {
    let mut envelope = FactoryUpgradeEnvelopeV1 {
        schema: FACTORY_UPGRADE_SCHEMA.to_string(),
        activation_id: activation_id.to_string(),
        candidate_graph,
        expected_active_graph,
        expected_active_state,
        previous_state: StateDocumentRef {
            schema: SUPERVISOR_STATE_SCHEMA.to_string(),
            blob: blob_value(previous_state),
        },
        migration_component,
        idempotency_key: DigestValue::sha256(b"pending"),
    };
    envelope.idempotency_key = envelope.computed_idempotency_key()?;
    Ok(envelope)
}

fn migration_component(package: &impl LifecyclePackageView) -> Result<DigestValue> {
    package
        .graph()
        .manifest
        .nodes
        .iter()
        .find(|node| node.id == "state-migration")
        .map(|node| policy_digest(&node.component_digest))
        .ok_or_else(|| "release graph has no state-migration component".into())
}

fn policy_digest(digest: &ContentDigest) -> DigestValue {
    DigestValue {
        algorithm: "sha256".to_string(),
        hex: hex(digest.as_str()).to_string(),
    }
}

fn active_manifest_content_digest(mechanisms: &LocalMechanisms) -> Result<ContentDigest> {
    let reference = mechanisms
        .active_manifest_reference()
        .map_err(failure_message)?
        .ok_or("mechanism state has no active manifest pointer")?;
    ContentDigest::new(format!("sha256:{}", reference.content_digest.hex)).map_err(Into::into)
}

fn blob_value(reference: &KernelBlobRef) -> BlobValue {
    BlobValue {
        content_digest: DigestValue {
            algorithm: "sha256".to_string(),
            hex: reference.content_digest.hex.clone(),
        },
        size_bytes: reference.size_bytes,
        media_type: reference.media_type.clone(),
    }
}

fn completed_job(
    mechanisms: &LocalMechanisms,
    inspect_reference: KernelBlobRef,
) -> Result<CompletedJob> {
    let inspect_bytes = mechanisms
        .get_blob(inspect_reference.clone())
        .map_err(failure_message)?;
    let value: serde_json::Value = serde_json::from_slice(&inspect_bytes)?;
    if value.get("status").and_then(serde_json::Value::as_str) != Some("completed") {
        return Err(format!("factory job did not complete: {value}").into());
    }
    let result: JobResultV1 = serde_json::from_slice(&inspect_bytes)?;
    let output = result
        .output
        .ok_or("completed factory job has no terminal output reference")?;
    if output.content_digest.algorithm != "sha256" {
        return Err("completed factory output does not use SHA-256".into());
    }
    let final_output = KernelBlobRef {
        content_digest: wasm_biotic_kernel::bindings::root::wasm_biotic::factory::foundation::Digest {
            algorithm: wasm_biotic_kernel::bindings::root::wasm_biotic::factory::foundation::HashAlgorithm::Sha256,
            hex: output.content_digest.hex,
        },
        size_bytes: output.size_bytes,
        media_type: output.media_type,
    };
    let final_output_bytes = mechanisms
        .get_blob(final_output.clone())
        .map_err(failure_message)?;
    Ok(CompletedJob {
        final_output,
        final_output_bytes,
        inspect_bytes,
        inspect_reference,
        value,
    })
}

fn verify_r1_semantics(
    fixture_label: &str,
    input_bytes: &[u8],
    completed: &CompletedJob,
) -> Result<R1SemanticEvidence> {
    use wasm_biotic_service_policy_core::r1;

    if completed.final_output.media_type != r1::WORK_STATE_MEDIA_TYPE {
        return Err(format!(
            "R1 terminal output has media type {}, expected {}",
            completed.final_output.media_type,
            r1::WORK_STATE_MEDIA_TYPE
        )
        .into());
    }
    let summary =
        r1::verify_resolved_work_state(&completed.final_output_bytes).map_err(|error| {
            format!(
                "R1 terminal output verification failed ({}): {}",
                error.code, error.message
            )
        })?;
    if !summary.source_changed
        || summary.base_tree_digest_hex == summary.patched_tree_digest_hex
        || summary.bytecode_size_bytes == 0
        || summary.provider_policy != "local-fixture"
        || summary.tests_discovered == 0
        || summary.total_tests == 0
        || summary.tests_discovered != summary.total_tests
        || summary.passed_tests != summary.total_tests
        || !summary.review_approved
        || !summary.package_verified
        || !summary.evidence_resolved
    {
        return Err("R1 terminal output did not prove the complete useful-work slice".into());
    }
    Ok(R1SemanticEvidence {
        artifact_digest_hex: summary.artifact_digest_hex,
        base_tree_digest_hex: summary.base_tree_digest_hex,
        bytecode_size_bytes: summary.bytecode_size_bytes,
        evidence_digest_hex: summary.evidence_digest_hex,
        evidence_resolved: summary.evidence_resolved,
        fixture_label: fixture_label.to_string(),
        input_digest: ContentDigest::from_bytes(input_bytes),
        input_media_type: r1::CHANGE_REQUEST_MEDIA_TYPE.to_string(),
        operation_history: summary.operation_history,
        output_digest: ContentDigest::from_bytes(&completed.final_output_bytes),
        output_media_type: completed.final_output.media_type.clone(),
        package_digest_hex: summary.package_digest_hex,
        package_verified: summary.package_verified,
        passed_tests: summary.passed_tests,
        patched_tree_digest_hex: summary.patched_tree_digest_hex,
        provider_policy: summary.provider_policy,
        request_digest_hex: summary.request_digest_hex,
        resolved_digest_hex: summary.resolved_digest_hex,
        review_approved: summary.review_approved,
        review_digest_hex: summary.review_digest_hex,
        source_changed: summary.source_changed,
        tests_discovered: summary.tests_discovered,
        total_tests: summary.total_tests,
        validation_digest_hex: summary.validation_digest_hex,
        verification_digest_hex: summary.verification_digest_hex,
    })
}

fn mechanism_replay_snapshot(state_dir: &Path) -> Result<(ContentDigest, ReplayMechanismCounters)> {
    let bytes = fs::read(state_dir.join("mechanisms.json"))?;
    Ok((
        ContentDigest::from_bytes(&bytes),
        replay_mechanism_counters(&bytes)?,
    ))
}

fn replay_mechanism_counters(bytes: &[u8]) -> Result<ReplayMechanismCounters> {
    let state: serde_json::Value = serde_json::from_slice(bytes)?;
    let counter = |name: &str| -> Result<u64> {
        state
            .get(name)
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| format!("mechanism journal has no unsigned {name}").into())
    };
    let map_len = |name: &str| -> Result<u64> {
        let length = state
            .get(name)
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| format!("mechanism journal has no object {name}"))?
            .len();
        u64::try_from(length).map_err(|_| format!("mechanism journal {name} is too large").into())
    };
    Ok(ReplayMechanismCounters {
        committed_transaction_count: map_len("commits")?,
        transaction_version: counter("transaction_version")?,
        wake_count: map_len("wakes")?,
        wake_idempotency_count: map_len("wake_idempotency")?,
    })
}

fn verify_exact_submit_replay(
    manager: &mut OpaqueRootManager,
    mechanisms: &LocalMechanisms,
    state_dir: &Path,
    submit: &KernelBlobRef,
    job_id: &str,
    completed: &CompletedJob,
) -> Result<ExactReplayEvidence> {
    let (mechanism_state_digest_before, mechanism_counters_before) =
        mechanism_replay_snapshot(state_dir)?;
    let replay_job_id = manager.root().submit(submit)?.map_err(failure_message)?;
    let replay_inspect = manager
        .root()
        .inspect(&replay_job_id)?
        .map_err(failure_message)?;
    let replay = completed_job(mechanisms, replay_inspect)?;
    let (mechanism_state_digest_after, mechanism_counters_after) =
        mechanism_replay_snapshot(state_dir)?;

    let evidence = ExactReplayEvidence {
        inspect_blob_equal: blob_json(&replay.inspect_reference)
            == blob_json(&completed.inspect_reference),
        inspect_bytes_equal: replay.inspect_bytes == completed.inspect_bytes,
        job_id_equal: replay_job_id == job_id,
        mechanism_counters_unchanged: mechanism_counters_after == mechanism_counters_before,
        mechanism_counters_after,
        mechanism_counters_before,
        mechanism_state_unchanged: mechanism_state_digest_after == mechanism_state_digest_before,
        mechanism_state_digest_after,
        mechanism_state_digest_before,
        output_blob_equal: blob_json(&replay.final_output) == blob_json(&completed.final_output),
        output_bytes_equal: replay.final_output_bytes == completed.final_output_bytes,
        resubmitted_exact_submit_blob: true,
        submit_blob: blob_json(submit),
    };
    if !evidence.job_id_equal
        || !evidence.inspect_blob_equal
        || !evidence.inspect_bytes_equal
        || !evidence.output_blob_equal
        || !evidence.output_bytes_equal
        || !evidence.mechanism_counters_unchanged
        || !evidence.mechanism_state_unchanged
    {
        return Err(
            "exact completed-job replay changed identity, output, or mechanism state".into(),
        );
    }
    Ok(evidence)
}

fn completion_json(
    completion: &wasm_biotic_kernel::bindings::root::wasm_biotic::factory::component_runner::RunCompletion,
) -> serde_json::Value {
    use wasm_biotic_kernel::bindings::root::wasm_biotic::factory::foundation::TerminalOutcome;

    let outcome = match &completion.outcome {
        TerminalOutcome::Succeeded(reference) => serde_json::json!({
            "kind": "succeeded",
            "output": blob_json(reference),
        }),
        TerminalOutcome::Rejected(failure) => serde_json::json!({
            "kind": "rejected",
            "failure": failure_json(failure),
        }),
        TerminalOutcome::Failed(failure) => serde_json::json!({
            "kind": "failed",
            "failure": failure_json(failure),
        }),
        TerminalOutcome::Cancelled => serde_json::json!({"kind": "cancelled"}),
        TerminalOutcome::Exhausted(failure) => serde_json::json!({
            "kind": "exhausted",
            "failure": failure_json(failure),
        }),
    };
    serde_json::json!({
        "run_id": completion.run_id,
        "outcome": outcome,
        "receipt": {
            "receipt_id": completion.receipt.receipt_id,
            "request_digest": wit_digest_json(&completion.receipt.request_digest),
            "executor_digest": wit_digest_json(&completion.receipt.executor_digest),
            "started_at_ms": completion.receipt.started_at_ms,
            "finished_at_ms": completion.receipt.finished_at_ms,
            "outcome_digest": wit_digest_json(&completion.receipt.outcome_digest),
            "audit_sequence": completion.receipt.audit_sequence,
        },
    })
}

fn failure_json(
    failure: &wasm_biotic_kernel::bindings::root::wasm_biotic::factory::foundation::Failure,
) -> serde_json::Value {
    serde_json::json!({
        "code": failure.code,
        "message": failure.message,
        "retryable": failure.retryable,
        "evidence": failure.evidence.as_ref().map(blob_json),
    })
}

fn wit_digest_json(
    digest: &wasm_biotic_kernel::bindings::root::wasm_biotic::factory::foundation::Digest,
) -> serde_json::Value {
    serde_json::json!({
        "algorithm": "sha256",
        "hex": digest.hex,
    })
}

fn root_limits() -> ResourceLimits {
    ResourceLimits {
        fuel: 50_000_000,
        max_memory_bytes: 64 * 1024 * 1024,
        max_instances: 256,
        max_memories: 128,
        max_tables: 128,
        max_table_elements: 1_000_000,
    }
}

fn kernel_digest(digest: &ContentDigest) -> Result<Sha256Digest> {
    Ok(digest.as_str().parse()?)
}

fn component_operation_id(
    package: &impl LifecyclePackageView,
    consumer: &str,
    idempotency_key: &ContentDigest,
) -> Result<String> {
    let principal_seed = package_principal_seed(package, consumer)?;
    principal_operation_id(
        &package.graph().manifest_digest,
        principal_seed,
        idempotency_key,
        "component-runner",
    )
}

fn package_principal_seed(
    package: &impl LifecyclePackageView,
    consumer: &str,
) -> Result<Sha256Digest> {
    let principal = package
        .profile()
        .principals()
        .iter()
        .find(|principal| principal.consumer == consumer)
        .ok_or_else(|| format!("missing R2 principal for {consumer}"))?;
    kernel_digest(&principal.principal_seed)
}

fn principal_operation_id(
    graph_manifest_digest: &ContentDigest,
    principal_seed: Sha256Digest,
    idempotency_key: &ContentDigest,
    capability: &str,
) -> Result<String> {
    let scope = canonical_json_bytes(&serde_json::json!({
        "capability": capability,
        "graph_manifest_digest": kernel_digest(graph_manifest_digest)?,
        "idempotency_key": kernel_digest(idempotency_key)?,
        "principal_seed": principal_seed,
        "schema": PRINCIPAL_OPERATION_SCHEMA,
    }))?;
    let operation_scope = Sha256Digest::from_bytes(&scope);
    Ok(format!(
        "operation-{}",
        operation_scope.to_string().trim_start_matches("sha256:")
    ))
}

fn hex(digest: &str) -> &str {
    digest.strip_prefix("sha256:").unwrap_or(digest)
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to a string cannot fail");
    }
    output
}

fn failure_message(
    failure: wasm_biotic_kernel::bindings::root::wasm_biotic::factory::foundation::Failure,
) -> DynError {
    format!("{}: {}", failure.code, failure.message).into()
}

fn blob_json(
    reference: &wasm_biotic_kernel::bindings::root::wasm_biotic::factory::foundation::BlobRef,
) -> serde_json::Value {
    serde_json::json!({
        "content_digest": {
            "algorithm": "sha256",
            "hex": reference.content_digest.hex,
        },
        "size_bytes": reference.size_bytes,
        "media_type": reference.media_type,
    })
}

fn initial_supervisor_state(
    package: &impl LifecyclePackageView,
    graph_hex: &str,
) -> Result<Vec<u8>> {
    let digest = |id: &str| -> Result<serde_json::Value> {
        let node = package
            .graph()
            .manifest
            .nodes
            .iter()
            .find(|node| node.id == id)
            .ok_or_else(|| format!("initial state references missing node {id}"))?;
        Ok(serde_json::json!({
            "algorithm": "sha256",
            "hex": hex(node.component_digest.as_str()),
        }))
    };
    Ok(serde_json::to_vec(&serde_json::json!({
        "schema": "wasm-biotic.supervisor-state.v1",
        "graph_digest": {"algorithm": "sha256", "hex": graph_hex},
        "last_event_sequence": 0,
        "worker_components": {
            "planner": digest("planner-worker")?,
            "builder": digest("builder-worker")?,
            "validator": digest("validator-worker")?,
            "reviewer": digest("reviewer-worker")?,
            "packager": digest("packager-worker")?,
            "continuity-worker": digest("continuity-worker")?,
        },
        "service_components": {
            "build": digest("build-service")?,
            "packaging": digest("packaging-service")?,
            "validation": digest("validation-service")?,
            "review": digest("review-service")?,
            "continuity": digest("continuity-service")?,
            "scheduling": digest("scheduling-service")?,
            "operations": digest("operations-service")?,
        },
        "jobs": {},
        "active_executions": {},
        "completed_executions": {},
    }))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retained_r3_pair_loads_without_build_state_or_signer_material() {
        let packages = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/r3");
        let incumbent = load_retained_lifecycle_package(
            &packages
                .join("sha256-ef9c8aac3b08848d3df56d069df0df405251786e4afb3dd95e1098dd08195eb4"),
        )
        .expect("retained incumbent summary");
        let successor = load_retained_lifecycle_package(
            &packages
                .join("sha256-f98f2f8b6be93e3d9342472a54c08ffa7e976d49a796e8f300a116650d6bbebd"),
        )
        .expect("retained successor summary");

        assert_eq!(
            successor.graph.manifest.previous_graph.as_ref(),
            Some(&incumbent.graph.manifest_digest)
        );
        assert!(matches!(incumbent.profile, ReleaseSubstrateProfile::R3(_)));
        assert!(matches!(successor.profile, ReleaseSubstrateProfile::R3(_)));
        assert!(!incumbent.descriptor.executables.is_empty());
        assert!(!successor.descriptor.executables.is_empty());
    }

    #[test]
    fn public_lifecycle_state_directory_must_be_fresh() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("wall clock after epoch")
            .as_nanos();
        let state = std::env::temp_dir().join(format!(
            "wasm-biotic-public-lifecycle-state-test-{}-{nonce}",
            std::process::id()
        ));
        assert!(!state.exists());
        prepare_fresh_state_directory(&state).expect("create fresh state directory");
        fs::write(state.join("occupied"), b"do not reuse").expect("occupy state directory");
        assert!(prepare_fresh_state_directory(&state).is_err());
        fs::remove_dir_all(state).expect("remove test-owned state directory");
    }

    fn r3_http_constraints_fixture() -> HttpTransportConstraintsV1 {
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
                "dns": {"cidrs": ["127.0.0.1/32"], "policy": "exact-cidrs"},
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
            "schema": "wasm-biotic.http-transport-constraints.v1"
        }))
        .expect("R3 HTTP fixture")
    }

    #[test]
    fn r2_component_operation_identity_is_principal_scoped_and_stable() {
        let graph = ContentDigest::from_bytes(b"graph");
        let principal = ContentDigest::from_bytes(b"principal");
        let idempotency = ContentDigest::from_bytes(b"lease");
        let operation = principal_operation_id(
            &graph,
            kernel_digest(&principal).unwrap(),
            &idempotency,
            "component-runner",
        )
        .unwrap();
        assert_eq!(
            operation,
            "operation-a8d7f72686c95e1b0aefc2c31dec6cb2fadfb6c22f4d185a8f9e92129f1f3e36"
        );
        assert_ne!(
            operation,
            principal_operation_id(
                &graph,
                kernel_digest(&ContentDigest::from_bytes(b"other-principal")).unwrap(),
                &idempotency,
                "component-runner",
            )
            .unwrap()
        );
    }

    #[test]
    fn r2_activation_handoff_trace_crosses_graph_qualified_runtime_principals() {
        let initial_graph = Sha256Digest::from_bytes(b"initial-graph");
        let successor_graph = Sha256Digest::from_bytes(b"successor-graph");
        let principal_seed = Sha256Digest::from_bytes(b"factory-control-principal");
        let activation_alias = "wasm-biotic:factory/host-activation-test@0.1.0";
        let entry =
            |graph_manifest_digest, runtime_principal_digest, method: &str| AuthorityTrace {
                graph_manifest_digest,
                consumer: "factory-control".to_string(),
                authority_component_digest: Sha256Digest::from_bytes(b"factory-control"),
                principal_seed,
                runtime_principal_digest,
                scoped_component_digest: Sha256Digest::from_bytes(b"scoped-factory-control"),
                executable_component_digest: Sha256Digest::from_bytes(b"root-executable"),
                alias: activation_alias.to_string(),
                capability: "activation".to_string(),
                scope: "switch".to_string(),
                constraint_digest: Sha256Digest::from_bytes(b"constraints"),
                method: method.to_string(),
                request_digest: Sha256Digest::from_bytes(method.as_bytes()),
                outcome: "success".to_string(),
            };
        let source_runtime = Sha256Digest::from_bytes(b"source-runtime-principal");
        let target_runtime = Sha256Digest::from_bytes(b"target-runtime-principal");
        let mut trace = vec![
            entry(initial_graph, source_runtime, "commit"),
            entry(successor_graph, target_runtime, "rollback"),
        ];
        assert!(trace_proves_graph_qualified_activation_handoff(
            &trace,
            initial_graph,
            successor_graph,
            principal_seed,
            activation_alias,
        ));
        trace[1].runtime_principal_digest = source_runtime;
        assert!(!trace_proves_graph_qualified_activation_handoff(
            &trace,
            initial_graph,
            successor_graph,
            principal_seed,
            activation_alias,
        ));
        trace[1].runtime_principal_digest = target_runtime;
        trace[1].principal_seed = Sha256Digest::from_bytes(b"wrong-principal");
        assert!(!trace_proves_graph_qualified_activation_handoff(
            &trace,
            initial_graph,
            successor_graph,
            principal_seed,
            activation_alias,
        ));
        trace[1].principal_seed = principal_seed;
        trace.reverse();
        assert!(!trace_proves_graph_qualified_activation_handoff(
            &trace,
            initial_graph,
            successor_graph,
            principal_seed,
            activation_alias,
        ));
    }

    #[test]
    fn r1_positive_fixture_labels_are_stable_and_content_distinct() {
        use wasm_biotic_service_policy_core::r1;

        let incumbent = r1::canonical_positive_fixture_bytes("lifecycle-incumbent");
        assert_eq!(
            incumbent,
            r1::canonical_positive_fixture_bytes("lifecycle-incumbent")
        );
        assert_ne!(
            incumbent,
            r1::canonical_positive_fixture_bytes("lifecycle-successor")
        );
        assert_ne!(
            r1::canonical_positive_fixture_bytes("kernel-probe"),
            r1::canonical_positive_fixture_bytes("lifecycle-post-rollback")
        );
        assert_eq!(
            r1::CHANGE_REQUEST_MEDIA_TYPE,
            "application/vnd.wasm-biotic.r1-change-request.v1+json"
        );
    }

    #[test]
    fn replay_snapshot_exposes_transaction_and_wake_counters() {
        let counters = replay_mechanism_counters(
            br#"{
                "transaction_version": 7,
                "commits": {"a": {}, "b": {}},
                "wakes": {"wake-a": {}},
                "wake_idempotency": {"key-a": "wake-a"}
            }"#,
        )
        .unwrap();
        assert_eq!(counters.transaction_version, 7);
        assert_eq!(counters.committed_transaction_count, 2);
        assert_eq!(counters.wake_count, 1);
        assert_eq!(counters.wake_idempotency_count, 1);
    }

    #[test]
    fn release_definition_is_component_complete_and_has_sealed_dynamic_targets() {
        let specs = node_specs();
        assert_eq!(specs.len(), 22);
        assert_eq!(
            specs
                .iter()
                .filter(|node| node.kind == FactoryComponentKind::AdmittedTool)
                .count(),
            1
        );
        let invocations = manifest_invocations();
        assert_eq!(invocations.len(), 7);
        assert!(invocations.iter().any(|edge| {
            edge.consumer == "factory-evolution" && edge.target == "admitted-tool-probe"
        }));
    }

    #[test]
    fn r2_direct_grants_do_not_collapse_static_closures() {
        let bindings = manifest_bindings();
        let closure = static_nodes("factory-control", &bindings);
        assert_eq!(closure.len(), 15);
        assert!(!closure.contains("planner-worker"));
        assert!(!closure.contains("admitted-tool-probe"));
        assert_eq!(
            bindings
                .iter()
                .filter(|binding| matches!(binding.provider, ComponentBindingProvider::Host { .. }))
                .count(),
            34
        );
        assert_eq!(
            bindings
                .iter()
                .filter(|binding| closure.contains(&binding.consumer))
                .filter(|binding| matches!(binding.provider, ComponentBindingProvider::Host { .. }))
                .count(),
            27
        );

        let built = node_specs()
            .into_iter()
            .map(|spec| {
                let digest = ContentDigest::from_bytes(spec.id.as_bytes());
                (
                    spec.id.to_string(),
                    BuiltNode {
                        spec,
                        bytes: Vec::new(),
                        digest,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        let constraints = ContentDigest::from_bytes(b"constraints");
        let nodes = manifest_nodes(&built, &bindings, &constraints, None).unwrap();
        let root = nodes
            .iter()
            .find(|node| node.id == "factory-control")
            .unwrap();
        assert_eq!(root.grants.len(), 4);
        assert!(root.grants.iter().any(|grant| {
            grant.capability == SubstratePrimitive::TransactionStore
                && grant.scope == "wasm-biotic.factory-control.v1"
        }));
        let planner = nodes
            .iter()
            .find(|node| node.id == "planner-worker")
            .unwrap();
        assert_eq!(planner.grants.len(), 1);
        assert_eq!(planner.grants[0].capability, SubstratePrimitive::BlobStore);
        assert!(
            nodes
                .iter()
                .flat_map(|node| node.grants.iter())
                .all(|grant| grant.constraints == constraints)
        );

        let http_constraints = r3_http_constraints_fixture()
            .content_digest()
            .expect("HTTP constraint digest");
        let r3_nodes =
            manifest_nodes(&built, &bindings, &constraints, Some(&http_constraints)).unwrap();
        let special_grants = r3_nodes
            .iter()
            .flat_map(|node| {
                node.grants
                    .iter()
                    .map(move |grant| (node.id.as_str(), grant))
            })
            .filter(|(_, grant)| grant.constraints == http_constraints)
            .collect::<Vec<_>>();
        assert_eq!(special_grants.len(), 1);
        assert_eq!(special_grants[0].0, "exchange-service");
        assert_eq!(
            special_grants[0].1.capability,
            SubstratePrimitive::HttpTransport
        );
        assert!(
            r3_nodes
                .iter()
                .flat_map(|node| node.grants.iter())
                .all(|grant| {
                    grant.capability == SubstratePrimitive::HttpTransport
                        || grant.constraints == constraints
                })
        );

        let aliases = nodes
            .iter()
            .flat_map(|node| {
                bindings
                    .iter()
                    .filter(move |binding| binding.consumer == node.id)
                    .filter_map(move |binding| match binding.provider {
                        ComponentBindingProvider::Host { capability } => Some(
                            HostImportAliasMaterialV1::for_binding(node, capability)
                                .alias()
                                .unwrap(),
                        ),
                        ComponentBindingProvider::Component { .. } => None,
                    })
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(aliases.len(), 34);
    }

    #[test]
    fn default_r2_profile_serialization_is_unchanged_by_profile_dispatch() {
        let profile = SubstrateProfileV2::component_complete(
            "factory-control",
            Vec::new(),
            CapabilityConstraintsV1::bounded_local_default(),
        );
        let expected = profile.canonical_bytes().expect("direct R2 bytes");
        let dispatched = ReleaseSubstrateProfile::R2(profile)
            .canonical_bytes()
            .expect("dispatched R2 bytes");
        assert_eq!(dispatched, expected);
        assert!(
            !String::from_utf8(dispatched)
                .expect("profile JSON")
                .contains("http_transport")
        );
    }

    #[test]
    fn signed_r2_profile_bytes_remain_an_exact_regression_fixture() {
        let historical = include_bytes!("../fixtures/r2/substrate-profile.json");
        let parsed: SubstrateProfileV2 =
            serde_json::from_slice(historical).expect("historical R2 profile");
        let dispatched = ReleaseSubstrateProfile::R2(parsed)
            .canonical_bytes()
            .expect("canonical historical R2 profile");
        assert_eq!(dispatched, historical);
        assert_eq!(
            ContentDigest::from_bytes(&dispatched).as_str(),
            "sha256:916cb55f0ce3623378854b974536d9f58a7ce489f0d41437f71ee7b4f5c92835"
        );
    }

    #[test]
    fn r3_profile_binding_is_exactly_the_exchange_http_principal_projection() {
        let constraint = r3_http_constraints_fixture()
            .content_digest()
            .expect("HTTP constraint digest");
        let principal = GraphNodePrincipalV2 {
            consumer: "exchange-service".to_string(),
            authority_component_digest: ContentDigest::from_bytes(b"exchange"),
            principal_seed: ContentDigest::from_bytes(b"principal"),
            scoped_component_digest: ContentDigest::from_bytes(b"scoped"),
            host_imports: vec![PrincipalHostImportV2 {
                alias: "wasm-biotic:factory/host-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@0.1.0".to_string(),
                source_import: SubstratePrimitive::HttpTransport.interface_name().to_string(),
                capability: SubstratePrimitive::HttpTransport,
                scope: "request".to_string(),
                constraints: constraint.clone(),
            }],
        };
        let projected = bounded_r3_http_bindings(std::slice::from_ref(&principal))
            .expect("single exchange binding");
        assert_eq!(
            projected,
            vec![HttpTransportBindingV1 {
                consumer: "exchange-service".to_string(),
                alias: principal.host_imports[0].alias.clone(),
                constraints: constraint,
            }]
        );

        let mut extra = principal.clone();
        extra.consumer = "validation-service".to_string();
        assert!(bounded_r3_http_bindings(&[principal, extra]).is_err());
    }

    #[test]
    fn r3_fixture_matches_component_authored_credential_skeleton() {
        let constraints = r3_http_constraints_fixture();
        constraints
            .validate_against(&CapabilityConstraintsV1::bounded_local_default())
            .expect("valid R3 fixture");
        assert_eq!(
            constraints.request_headers.allowed_names,
            vec!["authorization".to_string(), "content-type".to_string()]
        );
        assert_eq!(constraints.credential_bindings.len(), 1);
        assert_eq!(constraints.credential_bindings[0].handle, "exchange-api");
        assert_eq!(
            constraints.credential_bindings[0].header_name,
            "authorization"
        );
        assert_eq!(constraints.credential_bindings[0].value_prefix, "Bearer ");
    }

    #[test]
    fn checked_in_r3_config_loads_to_the_stable_canonical_constraint_digest() {
        let constraints = load_r3_http_constraints(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("r3-http-constraints.example.json"),
        )
        .expect("checked-in R3 constraint config");
        assert_eq!(constraints, r3_http_constraints_fixture());
        assert_eq!(
            constraints
                .content_digest()
                .expect("canonical R3 constraint digest")
                .as_str(),
            "sha256:bc54aaa9f58bc86e5a1fc5c941b6334a283a4074d53806832a675dd860b9a634"
        );
    }

    #[test]
    fn import_scoping_is_deterministic_and_only_renames_requested_top_level_imports() {
        let raw = wat::parse_str(
            r#"(component
                (import "wasm-biotic:factory/blob-store@0.1.0"
                    (instance $blob (export "mechanism" (func))))
                (import "wasm-biotic:factory/build-service@0.1.0"
                    (instance $service (export "build" (func))))
                (core module $leaf (func (export "run")))
                (core instance $instance (instantiate $leaf))
                (func $run (canon lift (core func $instance "run")))
                (export "run" (func $run))
            )"#,
        )
        .unwrap();
        let alias = "wasm-biotic:factory/host-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@0.1.0";
        let aliases = BTreeMap::from([(
            "wasm-biotic:factory/blob-store@0.1.0".to_string(),
            alias.to_string(),
        )]);
        let first = rewrite_host_imports(&raw, &aliases).unwrap();
        let second = rewrite_host_imports(&raw, &aliases).unwrap();
        assert_eq!(first, second);
        let surface = aiaf_v1::component_graph::inspect_component_surface(&first).unwrap();
        assert!(
            surface.imports.iter().any(|import| import == alias),
            "scoped imports: {:?}",
            surface.imports
        );
        assert!(
            surface
                .imports
                .iter()
                .any(|import| import == "wasm-biotic:factory/build-service@0.1.0")
        );
        assert!(
            !surface
                .imports
                .iter()
                .any(|import| import == "wasm-biotic:factory/blob-store@0.1.0")
        );
    }
}
