//! Independent release-package admission.
//!
//! This module deliberately shares no code with the production kernel or the
//! transitional native oracle. It reconstructs the signed artifact closure
//! from package bytes and a separately supplied certifier public key.

use crate::model::*;
use ring::signature::{ED25519, UnparsedPublicKey};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use wasmtime::component::{Component, types::ComponentItem};
use wasmtime::{Config, Engine};

const PACKAGE_SCHEMA: &str = "wasm-biotic.component-graph-package.v1";
const MANIFEST_SCHEMA: &str = "wasm-biotic.factory-graph.v1";
const CERTIFICATE_SCHEMA: &str = "wasm-biotic.release-certification.v1";
const STATEMENT_SCHEMA: &str = "wasm-biotic.release-certification-statement.v1";
const SIGNING_PAYLOAD_SCHEMA: &str = "wasm-biotic.release-certification-signing-payload.v1";
const WIT_PACKAGE: &str = "wasm-biotic:factory@0.1.0";
const TASK_EXPORT: &str = "wasm-biotic:factory/component-task@0.1.0";
const PROFILE_V1: &str = "wasm-biotic.factory-substrate-profile.v1";
const PROFILE_V2: &str = "wasm-biotic.factory-substrate-profile.v2";
const PROFILE_V3: &str = "wasm-biotic.factory-substrate-profile.v3";
const DESCRIPTOR_V1: &str = "wasm-biotic.component-derivation-descriptor.v1";
const DESCRIPTOR_V2: &str = "wasm-biotic.component-derivation-descriptor.v2";
const ALIAS_SCHEME: &str = "wasm-biotic.per-consumer-host-import.v1";
const PRINCIPAL_ID_SCHEME: &str = "wasm-biotic.graph-node-principal.v1";
const EIGHT_PRIMITIVES: [&str; 8] = [
    "blob-store",
    "transaction-store",
    "clock",
    "component-runner",
    "http-transport",
    "key-service",
    "activation",
    "audit-log",
];

#[derive(Clone)]
pub struct LoadedRelease {
    pub directory: PathBuf,
    pub index: PackageIndex,
    pub manifest: Manifest,
    pub manifest_bytes: Vec<u8>,
    pub metadata: Metadata,
    pub descriptor: Descriptor,
    pub profile: Profile,
    pub certificate: Certificate,
    pub certificate_bytes: Vec<u8>,
    pub validation_report_bytes: Vec<u8>,
    pub certified_kernel_tcb_inventory_bytes: Vec<u8>,
    pub root_bytes: Vec<u8>,
    pub raw_components: BTreeMap<Digest, Vec<u8>>,
    pub scoped_components: BTreeMap<Digest, Vec<u8>>,
    pub executables: BTreeMap<Digest, ExecutableArtifact>,
    pub constraints: BTreeMap<Digest, Vec<u8>>,
    pub http_transport_constraints: BTreeMap<Digest, HttpTransportConstraints>,
}

#[derive(Clone)]
pub struct ExecutableArtifact {
    pub descriptor: Executable,
    pub bytes: Vec<u8>,
}

impl LoadedRelease {
    pub fn load(directory: impl AsRef<Path>, certifier_public_key_hex: &str) -> Result<Self> {
        let directory = directory.as_ref().to_path_buf();
        let index: PackageIndex = serde_json::from_slice(&read(&directory, "package.json")?)?;
        require(
            index.package_schema == PACKAGE_SCHEMA,
            "unsupported package schema",
        )?;

        let manifest_bytes =
            checked_read(&directory, "manifest.json", index.graph_manifest_digest)?;
        let manifest: Manifest = parse_canonical(&manifest_bytes, "graph manifest")?;
        require(
            manifest.schema == MANIFEST_SCHEMA,
            "unsupported graph manifest schema",
        )?;
        require(
            manifest.wit_package == WIT_PACKAGE,
            "unexpected WIT package identity",
        )?;
        require(!manifest.nodes.is_empty(), "manifest has no nodes")?;

        let metadata_bytes = checked_read(&directory, "metadata.json", manifest.metadata)?;
        let metadata: Metadata = parse_canonical(&metadata_bytes, "graph metadata")?;
        let descriptor_bytes = checked_read(
            &directory,
            "derivation-descriptor.json",
            metadata.derivation_descriptor_digest,
        )?;
        let descriptor: Descriptor = parse_canonical(&descriptor_bytes, "derivation descriptor")?;
        let profile_bytes = checked_read(
            &directory,
            "substrate-profile.json",
            metadata.substrate_profile_digest,
        )?;
        let profile: Profile = parse_canonical(&profile_bytes, "substrate profile")?;
        validate_profile(&profile, &manifest)?;
        validate_descriptor_version(&descriptor, &profile)?;

        let validation_report_bytes = checked_read(
            &directory,
            "evidence/strict-validation.json",
            index.validation_report_digest,
        )?;
        let certificate_bytes = checked_read(
            &directory,
            "certification/release-certification.json",
            index.certification_digest,
        )?;
        let certificate: Certificate =
            parse_canonical(&certificate_bytes, "release certification")?;
        verify_signature(&certificate, certifier_public_key_hex)?;

        let certified_kernel_tcb_inventory_bytes = checked_read(
            &directory,
            &format!(
                "certified-kernel-tcb/{}.json",
                index.certified_kernel_tcb_inventory_digest.file_stem()
            ),
            index.certified_kernel_tcb_inventory_digest,
        )?;

        let root_bytes = checked_read(
            &directory,
            "factory-root.wasm",
            index.root_executable_digest,
        )?;
        require_component(&root_bytes, "composed root")?;

        let mut raw_components = BTreeMap::new();
        let mut raw_by_node = BTreeMap::new();
        let mut node_ids = BTreeSet::new();
        for node in &manifest.nodes {
            require(
                node_ids.insert(node.id.clone()),
                "duplicate manifest node id",
            )?;
            let bytes = checked_read(
                &directory,
                &format!("components/{}.wasm", node.component_digest.file_stem()),
                node.component_digest,
            )?;
            require_component(&bytes, &format!("raw node {}", node.id))?;
            raw_components.entry(node.component_digest).or_insert(bytes);
            raw_by_node.insert(node.id.clone(), node.component_digest);
        }
        require(
            raw_by_node.get(&manifest.root_node) == Some(&index.root_authority_digest),
            "package root authority differs from manifest",
        )?;

        let mut scoped_components = BTreeMap::new();
        if matches!(profile.schema.as_str(), PROFILE_V2 | PROFILE_V3) {
            for principal in &profile.principals {
                let bytes = checked_read(
                    &directory,
                    &format!(
                        "scoped-components/{}.wasm",
                        principal.scoped_component_digest.file_stem()
                    ),
                    principal.scoped_component_digest,
                )?;
                require_component(&bytes, &format!("scoped node {}", principal.consumer))?;
                require(
                    scoped_components
                        .insert(principal.scoped_component_digest, bytes)
                        .is_none(),
                    "duplicate scoped component digest",
                )?;
            }
        }

        let source_map = descriptor
            .sources
            .iter()
            .map(|source| {
                (
                    source.node_id.clone(),
                    (source.component_digest, source.world.clone()),
                )
            })
            .collect::<BTreeMap<_, _>>();
        require(
            source_map.len() == manifest.nodes.len(),
            "descriptor source set is incomplete",
        )?;
        for node in &manifest.nodes {
            require(
                source_map.get(&node.id) == Some(&(node.component_digest, node.world.clone())),
                &format!("descriptor source mismatch for {}", node.id),
            )?;
        }

        let mut executables = BTreeMap::new();
        let mut derived_by_authority = BTreeMap::new();
        for executable in &descriptor.executables {
            require(
                raw_by_node.get(&executable.authority_node) == Some(&executable.authority_digest),
                &format!(
                    "executable authority mismatch for {}",
                    executable.authority_node
                ),
            )?;
            let bytes = checked_read(
                &directory,
                &format!("derived/{}.wasm", executable.executable_digest.file_stem()),
                executable.executable_digest,
            )?;
            require_component(
                &bytes,
                &format!("derived executable {}", executable.authority_node),
            )?;
            require(
                executables
                    .insert(
                        executable.authority_digest,
                        ExecutableArtifact {
                            descriptor: executable.clone(),
                            bytes,
                        },
                    )
                    .is_none(),
                "duplicate executable authority digest",
            )?;
            derived_by_authority.insert(
                executable.authority_node.clone(),
                executable.executable_digest,
            );
        }
        if matches!(profile.schema.as_str(), PROFILE_V2 | PROFILE_V3) {
            for principal in &profile.principals {
                derived_by_authority.insert(
                    format!("scoped:{}", principal.consumer),
                    principal.scoped_component_digest,
                );
            }
            validate_v2_derivation_surfaces(
                &profile,
                &manifest,
                &descriptor,
                &scoped_components,
                &executables,
            )?;
        }
        let root_descriptor = executables
            .get(&index.root_authority_digest)
            .ok_or("root has no derived executable")?;
        require(
            root_descriptor.descriptor.executable_digest == index.root_executable_digest,
            "root executable index differs from descriptor",
        )?;
        require(
            root_descriptor.bytes == root_bytes,
            "factory-root bytes differ from derived root",
        )?;

        let wit_package_bytes = checked_read(
            &directory,
            &format!(
                "wit/{}-package.json",
                metadata.wit_package_digest.file_stem()
            ),
            metadata.wit_package_digest,
        )?;
        require(!wit_package_bytes.is_empty(), "empty WIT package evidence")?;
        for digest in metadata.wit_world_digests.values() {
            checked_read(
                &directory,
                &format!("wit/{}-worlds.wit", digest.file_stem()),
                *digest,
            )?;
        }
        let mut configuration_digests = descriptor
            .executables
            .iter()
            .map(|executable| executable.configuration_digest)
            .collect::<Vec<_>>();
        configuration_digests.sort_unstable();
        configuration_digests.dedup();
        for digest in &configuration_digests {
            checked_read(
                &directory,
                &format!("composition-configs/{}.config", digest.file_stem()),
                *digest,
            )?;
        }
        let mut constraint_digests = manifest
            .nodes
            .iter()
            .flat_map(|node| node.grants.iter().map(|grant| grant.constraints))
            .collect::<Vec<_>>();
        constraint_digests.sort_unstable();
        constraint_digests.dedup();
        let mut constraints = BTreeMap::new();
        for digest in &constraint_digests {
            let bytes = checked_read(
                &directory,
                &format!("constraints/{}.json", digest.file_stem()),
                *digest,
            )?;
            constraints.insert(*digest, bytes);
        }
        let http_transport_constraints =
            validate_http_transport_constraints(&profile, &constraints)?;

        let statement = &certificate.statement;
        require(
            statement.schema == STATEMENT_SCHEMA,
            "unsupported statement schema",
        )?;
        require(
            statement.graph_manifest_digest == index.graph_manifest_digest,
            "certificate manifest mismatch",
        )?;
        require(
            statement.native_tcb_inventory_digest == index.certified_kernel_tcb_inventory_digest,
            "certificate kernel TCB mismatch",
        )?;
        require(
            statement.wit_package_digest == metadata.wit_package_digest,
            "certificate WIT mismatch",
        )?;
        require(
            statement.metadata_digest == manifest.metadata,
            "certificate metadata mismatch",
        )?;
        require(
            statement.raw_artifacts == raw_by_node,
            "certificate raw artifact map mismatch",
        )?;
        require(
            statement.derived_artifacts == derived_by_authority,
            "certificate derived artifact map mismatch",
        )?;
        require(
            statement.derivation_descriptor_digest == metadata.derivation_descriptor_digest,
            "certificate descriptor mismatch",
        )?;
        require(
            statement.substrate_profile_digest == metadata.substrate_profile_digest,
            "certificate substrate profile mismatch",
        )?;
        require(
            statement.wit_world_digests == metadata.wit_world_digests,
            "certificate WIT worlds mismatch",
        )?;
        require(
            statement.composition_configuration_digests == configuration_digests,
            "certificate composition configuration mismatch",
        )?;
        require(
            statement.constraint_digests == constraint_digests,
            "certificate constraint mismatch",
        )?;
        require(
            statement.validation_report_digest == index.validation_report_digest,
            "certificate validation report mismatch",
        )?;
        require(
            descriptor.wit_package_digest == metadata.wit_package_digest,
            "descriptor WIT digest mismatch",
        )?;

        let allowed_targets = manifest
            .invocations
            .iter()
            .map(|edge| {
                require(
                    edge.export == TASK_EXPORT,
                    "dynamic target has an unexpected export",
                )?;
                raw_by_node
                    .get(&edge.target)
                    .copied()
                    .ok_or_else(|| format!("dynamic target {} is absent", edge.target).into())
            })
            .collect::<Result<BTreeSet<_>>>()?;
        let executable_targets = executables
            .keys()
            .copied()
            .filter(|digest| *digest != index.root_authority_digest)
            .collect::<BTreeSet<_>>();
        require(
            allowed_targets == executable_targets,
            "descriptor dynamic executable set differs from invocation topology",
        )?;

        Ok(Self {
            directory,
            index,
            manifest,
            manifest_bytes,
            metadata,
            descriptor,
            profile,
            certificate,
            certificate_bytes,
            validation_report_bytes,
            certified_kernel_tcb_inventory_bytes,
            root_bytes,
            raw_components,
            scoped_components,
            executables,
            constraints,
            http_transport_constraints,
        })
    }

    pub fn node_digest(&self, id: &str) -> Result<Digest> {
        self.manifest
            .nodes
            .iter()
            .find(|node| node.id == id)
            .map(|node| node.component_digest)
            .ok_or_else(|| format!("release has no node {id}").into())
    }

    pub fn principal_inventory_digest(&self) -> Result<Digest> {
        require(
            matches!(self.profile.schema.as_str(), PROFILE_V2 | PROFILE_V3),
            "principal inventory is only defined for a scoped profile",
        )?;
        let inventory = serde_json::json!({
            "graph_manifest_digest": self.index.graph_manifest_digest,
            "import_alias_scheme": self.profile.import_alias_scheme,
            "principal_id_scheme": self.profile.principal_id_scheme,
            "principals": self.profile.principals,
            "schema": "wasm-biotic.principal-inventory-evidence.v1",
        });
        Ok(Digest::of(&canonical_json(&inventory)?))
    }
}

fn validate_profile(profile: &Profile, manifest: &Manifest) -> Result<()> {
    require(
        matches!(
            profile.schema.as_str(),
            PROFILE_V1 | PROFILE_V2 | PROFILE_V3
        ),
        "unsupported substrate profile",
    )?;
    require(
        profile.wit_package == WIT_PACKAGE,
        "profile WIT package mismatch",
    )?;
    require(
        profile.root_node == manifest.root_node,
        "profile root mismatch",
    )?;
    require(
        profile.primitives == EIGHT_PRIMITIVES,
        "profile does not declare exactly the eight mechanisms",
    )?;
    match profile.schema.as_str() {
        PROFILE_V1 => {
            require(
                profile.static_grant_model == "composed-root-graph-union",
                "unsupported v1 static grant model",
            )?;
            require(
                !profile.root_grants.is_empty(),
                "v1 profile has no root grants",
            )?;
            require(
                profile.import_alias_scheme.is_none()
                    && profile.principal_id_scheme.is_none()
                    && profile.principals.is_empty()
                    && profile.http_transport.is_none(),
                "v1 profile contains v2 principal fields",
            )?;
        }
        PROFILE_V2 => {
            validate_v2_profile(profile, manifest)?;
            require(
                profile.http_transport.is_none(),
                "v2 profile contains v3 HTTP transport fields",
            )?;
        }
        PROFILE_V3 => {
            validate_v2_profile(profile, manifest)?;
            validate_v3_profile_projection(profile, manifest)?;
        }
        _ => unreachable!(),
    }
    let ceilings = &profile.ceilings;
    require(
        ceilings.max_blob_bytes > 0
            && ceilings.max_total_blob_bytes >= ceilings.max_blob_bytes
            && ceilings.max_component_fuel > 0
            && ceilings.max_component_memory_bytes > 0
            && ceilings.max_component_output_bytes > 0
            && ceilings.max_component_wall_time_ms > 0,
        "profile contains an invalid zero or inverted ceiling",
    )
}

fn validate_descriptor_version(descriptor: &Descriptor, profile: &Profile) -> Result<()> {
    let expected = match profile.schema.as_str() {
        PROFILE_V1 => DESCRIPTOR_V1,
        PROFILE_V2 | PROFILE_V3 => DESCRIPTOR_V2,
        _ => return Err("unsupported substrate profile".into()),
    };
    require(
        descriptor.schema == expected,
        "derivation descriptor/profile version mismatch",
    )?;
    for executable in &descriptor.executables {
        if profile.schema == PROFILE_V1 {
            require(
                executable.scoped_source_digests.is_empty()
                    && executable.principal_seeds.is_empty(),
                "v1 descriptor contains v2 principal fields",
            )?;
        } else {
            require(
                executable.grants.is_empty(),
                "v2 descriptor must omit graph-union grants",
            )?;
            require(
                !executable.source_digests.is_empty()
                    && !executable.scoped_source_digests.is_empty()
                    && !executable.principal_seeds.is_empty(),
                "v2 executable principal closure is incomplete",
            )?;
        }
    }
    Ok(())
}

fn validate_v2_profile(profile: &Profile, manifest: &Manifest) -> Result<()> {
    require(
        profile.static_grant_model == "per-consumer-import-alias",
        "unsupported v2 static grant model",
    )?;
    require(
        profile.root_grants.is_empty(),
        "v2 profile must omit graph-union root grants",
    )?;
    require(
        profile.import_alias_scheme.as_deref() == Some(ALIAS_SCHEME),
        "unsupported host import alias scheme",
    )?;
    require(
        profile.principal_id_scheme.as_deref() == Some(PRINCIPAL_ID_SCHEME),
        "unsupported principal identity scheme",
    )?;
    require(
        profile.principals.len() == manifest.nodes.len(),
        "v2 profile does not inventory every manifest node",
    )?;

    let nodes = manifest
        .nodes
        .iter()
        .map(|node| (node.id.as_str(), node))
        .collect::<BTreeMap<_, _>>();
    let mut prior_consumer: Option<&str> = None;
    let mut aliases = BTreeSet::new();
    for principal in &profile.principals {
        require(
            prior_consumer.is_none_or(|prior| prior < principal.consumer.as_str()),
            "v2 principals are not uniquely sorted by consumer",
        )?;
        prior_consumer = Some(&principal.consumer);
        let node = nodes
            .get(principal.consumer.as_str())
            .ok_or("v2 principal names a non-manifest consumer")?;
        require(
            principal.authority_component_digest == node.component_digest,
            "v2 principal authority digest differs from manifest",
        )?;
        require(
            principal.principal_seed
                == principal_seed(&principal.consumer, principal.authority_component_digest)?,
            "v2 principal seed is not deterministically derived",
        )?;

        let host_bindings = manifest
            .bindings
            .iter()
            .filter(|binding| {
                binding.consumer == principal.consumer && binding.provider.kind == "host"
            })
            .collect::<Vec<_>>();
        let component_bindings = manifest.bindings.iter().filter(|binding| {
            binding.consumer == principal.consumer && binding.provider.kind == "component"
        });
        for binding in component_bindings {
            require(
                binding.provider.capability.is_none()
                    && binding.provider.node.is_some()
                    && binding.provider.export.is_some(),
                "component binding is not closed",
            )?;
        }
        require(
            principal.host_imports.len() == host_bindings.len()
                && node.grants.len() == host_bindings.len(),
            "v2 direct grants, host bindings and alias imports differ",
        )?;

        let grants = node
            .grants
            .iter()
            .map(|grant| (grant.capability.as_str(), grant))
            .collect::<BTreeMap<_, _>>();
        require(
            grants.len() == node.grants.len(),
            "manifest node has duplicate capability grants",
        )?;
        let bindings = host_bindings
            .into_iter()
            .map(|binding| {
                let capability = binding
                    .provider
                    .capability
                    .as_deref()
                    .ok_or("host binding has no capability")?;
                require(
                    binding.provider.node.is_none() && binding.provider.export.is_none(),
                    "host binding contains component provider fields",
                )?;
                require(
                    binding.import_name == canonical_host_import(capability),
                    "host binding source import does not match its capability",
                )?;
                Ok((capability, binding.import_name.as_str()))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        require(
            bindings.len() == grants.len(),
            "manifest node has duplicate host capability bindings",
        )?;

        let mut prior_alias: Option<&str> = None;
        for import in &principal.host_imports {
            require(
                prior_alias.is_none_or(|prior| prior < import.alias.as_str()),
                "v2 host aliases are not uniquely sorted",
            )?;
            prior_alias = Some(&import.alias);
            let source_import = bindings
                .get(import.capability.as_str())
                .ok_or("v2 alias has no exact direct host binding")?;
            let grant = grants
                .get(import.capability.as_str())
                .ok_or("v2 alias has no exact direct grant")?;
            require(
                import.source_import == *source_import
                    && import.scope == grant.scope
                    && import.constraints == grant.constraints,
                "v2 alias grant context differs from manifest",
            )?;
            require(
                import.alias
                    == host_import_alias(
                        &principal.consumer,
                        principal.authority_component_digest,
                        &import.capability,
                        &import.source_import,
                    )?,
                "v2 host import alias is not deterministically derived",
            )?;
            require(
                aliases.insert(import.alias.clone()),
                "v2 host import aliases are not globally unique",
            )?;
        }
    }
    Ok(())
}

fn validate_v3_profile_projection(profile: &Profile, manifest: &Manifest) -> Result<()> {
    let transport = profile
        .http_transport
        .as_ref()
        .ok_or("v3 profile has no HTTP transport projection")?;
    require(
        transport.mode == "bounded-external",
        "unsupported v3 HTTP transport mode",
    )?;
    require(
        transport.bindings.len() == 1,
        "v3 profile must contain exactly one HTTP transport binding",
    )?;
    require(
        transport.bindings.windows(2).all(|pair| pair[0] < pair[1]),
        "v3 HTTP transport bindings are not uniquely sorted",
    )?;
    require(
        transport.bindings[0].consumer == "exchange-service",
        "v3 HTTP transport consumer is not exchange-service",
    )?;
    require(
        manifest.nodes.iter().any(|node| {
            node.id == transport.bindings[0].consumer && node.kind == "exchange-service"
        }),
        "v3 HTTP transport consumer is not an exchange-service node",
    )?;

    let mut projected = profile
        .principals
        .iter()
        .flat_map(|principal| {
            principal
                .host_imports
                .iter()
                .filter(|import| import.capability == "http-transport")
                .map(|import| HttpTransportBinding {
                    consumer: principal.consumer.clone(),
                    alias: import.alias.clone(),
                    constraints: import.constraints,
                })
        })
        .collect::<Vec<_>>();
    projected.sort_unstable();
    require(
        transport.bindings == projected,
        "v3 HTTP transport projection differs from principal imports",
    )?;

    let shared_constraints = Digest::of(&canonical_json(&profile.ceilings)?);
    for import in profile
        .principals
        .iter()
        .flat_map(|principal| &principal.host_imports)
    {
        if import.capability != "http-transport" {
            require(
                import.constraints == shared_constraints,
                "v3 non-HTTP import does not bind the exact shared ceilings",
            )?;
        }
    }
    require(
        transport.bindings[0].constraints != shared_constraints,
        "v3 HTTP transport must use its separate constraint object",
    )
}

fn validate_http_transport_constraints(
    profile: &Profile,
    bytes_by_digest: &BTreeMap<Digest, Vec<u8>>,
) -> Result<BTreeMap<Digest, HttpTransportConstraints>> {
    if profile.schema != PROFILE_V3 {
        require(
            profile.http_transport.is_none(),
            "pre-v3 profile contains HTTP transport projection",
        )?;
        return Ok(BTreeMap::new());
    }
    let transport = profile
        .http_transport
        .as_ref()
        .ok_or("v3 profile has no HTTP transport projection")?;
    let mut parsed = BTreeMap::new();
    for binding in &transport.bindings {
        let bytes = bytes_by_digest
            .get(&binding.constraints)
            .ok_or("v3 HTTP transport constraint bytes are absent")?;
        let constraints: HttpTransportConstraints =
            parse_canonical(bytes, "HTTP transport constraints")?;
        validate_http_constraint_object(&constraints, &profile.ceilings)?;
        parsed.insert(binding.constraints, constraints);
    }
    require(
        parsed.len() == transport.bindings.len(),
        "v3 HTTP transport bindings do not have distinct constraints",
    )?;
    Ok(parsed)
}

fn validate_http_constraint_object(
    constraints: &HttpTransportConstraints,
    ceilings: &Constraints,
) -> Result<()> {
    const SCHEMA: &str = "wasm-biotic.http-transport-constraints.v1";
    const METHODS: [&str; 6] = ["delete", "get", "head", "patch", "post", "put"];
    require(
        constraints.schema == SCHEMA,
        "unsupported HTTP constraint schema",
    )?;
    require(
        !constraints.origins.is_empty(),
        "HTTP constraint has no origins",
    )?;
    require(
        constraints
            .origins
            .windows(2)
            .all(|pair| pair[0].id < pair[1].id),
        "HTTP origins are not uniquely sorted by id",
    )?;
    require(
        !constraints.methods.is_empty()
            && constraints.methods.windows(2).all(|pair| pair[0] < pair[1])
            && constraints
                .methods
                .iter()
                .all(|method| METHODS.contains(&method.as_str())),
        "HTTP methods are not a nonempty unique lexical subset",
    )?;
    validate_header_names(
        &constraints.request_headers.allowed_names,
        "request header allowlist",
        true,
    )?;
    validate_header_names(
        &constraints.response_headers.exposed_names,
        "response header exposure list",
        false,
    )?;
    require(
        constraints.request_headers.max_count > 0
            && constraints.request_headers.max_total_bytes > 0
            && constraints.response_headers.max_count > 0
            && constraints.response_headers.max_total_bytes > 0,
        "HTTP header limits must be positive",
    )?;
    require(
        constraints.max_url_bytes > 0
            && constraints.max_request_body_bytes > 0
            && constraints.max_response_body_bytes > 0
            && constraints.max_timeout_ms > 0
            && constraints.max_concurrency > 0,
        "HTTP transport limits must be positive",
    )?;
    require(
        constraints.max_request_body_bytes <= ceilings.max_blob_bytes
            && constraints.max_response_body_bytes <= ceilings.max_blob_bytes
            && constraints.max_url_bytes <= ceilings.max_blob_bytes
            && constraints.request_headers.max_total_bytes <= ceilings.max_blob_bytes
            && constraints.response_headers.max_total_bytes <= ceilings.max_blob_bytes
            && constraints.max_timeout_ms <= ceilings.max_http_timeout_ms,
        "HTTP transport limits exceed shared substrate ceilings",
    )?;
    require(
        constraints.redirects == "deny",
        "HTTP redirects must be denied",
    )?;

    let origin_ids = constraints
        .origins
        .iter()
        .map(|origin| origin.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut origin_authorities = BTreeSet::new();
    for origin in &constraints.origins {
        validate_origin(origin)?;
        require(
            origin_authorities.insert((&origin.scheme, &origin.host, origin.port)),
            "HTTP origins contain a duplicate authority",
        )?;
    }
    require(
        constraints.credential_bindings.windows(2).all(|pair| {
            (&pair[0].handle, &pair[0].origin_id, &pair[0].header_name)
                < (&pair[1].handle, &pair[1].origin_id, &pair[1].header_name)
        }),
        "HTTP credential bindings are not uniquely sorted",
    )?;
    let mut handles = BTreeSet::new();
    for binding in &constraints.credential_bindings {
        require(
            !binding.handle.is_empty()
                && binding.handle.len() <= 256
                && binding
                    .handle
                    .bytes()
                    .all(|byte| (0x21..=0x7e).contains(&byte)),
            "HTTP credential handle is not a bounded visible ASCII token",
        )?;
        require(
            origin_ids.contains(binding.origin_id.as_str()),
            "HTTP credential binding names an unknown origin",
        )?;
        require(
            constraints
                .request_headers
                .allowed_names
                .contains(&binding.header_name),
            "HTTP credential header is not request-allowlisted",
        )?;
        validate_header_name(&binding.header_name, "credential header", true)?;
        require(
            !binding.value_prefix.is_empty()
                && binding.value_prefix.len() <= 1_024
                && binding
                    .value_prefix
                    .bytes()
                    .all(|byte| (0x20..=0x7e).contains(&byte)),
            "HTTP credential prefix is not nonempty bounded visible ASCII",
        )?;
        require(
            binding.placement == "append-to-header-value",
            "unsupported HTTP credential placement",
        )?;
        require(
            handles.insert(&binding.handle),
            "HTTP credential handle has more than one signed placement",
        )?;
    }
    Ok(())
}

fn validate_origin(origin: &HttpOriginConstraint) -> Result<()> {
    require(
        is_canonical_contract_id(&origin.id),
        "HTTP origin id is not canonical",
    )?;
    require(origin.scheme == "https", "HTTP origin scheme is not HTTPS")?;
    require(origin.port > 0, "HTTP origin port is zero")?;
    require(
        is_canonical_http_host(&origin.host),
        "HTTP origin host is not exact lowercase ASCII",
    )?;
    require(
        !origin.path_prefixes.is_empty()
            && origin
                .path_prefixes
                .windows(2)
                .all(|pair| pair[0] < pair[1]),
        "HTTP origin path prefixes are not a nonempty unique lexical list",
    )?;
    for path in &origin.path_prefixes {
        require(
            is_canonical_path_prefix(path),
            "HTTP path prefix is not canonical",
        )?;
    }
    match origin.dns.policy.as_str() {
        "public-only" => require(
            origin.dns.cidrs.is_empty(),
            "public-only DNS policy contains CIDRs",
        )?,
        "exact-cidrs" => {
            require(
                !origin.dns.cidrs.is_empty()
                    && origin.dns.cidrs.windows(2).all(|pair| pair[0] < pair[1]),
                "exact-cidrs policy has no unique lexical CIDRs",
            )?;
            for cidr in &origin.dns.cidrs {
                let network: ipnet::IpNet = cidr
                    .parse()
                    .map_err(|_| "HTTP DNS constraint contains an invalid CIDR")?;
                require(
                    network.to_string() == *cidr
                        && !cidr.ends_with("/0")
                        && cidr.split_once('/').is_some_and(|(_, prefix)| {
                            prefix.len() == 1 || !prefix.starts_with('0')
                        }),
                    "HTTP DNS CIDR is not canonical",
                )?;
            }
        }
        _ => return Err("unsupported HTTP DNS policy".into()),
    }
    require(
        origin.tls.minimum_version == "tls-1.3",
        "HTTP TLS minimum is not TLS 1.3",
    )?;
    require(
        is_canonical_http_host(&origin.tls.server_name) && origin.tls.server_name == origin.host,
        "HTTP TLS server name is not canonical lowercase ASCII",
    )?;
    require(
        !origin.tls.peer_spki_sha256.is_empty()
            && origin
                .tls
                .peer_spki_sha256
                .windows(2)
                .all(|pair| pair[0] < pair[1]),
        "HTTP TLS SPKI pins are not a nonempty unique lexical list",
    )
}

fn is_canonical_path_prefix(path: &str) -> bool {
    path.is_ascii()
        && path.starts_with('/')
        && path.len() <= 4_096
        && path.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
        && !path.contains('%')
        && !path.contains('\\')
        && !path.contains('?')
        && !path.contains('#')
        && !path.contains("//")
        && path
            .split('/')
            .all(|segment| !matches!(segment, "." | ".."))
}

fn validate_header_names(names: &[String], label: &str, forbid_request_names: bool) -> Result<()> {
    require(
        names.windows(2).all(|pair| pair[0] < pair[1]),
        &format!("{label} is not uniquely sorted"),
    )?;
    for name in names {
        validate_header_name(name, label, forbid_request_names)?;
    }
    Ok(())
}

fn validate_header_name(name: &str, label: &str, forbid_request_name: bool) -> Result<()> {
    const DENIED: [&str; 10] = [
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
    ];
    let token = !name.is_empty()
        && name.len() <= 256
        && name == name.to_ascii_lowercase()
        && name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
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
        });
    require(
        token && (!forbid_request_name || !DENIED.contains(&name)),
        &format!("{label} contains an invalid or permanently denied name"),
    )
}

fn is_canonical_contract_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 127
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
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
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    })
}

fn validate_v2_derivation_surfaces(
    profile: &Profile,
    manifest: &Manifest,
    descriptor: &Descriptor,
    scoped_components: &BTreeMap<Digest, Vec<u8>>,
    executables: &BTreeMap<Digest, ExecutableArtifact>,
) -> Result<()> {
    let engine = component_validation_engine()?;
    let principals = profile
        .principals
        .iter()
        .map(|principal| (principal.consumer.as_str(), principal))
        .collect::<BTreeMap<_, _>>();
    let principal_by_authority = profile
        .principals
        .iter()
        .map(|principal| (principal.authority_component_digest, principal))
        .collect::<BTreeMap<_, _>>();
    require(
        principal_by_authority.len() == profile.principals.len(),
        "v2 authority component digests are not unique",
    )?;

    for principal in &profile.principals {
        let bytes = scoped_components
            .get(&principal.scoped_component_digest)
            .ok_or("v2 scoped component bytes are absent")?;
        let actual = component_surface(
            &engine,
            bytes,
            &format!("scoped node {}", principal.consumer),
        )?;
        let expected_imports = manifest
            .bindings
            .iter()
            .filter(|binding| binding.consumer == principal.consumer)
            .map(|binding| {
                if binding.provider.kind == "host" {
                    let capability = binding
                        .provider
                        .capability
                        .as_deref()
                        .ok_or("host binding has no capability")?;
                    principal
                        .host_imports
                        .iter()
                        .find(|import| import.capability == capability)
                        .map(|import| import.alias.clone())
                        .ok_or_else(|| "scoped node has no alias for a host binding".into())
                } else {
                    Ok(binding.import_name.clone())
                }
            })
            .collect::<Result<BTreeSet<_>>>()?;
        let expected_exports = manifest
            .nodes
            .iter()
            .find(|node| node.id == principal.consumer)
            .ok_or("v2 scoped principal has no manifest node")?
            .exports
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        require(
            actual.imports == expected_imports && actual.exports == expected_exports,
            &format!(
                "scoped node {} callable surface is not exact",
                principal.consumer
            ),
        )?;
        require_no_canonical_host_imports(&actual.imports)?;
    }

    for executable in &descriptor.executables {
        let mut expected_aliases = BTreeSet::new();
        let mut expected_scoped = Vec::new();
        let mut expected_seeds = Vec::new();
        require(
            executable
                .source_digests
                .windows(2)
                .all(|pair| pair[0] < pair[1]),
            "v2 executable raw source closure is not uniquely sorted",
        )?;
        for source in &executable.source_digests {
            let principal = principal_by_authority
                .get(source)
                .ok_or("v2 executable source has no principal")?;
            expected_scoped.push(principal.scoped_component_digest);
            expected_seeds.push(principal.principal_seed);
            expected_aliases.extend(
                principal
                    .host_imports
                    .iter()
                    .map(|import| import.alias.clone()),
            );
        }
        expected_scoped.sort_unstable();
        expected_scoped.dedup();
        expected_seeds.sort_unstable();
        expected_seeds.dedup();
        require(
            executable.scoped_source_digests == expected_scoped
                && executable.principal_seeds == expected_seeds
                && executable
                    .scoped_source_digests
                    .windows(2)
                    .all(|pair| pair[0] < pair[1])
                && executable
                    .principal_seeds
                    .windows(2)
                    .all(|pair| pair[0] < pair[1]),
            "v2 executable scoped source/principal closure is not exact",
        )?;
        let authority = principals
            .get(executable.authority_node.as_str())
            .ok_or("v2 executable authority has no principal")?;
        require(
            executable.authority_digest == authority.authority_component_digest,
            "v2 executable authority is not the raw manifest authority",
        )?;
        let artifact = executables
            .get(&executable.authority_digest)
            .ok_or("v2 executable artifact is absent")?;
        let actual = component_surface(
            &engine,
            &artifact.bytes,
            &format!("derived executable {}", executable.authority_node),
        )?;
        require_alias_only_host_surface(&actual.imports, profile)?;
        let expected_exports = manifest
            .nodes
            .iter()
            .find(|node| node.id == executable.authority_node)
            .ok_or("v2 executable authority has no manifest node")?
            .exports
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        require(
            actual.imports == expected_aliases && actual.exports == expected_exports,
            &format!(
                "derived executable {} callable surface is not its exact scoped closure",
                executable.authority_node
            ),
        )?;
    }
    Ok(())
}

struct ComponentSurface {
    imports: BTreeSet<String>,
    exports: BTreeSet<String>,
}

fn component_validation_engine() -> Result<Engine> {
    let mut config = Config::new();
    config.wasm_component_model(true);
    Ok(Engine::new(&config)?)
}

fn component_surface(engine: &Engine, bytes: &[u8], label: &str) -> Result<ComponentSurface> {
    let component = Component::new(engine, bytes)
        .map_err(|error| format!("{label} cannot be compiled for surface validation: {error:#}"))?;
    let component_type = component.component_type();
    Ok(ComponentSurface {
        imports: component_type
            .imports(engine)
            .filter_map(|(name, item)| {
                (!component_item_is_type_only(&item, engine)).then(|| name.to_string())
            })
            .collect(),
        exports: component_type
            .exports(engine)
            .map(|(name, _)| name.to_string())
            .collect(),
    })
}

fn component_item_is_type_only(item: &ComponentItem, engine: &Engine) -> bool {
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

fn require_alias_only_host_surface(imports: &BTreeSet<String>, profile: &Profile) -> Result<()> {
    let aliases = profile
        .principals
        .iter()
        .flat_map(|principal| {
            principal
                .host_imports
                .iter()
                .map(|import| import.alias.as_str())
        })
        .collect::<BTreeSet<_>>();
    require_no_canonical_host_imports(imports)?;
    for import in imports {
        require(
            aliases.contains(import.as_str()),
            "v2 derived surface contains an undeclared import",
        )?;
    }
    Ok(())
}

fn require_no_canonical_host_imports(imports: &BTreeSet<String>) -> Result<()> {
    require(
        !imports.iter().any(|import| {
            EIGHT_PRIMITIVES
                .iter()
                .any(|capability| import == &canonical_host_import(capability))
        }),
        "v2 component surface retains a canonical host import",
    )
}

fn canonical_host_import(capability: &str) -> String {
    format!("wasm-biotic:factory/{capability}@0.1.0")
}

fn verify_signature(certificate: &Certificate, public_key_hex: &str) -> Result<()> {
    require(
        certificate.schema == CERTIFICATE_SCHEMA,
        "unsupported certificate schema",
    )?;
    require(
        certificate.signature.algorithm == "ed25519",
        "unsupported signature algorithm",
    )?;
    let public_key = decode_hex(public_key_hex, 32, "certifier public key")?;
    require(
        Digest::of(&public_key) == certificate.certifier_key_id,
        "pinned certifier key identity mismatch",
    )?;
    let signature = decode_hex(
        &certificate.signature.signature_hex,
        64,
        "certificate signature",
    )?;
    let payload = canonical_json(&SigningPayload {
        certifier_key_id: certificate.certifier_key_id,
        schema: SIGNING_PAYLOAD_SCHEMA,
        statement: &certificate.statement,
    })?;
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(&payload, &signature)
        .map_err(|_| "release certification signature verification failed".into())
}

fn read(directory: &Path, relative: &str) -> Result<Vec<u8>> {
    let path = directory.join(relative);
    fs::read(&path).map_err(|error| {
        format!(
            "cannot read signed package file {}: {error}",
            path.display()
        )
        .into()
    })
}

fn checked_read(directory: &Path, relative: &str, expected: Digest) -> Result<Vec<u8>> {
    let bytes = read(directory, relative)?;
    let actual = Digest::of(&bytes);
    require(
        actual == expected,
        &format!("{relative} digest mismatch: expected {expected}, found {actual}"),
    )?;
    Ok(bytes)
}

fn require_component(bytes: &[u8], label: &str) -> Result<()> {
    require(
        wasmparser::Parser::is_component(bytes),
        &format!("{label} is not a Component Model component"),
    )
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ceilings() -> Constraints {
        Constraints {
            schema: "wasm-biotic.substrate-constraints.v1".to_string(),
            max_blob_bytes: 1024,
            max_total_blob_bytes: 4096,
            max_random_bytes: 64,
            max_wake_delay_ms: 1000,
            max_http_timeout_ms: 1000,
            max_component_fuel: 10_000,
            max_component_memory_bytes: 65_536,
            max_component_output_bytes: 1024,
            max_component_wall_time_ms: 100,
            transaction_namespaces: vec!["test".to_string()],
        }
    }

    fn one_node_v2() -> (Manifest, Profile) {
        let authority = Digest::of(b"consumer");
        let constraints = Digest::of(b"constraints");
        let source_import = "wasm-biotic:factory/blob-store@0.1.0";
        let alias = host_import_alias("consumer", authority, "blob-store", source_import).unwrap();
        let manifest = Manifest {
            schema: MANIFEST_SCHEMA.to_string(),
            wit_package: WIT_PACKAGE.to_string(),
            root_node: "consumer".to_string(),
            previous_graph: None,
            state_schema: "test-state.v1".to_string(),
            nodes: vec![Node {
                id: "consumer".to_string(),
                kind: "test".to_string(),
                component_digest: authority,
                world: "test-world".to_string(),
                exports: vec![],
                grants: vec![Grant {
                    capability: "blob-store".to_string(),
                    scope: "read-write".to_string(),
                    constraints,
                }],
                state_schema: None,
            }],
            bindings: vec![Binding {
                consumer: "consumer".to_string(),
                import_name: source_import.to_string(),
                provider: BindingProvider {
                    kind: "host".to_string(),
                    capability: Some("blob-store".to_string()),
                    node: None,
                    export: None,
                },
            }],
            invocations: vec![],
            metadata: Digest::of(b"metadata"),
        };
        let profile = Profile {
            schema: PROFILE_V2.to_string(),
            wit_package: WIT_PACKAGE.to_string(),
            primitives: EIGHT_PRIMITIVES
                .iter()
                .map(|value| value.to_string())
                .collect(),
            static_grant_model: "per-consumer-import-alias".to_string(),
            root_node: "consumer".to_string(),
            root_grants: vec![],
            import_alias_scheme: Some(ALIAS_SCHEME.to_string()),
            principal_id_scheme: Some(PRINCIPAL_ID_SCHEME.to_string()),
            principals: vec![Principal {
                consumer: "consumer".to_string(),
                authority_component_digest: authority,
                principal_seed: principal_seed("consumer", authority).unwrap(),
                scoped_component_digest: Digest::of(b"scoped"),
                host_imports: vec![HostImport {
                    alias,
                    source_import: source_import.to_string(),
                    capability: "blob-store".to_string(),
                    scope: "read-write".to_string(),
                    constraints,
                }],
            }],
            http_transport: None,
            ceilings: ceilings(),
        };
        (manifest, profile)
    }

    fn one_node_v3() -> (
        Manifest,
        Profile,
        HttpTransportConstraints,
        BTreeMap<Digest, Vec<u8>>,
    ) {
        let ceilings = ceilings();
        let shared_bytes = canonical_json(&ceilings).unwrap();
        let shared_digest = Digest::of(&shared_bytes);
        let http = HttpTransportConstraints {
            schema: "wasm-biotic.http-transport-constraints.v1".to_string(),
            origins: vec![HttpOriginConstraint {
                id: "exchange".to_string(),
                scheme: "https".to_string(),
                host: "api.example.com".to_string(),
                port: 443,
                path_prefixes: vec!["/v1/".to_string()],
                dns: HttpDnsConstraint {
                    policy: "public-only".to_string(),
                    cidrs: vec![],
                },
                tls: HttpTlsConstraint {
                    minimum_version: "tls-1.3".to_string(),
                    server_name: "api.example.com".to_string(),
                    peer_spki_sha256: vec![Digest::of(b"SPKI")],
                },
            }],
            methods: vec!["post".to_string()],
            request_headers: RequestHeaderConstraints {
                allowed_names: vec!["authorization".to_string(), "content-type".to_string()],
                max_count: 4,
                max_total_bytes: 512,
            },
            response_headers: ResponseHeaderConstraints {
                exposed_names: vec!["content-type".to_string()],
                max_count: 16,
                max_total_bytes: 1024,
            },
            max_url_bytes: 512,
            max_request_body_bytes: 1024,
            max_response_body_bytes: 1024,
            max_timeout_ms: 1000,
            max_concurrency: 2,
            redirects: "deny".to_string(),
            credential_bindings: vec![HttpCredentialBinding {
                handle: "exchange-api".to_string(),
                origin_id: "exchange".to_string(),
                header_name: "authorization".to_string(),
                value_prefix: "Bearer ".to_string(),
                placement: "append-to-header-value".to_string(),
            }],
        };
        let http_bytes = canonical_json(&http).unwrap();
        let http_digest = Digest::of(&http_bytes);
        let authority = Digest::of(b"exchange-service");
        let mut imports = [
            (
                "blob-store",
                "read-write",
                shared_digest,
                "wasm-biotic:factory/blob-store@0.1.0",
            ),
            (
                "http-transport",
                "request",
                http_digest,
                "wasm-biotic:factory/http-transport@0.1.0",
            ),
        ]
        .into_iter()
        .map(
            |(capability, scope, constraints, source_import)| HostImport {
                alias: host_import_alias("exchange-service", authority, capability, source_import)
                    .unwrap(),
                source_import: source_import.to_string(),
                capability: capability.to_string(),
                scope: scope.to_string(),
                constraints,
            },
        )
        .collect::<Vec<_>>();
        imports.sort_by(|left, right| left.alias.cmp(&right.alias));
        let http_alias = imports
            .iter()
            .find(|import| import.capability == "http-transport")
            .unwrap()
            .alias
            .clone();
        let manifest = Manifest {
            schema: MANIFEST_SCHEMA.to_string(),
            wit_package: WIT_PACKAGE.to_string(),
            root_node: "exchange-service".to_string(),
            previous_graph: None,
            state_schema: "test-state.v1".to_string(),
            nodes: vec![Node {
                id: "exchange-service".to_string(),
                kind: "exchange-service".to_string(),
                component_digest: authority,
                world: "test-world".to_string(),
                exports: vec![],
                grants: vec![
                    Grant {
                        capability: "blob-store".to_string(),
                        scope: "read-write".to_string(),
                        constraints: shared_digest,
                    },
                    Grant {
                        capability: "http-transport".to_string(),
                        scope: "request".to_string(),
                        constraints: http_digest,
                    },
                ],
                state_schema: None,
            }],
            bindings: vec![
                Binding {
                    consumer: "exchange-service".to_string(),
                    import_name: "wasm-biotic:factory/blob-store@0.1.0".to_string(),
                    provider: BindingProvider {
                        kind: "host".to_string(),
                        capability: Some("blob-store".to_string()),
                        node: None,
                        export: None,
                    },
                },
                Binding {
                    consumer: "exchange-service".to_string(),
                    import_name: "wasm-biotic:factory/http-transport@0.1.0".to_string(),
                    provider: BindingProvider {
                        kind: "host".to_string(),
                        capability: Some("http-transport".to_string()),
                        node: None,
                        export: None,
                    },
                },
            ],
            invocations: vec![],
            metadata: Digest::of(b"metadata"),
        };
        let profile = Profile {
            schema: PROFILE_V3.to_string(),
            wit_package: WIT_PACKAGE.to_string(),
            primitives: EIGHT_PRIMITIVES
                .iter()
                .map(|value| value.to_string())
                .collect(),
            static_grant_model: "per-consumer-import-alias".to_string(),
            root_node: "exchange-service".to_string(),
            root_grants: vec![],
            import_alias_scheme: Some(ALIAS_SCHEME.to_string()),
            principal_id_scheme: Some(PRINCIPAL_ID_SCHEME.to_string()),
            principals: vec![Principal {
                consumer: "exchange-service".to_string(),
                authority_component_digest: authority,
                principal_seed: principal_seed("exchange-service", authority).unwrap(),
                scoped_component_digest: Digest::of(b"scoped"),
                host_imports: imports,
            }],
            http_transport: Some(HttpTransportProfile {
                mode: "bounded-external".to_string(),
                bindings: vec![HttpTransportBinding {
                    consumer: "exchange-service".to_string(),
                    alias: http_alias,
                    constraints: http_digest,
                }],
            }),
            ceilings,
        };
        let bytes = BTreeMap::from([(shared_digest, shared_bytes), (http_digest, http_bytes)]);
        (manifest, profile, http, bytes)
    }

    #[test]
    fn r2_profile_recomputes_every_principal_and_alias() {
        let (manifest, profile) = one_node_v2();
        validate_profile(&profile, &manifest).unwrap();

        let mut forged_seed = profile.clone();
        forged_seed.principals[0].principal_seed = Digest::of(b"forged");
        assert!(
            validate_profile(&forged_seed, &manifest)
                .unwrap_err()
                .to_string()
                .contains("principal seed")
        );

        let mut borrowed_alias = profile;
        borrowed_alias.principals[0].host_imports[0].alias = host_import_alias(
            "other-consumer",
            borrowed_alias.principals[0].authority_component_digest,
            "blob-store",
            "wasm-biotic:factory/blob-store@0.1.0",
        )
        .unwrap();
        assert!(
            validate_profile(&borrowed_alias, &manifest)
                .unwrap_err()
                .to_string()
                .contains("deterministically derived")
        );
    }

    #[test]
    fn r2_profile_rejects_grant_binding_drift() {
        let (mut manifest, profile) = one_node_v2();
        manifest.nodes[0].grants[0].scope = "read".to_string();
        assert!(
            validate_profile(&profile, &manifest)
                .unwrap_err()
                .to_string()
                .contains("differs from manifest")
        );
    }

    #[test]
    fn r3_profile_and_closed_http_constraints_are_exactly_projected() {
        let (manifest, profile, _, bytes) = one_node_v3();
        validate_profile(&profile, &manifest).unwrap();
        let admitted = validate_http_transport_constraints(&profile, &bytes).unwrap();
        assert_eq!(admitted.len(), 1);

        let mut forged_alias = profile.clone();
        forged_alias.http_transport.as_mut().unwrap().bindings[0].alias = "forged".to_string();
        assert!(
            validate_profile(&forged_alias, &manifest)
                .unwrap_err()
                .to_string()
                .contains("projection")
        );

        let mut shared_drift = profile;
        shared_drift.principals[0]
            .host_imports
            .iter_mut()
            .find(|import| import.capability == "blob-store")
            .unwrap()
            .constraints = Digest::of(b"drift");
        let error = validate_profile(&shared_drift, &manifest)
            .unwrap_err()
            .to_string();
        assert!(error.contains("differs from manifest") || error.contains("shared ceilings"));
    }

    #[test]
    fn r3_http_constraint_rejects_bounds_dns_paths_headers_and_unknown_fields() {
        let (_, profile, constraint, bytes) = one_node_v3();
        validate_http_transport_constraints(&profile, &bytes).unwrap();

        let mut invalid = constraint.clone();
        invalid.max_timeout_ms = profile.ceilings.max_http_timeout_ms + 1;
        assert!(validate_http_constraint_object(&invalid, &profile.ceilings).is_err());
        let mut invalid = constraint.clone();
        invalid.origins[0].dns.cidrs = vec!["10.0.0.0/8".to_string()];
        assert!(validate_http_constraint_object(&invalid, &profile.ceilings).is_err());
        let mut invalid = constraint.clone();
        invalid.origins[0].path_prefixes = vec!["/v1/../secret".to_string()];
        assert!(validate_http_constraint_object(&invalid, &profile.ceilings).is_err());
        let mut invalid = constraint.clone();
        invalid
            .request_headers
            .allowed_names
            .push("host".to_string());
        invalid.request_headers.allowed_names.sort();
        assert!(validate_http_constraint_object(&invalid, &profile.ceilings).is_err());

        let mut invalid = constraint;
        invalid.credential_bindings[0].value_prefix.clear();
        assert!(validate_http_constraint_object(&invalid, &profile.ceilings).is_err());

        let mut value = serde_json::to_value(&invalid).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("retry_policy".to_string(), serde_json::json!("native"));
        let bytes = canonical_json(&value).unwrap();
        assert!(parse_canonical::<HttpTransportConstraints>(&bytes, "HTTP constraints").is_err());
    }

    #[test]
    fn retained_r1_profile_and_manifest_remain_closed_canonical_documents() {
        let package = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/r1");
        let profile_bytes = fs::read(package.join("substrate-profile.json")).unwrap();
        let manifest_bytes = fs::read(package.join("manifest.json")).unwrap();
        let profile: Profile = parse_canonical(&profile_bytes, "retained R1 profile").unwrap();
        let manifest: Manifest = parse_canonical(&manifest_bytes, "retained R1 manifest").unwrap();
        validate_profile(&profile, &manifest).unwrap();
        assert_eq!(canonical_json(&profile).unwrap(), profile_bytes);
        assert_eq!(canonical_json(&manifest).unwrap(), manifest_bytes);
    }
}
