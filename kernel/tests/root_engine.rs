use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{Value, json};
use wasm_biotic_kernel::bindings::root::exports::wasm_biotic::factory::factory_api::IngressRequest;
use wasm_biotic_kernel::bindings::root::wasm_biotic::factory::{
    activation, clock, component_runner, foundation,
};
use wasm_biotic_kernel::{
    AdmittedComponent, ContentArtifact, LocalConfig, LocalMechanisms, OpaqueRootEngine,
    OpaqueRootManager, RELEASE_CERTIFICATION_STATEMENT_SCHEMA, ReleaseCertificationStatement,
    ResourceLimits, RootAdmission, RootEvidence, Sha256Digest, SignedReleaseCertification,
    TrustedCertifier, compiled_native_tcb_inventory_digest,
};

const ROOT_COMPONENT: &[u8] = include_bytes!("../fixtures/artifacts/root.wasm");
const TASK_COMPONENT: &[u8] = include_bytes!("../fixtures/artifacts/task.wasm");
const MECHANISM_TASK_COMPONENT: &[u8] = include_bytes!("../fixtures/artifacts/mechanism-task.wasm");
const ADVERSARIAL_TASK_COMPONENT: &[u8] =
    include_bytes!("../fixtures/artifacts/adversarial-task.wasm");
const ROOT_WORLD: &str = "wasm-biotic:factory/factory-control-component@0.1.0";
const TASK_WORLD: &str = "wasm-biotic:factory/admitted-tool-component@0.1.0";
static NEXT_TEMP: AtomicUsize = AtomicUsize::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "wasm-biotic-kernel-root-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn digest_value(digest: Sha256Digest) -> foundation::Digest {
    foundation::Digest {
        algorithm: foundation::HashAlgorithm::Sha256,
        hex: digest.to_string().trim_start_matches("sha256:").to_string(),
    }
}

fn manifest_reference(admission: &RootAdmission) -> foundation::BlobRef {
    foundation::BlobRef {
        content_digest: digest_value(admission.manifest_digest),
        size_bytes: u64::try_from(admission.manifest_bytes.len()).unwrap(),
        media_type: "application/vnd.wasm-biotic.graph+json".to_string(),
    }
}

fn canonical(value: &Value) -> Vec<u8> {
    fn write(value: &Value, output: &mut Vec<u8>) {
        match value {
            Value::Null => output.extend_from_slice(b"null"),
            Value::Bool(value) => {
                output.extend_from_slice(if *value { b"true" } else { b"false" });
            }
            Value::Number(value) => output.extend_from_slice(value.to_string().as_bytes()),
            Value::String(value) => output.extend_from_slice(&serde_json::to_vec(value).unwrap()),
            Value::Array(values) => {
                output.push(b'[');
                for (index, value) in values.iter().enumerate() {
                    if index != 0 {
                        output.push(b',');
                    }
                    write(value, output);
                }
                output.push(b']');
            }
            Value::Object(values) => {
                output.push(b'{');
                let mut keys = values.keys().collect::<Vec<_>>();
                keys.sort_unstable();
                for (index, key) in keys.into_iter().enumerate() {
                    if index != 0 {
                        output.push(b',');
                    }
                    write(&Value::String(key.clone()), output);
                    output.push(b':');
                    write(&values[key], output);
                }
                output.push(b'}');
            }
        }
    }

    let mut bytes = Vec::new();
    write(value, &mut bytes);
    bytes
}

fn artifact(bytes: Vec<u8>) -> ContentArtifact {
    ContentArtifact {
        digest: Sha256Digest::from_bytes(&bytes),
        bytes,
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

fn test_key_pair() -> Ed25519KeyPair {
    static PKCS8: OnceLock<Vec<u8>> = OnceLock::new();
    let pkcs8 = PKCS8.get_or_init(|| {
        Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .unwrap()
            .as_ref()
            .to_vec()
    });
    Ed25519KeyPair::from_pkcs8(pkcs8).unwrap()
}

fn test_trust() -> TrustedCertifier {
    TrustedCertifier::from_public_key_hex(&encode_hex(test_key_pair().public_key().as_ref()))
        .unwrap()
}

fn fresh_trust() -> TrustedCertifier {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    TrustedCertifier::from_public_key_hex(&encode_hex(key_pair.public_key().as_ref())).unwrap()
}

fn sign_statement(statement: ReleaseCertificationStatement) -> ContentArtifact {
    let key_pair = test_key_pair();
    let key_id = Sha256Digest::from_bytes(key_pair.public_key().as_ref());
    let payload = SignedReleaseCertification::signing_payload_bytes(&statement, key_id).unwrap();
    let certificate = SignedReleaseCertification::assemble(
        key_id,
        statement,
        encode_hex(key_pair.sign(&payload).as_ref()),
    )
    .unwrap();
    artifact(certificate.canonical_bytes().unwrap())
}

fn certify_admission(admission: &mut RootAdmission) {
    let manifest: Value = serde_json::from_slice(&admission.manifest_bytes).unwrap();
    let metadata: Value = serde_json::from_slice(&admission.evidence.metadata.bytes).unwrap();
    let descriptor: Value =
        serde_json::from_slice(&admission.evidence.derivation_descriptor.bytes).unwrap();
    let raw_artifacts = manifest["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|node| {
            (
                node["id"].as_str().unwrap().to_string(),
                node["component_digest"]
                    .as_str()
                    .unwrap()
                    .parse::<Sha256Digest>()
                    .unwrap(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let executables = descriptor["executables"].as_array().unwrap();
    let derived_artifacts = executables
        .iter()
        .map(|executable| {
            (
                executable["authority_node"].as_str().unwrap().to_string(),
                executable["executable_digest"]
                    .as_str()
                    .unwrap()
                    .parse::<Sha256Digest>()
                    .unwrap(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let wit_world_digests = metadata["wit_world_digests"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(world, digest)| {
            (
                world.clone(),
                digest.as_str().unwrap().parse::<Sha256Digest>().unwrap(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let composition_configuration_digests = executables
        .iter()
        .map(|executable| {
            executable["configuration_digest"]
                .as_str()
                .unwrap()
                .parse::<Sha256Digest>()
                .unwrap()
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let constraint_digests = manifest["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|node| node["grants"].as_array().unwrap())
        .map(|grant| {
            grant["constraints"]
                .as_str()
                .unwrap()
                .parse::<Sha256Digest>()
                .unwrap()
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let report = artifact(canonical(&json!({
        "outcome": "pass",
        "schema": "wasm-biotic.component-strict-validation-report.v1",
        "validator_identity": "kernel-test-offline-validator",
        "validator_version": "1",
    })));
    let statement = ReleaseCertificationStatement {
        schema: RELEASE_CERTIFICATION_STATEMENT_SCHEMA.to_string(),
        graph_manifest_digest: admission.manifest_digest,
        native_tcb_inventory_digest: compiled_native_tcb_inventory_digest(),
        wit_package_digest: admission.evidence.wit_package.digest,
        metadata_digest: admission.evidence.metadata.digest,
        raw_artifacts,
        derived_artifacts,
        derivation_descriptor_digest: admission.evidence.derivation_descriptor.digest,
        substrate_profile_digest: admission.evidence.substrate_profile.digest,
        wit_world_digests,
        composition_configuration_digests,
        constraint_digests,
        validation_report_digest: report.digest,
        validator_identity: "kernel-test-offline-validator".to_string(),
        validator_version: "1".to_string(),
    };
    admission.evidence.validation_report = report;
    admission.evidence.release_certification = sign_statement(statement);
}

fn compiled_wit_package() -> ContentArtifact {
    let files = [
        (
            "wit/wasm-biotic/control-plane.wit",
            include_str!("../../wit/wasm-biotic/control-plane.wit"),
        ),
        (
            "wit/wasm-biotic/foundation.wit",
            include_str!("../../wit/wasm-biotic/foundation.wit"),
        ),
        (
            "wit/wasm-biotic/services.wit",
            include_str!("../../wit/wasm-biotic/services.wit"),
        ),
        (
            "wit/wasm-biotic/substrate.wit",
            include_str!("../../wit/wasm-biotic/substrate.wit"),
        ),
        (
            "wit/wasm-biotic/workers.wit",
            include_str!("../../wit/wasm-biotic/workers.wit"),
        ),
        (
            "wit/wasm-biotic/worlds.wit",
            include_str!("../../wit/wasm-biotic/worlds.wit"),
        ),
    ]
    .into_iter()
    .map(|(path, content)| {
        json!({
            "content": content,
            "content_digest": Sha256Digest::from_bytes(content.as_bytes()),
            "path": path,
        })
    })
    .collect::<Vec<_>>();
    artifact(canonical(&json!({
        "files": files,
        "package": "wasm-biotic:factory@0.1.0",
        "schema": "wasm-biotic.wit-package.v1",
    })))
}

fn digest_stem(digest: Sha256Digest) -> String {
    digest.to_string().replace(':', "-")
}

fn write_package(path: &Path, admission: &RootAdmission) {
    for directory in [
        "components",
        "derived",
        "composition-configs",
        "constraints",
        "wit",
        "evidence",
        "certification",
        "certified-kernel-tcb",
    ] {
        fs::create_dir_all(path.join(directory)).unwrap();
    }
    let manifest: Value = serde_json::from_slice(&admission.manifest_bytes).unwrap();
    let root_node = manifest["root_node"].as_str().unwrap();
    let root_authority = manifest["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|node| node["id"].as_str() == Some(root_node))
        .unwrap()["component_digest"]
        .as_str()
        .unwrap()
        .parse::<Sha256Digest>()
        .unwrap();
    fs::write(
        path.join("package.json"),
        canonical(&json!({
            "certification_digest": admission.evidence.release_certification.digest,
            "certified_kernel_tcb_inventory_digest": admission
                .evidence
                .certified_kernel_tcb_inventory
                .digest,
            "package_schema": "wasm-biotic.component-graph-package.v1",
            "graph_manifest_digest": admission.manifest_digest,
            "root_authority_digest": root_authority,
            "root_executable_digest": admission.composed_root.digest,
            "validation_report_digest": admission.evidence.validation_report.digest,
        })),
    )
    .unwrap();
    fs::write(path.join("manifest.json"), &admission.manifest_bytes).unwrap();
    fs::write(
        path.join("metadata.json"),
        &admission.evidence.metadata.bytes,
    )
    .unwrap();
    fs::write(
        path.join("certified-kernel-tcb").join(format!(
            "{}.json",
            digest_stem(admission.evidence.certified_kernel_tcb_inventory.digest)
        )),
        &admission.evidence.certified_kernel_tcb_inventory.bytes,
    )
    .unwrap();
    fs::write(
        path.join("derivation-descriptor.json"),
        &admission.evidence.derivation_descriptor.bytes,
    )
    .unwrap();
    fs::write(
        path.join("substrate-profile.json"),
        &admission.evidence.substrate_profile.bytes,
    )
    .unwrap();
    fs::write(
        path.join("factory-root.wasm"),
        &admission.composed_root.bytes,
    )
    .unwrap();
    for component in &admission.source_components {
        fs::write(
            path.join(format!("components/{}.wasm", digest_stem(component.digest))),
            &component.bytes,
        )
        .unwrap();
    }
    for component in &admission.execution_artifacts {
        fs::write(
            path.join(format!("derived/{}.wasm", digest_stem(component.digest))),
            &component.bytes,
        )
        .unwrap();
    }
    fs::write(
        path.join(format!(
            "wit/{}-package.json",
            digest_stem(admission.evidence.wit_package.digest)
        )),
        &admission.evidence.wit_package.bytes,
    )
    .unwrap();
    for world in &admission.evidence.wit_worlds {
        fs::write(
            path.join(format!("wit/{}-worlds.wit", digest_stem(world.digest))),
            &world.bytes,
        )
        .unwrap();
    }
    for configuration in &admission.evidence.composition_configurations {
        fs::write(
            path.join(format!(
                "composition-configs/{}.config",
                digest_stem(configuration.digest)
            )),
            &configuration.bytes,
        )
        .unwrap();
    }
    for constraint in &admission.evidence.constraints {
        fs::write(
            path.join(format!(
                "constraints/{}.json",
                digest_stem(constraint.digest)
            )),
            &constraint.bytes,
        )
        .unwrap();
    }
    fs::write(
        path.join("evidence/strict-validation.json"),
        &admission.evidence.validation_report.bytes,
    )
    .unwrap();
    fs::write(
        path.join("certification/release-certification.json"),
        &admission.evidence.release_certification.bytes,
    )
    .unwrap();
}

fn component_variant(marker: &[u8]) -> Vec<u8> {
    fn push_leb(mut value: usize, bytes: &mut Vec<u8>) {
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            bytes.push(byte);
            if value == 0 {
                return;
            }
        }
    }

    let mut payload = Vec::new();
    push_leb("variant".len(), &mut payload);
    payload.extend_from_slice(b"variant");
    payload.extend_from_slice(marker);
    let mut bytes = ROOT_COMPONENT.to_vec();
    bytes.push(0);
    push_leb(payload.len(), &mut bytes);
    bytes.extend_from_slice(&payload);
    bytes
}

fn grant(capability: &str, scope: &str, constraints: Sha256Digest) -> Value {
    json!({
        "capability": capability,
        "scope": scope,
        "constraints": constraints,
    })
}

fn constraints(max_component_fuel: u64) -> ContentArtifact {
    artifact(canonical(&json!({
        "schema": "wasm-biotic.capability-constraints.v1",
        "max_blob_bytes": 16 * 1024 * 1024_u64,
        "max_total_blob_bytes": 256 * 1024 * 1024_u64,
        "max_random_bytes": 4096,
        "max_wake_delay_ms": 2_592_000_000_u64,
        "max_http_timeout_ms": 30_000,
        "max_component_fuel": max_component_fuel,
        "max_component_memory_bytes": 64 * 1024 * 1024_u64,
        "max_component_output_bytes": 16 * 1024 * 1024_u64,
        "max_component_wall_time_ms": 30_000,
        "transaction_namespaces": [
            "exchange-v1",
            "wasm-biotic.factory-control.v1",
            "wasm-biotic.schedule.v1"
        ],
    })))
}

fn root_grants(constraint: Sha256Digest) -> Vec<Value> {
    vec![
        grant("blob-store", "read-write", constraint),
        grant("transaction-store", "namespaces", constraint),
        grant("clock", "wake", constraint),
        grant("component-runner", "run", constraint),
        grant("http-transport", "request", constraint),
        grant("key-service", "use", constraint),
        grant("activation", "switch", constraint),
        grant("audit-log", "append-read", constraint),
    ]
}

fn task_grants(constraint: Sha256Digest) -> Vec<Value> {
    vec![
        grant("blob-store", "read-write", constraint),
        grant("transaction-store", "wasm-biotic.schedule.v1", constraint),
        grant("clock", "wake", constraint),
    ]
}

fn adversarial_task_grants(constraint: Sha256Digest) -> Vec<Value> {
    vec![
        grant("blob-store", "read-write", constraint),
        grant("transaction-store", "wasm-biotic.schedule.v1", constraint),
        grant("clock", "wake", constraint),
        grant("component-runner", "run", constraint),
        grant("http-transport", "request", constraint),
        grant("key-service", "use", constraint),
        grant("activation", "switch", constraint),
    ]
}

fn local_capacity() -> LocalConfig {
    LocalConfig::default()
        .allow_namespace("exchange-v1")
        .allow_namespace("wasm-biotic.factory-control.v1")
        .allow_namespace("wasm-biotic.schedule.v1")
}

fn launch_admission(
    root_source: Vec<u8>,
    dynamic: bool,
) -> (RootAdmission, Sha256Digest, Sha256Digest) {
    launch_admission_with_fuel(root_source, dynamic, 50_000_000)
}

fn launch_admission_with_fuel(
    root_source: Vec<u8>,
    dynamic: bool,
    max_component_fuel: u64,
) -> (RootAdmission, Sha256Digest, Sha256Digest) {
    launch_admission_with_fuel_and_task(
        root_source,
        dynamic,
        max_component_fuel,
        MECHANISM_TASK_COMPONENT,
        task_grants,
    )
}

fn launch_admission_with_adversarial_task(
    root_source: Vec<u8>,
) -> (RootAdmission, Sha256Digest, Sha256Digest) {
    launch_admission_with_fuel_and_task(
        root_source,
        true,
        50_000_000,
        ADVERSARIAL_TASK_COMPONENT,
        adversarial_task_grants,
    )
}

fn launch_admission_with_fuel_and_task(
    root_source: Vec<u8>,
    dynamic: bool,
    max_component_fuel: u64,
    task_executable: &[u8],
    task_grant_builder: fn(Sha256Digest) -> Vec<Value>,
) -> (RootAdmission, Sha256Digest, Sha256Digest) {
    let root_digest = Sha256Digest::from_bytes(&root_source);
    let task_digest = Sha256Digest::from_bytes(TASK_COMPONENT);
    let executable_digest = Sha256Digest::from_bytes(task_executable);
    let constraint = constraints(max_component_fuel);
    let root_grant_values = root_grants(constraint.digest);
    let task_grants = task_grant_builder(constraint.digest);
    let configuration = artifact(b"canonical test composition configuration".to_vec());
    let wit_package = compiled_wit_package();
    let root_world = artifact(b"canonical test root world".to_vec());
    let task_world = artifact(b"canonical test task world".to_vec());
    let substrate_profile = artifact(canonical(&json!({
        "schema": "wasm-biotic.factory-substrate-profile.v1",
        "wit_package": "wasm-biotic:factory@0.1.0",
        "primitives": [
            "blob-store",
            "transaction-store",
            "clock",
            "component-runner",
            "http-transport",
            "key-service",
            "activation",
            "audit-log"
        ],
        "static_grant_model": "composed-root-graph-union",
        "root_node": "root",
        "root_grants": root_grant_values,
        "ceilings": serde_json::from_slice::<Value>(&constraint.bytes).unwrap(),
    })));

    let mut nodes = vec![json!({
        "id": "root",
        "kind": "root",
        "component_digest": root_digest,
        "world": ROOT_WORLD,
        "exports": [
            "wasm-biotic:factory/factory-api@0.1.0",
            "wasm-biotic:factory/factory-control@0.1.0"
        ],
        "grants": root_grants(constraint.digest),
    })];
    let mut bindings = vec![
        json!({
            "consumer": "root",
            "import": "wasm-biotic:factory/blob-store@0.1.0",
            "provider": {"kind": "host", "capability": "blob-store"},
        }),
        json!({
            "consumer": "root",
            "import": "wasm-biotic:factory/component-runner@0.1.0",
            "provider": {"kind": "host", "capability": "component-runner"},
        }),
    ];
    let mut invocations = Vec::new();
    let mut sources = vec![json!({
        "node_id": "root",
        "component_digest": root_digest,
        "world": ROOT_WORLD,
    })];
    let mut executables = vec![json!({
        "authority_node": "root",
        "authority_digest": root_digest,
        "executable_digest": Sha256Digest::from_bytes(ROOT_COMPONENT),
        "source_digests": [root_digest],
        "world": ROOT_WORLD,
        "configuration_digest": configuration.digest,
        "grants": root_grants(constraint.digest),
    })];
    let mut source_components = vec![AdmittedComponent {
        digest: root_digest,
        bytes: root_source,
    }];
    let mut execution_artifacts = Vec::new();
    let mut world_map = serde_json::Map::new();
    world_map.insert(ROOT_WORLD.to_string(), json!(root_world.digest));
    let mut world_artifacts = vec![root_world];
    if dynamic {
        nodes.push(json!({
            "id": "task",
            "kind": "admitted-tool",
            "component_digest": task_digest,
            "world": TASK_WORLD,
            "exports": ["wasm-biotic:factory/component-task@0.1.0"],
            "grants": task_grants.clone(),
        }));
        bindings.push(json!({
            "consumer": "task",
            "import": "wasm-biotic:factory/blob-store@0.1.0",
            "provider": {"kind": "host", "capability": "blob-store"},
        }));
        invocations.push(json!({
            "consumer": "root",
            "target": "task",
            "export": "wasm-biotic:factory/component-task@0.1.0",
        }));
        sources.push(json!({
            "node_id": "task",
            "component_digest": task_digest,
            "world": TASK_WORLD,
        }));
        executables.push(json!({
            "authority_node": "task",
            "authority_digest": task_digest,
            "executable_digest": executable_digest,
            "source_digests": [task_digest],
            "world": TASK_WORLD,
            "configuration_digest": configuration.digest,
            "grants": task_grants,
        }));
        source_components.push(AdmittedComponent {
            digest: task_digest,
            bytes: TASK_COMPONENT.to_vec(),
        });
        execution_artifacts.push(AdmittedComponent {
            digest: executable_digest,
            bytes: task_executable.to_vec(),
        });
        world_map.insert(TASK_WORLD.to_string(), json!(task_world.digest));
        world_artifacts.push(task_world);
    }
    let descriptor = artifact(canonical(&json!({
        "schema": "wasm-biotic.component-derivation-descriptor.v1",
        "wit_package_digest": wit_package.digest,
        "sources": sources,
        "executables": executables,
        "tool": {"name": "fixture-composer", "version": "1", "options": ["--exact"]},
    })));
    let metadata = artifact(canonical(&json!({
        "schema": "wasm-biotic.factory-graph-metadata.v1",
        "wit_package_digest": wit_package.digest,
        "wit_world_digests": Value::Object(world_map),
        "substrate_profile_digest": substrate_profile.digest,
        "derivation_descriptor_digest": descriptor.digest,
    })));
    let manifest_bytes = canonical(&json!({
        "schema": "wasm-biotic.factory-graph.v1",
        "wit_package": "wasm-biotic:factory@0.1.0",
        "root_node": "root",
        "state_schema": "test-state.v1",
        "nodes": nodes,
        "bindings": bindings,
        "invocations": invocations,
        "metadata": metadata.digest,
    }));
    let manifest_digest = Sha256Digest::from_bytes(&manifest_bytes);
    let mut admission = RootAdmission {
        manifest_bytes,
        manifest_digest,
        source_components,
        execution_artifacts,
        composed_root: AdmittedComponent {
            digest: Sha256Digest::from_bytes(ROOT_COMPONENT),
            bytes: ROOT_COMPONENT.to_vec(),
        },
        evidence: RootEvidence {
            certified_kernel_tcb_inventory: artifact(include_bytes!("../native-tcb.json").to_vec()),
            metadata,
            derivation_descriptor: descriptor,
            substrate_profile,
            wit_package,
            wit_worlds: world_artifacts,
            composition_configurations: vec![configuration],
            scoped_components: Vec::new(),
            constraints: vec![constraint],
            validation_report: artifact(Vec::new()),
            release_certification: artifact(Vec::new()),
        },
    };
    certify_admission(&mut admission);
    (admission, task_digest, executable_digest)
}

#[test]
fn admits_bound_evidence_and_invokes_composed_root_with_generated_host_layer() {
    let directory = TestDirectory::new();
    let (admission, _, _) = launch_admission(ROOT_COMPONENT.to_vec(), false);
    let manifest_digest = admission.manifest_digest;
    let manifest_bytes = admission.manifest_bytes.clone();
    let root_digest = admission.composed_root.digest;
    let mechanisms = LocalMechanisms::initialize(
        directory.path(),
        local_capacity(),
        manifest_digest,
        test_trust(),
    )
    .unwrap();
    let input = mechanisms
        .put_blob(
            "application/octet-stream".to_string(),
            b"root input".to_vec(),
        )
        .unwrap();
    let mut engine =
        OpaqueRootEngine::load(admission, mechanisms.clone(), ResourceLimits::default()).unwrap();
    assert!(matches!(
        engine.submit(&input),
        Err(wasm_biotic_kernel::KernelError::InvalidConfiguration(_))
    ));
    mechanisms
        .bootstrap_active_manifest(manifest_digest)
        .unwrap();
    let active = activation::Host::active_manifest(&mut mechanisms.clone())
        .unwrap()
        .unwrap();
    assert_eq!(active.content_digest.hex, digest_value(manifest_digest).hex);
    assert_eq!(mechanisms.get_blob(active).unwrap(), manifest_bytes);
    assert_eq!(engine.binding().manifest_digest, manifest_digest);
    assert_eq!(engine.binding().composed_root_digest, root_digest);
    assert_eq!(
        engine.submit(&input).unwrap().unwrap(),
        input.content_digest.hex
    );
    let inspected = engine.inspect("opaque-id").unwrap().unwrap();
    assert_eq!(mechanisms.get_blob(inspected).unwrap(), b"opaque-id");
    let response = engine
        .handle(&IngressRequest {
            request_id: "ingress-1".to_string(),
            method: "POST".to_string(),
            path: "/opaque/path".to_string(),
            headers: Vec::new(),
            body: Some(input),
        })
        .unwrap()
        .unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(
        mechanisms.get_blob(response.body.unwrap()).unwrap(),
        b"/opaque/path"
    );
}

#[test]
fn rejects_tampered_manifest_evidence_and_non_component_sources() {
    let directory = TestDirectory::new();
    let mechanisms = LocalMechanisms::open(directory.path(), local_capacity()).unwrap();
    let (mut admission, _, _) = launch_admission(ROOT_COMPONENT.to_vec(), false);
    admission.manifest_digest = Sha256Digest::from_bytes(b"different");
    assert!(matches!(
        OpaqueRootEngine::load(admission, mechanisms.clone(), ResourceLimits::default()),
        Err(wasm_biotic_kernel::KernelError::ManifestDigestMismatch { .. })
    ));

    let (mut admission, _, _) = launch_admission(ROOT_COMPONENT.to_vec(), false);
    admission.evidence.derivation_descriptor.bytes.push(b' ');
    assert!(
        OpaqueRootEngine::load(admission, mechanisms.clone(), ResourceLimits::default()).is_err()
    );

    let core = wat::parse_str("(module)").unwrap();
    let (admission, _, _) = launch_admission(core, false);
    assert!(matches!(
        OpaqueRootEngine::load(admission, mechanisms, ResourceLimits::default()),
        Err(wasm_biotic_kernel::KernelError::Compile { .. })
    ));

    let (admission, _, _) = launch_admission(ROOT_COMPONENT.to_vec(), false);
    let broad_directory = TestDirectory::new();
    let inadequate = LocalMechanisms::initialize(
        broad_directory.path(),
        local_capacity().with_max_component_fuel(20_000_000),
        admission.manifest_digest,
        test_trust(),
    )
    .unwrap();
    assert!(matches!(
        OpaqueRootEngine::load(admission, inadequate, ResourceLimits::default()),
        Err(wasm_biotic_kernel::KernelError::InvalidConfiguration(_))
    ));
}

#[test]
fn certification_rejects_report_tamper_wrong_key_omissions_and_manifest_substitution() {
    let directory = TestDirectory::new();
    let (base, _, _) = launch_admission(ROOT_COMPONENT.to_vec(), false);
    let mechanisms = LocalMechanisms::initialize(
        directory.path(),
        local_capacity(),
        base.manifest_digest,
        test_trust(),
    )
    .unwrap();

    let mut report_tamper = base.clone();
    report_tamper.evidence.validation_report.bytes.push(b' ');
    assert!(
        OpaqueRootEngine::load(report_tamper, mechanisms.clone(), ResourceLimits::default(),)
            .err()
            .expect("tampered validation report must fail")
            .to_string()
            .contains("strict validation report")
    );

    let wrong_key_directory = TestDirectory::new();
    let wrong_key = LocalMechanisms::initialize(
        wrong_key_directory.path(),
        local_capacity(),
        base.manifest_digest,
        fresh_trust(),
    )
    .unwrap();
    assert!(
        OpaqueRootEngine::load(base.clone(), wrong_key, ResourceLimits::default())
            .err()
            .expect("wrong certifier key must fail")
            .to_string()
            .contains("signer does not match operator trust")
    );

    let mut missing_raw = base.clone();
    missing_raw.source_components.pop();
    assert!(matches!(
        OpaqueRootEngine::load(missing_raw, mechanisms.clone(), ResourceLimits::default(),),
        Err(wasm_biotic_kernel::KernelError::MissingComponent(_))
    ));

    let mut missing_configuration = base.clone();
    missing_configuration
        .evidence
        .composition_configurations
        .clear();
    assert!(
        OpaqueRootEngine::load(
            missing_configuration,
            mechanisms.clone(),
            ResourceLimits::default(),
        )
        .err()
        .expect("missing composition configuration must fail")
        .to_string()
        .contains("composition configurations")
    );

    let mut missing_constraint = base.clone();
    missing_constraint.evidence.constraints.clear();
    assert!(
        OpaqueRootEngine::load(
            missing_constraint,
            mechanisms.clone(),
            ResourceLimits::default(),
        )
        .err()
        .expect("missing constraint must fail")
        .to_string()
        .contains("constraint artifacts")
    );

    let (substitute, _, _) = launch_admission(component_variant(b"certificate-substitute"), false);
    let mut manifest_substitution = base;
    manifest_substitution.evidence.release_certification =
        substitute.evidence.release_certification;
    assert!(
        OpaqueRootEngine::load(manifest_substitution, mechanisms, ResourceLimits::default(),)
            .err()
            .expect("manifest certificate substitution must fail")
            .to_string()
            .contains("does not exactly bind")
    );
}

#[test]
fn package_loader_requires_both_certification_artifacts() {
    let directory = TestDirectory::new();
    let package = directory.path().join("package");
    let (admission, _, _) = launch_admission(ROOT_COMPONENT.to_vec(), false);
    write_package(&package, &admission);
    fs::remove_file(package.join("certification/release-certification.json")).unwrap();
    assert!(RootAdmission::from_package_directory(&package).is_err());

    write_package(&package, &admission);
    fs::remove_file(package.join("evidence/strict-validation.json")).unwrap();
    assert!(RootAdmission::from_package_directory(&package).is_err());
}

#[test]
fn resolves_only_descriptor_bound_cache_and_preserves_raw_authority_identity() {
    let directory = TestDirectory::new();
    let config = local_capacity();
    let (admission, authority_digest, executable_digest) =
        launch_admission(ROOT_COMPONENT.to_vec(), true);
    let manifest_digest = admission.manifest_digest;
    let mechanisms = LocalMechanisms::initialize(
        directory.path(),
        config.clone(),
        manifest_digest,
        test_trust(),
    )
    .unwrap();
    let engine =
        OpaqueRootEngine::load(admission, mechanisms.clone(), ResourceLimits::default()).unwrap();
    let mut scoped = mechanisms.scoped_to_graph(manifest_digest).unwrap();
    let input = scoped
        .put_blob(
            "application/octet-stream".to_string(),
            b"derived input".to_vec(),
        )
        .unwrap();
    let request = component_runner::RunRequest {
        run_id: "derived-run".to_string(),
        component_digest: digest_value(authority_digest),
        input,
        grants: vec![
            foundation::CapabilityGrant {
                capability: "blob-store".to_string(),
                scope: "read-write".to_string(),
                constraints: None,
            },
            foundation::CapabilityGrant {
                capability: "transaction-store".to_string(),
                scope: "wasm-biotic.schedule.v1".to_string(),
                constraints: None,
            },
            foundation::CapabilityGrant {
                capability: "clock".to_string(),
                scope: "wake".to_string(),
                constraints: None,
            },
        ],
        limits: foundation::ResourceLimits {
            fuel: 1_000_000,
            memory_bytes: 8 * 1024 * 1024,
            output_bytes: 1024,
            wall_time_ms: 1_000,
        },
        idempotency_key: digest_value(Sha256Digest::from_bytes(b"derived-run-key")),
    };
    let operation = component_runner::Host::start(&mut scoped, request.clone()).unwrap();
    let completion = component_runner::Host::poll(&mut scoped, operation.clone())
        .unwrap()
        .unwrap();
    assert_eq!(
        completion.receipt.executor_digest.hex,
        digest_value(authority_digest).hex
    );
    let provenance = scoped.execution_provenance(&operation).unwrap().unwrap();
    assert_eq!(provenance.graph_manifest_digest, Some(manifest_digest));
    assert_eq!(provenance.authority_component_digest, authority_digest);
    assert_eq!(provenance.executable_component_digest, executable_digest);

    let mut overgrant = request.clone();
    overgrant.run_id = "overgrant".to_string();
    overgrant.grants.push(foundation::CapabilityGrant {
        capability: "key-service".to_string(),
        scope: "use".to_string(),
        constraints: None,
    });
    overgrant.idempotency_key = digest_value(Sha256Digest::from_bytes(b"overgrant-key"));
    assert_eq!(
        component_runner::Host::start(&mut scoped, overgrant)
            .unwrap_err()
            .code,
        "not-granted"
    );

    let substituted_constraint = scoped
        .put_blob("application/json".to_string(), b"{}".to_vec())
        .unwrap();
    let mut substitution = request.clone();
    substitution.run_id = "constraint-substitution".to_string();
    substitution.grants[0].constraints = Some(substituted_constraint);
    substitution.idempotency_key =
        digest_value(Sha256Digest::from_bytes(b"constraint-substitution-key"));
    assert_eq!(
        component_runner::Host::start(&mut scoped, substitution)
            .unwrap_err()
            .code,
        "not-granted"
    );

    let mut excessive_limits = request.clone();
    excessive_limits.run_id = "excessive-limits".to_string();
    excessive_limits.limits.fuel = 50_000_001;
    excessive_limits.idempotency_key =
        digest_value(Sha256Digest::from_bytes(b"excessive-limits-key"));
    assert_eq!(
        component_runner::Host::start(&mut scoped, excessive_limits)
            .unwrap_err()
            .code,
        "limit-exceeded"
    );

    let mut outside = request;
    outside.run_id = "outside-run".to_string();
    outside.component_digest = digest_value(Sha256Digest::from_bytes(b"outside graph"));
    outside.idempotency_key = digest_value(Sha256Digest::from_bytes(b"outside-run-key"));
    assert_eq!(
        component_runner::Host::start(&mut scoped, outside)
            .unwrap_err()
            .code,
        "not-admitted"
    );

    drop(scoped);
    drop(engine);
    drop(mechanisms);
    let reopened = LocalMechanisms::open(directory.path(), config).unwrap();
    let reopened = reopened.scoped_to_graph(manifest_digest).unwrap();
    assert_eq!(
        reopened
            .execution_provenance(&operation)
            .unwrap()
            .unwrap()
            .executable_component_digest,
        executable_digest
    );
}

#[test]
fn deterministic_package_loads_bootstraps_and_reboots_from_persistent_content() {
    let directory = TestDirectory::new();
    let package = directory.path().join("package");
    let state = directory.path().join("state");
    let (admission, _, _) = launch_admission(ROOT_COMPONENT.to_vec(), false);
    let expected_manifest = admission.manifest_digest;
    write_package(&package, &admission);

    let loaded = RootAdmission::from_package_directory(&package).unwrap();
    assert_eq!(loaded.manifest_digest, expected_manifest);
    let config = loaded.local_config_ceiling().unwrap();
    let mechanisms =
        LocalMechanisms::initialize(&state, config.clone(), expected_manifest, test_trust())
            .unwrap();
    assert!(matches!(
        LocalMechanisms::open(&state, config.clone().with_max_component_fuel(49_000_000),),
        Err(wasm_biotic_kernel::KernelError::InvalidConfiguration(_))
    ));
    let mut manager =
        OpaqueRootManager::bootstrap(loaded, mechanisms.clone(), ResourceLimits::default())
            .unwrap();
    assert_eq!(manager.binding().manifest_digest, expected_manifest);
    let response = manager
        .root()
        .handle(&IngressRequest {
            request_id: "package-ingress".to_string(),
            method: "POST".to_string(),
            path: "/package".to_string(),
            headers: Vec::new(),
            body: None,
        })
        .unwrap()
        .unwrap();
    assert_eq!(response.status, 200);
    drop(manager);
    drop(mechanisms);

    let reopened = LocalMechanisms::open_existing(&state).unwrap();
    let mut rebooted = OpaqueRootManager::boot(reopened, ResourceLimits::default()).unwrap();
    assert_eq!(rebooted.binding().manifest_digest, expected_manifest);
    assert_eq!(
        rebooted
            .root()
            .inspect("after-restart")
            .unwrap()
            .unwrap()
            .media_type,
        "application/octet-stream"
    );
}

#[test]
fn admitted_profile_v3_derives_its_local_config_ceiling() {
    let (mut admission, _, _) = launch_admission(ROOT_COMPONENT.to_vec(), false);
    let mut profile: Value =
        serde_json::from_slice(&admission.evidence.substrate_profile.bytes).unwrap();
    profile["schema"] = json!("wasm-biotic.factory-substrate-profile.v3");
    profile["http_transport"] = json!({
        "bindings": [{
            "alias": "wasm-biotic:factory/host-0000000000000000000000000000000000000000000000000000000000000000@0.1.0",
            "constraints": admission.evidence.constraints[0].digest,
            "consumer": "root"
        }],
        "mode": "bounded-external"
    });
    admission.evidence.substrate_profile = artifact(canonical(&profile));

    assert_eq!(admission.local_config_ceiling().unwrap(), local_capacity());
}

#[test]
fn initial_bootstrap_requires_exact_immutable_operator_trust() {
    let directory = TestDirectory::new();
    let (trusted, _, _) = launch_admission(component_variant(b"trusted-initial"), false);
    let trusted_digest = trusted.manifest_digest;
    let (different, _, _) = launch_admission(component_variant(b"different-initial"), false);
    let different_digest = different.manifest_digest;

    let no_trust_state = directory.path().join("no-trust");
    let no_trust = LocalMechanisms::open(&no_trust_state, local_capacity()).unwrap();
    let no_trust_error =
        OpaqueRootManager::bootstrap(trusted.clone(), no_trust, ResourceLimits::default())
            .err()
            .expect("bootstrap without operator trust must fail");
    assert!(no_trust_error.to_string().contains("no operator-trusted"));

    let state = directory.path().join("trusted");
    let mechanisms =
        LocalMechanisms::initialize(&state, local_capacity(), trusted_digest, test_trust())
            .unwrap();
    let state_document: Value =
        serde_json::from_slice(&fs::read(state.join("mechanisms.json")).unwrap()).unwrap();
    let certifier_fields = state_document["trusted_certifier"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        certifier_fields,
        BTreeSet::from(["key_id", "public_key_hex"]),
        "persistent certification trust must contain only the public key and its digest"
    );
    assert!(
        LocalMechanisms::initialize(&state, local_capacity(), different_digest, test_trust())
            .is_err(),
        "the bootstrap anchor must be immutable after initialization"
    );
    assert!(
        LocalMechanisms::initialize(&state, local_capacity(), trusted_digest, fresh_trust())
            .is_err(),
        "the public certifier anchor must be immutable after initialization"
    );
    let mismatch =
        OpaqueRootManager::bootstrap(different, mechanisms.clone(), ResourceLimits::default())
            .err()
            .expect("mismatched bootstrap manifest must fail");
    assert!(
        mismatch
            .to_string()
            .contains("does not match operator trust anchor")
    );

    let manager =
        OpaqueRootManager::bootstrap(trusted, mechanisms.clone(), ResourceLimits::default())
            .unwrap();
    assert_eq!(manager.binding().manifest_digest, trusted_digest);
    drop(manager);
    drop(mechanisms);

    let reopened = LocalMechanisms::open_existing(&state).unwrap();
    let rebooted = OpaqueRootManager::boot(reopened, ResourceLimits::default()).unwrap();
    assert_eq!(rebooted.binding().manifest_digest, trusted_digest);
}

#[test]
fn admitted_candidate_activation_reloads_and_failed_reload_restores_last_good() {
    let directory = TestDirectory::new();
    let config = local_capacity();
    let (first, _, _) = launch_admission(component_variant(b"first"), false);
    let first_digest = first.manifest_digest;
    let mechanisms =
        LocalMechanisms::initialize(directory.path(), config.clone(), first_digest, test_trust())
            .unwrap();
    let mut manager =
        OpaqueRootManager::bootstrap(first, mechanisms.clone(), ResourceLimits::default()).unwrap();

    let (second, _, _) = launch_admission(component_variant(b"second"), false);
    let second_digest = second.manifest_digest;
    let second_reference = manifest_reference(&second);
    drop(OpaqueRootEngine::load(second, mechanisms.clone(), ResourceLimits::default()).unwrap());
    let mut activation_host = mechanisms.clone();
    activation::Host::stage(
        &mut activation_host,
        activation::ActivationRequest {
            activation_id: "activate-second".to_string(),
            graph_manifest: second_reference,
            expected_active_graph: Some(digest_value(first_digest)),
            expected_active_state: None,
            state_migration: None,
            migrated_state: None,
            idempotency_key: digest_value(Sha256Digest::from_bytes(b"activate-second")),
        },
    )
    .unwrap();
    activation::Host::commit(&mut activation_host, "activate-second".to_string()).unwrap();
    assert!(manager.reload_if_changed().unwrap());
    assert_eq!(manager.binding().manifest_digest, second_digest);

    let (third, _, _) = launch_admission(component_variant(b"third"), false);
    let third_digest = third.manifest_digest;
    let third_reference = manifest_reference(&third);
    drop(OpaqueRootEngine::load(third, mechanisms.clone(), ResourceLimits::default()).unwrap());
    activation::Host::stage(
        &mut activation_host,
        activation::ActivationRequest {
            activation_id: "activate-third".to_string(),
            graph_manifest: third_reference,
            expected_active_graph: Some(digest_value(second_digest)),
            expected_active_state: None,
            state_migration: None,
            migrated_state: None,
            idempotency_key: digest_value(Sha256Digest::from_bytes(b"activate-third")),
        },
    )
    .unwrap();
    activation::Host::commit(&mut activation_host, "activate-third".to_string()).unwrap();
    fs::write(
        directory
            .path()
            .join("blobs")
            .join(digest_value(third_digest).hex),
        b"corrupt active manifest",
    )
    .unwrap();

    assert!(manager.reload_if_changed().is_err());
    assert_eq!(manager.binding().manifest_digest, second_digest);
    let active = activation::Host::active_manifest(&mut activation_host)
        .unwrap()
        .unwrap();
    assert_eq!(active.content_digest.hex, digest_value(second_digest).hex);
    drop(manager);
    drop(activation_host);
    drop(mechanisms);

    let reopened = LocalMechanisms::open_existing(directory.path()).unwrap();
    let rebooted = OpaqueRootManager::boot(reopened, ResourceLimits::default()).unwrap();
    assert_eq!(rebooted.binding().manifest_digest, second_digest);
}

#[test]
fn activation_atomically_switches_and_rolls_back_opaque_graph_state_pairs() {
    let directory = TestDirectory::new();
    let (first, _, _) = launch_admission(component_variant(b"stateful-first"), false);
    let first_digest = first.manifest_digest;
    let first_reference = manifest_reference(&first);
    let migration_digest = first.source_components[0].digest;
    let mechanisms = LocalMechanisms::initialize(
        directory.path(),
        local_capacity(),
        first_digest,
        test_trust(),
    )
    .unwrap();
    let _manager =
        OpaqueRootManager::bootstrap(first, mechanisms.clone(), ResourceLimits::default()).unwrap();
    let old_state = mechanisms
        .put_blob(
            "application/json".to_string(),
            br#"{"state":"old"}"#.to_vec(),
        )
        .unwrap();
    let new_state = mechanisms
        .put_blob(
            "application/json".to_string(),
            br#"{"state":"new"}"#.to_vec(),
        )
        .unwrap();
    let stale_state = mechanisms
        .put_blob(
            "application/json".to_string(),
            br#"{"state":"stale"}"#.to_vec(),
        )
        .unwrap();
    let mut activation_host = mechanisms.clone();

    activation::Host::stage(
        &mut activation_host,
        activation::ActivationRequest {
            activation_id: "initialize-opaque-state".to_string(),
            graph_manifest: first_reference,
            expected_active_graph: Some(digest_value(first_digest)),
            expected_active_state: None,
            state_migration: Some(digest_value(migration_digest)),
            migrated_state: Some(old_state.clone()),
            idempotency_key: digest_value(Sha256Digest::from_bytes(b"initialize-opaque-state")),
        },
    )
    .unwrap();
    let initialized =
        activation::Host::commit(&mut activation_host, "initialize-opaque-state".to_string())
            .unwrap();
    assert_eq!(
        initialized
            .active_state
            .as_ref()
            .unwrap()
            .content_digest
            .hex,
        old_state.content_digest.hex
    );

    let (second, _, _) = launch_admission(component_variant(b"stateful-second"), false);
    let second_digest = second.manifest_digest;
    let second_reference = manifest_reference(&second);
    drop(OpaqueRootEngine::load(second, mechanisms.clone(), ResourceLimits::default()).unwrap());

    let partial = activation::Host::stage(
        &mut activation_host,
        activation::ActivationRequest {
            activation_id: "partial-migration".to_string(),
            graph_manifest: second_reference.clone(),
            expected_active_graph: Some(digest_value(first_digest)),
            expected_active_state: Some(old_state.clone()),
            state_migration: Some(digest_value(migration_digest)),
            migrated_state: None,
            idempotency_key: digest_value(Sha256Digest::from_bytes(b"partial-migration")),
        },
    )
    .unwrap_err();
    assert_eq!(partial.code, "incomplete-migration-binding");
    let stale = activation::Host::stage(
        &mut activation_host,
        activation::ActivationRequest {
            activation_id: "stale-state".to_string(),
            graph_manifest: second_reference.clone(),
            expected_active_graph: Some(digest_value(first_digest)),
            expected_active_state: Some(stale_state),
            state_migration: Some(digest_value(migration_digest)),
            migrated_state: Some(new_state.clone()),
            idempotency_key: digest_value(Sha256Digest::from_bytes(b"stale-state")),
        },
    )
    .unwrap_err();
    assert_eq!(stale.code, "conflict");

    let staged = activation::Host::stage(
        &mut activation_host,
        activation::ActivationRequest {
            activation_id: "switch-opaque-state".to_string(),
            graph_manifest: second_reference,
            expected_active_graph: Some(digest_value(first_digest)),
            expected_active_state: Some(old_state.clone()),
            state_migration: Some(digest_value(migration_digest)),
            migrated_state: Some(new_state.clone()),
            idempotency_key: digest_value(Sha256Digest::from_bytes(b"switch-opaque-state")),
        },
    )
    .unwrap();
    assert_eq!(
        staged.active_graph.unwrap().hex,
        digest_value(second_digest).hex
    );
    assert_eq!(
        staged.active_state.unwrap().content_digest.hex,
        new_state.content_digest.hex
    );
    let committed =
        activation::Host::commit(&mut activation_host, "switch-opaque-state".to_string()).unwrap();
    assert_eq!(
        committed.active_graph.unwrap().hex,
        digest_value(second_digest).hex
    );
    assert_eq!(
        activation::Host::active_state(&mut activation_host)
            .unwrap()
            .unwrap()
            .content_digest
            .hex,
        new_state.content_digest.hex
    );

    let rolled_back = activation::Host::rollback(
        &mut activation_host,
        "switch-opaque-state".to_string(),
        digest_value(first_digest),
    )
    .unwrap();
    assert!(matches!(
        rolled_back.state,
        activation::ActivationState::RolledBack
    ));
    assert_eq!(
        rolled_back.active_graph.unwrap().hex,
        digest_value(first_digest).hex
    );
    assert_eq!(
        rolled_back.active_state.unwrap().content_digest.hex,
        old_state.content_digest.hex
    );
}

#[test]
fn lower_ceiling_successor_reloads_with_the_narrower_effective_limit() {
    let directory = TestDirectory::new();
    let (first, _, _) = launch_admission(component_variant(b"wide"), false);
    let first_digest = first.manifest_digest;
    let mechanisms = LocalMechanisms::initialize(
        directory.path(),
        local_capacity(),
        first_digest,
        test_trust(),
    )
    .unwrap();
    let operator_capacity = mechanisms.root_runtime_capacity();
    assert_eq!(operator_capacity.fuel, 50_000_000);
    let mut manager =
        OpaqueRootManager::bootstrap(first, mechanisms.clone(), operator_capacity.clone()).unwrap();

    let (narrow, _, _) = launch_admission_with_fuel(component_variant(b"narrow"), false, 2_000_000);
    let narrow_digest = narrow.manifest_digest;
    let narrow_reference = manifest_reference(&narrow);
    assert!(matches!(
        OpaqueRootEngine::load(
            narrow.clone(),
            mechanisms.clone(),
            operator_capacity.clone(),
        ),
        Err(wasm_biotic_kernel::KernelError::InvalidConfiguration(_))
    ));
    let bounded = narrow.bounded_root_limits(&operator_capacity).unwrap();
    assert_eq!(bounded.fuel, 2_000_000);
    drop(OpaqueRootEngine::load(narrow, mechanisms.clone(), bounded).unwrap());

    let mut activation_host = mechanisms.clone();
    activation::Host::stage(
        &mut activation_host,
        activation::ActivationRequest {
            activation_id: "activate-narrow".to_string(),
            graph_manifest: narrow_reference,
            expected_active_graph: Some(digest_value(first_digest)),
            expected_active_state: None,
            state_migration: None,
            migrated_state: None,
            idempotency_key: digest_value(Sha256Digest::from_bytes(b"activate-narrow")),
        },
    )
    .unwrap();
    activation::Host::commit(&mut activation_host, "activate-narrow".to_string()).unwrap();
    assert!(manager.reload_if_changed().unwrap());
    assert_eq!(manager.binding().manifest_digest, narrow_digest);
    assert_eq!(manager.root().resource_limits().fuel, 2_000_000);
}

#[test]
fn active_graph_scope_rejects_globally_admitted_unlisted_run_and_wake_targets() {
    let directory = TestDirectory::new();
    let (admission, _, _) = launch_admission_with_adversarial_task(ROOT_COMPONENT.to_vec());
    let manifest_digest = admission.manifest_digest;
    let mechanisms = LocalMechanisms::initialize(
        directory.path(),
        local_capacity(),
        manifest_digest,
        test_trust(),
    )
    .unwrap();
    let _engine =
        OpaqueRootEngine::load(admission, mechanisms.clone(), ResourceLimits::default()).unwrap();
    mechanisms
        .bootstrap_active_manifest(manifest_digest)
        .unwrap();

    let outside_digest = Sha256Digest::from_bytes(MECHANISM_TASK_COMPONENT);
    mechanisms
        .admit_component(outside_digest, MECHANISM_TASK_COMPONENT)
        .unwrap();
    let mut scoped = mechanisms.scoped_to_graph(manifest_digest).unwrap();
    let input = scoped
        .put_blob(
            "application/octet-stream".to_string(),
            b"active-graph-scope".to_vec(),
        )
        .unwrap();

    let wake_error = clock::Host::schedule_wake(
        &mut scoped,
        clock::WakeRequest {
            wake_id: "outside-active-graph".to_string(),
            not_before_ms: 1,
            target_component: digest_value(outside_digest),
            payload_digest: input.content_digest.clone(),
            idempotency_key: digest_value(Sha256Digest::from_bytes(b"outside-wake")),
        },
    )
    .unwrap_err();
    assert_eq!(wake_error.code, "not-admitted");
    assert!(
        clock::Host::poll_wake(&mut scoped, "outside-active-graph".to_string())
            .unwrap()
            .is_none()
    );

    let run_error = component_runner::Host::start(
        &mut scoped,
        component_runner::RunRequest {
            run_id: "outside-active-graph".to_string(),
            component_digest: digest_value(outside_digest),
            input,
            grants: Vec::new(),
            limits: foundation::ResourceLimits {
                fuel: 1_000_000,
                memory_bytes: 8 * 1024 * 1024,
                output_bytes: 1024,
                wall_time_ms: 1_000,
            },
            idempotency_key: digest_value(Sha256Digest::from_bytes(b"outside-run")),
        },
    )
    .unwrap_err();
    assert_eq!(run_error.code, "not-admitted");
}

#[test]
fn activation_rejects_stale_expected_digest_without_state_change() {
    let directory = TestDirectory::new();
    let (admission, task_authority, task_executable) =
        launch_admission_with_adversarial_task(ROOT_COMPONENT.to_vec());
    assert_eq!(
        task_executable,
        Sha256Digest::from_bytes(ADVERSARIAL_TASK_COMPONENT)
    );
    let manifest_digest = admission.manifest_digest;
    let mechanisms = LocalMechanisms::initialize(
        directory.path(),
        local_capacity(),
        manifest_digest,
        test_trust(),
    )
    .unwrap();
    let _engine =
        OpaqueRootEngine::load(admission, mechanisms.clone(), ResourceLimits::default()).unwrap();
    mechanisms
        .bootstrap_active_manifest(manifest_digest)
        .unwrap();
    let mut scoped = mechanisms.scoped_to_graph(manifest_digest).unwrap();
    let active_before = activation::Host::active_manifest(&mut scoped)
        .unwrap()
        .unwrap();
    let active_bytes_before = scoped.get_blob(active_before.clone()).unwrap();
    let input = scoped
        .put_blob("application/octet-stream".to_string(), b"A".to_vec())
        .unwrap();
    let request = component_runner::RunRequest {
        run_id: "activation-stale-expected".to_string(),
        component_digest: digest_value(task_authority),
        input,
        grants: vec![
            foundation::CapabilityGrant {
                capability: "blob-store".to_string(),
                scope: "read-write".to_string(),
                constraints: None,
            },
            foundation::CapabilityGrant {
                capability: "activation".to_string(),
                scope: "switch".to_string(),
                constraints: None,
            },
        ],
        limits: foundation::ResourceLimits {
            fuel: 5_000_000,
            memory_bytes: 8 * 1024 * 1024,
            output_bytes: 1024,
            wall_time_ms: 1_000,
        },
        idempotency_key: digest_value(Sha256Digest::from_bytes(b"activation-stale-run")),
    };
    let operation = component_runner::Host::start(&mut scoped, request.clone()).unwrap();
    let completion = component_runner::Host::poll(&mut scoped, operation.clone())
        .unwrap()
        .unwrap();
    assert!(matches!(
        completion.outcome,
        foundation::TerminalOutcome::Rejected(ref failure) if failure.code == "conflict"
    ));
    assert_eq!(
        completion.receipt.executor_digest.hex,
        digest_value(task_authority).hex
    );
    assert_eq!(
        completion.receipt.request_digest.hex,
        digest_value(Sha256Digest::from_bytes(
            &serde_json::to_vec(&request).unwrap()
        ))
        .hex
    );
    assert_eq!(
        completion.receipt.outcome_digest.hex,
        digest_value(Sha256Digest::from_bytes(
            &serde_json::to_vec(&completion.outcome).unwrap()
        ))
        .hex
    );
    assert!(completion.receipt.started_at_ms <= completion.receipt.finished_at_ms);
    let provenance = scoped.execution_provenance(&operation).unwrap().unwrap();
    assert_eq!(provenance.authority_component_digest, task_authority);
    assert_eq!(provenance.executable_component_digest, task_executable);

    let active_after = activation::Host::active_manifest(&mut scoped)
        .unwrap()
        .unwrap();
    assert_eq!(
        active_after.content_digest.hex,
        active_before.content_digest.hex
    );
    assert_eq!(scoped.get_blob(active_after).unwrap(), active_bytes_before);
    assert_eq!(
        activation::Host::status(&mut scoped, "adversarial-stale-expected".to_string())
            .unwrap_err()
            .code,
        "not-found"
    );
}
