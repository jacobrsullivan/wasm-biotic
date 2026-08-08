use std::collections::BTreeMap;

use wasm_biotic_kernel::{
    ABI_S32_PAIR_TO_S32_V1, ComponentBlob, ComponentNode, EdgeBinding, EntryPoint, ExecutionInput,
    GraphManifest, GraphPackage, GraphRuntime, HostBinding, HostInterface, KernelError,
    MANIFEST_SCHEMA_V1, ResourceLimits, Sha256Digest,
};

const LEAF_INCLUSIVE: &str =
    include_str!("../../artifacts/fixtures/component-factory/service-inclusive.wat");
const LEAF_STRICT: &str =
    include_str!("../../artifacts/fixtures/component-factory/service-strict.wat");
const MIDDLE_INCREMENT_1: &str =
    include_str!("../../artifacts/fixtures/component-factory/worker-increment-1.wat");
const MIDDLE_INCREMENT_2: &str =
    include_str!("../../artifacts/fixtures/component-factory/worker-increment-2.wat");
const ROOT_BONUS_100: &str =
    include_str!("../../artifacts/fixtures/component-factory/supervisor-bonus-100.wat");
const ROOT_BONUS_200: &str =
    include_str!("../../artifacts/fixtures/component-factory/supervisor-bonus-200.wat");
const ROOT_SPIN: &str =
    include_str!("../../artifacts/fixtures/component-factory/supervisor-spin.wat");

struct FixturePackage {
    manifest: GraphManifest,
    components: BTreeMap<Sha256Digest, ComponentBlob>,
}

fn parse_component(source: &str) -> ComponentBlob {
    ComponentBlob::new(wat::parse_str(source).expect("fixture must parse"))
}

fn fixture_package(leaf: &str, middle: &str, root: &str) -> FixturePackage {
    let parts = [
        ("leaf", parse_component(leaf)),
        ("middle", parse_component(middle)),
        ("root", parse_component(root)),
    ];
    let nodes = parts
        .iter()
        .map(|(id, bytes)| ComponentNode {
            id: (*id).to_string(),
            component_digest: bytes.digest(),
            export: "invoke".to_string(),
        })
        .collect();
    let components = parts
        .into_iter()
        .map(|(_, bytes)| (bytes.digest(), bytes))
        .collect();
    FixturePackage {
        manifest: GraphManifest {
            schema: MANIFEST_SCHEMA_V1.to_string(),
            abi: ABI_S32_PAIR_TO_S32_V1.to_string(),
            entry: EntryPoint {
                node: "root".to_string(),
                export: "invoke".to_string(),
            },
            ordered_nodes: nodes,
            edges: vec![
                EdgeBinding {
                    consumer: "middle".to_string(),
                    import: "downstream".to_string(),
                    target: "leaf".to_string(),
                    target_export: "invoke".to_string(),
                },
                EdgeBinding {
                    consumer: "root".to_string(),
                    import: "downstream".to_string(),
                    target: "middle".to_string(),
                    target_export: "invoke".to_string(),
                },
            ],
            host_bindings: Vec::new(),
        },
        components,
    }
}

fn execute(leaf: &str, middle: &str, root: &str) -> wasm_biotic_kernel::ExecutionTrace {
    let fixture = fixture_package(leaf, middle, root);
    let package = GraphPackage::assemble(fixture.manifest, fixture.components).unwrap();
    GraphRuntime::new(package, ResourceLimits::default())
        .unwrap()
        .execute(ExecutionInput {
            first: 4,
            second: 5,
        })
        .unwrap()
}

#[test]
fn executes_exact_manifest_edges_between_typed_components() {
    let trace = execute(LEAF_INCLUSIVE, MIDDLE_INCREMENT_1, ROOT_BONUS_100);

    assert_eq!(trace.output, 115);
    assert_eq!(trace.node_calls.len(), 3);
    assert_eq!(
        trace
            .node_calls
            .iter()
            .map(|call| (call.node.as_str(), call.output))
            .collect::<Vec<_>>(),
        vec![("leaf", 5), ("middle", 15), ("root", 115)]
    );
    assert_eq!(trace.edge_calls.len(), 2);
    assert_eq!(trace.edge_calls[0].consumer, "root");
    assert_eq!(trace.edge_calls[0].target, "middle");
    assert_eq!(trace.edge_calls[0].input, trace.input);
    assert_eq!(trace.edge_calls[0].output, 15);
    assert_eq!(trace.edge_calls[1].consumer, "middle");
    assert_eq!(trace.edge_calls[1].target, "leaf");
    assert_eq!(
        trace.edge_calls[1].input,
        ExecutionInput {
            first: 5,
            second: 5,
        }
    );
    assert_eq!(trace.edge_calls[1].output, 5);
}

#[test]
fn changing_only_component_bytes_changes_behavior_and_content_binding() {
    let baseline = execute(LEAF_INCLUSIVE, MIDDLE_INCREMENT_1, ROOT_BONUS_100);
    let strict = execute(LEAF_STRICT, MIDDLE_INCREMENT_1, ROOT_BONUS_100);
    let incremented = execute(LEAF_INCLUSIVE, MIDDLE_INCREMENT_2, ROOT_BONUS_100);
    let larger_bonus = execute(LEAF_INCLUSIVE, MIDDLE_INCREMENT_1, ROOT_BONUS_200);

    assert_eq!(baseline.output, 115);
    assert_eq!(strict.output, -1);
    assert_eq!(incremented.output, 116);
    assert_eq!(larger_bonus.output, 215);
    assert_only_digest_changed(&baseline, &strict, "leaf");
    assert_only_digest_changed(&baseline, &incremented, "middle");
    assert_only_digest_changed(&baseline, &larger_bonus, "root");
    for variant in [&strict, &incremented, &larger_bonus] {
        assert_ne!(
            variant.binding.manifest_digest,
            baseline.binding.manifest_digest
        );
    }
}

#[test]
fn applies_uniform_store_and_fuel_limits() {
    let fixture = fixture_package(LEAF_INCLUSIVE, MIDDLE_INCREMENT_1, ROOT_BONUS_100);
    let package = GraphPackage::assemble(fixture.manifest, fixture.components).unwrap();
    let limits = ResourceLimits {
        fuel: 20_000,
        ..ResourceLimits::default()
    };
    let trace = GraphRuntime::new(package, limits.clone())
        .unwrap()
        .execute(ExecutionInput {
            first: 4,
            second: 5,
        })
        .unwrap();
    assert!(
        trace
            .node_calls
            .iter()
            .all(|call| call.limits == limits && call.fuel_consumed <= limits.fuel)
    );

    let spinning = fixture_package(LEAF_INCLUSIVE, MIDDLE_INCREMENT_1, ROOT_SPIN);
    let package = GraphPackage::assemble(spinning.manifest, spinning.components).unwrap();
    let error = GraphRuntime::new(package, limits)
        .unwrap()
        .execute(ExecutionInput {
            first: 4,
            second: 5,
        })
        .unwrap_err();
    assert!(matches!(
        error,
        KernelError::Invoke {
            node,
            fuel_exhausted: true,
            ..
        } if node == "root"
    ));
}

#[test]
fn rejects_manifest_and_component_digest_tampering() {
    let fixture = fixture_package(LEAF_INCLUSIVE, MIDDLE_INCREMENT_1, ROOT_BONUS_100);
    let bytes = serde_json::to_vec(&fixture.manifest).unwrap();
    let wrong_manifest_digest = Sha256Digest::from_bytes(b"different manifest");
    assert!(matches!(
        GraphPackage::load(&bytes, wrong_manifest_digest, fixture.components),
        Err(KernelError::ManifestDigestMismatch { .. })
    ));

    let mut fixture = fixture_package(LEAF_INCLUSIVE, MIDDLE_INCREMENT_1, ROOT_BONUS_100);
    let declared = fixture.manifest.ordered_nodes[0].component_digest;
    fixture.components.insert(
        declared,
        ComponentBlob::new(wat::parse_str(LEAF_STRICT).unwrap()),
    );
    assert!(matches!(
        GraphPackage::assemble(fixture.manifest, fixture.components),
        Err(KernelError::ComponentDigestMismatch { node, .. }) if node == "leaf"
    ));
}

#[test]
fn rejects_unlisted_or_non_component_bytes_and_unbound_imports() {
    let mut fixture = fixture_package(LEAF_INCLUSIVE, MIDDLE_INCREMENT_1, ROOT_BONUS_100);
    let extra = ComponentBlob::new(wat::parse_str(LEAF_STRICT).unwrap());
    fixture.components.insert(extra.digest(), extra);
    assert!(matches!(
        GraphPackage::assemble(fixture.manifest, fixture.components),
        Err(KernelError::UnlistedComponent(_))
    ));

    let mut fixture = fixture_package(LEAF_INCLUSIVE, MIDDLE_INCREMENT_1, ROOT_BONUS_100);
    let core_module = ComponentBlob::new(wat::parse_str("(module)").unwrap());
    let previous_leaf_digest = fixture.manifest.ordered_nodes[0].component_digest;
    fixture.manifest.ordered_nodes[0].component_digest = core_module.digest();
    fixture.components.remove(&previous_leaf_digest);
    fixture.components.insert(core_module.digest(), core_module);
    let package = GraphPackage::assemble(fixture.manifest, fixture.components).unwrap();
    assert!(matches!(
        GraphRuntime::new(package, ResourceLimits::default()),
        Err(KernelError::Compile { node, .. }) if node == "leaf"
    ));

    let mut fixture = fixture_package(LEAF_INCLUSIVE, MIDDLE_INCREMENT_1, ROOT_BONUS_100);
    fixture
        .manifest
        .edges
        .retain(|edge| edge.consumer != "middle");
    let package = GraphPackage::assemble(fixture.manifest, fixture.components).unwrap();
    assert!(matches!(
        GraphRuntime::new(package, ResourceLimits::default()),
        Err(KernelError::Instantiate { node, .. }) if node == "middle"
    ));
}

#[test]
fn accepts_only_the_closed_native_interface_vocabulary() {
    let expected = [
        "activation",
        "audit-log",
        "blob-store",
        "clock",
        "component-runner",
        "http-transport",
        "key-service",
        "transaction-store",
    ];
    assert_eq!(wasm_biotic_kernel::HOST_INTERFACE_ALLOWLIST, expected);
    assert_eq!(
        HostInterface::ALL.map(HostInterface::as_str),
        wasm_biotic_kernel::HOST_INTERFACE_ALLOWLIST
    );
    for name in expected {
        let parsed: HostInterface = serde_json::from_str(&format!("\"{name}\"")).unwrap();
        assert_eq!(parsed.as_str(), name);
    }
    assert!(serde_json::from_str::<HostInterface>("\"process-runner\"").is_err());
    assert!(serde_json::from_str::<HostInterface>("\"native-shell\"").is_err());

    let mut fixture = fixture_package(LEAF_INCLUSIVE, MIDDLE_INCREMENT_1, ROOT_BONUS_100);
    fixture.manifest.host_bindings.push(HostBinding {
        consumer: "root".to_string(),
        import: "bytes".to_string(),
        interface: HostInterface::BlobStore,
    });
    let package = GraphPackage::assemble(fixture.manifest, fixture.components).unwrap();
    assert!(matches!(
        GraphRuntime::new(package, ResourceLimits::default()),
        Err(KernelError::HostInterfacesUnavailable)
    ));
}

fn assert_only_digest_changed(
    baseline: &wasm_biotic_kernel::ExecutionTrace,
    variant: &wasm_biotic_kernel::ExecutionTrace,
    changed_node: &str,
) {
    for (node, baseline_digest) in &baseline.binding.component_digests {
        let variant_digest = variant.binding.component_digests.get(node).unwrap();
        if node == changed_node {
            assert_ne!(variant_digest, baseline_digest);
        } else {
            assert_eq!(variant_digest, baseline_digest);
        }
    }
}
