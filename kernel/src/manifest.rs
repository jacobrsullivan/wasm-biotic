use crate::{HostInterface, KernelError, Sha256Digest};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Schema identifier for the first policy-neutral graph manifest.
pub const MANIFEST_SCHEMA_V1: &str = "wasm-biotic.kernel-graph.v1";

/// Typed call ABI implemented by the first executable graph slice.
pub const ABI_S32_PAIR_TO_S32_V1: &str = "s32-pair-to-s32@1";

/// One component selected by exact digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentNode {
    /// Opaque graph-local identifier.
    pub id: String,
    /// Digest of the exact Component Model binary.
    pub component_digest: Sha256Digest,
    /// Single exported function used by this ABI slice.
    pub export: String,
}

/// Exact graph entry point.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntryPoint {
    /// Opaque graph-local node identifier.
    pub node: String,
    /// Exported typed function name.
    pub export: String,
}

/// A typed component-to-component import binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeBinding {
    /// Importing node identifier.
    pub consumer: String,
    /// Imported function name.
    pub import: String,
    /// Target node identifier.
    pub target: String,
    /// Target function export.
    pub target_export: String,
}

/// A declared native-boundary binding.
///
/// The closed enum prevents unrecognized native imports from entering a
/// manifest. This first runtime slice intentionally does not implement these
/// bindings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostBinding {
    /// Importing node identifier.
    pub consumer: String,
    /// Imported interface name at that node.
    pub import: String,
    /// Closed native-boundary interface identifier.
    pub interface: HostInterface,
}

/// Versioned, content-addressed component graph declaration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphManifest {
    /// Exact manifest schema identifier.
    pub schema: String,
    /// Exact typed ABI identifier.
    pub abi: String,
    /// Root call target.
    pub entry: EntryPoint,
    /// Dependency-first component nodes.
    pub ordered_nodes: Vec<ComponentNode>,
    /// Typed component-to-component calls.
    #[serde(default)]
    pub edges: Vec<EdgeBinding>,
    /// Explicit native-boundary declarations.
    #[serde(default)]
    pub host_bindings: Vec<HostBinding>,
}

/// Exact Component Model binary bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComponentBlob {
    bytes: Vec<u8>,
}

impl ComponentBlob {
    /// Wraps exact binary bytes without interpreting them.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Returns the exact bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Computes the SHA-256 digest of the exact bytes.
    #[must_use]
    pub fn digest(&self) -> Sha256Digest {
        Sha256Digest::from_bytes(&self.bytes)
    }
}

/// A verified manifest and its exact admitted component bytes.
#[derive(Clone, Debug)]
pub struct GraphPackage {
    manifest: GraphManifest,
    manifest_digest: Sha256Digest,
    components: BTreeMap<Sha256Digest, ComponentBlob>,
}

impl GraphPackage {
    /// Serializes a programmatically constructed manifest, binds its digest,
    /// and performs the same validation as [`Self::load`].
    pub fn assemble(
        manifest: GraphManifest,
        components: BTreeMap<Sha256Digest, ComponentBlob>,
    ) -> Result<Self, KernelError> {
        let bytes = serde_json::to_vec(&manifest)
            .map_err(|error| KernelError::ManifestDecode(error.to_string()))?;
        let digest = Sha256Digest::from_bytes(&bytes);
        Self::load(&bytes, digest, components)
    }

    /// Loads exact manifest bytes, verifies their expected digest, and verifies
    /// every listed component byte digest.
    pub fn load(
        manifest_bytes: &[u8],
        expected_manifest_digest: Sha256Digest,
        components: BTreeMap<Sha256Digest, ComponentBlob>,
    ) -> Result<Self, KernelError> {
        let actual_manifest_digest = Sha256Digest::from_bytes(manifest_bytes);
        if actual_manifest_digest != expected_manifest_digest {
            return Err(KernelError::ManifestDigestMismatch {
                expected: expected_manifest_digest,
                actual: actual_manifest_digest,
            });
        }
        let manifest: GraphManifest = serde_json::from_slice(manifest_bytes)
            .map_err(|error| KernelError::ManifestDecode(error.to_string()))?;
        validate_manifest(&manifest, &components)?;
        Ok(Self {
            manifest,
            manifest_digest: actual_manifest_digest,
            components,
        })
    }

    /// Returns the verified graph declaration.
    #[must_use]
    pub fn manifest(&self) -> &GraphManifest {
        &self.manifest
    }

    /// Returns the digest of the exact manifest bytes supplied to [`Self::load`].
    #[must_use]
    pub const fn manifest_digest(&self) -> Sha256Digest {
        self.manifest_digest
    }

    pub(crate) fn component(&self, digest: &Sha256Digest) -> &ComponentBlob {
        self.components
            .get(digest)
            .expect("verified package retains every declared component")
    }
}

fn validate_manifest(
    manifest: &GraphManifest,
    components: &BTreeMap<Sha256Digest, ComponentBlob>,
) -> Result<(), KernelError> {
    if manifest.schema != MANIFEST_SCHEMA_V1 {
        return Err(KernelError::UnsupportedSchema(manifest.schema.clone()));
    }
    if manifest.abi != ABI_S32_PAIR_TO_S32_V1 {
        return Err(KernelError::UnsupportedAbi(manifest.abi.clone()));
    }
    if manifest.ordered_nodes.is_empty() {
        return Err(KernelError::EmptyGraph);
    }

    let mut positions = BTreeMap::new();
    let mut admitted_digests = BTreeSet::new();
    for (position, node) in manifest.ordered_nodes.iter().enumerate() {
        require_identifier(&node.id, "node identifier")?;
        require_identifier(&node.export, "node export")?;
        if positions.insert(node.id.clone(), position).is_some() {
            return Err(KernelError::DuplicateNode(node.id.clone()));
        }
        let bytes = components
            .get(&node.component_digest)
            .ok_or(KernelError::MissingComponent(node.component_digest))?;
        let actual = bytes.digest();
        if actual != node.component_digest {
            return Err(KernelError::ComponentDigestMismatch {
                node: node.id.clone(),
                expected: node.component_digest,
                actual,
            });
        }
        admitted_digests.insert(node.component_digest);
    }
    if let Some(extra) = components
        .keys()
        .find(|digest| !admitted_digests.contains(digest))
    {
        return Err(KernelError::UnlistedComponent(*extra));
    }

    require_identifier(&manifest.entry.node, "entry node")?;
    require_identifier(&manifest.entry.export, "entry export")?;
    let Some(entry_node) = manifest
        .ordered_nodes
        .iter()
        .find(|node| node.id == manifest.entry.node)
    else {
        return Err(KernelError::InvalidEntryPoint);
    };
    if entry_node.export != manifest.entry.export {
        return Err(KernelError::InvalidEntryPoint);
    }

    let mut bound_imports = BTreeSet::new();
    for edge in &manifest.edges {
        validate_import_fields(&edge.consumer, &edge.import, &mut bound_imports)?;
        require_identifier(&edge.target, "target node")?;
        require_identifier(&edge.target_export, "target export")?;
        let consumer_position = positions
            .get(&edge.consumer)
            .ok_or_else(|| KernelError::UnknownNode(edge.consumer.clone()))?;
        let target_position = positions
            .get(&edge.target)
            .ok_or_else(|| KernelError::UnknownNode(edge.target.clone()))?;
        if target_position >= consumer_position {
            return Err(KernelError::DependencyOrder {
                consumer: edge.consumer.clone(),
                target: edge.target.clone(),
            });
        }
        let target = &manifest.ordered_nodes[*target_position];
        if target.export != edge.target_export {
            return Err(KernelError::UnknownExport {
                node: edge.target.clone(),
                export: edge.target_export.clone(),
            });
        }
    }
    for binding in &manifest.host_bindings {
        validate_import_fields(&binding.consumer, &binding.import, &mut bound_imports)?;
        if !positions.contains_key(&binding.consumer) {
            return Err(KernelError::UnknownNode(binding.consumer.clone()));
        }
        let _closed_identifier = binding.interface;
    }
    Ok(())
}

fn validate_import_fields(
    node: &str,
    import: &str,
    bound_imports: &mut BTreeSet<(String, String)>,
) -> Result<(), KernelError> {
    require_identifier(node, "consumer node")?;
    require_identifier(import, "import name")?;
    if !bound_imports.insert((node.to_string(), import.to_string())) {
        return Err(KernelError::DuplicateImport {
            node: node.to_string(),
            import: import.to_string(),
        });
    }
    Ok(())
}

fn require_identifier(value: &str, kind: &'static str) -> Result<(), KernelError> {
    if value.trim().is_empty() {
        Err(KernelError::EmptyIdentifier(kind))
    } else {
        Ok(())
    }
}
