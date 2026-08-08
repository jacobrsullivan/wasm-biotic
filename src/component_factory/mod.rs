//! Executable proof of a component-complete factory graph.
//!
//! Domain behavior is supplied by typed Wasm components. The native substrate
//! validates a content-bound graph manifest, instantiates each declared node
//! under identical limits, and implements one exact-value forwarding import.
//! It does not branch on supervisor, worker, or service meaning.

use crate::execution::artifact::ContentDigest;
pub use crate::execution::component::ComponentExecutionLimits;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use wasmtime::component::{Component, Linker, TypedFunc};
use wasmtime::{Config, Engine, Store, StoreLimits, StoreLimitsBuilder, Trap};

pub const COMPONENT_FACTORY_ABI: &str = "invoke(candidate: s32, minimum: s32) -> s32";
pub const COMPONENT_FACTORY_EXPORT: &str = "invoke";
pub const HOST_FORWARDER_IMPLEMENTATION_ID: &str = "wasm-biotic.host.forward-exactly.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentFactoryInput {
    pub candidate: i32,
    pub minimum: i32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentFactoryNodeManifest {
    pub node_id: String,
    pub component_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentFactoryEdge {
    pub from_node: String,
    pub import_name: String,
    pub to_node: String,
}

impl ComponentFactoryEdge {
    pub fn new(
        from_node: impl Into<String>,
        import_name: impl Into<String>,
        to_node: impl Into<String>,
    ) -> Self {
        Self {
            from_node: from_node.into(),
            import_name: import_name.into(),
            to_node: to_node.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentFactoryManifest {
    pub abi: String,
    pub entrypoint: String,
    /// Dependency order: an edge target must appear before its source.
    pub ordered_nodes: Vec<ComponentFactoryNodeManifest>,
    pub edges: Vec<ComponentFactoryEdge>,
}

impl ComponentFactoryManifest {
    pub fn component_digest(&self, node_id: &str) -> Option<&ContentDigest> {
        self.ordered_nodes
            .iter()
            .find(|node| node.node_id == node_id)
            .map(|node| &node.component_digest)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComponentFactoryNode {
    node_id: String,
    component_bytes: Vec<u8>,
}

impl ComponentFactoryNode {
    pub fn new(node_id: impl Into<String>, component_bytes: Vec<u8>) -> Self {
        Self {
            node_id: node_id.into(),
            component_bytes,
        }
    }

    pub fn from_wat(
        node_id: impl Into<String>,
        component_wat: &str,
    ) -> Result<Self, ComponentFactoryError> {
        let node_id = node_id.into();
        let component_bytes = wat::parse_str(component_wat).map_err(|error| {
            ComponentFactoryError::InvalidComponentWat {
                node_id: node_id.clone(),
                reason: error.to_string(),
            }
        })?;
        Ok(Self::new(node_id, component_bytes))
    }
}

#[derive(Clone, Debug)]
pub struct ComponentFactoryPackage {
    manifest: ComponentFactoryManifest,
    manifest_digest: ContentDigest,
    component_bytes: BTreeMap<String, Vec<u8>>,
}

impl ComponentFactoryPackage {
    pub fn new(
        entrypoint: impl Into<String>,
        ordered_nodes: Vec<ComponentFactoryNode>,
        edges: Vec<ComponentFactoryEdge>,
    ) -> Result<Self, ComponentFactoryError> {
        let entrypoint = entrypoint.into();
        let mut component_bytes = BTreeMap::new();
        let mut manifest_nodes = Vec::with_capacity(ordered_nodes.len());
        for node in ordered_nodes {
            let digest = ContentDigest::from_bytes(&node.component_bytes);
            if component_bytes
                .insert(node.node_id.clone(), node.component_bytes)
                .is_some()
            {
                return Err(ComponentFactoryError::DuplicateNode(node.node_id));
            }
            manifest_nodes.push(ComponentFactoryNodeManifest {
                node_id: node.node_id,
                component_digest: digest,
            });
        }
        let manifest = ComponentFactoryManifest {
            abi: COMPONENT_FACTORY_ABI.to_string(),
            entrypoint,
            ordered_nodes: manifest_nodes,
            edges,
        };
        validate_manifest(&manifest, &component_bytes)?;
        let manifest_digest = digest_manifest(&manifest)?;
        Ok(Self {
            manifest,
            manifest_digest,
            component_bytes,
        })
    }

    pub fn manifest(&self) -> &ComponentFactoryManifest {
        &self.manifest
    }

    pub fn manifest_digest(&self) -> &ContentDigest {
        &self.manifest_digest
    }

    fn validate(&self) -> Result<(), ComponentFactoryError> {
        validate_manifest(&self.manifest, &self.component_bytes)?;
        let actual_manifest_digest = digest_manifest(&self.manifest)?;
        if actual_manifest_digest != self.manifest_digest {
            return Err(ComponentFactoryError::ManifestDigestMismatch {
                expected: self.manifest_digest.clone(),
                actual: actual_manifest_digest,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentFactoryBinding {
    pub manifest_digest: ContentDigest,
    pub component_digests: BTreeMap<String, ContentDigest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentFactoryNodeTrace {
    pub node_id: String,
    pub component_digest: ContentDigest,
    pub input: ComponentFactoryInput,
    pub output: i32,
    pub limits: ComponentExecutionLimits,
    pub fuel_consumed: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostForwardCall {
    pub sequence: u64,
    pub implementation_id: String,
    pub from_node: String,
    pub to_node: String,
    pub import_name: String,
    pub from_component_digest: ContentDigest,
    pub to_component_digest: ContentDigest,
    pub input: ComponentFactoryInput,
    pub output: i32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentFactoryExecutionTrace {
    pub binding: ComponentFactoryBinding,
    pub entrypoint: String,
    pub input: ComponentFactoryInput,
    pub output: i32,
    pub node_traces: Vec<ComponentFactoryNodeTrace>,
    pub host_forward_calls: Vec<HostForwardCall>,
}

struct ComponentHostState {
    limits: StoreLimits,
}

struct ExecutableNode {
    node_id: String,
    component_digest: ContentDigest,
    limits: ComponentExecutionLimits,
    store: Store<ComponentHostState>,
    invoke: TypedFunc<(i32, i32), (i32,)>,
    last_trace: Option<ComponentFactoryNodeTrace>,
}

type NodeHandle = Arc<Mutex<ExecutableNode>>;

#[derive(Clone)]
struct ForwardTarget {
    from_node: String,
    to_node: String,
    import_name: String,
    from_component_digest: ContentDigest,
    to_component_digest: ContentDigest,
    node: NodeHandle,
}

pub struct ComponentFactoryRuntime {
    manifest: ComponentFactoryManifest,
    binding: ComponentFactoryBinding,
    nodes: BTreeMap<String, NodeHandle>,
    entrypoint: NodeHandle,
    host_forward_calls: Arc<Mutex<Vec<HostForwardCall>>>,
    next_forward_sequence: Arc<AtomicU64>,
    execution_lock: Mutex<()>,
}

impl ComponentFactoryRuntime {
    pub fn new(
        package: ComponentFactoryPackage,
        limits: ComponentExecutionLimits,
    ) -> Result<Self, ComponentFactoryError> {
        package.validate()?;
        validate_execution_limits(&limits)?;

        let mut config = Config::new();
        config.consume_fuel(true);
        let engine = Engine::new(&config)
            .map_err(|error| ComponentFactoryError::Engine(error.to_string()))?;
        let host_forward_calls = Arc::new(Mutex::new(Vec::new()));
        let next_forward_sequence = Arc::new(AtomicU64::new(0));
        let mut nodes = BTreeMap::<String, NodeHandle>::new();

        for manifest_node in &package.manifest.ordered_nodes {
            let outgoing = package
                .manifest
                .edges
                .iter()
                .find(|edge| edge.from_node == manifest_node.node_id);
            let forward_target = if let Some(edge) = outgoing {
                let downstream = nodes.get(&edge.to_node).cloned().ok_or_else(|| {
                    ComponentFactoryError::DependencyOrder {
                        from_node: edge.from_node.clone(),
                        to_node: edge.to_node.clone(),
                    }
                })?;
                let downstream_digest = package
                    .manifest
                    .component_digest(&edge.to_node)
                    .expect("validated edge target must have a digest")
                    .clone();
                Some(ForwardTarget {
                    from_node: edge.from_node.clone(),
                    to_node: edge.to_node.clone(),
                    import_name: edge.import_name.clone(),
                    from_component_digest: manifest_node.component_digest.clone(),
                    to_component_digest: downstream_digest,
                    node: downstream,
                })
            } else {
                None
            };
            let bytes = package
                .component_bytes
                .get(&manifest_node.node_id)
                .expect("validated node must have component bytes");
            let node = instantiate_node(
                &engine,
                manifest_node,
                bytes,
                &limits,
                forward_target,
                Arc::clone(&host_forward_calls),
                Arc::clone(&next_forward_sequence),
            )?;
            nodes.insert(manifest_node.node_id.clone(), node);
        }

        let entrypoint = nodes
            .get(&package.manifest.entrypoint)
            .cloned()
            .ok_or_else(|| {
                ComponentFactoryError::MissingEntrypoint(package.manifest.entrypoint.clone())
            })?;
        let component_digests = package
            .manifest
            .ordered_nodes
            .iter()
            .map(|node| (node.node_id.clone(), node.component_digest.clone()))
            .collect();

        Ok(Self {
            manifest: package.manifest,
            binding: ComponentFactoryBinding {
                manifest_digest: package.manifest_digest,
                component_digests,
            },
            nodes,
            entrypoint,
            host_forward_calls,
            next_forward_sequence,
            execution_lock: Mutex::new(()),
        })
    }

    pub fn binding(&self) -> &ComponentFactoryBinding {
        &self.binding
    }

    pub fn execute(
        &self,
        candidate: i32,
        minimum: i32,
    ) -> Result<ComponentFactoryExecutionTrace, ComponentFactoryError> {
        let _execution = self
            .execution_lock
            .lock()
            .map_err(|_| ComponentFactoryError::Synchronization("execution lock".to_string()))?;
        self.next_forward_sequence.store(0, Ordering::SeqCst);
        self.host_forward_calls
            .lock()
            .map_err(|_| ComponentFactoryError::Synchronization("host forward trace".to_string()))?
            .clear();
        for node in self.nodes.values() {
            node.lock()
                .map_err(|_| ComponentFactoryError::Synchronization("component node".to_string()))?
                .last_trace = None;
        }

        let input = ComponentFactoryInput { candidate, minimum };
        let output = self
            .entrypoint
            .lock()
            .map_err(|_| ComponentFactoryError::Synchronization("entrypoint node".to_string()))?
            .invoke(input)?;

        let mut node_traces = Vec::new();
        for manifest_node in &self.manifest.ordered_nodes {
            if let Some(trace) = self
                .nodes
                .get(&manifest_node.node_id)
                .expect("runtime node must match validated manifest")
                .lock()
                .map_err(|_| ComponentFactoryError::Synchronization("component trace".to_string()))?
                .last_trace
                .clone()
            {
                node_traces.push(trace);
            }
        }
        let mut host_forward_calls = self
            .host_forward_calls
            .lock()
            .map_err(|_| ComponentFactoryError::Synchronization("host forward trace".to_string()))?
            .clone();
        host_forward_calls.sort_by_key(|call| call.sequence);

        Ok(ComponentFactoryExecutionTrace {
            binding: self.binding.clone(),
            entrypoint: self.manifest.entrypoint.clone(),
            input,
            output,
            node_traces,
            host_forward_calls,
        })
    }
}

impl ExecutableNode {
    fn invoke(&mut self, input: ComponentFactoryInput) -> Result<i32, ComponentFactoryError> {
        self.store.set_fuel(self.limits.fuel).map_err(|error| {
            ComponentFactoryError::Invocation {
                node_id: self.node_id.clone(),
                reason: error.to_string(),
                fuel_exhausted: false,
                fuel_consumed: 0,
            }
        })?;
        let invoke = self.invoke.clone();
        let result = invoke.call(&mut self.store, (input.candidate, input.minimum));
        let fuel_consumed = self
            .store
            .get_fuel()
            .map(|remaining| self.limits.fuel.saturating_sub(remaining))
            .unwrap_or_default();
        match result {
            Ok((output,)) => {
                self.last_trace = Some(ComponentFactoryNodeTrace {
                    node_id: self.node_id.clone(),
                    component_digest: self.component_digest.clone(),
                    input,
                    output,
                    limits: self.limits.clone(),
                    fuel_consumed,
                });
                Ok(output)
            }
            Err(error) => Err(ComponentFactoryError::Invocation {
                node_id: self.node_id.clone(),
                reason: format!("{error:#}"),
                fuel_exhausted: error.downcast_ref::<Trap>() == Some(&Trap::OutOfFuel),
                fuel_consumed,
            }),
        }
    }
}

fn instantiate_node(
    engine: &Engine,
    manifest_node: &ComponentFactoryNodeManifest,
    component_bytes: &[u8],
    limits: &ComponentExecutionLimits,
    forward_target: Option<ForwardTarget>,
    host_forward_calls: Arc<Mutex<Vec<HostForwardCall>>>,
    next_forward_sequence: Arc<AtomicU64>,
) -> Result<NodeHandle, ComponentFactoryError> {
    let component = Component::new(engine, component_bytes).map_err(|error| {
        ComponentFactoryError::Compile {
            node_id: manifest_node.node_id.clone(),
            reason: error.to_string(),
        }
    })?;
    let mut linker = Linker::<ComponentHostState>::new(engine);
    if let Some(target) = forward_target {
        let import_name = target.import_name.clone();
        linker
            .root()
            .func_wrap(
                import_name.as_str(),
                move |_store: wasmtime::StoreContextMut<'_, ComponentHostState>,
                      (candidate, minimum): (i32, i32)|
                      -> wasmtime::Result<(i32,)> {
                    let input = ComponentFactoryInput { candidate, minimum };
                    let output = forward_exactly(
                        &target,
                        input,
                        &host_forward_calls,
                        &next_forward_sequence,
                    )
                    .map_err(|error| wasmtime::Error::msg(error.to_string()))?;
                    Ok((output,))
                },
            )
            .map_err(|error| ComponentFactoryError::Link {
                node_id: manifest_node.node_id.clone(),
                reason: error.to_string(),
            })?;
    }

    let store_limits = build_store_limits(limits)?;
    let mut store = Store::new(
        engine,
        ComponentHostState {
            limits: store_limits,
        },
    );
    store.limiter(|state| &mut state.limits);
    store
        .set_fuel(limits.fuel)
        .map_err(|error| ComponentFactoryError::Instantiation {
            node_id: manifest_node.node_id.clone(),
            reason: error.to_string(),
        })?;
    let instance = linker
        .instantiate(&mut store, &component)
        .map_err(|error| ComponentFactoryError::Instantiation {
            node_id: manifest_node.node_id.clone(),
            reason: format!("{error:#}"),
        })?;
    let invoke = instance
        .get_typed_func::<(i32, i32), (i32,)>(&mut store, COMPONENT_FACTORY_EXPORT)
        .map_err(|error| ComponentFactoryError::MissingTypedExport {
            node_id: manifest_node.node_id.clone(),
            reason: error.to_string(),
        })?;

    Ok(Arc::new(Mutex::new(ExecutableNode {
        node_id: manifest_node.node_id.clone(),
        component_digest: manifest_node.component_digest.clone(),
        limits: limits.clone(),
        store,
        invoke,
        last_trace: None,
    })))
}

/// The only host operation on the domain path. It performs no arithmetic,
/// threshold check, retry, approval, or role-specific dispatch.
fn forward_exactly(
    target: &ForwardTarget,
    input: ComponentFactoryInput,
    calls: &Mutex<Vec<HostForwardCall>>,
    sequence: &AtomicU64,
) -> Result<i32, ComponentFactoryError> {
    let call_sequence = sequence.fetch_add(1, Ordering::SeqCst);
    let output = target
        .node
        .lock()
        .map_err(|_| ComponentFactoryError::Synchronization("downstream node".to_string()))?
        .invoke(input)?;
    calls
        .lock()
        .map_err(|_| ComponentFactoryError::Synchronization("host forward trace".to_string()))?
        .push(HostForwardCall {
            sequence: call_sequence,
            implementation_id: HOST_FORWARDER_IMPLEMENTATION_ID.to_string(),
            from_node: target.from_node.clone(),
            to_node: target.to_node.clone(),
            import_name: target.import_name.clone(),
            from_component_digest: target.from_component_digest.clone(),
            to_component_digest: target.to_component_digest.clone(),
            input,
            output,
        });
    Ok(output)
}

fn validate_manifest(
    manifest: &ComponentFactoryManifest,
    component_bytes: &BTreeMap<String, Vec<u8>>,
) -> Result<(), ComponentFactoryError> {
    if manifest.abi != COMPONENT_FACTORY_ABI {
        return Err(ComponentFactoryError::UnsupportedAbi(manifest.abi.clone()));
    }
    if manifest.entrypoint.trim().is_empty() {
        return Err(ComponentFactoryError::MissingEntrypoint(
            manifest.entrypoint.clone(),
        ));
    }
    if manifest.ordered_nodes.is_empty() {
        return Err(ComponentFactoryError::EmptyGraph);
    }
    let mut positions = BTreeMap::new();
    for (position, node) in manifest.ordered_nodes.iter().enumerate() {
        if node.node_id.trim().is_empty() {
            return Err(ComponentFactoryError::EmptyNodeId);
        }
        if positions.insert(node.node_id.clone(), position).is_some() {
            return Err(ComponentFactoryError::DuplicateNode(node.node_id.clone()));
        }
        let bytes = component_bytes
            .get(&node.node_id)
            .ok_or_else(|| ComponentFactoryError::MissingComponent(node.node_id.clone()))?;
        if bytes.is_empty() {
            return Err(ComponentFactoryError::MissingComponent(
                node.node_id.clone(),
            ));
        }
        let actual = ContentDigest::from_bytes(bytes);
        if actual != node.component_digest {
            return Err(ComponentFactoryError::ComponentDigestMismatch {
                node_id: node.node_id.clone(),
                expected: node.component_digest.clone(),
                actual,
            });
        }
    }
    if !positions.contains_key(&manifest.entrypoint) {
        return Err(ComponentFactoryError::MissingEntrypoint(
            manifest.entrypoint.clone(),
        ));
    }
    let mut outgoing = BTreeSet::new();
    for edge in &manifest.edges {
        if edge.from_node.trim().is_empty()
            || edge.to_node.trim().is_empty()
            || edge.import_name.trim().is_empty()
        {
            return Err(ComponentFactoryError::MalformedEdge);
        }
        if !outgoing.insert(edge.from_node.clone()) {
            return Err(ComponentFactoryError::MultipleOutgoingEdges(
                edge.from_node.clone(),
            ));
        }
        let from_position = positions
            .get(&edge.from_node)
            .ok_or_else(|| ComponentFactoryError::UnknownNode(edge.from_node.clone()))?;
        let to_position = positions
            .get(&edge.to_node)
            .ok_or_else(|| ComponentFactoryError::UnknownNode(edge.to_node.clone()))?;
        if to_position >= from_position {
            return Err(ComponentFactoryError::DependencyOrder {
                from_node: edge.from_node.clone(),
                to_node: edge.to_node.clone(),
            });
        }
    }
    Ok(())
}

fn digest_manifest(
    manifest: &ComponentFactoryManifest,
) -> Result<ContentDigest, ComponentFactoryError> {
    serde_json::to_vec(manifest)
        .map(|bytes| ContentDigest::from_bytes(&bytes))
        .map_err(|error| ComponentFactoryError::ManifestEncoding(error.to_string()))
}

fn validate_execution_limits(
    limits: &ComponentExecutionLimits,
) -> Result<(), ComponentFactoryError> {
    for (name, value) in [
        ("fuel", limits.fuel),
        ("max_memory_bytes", limits.max_memory_bytes),
        ("max_instances", u64::from(limits.max_instances)),
        ("max_memories", u64::from(limits.max_memories)),
        ("max_tables", u64::from(limits.max_tables)),
        ("max_table_elements", u64::from(limits.max_table_elements)),
    ] {
        if value == 0 {
            return Err(ComponentFactoryError::InvalidLimit {
                name: name.to_string(),
                value,
            });
        }
    }
    Ok(())
}

fn build_store_limits(
    limits: &ComponentExecutionLimits,
) -> Result<StoreLimits, ComponentFactoryError> {
    let max_memory_bytes = usize::try_from(limits.max_memory_bytes).map_err(|_| {
        ComponentFactoryError::LimitOutOfRange {
            name: "max_memory_bytes".to_string(),
            value: limits.max_memory_bytes,
        }
    })?;
    Ok(StoreLimitsBuilder::new()
        .memory_size(max_memory_bytes)
        .instances(limits.max_instances as usize)
        .memories(limits.max_memories as usize)
        .tables(limits.max_tables as usize)
        .table_elements(limits.max_table_elements as usize)
        .trap_on_grow_failure(true)
        .build())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ComponentFactoryError {
    InvalidComponentWat {
        node_id: String,
        reason: String,
    },
    EmptyGraph,
    EmptyNodeId,
    DuplicateNode(String),
    UnknownNode(String),
    MissingComponent(String),
    MissingEntrypoint(String),
    MalformedEdge,
    MultipleOutgoingEdges(String),
    DependencyOrder {
        from_node: String,
        to_node: String,
    },
    UnsupportedAbi(String),
    ManifestEncoding(String),
    ManifestDigestMismatch {
        expected: ContentDigest,
        actual: ContentDigest,
    },
    ComponentDigestMismatch {
        node_id: String,
        expected: ContentDigest,
        actual: ContentDigest,
    },
    InvalidLimit {
        name: String,
        value: u64,
    },
    LimitOutOfRange {
        name: String,
        value: u64,
    },
    Engine(String),
    Compile {
        node_id: String,
        reason: String,
    },
    Link {
        node_id: String,
        reason: String,
    },
    Instantiation {
        node_id: String,
        reason: String,
    },
    MissingTypedExport {
        node_id: String,
        reason: String,
    },
    Invocation {
        node_id: String,
        reason: String,
        fuel_exhausted: bool,
        fuel_consumed: u64,
    },
    Synchronization(String),
}

impl Display for ComponentFactoryError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidComponentWat { node_id, reason } => {
                write!(f, "component node '{node_id}' has invalid WAT: {reason}")
            }
            Self::EmptyGraph => write!(f, "component graph must contain at least one node"),
            Self::EmptyNodeId => write!(f, "component graph node id must not be empty"),
            Self::DuplicateNode(node) => write!(f, "duplicate component graph node '{node}'"),
            Self::UnknownNode(node) => {
                write!(f, "component graph references unknown node '{node}'")
            }
            Self::MissingComponent(node) => {
                write!(f, "component graph node '{node}' has no component bytes")
            }
            Self::MissingEntrypoint(node) => {
                write!(f, "component graph entrypoint '{node}' does not exist")
            }
            Self::MalformedEdge => write!(f, "component graph edge fields must not be empty"),
            Self::MultipleOutgoingEdges(node) => write!(
                f,
                "component graph node '{node}' declares more than one typed downstream edge"
            ),
            Self::DependencyOrder { from_node, to_node } => write!(
                f,
                "component graph edge '{from_node}' -> '{to_node}' violates dependency order"
            ),
            Self::UnsupportedAbi(abi) => write!(f, "unsupported component-factory ABI '{abi}'"),
            Self::ManifestEncoding(reason) => {
                write!(f, "component graph manifest could not be encoded: {reason}")
            }
            Self::ManifestDigestMismatch { expected, actual } => write!(
                f,
                "component graph manifest digest mismatch: expected {expected}, got {actual}"
            ),
            Self::ComponentDigestMismatch {
                node_id,
                expected,
                actual,
            } => write!(
                f,
                "component node '{node_id}' digest mismatch: expected {expected}, got {actual}"
            ),
            Self::InvalidLimit { name, value } => {
                write!(
                    f,
                    "component execution limit '{name}' must be positive, got {value}"
                )
            }
            Self::LimitOutOfRange { name, value } => {
                write!(
                    f,
                    "component execution limit '{name}' is out of range: {value}"
                )
            }
            Self::Engine(reason) => write!(f, "component engine setup failed: {reason}"),
            Self::Compile { node_id, reason } => {
                write!(f, "component node '{node_id}' failed to compile: {reason}")
            }
            Self::Link { node_id, reason } => {
                write!(f, "component node '{node_id}' failed to link: {reason}")
            }
            Self::Instantiation { node_id, reason } => {
                write!(
                    f,
                    "component node '{node_id}' failed to instantiate: {reason}"
                )
            }
            Self::MissingTypedExport { node_id, reason } => write!(
                f,
                "component node '{node_id}' lacks the typed '{COMPONENT_FACTORY_EXPORT}' export: {reason}"
            ),
            Self::Invocation {
                node_id,
                reason,
                fuel_exhausted,
                fuel_consumed,
            } => write!(
                f,
                "component node '{node_id}' invocation failed (fuel_exhausted={fuel_exhausted}, fuel_consumed={fuel_consumed}): {reason}"
            ),
            Self::Synchronization(context) => {
                write!(f, "component factory synchronization failed at {context}")
            }
        }
    }
}

impl Error for ComponentFactoryError {}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVICE_INCLUSIVE: &str =
        include_str!("../../artifacts/fixtures/component-factory/service-inclusive.wat");
    const SERVICE_STRICT: &str =
        include_str!("../../artifacts/fixtures/component-factory/service-strict.wat");
    const WORKER_INCREMENT_1: &str =
        include_str!("../../artifacts/fixtures/component-factory/worker-increment-1.wat");
    const WORKER_INCREMENT_2: &str =
        include_str!("../../artifacts/fixtures/component-factory/worker-increment-2.wat");
    const SUPERVISOR_BONUS_100: &str =
        include_str!("../../artifacts/fixtures/component-factory/supervisor-bonus-100.wat");
    const SUPERVISOR_BONUS_200: &str =
        include_str!("../../artifacts/fixtures/component-factory/supervisor-bonus-200.wat");
    const SUPERVISOR_SPIN: &str =
        include_str!("../../artifacts/fixtures/component-factory/supervisor-spin.wat");

    fn package(
        service_wat: &str,
        worker_wat: &str,
        supervisor_wat: &str,
    ) -> ComponentFactoryPackage {
        ComponentFactoryPackage::new(
            "supervisor-policy",
            vec![
                ComponentFactoryNode::from_wat("threshold-service", service_wat).unwrap(),
                ComponentFactoryNode::from_wat("worker-policy", worker_wat).unwrap(),
                ComponentFactoryNode::from_wat("supervisor-policy", supervisor_wat).unwrap(),
            ],
            vec![
                ComponentFactoryEdge::new("worker-policy", "downstream", "threshold-service"),
                ComponentFactoryEdge::new("supervisor-policy", "downstream", "worker-policy"),
            ],
        )
        .unwrap()
    }

    fn execute(
        service_wat: &str,
        worker_wat: &str,
        supervisor_wat: &str,
    ) -> ComponentFactoryExecutionTrace {
        ComponentFactoryRuntime::new(
            package(service_wat, worker_wat, supervisor_wat),
            ComponentExecutionLimits::default(),
        )
        .unwrap()
        .execute(4, 5)
        .unwrap()
    }

    #[test]
    fn executes_manifest_declared_typed_component_graph() {
        let trace = execute(SERVICE_INCLUSIVE, WORKER_INCREMENT_1, SUPERVISOR_BONUS_100);

        assert_eq!(trace.output, 115);
        assert_eq!(trace.node_traces.len(), 3);
        assert_eq!(
            trace
                .node_traces
                .iter()
                .map(|node| (node.node_id.as_str(), node.output))
                .collect::<Vec<_>>(),
            vec![
                ("threshold-service", 5),
                ("worker-policy", 15),
                ("supervisor-policy", 115),
            ]
        );
        assert_eq!(trace.host_forward_calls.len(), 2);
        assert_eq!(trace.host_forward_calls[0].from_node, "supervisor-policy");
        assert_eq!(trace.host_forward_calls[0].to_node, "worker-policy");
        assert_eq!(trace.host_forward_calls[0].input, trace.input);
        assert_eq!(trace.host_forward_calls[0].output, 15);
        assert_eq!(trace.host_forward_calls[1].from_node, "worker-policy");
        assert_eq!(trace.host_forward_calls[1].to_node, "threshold-service");
        assert_eq!(
            trace.host_forward_calls[1].input,
            ComponentFactoryInput {
                candidate: 5,
                minimum: 5,
            }
        );
        assert_eq!(trace.host_forward_calls[1].output, 5);
        assert!(
            trace
                .host_forward_calls
                .iter()
                .all(|call| call.implementation_id == HOST_FORWARDER_IMPLEMENTATION_ID)
        );
    }

    #[test]
    fn changing_only_component_bytes_changes_each_nodes_policy() {
        let baseline = execute(SERVICE_INCLUSIVE, WORKER_INCREMENT_1, SUPERVISOR_BONUS_100);
        let strict_service = execute(SERVICE_STRICT, WORKER_INCREMENT_1, SUPERVISOR_BONUS_100);
        let increment_two = execute(SERVICE_INCLUSIVE, WORKER_INCREMENT_2, SUPERVISOR_BONUS_100);
        let bonus_two_hundred =
            execute(SERVICE_INCLUSIVE, WORKER_INCREMENT_1, SUPERVISOR_BONUS_200);

        assert_eq!(baseline.output, 115);
        assert_eq!(strict_service.output, -1);
        assert_eq!(increment_two.output, 116);
        assert_eq!(bonus_two_hundred.output, 215);

        assert_only_digest_changed(&baseline, &strict_service, "threshold-service");
        assert_only_digest_changed(&baseline, &increment_two, "worker-policy");
        assert_only_digest_changed(&baseline, &bonus_two_hundred, "supervisor-policy");
        for trace in [&strict_service, &increment_two, &bonus_two_hundred] {
            assert_ne!(
                trace.binding.manifest_digest,
                baseline.binding.manifest_digest
            );
            assert!(
                trace
                    .host_forward_calls
                    .iter()
                    .all(|call| call.implementation_id == HOST_FORWARDER_IMPLEMENTATION_ID)
            );
        }
    }

    #[test]
    fn host_is_policy_blind_and_applies_uniform_limits() {
        let limits = ComponentExecutionLimits {
            fuel: 20_000,
            ..ComponentExecutionLimits::default()
        };
        let runtime = ComponentFactoryRuntime::new(
            package(SERVICE_INCLUSIVE, WORKER_INCREMENT_1, SUPERVISOR_BONUS_100),
            limits.clone(),
        )
        .unwrap();
        let trace = runtime.execute(4, 5).unwrap();

        assert!(
            trace
                .node_traces
                .iter()
                .all(|node| node.limits == limits && node.fuel_consumed <= limits.fuel)
        );
        // The first component forwards (4, 5) unchanged. The worker component,
        // not the callback, changes the next forwarded candidate to 5.
        assert_eq!(trace.host_forward_calls[0].input, trace.input);
        assert_eq!(trace.host_forward_calls[1].input.candidate, 5);

        let spin_runtime = ComponentFactoryRuntime::new(
            package(SERVICE_INCLUSIVE, WORKER_INCREMENT_1, SUPERVISOR_SPIN),
            limits,
        )
        .unwrap();
        let error = spin_runtime.execute(4, 5).unwrap_err();
        assert!(matches!(
            error,
            ComponentFactoryError::Invocation {
                node_id,
                fuel_exhausted: true,
                ..
            } if node_id == "supervisor-policy"
        ));
    }

    fn assert_only_digest_changed(
        baseline: &ComponentFactoryExecutionTrace,
        variant: &ComponentFactoryExecutionTrace,
        changed_node: &str,
    ) {
        for (node_id, baseline_digest) in &baseline.binding.component_digests {
            let variant_digest = variant.binding.component_digests.get(node_id).unwrap();
            if node_id == changed_node {
                assert_ne!(variant_digest, baseline_digest);
            } else {
                assert_eq!(variant_digest, baseline_digest);
            }
        }
    }
}
