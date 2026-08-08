use crate::{EdgeBinding, GraphManifest, GraphPackage, KernelError, Sha256Digest};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use wasmtime::component::{Component, Linker, TypedFunc};
use wasmtime::{Config, Engine, Store, StoreLimits, StoreLimitsBuilder, Trap};

/// Uniform resource bounds applied independently to every component store.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    /// Deterministic instruction budget per invocation.
    pub fuel: u64,
    /// Maximum linear-memory bytes.
    pub max_memory_bytes: u64,
    /// Maximum core instances in a store.
    pub max_instances: u32,
    /// Maximum memories in a store.
    pub max_memories: u32,
    /// Maximum tables in a store.
    pub max_tables: u32,
    /// Maximum elements across a table.
    pub max_table_elements: u32,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            fuel: 100_000,
            max_memory_bytes: 16 * 1024 * 1024,
            max_instances: 16,
            max_memories: 4,
            max_tables: 4,
            max_table_elements: 10_000,
        }
    }
}

/// Input value for [`crate::ABI_S32_PAIR_TO_S32_V1`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionInput {
    /// First signed 32-bit value.
    pub first: i32,
    /// Second signed 32-bit value.
    pub second: i32,
}

/// Content binding established before execution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphBinding {
    /// Digest of the exact manifest bytes.
    pub manifest_digest: Sha256Digest,
    /// Exact component digest per opaque node identifier.
    pub component_digests: BTreeMap<String, Sha256Digest>,
}

/// Trace of one typed component export call.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeCallTrace {
    /// Opaque manifest node identifier.
    pub node: String,
    /// Exact invoked component digest.
    pub component_digest: Sha256Digest,
    /// Exact export name.
    pub export: String,
    /// Input delivered to the component.
    pub input: ExecutionInput,
    /// Component-produced value.
    pub output: i32,
    /// Uniform bounds in force.
    pub limits: ResourceLimits,
    /// Fuel consumed by the call.
    pub fuel_consumed: u64,
}

/// Trace proving an exact manifest edge was followed without value changes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeCallTrace {
    /// Edge invocation order.
    pub sequence: u64,
    /// Importing node identifier.
    pub consumer: String,
    /// Imported function name.
    pub import: String,
    /// Target node identifier.
    pub target: String,
    /// Target export name.
    pub target_export: String,
    /// Input forwarded exactly as received.
    pub input: ExecutionInput,
    /// Target-produced output forwarded exactly as received.
    pub output: i32,
}

/// Complete trace of one graph entry invocation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionTrace {
    /// Exact content binding used by the runtime.
    pub binding: GraphBinding,
    /// Manifest entry point.
    pub entry: crate::EntryPoint,
    /// Entry input.
    pub input: ExecutionInput,
    /// Entry output.
    pub output: i32,
    /// Successful component invocations.
    pub node_calls: Vec<NodeCallTrace>,
    /// Successful typed edge calls.
    pub edge_calls: Vec<EdgeCallTrace>,
}

struct StoreState {
    limits: StoreLimits,
}

struct ExecutableNode {
    id: String,
    digest: Sha256Digest,
    export_name: String,
    limits: ResourceLimits,
    store: Store<StoreState>,
    invoke: TypedFunc<(i32, i32), (i32,)>,
    calls: Vec<NodeCallTrace>,
}

type NodeHandle = Arc<Mutex<ExecutableNode>>;

#[derive(Clone)]
struct EdgeTarget {
    binding: EdgeBinding,
    node: NodeHandle,
}

/// Instantiated, digest-bound component graph.
pub struct GraphRuntime {
    manifest: GraphManifest,
    binding: GraphBinding,
    nodes: BTreeMap<String, NodeHandle>,
    entry: NodeHandle,
    edge_calls: Arc<Mutex<Vec<EdgeCallTrace>>>,
    next_sequence: Arc<AtomicU64>,
    execution_lock: Mutex<()>,
}

impl GraphRuntime {
    /// Validates and instantiates every node under identical limits.
    pub fn new(package: GraphPackage, limits: ResourceLimits) -> Result<Self, KernelError> {
        validate_limits(&limits)?;
        if !package.manifest().host_bindings.is_empty() {
            return Err(KernelError::HostInterfacesUnavailable);
        }

        let mut config = Config::new();
        config.consume_fuel(true);
        let engine =
            Engine::new(&config).map_err(|error| KernelError::Engine(error.to_string()))?;
        let edge_calls = Arc::new(Mutex::new(Vec::new()));
        let next_sequence = Arc::new(AtomicU64::new(0));
        let mut nodes = BTreeMap::<String, NodeHandle>::new();

        for node_spec in &package.manifest().ordered_nodes {
            let mut targets = Vec::new();
            for edge in package
                .manifest()
                .edges
                .iter()
                .filter(|edge| edge.consumer == node_spec.id)
            {
                let target = nodes.get(&edge.target).cloned().ok_or_else(|| {
                    KernelError::DependencyOrder {
                        consumer: edge.consumer.clone(),
                        target: edge.target.clone(),
                    }
                })?;
                targets.push(EdgeTarget {
                    binding: edge.clone(),
                    node: target,
                });
            }
            let node = instantiate_node(
                &engine,
                node_spec,
                package.component(&node_spec.component_digest).as_bytes(),
                &limits,
                targets,
                Arc::clone(&edge_calls),
                Arc::clone(&next_sequence),
            )?;
            nodes.insert(node_spec.id.clone(), node);
        }

        let entry = nodes
            .get(&package.manifest().entry.node)
            .cloned()
            .ok_or(KernelError::InvalidEntryPoint)?;
        let binding = GraphBinding {
            manifest_digest: package.manifest_digest(),
            component_digests: package
                .manifest()
                .ordered_nodes
                .iter()
                .map(|node| (node.id.clone(), node.component_digest))
                .collect(),
        };

        Ok(Self {
            manifest: package.manifest().clone(),
            binding,
            nodes,
            entry,
            edge_calls,
            next_sequence,
            execution_lock: Mutex::new(()),
        })
    }

    /// Returns the immutable manifest/component content binding.
    #[must_use]
    pub const fn binding(&self) -> &GraphBinding {
        &self.binding
    }

    /// Invokes the exact manifest entry point.
    pub fn execute(&self, input: ExecutionInput) -> Result<ExecutionTrace, KernelError> {
        let _guard = self
            .execution_lock
            .lock()
            .map_err(|_| KernelError::Synchronization("entry lock"))?;
        self.next_sequence.store(0, Ordering::SeqCst);
        self.edge_calls
            .lock()
            .map_err(|_| KernelError::Synchronization("edge trace"))?
            .clear();
        for node in self.nodes.values() {
            node.lock()
                .map_err(|_| KernelError::Synchronization("node trace"))?
                .calls
                .clear();
        }

        let output = self
            .entry
            .lock()
            .map_err(|_| KernelError::Synchronization("entry node"))?
            .call(input)?;
        let mut node_calls = Vec::new();
        for spec in &self.manifest.ordered_nodes {
            node_calls.extend(
                self.nodes[&spec.id]
                    .lock()
                    .map_err(|_| KernelError::Synchronization("node calls"))?
                    .calls
                    .clone(),
            );
        }
        let mut edge_calls = self
            .edge_calls
            .lock()
            .map_err(|_| KernelError::Synchronization("edge calls"))?
            .clone();
        edge_calls.sort_by_key(|call| call.sequence);

        Ok(ExecutionTrace {
            binding: self.binding.clone(),
            entry: self.manifest.entry.clone(),
            input,
            output,
            node_calls,
            edge_calls,
        })
    }
}

impl ExecutableNode {
    fn call(&mut self, input: ExecutionInput) -> Result<i32, KernelError> {
        self.store
            .set_fuel(self.limits.fuel)
            .map_err(|error| KernelError::Invoke {
                node: self.id.clone(),
                reason: error.to_string(),
                fuel_exhausted: false,
                fuel_consumed: 0,
            })?;
        let invoke = self.invoke;
        let result = invoke.call(&mut self.store, (input.first, input.second));
        let fuel_consumed = self
            .store
            .get_fuel()
            .map(|remaining| self.limits.fuel.saturating_sub(remaining))
            .unwrap_or_default();
        match result {
            Ok((output,)) => {
                self.calls.push(NodeCallTrace {
                    node: self.id.clone(),
                    component_digest: self.digest,
                    export: self.export_name.clone(),
                    input,
                    output,
                    limits: self.limits.clone(),
                    fuel_consumed,
                });
                Ok(output)
            }
            Err(error) => Err(KernelError::Invoke {
                node: self.id.clone(),
                reason: format!("{error:#}"),
                fuel_exhausted: error.downcast_ref::<Trap>() == Some(&Trap::OutOfFuel),
                fuel_consumed,
            }),
        }
    }
}

fn instantiate_node(
    engine: &Engine,
    spec: &crate::ComponentNode,
    bytes: &[u8],
    limits: &ResourceLimits,
    targets: Vec<EdgeTarget>,
    edge_calls: Arc<Mutex<Vec<EdgeCallTrace>>>,
    next_sequence: Arc<AtomicU64>,
) -> Result<NodeHandle, KernelError> {
    let component = Component::new(engine, bytes).map_err(|error| KernelError::Compile {
        node: spec.id.clone(),
        reason: error.to_string(),
    })?;
    let mut linker = Linker::<StoreState>::new(engine);
    for target in targets {
        let import = target.binding.import.clone();
        let call_log = Arc::clone(&edge_calls);
        let call_sequence = Arc::clone(&next_sequence);
        linker
            .root()
            .func_wrap(
                import.as_str(),
                move |_store: wasmtime::StoreContextMut<'_, StoreState>,
                      (first, second): (i32, i32)|
                      -> wasmtime::Result<(i32,)> {
                    let input = ExecutionInput { first, second };
                    let sequence = call_sequence.fetch_add(1, Ordering::SeqCst);
                    let output = target
                        .node
                        .lock()
                        .map_err(|_| wasmtime::Error::msg("target node lock failed"))?
                        .call(input)
                        .map_err(|error| wasmtime::Error::msg(error.to_string()))?;
                    call_log
                        .lock()
                        .map_err(|_| wasmtime::Error::msg("edge trace lock failed"))?
                        .push(EdgeCallTrace {
                            sequence,
                            consumer: target.binding.consumer.clone(),
                            import: target.binding.import.clone(),
                            target: target.binding.target.clone(),
                            target_export: target.binding.target_export.clone(),
                            input,
                            output,
                        });
                    Ok((output,))
                },
            )
            .map_err(|error| KernelError::Link {
                node: spec.id.clone(),
                reason: error.to_string(),
            })?;
    }

    let mut store = Store::new(
        engine,
        StoreState {
            limits: build_store_limits(limits)?,
        },
    );
    store.limiter(|state| &mut state.limits);
    store
        .set_fuel(limits.fuel)
        .map_err(|error| KernelError::Instantiate {
            node: spec.id.clone(),
            reason: error.to_string(),
        })?;
    let instance = linker
        .instantiate(&mut store, &component)
        .map_err(|error| KernelError::Instantiate {
            node: spec.id.clone(),
            reason: format!("{error:#}"),
        })?;
    let invoke = instance
        .get_typed_func::<(i32, i32), (i32,)>(&mut store, &spec.export)
        .map_err(|error| KernelError::Export {
            node: spec.id.clone(),
            reason: error.to_string(),
        })?;

    Ok(Arc::new(Mutex::new(ExecutableNode {
        id: spec.id.clone(),
        digest: spec.component_digest,
        export_name: spec.export.clone(),
        limits: limits.clone(),
        store,
        invoke,
        calls: Vec::new(),
    })))
}

fn validate_limits(limits: &ResourceLimits) -> Result<(), KernelError> {
    for (name, value) in [
        ("fuel", limits.fuel),
        ("max_memory_bytes", limits.max_memory_bytes),
        ("max_instances", u64::from(limits.max_instances)),
        ("max_memories", u64::from(limits.max_memories)),
        ("max_tables", u64::from(limits.max_tables)),
        ("max_table_elements", u64::from(limits.max_table_elements)),
    ] {
        if value == 0 {
            return Err(KernelError::InvalidLimit { name, value });
        }
    }
    Ok(())
}

fn build_store_limits(limits: &ResourceLimits) -> Result<StoreLimits, KernelError> {
    let memory_size =
        usize::try_from(limits.max_memory_bytes).map_err(|_| KernelError::LimitOutOfRange {
            name: "max_memory_bytes",
            value: limits.max_memory_bytes,
        })?;
    Ok(StoreLimitsBuilder::new()
        .memory_size(memory_size)
        .instances(limits.max_instances as usize)
        .memories(limits.max_memories as usize)
        .tables(limits.max_tables as usize)
        .table_elements(limits.max_table_elements as usize)
        .trap_on_grow_failure(true)
        .build())
}
