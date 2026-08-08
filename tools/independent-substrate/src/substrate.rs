//! A small in-memory implementation of exactly the eight substrate mechanisms.
//!
//! Selection is exclusively by content digest and declared grant. This module
//! contains no worker, capability-operation, workflow, milestone or policy
//! vocabulary.

use crate::bindings::{root, task};
use crate::model::{AnyError, Digest, Executable, HttpOperatorCapacity, Result, canonical_json};
use crate::package::LoadedRelease;
use crate::transport::{
    TransportFailure, TransportHeader, TransportOwner, TransportPoll, TransportRequest,
    TransportRuntime,
};
use ring::rand::{SecureRandom as _, SystemRandom};
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair as _, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::thread;
use std::time::Duration;
use wasmtime::component::{Component, HasSelf, Linker};
use wasmtime::{Config, Engine, Store, StoreContextMut, StoreLimits, StoreLimitsBuilder, Trap};

const MAX_INSTANCES: usize = 128;
const MAX_MEMORIES: usize = 64;
const MAX_TABLES: usize = 64;
const MAX_TABLE_ELEMENTS: usize = 1_000_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreBlob {
    pub digest: Digest,
    pub size_bytes: u64,
    pub media_type: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreFailure {
    pub code: String,
    pub message: String,
    pub retryable: bool,
    pub evidence: Option<CoreBlob>,
}

impl CoreFailure {
    fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_string(),
            message: message.into(),
            retryable: false,
            evidence: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreGrant {
    pub capability: String,
    pub scope: String,
    pub constraints: Option<CoreBlob>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreLimits {
    pub fuel: u64,
    pub memory_bytes: u64,
    pub output_bytes: u64,
    pub wall_time_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreRunRequest {
    pub run_id: String,
    pub component_digest: Digest,
    pub input: CoreBlob,
    pub grants: Vec<CoreGrant>,
    pub limits: CoreLimits,
    pub idempotency_key: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoreOutcome {
    Succeeded(CoreBlob),
    Rejected(CoreFailure),
    Failed(CoreFailure),
    Cancelled,
    Exhausted(CoreFailure),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreReceipt {
    pub receipt_id: String,
    pub request_digest: Digest,
    pub executor_digest: Digest,
    pub started_at_ms: u64,
    pub finished_at_ms: u64,
    pub outcome_digest: Digest,
    pub audit_sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreCompletion {
    pub run_id: String,
    pub outcome: CoreOutcome,
    pub receipt: CoreReceipt,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    pub graph_manifest_digest: Digest,
    pub authority_component_digest: Digest,
    pub executable_component_digest: Digest,
    pub source_component_digests: Vec<Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_principal_seed: Option<Digest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WakeSnapshot {
    pub idempotency_key: Digest,
    pub not_before_ms: u64,
    pub payload_digest: Digest,
    pub target_component: Digest,
    pub wake_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MechanismSnapshot {
    pub activation_count: usize,
    pub active_graph: Digest,
    pub active_manifest: CoreBlob,
    pub active_state: Option<CoreBlob>,
    pub audit_entry_count: usize,
    pub blob_count: usize,
    pub clock_ms: u64,
    pub commit_count: usize,
    pub transaction_entries_by_namespace: BTreeMap<String, usize>,
    pub wakes: Vec<WakeSnapshot>,
}

#[derive(Clone, Debug)]
struct StoredBlob {
    media_type: String,
    bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
struct VersionedBlob {
    version: u64,
    value: CoreBlob,
}

#[derive(Clone, Debug)]
struct CommitRecord {
    owner: Option<Digest>,
    request_digest: Digest,
    transaction_id: String,
    commit_version: u64,
    committed_value_digest: Digest,
}

#[derive(Clone, Debug)]
struct Wake {
    owner: Option<Digest>,
    not_before_ms: u64,
    target_component: Digest,
    payload_digest: Digest,
    idempotency_key: Digest,
}

#[derive(Clone, Debug, Serialize)]
struct CoreAuditEntry {
    event_id: String,
    actor_id: String,
    actor_component: Digest,
    event_type: String,
    payload: CoreBlob,
    previous_entry: Option<Digest>,
    occurred_at_ms: u64,
    idempotency_key: Digest,
}

#[derive(Clone, Debug)]
struct CoreActivation {
    owner: Option<GraphPrincipalOwner>,
    activation_id: String,
    state: ActivationState,
    graph_manifest: CoreBlob,
    previous_graph: Digest,
    previous_state: Option<CoreBlob>,
    migrated_state: Option<CoreBlob>,
    request_digest: Digest,
    receipt: Option<CoreReceipt>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ActivationState {
    Staged,
    Active,
    RolledBack,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct GraphPrincipalOwner {
    graph_manifest_digest: Digest,
    principal_seed: Digest,
}

struct Memory {
    blobs: BTreeMap<Digest, StoredBlob>,
    total_blob_bytes: u64,
    transactions: BTreeMap<(String, String), VersionedBlob>,
    commits: BTreeMap<Digest, CommitRecord>,
    commit_version: u64,
    wakes: BTreeMap<String, Wake>,
    audits: Vec<(Digest, CoreAuditEntry)>,
    audit_idempotency: BTreeMap<Digest, (Option<Digest>, Digest, u64)>,
    activations: BTreeMap<String, CoreActivation>,
    admitted_manifests: BTreeMap<Digest, CoreBlob>,
    admitted_activation_principal_seeds: BTreeMap<Digest, BTreeSet<Digest>>,
    active_manifest: CoreBlob,
    active_graph: Digest,
    active_state: Option<CoreBlob>,
    clock_ms: u64,
    signing_seeds: BTreeMap<String, [u8; 32]>,
    verification_keys: BTreeMap<String, Vec<u8>>,
    entropy: SystemRandom,
}

#[derive(Clone)]
pub struct InMemorySubstrate {
    memory: Rc<RefCell<Memory>>,
    release: Rc<LoadedRelease>,
    transport: TransportRuntime,
}

impl InMemorySubstrate {
    /// Constructs a substrate whose external HTTP mechanism is disabled,
    /// including when the release uses profile v3.
    pub fn new(release: Rc<LoadedRelease>) -> Result<Self> {
        Self::new_configured(release, None)
    }

    /// Constructs a profile-v3 substrate with an explicit immutable operator
    /// capacity. Runtime authority is the intersection of this capacity and
    /// the signed per-principal HTTP constraints.
    pub fn new_with_http_capacity(
        release: Rc<LoadedRelease>,
        capacity: HttpOperatorCapacity,
    ) -> Result<Self> {
        Self::new_configured(release, Some(capacity))
    }

    fn new_configured(
        release: Rc<LoadedRelease>,
        capacity: Option<HttpOperatorCapacity>,
    ) -> Result<Self> {
        let manifest = CoreBlob {
            digest: release.index.graph_manifest_digest,
            size_bytes: release.manifest_bytes.len().try_into()?,
            media_type: "application/vnd.wasm-biotic.factory-graph+json".to_string(),
        };
        let mut blobs = BTreeMap::new();
        blobs.insert(
            manifest.digest,
            StoredBlob {
                media_type: manifest.media_type.clone(),
                bytes: release.manifest_bytes.clone(),
            },
        );
        let entropy = SystemRandom::new();
        let mut seed = [0_u8; 32];
        entropy.fill(&mut seed).map_err(|_| "OS entropy failed")?;
        let key_pair = Ed25519KeyPair::from_seed_unchecked(&seed)
            .map_err(|_| "could not initialize independent key handle")?;
        let key_id = Digest::of(key_pair.public_key().as_ref()).to_string();
        let mut signing_seeds = BTreeMap::new();
        signing_seeds.insert("independent-default".to_string(), seed);
        let mut verification_keys = BTreeMap::new();
        verification_keys.insert(key_id, key_pair.public_key().as_ref().to_vec());
        let mut admitted_manifests = BTreeMap::new();
        admitted_manifests.insert(manifest.digest, manifest.clone());
        let admitted_activation_principal_seeds = BTreeMap::from([(
            manifest.digest,
            release
                .profile
                .principals
                .iter()
                .filter(|principal| {
                    principal
                        .host_imports
                        .iter()
                        .any(|import| import.capability == "activation" && import.scope == "switch")
                })
                .map(|principal| principal.principal_seed)
                .collect(),
        )]);
        let total_blob_bytes = manifest.size_bytes;
        let transport = match capacity {
            Some(capacity) => TransportRuntime::new_with_operator(
                &release.profile.schema,
                release.http_transport_constraints.clone(),
                capacity,
            )
            .map_err(|failure| format!("{}: {}", failure.code, failure.message))?,
            None => TransportRuntime::new(
                &release.profile.schema,
                release.http_transport_constraints.clone(),
            ),
        };
        Ok(Self {
            memory: Rc::new(RefCell::new(Memory {
                blobs,
                total_blob_bytes,
                transactions: BTreeMap::new(),
                commits: BTreeMap::new(),
                commit_version: 0,
                wakes: BTreeMap::new(),
                audits: Vec::new(),
                audit_idempotency: BTreeMap::new(),
                activations: BTreeMap::new(),
                admitted_manifests,
                admitted_activation_principal_seeds,
                active_manifest: manifest,
                active_graph: release.index.graph_manifest_digest,
                active_state: None,
                clock_ms: 1_725_000_000_000,
                signing_seeds,
                verification_keys,
                entropy,
            })),
            release,
            transport,
        })
    }

    /// Installs an operator-supplied opaque credential for a signed R3
    /// handle. The bytes remain solely in the transport vault and are never
    /// copied into release state, operation records, receipts or guest blobs.
    pub fn install_transport_credential(
        &self,
        handle: &str,
        secret: Vec<u8>,
    ) -> std::result::Result<(), CoreFailure> {
        self.transport
            .install_credential(handle, secret)
            .map_err(transport_failure_to_core)
    }

    /// Applies crash recovery to the transport journal. Any operation whose
    /// durable state says dispatch began but has no terminal record becomes
    /// permanently indeterminate; it is never resent.
    pub fn recover_transport_journal(&self) {
        self.transport.recover_dispatching_as_indeterminate();
    }

    pub(crate) fn admit_release(&self, release: Rc<LoadedRelease>) -> Result<Self> {
        let scoped_source = matches!(
            self.release.profile.schema.as_str(),
            "wasm-biotic.factory-substrate-profile.v2" | "wasm-biotic.factory-substrate-profile.v3"
        );
        require(
            scoped_source && release.profile.schema == self.release.profile.schema,
            "shared release admission requires the same scoped profile version",
        )?;
        if release.profile.schema == "wasm-biotic.factory-substrate-profile.v3" {
            require(
                release.http_transport_constraints == self.release.http_transport_constraints,
                "admitted successor changes bounded HTTP constraints",
            )?;
        }
        require(
            release.manifest.previous_graph == Some(self.release.index.graph_manifest_digest),
            "admitted successor does not name the active release",
        )?;
        require(
            release.certificate.certifier_key_id == self.release.certificate.certifier_key_id
                && release.index.certified_kernel_tcb_inventory_digest
                    == self.release.index.certified_kernel_tcb_inventory_digest,
            "admitted successor has a different signer or native TCB",
        )?;
        let source_principals = self
            .release
            .profile
            .principals
            .iter()
            .map(|principal| (principal.consumer.as_str(), principal.principal_seed))
            .collect::<BTreeMap<_, _>>();
        let target_principals = release
            .profile
            .principals
            .iter()
            .map(|principal| (principal.consumer.as_str(), principal.principal_seed))
            .collect::<BTreeMap<_, _>>();
        require(
            source_principals == target_principals,
            "admitted successor changes the per-consumer principal mapping",
        )?;

        let manifest = self
            .put(
                "application/vnd.wasm-biotic.factory-graph+json".to_string(),
                release.manifest_bytes.clone(),
            )
            .map_err(|failure| format!("{}: {}", failure.code, failure.message))?;
        require(
            manifest.digest == release.index.graph_manifest_digest,
            "admitted successor manifest identity is inconsistent",
        )?;
        let activation_principal_seeds = release
            .profile
            .principals
            .iter()
            .filter(|principal| {
                principal
                    .host_imports
                    .iter()
                    .any(|import| import.capability == "activation" && import.scope == "switch")
            })
            .map(|principal| principal.principal_seed)
            .collect();
        let mut memory = self.memory.borrow_mut();
        memory.admitted_manifests.insert(manifest.digest, manifest);
        memory.admitted_activation_principal_seeds.insert(
            release.index.graph_manifest_digest,
            activation_principal_seeds,
        );
        drop(memory);
        Ok(Self {
            memory: self.memory.clone(),
            release,
            transport: self.transport.clone(),
        })
    }

    pub fn put(
        &self,
        media_type: String,
        bytes: Vec<u8>,
    ) -> std::result::Result<CoreBlob, CoreFailure> {
        if media_type.trim().is_empty() {
            return Err(CoreFailure::new(
                "invalid-media-type",
                "media type is blank",
            ));
        }
        let size_bytes = u64::try_from(bytes.len()).map_err(|_| {
            CoreFailure::new(
                "limit-exceeded",
                "blob length is outside the supported range",
            )
        })?;
        if size_bytes > self.release.profile.ceilings.max_blob_bytes {
            return Err(CoreFailure::new(
                "limit-exceeded",
                "blob exceeds release ceiling",
            ));
        }
        let digest = Digest::of(&bytes);
        let mut memory = self.memory.borrow_mut();
        if let Some(existing) = memory.blobs.get(&digest) {
            if existing.bytes != bytes {
                return Err(CoreFailure::new(
                    "digest-collision",
                    "content digest collision",
                ));
            }
        } else {
            let next_total = memory
                .total_blob_bytes
                .checked_add(size_bytes)
                .ok_or_else(|| CoreFailure::new("limit-exceeded", "blob quota overflow"))?;
            if next_total > self.release.profile.ceilings.max_total_blob_bytes {
                return Err(CoreFailure::new(
                    "limit-exceeded",
                    "total blob quota exceeded",
                ));
            }
            memory.total_blob_bytes = next_total;
            memory.blobs.insert(
                digest,
                StoredBlob {
                    media_type: media_type.clone(),
                    bytes,
                },
            );
        }
        Ok(CoreBlob {
            digest,
            size_bytes,
            media_type,
        })
    }

    pub fn get(&self, reference: &CoreBlob) -> std::result::Result<Vec<u8>, CoreFailure> {
        let memory = self.memory.borrow();
        let stored = memory
            .blobs
            .get(&reference.digest)
            .ok_or_else(|| CoreFailure::new("blob-not-found", "content digest is absent"))?;
        if stored.bytes.len() as u64 != reference.size_bytes
            || stored.media_type != reference.media_type
            || Digest::of(&stored.bytes) != reference.digest
        {
            return Err(CoreFailure::new(
                "blob-reference-mismatch",
                "blob identity does not match",
            ));
        }
        Ok(stored.bytes.clone())
    }

    pub fn has(&self, digest: Digest) -> bool {
        self.memory.borrow().blobs.contains_key(&digest)
    }

    pub fn now(&self) -> u64 {
        self.memory.borrow().clock_ms
    }

    fn tick(&self) -> u64 {
        let mut memory = self.memory.borrow_mut();
        let value = memory.clock_ms;
        memory.clock_ms = memory.clock_ms.saturating_add(1);
        value
    }

    pub fn release(&self) -> &LoadedRelease {
        &self.release
    }

    pub(crate) fn admitted_manifest(&self, graph: Digest) -> Option<CoreBlob> {
        self.memory.borrow().admitted_manifests.get(&graph).cloned()
    }

    pub(crate) fn activation_owner(&self, activation_id: &str) -> Option<(Digest, Digest)> {
        self.memory
            .borrow()
            .activations
            .get(activation_id)
            .and_then(|activation| activation.owner)
            .map(|owner| (owner.graph_manifest_digest, owner.principal_seed))
    }

    pub fn mechanism_snapshot(&self) -> MechanismSnapshot {
        let memory = self.memory.borrow();
        let mut transaction_entries_by_namespace = BTreeMap::new();
        for (namespace, _) in memory.transactions.keys() {
            *transaction_entries_by_namespace
                .entry(namespace.clone())
                .or_insert(0) += 1;
        }
        let wakes = memory
            .wakes
            .iter()
            .map(|(wake_id, wake)| WakeSnapshot {
                idempotency_key: wake.idempotency_key,
                not_before_ms: wake.not_before_ms,
                payload_digest: wake.payload_digest,
                target_component: wake.target_component,
                wake_id: wake_id.clone(),
            })
            .collect();
        MechanismSnapshot {
            activation_count: memory.activations.len(),
            active_graph: memory.active_graph,
            active_manifest: memory.active_manifest.clone(),
            active_state: memory.active_state.clone(),
            audit_entry_count: memory.audits.len(),
            blob_count: memory.blobs.len(),
            clock_ms: memory.clock_ms,
            commit_count: memory.commits.len(),
            transaction_entries_by_namespace,
            wakes,
        }
    }

    pub fn shares_mechanism_root_with(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.memory, &other.memory)
    }
}

#[derive(Clone, Debug, Default)]
struct Access {
    blob_read: bool,
    blob_write: bool,
    transaction_namespaces: BTreeSet<String>,
    clock: bool,
    component_runner: bool,
    http_transport: bool,
    key_service: bool,
    activation: bool,
    audit_append: bool,
    audit_read: bool,
}

#[derive(Clone, Debug)]
struct PrincipalContext {
    access: Access,
    authority_component_digest: Digest,
    consumer: String,
    graph_manifest_digest: Digest,
    principal_seed: Digest,
    alias: String,
    constraints: Digest,
}

#[derive(Clone, Debug)]
struct ActivePrincipal {
    authority_component_digest: Digest,
    consumer: String,
    graph_manifest_digest: Digest,
    principal_seed: Digest,
    alias: String,
    constraints: Digest,
}

impl Access {
    fn root(release: &LoadedRelease) -> Result<Self> {
        let grants = release.profile.root_grants.iter().map(|grant| CoreGrant {
            capability: grant.capability.clone(),
            scope: grant.scope.clone(),
            constraints: None,
        });
        Self::from_grants(grants, release, true)
    }

    fn principal(import: &crate::model::HostImport, release: &LoadedRelease) -> Result<Self> {
        Self::from_grants(
            [CoreGrant {
                capability: import.capability.clone(),
                scope: import.scope.clone(),
                constraints: None,
            }],
            release,
            true,
        )
    }

    fn from_grants(
        grants: impl IntoIterator<Item = CoreGrant>,
        release: &LoadedRelease,
        expand_namespaces: bool,
    ) -> Result<Self> {
        let mut access = Self::default();
        for grant in grants {
            match (grant.capability.as_str(), grant.scope.as_str()) {
                ("blob-store", "read") => access.blob_read = true,
                ("blob-store", "write") => access.blob_write = true,
                ("blob-store", "read-write") => {
                    access.blob_read = true;
                    access.blob_write = true;
                }
                ("transaction-store", "namespaces") if expand_namespaces => {
                    access.transaction_namespaces.extend(
                        release
                            .profile
                            .ceilings
                            .transaction_namespaces
                            .iter()
                            .cloned(),
                    );
                }
                ("transaction-store", namespace) if !namespace.trim().is_empty() => {
                    access.transaction_namespaces.insert(namespace.to_string());
                }
                ("clock", "wake") => access.clock = true,
                ("component-runner", "run") => access.component_runner = true,
                ("http-transport", "request") => access.http_transport = true,
                ("key-service", "use") => access.key_service = true,
                ("activation", "switch") => access.activation = true,
                ("audit-log", "append") => access.audit_append = true,
                ("audit-log", "read") => access.audit_read = true,
                ("audit-log", "append-read") => {
                    access.audit_append = true;
                    access.audit_read = true;
                }
                _ => {
                    return Err(
                        format!("unsupported grant {}:{}", grant.capability, grant.scope).into(),
                    );
                }
            }
        }
        Ok(access)
    }
}

#[derive(Clone)]
struct RunRecord {
    owner: Option<Digest>,
    request_digest: Digest,
    completion: CoreCompletion,
    provenance: Provenance,
}

pub struct HostState {
    substrate: InMemorySubstrate,
    access: Access,
    active_principal: Option<ActivePrincipal>,
    aliases: BTreeMap<String, PrincipalContext>,
    runs: BTreeMap<String, RunRecord>,
    limits: StoreLimits,
}

impl HostState {
    pub fn root(substrate: InMemorySubstrate) -> Result<Self> {
        let access =
            if substrate.release().profile.schema == "wasm-biotic.factory-substrate-profile.v1" {
                Access::root(substrate.release())?
            } else {
                Access::default()
            };
        let aliases = principal_contexts(substrate.release())?;
        let memory = usize::try_from(
            substrate
                .release
                .profile
                .ceilings
                .max_component_memory_bytes,
        )?;
        Ok(Self {
            substrate,
            access,
            active_principal: None,
            aliases,
            runs: BTreeMap::new(),
            limits: store_limits(memory),
        })
    }

    pub fn provenance(&self) -> BTreeMap<String, Provenance> {
        self.runs
            .iter()
            .map(|(operation, record)| (operation.clone(), record.provenance.clone()))
            .collect()
    }

    fn caller(&self) -> Option<Digest> {
        self.active_principal
            .as_ref()
            .map(|principal| principal.principal_seed)
    }

    fn activation_caller(&self) -> Option<GraphPrincipalOwner> {
        self.active_principal
            .as_ref()
            .map(|principal| GraphPrincipalOwner {
                graph_manifest_digest: principal.graph_manifest_digest,
                principal_seed: principal.principal_seed,
            })
    }

    pub(crate) fn with_alias<R>(
        &mut self,
        alias: &str,
        call: impl FnOnce(&mut Self) -> R,
    ) -> wasmtime::Result<R> {
        let context = self
            .aliases
            .get(alias)
            .cloned()
            .ok_or_else(|| wasmtime::Error::msg("undeclared R2 host import alias"))?;
        let previous_access = std::mem::replace(&mut self.access, context.access);
        let previous_principal = self.active_principal.replace(ActivePrincipal {
            authority_component_digest: context.authority_component_digest,
            consumer: context.consumer,
            graph_manifest_digest: context.graph_manifest_digest,
            principal_seed: context.principal_seed,
            alias: context.alias,
            constraints: context.constraints,
        });
        let result = call(self);
        self.access = previous_access;
        self.active_principal = previous_principal;
        Ok(result)
    }

    fn caller_owns(&self, owner: Option<Digest>) -> bool {
        owner == self.caller()
    }

    fn transport_owner(&self) -> std::result::Result<TransportOwner, CoreFailure> {
        let principal = self.active_principal.as_ref().ok_or_else(|| {
            CoreFailure::new(
                "not-granted",
                "HTTP transport requires a linker-bound graph principal",
            )
        })?;
        Ok(TransportOwner {
            graph_manifest_digest: principal.graph_manifest_digest,
            authority_component_digest: principal.authority_component_digest,
            principal_seed: principal.principal_seed,
            consumer: principal.consumer.clone(),
            alias: principal.alias.clone(),
            constraints: principal.constraints,
        })
    }

    fn caller_may_run(&self, target: Digest) -> bool {
        if self.substrate.release.profile.schema == "wasm-biotic.factory-substrate-profile.v1" {
            return true;
        }
        let Some(principal) = self.active_principal.as_ref() else {
            return false;
        };
        if !self
            .substrate
            .release
            .node_digest(&principal.consumer)
            .is_ok_and(|digest| digest == principal.authority_component_digest)
        {
            return false;
        }
        self.substrate
            .release
            .manifest
            .invocations
            .iter()
            .any(|edge| {
                edge.consumer == principal.consumer
                    && self
                        .substrate
                        .release
                        .node_digest(&edge.target)
                        .is_ok_and(|digest| digest == target)
            })
    }
}

fn principal_contexts(release: &LoadedRelease) -> Result<BTreeMap<String, PrincipalContext>> {
    let mut aliases = BTreeMap::new();
    if !matches!(
        release.profile.schema.as_str(),
        "wasm-biotic.factory-substrate-profile.v2" | "wasm-biotic.factory-substrate-profile.v3"
    ) {
        return Ok(aliases);
    }
    for principal in &release.profile.principals {
        for import in &principal.host_imports {
            let context = PrincipalContext {
                access: Access::principal(import, release)?,
                authority_component_digest: principal.authority_component_digest,
                consumer: principal.consumer.clone(),
                graph_manifest_digest: release.index.graph_manifest_digest,
                principal_seed: principal.principal_seed,
                alias: import.alias.clone(),
                constraints: import.constraints,
            };
            if aliases.insert(import.alias.clone(), context).is_some() {
                return Err("duplicate R2 runtime host import alias".into());
            }
        }
    }
    Ok(aliases)
}

fn store_limits(memory: usize) -> StoreLimits {
    StoreLimitsBuilder::new()
        .memory_size(memory)
        .instances(MAX_INSTANCES)
        .memories(MAX_MEMORIES)
        .tables(MAX_TABLES)
        .table_elements(MAX_TABLE_ELEMENTS)
        .trap_on_grow_failure(true)
        .build()
}

fn validate_digest_hex(hex: &str) -> std::result::Result<Digest, CoreFailure> {
    format!("sha256:{hex}")
        .parse()
        .map_err(|_| CoreFailure::new("invalid-digest", "digest is not lowercase SHA-256"))
}

fn transport_failure_to_core(failure: TransportFailure) -> CoreFailure {
    CoreFailure::new(failure.code, failure.message)
}

macro_rules! digest_to_wit {
    ($bindings:ident, $digest:expr) => {
        $bindings::wasm_biotic::factory::foundation::Digest {
            algorithm: $bindings::wasm_biotic::factory::foundation::HashAlgorithm::Sha256,
            hex: $digest.hex(),
        }
    };
}

macro_rules! blob_to_wit {
    ($bindings:ident, $blob:expr) => {{
        let blob = $blob;
        $bindings::wasm_biotic::factory::foundation::BlobRef {
            content_digest: digest_to_wit!($bindings, blob.digest),
            size_bytes: blob.size_bytes,
            media_type: blob.media_type,
        }
    }};
}

macro_rules! wit_blob_to_core {
    ($blob:expr) => {{
        let blob = $blob;
        validate_digest_hex(&blob.content_digest.hex).map(|digest| CoreBlob {
            digest,
            size_bytes: blob.size_bytes,
            media_type: blob.media_type,
        })
    }};
}

macro_rules! wit_failure_to_core {
    ($failure:expr) => {{
        let failure = $failure;
        CoreFailure {
            code: failure.code,
            message: failure.message,
            retryable: failure.retryable,
            evidence: failure
                .evidence
                .and_then(|blob| wit_blob_to_core!(blob).ok()),
        }
    }};
}

fn validate_dynamic_request(
    substrate: &InMemorySubstrate,
    request: &CoreRunRequest,
) -> std::result::Result<(Executable, Vec<u8>, Access), CoreFailure> {
    substrate.get(&request.input)?;
    let artifact = substrate
        .release
        .executables
        .get(&request.component_digest)
        .ok_or_else(|| {
            CoreFailure::new("not-admitted", "component digest is not a dynamic target")
        })?;
    if artifact.descriptor.authority_node == substrate.release.manifest.root_node {
        return Err(CoreFailure::new(
            "not-admitted",
            "root cannot be selected as a dynamic task",
        ));
    }
    if request.limits.fuel == 0
        || request.limits.fuel > substrate.release.profile.ceilings.max_component_fuel
        || request.limits.memory_bytes == 0
        || request.limits.memory_bytes
            > substrate
                .release
                .profile
                .ceilings
                .max_component_memory_bytes
        || request.limits.output_bytes == 0
        || request.limits.output_bytes
            > substrate
                .release
                .profile
                .ceilings
                .max_component_output_bytes
        || request.limits.wall_time_ms == 0
        || request.limits.wall_time_ms
            > substrate
                .release
                .profile
                .ceilings
                .max_component_wall_time_ms
    {
        return Err(CoreFailure::new(
            "limit-exceeded",
            "run limits exceed release ceiling",
        ));
    }
    let mut seen = BTreeSet::new();
    let is_r2 = matches!(
        substrate.release.profile.schema.as_str(),
        "wasm-biotic.factory-substrate-profile.v2" | "wasm-biotic.factory-substrate-profile.v3"
    );
    for grant in &request.grants {
        if !seen.insert(grant.capability.clone()) {
            return Err(CoreFailure::new(
                "invalid-request",
                "duplicate run capability grant",
            ));
        }
        let admitted = if is_r2 {
            r2_legacy_grant_is_bounded_by_principal_closure(substrate, &artifact.descriptor, grant)
        } else {
            artifact.descriptor.grants.iter().any(|bound| {
                bound.capability == grant.capability
                    && scope_is_subset(&grant.capability, &grant.scope, &bound.scope)
                    && grant.constraints.as_ref().is_none_or(|reference| {
                        reference.digest == bound.constraints && substrate.get(reference).is_ok()
                    })
            })
        };
        if !admitted {
            return Err(CoreFailure::new(
                "not-granted",
                "run grant exceeds descriptor",
            ));
        }
    }
    // In R2 the outer RunRequest grant list is compatibility metadata only. It
    // is bounded by the signed executable closure above, but it never becomes
    // runtime authority. Actual host calls receive only the immutable access
    // attached to their per-consumer import alias.
    let access = if is_r2 {
        Access::default()
    } else {
        Access::from_grants(request.grants.clone(), substrate.release(), false)
            .map_err(|error| CoreFailure::new("invalid-grant", error.to_string()))?
    };
    Ok((artifact.descriptor.clone(), artifact.bytes.clone(), access))
}

fn r2_legacy_grant_is_bounded_by_principal_closure(
    substrate: &InMemorySubstrate,
    executable: &Executable,
    grant: &CoreGrant,
) -> bool {
    let mut seen = BTreeSet::new();
    let mut admitted = false;
    for principal_seed in &executable.principal_seeds {
        if !seen.insert(*principal_seed) {
            return false;
        }
        let Some(principal) = substrate
            .release
            .profile
            .principals
            .iter()
            .find(|principal| principal.principal_seed == *principal_seed)
        else {
            return false;
        };
        admitted |= principal.host_imports.iter().any(|bound| {
            bound.capability == grant.capability
                && scope_is_subset(&grant.capability, &grant.scope, &bound.scope)
                && grant.constraints.as_ref().is_none_or(|reference| {
                    reference.digest == bound.constraints && substrate.get(reference).is_ok()
                })
        });
    }
    admitted
}

fn scope_is_subset(capability: &str, requested: &str, admitted: &str) -> bool {
    match capability {
        "blob-store" => {
            requested == admitted
                || admitted == "read-write" && matches!(requested, "read" | "write")
        }
        "audit-log" => {
            requested == admitted
                || admitted == "append-read" && matches!(requested, "append" | "read")
        }
        _ => requested == admitted,
    }
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string().into())
    }
}

fn execute_dynamic(
    substrate: InMemorySubstrate,
    request: &CoreRunRequest,
    caller_principal_seed: Option<Digest>,
) -> (CoreCompletion, Provenance) {
    let request_digest = Digest::of(&canonical_json(request).unwrap_or_default());
    let started_at_ms = substrate.tick();
    let validation = validate_dynamic_request(&substrate, request);
    let (outcome, descriptor) = match validation {
        Err(error) => (CoreOutcome::Rejected(error), None),
        Ok((descriptor, bytes, access)) => {
            let input = request.input.clone();
            let limits = request.limits;
            let result = (|| -> wasmtime::Result<std::result::Result<task::wasm_biotic::factory::foundation::BlobRef, task::wasm_biotic::factory::foundation::Failure>> {
                let mut config = Config::new();
                config.consume_fuel(true);
                config.epoch_interruption(true);
                let engine = Engine::new(&config)?;
                let component = Component::new(&engine, &bytes)?;
                let mut linker = Linker::<HostState>::new(&engine);
                if substrate.release.profile.schema
                    == "wasm-biotic.factory-substrate-profile.v1"
                {
                    task::AdmittedTaskComponent::add_to_linker::<_, HasSelf<_>>(
                        &mut linker,
                        |state| state,
                    )?;
                } else {
                    add_r2_aliases_to_linker(&mut linker, substrate.release())
                        .map_err(|error| wasmtime::Error::msg(error.to_string()))?;
                }
                let memory = usize::try_from(limits.memory_bytes)
                    .map_err(|_| wasmtime::Error::msg("memory limit is out of range"))?;
                let mut store = Store::new(
                    &engine,
                    HostState {
                        substrate: substrate.clone(),
                        access: if substrate.release.profile.schema
                            == "wasm-biotic.factory-substrate-profile.v1"
                        {
                            access
                        } else {
                            Access::default()
                        },
                        active_principal: None,
                        aliases: principal_contexts(substrate.release())
                            .map_err(|error| wasmtime::Error::msg(error.to_string()))?,
                        runs: BTreeMap::new(),
                        limits: store_limits(memory),
                    },
                );
                store.limiter(|state| &mut state.limits);
                store.set_fuel(limits.fuel)?;
                store.set_epoch_deadline(1);
                let timer_engine = engine.clone();
                thread::spawn(move || {
                    thread::sleep(Duration::from_millis(limits.wall_time_ms));
                    timer_engine.increment_epoch();
                });
                let instance = task::AdmittedTaskComponent::instantiate(&mut store, &component, &linker)?;
                instance
                    .wasm_biotic_factory_component_task()
                    .call_run(&mut store, &blob_to_wit!(task, input))
            })();
            let outcome = match result {
                Ok(Ok(reference)) => {
                    let reference = match wit_blob_to_core!(reference) {
                        Ok(reference) => reference,
                        Err(error) => {
                            return (
                                CoreCompletion {
                                    run_id: request.run_id.clone(),
                                    outcome: CoreOutcome::Failed(error),
                                    receipt: CoreReceipt {
                                        receipt_id: format!(
                                            "receipt-{}",
                                            request.idempotency_key.hex()
                                        ),
                                        request_digest,
                                        executor_digest: request.component_digest,
                                        started_at_ms,
                                        finished_at_ms: substrate.tick(),
                                        outcome_digest: Digest::of(b"invalid-output-reference"),
                                        audit_sequence: 0,
                                    },
                                },
                                Provenance {
                                    graph_manifest_digest: substrate
                                        .release
                                        .index
                                        .graph_manifest_digest,
                                    authority_component_digest: request.component_digest,
                                    executable_component_digest: descriptor.executable_digest,
                                    source_component_digests: descriptor.source_digests,
                                    caller_principal_seed,
                                },
                            );
                        }
                    };
                    if reference.size_bytes > request.limits.output_bytes {
                        CoreOutcome::Exhausted(CoreFailure::new(
                            "limit-exceeded",
                            "component output exceeds requested bound",
                        ))
                    } else if let Err(error) = substrate.get(&reference) {
                        CoreOutcome::Failed(error)
                    } else {
                        CoreOutcome::Succeeded(reference)
                    }
                }
                Ok(Err(error)) => CoreOutcome::Rejected(wit_failure_to_core!(error)),
                Err(error)
                    if matches!(
                        error.downcast_ref::<Trap>(),
                        Some(Trap::OutOfFuel | Trap::Interrupt)
                    ) =>
                {
                    CoreOutcome::Exhausted(CoreFailure::new(
                        "execution-exhausted",
                        "component exceeded an execution bound",
                    ))
                }
                Err(error) => CoreOutcome::Failed(CoreFailure::new(
                    "component-failed",
                    format!("component invocation failed: {error:#}"),
                )),
            };
            (outcome, Some(descriptor))
        }
    };
    let finished_at_ms = substrate.tick();
    let outcome_digest = Digest::of(&canonical_json(&outcome).unwrap_or_default());
    let executor = descriptor
        .as_ref()
        .map_or(request.component_digest, |value| value.authority_digest);
    let completion = CoreCompletion {
        run_id: request.run_id.clone(),
        outcome,
        receipt: CoreReceipt {
            receipt_id: format!("receipt-{}", request.idempotency_key.hex()),
            request_digest,
            executor_digest: executor,
            started_at_ms,
            finished_at_ms,
            outcome_digest,
            audit_sequence: 0,
        },
    };
    let provenance = descriptor.map_or_else(
        || Provenance {
            graph_manifest_digest: substrate.release.index.graph_manifest_digest,
            authority_component_digest: request.component_digest,
            executable_component_digest: request.component_digest,
            source_component_digests: Vec::new(),
            caller_principal_seed,
        },
        |value| Provenance {
            graph_manifest_digest: substrate.release.index.graph_manifest_digest,
            authority_component_digest: value.authority_digest,
            executable_component_digest: value.executable_digest,
            source_component_digests: value.source_digests,
            caller_principal_seed,
        },
    );
    (completion, provenance)
}

macro_rules! failure_to_wit {
    ($bindings:ident, $failure:expr) => {{
        let failure = $failure;
        $bindings::wasm_biotic::factory::foundation::Failure {
            code: failure.code,
            message: failure.message,
            retryable: failure.retryable,
            evidence: failure.evidence.map(|blob| blob_to_wit!($bindings, blob)),
        }
    }};
}

macro_rules! outcome_to_wit {
    ($bindings:ident, $outcome:expr) => {
        match $outcome {
            CoreOutcome::Succeeded(blob) => {
                $bindings::wasm_biotic::factory::foundation::TerminalOutcome::Succeeded(
                    blob_to_wit!($bindings, blob),
                )
            }
            CoreOutcome::Rejected(error) => {
                $bindings::wasm_biotic::factory::foundation::TerminalOutcome::Rejected(
                    failure_to_wit!($bindings, error),
                )
            }
            CoreOutcome::Failed(error) => {
                $bindings::wasm_biotic::factory::foundation::TerminalOutcome::Failed(
                    failure_to_wit!($bindings, error),
                )
            }
            CoreOutcome::Cancelled => {
                $bindings::wasm_biotic::factory::foundation::TerminalOutcome::Cancelled
            }
            CoreOutcome::Exhausted(error) => {
                $bindings::wasm_biotic::factory::foundation::TerminalOutcome::Exhausted(
                    failure_to_wit!($bindings, error),
                )
            }
        }
    };
}

macro_rules! receipt_to_wit {
    ($bindings:ident, $receipt:expr) => {{
        let receipt = $receipt;
        $bindings::wasm_biotic::factory::foundation::EffectReceipt {
            receipt_id: receipt.receipt_id,
            request_digest: digest_to_wit!($bindings, receipt.request_digest),
            executor_digest: digest_to_wit!($bindings, receipt.executor_digest),
            started_at_ms: receipt.started_at_ms,
            finished_at_ms: receipt.finished_at_ms,
            outcome_digest: digest_to_wit!($bindings, receipt.outcome_digest),
            audit_sequence: receipt.audit_sequence,
        }
    }};
}

macro_rules! completion_to_wit {
    ($bindings:ident, $completion:expr) => {{
        let completion = $completion;
        $bindings::wasm_biotic::factory::component_runner::RunCompletion {
            run_id: completion.run_id,
            outcome: outcome_to_wit!($bindings, completion.outcome),
            receipt: receipt_to_wit!($bindings, completion.receipt),
        }
    }};
}

macro_rules! impl_boundary {
    ($bindings:ident) => {
        impl $bindings::wasm_biotic::factory::foundation::Host for HostState {}

        impl $bindings::wasm_biotic::factory::blob_store::Host for HostState {
            fn put(
                &mut self,
                media_type: String,
                content: Vec<u8>,
            ) -> std::result::Result<
                $bindings::wasm_biotic::factory::foundation::BlobRef,
                $bindings::wasm_biotic::factory::foundation::Failure,
            > {
                if !self.access.blob_write {
                    return Err(failure_to_wit!(
                        $bindings,
                        CoreFailure::new("not-granted", "blob write is not granted")
                    ));
                }
                self.substrate
                    .put(media_type, content)
                    .map(|blob| blob_to_wit!($bindings, blob))
                    .map_err(|error| failure_to_wit!($bindings, error))
            }

            fn get(
                &mut self,
                reference: $bindings::wasm_biotic::factory::foundation::BlobRef,
            ) -> std::result::Result<Vec<u8>, $bindings::wasm_biotic::factory::foundation::Failure>
            {
                if !self.access.blob_read {
                    return Err(failure_to_wit!(
                        $bindings,
                        CoreFailure::new("not-granted", "blob read is not granted")
                    ));
                }
                let reference = wit_blob_to_core!(reference)
                    .map_err(|error| failure_to_wit!($bindings, error))?;
                self.substrate
                    .get(&reference)
                    .map_err(|error| failure_to_wit!($bindings, error))
            }

            fn has(
                &mut self,
                digest: $bindings::wasm_biotic::factory::foundation::Digest,
            ) -> std::result::Result<bool, $bindings::wasm_biotic::factory::foundation::Failure>
            {
                if !self.access.blob_read {
                    return Err(failure_to_wit!(
                        $bindings,
                        CoreFailure::new("not-granted", "blob read is not granted")
                    ));
                }
                let digest = validate_digest_hex(&digest.hex)
                    .map_err(|error| failure_to_wit!($bindings, error))?;
                Ok(self.substrate.has(digest))
            }
        }

        impl $bindings::wasm_biotic::factory::transaction_store::Host for HostState {
            fn read(
                &mut self,
                namespace: String,
                key: String,
            ) -> std::result::Result<
                Option<$bindings::wasm_biotic::factory::transaction_store::VersionedValue>,
                $bindings::wasm_biotic::factory::foundation::Failure,
            > {
                if !self.access.transaction_namespaces.contains(&namespace) {
                    return Err(failure_to_wit!(
                        $bindings,
                        CoreFailure::new("not-granted", "transaction namespace is not granted")
                    ));
                }
                Ok(self
                    .substrate
                    .memory
                    .borrow()
                    .transactions
                    .get(&(namespace, key))
                    .map(|value| {
                        $bindings::wasm_biotic::factory::transaction_store::VersionedValue {
                            version: value.version,
                            value: blob_to_wit!($bindings, value.value.clone()),
                        }
                    }))
            }

            fn commit(
                &mut self,
                request: $bindings::wasm_biotic::factory::transaction_store::CommitRequest,
            ) -> std::result::Result<
                $bindings::wasm_biotic::factory::transaction_store::CommitReceipt,
                $bindings::wasm_biotic::factory::foundation::Failure,
            > {
                let idempotency = validate_digest_hex(&request.idempotency_key.hex)
                    .map_err(|error| failure_to_wit!($bindings, error))?;
                let request_bytes = serde_json::to_vec(&request).map_err(|_| {
                    failure_to_wit!(
                        $bindings,
                        CoreFailure::new(
                            "encoding-error",
                            "transaction request could not be encoded"
                        )
                    )
                })?;
                let request_digest = Digest::of(&request_bytes);
                let owner = self.caller();
                {
                    let memory = self.substrate.memory.borrow();
                    if let Some(existing) = memory.commits.get(&idempotency) {
                        if existing.owner != owner {
                            return Err(failure_to_wit!(
                                $bindings,
                                CoreFailure::new(
                                    "not-owned",
                                    "transaction idempotency key belongs to another principal"
                                )
                            ));
                        }
                        if existing.request_digest != request_digest {
                            return Err(failure_to_wit!(
                                $bindings,
                                CoreFailure::new(
                                    "idempotency-conflict",
                                    "idempotency key was reused"
                                )
                            ));
                        }
                        return Ok(
                            $bindings::wasm_biotic::factory::transaction_store::CommitReceipt {
                                transaction_id: existing.transaction_id.clone(),
                                commit_version: existing.commit_version,
                                committed_value_digest: digest_to_wit!(
                                    $bindings,
                                    existing.committed_value_digest
                                ),
                            },
                        );
                    }
                }
                for assertion in &request.assertions {
                    if !self
                        .access
                        .transaction_namespaces
                        .contains(&assertion.namespace)
                    {
                        return Err(failure_to_wit!(
                            $bindings,
                            CoreFailure::new(
                                "not-granted",
                                "transaction assertion escapes namespace grant"
                            )
                        ));
                    }
                    let actual = self
                        .substrate
                        .memory
                        .borrow()
                        .transactions
                        .get(&(assertion.namespace.clone(), assertion.key.clone()))
                        .map(|value| value.version);
                    if actual != assertion.expected_version {
                        return Err(failure_to_wit!(
                            $bindings,
                            CoreFailure::new(
                                "assertion-failed",
                                "transaction version assertion failed"
                            )
                        ));
                    }
                }
                let mut mutations = Vec::new();
                for mutation in request.mutations {
                    match mutation {
                        $bindings::wasm_biotic::factory::transaction_store::Mutation::Put((
                            namespace,
                            key,
                            value,
                        )) => {
                            if !self.access.transaction_namespaces.contains(&namespace) {
                                return Err(failure_to_wit!(
                                    $bindings,
                                    CoreFailure::new(
                                        "not-granted",
                                        "transaction mutation escapes namespace grant"
                                    )
                                ));
                            }
                            let value = wit_blob_to_core!(value)
                                .map_err(|error| failure_to_wit!($bindings, error))?;
                            self.substrate
                                .get(&value)
                                .map_err(|error| failure_to_wit!($bindings, error))?;
                            mutations.push((namespace, key, Some(value)));
                        }
                        $bindings::wasm_biotic::factory::transaction_store::Mutation::Delete((
                            namespace,
                            key,
                        )) => {
                            if !self.access.transaction_namespaces.contains(&namespace) {
                                return Err(failure_to_wit!(
                                    $bindings,
                                    CoreFailure::new(
                                        "not-granted",
                                        "transaction mutation escapes namespace grant"
                                    )
                                ));
                            }
                            mutations.push((namespace, key, None));
                        }
                    }
                }
                let mut memory = self.substrate.memory.borrow_mut();
                memory.commit_version = memory.commit_version.saturating_add(1);
                let version = memory.commit_version;
                for (namespace, key, value) in mutations {
                    if let Some(value) = value {
                        memory
                            .transactions
                            .insert((namespace, key), VersionedBlob { version, value });
                    } else {
                        memory.transactions.remove(&(namespace, key));
                    }
                }
                let committed_value_digest = Digest::of(&request_bytes);
                let record = CommitRecord {
                    owner,
                    request_digest,
                    transaction_id: request.transaction_id.clone(),
                    commit_version: version,
                    committed_value_digest,
                };
                memory.commits.insert(idempotency, record);
                Ok(
                    $bindings::wasm_biotic::factory::transaction_store::CommitReceipt {
                        transaction_id: request.transaction_id,
                        commit_version: version,
                        committed_value_digest: digest_to_wit!($bindings, committed_value_digest),
                    },
                )
            }
        }

        impl $bindings::wasm_biotic::factory::clock::Host for HostState {
            fn now_ms(&mut self) -> u64 {
                if self.access.clock {
                    self.substrate.now()
                } else {
                    0
                }
            }

            fn schedule_wake(
                &mut self,
                request: $bindings::wasm_biotic::factory::clock::WakeRequest,
            ) -> std::result::Result<u64, $bindings::wasm_biotic::factory::foundation::Failure>
            {
                if !self.access.clock {
                    return Err(failure_to_wit!(
                        $bindings,
                        CoreFailure::new("not-granted", "clock is not granted")
                    ));
                }
                let target_component = validate_digest_hex(&request.target_component.hex)
                    .map_err(|error| failure_to_wit!($bindings, error))?;
                let payload_digest = validate_digest_hex(&request.payload_digest.hex)
                    .map_err(|error| failure_to_wit!($bindings, error))?;
                let idempotency_key = validate_digest_hex(&request.idempotency_key.hex)
                    .map_err(|error| failure_to_wit!($bindings, error))?;
                let now = self.substrate.now();
                if request.not_before_ms.saturating_sub(now)
                    > self.substrate.release.profile.ceilings.max_wake_delay_ms
                {
                    return Err(failure_to_wit!(
                        $bindings,
                        CoreFailure::new("limit-exceeded", "wake delay exceeds release ceiling")
                    ));
                }
                let wake = Wake {
                    owner: self.caller(),
                    not_before_ms: request.not_before_ms,
                    target_component,
                    payload_digest,
                    idempotency_key,
                };
                let mut memory = self.substrate.memory.borrow_mut();
                if let Some(existing) = memory.wakes.get(&request.wake_id) {
                    if existing.owner != wake.owner {
                        return Err(failure_to_wit!(
                            $bindings,
                            CoreFailure::new("not-owned", "wake belongs to another principal")
                        ));
                    }
                    if existing.not_before_ms != wake.not_before_ms
                        || existing.target_component != wake.target_component
                        || existing.payload_digest != wake.payload_digest
                        || existing.idempotency_key != wake.idempotency_key
                    {
                        return Err(failure_to_wit!(
                            $bindings,
                            CoreFailure::new("idempotency-conflict", "wake id was reused")
                        ));
                    }
                } else {
                    memory.wakes.insert(request.wake_id, wake);
                }
                Ok(request.not_before_ms)
            }

            fn poll_wake(
                &mut self,
                wake_id: String,
            ) -> std::result::Result<
                Option<$bindings::wasm_biotic::factory::clock::FiredWake>,
                $bindings::wasm_biotic::factory::foundation::Failure,
            > {
                if !self.access.clock {
                    return Err(failure_to_wit!(
                        $bindings,
                        CoreFailure::new("not-granted", "clock is not granted")
                    ));
                }
                let memory = self.substrate.memory.borrow();
                if memory
                    .wakes
                    .get(&wake_id)
                    .is_some_and(|wake| !self.caller_owns(wake.owner))
                {
                    return Err(failure_to_wit!(
                        $bindings,
                        CoreFailure::new("not-owned", "wake belongs to another principal")
                    ));
                }
                Ok(memory.wakes.get(&wake_id).and_then(|wake| {
                    (memory.clock_ms >= wake.not_before_ms).then(|| {
                        $bindings::wasm_biotic::factory::clock::FiredWake {
                            wake_id,
                            fired_at_ms: memory.clock_ms,
                            payload_digest: digest_to_wit!($bindings, wake.payload_digest),
                        }
                    })
                }))
            }

            fn cancel_wake(
                &mut self,
                wake_id: String,
            ) -> std::result::Result<bool, $bindings::wasm_biotic::factory::foundation::Failure>
            {
                if !self.access.clock {
                    return Err(failure_to_wit!(
                        $bindings,
                        CoreFailure::new("not-granted", "clock is not granted")
                    ));
                }
                let mut memory = self.substrate.memory.borrow_mut();
                if memory
                    .wakes
                    .get(&wake_id)
                    .is_some_and(|wake| !self.caller_owns(wake.owner))
                {
                    return Err(failure_to_wit!(
                        $bindings,
                        CoreFailure::new("not-owned", "wake belongs to another principal")
                    ));
                }
                Ok(memory.wakes.remove(&wake_id).is_some())
            }
        }

        impl $bindings::wasm_biotic::factory::component_runner::Host for HostState {
            fn start(
                &mut self,
                request: $bindings::wasm_biotic::factory::component_runner::RunRequest,
            ) -> std::result::Result<String, $bindings::wasm_biotic::factory::foundation::Failure>
            {
                if !self.access.component_runner {
                    return Err(failure_to_wit!(
                        $bindings,
                        CoreFailure::new("not-granted", "component runner is not granted")
                    ));
                }
                let core = CoreRunRequest {
                    run_id: request.run_id,
                    component_digest: validate_digest_hex(&request.component_digest.hex)
                        .map_err(|error| failure_to_wit!($bindings, error))?,
                    input: wit_blob_to_core!(request.input)
                        .map_err(|error| failure_to_wit!($bindings, error))?,
                    grants: request
                        .grants
                        .into_iter()
                        .map(|grant| {
                            Ok(CoreGrant {
                                capability: grant.capability,
                                scope: grant.scope,
                                constraints: match grant.constraints {
                                    Some(reference) => Some(wit_blob_to_core!(reference)?),
                                    None => None,
                                },
                            })
                        })
                        .collect::<std::result::Result<Vec<_>, CoreFailure>>()
                        .map_err(|error| failure_to_wit!($bindings, error))?,
                    limits: CoreLimits {
                        fuel: request.limits.fuel,
                        memory_bytes: request.limits.memory_bytes,
                        output_bytes: request.limits.output_bytes,
                        wall_time_ms: request.limits.wall_time_ms,
                    },
                    idempotency_key: validate_digest_hex(&request.idempotency_key.hex)
                        .map_err(|error| failure_to_wit!($bindings, error))?,
                };
                let request_digest = Digest::of(&canonical_json(&core).unwrap_or_default());
                let operation_id = format!("operation-{}", core.idempotency_key.hex());
                if !self.caller_may_run(core.component_digest) {
                    return Err(failure_to_wit!(
                        $bindings,
                        CoreFailure::new(
                            "not-granted",
                            "caller has no invocation edge to the target component"
                        )
                    ));
                }
                let owner = self.caller();
                if let Some(existing) = self.runs.get(&operation_id) {
                    if existing.owner != owner {
                        return Err(failure_to_wit!(
                            $bindings,
                            CoreFailure::new(
                                "not-owned",
                                "run idempotency key belongs to another principal"
                            )
                        ));
                    }
                    if existing.request_digest != request_digest {
                        return Err(failure_to_wit!(
                            $bindings,
                            CoreFailure::new("idempotency-conflict", "run key was reused")
                        ));
                    }
                    return Ok(operation_id);
                }
                let (completion, provenance) =
                    execute_dynamic(self.substrate.clone(), &core, owner);
                self.runs.insert(
                    operation_id.clone(),
                    RunRecord {
                        owner,
                        request_digest,
                        completion,
                        provenance,
                    },
                );
                Ok(operation_id)
            }

            fn poll(
                &mut self,
                operation_id: String,
            ) -> std::result::Result<
                Option<$bindings::wasm_biotic::factory::component_runner::RunCompletion>,
                $bindings::wasm_biotic::factory::foundation::Failure,
            > {
                if !self.access.component_runner {
                    return Err(failure_to_wit!(
                        $bindings,
                        CoreFailure::new("not-granted", "component runner is not granted")
                    ));
                }
                if self
                    .runs
                    .get(&operation_id)
                    .is_some_and(|record| !self.caller_owns(record.owner))
                {
                    return Err(failure_to_wit!(
                        $bindings,
                        CoreFailure::new("not-owned", "run belongs to another principal")
                    ));
                }
                Ok(self
                    .runs
                    .get(&operation_id)
                    .cloned()
                    .map(|record| completion_to_wit!($bindings, record.completion)))
            }

            fn cancel(
                &mut self,
                operation_id: String,
            ) -> std::result::Result<bool, $bindings::wasm_biotic::factory::foundation::Failure>
            {
                if !self.access.component_runner {
                    return Err(failure_to_wit!(
                        $bindings,
                        CoreFailure::new("not-granted", "component runner is not granted")
                    ));
                }
                if self
                    .runs
                    .get(&operation_id)
                    .is_some_and(|record| !self.caller_owns(record.owner))
                {
                    return Err(failure_to_wit!(
                        $bindings,
                        CoreFailure::new("not-owned", "run belongs to another principal")
                    ));
                }
                Ok(self.runs.remove(&operation_id).is_some())
            }
        }

        impl $bindings::wasm_biotic::factory::http_transport::Host for HostState {
            fn start(
                &mut self,
                request: $bindings::wasm_biotic::factory::http_transport::Request,
            ) -> std::result::Result<String, $bindings::wasm_biotic::factory::foundation::Failure>
            {
                if !self.access.http_transport {
                    return Err(failure_to_wit!(
                        $bindings,
                        CoreFailure::new("not-granted", "HTTP transport is not granted")
                    ));
                }
                if self.substrate.release.profile.schema
                    != "wasm-biotic.factory-substrate-profile.v3"
                {
                    return Err(failure_to_wit!(
                        $bindings,
                        CoreFailure::new(
                            "transport-unavailable",
                            "independent in-memory substrate has no configured HTTP peer"
                        )
                    ));
                }
                let owner = self
                    .transport_owner()
                    .map_err(|failure| failure_to_wit!($bindings, failure))?;
                let body = request
                    .body
                    .map(|reference| {
                        let reference = wit_blob_to_core!(reference)?;
                        self.substrate.get(&reference)
                    })
                    .transpose()
                    .map_err(|failure| failure_to_wit!($bindings, failure))?;
                let method = match request.method {
                    $bindings::wasm_biotic::factory::http_transport::Method::Get => "get",
                    $bindings::wasm_biotic::factory::http_transport::Method::Head => "head",
                    $bindings::wasm_biotic::factory::http_transport::Method::Post => "post",
                    $bindings::wasm_biotic::factory::http_transport::Method::Put => "put",
                    $bindings::wasm_biotic::factory::http_transport::Method::Patch => "patch",
                    $bindings::wasm_biotic::factory::http_transport::Method::Delete => "delete",
                };
                let idempotency_key = validate_digest_hex(&request.idempotency_key.hex)
                    .map_err(|failure| failure_to_wit!($bindings, failure))?;
                let request = TransportRequest {
                    request_id: request.request_id,
                    method: method.to_string(),
                    url: request.url,
                    headers: request
                        .headers
                        .into_iter()
                        .map(|header| TransportHeader {
                            name: header.name,
                            value: header.value,
                        })
                        .collect(),
                    body,
                    timeout_ms: request.timeout_ms,
                    idempotency_key,
                    credential_handle: request.credential_handle,
                };
                self.substrate
                    .transport
                    .start(owner, request)
                    .map_err(|failure| {
                        failure_to_wit!($bindings, transport_failure_to_core(failure))
                    })
            }

            fn poll(
                &mut self,
                operation_id: String,
            ) -> std::result::Result<
                Option<$bindings::wasm_biotic::factory::http_transport::Response>,
                $bindings::wasm_biotic::factory::foundation::Failure,
            > {
                if !self.access.http_transport {
                    return Err(failure_to_wit!(
                        $bindings,
                        CoreFailure::new("not-granted", "HTTP transport is not granted")
                    ));
                }
                if self.substrate.release.profile.schema
                    != "wasm-biotic.factory-substrate-profile.v3"
                {
                    return Ok(None);
                }
                let owner = self
                    .transport_owner()
                    .map_err(|failure| failure_to_wit!($bindings, failure))?;
                match self
                    .substrate
                    .transport
                    .poll(&owner, &operation_id)
                    .map_err(|failure| {
                        failure_to_wit!($bindings, transport_failure_to_core(failure))
                    })? {
                    TransportPoll::Pending => Ok(None),
                    TransportPoll::Completed(response) => {
                        let body = response
                            .body
                            .map(|bytes| {
                                self.substrate
                                    .put("application/octet-stream".to_string(), bytes)
                            })
                            .transpose()
                            .map_err(|_| {
                                failure_to_wit!(
                                    $bindings,
                                    CoreFailure::new(
                                        "transport-outcome-unknown",
                                        "HTTP response completed but its body could not be persisted"
                                    )
                                )
                            })?;
                        Ok(Some(
                            $bindings::wasm_biotic::factory::http_transport::Response {
                                status: response.status,
                                headers: response
                                    .headers
                                    .into_iter()
                                    .map(|header| {
                                        $bindings::wasm_biotic::factory::http_transport::Header {
                                            name: header.name,
                                            value: header.value,
                                        }
                                    })
                                    .collect(),
                                body: body.map(|reference| blob_to_wit!($bindings, reference)),
                                receipt:
                                    $bindings::wasm_biotic::factory::foundation::EffectReceipt {
                                        receipt_id: response.receipt.receipt_id,
                                        request_digest: digest_to_wit!(
                                            $bindings,
                                            response.receipt.request_digest
                                        ),
                                        executor_digest: digest_to_wit!(
                                            $bindings,
                                            response.receipt.executor_digest
                                        ),
                                        started_at_ms: response.receipt.started_at_ms,
                                        finished_at_ms: response.receipt.finished_at_ms,
                                        outcome_digest: digest_to_wit!(
                                            $bindings,
                                            response.receipt.outcome_digest
                                        ),
                                        audit_sequence: response.receipt.audit_sequence,
                                    },
                            },
                        ))
                    }
                    TransportPoll::DefiniteFailure(failure)
                    | TransportPoll::Indeterminate(failure) => Err(failure_to_wit!(
                        $bindings,
                        transport_failure_to_core(failure)
                    )),
                    TransportPoll::CancelledBeforeDispatch => Err(failure_to_wit!(
                        $bindings,
                        CoreFailure::new(
                            "transport-cancelled-before-dispatch",
                            "HTTP operation was cancelled before dispatch"
                        )
                    )),
                }
            }

            fn cancel(
                &mut self,
                operation_id: String,
            ) -> std::result::Result<bool, $bindings::wasm_biotic::factory::foundation::Failure>
            {
                if !self.access.http_transport {
                    return Err(failure_to_wit!(
                        $bindings,
                        CoreFailure::new("not-granted", "HTTP transport is not granted")
                    ));
                }
                if self.substrate.release.profile.schema
                    != "wasm-biotic.factory-substrate-profile.v3"
                {
                    return Ok(false);
                }
                let owner = self
                    .transport_owner()
                    .map_err(|failure| failure_to_wit!($bindings, failure))?;
                self.substrate
                    .transport
                    .cancel(&owner, &operation_id)
                    .map_err(|failure| {
                        failure_to_wit!($bindings, transport_failure_to_core(failure))
                    })
            }
        }

        impl $bindings::wasm_biotic::factory::key_service::Host for HostState {
            fn sign_digest(
                &mut self,
                key_handle: String,
                payload: $bindings::wasm_biotic::factory::foundation::Digest,
            ) -> std::result::Result<
                $bindings::wasm_biotic::factory::key_service::Signature,
                $bindings::wasm_biotic::factory::foundation::Failure,
            > {
                if !self.access.key_service {
                    return Err(failure_to_wit!(
                        $bindings,
                        CoreFailure::new("not-granted", "key service is not granted")
                    ));
                }
                let digest = validate_digest_hex(&payload.hex)
                    .map_err(|error| failure_to_wit!($bindings, error))?;
                let memory = self.substrate.memory.borrow();
                let seed = memory.signing_seeds.get(&key_handle).ok_or_else(|| {
                    failure_to_wit!(
                        $bindings,
                        CoreFailure::new("unknown-key-handle", "signing key handle is absent")
                    )
                })?;
                let pair = Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| {
                    failure_to_wit!(
                        $bindings,
                        CoreFailure::new("key-failure", "signing key could not be loaded")
                    )
                })?;
                let key_id = Digest::of(pair.public_key().as_ref()).to_string();
                Ok($bindings::wasm_biotic::factory::key_service::Signature {
                    key_id,
                    algorithm:
                        $bindings::wasm_biotic::factory::key_service::SignatureAlgorithm::Ed25519,
                    bytes: pair.sign(&digest.0).as_ref().to_vec(),
                })
            }

            fn verify_digest(
                &mut self,
                key_id: String,
                payload: $bindings::wasm_biotic::factory::foundation::Digest,
                signature: $bindings::wasm_biotic::factory::key_service::Signature,
            ) -> std::result::Result<bool, $bindings::wasm_biotic::factory::foundation::Failure>
            {
                if !self.access.key_service {
                    return Err(failure_to_wit!(
                        $bindings,
                        CoreFailure::new("not-granted", "key service is not granted")
                    ));
                }
                if signature.key_id != key_id {
                    return Ok(false);
                }
                let digest = validate_digest_hex(&payload.hex)
                    .map_err(|error| failure_to_wit!($bindings, error))?;
                let memory = self.substrate.memory.borrow();
                let Some(public_key) = memory.verification_keys.get(&key_id) else {
                    return Ok(false);
                };
                Ok(UnparsedPublicKey::new(&ED25519, public_key)
                    .verify(&digest.0, &signature.bytes)
                    .is_ok())
            }

            fn random_bytes(
                &mut self,
                length: u32,
            ) -> std::result::Result<Vec<u8>, $bindings::wasm_biotic::factory::foundation::Failure>
            {
                if !self.access.key_service {
                    return Err(failure_to_wit!(
                        $bindings,
                        CoreFailure::new("not-granted", "key service is not granted")
                    ));
                }
                if length > self.substrate.release.profile.ceilings.max_random_bytes {
                    return Err(failure_to_wit!(
                        $bindings,
                        CoreFailure::new(
                            "limit-exceeded",
                            "entropy request exceeds release ceiling"
                        )
                    ));
                }
                let mut bytes = vec![0_u8; length as usize];
                self.substrate
                    .memory
                    .borrow()
                    .entropy
                    .fill(&mut bytes)
                    .map_err(|_| {
                        failure_to_wit!(
                            $bindings,
                            CoreFailure::new("entropy-failure", "OS entropy failed")
                        )
                    })?;
                Ok(bytes)
            }
        }

        impl $bindings::wasm_biotic::factory::activation::Host for HostState {
            fn active_manifest(
                &mut self,
            ) -> std::result::Result<
                Option<$bindings::wasm_biotic::factory::foundation::BlobRef>,
                $bindings::wasm_biotic::factory::foundation::Failure,
            > {
                if !self.access.activation {
                    return Err(failure_to_wit!(
                        $bindings,
                        CoreFailure::new("not-granted", "activation is not granted")
                    ));
                }
                Ok(Some(blob_to_wit!(
                    $bindings,
                    self.substrate.memory.borrow().active_manifest.clone()
                )))
            }

            fn active_state(
                &mut self,
            ) -> std::result::Result<
                Option<$bindings::wasm_biotic::factory::foundation::BlobRef>,
                $bindings::wasm_biotic::factory::foundation::Failure,
            > {
                if !self.access.activation {
                    return Err(failure_to_wit!(
                        $bindings,
                        CoreFailure::new("not-granted", "activation is not granted")
                    ));
                }
                Ok(self
                    .substrate
                    .memory
                    .borrow()
                    .active_state
                    .clone()
                    .map(|blob| blob_to_wit!($bindings, blob)))
            }

            fn stage(
                &mut self,
                request: $bindings::wasm_biotic::factory::activation::ActivationRequest,
            ) -> std::result::Result<
                $bindings::wasm_biotic::factory::activation::ActivationStatus,
                $bindings::wasm_biotic::factory::foundation::Failure,
            > {
                if !self.access.activation {
                    return Err(failure_to_wit!(
                        $bindings,
                        CoreFailure::new("not-granted", "activation is not granted")
                    ));
                }
                let request_digest = Digest::of(&serde_json::to_vec(&request).unwrap_or_default());
                let owner = if matches!(
                    self.substrate.release.profile.schema.as_str(),
                    "wasm-biotic.factory-substrate-profile.v2"
                        | "wasm-biotic.factory-substrate-profile.v3"
                ) {
                    Some(self.activation_caller().ok_or_else(|| {
                        failure_to_wit!(
                            $bindings,
                            CoreFailure::new(
                                "not-granted",
                                "R2 activation requires a linker-bound principal"
                            )
                        )
                    })?)
                } else {
                    None
                };
                let graph_manifest = wit_blob_to_core!(request.graph_manifest)
                    .map_err(|error| failure_to_wit!($bindings, error))?;
                self.substrate
                    .get(&graph_manifest)
                    .map_err(|error| failure_to_wit!($bindings, error))?;
                let expected_graph = request
                    .expected_active_graph
                    .map(|digest| validate_digest_hex(&digest.hex))
                    .transpose()
                    .map_err(|error| failure_to_wit!($bindings, error))?;
                let expected_state = request
                    .expected_active_state
                    .map(|blob| wit_blob_to_core!(blob))
                    .transpose()
                    .map_err(|error| failure_to_wit!($bindings, error))?;
                let migrated_state = request
                    .migrated_state
                    .map(|blob| wit_blob_to_core!(blob))
                    .transpose()
                    .map_err(|error| failure_to_wit!($bindings, error))?;
                if let Some(state) = &migrated_state {
                    self.substrate
                        .get(state)
                        .map_err(|error| failure_to_wit!($bindings, error))?;
                }
                let mut memory = self.substrate.memory.borrow_mut();
                if let Some(owner) = owner {
                    if owner.graph_manifest_digest != memory.active_graph
                        || !memory
                            .admitted_activation_principal_seeds
                            .get(&owner.graph_manifest_digest)
                            .is_some_and(|seeds| seeds.contains(&owner.principal_seed))
                    {
                        return Err(failure_to_wit!(
                            $bindings,
                            CoreFailure::new(
                                "stale-principal",
                                "activation caller is not owned by the active graph"
                            )
                        ));
                    }
                }
                if expected_graph.is_some_and(|expected| expected != memory.active_graph)
                    || expected_state != memory.active_state
                {
                    return Err(failure_to_wit!(
                        $bindings,
                        CoreFailure::new(
                            "activation-cas-failed",
                            "active graph or state differs from expectation"
                        )
                    ));
                }
                if !memory
                    .admitted_manifests
                    .contains_key(&graph_manifest.digest)
                {
                    return Err(failure_to_wit!(
                        $bindings,
                        CoreFailure::new("not-admitted", "target manifest is not admitted")
                    ));
                }
                if request.state_migration.is_some() != migrated_state.is_some() {
                    return Err(failure_to_wit!(
                        $bindings,
                        CoreFailure::new(
                            "invalid-migration",
                            "migration digest and migrated state must appear together"
                        )
                    ));
                }
                if let Some(existing) = memory.activations.get(&request.activation_id) {
                    if existing.owner != owner {
                        return Err(failure_to_wit!(
                            $bindings,
                            CoreFailure::new(
                                "not-owned",
                                "activation id belongs to another principal"
                            )
                        ));
                    }
                    if existing.request_digest != request_digest {
                        return Err(failure_to_wit!(
                            $bindings,
                            CoreFailure::new("idempotency-conflict", "activation id was reused")
                        ));
                    }
                    return Ok(activation_status_to_wit!($bindings, existing, &memory));
                }
                let activation = CoreActivation {
                    owner,
                    activation_id: request.activation_id.clone(),
                    state: ActivationState::Staged,
                    graph_manifest,
                    previous_graph: memory.active_graph,
                    previous_state: memory.active_state.clone(),
                    migrated_state,
                    request_digest,
                    receipt: None,
                };
                memory
                    .activations
                    .insert(request.activation_id.clone(), activation);
                let activation = memory
                    .activations
                    .get(&request.activation_id)
                    .expect("inserted activation");
                Ok(activation_status_to_wit!($bindings, activation, &memory))
            }

            fn commit(
                &mut self,
                activation_id: String,
            ) -> std::result::Result<
                $bindings::wasm_biotic::factory::activation::ActivationStatus,
                $bindings::wasm_biotic::factory::foundation::Failure,
            > {
                if !self.access.activation {
                    return Err(failure_to_wit!(
                        $bindings,
                        CoreFailure::new("not-granted", "activation is not granted")
                    ));
                }
                let mut memory = self.substrate.memory.borrow_mut();
                let Some(mut activation) = memory.activations.remove(&activation_id) else {
                    return Err(failure_to_wit!(
                        $bindings,
                        CoreFailure::new("unknown-activation", "activation id is absent")
                    ));
                };
                let caller = if activation.owner.is_some() {
                    self.activation_caller()
                } else {
                    None
                };
                if caller != activation.owner {
                    memory.activations.insert(activation_id, activation);
                    return Err(failure_to_wit!(
                        $bindings,
                        CoreFailure::new("not-owned", "activation belongs to another principal")
                    ));
                }
                if activation.state == ActivationState::Staged {
                    if let Some(owner) = activation.owner {
                        if owner.graph_manifest_digest != memory.active_graph
                            || activation.previous_graph != owner.graph_manifest_digest
                        {
                            memory.activations.insert(activation_id, activation);
                            return Err(failure_to_wit!(
                                $bindings,
                                CoreFailure::new(
                                    "stale-principal",
                                    "activation source graph is no longer active"
                                )
                            ));
                        }
                        let target = activation.graph_manifest.digest;
                        if !memory
                            .admitted_activation_principal_seeds
                            .get(&target)
                            .is_some_and(|seeds| seeds.contains(&owner.principal_seed))
                        {
                            memory.activations.insert(activation_id, activation);
                            return Err(failure_to_wit!(
                                $bindings,
                                CoreFailure::new(
                                    "not-owned",
                                    "target graph does not admit the same principal seed"
                                )
                            ));
                        }
                        activation.owner = Some(GraphPrincipalOwner {
                            graph_manifest_digest: target,
                            principal_seed: owner.principal_seed,
                        });
                    }
                    memory.active_manifest = activation.graph_manifest.clone();
                    memory.active_graph = activation.graph_manifest.digest;
                    memory.active_state = activation.migrated_state.clone();
                    activation.state = ActivationState::Active;
                    activation.receipt = Some(mechanism_receipt(
                        &mut memory,
                        "activation",
                        activation.request_digest,
                    ));
                }
                memory.activations.insert(activation_id.clone(), activation);
                let activation = memory
                    .activations
                    .get(&activation_id)
                    .expect("restored activation");
                Ok(activation_status_to_wit!($bindings, activation, &memory))
            }

            fn status(
                &mut self,
                activation_id: String,
            ) -> std::result::Result<
                $bindings::wasm_biotic::factory::activation::ActivationStatus,
                $bindings::wasm_biotic::factory::foundation::Failure,
            > {
                if !self.access.activation {
                    return Err(failure_to_wit!(
                        $bindings,
                        CoreFailure::new("not-granted", "activation is not granted")
                    ));
                }
                let memory = self.substrate.memory.borrow();
                let activation = memory.activations.get(&activation_id).ok_or_else(|| {
                    failure_to_wit!(
                        $bindings,
                        CoreFailure::new("unknown-activation", "activation id is absent")
                    )
                })?;
                let caller = if activation.owner.is_some() {
                    self.activation_caller()
                } else {
                    None
                };
                if caller != activation.owner {
                    return Err(failure_to_wit!(
                        $bindings,
                        CoreFailure::new("not-owned", "activation belongs to another principal")
                    ));
                }
                Ok(activation_status_to_wit!($bindings, activation, &memory))
            }

            fn rollback(
                &mut self,
                activation_id: String,
                target_graph: $bindings::wasm_biotic::factory::foundation::Digest,
            ) -> std::result::Result<
                $bindings::wasm_biotic::factory::activation::ActivationStatus,
                $bindings::wasm_biotic::factory::foundation::Failure,
            > {
                if !self.access.activation {
                    return Err(failure_to_wit!(
                        $bindings,
                        CoreFailure::new("not-granted", "activation is not granted")
                    ));
                }
                let target = validate_digest_hex(&target_graph.hex)
                    .map_err(|error| failure_to_wit!($bindings, error))?;
                let mut memory = self.substrate.memory.borrow_mut();
                let Some(mut activation) = memory.activations.remove(&activation_id) else {
                    return Err(failure_to_wit!(
                        $bindings,
                        CoreFailure::new("unknown-activation", "activation id is absent")
                    ));
                };
                let caller = if activation.owner.is_some() {
                    self.activation_caller()
                } else {
                    None
                };
                if caller != activation.owner {
                    memory.activations.insert(activation_id, activation);
                    return Err(failure_to_wit!(
                        $bindings,
                        CoreFailure::new("not-owned", "activation belongs to another principal")
                    ));
                }
                if target != activation.previous_graph {
                    memory.activations.insert(activation_id, activation);
                    return Err(failure_to_wit!(
                        $bindings,
                        CoreFailure::new(
                            "rollback-target-mismatch",
                            "rollback target differs from staged predecessor"
                        )
                    ));
                }
                let Some(manifest) = memory.admitted_manifests.get(&target).cloned() else {
                    memory.activations.insert(activation_id, activation);
                    return Err(failure_to_wit!(
                        $bindings,
                        CoreFailure::new("not-admitted", "rollback target is not admitted")
                    ));
                };
                if let Some(owner) = activation.owner {
                    if activation.state == ActivationState::RolledBack {
                        memory.activations.insert(activation_id.clone(), activation);
                        let activation = memory
                            .activations
                            .get(&activation_id)
                            .expect("restored activation");
                        return Ok(activation_status_to_wit!($bindings, activation, &memory));
                    }
                    if activation.state != ActivationState::Active
                        || owner.graph_manifest_digest != memory.active_graph
                        || owner.graph_manifest_digest != activation.graph_manifest.digest
                    {
                        memory.activations.insert(activation_id, activation);
                        return Err(failure_to_wit!(
                            $bindings,
                            CoreFailure::new(
                                "stale-principal",
                                "rollback caller is not owned by the active target graph"
                            )
                        ));
                    }
                    if !memory
                        .admitted_activation_principal_seeds
                        .get(&target)
                        .is_some_and(|seeds| seeds.contains(&owner.principal_seed))
                    {
                        memory.activations.insert(activation_id, activation);
                        return Err(failure_to_wit!(
                            $bindings,
                            CoreFailure::new(
                                "not-owned",
                                "last-known-good graph does not admit the same principal seed"
                            )
                        ));
                    }
                    activation.owner = Some(GraphPrincipalOwner {
                        graph_manifest_digest: target,
                        principal_seed: owner.principal_seed,
                    });
                }
                memory.active_manifest = manifest;
                memory.active_graph = target;
                memory.active_state = activation.previous_state.clone();
                activation.state = ActivationState::RolledBack;
                memory.activations.insert(activation_id.clone(), activation);
                let activation = memory
                    .activations
                    .get(&activation_id)
                    .expect("restored activation");
                Ok(activation_status_to_wit!($bindings, activation, &memory))
            }
        }

        impl $bindings::wasm_biotic::factory::audit_log::Host for HostState {
            fn append(
                &mut self,
                entry: $bindings::wasm_biotic::factory::audit_log::AuditEntry,
            ) -> std::result::Result<
                $bindings::wasm_biotic::factory::audit_log::AuditReceipt,
                $bindings::wasm_biotic::factory::foundation::Failure,
            > {
                if !self.access.audit_append {
                    return Err(failure_to_wit!(
                        $bindings,
                        CoreFailure::new("not-granted", "audit append is not granted")
                    ));
                }
                let core = CoreAuditEntry {
                    event_id: entry.event_id,
                    actor_id: entry.actor.id,
                    actor_component: validate_digest_hex(&entry.actor.component_digest.hex)
                        .map_err(|error| failure_to_wit!($bindings, error))?,
                    event_type: entry.event_type,
                    payload: wit_blob_to_core!(entry.payload)
                        .map_err(|error| failure_to_wit!($bindings, error))?,
                    previous_entry: entry
                        .previous_entry
                        .map(|digest| validate_digest_hex(&digest.hex))
                        .transpose()
                        .map_err(|error| failure_to_wit!($bindings, error))?,
                    occurred_at_ms: entry.occurred_at_ms,
                    idempotency_key: validate_digest_hex(&entry.idempotency_key.hex)
                        .map_err(|error| failure_to_wit!($bindings, error))?,
                };
                self.substrate
                    .get(&core.payload)
                    .map_err(|error| failure_to_wit!($bindings, error))?;
                let bytes = canonical_json(&core).unwrap_or_default();
                let digest = Digest::of(&bytes);
                let mut memory = self.substrate.memory.borrow_mut();
                let owner = self.caller();
                if let Some((existing_owner, existing, sequence)) =
                    memory.audit_idempotency.get(&core.idempotency_key)
                {
                    if *existing_owner != owner {
                        return Err(failure_to_wit!(
                            $bindings,
                            CoreFailure::new(
                                "not-owned",
                                "audit idempotency key belongs to another principal"
                            )
                        ));
                    }
                    if *existing != digest {
                        return Err(failure_to_wit!(
                            $bindings,
                            CoreFailure::new("idempotency-conflict", "audit key was reused")
                        ));
                    }
                    return Ok($bindings::wasm_biotic::factory::audit_log::AuditReceipt {
                        sequence: *sequence,
                        entry_digest: digest_to_wit!($bindings, digest),
                    });
                }
                let expected_previous = memory.audits.last().map(|(digest, _)| *digest);
                if core.previous_entry != expected_previous {
                    return Err(failure_to_wit!(
                        $bindings,
                        CoreFailure::new("audit-chain-mismatch", "previous audit digest differs")
                    ));
                }
                let sequence = memory.audits.len() as u64 + 1;
                memory
                    .audit_idempotency
                    .insert(core.idempotency_key, (owner, digest, sequence));
                memory.audits.push((digest, core));
                Ok($bindings::wasm_biotic::factory::audit_log::AuditReceipt {
                    sequence,
                    entry_digest: digest_to_wit!($bindings, digest),
                })
            }

            fn resolve(
                &mut self,
                sequence: u64,
            ) -> std::result::Result<
                Option<$bindings::wasm_biotic::factory::audit_log::AuditEntry>,
                $bindings::wasm_biotic::factory::foundation::Failure,
            > {
                if !self.access.audit_read {
                    return Err(failure_to_wit!(
                        $bindings,
                        CoreFailure::new("not-granted", "audit read is not granted")
                    ));
                }
                let memory = self.substrate.memory.borrow();
                Ok(sequence
                    .checked_sub(1)
                    .and_then(|index| memory.audits.get(index as usize))
                    .map(
                        |(_, entry)| $bindings::wasm_biotic::factory::audit_log::AuditEntry {
                            event_id: entry.event_id.clone(),
                            actor: $bindings::wasm_biotic::factory::foundation::Principal {
                                id: entry.actor_id.clone(),
                                component_digest: digest_to_wit!($bindings, entry.actor_component),
                            },
                            event_type: entry.event_type.clone(),
                            payload: blob_to_wit!($bindings, entry.payload.clone()),
                            previous_entry: entry
                                .previous_entry
                                .map(|digest| digest_to_wit!($bindings, digest)),
                            occurred_at_ms: entry.occurred_at_ms,
                            idempotency_key: digest_to_wit!($bindings, entry.idempotency_key),
                        },
                    ))
            }
        }
    };
}

macro_rules! activation_status_to_wit {
    ($bindings:ident, $activation:expr, $memory:expr) => {{
        let activation = $activation;
        $bindings::wasm_biotic::factory::activation::ActivationStatus {
            activation_id: activation.activation_id.clone(),
            state: match activation.state {
                ActivationState::Staged => {
                    $bindings::wasm_biotic::factory::activation::ActivationState::Staged
                }
                ActivationState::Active => {
                    $bindings::wasm_biotic::factory::activation::ActivationState::Active
                }
                ActivationState::RolledBack => {
                    $bindings::wasm_biotic::factory::activation::ActivationState::RolledBack
                }
            },
            active_graph: Some(digest_to_wit!($bindings, $memory.active_graph)),
            active_state: $memory
                .active_state
                .clone()
                .map(|blob| blob_to_wit!($bindings, blob)),
            receipt: activation
                .receipt
                .clone()
                .map(|receipt| receipt_to_wit!($bindings, receipt)),
        }
    }};
}

fn mechanism_receipt(memory: &mut Memory, name: &str, request: Digest) -> CoreReceipt {
    let started = memory.clock_ms;
    memory.clock_ms = memory.clock_ms.saturating_add(1);
    let finished = memory.clock_ms;
    memory.clock_ms = memory.clock_ms.saturating_add(1);
    let executor = Digest::of(format!("wasm-biotic-mechanism:{name}").as_bytes());
    CoreReceipt {
        receipt_id: format!("receipt-{}", request.hex()),
        request_digest: request,
        executor_digest: executor,
        started_at_ms: started,
        finished_at_ms: finished,
        outcome_digest: Digest::of(b"ok"),
        audit_sequence: 0,
    }
}

impl_boundary!(root);
impl_boundary!(task);

pub fn root_engine() -> Result<Engine> {
    let mut config = Config::new();
    config.consume_fuel(true);
    config.epoch_interruption(true);
    Ok(Engine::new(&config)?)
}

pub fn root_store(engine: &Engine, state: HostState) -> Store<HostState> {
    let mut store = Store::new(engine, state);
    store.limiter(|state| &mut state.limits);
    store
}

pub fn add_root_to_linker(linker: &mut Linker<HostState>) -> Result<()> {
    root::FactoryRoot::add_to_linker::<_, HasSelf<_>>(linker, |state| state)
        .map_err(|error| -> AnyError { error.to_string().into() })
}

pub fn add_release_to_linker(
    linker: &mut Linker<HostState>,
    release: &LoadedRelease,
) -> Result<()> {
    if release.profile.schema == "wasm-biotic.factory-substrate-profile.v1" {
        return add_root_to_linker(linker);
    }
    add_r2_aliases_to_linker(linker, release)
}

macro_rules! alias_func {
    ($instance:expr, $name:literal, $alias:expr, ($($arg:ident : $ty:ty),* $(,)?), |$state:ident| $body:block) => {{
        let alias = $alias.to_string();
        $instance.func_wrap(
            $name,
            move |mut store: StoreContextMut<'_, HostState>, ($($arg,)*): ($($ty,)*)| {
                let result = store
                    .data_mut()
                    .with_alias(&alias, |$state| $body)?;
                Ok((result,))
            },
        )?;
    }};
}

fn add_r2_aliases_to_linker(linker: &mut Linker<HostState>, release: &LoadedRelease) -> Result<()> {
    for principal in &release.profile.principals {
        for import in &principal.host_imports {
            match import.capability.as_str() {
                "blob-store" => add_blob_alias(linker, &import.alias)?,
                "transaction-store" => add_transaction_alias(linker, &import.alias)?,
                "clock" => add_clock_alias(linker, &import.alias)?,
                "component-runner" => add_runner_alias(linker, &import.alias)?,
                "http-transport" => add_http_alias(linker, &import.alias)?,
                "key-service" => add_key_alias(linker, &import.alias)?,
                "activation" => add_activation_alias(linker, &import.alias)?,
                "audit-log" => add_audit_alias(linker, &import.alias)?,
                _ => return Err("R2 profile contains an unsupported capability alias".into()),
            }
        }
    }
    Ok(())
}

fn add_blob_alias(linker: &mut Linker<HostState>, alias: &str) -> Result<()> {
    let mut instance = linker.instance(alias)?;
    alias_func!(instance, "put", alias, (media_type: String, content: Vec<u8>), |state| {
        <HostState as root::wasm_biotic::factory::blob_store::Host>::put(
            state,
            media_type,
            content,
        )
    });
    alias_func!(
        instance,
        "get",
        alias,
        (reference: root::wasm_biotic::factory::foundation::BlobRef),
        |state| {
            <HostState as root::wasm_biotic::factory::blob_store::Host>::get(state, reference)
        }
    );
    alias_func!(
        instance,
        "has",
        alias,
        (digest: root::wasm_biotic::factory::foundation::Digest),
        |state| {
            <HostState as root::wasm_biotic::factory::blob_store::Host>::has(state, digest)
        }
    );
    Ok(())
}

fn add_transaction_alias(linker: &mut Linker<HostState>, alias: &str) -> Result<()> {
    let mut instance = linker.instance(alias)?;
    alias_func!(instance, "read", alias, (namespace: String, key: String), |state| {
        <HostState as root::wasm_biotic::factory::transaction_store::Host>::read(
            state, namespace, key,
        )
    });
    alias_func!(
        instance,
        "commit",
        alias,
        (request: root::wasm_biotic::factory::transaction_store::CommitRequest),
        |state| {
            <HostState as root::wasm_biotic::factory::transaction_store::Host>::commit(
                state, request,
            )
        }
    );
    Ok(())
}

fn add_clock_alias(linker: &mut Linker<HostState>, alias: &str) -> Result<()> {
    let mut instance = linker.instance(alias)?;
    alias_func!(instance, "now-ms", alias, (), |state| {
        <HostState as root::wasm_biotic::factory::clock::Host>::now_ms(state)
    });
    alias_func!(
        instance,
        "schedule-wake",
        alias,
        (request: root::wasm_biotic::factory::clock::WakeRequest),
        |state| {
            <HostState as root::wasm_biotic::factory::clock::Host>::schedule_wake(state, request)
        }
    );
    alias_func!(instance, "poll-wake", alias, (wake_id: String), |state| {
        <HostState as root::wasm_biotic::factory::clock::Host>::poll_wake(state, wake_id)
    });
    alias_func!(instance, "cancel-wake", alias, (wake_id: String), |state| {
        <HostState as root::wasm_biotic::factory::clock::Host>::cancel_wake(state, wake_id)
    });
    Ok(())
}

fn add_runner_alias(linker: &mut Linker<HostState>, alias: &str) -> Result<()> {
    let mut instance = linker.instance(alias)?;
    alias_func!(
        instance,
        "start",
        alias,
        (request: root::wasm_biotic::factory::component_runner::RunRequest),
        |state| {
            <HostState as root::wasm_biotic::factory::component_runner::Host>::start(
                state, request,
            )
        }
    );
    alias_func!(instance, "poll", alias, (operation_id: String), |state| {
        <HostState as root::wasm_biotic::factory::component_runner::Host>::poll(
            state,
            operation_id,
        )
    });
    alias_func!(instance, "cancel", alias, (operation_id: String), |state| {
        <HostState as root::wasm_biotic::factory::component_runner::Host>::cancel(
            state,
            operation_id,
        )
    });
    Ok(())
}

fn add_http_alias(linker: &mut Linker<HostState>, alias: &str) -> Result<()> {
    let mut instance = linker.instance(alias)?;
    alias_func!(
        instance,
        "start",
        alias,
        (request: root::wasm_biotic::factory::http_transport::Request),
        |state| {
            <HostState as root::wasm_biotic::factory::http_transport::Host>::start(state, request)
        }
    );
    alias_func!(instance, "poll", alias, (operation_id: String), |state| {
        <HostState as root::wasm_biotic::factory::http_transport::Host>::poll(
            state,
            operation_id,
        )
    });
    alias_func!(instance, "cancel", alias, (operation_id: String), |state| {
        <HostState as root::wasm_biotic::factory::http_transport::Host>::cancel(
            state,
            operation_id,
        )
    });
    Ok(())
}

fn add_key_alias(linker: &mut Linker<HostState>, alias: &str) -> Result<()> {
    let mut instance = linker.instance(alias)?;
    alias_func!(
        instance,
        "sign-digest",
        alias,
        (key_handle: String, payload: root::wasm_biotic::factory::foundation::Digest),
        |state| {
            <HostState as root::wasm_biotic::factory::key_service::Host>::sign_digest(
                state, key_handle, payload,
            )
        }
    );
    alias_func!(
        instance,
        "verify-digest",
        alias,
        (
            key_id: String,
            payload: root::wasm_biotic::factory::foundation::Digest,
            signature: root::wasm_biotic::factory::key_service::Signature
        ),
        |state| {
            <HostState as root::wasm_biotic::factory::key_service::Host>::verify_digest(
                state, key_id, payload, signature,
            )
        }
    );
    alias_func!(instance, "random-bytes", alias, (length: u32), |state| {
        <HostState as root::wasm_biotic::factory::key_service::Host>::random_bytes(state, length)
    });
    Ok(())
}

fn add_activation_alias(linker: &mut Linker<HostState>, alias: &str) -> Result<()> {
    let mut instance = linker.instance(alias)?;
    alias_func!(instance, "active-manifest", alias, (), |state| {
        <HostState as root::wasm_biotic::factory::activation::Host>::active_manifest(state)
    });
    alias_func!(instance, "active-state", alias, (), |state| {
        <HostState as root::wasm_biotic::factory::activation::Host>::active_state(state)
    });
    alias_func!(
        instance,
        "stage",
        alias,
        (request: root::wasm_biotic::factory::activation::ActivationRequest),
        |state| {
            <HostState as root::wasm_biotic::factory::activation::Host>::stage(state, request)
        }
    );
    alias_func!(instance, "commit", alias, (activation_id: String), |state| {
        <HostState as root::wasm_biotic::factory::activation::Host>::commit(state, activation_id)
    });
    alias_func!(instance, "status", alias, (activation_id: String), |state| {
        <HostState as root::wasm_biotic::factory::activation::Host>::status(state, activation_id)
    });
    alias_func!(
        instance,
        "rollback",
        alias,
        (activation_id: String, target_graph: root::wasm_biotic::factory::foundation::Digest),
        |state| {
            <HostState as root::wasm_biotic::factory::activation::Host>::rollback(
                state,
                activation_id,
                target_graph,
            )
        }
    );
    Ok(())
}

fn add_audit_alias(linker: &mut Linker<HostState>, alias: &str) -> Result<()> {
    let mut instance = linker.instance(alias)?;
    alias_func!(
        instance,
        "append",
        alias,
        (entry: root::wasm_biotic::factory::audit_log::AuditEntry),
        |state| {
            <HostState as root::wasm_biotic::factory::audit_log::Host>::append(state, entry)
        }
    );
    alias_func!(instance, "resolve", alias, (sequence: u64), |state| {
        <HostState as root::wasm_biotic::factory::audit_log::Host>::resolve(state, sequence)
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        Binding, BindingProvider, Grant, HostImport, HttpCredentialBinding, HttpDnsConstraint,
        HttpOriginConstraint, HttpTlsConstraint, HttpTransportBinding, HttpTransportConstraints,
        HttpTransportProfile, Invocation, Node, Principal, RequestHeaderConstraints,
        ResponseHeaderConstraints, host_import_alias, principal_seed,
    };
    use std::path::Path;

    #[test]
    fn grants_do_not_name_factory_domains() {
        let source = include_str!("substrate.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap()
            .to_ascii_lowercase();
        for forbidden in ["candidate-build", "validation-prove", "promotion-control"] {
            assert!(!source.contains(forbidden));
        }
    }

    fn retained_release() -> LoadedRelease {
        let package = Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "../../artifacts/component-complete/r1-packages/sha256-4d4bca5c0fbcb5651bbc326049a08bf495b555392a83093cdf756fd213d0dd09",
        );
        LoadedRelease::load(
            package,
            "7b28a8de3427caf35341e72c56d83b1b250e2e0a599c11259becf69148f7eb07",
        )
        .unwrap()
    }

    fn r2_state() -> (
        HostState,
        BTreeMap<String, String>,
        BTreeMap<String, Digest>,
    ) {
        let mut release = retained_release();
        let constraints = Digest::of(b"r2-test-constraints");
        let authorities = BTreeMap::from([
            ("a".to_string(), Digest::of(b"principal-a")),
            ("b".to_string(), Digest::of(b"principal-b")),
            ("c".to_string(), Digest::of(b"principal-c")),
        ]);
        let capabilities = [
            "activation",
            "clock",
            "component-runner",
            "http-transport",
            "transaction-store",
        ];
        let mut aliases = BTreeMap::new();
        let principals = ["a", "b", "c"]
            .into_iter()
            .map(|consumer| {
                let authority = authorities[consumer];
                let mut host_imports = if consumer == "c" {
                    Vec::new()
                } else {
                    capabilities
                        .into_iter()
                        .map(|capability| {
                            let source_import = format!("wasm-biotic:factory/{capability}@0.1.0");
                            let alias =
                                host_import_alias(consumer, authority, capability, &source_import)
                                    .unwrap();
                            aliases.insert(format!("{consumer}-{capability}"), alias.clone());
                            HostImport {
                                alias,
                                source_import,
                                capability: capability.to_string(),
                                scope: match capability {
                                    "activation" => "switch",
                                    "clock" => "wake",
                                    "component-runner" => "run",
                                    "http-transport" => "request",
                                    "transaction-store" => "r2.test",
                                    _ => unreachable!(),
                                }
                                .to_string(),
                                constraints,
                            }
                        })
                        .collect::<Vec<_>>()
                };
                host_imports.sort_by(|left, right| left.alias.cmp(&right.alias));
                Principal {
                    consumer: consumer.to_string(),
                    authority_component_digest: authority,
                    principal_seed: principal_seed(consumer, authority).unwrap(),
                    scoped_component_digest: Digest::of(format!("scoped-{consumer}").as_bytes()),
                    host_imports,
                }
            })
            .collect::<Vec<_>>();
        release.profile.schema = "wasm-biotic.factory-substrate-profile.v2".to_string();
        release.profile.static_grant_model = "per-consumer-import-alias".to_string();
        release.profile.root_node = "a".to_string();
        release.profile.root_grants.clear();
        release.profile.import_alias_scheme =
            Some("wasm-biotic.per-consumer-host-import.v1".to_string());
        release.profile.principal_id_scheme =
            Some("wasm-biotic.graph-node-principal.v1".to_string());
        release.profile.principals = principals;
        release.manifest.root_node = "a".to_string();
        release.manifest.nodes = ["a", "b", "c"]
            .into_iter()
            .map(|consumer| Node {
                id: consumer.to_string(),
                kind: "test".to_string(),
                component_digest: authorities[consumer],
                world: "test".to_string(),
                exports: vec![],
                grants: if consumer == "c" {
                    vec![]
                } else {
                    vec![
                        Grant {
                            capability: "activation".to_string(),
                            scope: "switch".to_string(),
                            constraints,
                        },
                        Grant {
                            capability: "clock".to_string(),
                            scope: "wake".to_string(),
                            constraints,
                        },
                        Grant {
                            capability: "component-runner".to_string(),
                            scope: "run".to_string(),
                            constraints,
                        },
                        Grant {
                            capability: "http-transport".to_string(),
                            scope: "request".to_string(),
                            constraints,
                        },
                        Grant {
                            capability: "transaction-store".to_string(),
                            scope: "r2.test".to_string(),
                            constraints,
                        },
                    ]
                },
                state_schema: None,
            })
            .collect();
        release.manifest.bindings = release
            .profile
            .principals
            .iter()
            .flat_map(|principal| {
                principal.host_imports.iter().map(|import| Binding {
                    consumer: principal.consumer.clone(),
                    import_name: import.source_import.clone(),
                    provider: BindingProvider {
                        kind: "host".to_string(),
                        capability: Some(import.capability.clone()),
                        node: None,
                        export: None,
                    },
                })
            })
            .collect();
        release.manifest.invocations = vec![Invocation {
            consumer: "a".to_string(),
            target: "b".to_string(),
            export: "wasm-biotic:factory/component-task@0.1.0".to_string(),
        }];
        release.manifest_bytes = canonical_json(&release.manifest).unwrap();
        release.index.graph_manifest_digest = Digest::of(&release.manifest_bytes);
        release.index.root_authority_digest = authorities["a"];
        let substrate = InMemorySubstrate::new(Rc::new(release)).unwrap();
        (HostState::root(substrate).unwrap(), aliases, authorities)
    }

    fn wit_digest(digest: Digest) -> root::wasm_biotic::factory::foundation::Digest {
        root::wasm_biotic::factory::foundation::Digest {
            algorithm: root::wasm_biotic::factory::foundation::HashAlgorithm::Sha256,
            hex: digest.hex(),
        }
    }

    fn r3_http_state() -> (HostState, String) {
        let (state, aliases, _) = r2_state();
        let mut release = (*state.substrate.release).clone();
        let http_alias = aliases["a-http-transport"].clone();
        let constraints = HttpTransportConstraints {
            schema: "wasm-biotic.http-transport-constraints.v1".to_string(),
            origins: vec![HttpOriginConstraint {
                id: "exchange".to_string(),
                scheme: "https".to_string(),
                host: "192.0.2.1".to_string(),
                port: 443,
                path_prefixes: vec!["/v1/".to_string()],
                dns: HttpDnsConstraint {
                    policy: "exact-cidrs".to_string(),
                    cidrs: vec!["198.51.100.0/24".to_string()],
                },
                tls: HttpTlsConstraint {
                    minimum_version: "tls-1.3".to_string(),
                    server_name: "192.0.2.1".to_string(),
                    peer_spki_sha256: vec![Digest::of(b"pin")],
                },
            }],
            methods: vec!["post".to_string()],
            request_headers: RequestHeaderConstraints {
                allowed_names: vec!["authorization".to_string()],
                max_count: 1,
                max_total_bytes: 128,
            },
            response_headers: ResponseHeaderConstraints {
                exposed_names: vec![],
                max_count: 16,
                max_total_bytes: 1024,
            },
            max_url_bytes: 1024,
            max_request_body_bytes: 1024,
            max_response_body_bytes: 1024,
            max_timeout_ms: 100,
            max_concurrency: 1,
            redirects: "deny".to_string(),
            credential_bindings: vec![HttpCredentialBinding {
                handle: "exchange-api".to_string(),
                origin_id: "exchange".to_string(),
                header_name: "authorization".to_string(),
                value_prefix: "Bearer ".to_string(),
                placement: "append-to-header-value".to_string(),
            }],
        };
        let bytes = canonical_json(&constraints).unwrap();
        let digest = Digest::of(&bytes);
        release.profile.schema = "wasm-biotic.factory-substrate-profile.v3".to_string();
        release.profile.http_transport = Some(HttpTransportProfile {
            mode: "bounded-external".to_string(),
            bindings: vec![HttpTransportBinding {
                consumer: "a".to_string(),
                alias: http_alias.clone(),
                constraints: digest,
            }],
        });
        for principal in &mut release.profile.principals {
            if principal.consumer == "a" {
                principal
                    .host_imports
                    .iter_mut()
                    .find(|import| import.capability == "http-transport")
                    .unwrap()
                    .constraints = digest;
            } else {
                principal
                    .host_imports
                    .retain(|import| import.capability != "http-transport");
            }
        }
        let capacity = HttpOperatorCapacity {
            enabled: true,
            allowed_origins: vec!["https://192.0.2.1:443".to_string()],
            allowed_methods: vec!["post".to_string()],
            allowed_request_headers: vec!["authorization".to_string()],
            allowed_response_headers: vec![],
            allowed_cidrs: vec!["198.51.100.0/24".to_string()],
            credential_handles: vec!["exchange-api".to_string()],
            max_url_bytes: 1024,
            max_request_body_bytes: 1024,
            max_response_body_bytes: 1024,
            max_request_header_count: 1,
            max_request_header_bytes: 128,
            max_response_header_count: 16,
            max_response_header_bytes: 1024,
            max_timeout_ms: 100,
            max_concurrency: 1,
        };
        release.http_transport_constraints = BTreeMap::from([(digest, constraints)]);
        release.constraints.insert(digest, bytes);
        let substrate =
            InMemorySubstrate::new_with_http_capacity(Rc::new(release), capacity).unwrap();
        substrate
            .install_transport_credential("exchange-api", b"0123456789abcdef".to_vec())
            .unwrap();
        (HostState::root(substrate).unwrap(), http_alias)
    }

    fn r3_http_request() -> root::wasm_biotic::factory::http_transport::Request {
        root::wasm_biotic::factory::http_transport::Request {
            request_id: "r3-http".to_string(),
            method: root::wasm_biotic::factory::http_transport::Method::Post,
            url: "https://192.0.2.1/v1/message".to_string(),
            headers: vec![root::wasm_biotic::factory::http_transport::Header {
                name: "authorization".to_string(),
                value: b"Bearer ".to_vec(),
            }],
            body: None,
            timeout_ms: 10,
            idempotency_key: wit_digest(Digest::of(b"r3-http")),
            credential_handle: Some("exchange-api".to_string()),
        }
    }

    #[test]
    fn r3_http_is_disabled_without_explicit_operator_capacity() {
        let (configured, alias) = r3_http_state();
        let substrate = InMemorySubstrate::new(configured.substrate.release.clone()).unwrap();
        let mut state = HostState::root(substrate).unwrap();
        let failure = state
            .with_alias(&alias, |state| {
                <HostState as root::wasm_biotic::factory::http_transport::Host>::start(
                    state,
                    r3_http_request(),
                )
            })
            .unwrap()
            .unwrap_err();
        assert_eq!(failure.code, "transport-unavailable");
    }

    #[test]
    fn r3_wit_http_boundary_uses_the_signed_alias_and_async_journal() {
        let (mut state, alias) = r3_http_state();
        let request = r3_http_request();
        let operation = state
            .with_alias(&alias, |state| {
                <HostState as root::wasm_biotic::factory::http_transport::Host>::start(
                    state,
                    request.clone(),
                )
            })
            .unwrap()
            .unwrap();
        let replay = state
            .with_alias(&alias, |state| {
                <HostState as root::wasm_biotic::factory::http_transport::Host>::start(
                    state, request,
                )
            })
            .unwrap()
            .unwrap();
        assert_eq!(replay, operation);
        let failure = (0..10_000).find_map(|_| {
            match state
                .with_alias(&alias, |state| {
                    <HostState as root::wasm_biotic::factory::http_transport::Host>::poll(
                        state,
                        operation.clone(),
                    )
                })
                .unwrap()
            {
                Ok(None) => {
                    thread::yield_now();
                    None
                }
                Ok(Some(_)) => panic!("DNS-denied operation unexpectedly completed"),
                Err(failure) => Some(failure),
            }
        });
        assert_eq!(failure.unwrap().code, "dns-denied");
    }

    #[test]
    fn r2_alias_contexts_reject_cross_principal_capability_and_operation_theft() {
        let (mut state, aliases, authorities) = r2_state();
        assert!(
            state
                .with_alias("forged-alias", |_| ())
                .unwrap_err()
                .to_string()
                .contains("undeclared")
        );

        let blob_attempt = state
            .with_alias(&aliases["a-clock"], |state| {
                <HostState as root::wasm_biotic::factory::blob_store::Host>::put(
                    state,
                    "application/octet-stream".to_string(),
                    b"forbidden".to_vec(),
                )
            })
            .unwrap()
            .unwrap_err();
        assert_eq!(blob_attempt.code, "not-granted");

        let legacy_http = root::wasm_biotic::factory::http_transport::Request {
            request_id: "r2-disabled".to_string(),
            method: root::wasm_biotic::factory::http_transport::Method::Post,
            url: "https://example.invalid/".to_string(),
            headers: vec![],
            body: None,
            timeout_ms: 1,
            idempotency_key: wit_digest(Digest::of(b"r2-disabled")),
            credential_handle: None,
        };
        let unavailable = state
            .with_alias(&aliases["a-http-transport"], |state| {
                <HostState as root::wasm_biotic::factory::http_transport::Host>::start(
                    state,
                    legacy_http,
                )
            })
            .unwrap()
            .unwrap_err();
        assert_eq!(unavailable.code, "transport-unavailable");
        assert!(
            state
                .with_alias(&aliases["a-http-transport"], |state| {
                    <HostState as root::wasm_biotic::factory::http_transport::Host>::poll(
                        state,
                        "absent".to_string(),
                    )
                })
                .unwrap()
                .unwrap()
                .is_none()
        );
        assert!(
            !state
                .with_alias(&aliases["a-http-transport"], |state| {
                    <HostState as root::wasm_biotic::factory::http_transport::Host>::cancel(
                        state,
                        "absent".to_string(),
                    )
                })
                .unwrap()
                .unwrap()
        );

        let wake_id = "owned-wake".to_string();
        let wake = root::wasm_biotic::factory::clock::WakeRequest {
            wake_id: wake_id.clone(),
            not_before_ms: state.substrate.now(),
            target_component: wit_digest(authorities["b"]),
            payload_digest: wit_digest(Digest::of(b"payload")),
            idempotency_key: wit_digest(Digest::of(b"wake-key")),
        };
        state
            .with_alias(&aliases["a-clock"], |state| {
                <HostState as root::wasm_biotic::factory::clock::Host>::schedule_wake(state, wake)
            })
            .unwrap()
            .unwrap();
        let stolen_poll = state
            .with_alias(&aliases["b-clock"], |state| {
                <HostState as root::wasm_biotic::factory::clock::Host>::poll_wake(
                    state,
                    wake_id.clone(),
                )
            })
            .unwrap()
            .unwrap_err();
        assert_eq!(stolen_poll.code, "not-owned");
        let stolen_cancel = state
            .with_alias(&aliases["b-clock"], |state| {
                <HostState as root::wasm_biotic::factory::clock::Host>::cancel_wake(state, wake_id)
            })
            .unwrap()
            .unwrap_err();
        assert_eq!(stolen_cancel.code, "not-owned");

        let transaction_key = Digest::of(b"transaction-key");
        let request = root::wasm_biotic::factory::transaction_store::CommitRequest {
            transaction_id: "tx".to_string(),
            assertions: vec![],
            mutations: vec![],
            idempotency_key: wit_digest(transaction_key),
        };
        state
            .with_alias(&aliases["a-transaction-store"], |state| {
                <HostState as root::wasm_biotic::factory::transaction_store::Host>::commit(
                    state,
                    request.clone(),
                )
            })
            .unwrap()
            .unwrap();
        let stolen_key = state
            .with_alias(&aliases["b-transaction-store"], |state| {
                <HostState as root::wasm_biotic::factory::transaction_store::Host>::commit(
                    state, request,
                )
            })
            .unwrap()
            .unwrap_err();
        assert_eq!(stolen_key.code, "not-owned");

        assert!(
            state
                .with_alias(&aliases["a-component-runner"], |state| {
                    state.caller_may_run(authorities["b"])
                })
                .unwrap()
        );
        assert!(
            !state
                .with_alias(&aliases["b-component-runner"], |state| {
                    state.caller_may_run(authorities["a"])
                })
                .unwrap()
        );

        let operation = "operation-owned".to_string();
        state
            .with_alias(&aliases["a-component-runner"], |state| {
                state.runs.insert(
                    operation.clone(),
                    RunRecord {
                        owner: state.caller(),
                        request_digest: Digest::of(b"run-request"),
                        completion: CoreCompletion {
                            run_id: "run".to_string(),
                            outcome: CoreOutcome::Cancelled,
                            receipt: CoreReceipt {
                                receipt_id: "receipt".to_string(),
                                request_digest: Digest::of(b"run-request"),
                                executor_digest: authorities["b"],
                                started_at_ms: 1,
                                finished_at_ms: 2,
                                outcome_digest: Digest::of(b"cancelled"),
                                audit_sequence: 0,
                            },
                        },
                        provenance: Provenance {
                            graph_manifest_digest: state
                                .substrate
                                .release
                                .index
                                .graph_manifest_digest,
                            authority_component_digest: authorities["b"],
                            executable_component_digest: authorities["b"],
                            source_component_digests: vec![authorities["b"]],
                            caller_principal_seed: state.caller(),
                        },
                    },
                );
            })
            .unwrap();
        let stolen_run = state
            .with_alias(&aliases["b-component-runner"], |state| {
                <HostState as root::wasm_biotic::factory::component_runner::Host>::poll(
                    state, operation,
                )
            })
            .unwrap()
            .unwrap_err();
        assert_eq!(stolen_run.code, "not-owned");
    }

    #[test]
    fn r2_graph_qualified_activation_owner_handoff_survives_restart() {
        let (mut source_state, aliases, _) = r2_state();
        let source_substrate = source_state.substrate.clone();
        let source_graph = source_substrate.release.index.graph_manifest_digest;
        let source_seed = source_substrate
            .release
            .profile
            .principals
            .iter()
            .find(|principal| principal.consumer == "a")
            .unwrap()
            .principal_seed;
        let wrong_seed = source_substrate
            .release
            .profile
            .principals
            .iter()
            .find(|principal| principal.consumer == "b")
            .unwrap()
            .principal_seed;

        let mut successor = (*source_substrate.release).clone();
        successor.manifest.previous_graph = Some(source_graph);
        successor.manifest_bytes = canonical_json(&successor.manifest).unwrap();
        let target_graph = Digest::of(&successor.manifest_bytes);
        successor.index.graph_manifest_digest = target_graph;
        let mut missing_target_import = successor.clone();
        missing_target_import
            .profile
            .principals
            .iter_mut()
            .find(|principal| principal.consumer == "a")
            .unwrap()
            .host_imports
            .retain(|import| import.capability != "activation");
        let missing_import_substrate = source_substrate
            .admit_release(Rc::new(missing_target_import))
            .unwrap();
        let target_manifest = missing_import_substrate
            .memory
            .borrow()
            .admitted_manifests
            .get(&target_graph)
            .unwrap()
            .clone();
        let activation_id = "graph-qualified-handoff".to_string();
        let request = root::wasm_biotic::factory::activation::ActivationRequest {
            activation_id: activation_id.clone(),
            graph_manifest: blob_to_wit!(root, target_manifest),
            expected_active_graph: Some(wit_digest(source_graph)),
            expected_active_state: None,
            state_migration: None,
            migrated_state: None,
            idempotency_key: wit_digest(Digest::of(b"graph-qualified-handoff")),
        };
        source_state
            .with_alias(&aliases["a-activation"], |state| {
                <HostState as root::wasm_biotic::factory::activation::Host>::stage(state, request)
            })
            .unwrap()
            .unwrap();
        assert_eq!(
            source_substrate.memory.borrow().activations[&activation_id].owner,
            Some(GraphPrincipalOwner {
                graph_manifest_digest: source_graph,
                principal_seed: source_seed,
            })
        );

        let before_missing_import = {
            let memory = source_substrate.memory.borrow();
            (
                memory.active_graph,
                memory.activations[&activation_id].owner,
            )
        };
        let missing_import = source_state
            .with_alias(&aliases["a-activation"], |state| {
                <HostState as root::wasm_biotic::factory::activation::Host>::commit(
                    state,
                    activation_id.clone(),
                )
            })
            .unwrap()
            .unwrap_err();
        assert_eq!(missing_import.code, "not-owned");
        let after_missing_import = {
            let memory = source_substrate.memory.borrow();
            (
                memory.active_graph,
                memory.activations[&activation_id].owner,
            )
        };
        assert_eq!(before_missing_import, after_missing_import);

        let target_substrate = source_substrate.admit_release(Rc::new(successor)).unwrap();

        source_state
            .with_alias(&aliases["a-activation"], |state| {
                <HostState as root::wasm_biotic::factory::activation::Host>::commit(
                    state,
                    activation_id.clone(),
                )
            })
            .unwrap()
            .unwrap();
        assert_eq!(source_substrate.memory.borrow().active_graph, target_graph);
        assert_eq!(
            source_substrate.memory.borrow().activations[&activation_id].owner,
            Some(GraphPrincipalOwner {
                graph_manifest_digest: target_graph,
                principal_seed: source_seed,
            })
        );

        let stale_source = source_state
            .with_alias(&aliases["a-activation"], |state| {
                <HostState as root::wasm_biotic::factory::activation::Host>::status(
                    state,
                    activation_id.clone(),
                )
            })
            .unwrap()
            .unwrap_err();
        assert_eq!(stale_source.code, "not-owned");

        let mut target_state = HostState::root(target_substrate.clone()).unwrap();
        let wrong_principal = target_state
            .with_alias(&aliases["b-activation"], |state| {
                <HostState as root::wasm_biotic::factory::activation::Host>::status(
                    state,
                    activation_id.clone(),
                )
            })
            .unwrap()
            .unwrap_err();
        assert_eq!(wrong_principal.code, "not-owned");
        assert_ne!(source_seed, wrong_seed);

        let before_rejection = {
            let memory = source_substrate.memory.borrow();
            (
                memory.active_graph,
                memory.activations[&activation_id].owner,
            )
        };
        let wrong_target = target_state
            .with_alias(&aliases["a-activation"], |state| {
                <HostState as root::wasm_biotic::factory::activation::Host>::rollback(
                    state,
                    activation_id.clone(),
                    wit_digest(target_graph),
                )
            })
            .unwrap()
            .unwrap_err();
        assert_eq!(wrong_target.code, "rollback-target-mismatch");
        let after_rejection = {
            let memory = source_substrate.memory.borrow();
            (
                memory.active_graph,
                memory.activations[&activation_id].owner,
            )
        };
        assert_eq!(before_rejection, after_rejection);

        drop(target_state);
        let mut restarted_target = HostState::root(target_substrate).unwrap();
        restarted_target
            .with_alias(&aliases["a-activation"], |state| {
                <HostState as root::wasm_biotic::factory::activation::Host>::status(
                    state,
                    activation_id.clone(),
                )
            })
            .unwrap()
            .unwrap();
        restarted_target
            .with_alias(&aliases["a-activation"], |state| {
                <HostState as root::wasm_biotic::factory::activation::Host>::rollback(
                    state,
                    activation_id.clone(),
                    wit_digest(source_graph),
                )
            })
            .unwrap()
            .unwrap();
        assert_eq!(source_substrate.memory.borrow().active_graph, source_graph);
        assert_eq!(
            source_substrate.memory.borrow().activations[&activation_id].owner,
            Some(GraphPrincipalOwner {
                graph_manifest_digest: source_graph,
                principal_seed: source_seed,
            })
        );

        let stale_target = restarted_target
            .with_alias(&aliases["a-activation"], |state| {
                <HostState as root::wasm_biotic::factory::activation::Host>::status(
                    state,
                    activation_id.clone(),
                )
            })
            .unwrap()
            .unwrap_err();
        assert_eq!(stale_target.code, "not-owned");
        drop(restarted_target);
        drop(source_state);
        let mut restarted_source = HostState::root(source_substrate).unwrap();
        restarted_source
            .with_alias(&aliases["a-activation"], |state| {
                <HostState as root::wasm_biotic::factory::activation::Host>::status(
                    state,
                    activation_id,
                )
            })
            .unwrap()
            .unwrap();
    }

    #[test]
    fn r2_legacy_run_grants_are_metadata_bounded_by_the_signed_principal_closure() {
        let (state, _, authorities) = r2_state();
        let mut release = (*state.substrate.release).clone();
        let a_seed = release
            .profile
            .principals
            .iter()
            .find(|principal| principal.consumer == "a")
            .unwrap()
            .principal_seed;
        let b_principal = release
            .profile
            .principals
            .iter_mut()
            .find(|principal| principal.consumer == "b")
            .unwrap();
        let b_seed = b_principal.principal_seed;
        b_principal
            .host_imports
            .retain(|import| import.capability != "transaction-store");

        let mut descriptor = release.descriptor.executables[0].clone();
        descriptor.authority_node = "b".to_string();
        descriptor.authority_digest = authorities["b"];
        descriptor.principal_seeds = vec![a_seed, b_seed];
        descriptor.principal_seeds.sort_unstable();
        let bytes = release.executables.values().next().unwrap().bytes.clone();
        release.executables.insert(
            authorities["b"],
            crate::package::ExecutableArtifact {
                descriptor: descriptor.clone(),
                bytes,
            },
        );
        let substrate = InMemorySubstrate::new(Rc::new(release)).unwrap();
        let input = substrate
            .put("application/octet-stream".to_string(), b"input".to_vec())
            .unwrap();
        let request = CoreRunRequest {
            run_id: "closure-compatible".to_string(),
            component_digest: authorities["b"],
            input,
            grants: vec![CoreGrant {
                capability: "transaction-store".to_string(),
                scope: "r2.test".to_string(),
                constraints: None,
            }],
            limits: CoreLimits {
                fuel: 1,
                memory_bytes: 1,
                output_bytes: 1,
                wall_time_ms: 1,
            },
            idempotency_key: Digest::of(b"closure-compatible"),
        };

        // The target principal has no transaction import. The legacy outer
        // metadata is nevertheless compatible because another principal in
        // this exact signed executable closure does declare it.
        let (_, _, access) = validate_dynamic_request(&substrate, &request).unwrap();
        assert!(!access.blob_read);
        assert!(!access.blob_write);
        assert!(access.transaction_namespaces.is_empty());
        assert!(!access.clock);
        assert!(!access.component_runner);
        assert!(!access.http_transport);
        assert!(!access.key_service);
        assert!(!access.activation);
        assert!(!access.audit_append);
        assert!(!access.audit_read);

        let escape = CoreGrant {
            capability: "blob-store".to_string(),
            scope: "read".to_string(),
            constraints: None,
        };
        assert!(!r2_legacy_grant_is_bounded_by_principal_closure(
            &substrate,
            &descriptor,
            &escape,
        ));

        let mut target_only = descriptor.clone();
        target_only.principal_seeds = vec![b_seed];
        assert!(!r2_legacy_grant_is_bounded_by_principal_closure(
            &substrate,
            &target_only,
            &request.grants[0],
        ));

        let mut forged = descriptor;
        forged.principal_seeds.push(Digest::of(b"forged-principal"));
        forged.principal_seeds.sort_unstable();
        assert!(!r2_legacy_grant_is_bounded_by_principal_closure(
            &substrate,
            &forged,
            &request.grants[0],
        ));
    }
}
