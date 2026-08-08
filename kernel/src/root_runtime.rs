//! Typed root and digest-selected component execution.

use crate::bindings::root::wasm_biotic::factory::{
    activation, audit_log, blob_store, clock, component_runner, foundation, http_transport,
    key_service, transaction_store,
};
use crate::bindings::task::wasm_biotic::factory::{
    activation as task_activation, audit_log as task_audit_log, clock as task_clock,
    component_runner as task_component_runner, http_transport as task_http_transport,
    key_service as task_key_service, transaction_store as task_transaction_store,
};
use crate::bindings::{root, task};
use crate::http_transport as bounded_http;
use crate::local::{
    AdmittedExecutionBinding, AdmittedGrant, DurabilityFaultPoint, HttpAuthority, LocalMechanisms,
    PackageDirectory, RequiredCapacity, RootBindingAdmission, StoredRun, canonical_digest,
    effect_receipt, failure, validate_digest,
};
use crate::{
    KernelError, RELEASE_CERTIFICATION_STATEMENT_SCHEMA, ReleaseCertificationStatement,
    ResourceLimits, Sha256Digest, SignedReleaseCertification, compiled_native_tcb_inventory_digest,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::thread;
use std::time::Duration;
use wasmtime::StoreContextMut;
use wasmtime::component::{Component, HasSelf, Linker, types::ComponentItem};
use wasmtime::{Config, Engine, Store, StoreLimits, StoreLimitsBuilder, Trap};

const ROOT_MANIFEST_MEDIA_TYPE: &str = "application/vnd.wasm-biotic.graph+json";
const BLOB_CONSTRAINT_SCHEMA: &str = "wasm-biotic.blob-grant.v1";
const GRAPH_SCHEMA: &str = "wasm-biotic.factory-graph.v1";
const GRAPH_METADATA_SCHEMA: &str = "wasm-biotic.factory-graph-metadata.v1";
const DERIVATION_DESCRIPTOR_SCHEMA: &str = "wasm-biotic.component-derivation-descriptor.v1";
const DERIVATION_DESCRIPTOR_SCHEMA_V2: &str = "wasm-biotic.component-derivation-descriptor.v2";
const SUBSTRATE_PROFILE_SCHEMA: &str = "wasm-biotic.factory-substrate-profile.v1";
const SUBSTRATE_PROFILE_SCHEMA_V2: &str = "wasm-biotic.factory-substrate-profile.v2";
const SUBSTRATE_PROFILE_SCHEMA_V3: &str = "wasm-biotic.factory-substrate-profile.v3";
const R2_STATIC_GRANT_MODEL: &str = "per-consumer-import-alias";
const R2_IMPORT_ALIAS_SCHEME: &str = "wasm-biotic.per-consumer-host-import.v1";
const R2_PRINCIPAL_ID_SCHEME: &str = "wasm-biotic.graph-node-principal.v1";
const R2_PRINCIPAL_SEED_SCHEMA: &str = "wasm-biotic.principal-seed.v1";
const R2_ALIAS_MATERIAL_SCHEMA: &str = "wasm-biotic.host-import-alias-material.v1";
const R2_RUNTIME_PRINCIPAL_SCHEMA: &str = "wasm-biotic.runtime-principal.v1";
const FACTORY_WIT_PACKAGE: &str = "wasm-biotic:factory@0.1.0";
const FACTORY_WIT_PACKAGE_DIGEST: &str =
    "sha256:b7e64a6a131af7a89ab27a0488b1f020f5e26620a1c10abbaeb06f27d6ed2633";
const CAPABILITY_CONSTRAINTS_SCHEMA: &str = "wasm-biotic.capability-constraints.v1";
const MAX_TASK_INSTANCES: usize = 256;
const MAX_TASK_MEMORIES: usize = 128;
const MAX_TASK_TABLES: usize = 128;
const MAX_TASK_TABLE_ELEMENTS: usize = 1_000_000;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BlobConstraint {
    schema: String,
    max_put_bytes: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct BlobAccess {
    read: bool,
    write: bool,
    max_put_bytes: u64,
}

#[derive(Clone, Debug, Default)]
struct TaskGrants {
    blob: BlobAccess,
    transaction_namespace: Option<String>,
    clock: bool,
    component_runner: bool,
    http_transport: bool,
    key_service: bool,
    activation: bool,
    audit_append: bool,
    audit_read: bool,
}

#[derive(Clone, Copy, Debug)]
struct TaskExecutionLimits {
    fuel: u64,
    memory: u64,
    output: u64,
    wall_time_ms: u64,
}

struct TaskState {
    mechanisms: LocalMechanisms,
    grants: TaskGrants,
    active_principal: Option<ActivePrincipal>,
    limits: StoreLimits,
}

trait AliasState {
    fn mechanisms(&self) -> &LocalMechanisms;
    fn active_principal_mut(&mut self) -> &mut Option<ActivePrincipal>;
}

impl AliasState for TaskState {
    fn mechanisms(&self) -> &LocalMechanisms {
        &self.mechanisms
    }

    fn active_principal_mut(&mut self) -> &mut Option<ActivePrincipal> {
        &mut self.active_principal
    }
}

fn invoke_as_principal<S, R>(
    state: &mut S,
    principal: &ActivePrincipal,
    method: &str,
    request_digest: Sha256Digest,
    call: impl FnOnce(&mut S) -> R,
) -> R
where
    S: AliasState,
    R: AuthorityOutcome,
{
    let previous = state.active_principal_mut().replace(principal.clone());
    let result = call(state);
    *state.active_principal_mut() = previous;
    state.mechanisms().record_authority_trace(AuthorityTrace {
        graph_manifest_digest: principal.graph_manifest_digest,
        consumer: principal.consumer.clone(),
        authority_component_digest: principal.authority_component_digest,
        principal_seed: principal.principal_seed,
        runtime_principal_digest: principal.runtime_principal_digest,
        scoped_component_digest: principal.scoped_component_digest,
        executable_component_digest: principal.executable_component_digest,
        alias: principal.host_import.alias.clone(),
        capability: principal.host_import.capability.clone(),
        scope: principal.host_import.scope.clone(),
        constraint_digest: principal.host_import.constraint_digest,
        method: method.to_string(),
        request_digest,
        outcome: result.authority_outcome(),
    });
    result
}

trait AuthorityOutcome {
    fn authority_outcome(&self) -> String;
}

impl<T> AuthorityOutcome for Result<T, foundation::Failure> {
    fn authority_outcome(&self) -> String {
        self.as_ref()
            .map(|_| "success".to_string())
            .unwrap_or_else(|failure| failure.code.clone())
    }
}

impl<T> AuthorityOutcome for Result<T, task::wasm_biotic::factory::foundation::Failure> {
    fn authority_outcome(&self) -> String {
        self.as_ref()
            .map(|_| "success".to_string())
            .unwrap_or_else(|failure| failure.code.clone())
    }
}

impl AuthorityOutcome for u64 {
    fn authority_outcome(&self) -> String {
        "success".to_string()
    }
}

fn authority_request_digest(request: &impl Serialize) -> Sha256Digest {
    Sha256Digest::from_bytes(
        &canonical_json_bytes(request).unwrap_or_else(|_| b"unencodable-host-request".to_vec()),
    )
}

fn active_scope<'a>(principal: &'a Option<ActivePrincipal>, capability: &str) -> Option<&'a str> {
    principal
        .as_ref()
        .filter(|principal| principal.host_import.capability == capability)
        .map(|principal| principal.host_import.scope.as_str())
}

impl TaskState {
    fn blob_access(&self) -> BlobAccess {
        match active_scope(&self.active_principal, "blob-store") {
            Some("read") => BlobAccess {
                read: true,
                max_put_bytes: self.grants.blob.max_put_bytes,
                ..BlobAccess::default()
            },
            Some("write") => BlobAccess {
                write: true,
                max_put_bytes: self.grants.blob.max_put_bytes,
                ..BlobAccess::default()
            },
            Some("read-write") => BlobAccess {
                read: true,
                write: true,
                max_put_bytes: self.grants.blob.max_put_bytes,
            },
            Some(_) => BlobAccess::default(),
            None if self.active_principal.is_some() => BlobAccess::default(),
            None => self.grants.blob,
        }
    }

    fn transaction_namespace(&self) -> Option<&str> {
        if self.active_principal.is_some() {
            active_scope(&self.active_principal, "transaction-store")
        } else {
            self.grants.transaction_namespace.as_deref()
        }
    }

    fn granted(&self, capability: &str, scope: &str) -> bool {
        if self.active_principal.is_some() {
            return active_scope(&self.active_principal, capability)
                .is_some_and(|admitted| scope_is_subset(capability, scope, admitted));
        }
        match capability {
            "clock" => self.grants.clock,
            "component-runner" => self.grants.component_runner,
            "http-transport" => self.grants.http_transport,
            "key-service" => self.grants.key_service,
            "activation" => self.grants.activation,
            "audit-log" if scope == "append" => self.grants.audit_append,
            "audit-log" if scope == "read" => self.grants.audit_read,
            _ => false,
        }
    }
}

impl task::wasm_biotic::factory::foundation::Host for TaskState {}

impl task::wasm_biotic::factory::blob_store::Host for TaskState {
    fn put(
        &mut self,
        media_type: String,
        content: Vec<u8>,
    ) -> Result<
        task::wasm_biotic::factory::foundation::BlobRef,
        task::wasm_biotic::factory::foundation::Failure,
    > {
        let access = self.blob_access();
        if !access.write {
            return Err(task_failure("not-granted", "blob write was not granted"));
        }
        if u64::try_from(content.len()).unwrap_or(u64::MAX) > access.max_put_bytes {
            return Err(task_failure(
                "limit-exceeded",
                "blob write exceeds the run grant",
            ));
        }
        self.mechanisms
            .put_blob(media_type, content)
            .map(root_blob_to_task)
            .map_err(root_failure_to_task)
    }

    fn get(
        &mut self,
        reference: task::wasm_biotic::factory::foundation::BlobRef,
    ) -> Result<Vec<u8>, task::wasm_biotic::factory::foundation::Failure> {
        if !self.blob_access().read {
            return Err(task_failure("not-granted", "blob read was not granted"));
        }
        self.mechanisms
            .get_blob(task_blob_to_root(reference))
            .map_err(root_failure_to_task)
    }

    fn has(
        &mut self,
        digest: task::wasm_biotic::factory::foundation::Digest,
    ) -> Result<bool, task::wasm_biotic::factory::foundation::Failure> {
        if !self.blob_access().read {
            return Err(task_failure("not-granted", "blob read was not granted"));
        }
        self.mechanisms
            .has_blob(task_digest_to_root(digest))
            .map_err(root_failure_to_task)
    }
}

impl task_transaction_store::Host for TaskState {
    fn read(
        &mut self,
        namespace: String,
        key: String,
    ) -> Result<
        Option<task_transaction_store::VersionedValue>,
        task::wasm_biotic::factory::foundation::Failure,
    > {
        if self.transaction_namespace() != Some(namespace.as_str()) {
            return Err(task_failure(
                "not-granted",
                "transaction namespace is outside the run grant",
            ));
        }
        transaction_store::Host::read(&mut self.mechanisms, namespace, key)
            .map_err(root_failure_to_task)?
            .map(convert_root_value)
            .transpose()
    }

    fn commit(
        &mut self,
        request: task_transaction_store::CommitRequest,
    ) -> Result<
        task_transaction_store::CommitReceipt,
        task::wasm_biotic::factory::foundation::Failure,
    > {
        let namespace = self
            .transaction_namespace()
            .ok_or_else(|| task_failure("not-granted", "transaction store was not granted"))?;
        let in_scope = request
            .assertions
            .iter()
            .all(|assertion| assertion.namespace == namespace)
            && request.mutations.iter().all(|mutation| match mutation {
                task_transaction_store::Mutation::Put((candidate, _, _))
                | task_transaction_store::Mutation::Delete((candidate, _)) => {
                    candidate == namespace
                }
            });
        if !in_scope {
            return Err(task_failure(
                "not-granted",
                "transaction request escapes the run namespace",
            ));
        }
        let request = convert_task_value(request)?;
        let caller = self
            .active_principal
            .as_ref()
            .map(|principal| principal.principal_seed);
        self.mechanisms
            .commit_transaction_for_principal(request, caller)
            .map_err(root_failure_to_task)
            .and_then(convert_root_value)
    }
}

impl task_clock::Host for TaskState {
    fn now_ms(&mut self) -> u64 {
        if self.granted("clock", "wake") {
            clock::Host::now_ms(&mut self.mechanisms)
        } else {
            0
        }
    }

    fn schedule_wake(
        &mut self,
        request: task_clock::WakeRequest,
    ) -> Result<u64, task::wasm_biotic::factory::foundation::Failure> {
        require_task_grant(self.granted("clock", "wake"), "clock")?;
        let caller = self
            .active_principal
            .as_ref()
            .map(|principal| principal.principal_seed);
        self.mechanisms
            .schedule_for_principal(convert_task_value(request)?, caller)
            .map_err(root_failure_to_task)
    }

    fn poll_wake(
        &mut self,
        wake_id: String,
    ) -> Result<Option<task_clock::FiredWake>, task::wasm_biotic::factory::foundation::Failure>
    {
        require_task_grant(self.granted("clock", "wake"), "clock")?;
        let caller = self
            .active_principal
            .as_ref()
            .map(|principal| principal.principal_seed);
        self.mechanisms
            .poll_scheduled_for_principal(wake_id, caller)
            .map_err(root_failure_to_task)?
            .map(convert_root_value)
            .transpose()
    }

    fn cancel_wake(
        &mut self,
        wake_id: String,
    ) -> Result<bool, task::wasm_biotic::factory::foundation::Failure> {
        require_task_grant(self.granted("clock", "wake"), "clock")?;
        let caller = self
            .active_principal
            .as_ref()
            .map(|principal| principal.principal_seed);
        self.mechanisms
            .cancel_scheduled_for_principal(wake_id, caller)
            .map_err(root_failure_to_task)
    }
}

impl task_component_runner::Host for TaskState {
    fn start(
        &mut self,
        request: task_component_runner::RunRequest,
    ) -> Result<String, task::wasm_biotic::factory::foundation::Failure> {
        require_task_grant(self.granted("component-runner", "run"), "component-runner")?;
        let caller = self
            .active_principal
            .as_ref()
            .map(|principal| principal.principal_seed);
        start_task(
            self.mechanisms.clone(),
            convert_task_value(request)?,
            caller,
        )
        .map_err(root_failure_to_task)
    }

    fn poll(
        &mut self,
        operation_id: String,
    ) -> Result<
        Option<task_component_runner::RunCompletion>,
        task::wasm_biotic::factory::foundation::Failure,
    > {
        require_task_grant(self.granted("component-runner", "run"), "component-runner")?;
        let caller = self
            .active_principal
            .as_ref()
            .map(|principal| principal.principal_seed);
        self.mechanisms
            .poll_run_for_principal(&operation_id, caller)
            .map_err(root_failure_to_task)?
            .map(|run| run.completion)
            .map(convert_root_value)
            .transpose()
    }

    fn cancel(
        &mut self,
        operation_id: String,
    ) -> Result<bool, task::wasm_biotic::factory::foundation::Failure> {
        require_task_grant(self.granted("component-runner", "run"), "component-runner")?;
        let caller = self
            .active_principal
            .as_ref()
            .map(|principal| principal.principal_seed);
        self.mechanisms
            .cancel_run_for_principal(&operation_id, caller)
            .map_err(root_failure_to_task)
    }
}

impl task_http_transport::Host for TaskState {
    fn start(
        &mut self,
        request: task_http_transport::Request,
    ) -> Result<String, task::wasm_biotic::factory::foundation::Failure> {
        require_task_grant(self.granted("http-transport", "request"), "http-transport")?;
        let request = convert_task_value(request)?;
        match self.active_principal.as_ref() {
            Some(principal) => self
                .mechanisms
                .start_http_for_authority(request, principal.http_authority())
                .map_err(root_failure_to_task),
            None => http_transport::Host::start(&mut self.mechanisms, request)
                .map_err(root_failure_to_task),
        }
    }

    fn poll(
        &mut self,
        operation_id: String,
    ) -> Result<
        Option<task_http_transport::Response>,
        task::wasm_biotic::factory::foundation::Failure,
    > {
        require_task_grant(self.granted("http-transport", "request"), "http-transport")?;
        let response = match self.active_principal.as_ref() {
            Some(principal) => self
                .mechanisms
                .poll_http_for_authority(&operation_id, &principal.http_authority()),
            None => self.mechanisms.poll_http_for_principal(&operation_id, None),
        };
        response
            .map_err(root_failure_to_task)?
            .map(convert_root_value)
            .transpose()
    }

    fn cancel(
        &mut self,
        operation_id: String,
    ) -> Result<bool, task::wasm_biotic::factory::foundation::Failure> {
        require_task_grant(self.granted("http-transport", "request"), "http-transport")?;
        match self.active_principal.as_ref() {
            Some(principal) => self
                .mechanisms
                .cancel_http_for_authority(&operation_id, &principal.http_authority()),
            None => self
                .mechanisms
                .cancel_http_for_principal(&operation_id, None),
        }
        .map_err(root_failure_to_task)
    }
}

impl task_key_service::Host for TaskState {
    fn sign_digest(
        &mut self,
        key_handle: String,
        payload: task::wasm_biotic::factory::foundation::Digest,
    ) -> Result<task_key_service::Signature, task::wasm_biotic::factory::foundation::Failure> {
        require_task_grant(self.granted("key-service", "use"), "key-service")?;
        key_service::Host::sign_digest(
            &mut self.mechanisms,
            key_handle,
            task_digest_to_root(payload),
        )
        .map_err(root_failure_to_task)
        .and_then(convert_root_value)
    }

    fn verify_digest(
        &mut self,
        key_id: String,
        payload: task::wasm_biotic::factory::foundation::Digest,
        signature: task_key_service::Signature,
    ) -> Result<bool, task::wasm_biotic::factory::foundation::Failure> {
        require_task_grant(self.granted("key-service", "use"), "key-service")?;
        key_service::Host::verify_digest(
            &mut self.mechanisms,
            key_id,
            task_digest_to_root(payload),
            convert_task_value(signature)?,
        )
        .map_err(root_failure_to_task)
    }

    fn random_bytes(
        &mut self,
        length: u32,
    ) -> Result<Vec<u8>, task::wasm_biotic::factory::foundation::Failure> {
        require_task_grant(self.granted("key-service", "use"), "key-service")?;
        key_service::Host::random_bytes(&mut self.mechanisms, length).map_err(root_failure_to_task)
    }
}

impl task_activation::Host for TaskState {
    fn active_manifest(
        &mut self,
    ) -> Result<
        Option<task::wasm_biotic::factory::foundation::BlobRef>,
        task::wasm_biotic::factory::foundation::Failure,
    > {
        require_task_grant(self.granted("activation", "switch"), "activation")?;
        self.mechanisms
            .active_manifest_reference()
            .map(|reference| reference.map(root_blob_to_task))
            .map_err(root_failure_to_task)
    }

    fn active_state(
        &mut self,
    ) -> Result<
        Option<task::wasm_biotic::factory::foundation::BlobRef>,
        task::wasm_biotic::factory::foundation::Failure,
    > {
        require_task_grant(self.granted("activation", "switch"), "activation")?;
        self.mechanisms
            .active_state_reference()
            .map(|reference| reference.map(root_blob_to_task))
            .map_err(root_failure_to_task)
    }

    fn stage(
        &mut self,
        request: task_activation::ActivationRequest,
    ) -> Result<task_activation::ActivationStatus, task::wasm_biotic::factory::foundation::Failure>
    {
        require_task_grant(self.granted("activation", "switch"), "activation")?;
        let caller = self
            .active_principal
            .as_ref()
            .map(|principal| principal.principal_seed);
        self.mechanisms
            .stage_activation_for_principal(convert_task_value(request)?, caller)
            .map_err(root_failure_to_task)
            .and_then(convert_root_value)
    }

    fn commit(
        &mut self,
        activation_id: String,
    ) -> Result<task_activation::ActivationStatus, task::wasm_biotic::factory::foundation::Failure>
    {
        require_task_grant(self.granted("activation", "switch"), "activation")?;
        let caller = self
            .active_principal
            .as_ref()
            .map(|principal| principal.principal_seed);
        self.mechanisms
            .commit_activation_for_principal(activation_id, caller)
            .map_err(root_failure_to_task)
            .and_then(convert_root_value)
    }

    fn status(
        &mut self,
        activation_id: String,
    ) -> Result<task_activation::ActivationStatus, task::wasm_biotic::factory::foundation::Failure>
    {
        require_task_grant(self.granted("activation", "switch"), "activation")?;
        let caller = self
            .active_principal
            .as_ref()
            .map(|principal| principal.principal_seed);
        self.mechanisms
            .activation_status_for_principal(activation_id, caller)
            .map_err(root_failure_to_task)
            .and_then(convert_root_value)
    }

    fn rollback(
        &mut self,
        activation_id: String,
        target_graph: task::wasm_biotic::factory::foundation::Digest,
    ) -> Result<task_activation::ActivationStatus, task::wasm_biotic::factory::foundation::Failure>
    {
        require_task_grant(self.granted("activation", "switch"), "activation")?;
        let caller = self
            .active_principal
            .as_ref()
            .map(|principal| principal.principal_seed);
        self.mechanisms
            .rollback_activation_for_principal(
                activation_id,
                task_digest_to_root(target_graph),
                caller,
            )
            .map_err(root_failure_to_task)
            .and_then(convert_root_value)
    }
}

impl task_audit_log::Host for TaskState {
    fn append(
        &mut self,
        entry: task_audit_log::AuditEntry,
    ) -> Result<task_audit_log::AuditReceipt, task::wasm_biotic::factory::foundation::Failure> {
        require_task_grant(self.granted("audit-log", "append"), "audit-log append")?;
        audit_log::Host::append(&mut self.mechanisms, convert_task_value(entry)?)
            .map_err(root_failure_to_task)
            .and_then(convert_root_value)
    }

    fn resolve(
        &mut self,
        sequence: u64,
    ) -> Result<Option<task_audit_log::AuditEntry>, task::wasm_biotic::factory::foundation::Failure>
    {
        require_task_grant(self.granted("audit-log", "read"), "audit-log read")?;
        audit_log::Host::resolve(&mut self.mechanisms, sequence)
            .map_err(root_failure_to_task)?
            .map(convert_root_value)
            .transpose()
    }
}

/// Exact, uncomposed source component bytes declared by an admitted manifest.
#[derive(Clone, Debug)]
pub struct AdmittedComponent {
    /// Caller-asserted exact SHA-256 digest.
    pub digest: Sha256Digest,
    /// Exact Component Model binary bytes.
    pub bytes: Vec<u8>,
}

/// Exact content-addressed non-component evidence bytes.
#[derive(Clone, Debug)]
pub struct ContentArtifact {
    /// Caller-asserted exact SHA-256 digest.
    pub digest: Sha256Digest,
    /// Exact artifact bytes.
    pub bytes: Vec<u8>,
}

/// Exact evidence chain required before any derived executable is trusted.
#[derive(Clone, Debug)]
pub struct RootEvidence {
    /// Exact native inventory certified for the original release kernel. An
    /// independent substrate records its own inventory separately.
    pub certified_kernel_tcb_inventory: ContentArtifact,
    /// Metadata blob reached through the manifest's `metadata` digest.
    pub metadata: ContentArtifact,
    /// Metadata-bound canonical derivation descriptor.
    pub derivation_descriptor: ContentArtifact,
    /// Metadata-bound canonical declaration of the eight-host boundary.
    pub substrate_profile: ContentArtifact,
    /// Metadata-bound canonical WIT package artifact.
    pub wit_package: ContentArtifact,
    /// Exact WIT world artifacts keyed by the metadata digest map.
    pub wit_worlds: Vec<ContentArtifact>,
    /// Exact composition configurations named by executable descriptors.
    pub composition_configurations: Vec<ContentArtifact>,
    /// R2 components whose canonical host imports have been deterministically
    /// rewritten to per-consumer aliases. Empty for v1 admissions.
    pub scoped_components: Vec<AdmittedComponent>,
    /// Exact immutable constraint blobs named by manifest grants.
    pub constraints: Vec<ContentArtifact>,
    /// Canonical offline strict-validation report treated as opaque bytes.
    pub validation_report: ContentArtifact,
    /// Canonical signed content-set certification for this admission.
    pub release_certification: ContentArtifact,
}

/// Separate evidence for the bytes actually instantiated for one run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionProvenance {
    /// Graph manifest that authorized resolution, absent only in direct tests.
    pub graph_manifest_digest: Option<Sha256Digest>,
    /// Raw source-node identity supplied in the request and mechanism receipt.
    pub authority_component_digest: Sha256Digest,
    /// Exact Component Model artifact instantiated by Wasmtime.
    pub executable_component_digest: Sha256Digest,
    /// Source node digests bound into the executable cache.
    pub source_component_digests: Vec<Sha256Digest>,
    /// R2 caller principal fixed by the selected import alias. Absent for the
    /// retained v1 graph-union path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_principal_seed: Option<Sha256Digest>,
}

/// One native-observed call through a release-bound per-consumer import alias.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityTrace {
    /// Active graph whose admission fixed this authority mapping.
    pub graph_manifest_digest: Sha256Digest,
    /// Opaque graph node identifier; native code never branches on its value.
    pub consumer: String,
    /// Raw component identity represented by the principal.
    pub authority_component_digest: Sha256Digest,
    /// Canonical principal seed independently recomputed from graph data.
    pub principal_seed: Sha256Digest,
    /// Graph-qualified runtime identity of this principal.
    pub runtime_principal_digest: Sha256Digest,
    /// Rewritten component bytes from which this residual alias originated.
    pub scoped_component_digest: Sha256Digest,
    /// Exact enclosing root or dynamic executable instantiated by Wasmtime.
    pub executable_component_digest: Sha256Digest,
    /// Exact residual import instance selected by Wasmtime.
    pub alias: String,
    /// One of the closed eight generic mechanisms.
    pub capability: String,
    /// Opaque release-declared scope enforced for this call.
    pub scope: String,
    /// Immutable constraint document selected by the graph.
    pub constraint_digest: Sha256Digest,
    /// Generic WIT method name, never a factory operation or role.
    pub method: String,
    /// Digest of the exact lowered request values observed at the boundary.
    pub request_digest: Sha256Digest,
    /// `success` or the stable generic failure code returned by the mechanism.
    pub outcome: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LaunchGrant {
    capability: String,
    scope: String,
    constraints: Sha256Digest,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LaunchNode {
    id: String,
    kind: String,
    component_digest: Sha256Digest,
    world: String,
    exports: Vec<String>,
    grants: Vec<LaunchGrant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    state_schema: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
enum LaunchProvider {
    Component { node: String, export: String },
    Host { capability: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LaunchBinding {
    consumer: String,
    #[serde(rename = "import")]
    import_name: String,
    provider: LaunchProvider,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LaunchInvocation {
    consumer: String,
    target: String,
    export: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LaunchManifest {
    schema: String,
    wit_package: String,
    root_node: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    previous_graph: Option<Sha256Digest>,
    state_schema: String,
    nodes: Vec<LaunchNode>,
    bindings: Vec<LaunchBinding>,
    invocations: Vec<LaunchInvocation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    metadata: Option<Sha256Digest>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LaunchMetadata {
    schema: String,
    wit_package_digest: Sha256Digest,
    wit_world_digests: BTreeMap<String, Sha256Digest>,
    substrate_profile_digest: Sha256Digest,
    derivation_descriptor_digest: Sha256Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DerivationSource {
    node_id: String,
    component_digest: Sha256Digest,
    world: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DerivedExecutable {
    authority_node: String,
    authority_digest: Sha256Digest,
    executable_digest: Sha256Digest,
    source_digests: Vec<Sha256Digest>,
    world: String,
    configuration_digest: Sha256Digest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    grants: Option<Vec<LaunchGrant>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    scoped_source_digests: Vec<Sha256Digest>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    principal_seeds: Vec<Sha256Digest>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompositionTool {
    name: String,
    version: String,
    options: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DerivationDescriptor {
    schema: String,
    wit_package_digest: Sha256Digest,
    sources: Vec<DerivationSource>,
    executables: Vec<DerivedExecutable>,
    tool: CompositionTool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SubstrateProfile {
    schema: String,
    wit_package: String,
    primitives: Vec<String>,
    static_grant_model: String,
    root_node: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    root_grants: Vec<LaunchGrant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    import_alias_scheme: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    principal_id_scheme: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    principals: Vec<LaunchPrincipal>,
    ceilings: CapabilityConstraints,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    http_transport: Option<HttpTransportProfileV1>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpTransportProfileV1 {
    mode: HttpTransportProfileModeV1,
    bindings: Vec<HttpTransportBindingV1>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum HttpTransportProfileModeV1 {
    BoundedExternal,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpTransportBindingV1 {
    consumer: String,
    alias: String,
    constraints: Sha256Digest,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LaunchPrincipal {
    consumer: String,
    authority_component_digest: Sha256Digest,
    principal_seed: Sha256Digest,
    scoped_component_digest: Sha256Digest,
    host_imports: Vec<LaunchHostImport>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LaunchHostImport {
    alias: String,
    source_import: String,
    capability: String,
    scope: String,
    constraints: Sha256Digest,
}

#[derive(Clone, Debug)]
pub(crate) struct AdmittedPrincipal {
    pub(crate) consumer: String,
    pub(crate) authority_component_digest: Sha256Digest,
    pub(crate) principal_seed: Sha256Digest,
    pub(crate) scoped_component_digest: Sha256Digest,
    pub(crate) host_imports: Vec<AdmittedHostImport>,
}

#[derive(Clone, Debug)]
pub(crate) struct AdmittedHostImport {
    pub(crate) alias: String,
    pub(crate) source_import: String,
    pub(crate) capability: String,
    pub(crate) scope: String,
    pub(crate) constraint_digest: Sha256Digest,
}

#[derive(Clone, Debug)]
struct ActivePrincipal {
    graph_manifest_digest: Sha256Digest,
    consumer: String,
    authority_component_digest: Sha256Digest,
    principal_seed: Sha256Digest,
    runtime_principal_digest: Sha256Digest,
    scoped_component_digest: Sha256Digest,
    executable_component_digest: Sha256Digest,
    host_import: AdmittedHostImport,
}

impl ActivePrincipal {
    fn http_authority(&self) -> HttpAuthority {
        HttpAuthority {
            graph_manifest_digest: self.graph_manifest_digest,
            principal_seed: self.principal_seed,
            alias: self.host_import.alias.clone(),
            constraint_digest: self.host_import.constraint_digest,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityConstraints {
    schema: String,
    max_blob_bytes: u64,
    max_total_blob_bytes: u64,
    max_random_bytes: u32,
    max_wake_delay_ms: u64,
    max_http_timeout_ms: u64,
    max_component_fuel: u64,
    max_component_memory_bytes: u64,
    max_component_output_bytes: u64,
    max_component_wall_time_ms: u64,
    transaction_namespaces: Vec<String>,
}

struct ValidatedLaunch {
    source_digests: Vec<Sha256Digest>,
    execution_bindings: Vec<AdmittedExecutionBinding>,
    root_grants: Vec<AdmittedGrant>,
    r2_principals: Vec<AdmittedPrincipal>,
    r2_invocations: Vec<(Sha256Digest, Sha256Digest)>,
    r2_root_principal_seeds: Vec<Sha256Digest>,
    ceilings: CapabilityConstraints,
    certification_closure: CertificationClosure,
}

struct CertificationClosure {
    graph_manifest_digest: Sha256Digest,
    wit_package_digest: Sha256Digest,
    metadata_digest: Sha256Digest,
    raw_artifacts: BTreeMap<String, Sha256Digest>,
    derived_artifacts: BTreeMap<String, Sha256Digest>,
    derivation_descriptor_digest: Sha256Digest,
    substrate_profile_digest: Sha256Digest,
    wit_world_digests: BTreeMap<String, Sha256Digest>,
    composition_configuration_digests: Vec<Sha256Digest>,
    constraint_digests: Vec<Sha256Digest>,
}

/// Content-bound source graph plus a derived composed root cache.
#[derive(Clone, Debug)]
pub struct RootAdmission {
    /// Exact authoritative manifest bytes.
    pub manifest_bytes: Vec<u8>,
    /// Expected digest of the authoritative manifest bytes.
    pub manifest_digest: Sha256Digest,
    /// Exact uncomposed component definitions declared by the manifest.
    pub source_components: Vec<AdmittedComponent>,
    /// Derived executable bytes; descriptor bytes are their only mapping authority.
    pub execution_artifacts: Vec<AdmittedComponent>,
    /// Derived composed root component bytes.
    pub composed_root: AdmittedComponent,
    /// Exact manifest-bound metadata, derivation and configuration evidence.
    pub evidence: RootEvidence,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GraphPackageIndex {
    certification_digest: Sha256Digest,
    certified_kernel_tcb_inventory_digest: Sha256Digest,
    package_schema: String,
    graph_manifest_digest: Sha256Digest,
    root_authority_digest: Sha256Digest,
    root_executable_digest: Sha256Digest,
    validation_report_digest: Sha256Digest,
}

impl RootAdmission {
    /// Derives the minimum local mechanism capacity that can satisfy this
    /// package's immutable substrate profile.
    pub fn local_config_ceiling(&self) -> Result<crate::LocalConfig, KernelError> {
        let profile = self.verified_substrate_profile()?;
        Ok(crate::LocalConfig::from_manifest_ceiling(
            required_capacity(&profile.ceilings),
        ))
    }

    /// Intersects operator-selected generic root limits with this graph's
    /// verified fuel and memory ceilings.
    pub fn bounded_root_limits(
        &self,
        operator_capacity: &ResourceLimits,
    ) -> Result<ResourceLimits, KernelError> {
        let profile = self.verified_substrate_profile()?;
        let mut limits = operator_capacity.clone();
        limits.fuel = limits.fuel.min(profile.ceilings.max_component_fuel);
        limits.max_memory_bytes = limits
            .max_memory_bytes
            .min(profile.ceilings.max_component_memory_bytes);
        validate_runtime_limits(&limits)?;
        Ok(limits)
    }

    /// Loads an admission set from the deterministic, digest-named graph
    /// package layout. Every authoritative join is taken from verified content;
    /// the convenience index cannot redefine manifest or descriptor mappings.
    pub fn from_package_directory(path: impl AsRef<Path>) -> Result<Self, KernelError> {
        let directory = PackageDirectory::open(path)?;
        let index: GraphPackageIndex = serde_json::from_slice(&directory.read("package.json")?)
            .map_err(|error| KernelError::ManifestDecode(error.to_string()))?;
        if index.package_schema != "wasm-biotic.component-graph-package.v1" {
            return Err(KernelError::UnsupportedSchema(index.package_schema));
        }
        let validation_report = package_content(
            &directory,
            "evidence/strict-validation.json",
            index.validation_report_digest,
        )?;
        let release_certification = package_content(
            &directory,
            "certification/release-certification.json",
            index.certification_digest,
        )?;
        let certified_kernel_tcb_inventory = package_content(
            &directory,
            &format!(
                "certified-kernel-tcb/{}.json",
                digest_file_stem(index.certified_kernel_tcb_inventory_digest)
            ),
            index.certified_kernel_tcb_inventory_digest,
        )?;

        let manifest_bytes = directory.read("manifest.json")?;
        require_artifact_digest(
            "manifest.json",
            &manifest_bytes,
            index.graph_manifest_digest,
        )?;
        let manifest: LaunchManifest = parse_canonical_json(&manifest_bytes, "graph manifest")?;
        let metadata_digest = manifest.metadata.ok_or_else(|| {
            KernelError::InvalidConfiguration(
                "graph package manifest has no evidence metadata digest".to_string(),
            )
        })?;
        let root_authority_digest = manifest
            .nodes
            .iter()
            .find(|node| node.id == manifest.root_node)
            .map(|node| node.component_digest)
            .ok_or(KernelError::InvalidEntryPoint)?;
        if index.root_authority_digest != root_authority_digest {
            return Err(KernelError::InvalidConfiguration(
                "package index root authority differs from the manifest".to_string(),
            ));
        }

        let metadata = package_content(&directory, "metadata.json", metadata_digest)?;
        let metadata_value: LaunchMetadata =
            parse_canonical_json(&metadata.bytes, "graph metadata")?;
        let descriptor = package_content(
            &directory,
            "derivation-descriptor.json",
            metadata_value.derivation_descriptor_digest,
        )?;
        let descriptor_value: DerivationDescriptor =
            parse_canonical_json(&descriptor.bytes, "derivation descriptor")?;
        let substrate_profile = package_content(
            &directory,
            "substrate-profile.json",
            metadata_value.substrate_profile_digest,
        )?;
        let wit_package = package_content(
            &directory,
            &format!(
                "wit/{}-package.json",
                digest_file_stem(metadata_value.wit_package_digest)
            ),
            metadata_value.wit_package_digest,
        )?;

        let mut source_components = Vec::new();
        let mut seen_sources = BTreeSet::new();
        for source in &descriptor_value.sources {
            if seen_sources.insert(source.component_digest) {
                source_components.push(package_component(
                    &directory,
                    &format!(
                        "components/{}.wasm",
                        digest_file_stem(source.component_digest)
                    ),
                    source.component_digest,
                )?);
            }
        }

        let composed_root = package_component(
            &directory,
            "factory-root.wasm",
            index.root_executable_digest,
        )?;
        let root_descriptor = descriptor_value
            .executables
            .iter()
            .find(|executable| executable.authority_node == manifest.root_node)
            .ok_or_else(|| {
                KernelError::InvalidConfiguration(
                    "derivation descriptor has no root executable".to_string(),
                )
            })?;
        if root_descriptor.authority_digest != index.root_authority_digest
            || root_descriptor.executable_digest != index.root_executable_digest
        {
            return Err(KernelError::InvalidConfiguration(
                "package index root executable differs from the descriptor".to_string(),
            ));
        }

        let mut execution_artifacts = Vec::new();
        let mut seen_executables = BTreeSet::new();
        for executable in &descriptor_value.executables {
            if executable.authority_node != manifest.root_node
                && executable.executable_digest != executable.authority_digest
                && seen_executables.insert(executable.executable_digest)
            {
                execution_artifacts.push(package_component(
                    &directory,
                    &format!(
                        "derived/{}.wasm",
                        digest_file_stem(executable.executable_digest)
                    ),
                    executable.executable_digest,
                )?);
            }
        }

        let mut wit_worlds = Vec::new();
        let mut seen_worlds = BTreeSet::new();
        for digest in metadata_value.wit_world_digests.values().copied() {
            if seen_worlds.insert(digest) {
                wit_worlds.push(package_content(
                    &directory,
                    &format!("wit/{}-worlds.wit", digest_file_stem(digest)),
                    digest,
                )?);
            }
        }

        let mut composition_configurations = Vec::new();
        let mut seen_configurations = BTreeSet::new();
        for digest in descriptor_value
            .executables
            .iter()
            .map(|executable| executable.configuration_digest)
        {
            if seen_configurations.insert(digest) {
                composition_configurations.push(package_content(
                    &directory,
                    &format!("composition-configs/{}.config", digest_file_stem(digest)),
                    digest,
                )?);
            }
        }

        let mut scoped_components = Vec::new();
        let mut seen_scoped_components = BTreeSet::new();
        for digest in descriptor_value
            .executables
            .iter()
            .flat_map(|executable| executable.scoped_source_digests.iter().copied())
        {
            if seen_scoped_components.insert(digest) {
                scoped_components.push(package_component(
                    &directory,
                    &format!("scoped-components/{}.wasm", digest_file_stem(digest)),
                    digest,
                )?);
            }
        }

        let mut constraints = Vec::new();
        let mut seen_constraints = BTreeSet::new();
        for digest in manifest
            .nodes
            .iter()
            .flat_map(|node| node.grants.iter().map(|grant| grant.constraints))
        {
            if seen_constraints.insert(digest) {
                constraints.push(package_content(
                    &directory,
                    &format!("constraints/{}.json", digest_file_stem(digest)),
                    digest,
                )?);
            }
        }

        Ok(Self {
            manifest_bytes,
            manifest_digest: index.graph_manifest_digest,
            source_components,
            execution_artifacts,
            composed_root,
            evidence: RootEvidence {
                certified_kernel_tcb_inventory,
                metadata,
                derivation_descriptor: descriptor,
                substrate_profile,
                wit_package,
                wit_worlds,
                composition_configurations,
                scoped_components,
                constraints,
                validation_report,
                release_certification,
            },
        })
    }

    /// Reconstructs a previously verified admission set from the substrate's
    /// content store. All joins are re-read from the canonical manifest,
    /// metadata and derivation descriptor before launch.
    pub fn from_persistent_store(
        mechanisms: &LocalMechanisms,
        manifest_digest: Sha256Digest,
    ) -> Result<Self, KernelError> {
        let manifest_bytes = stored_blob(mechanisms, manifest_digest)?;
        require_artifact_digest("active manifest", &manifest_bytes, manifest_digest)?;
        let manifest: LaunchManifest = parse_canonical_json(&manifest_bytes, "graph manifest")?;
        let metadata_digest = manifest.metadata.ok_or_else(|| {
            KernelError::InvalidConfiguration(
                "stored graph manifest has no evidence metadata digest".to_string(),
            )
        })?;
        let metadata = stored_content(mechanisms, metadata_digest)?;
        let metadata_value: LaunchMetadata =
            parse_canonical_json(&metadata.bytes, "graph metadata")?;
        let derivation_descriptor =
            stored_content(mechanisms, metadata_value.derivation_descriptor_digest)?;
        let descriptor_value: DerivationDescriptor =
            parse_canonical_json(&derivation_descriptor.bytes, "derivation descriptor")?;
        let substrate_profile =
            stored_content(mechanisms, metadata_value.substrate_profile_digest)?;
        let wit_package = stored_content(mechanisms, metadata_value.wit_package_digest)?;
        let (validation_report_digest, release_certification_digest) =
            mechanisms.root_certification_digests(manifest_digest)?;
        let validation_report = stored_content(mechanisms, validation_report_digest)?;
        let release_certification = stored_content(mechanisms, release_certification_digest)?;
        let certificate =
            SignedReleaseCertification::from_canonical_bytes(&release_certification.bytes)?;
        let certified_kernel_tcb_inventory = stored_content(
            mechanisms,
            certificate.statement.native_tcb_inventory_digest,
        )?;

        let mut source_components = Vec::new();
        let mut seen_sources = BTreeSet::new();
        for source in &descriptor_value.sources {
            if seen_sources.insert(source.component_digest) {
                source_components.push(stored_component(mechanisms, source.component_digest)?);
            }
        }

        let root_executable_digest = mechanisms.root_executable_digest(manifest_digest)?;
        let composed_root = stored_component(mechanisms, root_executable_digest)?;

        let mut execution_artifacts = Vec::new();
        let mut seen_executables = BTreeSet::new();
        for executable in &descriptor_value.executables {
            if executable.authority_node != manifest.root_node
                && executable.executable_digest != executable.authority_digest
                && seen_executables.insert(executable.executable_digest)
            {
                execution_artifacts
                    .push(stored_component(mechanisms, executable.executable_digest)?);
            }
        }

        let mut wit_worlds = Vec::new();
        let mut seen_worlds = BTreeSet::new();
        for digest in metadata_value.wit_world_digests.values().copied() {
            if seen_worlds.insert(digest) {
                wit_worlds.push(stored_content(mechanisms, digest)?);
            }
        }

        let mut composition_configurations = Vec::new();
        let mut seen_configurations = BTreeSet::new();
        for digest in descriptor_value
            .executables
            .iter()
            .map(|executable| executable.configuration_digest)
        {
            if seen_configurations.insert(digest) {
                composition_configurations.push(stored_content(mechanisms, digest)?);
            }
        }

        let mut scoped_components = Vec::new();
        let mut seen_scoped_components = BTreeSet::new();
        for digest in descriptor_value
            .executables
            .iter()
            .flat_map(|executable| executable.scoped_source_digests.iter().copied())
        {
            if seen_scoped_components.insert(digest) {
                scoped_components.push(stored_component(mechanisms, digest)?);
            }
        }

        let mut constraints = Vec::new();
        let mut seen_constraints = BTreeSet::new();
        for digest in manifest
            .nodes
            .iter()
            .flat_map(|node| node.grants.iter().map(|grant| grant.constraints))
        {
            if seen_constraints.insert(digest) {
                constraints.push(stored_content(mechanisms, digest)?);
            }
        }

        Ok(Self {
            manifest_bytes,
            manifest_digest,
            source_components,
            execution_artifacts,
            composed_root,
            evidence: RootEvidence {
                certified_kernel_tcb_inventory,
                metadata,
                derivation_descriptor,
                substrate_profile,
                wit_package,
                wit_worlds,
                composition_configurations,
                scoped_components,
                constraints,
                validation_report,
                release_certification,
            },
        })
    }

    fn verified_substrate_profile(&self) -> Result<SubstrateProfile, KernelError> {
        require_artifact_digest(
            "substrate profile",
            &self.evidence.substrate_profile.bytes,
            self.evidence.substrate_profile.digest,
        )?;
        let profile: SubstrateProfile =
            parse_canonical_json(&self.evidence.substrate_profile.bytes, "substrate profile")?;
        if !matches!(
            profile.schema.as_str(),
            SUBSTRATE_PROFILE_SCHEMA | SUBSTRATE_PROFILE_SCHEMA_V2 | SUBSTRATE_PROFILE_SCHEMA_V3
        ) || !valid_capability_constraints(&profile.ceilings)
        {
            return Err(KernelError::InvalidConfiguration(
                "package substrate ceiling is invalid".to_string(),
            ));
        }
        Ok(profile)
    }
}

fn digest_file_stem(digest: Sha256Digest) -> String {
    digest.to_string().replace(':', "-")
}

fn require_artifact_digest(
    label: &str,
    bytes: &[u8],
    expected: Sha256Digest,
) -> Result<(), KernelError> {
    let actual = Sha256Digest::from_bytes(bytes);
    if actual != expected {
        return Err(KernelError::ComponentDigestMismatch {
            node: label.to_string(),
            expected,
            actual,
        });
    }
    Ok(())
}

fn package_content(
    directory: &PackageDirectory,
    relative: &str,
    digest: Sha256Digest,
) -> Result<ContentArtifact, KernelError> {
    let bytes = directory.read(relative)?;
    require_artifact_digest(relative, &bytes, digest)?;
    Ok(ContentArtifact { digest, bytes })
}

fn package_component(
    directory: &PackageDirectory,
    relative: &str,
    digest: Sha256Digest,
) -> Result<AdmittedComponent, KernelError> {
    let bytes = directory.read(relative)?;
    require_artifact_digest(relative, &bytes, digest)?;
    Ok(AdmittedComponent { digest, bytes })
}

fn stored_blob(mechanisms: &LocalMechanisms, digest: Sha256Digest) -> Result<Vec<u8>, KernelError> {
    mechanisms
        .blob_bytes(digest)
        .map_err(|error| KernelError::Persistence(error.message))
}

fn stored_content(
    mechanisms: &LocalMechanisms,
    digest: Sha256Digest,
) -> Result<ContentArtifact, KernelError> {
    Ok(ContentArtifact {
        digest,
        bytes: stored_blob(mechanisms, digest)?,
    })
}

fn stored_component(
    mechanisms: &LocalMechanisms,
    digest: Sha256Digest,
) -> Result<AdmittedComponent, KernelError> {
    Ok(AdmittedComponent {
        digest,
        bytes: mechanisms
            .component_bytes(digest)
            .map_err(|error| KernelError::Persistence(error.message))?,
    })
}

fn verify_release_certification(
    admission: &RootAdmission,
    validated: &ValidatedLaunch,
    mechanisms: &LocalMechanisms,
) -> Result<(Sha256Digest, Sha256Digest), KernelError> {
    verify_content_artifact(
        &admission.evidence.validation_report,
        "strict validation report",
    )?;
    verify_content_artifact(
        &admission.evidence.release_certification,
        "release certification",
    )?;
    verify_content_artifact(
        &admission.evidence.certified_kernel_tcb_inventory,
        "certified kernel TCB inventory",
    )?;
    let certificate = SignedReleaseCertification::from_canonical_bytes(
        &admission.evidence.release_certification.bytes,
    )?;
    certificate.verify_signature(&mechanisms.require_certifier_trust()?)?;
    if certificate.statement.native_tcb_inventory_digest
        != admission.evidence.certified_kernel_tcb_inventory.digest
        || certificate.statement.native_tcb_inventory_digest
            != compiled_native_tcb_inventory_digest()
    {
        return Err(KernelError::InvalidConfiguration(
            "release certification does not bind the packaged compiled kernel TCB inventory"
                .to_string(),
        ));
    }

    let artifact_set = &validated.certification_closure;
    let expected = ReleaseCertificationStatement {
        schema: RELEASE_CERTIFICATION_STATEMENT_SCHEMA.to_string(),
        graph_manifest_digest: artifact_set.graph_manifest_digest,
        native_tcb_inventory_digest: compiled_native_tcb_inventory_digest(),
        wit_package_digest: artifact_set.wit_package_digest,
        metadata_digest: artifact_set.metadata_digest,
        raw_artifacts: artifact_set.raw_artifacts.clone(),
        derived_artifacts: artifact_set.derived_artifacts.clone(),
        derivation_descriptor_digest: artifact_set.derivation_descriptor_digest,
        substrate_profile_digest: artifact_set.substrate_profile_digest,
        wit_world_digests: artifact_set.wit_world_digests.clone(),
        composition_configuration_digests: artifact_set.composition_configuration_digests.clone(),
        constraint_digests: artifact_set.constraint_digests.clone(),
        validation_report_digest: admission.evidence.validation_report.digest,
        validator_identity: certificate.statement.validator_identity.clone(),
        validator_version: certificate.statement.validator_version.clone(),
    };
    if certificate.statement != expected {
        return Err(KernelError::InvalidConfiguration(
            "release certification does not exactly bind the admitted content set".to_string(),
        ));
    }
    Ok((
        admission.evidence.validation_report.digest,
        admission.evidence.release_certification.digest,
    ))
}

#[derive(Clone, Debug, Default)]
struct RootGrants {
    blob: BlobAccess,
    transaction_namespaces: BTreeSet<String>,
    clock: bool,
    component_runner: bool,
    http_transport: bool,
    key_service: bool,
    activation: bool,
    audit_append: bool,
    audit_read: bool,
}

struct RootState {
    mechanisms: LocalMechanisms,
    grants: RootGrants,
    active_principal: Option<ActivePrincipal>,
    limits: StoreLimits,
}

impl AliasState for RootState {
    fn mechanisms(&self) -> &LocalMechanisms {
        &self.mechanisms
    }

    fn active_principal_mut(&mut self) -> &mut Option<ActivePrincipal> {
        &mut self.active_principal
    }
}

impl RootState {
    fn blob_access(&self) -> BlobAccess {
        match active_scope(&self.active_principal, "blob-store") {
            Some("read") => BlobAccess {
                read: true,
                max_put_bytes: self.grants.blob.max_put_bytes,
                ..BlobAccess::default()
            },
            Some("write") => BlobAccess {
                write: true,
                max_put_bytes: self.grants.blob.max_put_bytes,
                ..BlobAccess::default()
            },
            Some("read-write") => BlobAccess {
                read: true,
                write: true,
                max_put_bytes: self.grants.blob.max_put_bytes,
            },
            Some(_) => BlobAccess::default(),
            None if self.active_principal.is_some() => BlobAccess::default(),
            None => self.grants.blob,
        }
    }

    fn transaction_allowed(&self, namespace: &str) -> bool {
        if self.active_principal.is_some() {
            active_scope(&self.active_principal, "transaction-store") == Some(namespace)
        } else {
            self.grants.transaction_namespaces.contains(namespace)
        }
    }

    fn granted(&self, capability: &str, scope: &str) -> bool {
        if self.active_principal.is_some() {
            return active_scope(&self.active_principal, capability)
                .is_some_and(|admitted| scope_is_subset(capability, scope, admitted));
        }
        match capability {
            "clock" => self.grants.clock,
            "component-runner" => self.grants.component_runner,
            "http-transport" => self.grants.http_transport,
            "key-service" => self.grants.key_service,
            "activation" => self.grants.activation,
            "audit-log" if scope == "append" => self.grants.audit_append,
            "audit-log" if scope == "read" => self.grants.audit_read,
            _ => false,
        }
    }
}

impl foundation::Host for RootState {}

impl blob_store::Host for RootState {
    fn put(
        &mut self,
        media_type: String,
        content: Vec<u8>,
    ) -> Result<foundation::BlobRef, foundation::Failure> {
        let access = self.blob_access();
        require_root_grant(access.write, "blob write")?;
        if u64::try_from(content.len()).unwrap_or(u64::MAX) > access.max_put_bytes {
            return Err(failure(
                "limit-exceeded",
                "blob write exceeds the root grant",
            ));
        }
        self.mechanisms.put_blob(media_type, content)
    }

    fn get(&mut self, reference: foundation::BlobRef) -> Result<Vec<u8>, foundation::Failure> {
        require_root_grant(self.blob_access().read, "blob read")?;
        self.mechanisms.get_blob(reference)
    }

    fn has(&mut self, digest: foundation::Digest) -> Result<bool, foundation::Failure> {
        require_root_grant(self.blob_access().read, "blob read")?;
        self.mechanisms.has_blob(digest)
    }
}

impl transaction_store::Host for RootState {
    fn read(
        &mut self,
        namespace: String,
        key: String,
    ) -> Result<Option<transaction_store::VersionedValue>, foundation::Failure> {
        if !self.transaction_allowed(&namespace) {
            return Err(failure(
                "not-granted",
                "transaction namespace is outside the root graph grant",
            ));
        }
        transaction_store::Host::read(&mut self.mechanisms, namespace, key)
    }

    fn commit(
        &mut self,
        request: transaction_store::CommitRequest,
    ) -> Result<transaction_store::CommitReceipt, foundation::Failure> {
        let in_scope = request
            .assertions
            .iter()
            .all(|assertion| self.transaction_allowed(&assertion.namespace))
            && request.mutations.iter().all(|mutation| match mutation {
                transaction_store::Mutation::Put((namespace, _, _))
                | transaction_store::Mutation::Delete((namespace, _)) => {
                    self.transaction_allowed(namespace)
                }
            });
        if !in_scope {
            return Err(failure(
                "not-granted",
                "transaction request escapes the root graph grant",
            ));
        }
        let caller = self
            .active_principal
            .as_ref()
            .map(|principal| principal.principal_seed);
        self.mechanisms
            .commit_transaction_for_principal(request, caller)
    }
}

impl clock::Host for RootState {
    fn now_ms(&mut self) -> u64 {
        if self.granted("clock", "wake") {
            clock::Host::now_ms(&mut self.mechanisms)
        } else {
            0
        }
    }

    fn schedule_wake(&mut self, request: clock::WakeRequest) -> Result<u64, foundation::Failure> {
        require_root_grant(self.granted("clock", "wake"), "clock")?;
        let caller = self
            .active_principal
            .as_ref()
            .map(|principal| principal.principal_seed);
        self.mechanisms.schedule_for_principal(request, caller)
    }

    fn poll_wake(
        &mut self,
        wake_id: String,
    ) -> Result<Option<clock::FiredWake>, foundation::Failure> {
        require_root_grant(self.granted("clock", "wake"), "clock")?;
        let caller = self
            .active_principal
            .as_ref()
            .map(|principal| principal.principal_seed);
        self.mechanisms
            .poll_scheduled_for_principal(wake_id, caller)
    }

    fn cancel_wake(&mut self, wake_id: String) -> Result<bool, foundation::Failure> {
        require_root_grant(self.granted("clock", "wake"), "clock")?;
        let caller = self
            .active_principal
            .as_ref()
            .map(|principal| principal.principal_seed);
        self.mechanisms
            .cancel_scheduled_for_principal(wake_id, caller)
    }
}

impl component_runner::Host for RootState {
    fn start(
        &mut self,
        request: component_runner::RunRequest,
    ) -> Result<String, foundation::Failure> {
        require_root_grant(self.granted("component-runner", "run"), "component-runner")?;
        let caller = self
            .active_principal
            .as_ref()
            .map(|principal| principal.principal_seed);
        start_task(self.mechanisms.clone(), request, caller)
    }

    fn poll(
        &mut self,
        operation_id: String,
    ) -> Result<Option<component_runner::RunCompletion>, foundation::Failure> {
        require_root_grant(self.granted("component-runner", "run"), "component-runner")?;
        let caller = self
            .active_principal
            .as_ref()
            .map(|principal| principal.principal_seed);
        self.mechanisms
            .poll_run_for_principal(&operation_id, caller)
            .map(|run| run.map(|stored| stored.completion))
    }

    fn cancel(&mut self, operation_id: String) -> Result<bool, foundation::Failure> {
        require_root_grant(self.granted("component-runner", "run"), "component-runner")?;
        let caller = self
            .active_principal
            .as_ref()
            .map(|principal| principal.principal_seed);
        self.mechanisms
            .cancel_run_for_principal(&operation_id, caller)
    }
}

impl http_transport::Host for RootState {
    fn start(&mut self, request: http_transport::Request) -> Result<String, foundation::Failure> {
        require_root_grant(self.granted("http-transport", "request"), "http-transport")?;
        match self.active_principal.as_ref() {
            Some(principal) => self
                .mechanisms
                .start_http_for_authority(request, principal.http_authority()),
            None => http_transport::Host::start(&mut self.mechanisms, request),
        }
    }

    fn poll(
        &mut self,
        operation_id: String,
    ) -> Result<Option<http_transport::Response>, foundation::Failure> {
        require_root_grant(self.granted("http-transport", "request"), "http-transport")?;
        match self.active_principal.as_ref() {
            Some(principal) => self
                .mechanisms
                .poll_http_for_authority(&operation_id, &principal.http_authority()),
            None => self.mechanisms.poll_http_for_principal(&operation_id, None),
        }
    }

    fn cancel(&mut self, operation_id: String) -> Result<bool, foundation::Failure> {
        require_root_grant(self.granted("http-transport", "request"), "http-transport")?;
        match self.active_principal.as_ref() {
            Some(principal) => self
                .mechanisms
                .cancel_http_for_authority(&operation_id, &principal.http_authority()),
            None => self
                .mechanisms
                .cancel_http_for_principal(&operation_id, None),
        }
    }
}

impl key_service::Host for RootState {
    fn sign_digest(
        &mut self,
        key_handle: String,
        payload: foundation::Digest,
    ) -> Result<key_service::Signature, foundation::Failure> {
        require_root_grant(self.granted("key-service", "use"), "key-service")?;
        key_service::Host::sign_digest(&mut self.mechanisms, key_handle, payload)
    }

    fn verify_digest(
        &mut self,
        key_id: String,
        payload: foundation::Digest,
        signature: key_service::Signature,
    ) -> Result<bool, foundation::Failure> {
        require_root_grant(self.granted("key-service", "use"), "key-service")?;
        key_service::Host::verify_digest(&mut self.mechanisms, key_id, payload, signature)
    }

    fn random_bytes(&mut self, length: u32) -> Result<Vec<u8>, foundation::Failure> {
        require_root_grant(self.granted("key-service", "use"), "key-service")?;
        key_service::Host::random_bytes(&mut self.mechanisms, length)
    }
}

impl activation::Host for RootState {
    fn active_manifest(&mut self) -> Result<Option<foundation::BlobRef>, foundation::Failure> {
        require_root_grant(self.granted("activation", "switch"), "activation")?;
        self.mechanisms.active_manifest_reference()
    }

    fn active_state(&mut self) -> Result<Option<foundation::BlobRef>, foundation::Failure> {
        require_root_grant(self.granted("activation", "switch"), "activation")?;
        self.mechanisms.active_state_reference()
    }

    fn stage(
        &mut self,
        request: activation::ActivationRequest,
    ) -> Result<activation::ActivationStatus, foundation::Failure> {
        require_root_grant(self.granted("activation", "switch"), "activation")?;
        let caller = self
            .active_principal
            .as_ref()
            .map(|principal| principal.principal_seed);
        self.mechanisms
            .stage_activation_for_principal(request, caller)
    }

    fn commit(
        &mut self,
        activation_id: String,
    ) -> Result<activation::ActivationStatus, foundation::Failure> {
        require_root_grant(self.granted("activation", "switch"), "activation")?;
        let caller = self
            .active_principal
            .as_ref()
            .map(|principal| principal.principal_seed);
        self.mechanisms
            .commit_activation_for_principal(activation_id, caller)
    }

    fn status(
        &mut self,
        activation_id: String,
    ) -> Result<activation::ActivationStatus, foundation::Failure> {
        require_root_grant(self.granted("activation", "switch"), "activation")?;
        let caller = self
            .active_principal
            .as_ref()
            .map(|principal| principal.principal_seed);
        self.mechanisms
            .activation_status_for_principal(activation_id, caller)
    }

    fn rollback(
        &mut self,
        activation_id: String,
        target_graph: foundation::Digest,
    ) -> Result<activation::ActivationStatus, foundation::Failure> {
        require_root_grant(self.granted("activation", "switch"), "activation")?;
        let caller = self
            .active_principal
            .as_ref()
            .map(|principal| principal.principal_seed);
        self.mechanisms
            .rollback_activation_for_principal(activation_id, target_graph, caller)
    }
}

impl audit_log::Host for RootState {
    fn append(
        &mut self,
        entry: audit_log::AuditEntry,
    ) -> Result<audit_log::AuditReceipt, foundation::Failure> {
        require_root_grant(self.granted("audit-log", "append"), "audit append")?;
        audit_log::Host::append(&mut self.mechanisms, entry)
    }

    fn resolve(
        &mut self,
        sequence: u64,
    ) -> Result<Option<audit_log::AuditEntry>, foundation::Failure> {
        require_root_grant(self.granted("audit-log", "read"), "audit read")?;
        audit_log::Host::resolve(&mut self.mechanisms, sequence)
    }
}

macro_rules! root_alias_func {
    ($instance:ident, $name:literal, $principal:expr, ($($arg:ident : $ty:ty),* $(,)?), |$state:ident| $body:block) => {{
        let principal = $principal.clone();
        $instance.func_wrap(
            $name,
            move |mut store: StoreContextMut<'_, RootState>, ($($arg,)*): ($($ty,)*)| {
                let request_digest = authority_request_digest(&($(&$arg,)*));
                let result = invoke_as_principal(
                    store.data_mut(),
                    &principal,
                    $name,
                    request_digest,
                    |$state| $body,
                );
                Ok((result,))
            },
        )?;
    }};
}

fn add_root_aliases_to_linker(
    linker: &mut Linker<RootState>,
    principals: &[ActivePrincipal],
) -> wasmtime::Result<()> {
    for principal in principals {
        match principal.host_import.capability.as_str() {
            "blob-store" => add_root_blob_alias(linker, principal)?,
            "transaction-store" => add_root_transaction_alias(linker, principal)?,
            "clock" => add_root_clock_alias(linker, principal)?,
            "component-runner" => add_root_runner_alias(linker, principal)?,
            "http-transport" => add_root_http_alias(linker, principal)?,
            "key-service" => add_root_key_alias(linker, principal)?,
            "activation" => add_root_activation_alias(linker, principal)?,
            "audit-log" => add_root_audit_alias(linker, principal)?,
            _ => return Err(wasmtime::Error::msg("unsupported R2 root capability alias")),
        }
    }
    Ok(())
}

fn add_root_blob_alias(
    linker: &mut Linker<RootState>,
    principal: &ActivePrincipal,
) -> wasmtime::Result<()> {
    let mut instance = linker.instance(&principal.host_import.alias)?;
    root_alias_func!(instance, "put", principal, (media_type: String, content: Vec<u8>), |state| {
        <RootState as blob_store::Host>::put(state, media_type, content)
    });
    root_alias_func!(instance, "get", principal, (reference: foundation::BlobRef), |state| {
        <RootState as blob_store::Host>::get(state, reference)
    });
    root_alias_func!(instance, "has", principal, (digest: foundation::Digest), |state| {
        <RootState as blob_store::Host>::has(state, digest)
    });
    Ok(())
}

fn add_root_transaction_alias(
    linker: &mut Linker<RootState>,
    principal: &ActivePrincipal,
) -> wasmtime::Result<()> {
    let mut instance = linker.instance(&principal.host_import.alias)?;
    root_alias_func!(instance, "read", principal, (namespace: String, key: String), |state| {
        <RootState as transaction_store::Host>::read(state, namespace, key)
    });
    root_alias_func!(instance, "commit", principal, (request: transaction_store::CommitRequest), |state| {
        <RootState as transaction_store::Host>::commit(state, request)
    });
    Ok(())
}

fn add_root_clock_alias(
    linker: &mut Linker<RootState>,
    principal: &ActivePrincipal,
) -> wasmtime::Result<()> {
    let mut instance = linker.instance(&principal.host_import.alias)?;
    root_alias_func!(instance, "now-ms", principal, (), |state| {
        <RootState as clock::Host>::now_ms(state)
    });
    root_alias_func!(instance, "schedule-wake", principal, (request: clock::WakeRequest), |state| {
        <RootState as clock::Host>::schedule_wake(state, request)
    });
    root_alias_func!(instance, "poll-wake", principal, (wake_id: String), |state| {
        <RootState as clock::Host>::poll_wake(state, wake_id)
    });
    root_alias_func!(instance, "cancel-wake", principal, (wake_id: String), |state| {
        <RootState as clock::Host>::cancel_wake(state, wake_id)
    });
    Ok(())
}

fn add_root_runner_alias(
    linker: &mut Linker<RootState>,
    principal: &ActivePrincipal,
) -> wasmtime::Result<()> {
    let mut instance = linker.instance(&principal.host_import.alias)?;
    root_alias_func!(instance, "start", principal, (request: component_runner::RunRequest), |state| {
        <RootState as component_runner::Host>::start(state, request)
    });
    root_alias_func!(instance, "poll", principal, (operation_id: String), |state| {
        <RootState as component_runner::Host>::poll(state, operation_id)
    });
    root_alias_func!(instance, "cancel", principal, (operation_id: String), |state| {
        <RootState as component_runner::Host>::cancel(state, operation_id)
    });
    Ok(())
}

fn add_root_http_alias(
    linker: &mut Linker<RootState>,
    principal: &ActivePrincipal,
) -> wasmtime::Result<()> {
    let mut instance = linker.instance(&principal.host_import.alias)?;
    root_alias_func!(instance, "start", principal, (request: http_transport::Request), |state| {
        <RootState as http_transport::Host>::start(state, request)
    });
    root_alias_func!(instance, "poll", principal, (operation_id: String), |state| {
        <RootState as http_transport::Host>::poll(state, operation_id)
    });
    root_alias_func!(instance, "cancel", principal, (operation_id: String), |state| {
        <RootState as http_transport::Host>::cancel(state, operation_id)
    });
    Ok(())
}

fn add_root_key_alias(
    linker: &mut Linker<RootState>,
    principal: &ActivePrincipal,
) -> wasmtime::Result<()> {
    let mut instance = linker.instance(&principal.host_import.alias)?;
    root_alias_func!(instance, "sign-digest", principal, (key_handle: String, payload: foundation::Digest), |state| {
        <RootState as key_service::Host>::sign_digest(state, key_handle, payload)
    });
    root_alias_func!(instance, "verify-digest", principal, (key_id: String, payload: foundation::Digest, signature: key_service::Signature), |state| {
        <RootState as key_service::Host>::verify_digest(state, key_id, payload, signature)
    });
    root_alias_func!(instance, "random-bytes", principal, (length: u32), |state| {
        <RootState as key_service::Host>::random_bytes(state, length)
    });
    Ok(())
}

fn add_root_activation_alias(
    linker: &mut Linker<RootState>,
    principal: &ActivePrincipal,
) -> wasmtime::Result<()> {
    let mut instance = linker.instance(&principal.host_import.alias)?;
    root_alias_func!(instance, "active-manifest", principal, (), |state| {
        <RootState as activation::Host>::active_manifest(state)
    });
    root_alias_func!(instance, "active-state", principal, (), |state| {
        <RootState as activation::Host>::active_state(state)
    });
    root_alias_func!(instance, "stage", principal, (request: activation::ActivationRequest), |state| {
        <RootState as activation::Host>::stage(state, request)
    });
    root_alias_func!(instance, "commit", principal, (activation_id: String), |state| {
        <RootState as activation::Host>::commit(state, activation_id)
    });
    root_alias_func!(instance, "status", principal, (activation_id: String), |state| {
        <RootState as activation::Host>::status(state, activation_id)
    });
    root_alias_func!(instance, "rollback", principal, (activation_id: String, target_graph: foundation::Digest), |state| {
        <RootState as activation::Host>::rollback(state, activation_id, target_graph)
    });
    Ok(())
}

fn add_root_audit_alias(
    linker: &mut Linker<RootState>,
    principal: &ActivePrincipal,
) -> wasmtime::Result<()> {
    let mut instance = linker.instance(&principal.host_import.alias)?;
    root_alias_func!(instance, "append", principal, (entry: audit_log::AuditEntry), |state| {
        <RootState as audit_log::Host>::append(state, entry)
    });
    root_alias_func!(instance, "resolve", principal, (sequence: u64), |state| {
        <RootState as audit_log::Host>::resolve(state, sequence)
    });
    Ok(())
}

/// Instantiated composed root with only the generated eight-interface linker.
pub struct OpaqueRootEngine {
    store: Store<RootState>,
    instance: root::FactoryRoot,
    binding: RootBinding,
    limits: ResourceLimits,
}

/// Exact manifest and derived-root content binding in use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RootBinding {
    /// Authoritative source manifest digest.
    pub manifest_digest: Sha256Digest,
    /// Derived composed root digest.
    pub composed_root_digest: Sha256Digest,
}

/// Policy-neutral owner of the instantiated root selected by the durable
/// active-manifest pointer.
pub struct OpaqueRootManager {
    mechanisms: LocalMechanisms,
    operator_capacity: ResourceLimits,
    engine: OpaqueRootEngine,
}

impl OpaqueRootManager {
    /// Verifies a package, instantiates its root and selects it only when the
    /// mechanism store has no active manifest yet.
    pub fn bootstrap(
        admission: RootAdmission,
        mechanisms: LocalMechanisms,
        operator_capacity: ResourceLimits,
    ) -> Result<Self, KernelError> {
        let manifest_digest = admission.manifest_digest;
        mechanisms.require_bootstrap_manifest_trust(manifest_digest)?;
        let limits = admission.bounded_root_limits(&operator_capacity)?;
        let engine = OpaqueRootEngine::load(admission, mechanisms.clone(), limits)?;
        mechanisms.bootstrap_active_manifest(manifest_digest)?;
        Ok(Self {
            mechanisms,
            operator_capacity,
            engine,
        })
    }

    /// Boots the exact active manifest from durable content. If its bytes no
    /// longer verify or instantiate, the manager boots the verified
    /// last-known-good manifest and atomically restores that pointer.
    pub fn boot(
        mechanisms: LocalMechanisms,
        operator_capacity: ResourceLimits,
    ) -> Result<Self, KernelError> {
        mechanisms.require_bootstrap_trust()?;
        let active = mechanisms.active_manifest_digest()?.ok_or_else(|| {
            KernelError::InvalidConfiguration("no active manifest is selected".to_string())
        })?;
        match load_stored_root(&mechanisms, active, &operator_capacity) {
            Ok(engine) => Ok(Self {
                mechanisms,
                operator_capacity,
                engine,
            }),
            Err(active_error) => {
                let previous = mechanisms
                    .last_known_good_manifest_digest()?
                    .ok_or(active_error.clone())?;
                let engine = load_stored_root(&mechanisms, previous, &operator_capacity)
                    .map_err(|_| active_error)?;
                let restored = mechanisms.restore_last_known_good_manifest(active)?;
                if restored != previous {
                    return Err(KernelError::InvalidConfiguration(
                        "restored manifest differs from the verified fallback".to_string(),
                    ));
                }
                Ok(Self {
                    mechanisms,
                    operator_capacity,
                    engine,
                })
            }
        }
    }

    /// Re-reads the durable pointer and replaces the current instance only
    /// after the newly selected graph has passed full admission and launch.
    /// A failed replacement restores the verified last-known-good pointer.
    pub fn reload_if_changed(&mut self) -> Result<bool, KernelError> {
        let selected = self.mechanisms.active_manifest_digest()?.ok_or_else(|| {
            KernelError::InvalidConfiguration("active manifest pointer disappeared".to_string())
        })?;
        if selected == self.engine.binding.manifest_digest {
            return Ok(false);
        }
        match load_stored_root(&self.mechanisms, selected, &self.operator_capacity) {
            Ok(engine) => {
                self.engine = engine;
                Ok(true)
            }
            Err(error) => {
                let previous = self
                    .mechanisms
                    .last_known_good_manifest_digest()?
                    .ok_or_else(|| error.clone())?;
                if previous != self.engine.binding.manifest_digest {
                    self.engine =
                        load_stored_root(&self.mechanisms, previous, &self.operator_capacity)
                            .map_err(|_| error.clone())?;
                }
                let restored = self.mechanisms.restore_last_known_good_manifest(selected)?;
                if restored != previous {
                    return Err(KernelError::InvalidConfiguration(
                        "restored manifest differs from the running fallback".to_string(),
                    ));
                }
                Err(error)
            }
        }
    }

    /// Returns the exact manifest/root binding of the running instance.
    #[must_use]
    pub const fn binding(&self) -> RootBinding {
        self.engine.binding()
    }

    /// Borrows the generated typed root entry points.
    pub fn root(&mut self) -> &mut OpaqueRootEngine {
        &mut self.engine
    }
}

fn load_stored_root(
    mechanisms: &LocalMechanisms,
    manifest_digest: Sha256Digest,
    operator_capacity: &ResourceLimits,
) -> Result<OpaqueRootEngine, KernelError> {
    let admission = RootAdmission::from_persistent_store(mechanisms, manifest_digest)?;
    let limits = admission.bounded_root_limits(operator_capacity)?;
    OpaqueRootEngine::load(admission, mechanisms.clone(), limits)
}

impl OpaqueRootEngine {
    /// Verifies and admits the exact graph set, then instantiates the composed
    /// root with no linker imports beyond the generated native boundary.
    pub fn load(
        admission: RootAdmission,
        mechanisms: LocalMechanisms,
        limits: ResourceLimits,
    ) -> Result<Self, KernelError> {
        validate_runtime_limits(&limits)?;
        let actual_manifest = Sha256Digest::from_bytes(&admission.manifest_bytes);
        if actual_manifest != admission.manifest_digest {
            return Err(KernelError::ManifestDigestMismatch {
                expected: admission.manifest_digest,
                actual: actual_manifest,
            });
        }
        let validated = validate_launch_admission(&admission)?;
        let (validation_report_digest, release_certification_digest) =
            verify_release_certification(&admission, &validated, &mechanisms)?;
        mechanisms.verify_configured_ceiling(&required_capacity(&validated.ceilings))?;
        if limits.fuel > validated.ceilings.max_component_fuel
            || limits.max_memory_bytes > validated.ceilings.max_component_memory_bytes
        {
            return Err(KernelError::InvalidConfiguration(
                "root runtime limits exceed manifest-bound ceilings".to_string(),
            ));
        }
        let root_grants = build_root_grants(&validated)?;
        let root_aliases = active_principals(
            admission.manifest_digest,
            admission.composed_root.digest,
            &validated.r2_root_principal_seeds,
            &validated.r2_principals,
        )?;
        let is_r2 = !validated.r2_principals.is_empty();

        mechanisms
            .put_blob(
                ROOT_MANIFEST_MEDIA_TYPE.to_string(),
                admission.manifest_bytes,
            )
            .map_err(|error| KernelError::Persistence(error.message))?;
        for artifact in [
            &admission.evidence.certified_kernel_tcb_inventory,
            &admission.evidence.metadata,
            &admission.evidence.derivation_descriptor,
            &admission.evidence.substrate_profile,
            &admission.evidence.wit_package,
        ]
        .into_iter()
        .chain(admission.evidence.wit_worlds.iter())
        .chain(admission.evidence.composition_configurations.iter())
        .chain(admission.evidence.constraints.iter())
        .chain([
            &admission.evidence.validation_report,
            &admission.evidence.release_certification,
        ]) {
            mechanisms
                .put_blob(
                    "application/octet-stream".to_string(),
                    artifact.bytes.clone(),
                )
                .map_err(|error| KernelError::Persistence(error.message))?;
        }
        for artifact in &admission.source_components {
            mechanisms.admit_component(artifact.digest, &artifact.bytes)?;
        }
        for artifact in &admission.evidence.scoped_components {
            mechanisms.admit_component(artifact.digest, &artifact.bytes)?;
        }
        for artifact in &admission.execution_artifacts {
            mechanisms.admit_component(artifact.digest, &artifact.bytes)?;
        }
        mechanisms.admit_component(
            admission.composed_root.digest,
            &admission.composed_root.bytes,
        )?;
        mechanisms.admit_root_binding(RootBindingAdmission {
            manifest_digest: admission.manifest_digest,
            composed_root_digest: admission.composed_root.digest,
            source_component_digests: &validated.source_digests,
            execution_bindings: &validated.execution_bindings,
            r2_principals: &validated.r2_principals,
            r2_invocations: &validated.r2_invocations,
            r2_root_principal_seeds: &validated.r2_root_principal_seeds,
            validation_report_digest,
            release_certification_digest,
        })?;
        let mechanisms = mechanisms.scoped_to_graph(admission.manifest_digest)?;

        let mut config = Config::new();
        config.consume_fuel(true);
        config.epoch_interruption(true);
        let engine =
            Engine::new(&config).map_err(|error| KernelError::Engine(error.to_string()))?;
        let component =
            Component::new(&engine, &admission.composed_root.bytes).map_err(|error| {
                KernelError::Compile {
                    node: admission.composed_root.digest.to_string(),
                    reason: error.to_string(),
                }
            })?;
        let mut linker = Linker::<RootState>::new(&engine);
        let link_result = if is_r2 {
            add_root_aliases_to_linker(&mut linker, &root_aliases)
        } else {
            root::FactoryRoot::add_to_linker::<_, HasSelf<_>>(&mut linker, |state| state)
        };
        link_result.map_err(|error| KernelError::Link {
            node: admission.composed_root.digest.to_string(),
            reason: error.to_string(),
        })?;
        let mut store = Store::new(
            &engine,
            RootState {
                mechanisms,
                grants: root_grants,
                active_principal: None,
                limits: build_store_limits(&limits)?,
            },
        );
        store.limiter(|state| &mut state.limits);
        store
            .set_fuel(limits.fuel)
            .map_err(|error| KernelError::Instantiate {
                node: admission.composed_root.digest.to_string(),
                reason: error.to_string(),
            })?;
        store.set_epoch_deadline(1);
        let instance =
            root::FactoryRoot::instantiate(&mut store, &component, &linker).map_err(|error| {
                KernelError::Instantiate {
                    node: admission.composed_root.digest.to_string(),
                    reason: format!("{error:#}"),
                }
            })?;

        Ok(Self {
            store,
            instance,
            binding: RootBinding {
                manifest_digest: admission.manifest_digest,
                composed_root_digest: admission.composed_root.digest,
            },
            limits,
        })
    }

    /// Returns the exact source-manifest and composed-root binding.
    #[must_use]
    pub const fn binding(&self) -> RootBinding {
        self.binding
    }

    /// Returns the effective per-call root limits after intersecting operator
    /// capacity with the active graph's verified ceiling.
    #[must_use]
    pub const fn resource_limits(&self) -> &ResourceLimits {
        &self.limits
    }

    /// Forwards an opaque blob reference to the root control export.
    pub fn submit(
        &mut self,
        event: &foundation::BlobRef,
    ) -> Result<Result<String, foundation::Failure>, KernelError> {
        self.reset_fuel()?;
        self.instance
            .wasm_biotic_factory_factory_control()
            .call_submit(&mut self.store, event)
            .map_err(|error| self.invocation_error(error))
    }

    /// Forwards an opaque identifier to the root inspection export.
    pub fn inspect(
        &mut self,
        id: &str,
    ) -> Result<Result<foundation::BlobRef, foundation::Failure>, KernelError> {
        self.reset_fuel()?;
        self.instance
            .wasm_biotic_factory_factory_control()
            .call_inspect(&mut self.store, id)
            .map_err(|error| self.invocation_error(error))
    }

    /// Forwards opaque cancellation inputs to the root export.
    pub fn cancel(
        &mut self,
        id: &str,
        reason: &foundation::BlobRef,
    ) -> Result<Result<foundation::BlobRef, foundation::Failure>, KernelError> {
        self.reset_fuel()?;
        self.instance
            .wasm_biotic_factory_factory_control()
            .call_cancel(&mut self.store, id, reason)
            .map_err(|error| self.invocation_error(error))
    }

    /// Forwards an opaque recovery reference to the root export.
    pub fn recover(
        &mut self,
        request: &foundation::BlobRef,
    ) -> Result<Result<foundation::BlobRef, foundation::Failure>, KernelError> {
        self.reset_fuel()?;
        self.instance
            .wasm_biotic_factory_factory_control()
            .call_recover(&mut self.store, request)
            .map_err(|error| self.invocation_error(error))
    }

    /// Forwards an ingress byte envelope to the root API export.
    pub fn handle(
        &mut self,
        request: &root::exports::wasm_biotic::factory::factory_api::IngressRequest,
    ) -> Result<
        Result<
            root::exports::wasm_biotic::factory::factory_api::IngressResponse,
            foundation::Failure,
        >,
        KernelError,
    > {
        self.reset_fuel()?;
        self.instance
            .wasm_biotic_factory_factory_api()
            .call_handle(&mut self.store, request)
            .map_err(|error| self.invocation_error(error))
    }

    fn reset_fuel(&mut self) -> Result<(), KernelError> {
        let selected = self
            .store
            .data()
            .mechanisms
            .active_manifest_digest()?
            .ok_or_else(|| {
                KernelError::InvalidConfiguration(
                    "root entry point cannot run without an active manifest".to_string(),
                )
            })?;
        if selected != self.binding.manifest_digest {
            return Err(KernelError::InvalidConfiguration(
                "root entry point is not bound to the active manifest".to_string(),
            ));
        }
        self.store
            .set_fuel(self.limits.fuel)
            .map_err(|error| self.invocation_error(error))?;
        self.store.set_epoch_deadline(1);
        Ok(())
    }

    fn invocation_error(&self, error: wasmtime::Error) -> KernelError {
        let remaining = self.store.get_fuel().unwrap_or_default();
        KernelError::Invoke {
            node: self.binding.composed_root_digest.to_string(),
            reason: format!("{error:#}"),
            fuel_exhausted: error.downcast_ref::<Trap>() == Some(&Trap::OutOfFuel),
            fuel_consumed: self.limits.fuel.saturating_sub(remaining),
        }
    }
}

pub(crate) fn start_task(
    mechanisms: LocalMechanisms,
    request: component_runner::RunRequest,
    caller_principal_seed: Option<Sha256Digest>,
) -> Result<String, foundation::Failure> {
    let component_digest = validate_digest(&request.component_digest)?;
    if let Some(caller) = caller_principal_seed {
        mechanisms.enforce_component_invocation(caller, component_digest)?;
    }
    let idempotency = validate_digest(&request.idempotency_key)?.to_string();
    let request_digest = canonical_digest(&request)?;
    mechanisms.get_blob(request.input.clone())?;
    let (bytes, mut provenance) = mechanisms.resolve_execution(component_digest)?;
    let principals = mechanisms.execution_principals(component_digest)?;
    if !principals.is_empty() && caller_principal_seed.is_none() {
        return Err(failure(
            "not-granted",
            "R2 component execution requires an alias-bound caller principal",
        ));
    }
    provenance.caller_principal_seed = caller_principal_seed;
    let (grants, bound_ceiling) =
        parse_task_grants(&mechanisms, component_digest, &request.grants)?;
    let limits = validate_requested_limits(&mechanisms, &request.limits, bound_ceiling.as_ref())?;
    let operation_scope =
        mechanisms.component_operation_scope(&idempotency, caller_principal_seed)?;
    if let Some(existing) = mechanisms.existing_run(
        &operation_scope,
        &request_digest,
        provenance.graph_manifest_digest,
        caller_principal_seed,
    )? {
        return Ok(existing.operation_id);
    }
    let started_at_ms = mechanisms.now_ms();
    mechanisms.inject_runtime_fault(
        DurabilityFaultPoint::BeforeComponentDispatch,
        "component-run",
    )?;
    let outcome = invoke_task(TaskInvocation {
        mechanisms: mechanisms.clone(),
        bytes: &bytes,
        input: task_blob_from_root(request.input.clone()),
        grants,
        limits,
        graph_manifest_digest: provenance.graph_manifest_digest,
        executable_component_digest: provenance.executable_component_digest,
        principals,
    });
    mechanisms.inject_runtime_fault(
        DurabilityFaultPoint::AfterComponentDispatch,
        "component-run",
    )?;
    let outcome_digest = Sha256Digest::from_bytes(
        &serde_json::to_vec(&outcome)
            .map_err(|_| failure("encoding-error", "could not encode run outcome"))?,
    );
    let finished_at_ms = mechanisms.now_ms();
    let request_sha: Sha256Digest = request_digest
        .parse()
        .map_err(|_| failure("invalid-digest", "request digest could not be parsed"))?;
    mechanisms.inject_runtime_fault(
        DurabilityFaultPoint::BeforeComponentCompletion,
        "component-run",
    )?;
    let completion = component_runner::RunCompletion {
        run_id: request.run_id,
        outcome,
        receipt: effect_receipt(
            request_sha,
            component_digest,
            outcome_digest,
            started_at_ms,
            finished_at_ms,
            0,
        ),
    };
    mechanisms.inject_runtime_fault(
        DurabilityFaultPoint::AfterComponentCompletion,
        "component-run",
    )?;
    let operation_id = format!(
        "operation-{}",
        operation_scope.trim_start_matches("sha256:")
    );
    mechanisms.inject_runtime_fault(
        DurabilityFaultPoint::BeforeRunReceiptCommit,
        "component-run",
    )?;
    mechanisms.record_run(
        operation_scope,
        StoredRun {
            request_digest,
            operation_id: operation_id.clone(),
            completion,
            provenance: Some(provenance),
            caller_principal_seed,
        },
    )?;
    mechanisms
        .inject_runtime_fault(DurabilityFaultPoint::AfterRunReceiptCommit, "component-run")?;
    Ok(operation_id)
}

macro_rules! task_alias_func {
    ($instance:ident, $name:literal, $principal:expr, ($($arg:ident : $ty:ty),* $(,)?), |$state:ident| $body:block) => {{
        let principal = $principal.clone();
        $instance.func_wrap(
            $name,
            move |mut store: StoreContextMut<'_, TaskState>, ($($arg,)*): ($($ty,)*)| {
                let request_digest = authority_request_digest(&($(&$arg,)*));
                let result = invoke_as_principal(
                    store.data_mut(),
                    &principal,
                    $name,
                    request_digest,
                    |$state| $body,
                );
                Ok((result,))
            },
        )?;
    }};
}

fn add_task_aliases_to_linker(
    linker: &mut Linker<TaskState>,
    principals: &[ActivePrincipal],
) -> wasmtime::Result<()> {
    for principal in principals {
        match principal.host_import.capability.as_str() {
            "blob-store" => add_task_blob_alias(linker, principal)?,
            "transaction-store" => add_task_transaction_alias(linker, principal)?,
            "clock" => add_task_clock_alias(linker, principal)?,
            "component-runner" => add_task_runner_alias(linker, principal)?,
            "http-transport" => add_task_http_alias(linker, principal)?,
            "key-service" => add_task_key_alias(linker, principal)?,
            "activation" => add_task_activation_alias(linker, principal)?,
            "audit-log" => add_task_audit_alias(linker, principal)?,
            _ => return Err(wasmtime::Error::msg("unsupported R2 task capability alias")),
        }
    }
    Ok(())
}

fn add_task_blob_alias(
    linker: &mut Linker<TaskState>,
    principal: &ActivePrincipal,
) -> wasmtime::Result<()> {
    let mut instance = linker.instance(&principal.host_import.alias)?;
    task_alias_func!(instance, "put", principal, (media_type: String, content: Vec<u8>), |state| {
        <TaskState as task::wasm_biotic::factory::blob_store::Host>::put(state, media_type, content)
    });
    task_alias_func!(instance, "get", principal, (reference: task::wasm_biotic::factory::foundation::BlobRef), |state| {
        <TaskState as task::wasm_biotic::factory::blob_store::Host>::get(state, reference)
    });
    task_alias_func!(instance, "has", principal, (digest: task::wasm_biotic::factory::foundation::Digest), |state| {
        <TaskState as task::wasm_biotic::factory::blob_store::Host>::has(state, digest)
    });
    Ok(())
}

fn add_task_transaction_alias(
    linker: &mut Linker<TaskState>,
    principal: &ActivePrincipal,
) -> wasmtime::Result<()> {
    let mut instance = linker.instance(&principal.host_import.alias)?;
    task_alias_func!(instance, "read", principal, (namespace: String, key: String), |state| {
        <TaskState as task_transaction_store::Host>::read(state, namespace, key)
    });
    task_alias_func!(instance, "commit", principal, (request: task_transaction_store::CommitRequest), |state| {
        <TaskState as task_transaction_store::Host>::commit(state, request)
    });
    Ok(())
}

fn add_task_clock_alias(
    linker: &mut Linker<TaskState>,
    principal: &ActivePrincipal,
) -> wasmtime::Result<()> {
    let mut instance = linker.instance(&principal.host_import.alias)?;
    task_alias_func!(instance, "now-ms", principal, (), |state| {
        <TaskState as task_clock::Host>::now_ms(state)
    });
    task_alias_func!(instance, "schedule-wake", principal, (request: task_clock::WakeRequest), |state| {
        <TaskState as task_clock::Host>::schedule_wake(state, request)
    });
    task_alias_func!(instance, "poll-wake", principal, (wake_id: String), |state| {
        <TaskState as task_clock::Host>::poll_wake(state, wake_id)
    });
    task_alias_func!(instance, "cancel-wake", principal, (wake_id: String), |state| {
        <TaskState as task_clock::Host>::cancel_wake(state, wake_id)
    });
    Ok(())
}

fn add_task_runner_alias(
    linker: &mut Linker<TaskState>,
    principal: &ActivePrincipal,
) -> wasmtime::Result<()> {
    let mut instance = linker.instance(&principal.host_import.alias)?;
    task_alias_func!(instance, "start", principal, (request: task_component_runner::RunRequest), |state| {
        <TaskState as task_component_runner::Host>::start(state, request)
    });
    task_alias_func!(instance, "poll", principal, (operation_id: String), |state| {
        <TaskState as task_component_runner::Host>::poll(state, operation_id)
    });
    task_alias_func!(instance, "cancel", principal, (operation_id: String), |state| {
        <TaskState as task_component_runner::Host>::cancel(state, operation_id)
    });
    Ok(())
}

fn add_task_http_alias(
    linker: &mut Linker<TaskState>,
    principal: &ActivePrincipal,
) -> wasmtime::Result<()> {
    let mut instance = linker.instance(&principal.host_import.alias)?;
    task_alias_func!(instance, "start", principal, (request: task_http_transport::Request), |state| {
        <TaskState as task_http_transport::Host>::start(state, request)
    });
    task_alias_func!(instance, "poll", principal, (operation_id: String), |state| {
        <TaskState as task_http_transport::Host>::poll(state, operation_id)
    });
    task_alias_func!(instance, "cancel", principal, (operation_id: String), |state| {
        <TaskState as task_http_transport::Host>::cancel(state, operation_id)
    });
    Ok(())
}

fn add_task_key_alias(
    linker: &mut Linker<TaskState>,
    principal: &ActivePrincipal,
) -> wasmtime::Result<()> {
    let mut instance = linker.instance(&principal.host_import.alias)?;
    task_alias_func!(instance, "sign-digest", principal, (key_handle: String, payload: task::wasm_biotic::factory::foundation::Digest), |state| {
        <TaskState as task_key_service::Host>::sign_digest(state, key_handle, payload)
    });
    task_alias_func!(instance, "verify-digest", principal, (key_id: String, payload: task::wasm_biotic::factory::foundation::Digest, signature: task_key_service::Signature), |state| {
        <TaskState as task_key_service::Host>::verify_digest(state, key_id, payload, signature)
    });
    task_alias_func!(instance, "random-bytes", principal, (length: u32), |state| {
        <TaskState as task_key_service::Host>::random_bytes(state, length)
    });
    Ok(())
}

fn add_task_activation_alias(
    linker: &mut Linker<TaskState>,
    principal: &ActivePrincipal,
) -> wasmtime::Result<()> {
    let mut instance = linker.instance(&principal.host_import.alias)?;
    task_alias_func!(instance, "active-manifest", principal, (), |state| {
        <TaskState as task_activation::Host>::active_manifest(state)
    });
    task_alias_func!(instance, "active-state", principal, (), |state| {
        <TaskState as task_activation::Host>::active_state(state)
    });
    task_alias_func!(instance, "stage", principal, (request: task_activation::ActivationRequest), |state| {
        <TaskState as task_activation::Host>::stage(state, request)
    });
    task_alias_func!(instance, "commit", principal, (activation_id: String), |state| {
        <TaskState as task_activation::Host>::commit(state, activation_id)
    });
    task_alias_func!(instance, "status", principal, (activation_id: String), |state| {
        <TaskState as task_activation::Host>::status(state, activation_id)
    });
    task_alias_func!(instance, "rollback", principal, (activation_id: String, target_graph: task::wasm_biotic::factory::foundation::Digest), |state| {
        <TaskState as task_activation::Host>::rollback(state, activation_id, target_graph)
    });
    Ok(())
}

fn add_task_audit_alias(
    linker: &mut Linker<TaskState>,
    principal: &ActivePrincipal,
) -> wasmtime::Result<()> {
    let mut instance = linker.instance(&principal.host_import.alias)?;
    task_alias_func!(instance, "append", principal, (entry: task_audit_log::AuditEntry), |state| {
        <TaskState as task_audit_log::Host>::append(state, entry)
    });
    task_alias_func!(instance, "resolve", principal, (sequence: u64), |state| {
        <TaskState as task_audit_log::Host>::resolve(state, sequence)
    });
    Ok(())
}

struct TaskInvocation<'a> {
    mechanisms: LocalMechanisms,
    bytes: &'a [u8],
    input: task::wasm_biotic::factory::foundation::BlobRef,
    grants: TaskGrants,
    limits: TaskExecutionLimits,
    graph_manifest_digest: Option<Sha256Digest>,
    executable_component_digest: Sha256Digest,
    principals: Vec<AdmittedPrincipal>,
}

fn invoke_task(invocation: TaskInvocation<'_>) -> foundation::TerminalOutcome {
    let TaskInvocation {
        mechanisms,
        bytes,
        input,
        grants,
        limits,
        graph_manifest_digest,
        executable_component_digest,
        principals,
    } = invocation;
    let verifier = mechanisms.clone();
    let result = (|| -> wasmtime::Result<Result<task::wasm_biotic::factory::foundation::BlobRef, task::wasm_biotic::factory::foundation::Failure>> {
        let mut config = Config::new();
        config.consume_fuel(true);
        config.epoch_interruption(true);
        let engine = Engine::new(&config)?;
        let component = Component::new(&engine, bytes)?;
        let mut linker = Linker::<TaskState>::new(&engine);
        if principals.is_empty() {
            task::AdmittedTaskComponent::add_to_linker::<_, HasSelf<_>>(&mut linker, |state| state)?;
        } else {
            let graph_manifest_digest = graph_manifest_digest
                .ok_or_else(|| wasmtime::Error::msg("R2 task has no graph binding"))?;
            let selected_seeds = principals
                .iter()
                .map(|principal| principal.principal_seed)
                .collect::<Vec<_>>();
            let active = active_principals(
                graph_manifest_digest,
                executable_component_digest,
                &selected_seeds,
                &principals,
            )
            .map_err(|error| wasmtime::Error::msg(error.to_string()))?;
            add_task_aliases_to_linker(&mut linker, &active)?;
        }
        let memory_size = usize::try_from(limits.memory)
            .map_err(|_| wasmtime::Error::msg("memory limit is out of range"))?;
        let mut store = Store::new(
            &engine,
            TaskState {
                mechanisms,
                grants,
                active_principal: None,
                limits: StoreLimitsBuilder::new()
                    .memory_size(memory_size)
                    .instances(MAX_TASK_INSTANCES)
                    .memories(MAX_TASK_MEMORIES)
                    .tables(MAX_TASK_TABLES)
                    .table_elements(MAX_TASK_TABLE_ELEMENTS)
                    .trap_on_grow_failure(true)
                    .build(),
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
            .call_run(&mut store, &input)
    })();

    match result {
        Ok(Ok(reference)) => {
            let reference = task_blob_to_root(reference);
            if reference.size_bytes > limits.output {
                foundation::TerminalOutcome::Exhausted(failure(
                    "limit-exceeded",
                    "component output exceeds the requested bound",
                ))
            } else if let Err(error) = verifier.get_blob(reference.clone()) {
                foundation::TerminalOutcome::Failed(error)
            } else {
                foundation::TerminalOutcome::Succeeded(reference)
            }
        }
        Ok(Err(error)) => foundation::TerminalOutcome::Rejected(task_failure_to_root(error)),
        Err(error)
            if matches!(
                error.downcast_ref::<Trap>(),
                Some(Trap::OutOfFuel | Trap::Interrupt)
            ) =>
        {
            foundation::TerminalOutcome::Exhausted(failure(
                "execution-exhausted",
                "component exceeded a deterministic execution bound",
            ))
        }
        Err(error) => foundation::TerminalOutcome::Failed(failure(
            "component-failed",
            format!("component invocation failed: {error:#}"),
        )),
    }
}

fn parse_task_grants(
    mechanisms: &LocalMechanisms,
    authority_digest: Sha256Digest,
    grants: &[foundation::CapabilityGrant],
) -> Result<(TaskGrants, Option<CapabilityConstraints>), foundation::Failure> {
    let admitted = mechanisms.admitted_run_grants(authority_digest)?;
    let bound_ceiling = admitted
        .as_deref()
        .map(|grants| load_bound_ceiling(mechanisms, grants))
        .transpose()?;
    let mut parsed = TaskGrants {
        blob: BlobAccess {
            max_put_bytes: mechanisms.max_blob_bytes(),
            ..BlobAccess::default()
        },
        ..TaskGrants::default()
    };
    let mut seen = BTreeSet::new();
    for grant in grants {
        if !crate::HOST_INTERFACE_ALLOWLIST.contains(&grant.capability.as_str()) {
            return Err(failure(
                "not-allowlisted",
                "run grant names a non-host interface",
            ));
        }
        if !seen.insert(grant.capability.clone()) {
            return Err(failure(
                "invalid-request",
                "run grants contain a duplicate interface",
            ));
        }
        let bound = match_admitted_run_grant(admitted.as_deref(), grant)?;
        let constraint_bytes = if let Some(bound) = bound {
            if let Some(reference) = &grant.constraints {
                let supplied = validate_digest(&reference.content_digest)?;
                if supplied != bound.constraint_digest {
                    return Err(failure(
                        "not-granted",
                        "requested run constraint substitutes a different digest",
                    ));
                }
                mechanisms.get_blob(reference.clone())?;
            }
            Some(mechanisms.constraint_bytes(bound.constraint_digest)?)
        } else if let Some(reference) = &grant.constraints {
            Some(mechanisms.get_blob(reference.clone())?)
        } else {
            None
        };
        if grant.capability == "blob-store"
            && let Some(bytes) = constraint_bytes
        {
            if admitted.is_some() {
                let constraint: CapabilityConstraints =
                    parse_canonical_wit_json(&bytes, "bound capability constraints")?;
                if !valid_capability_constraints(&constraint) {
                    return Err(failure(
                        "invalid-constraint",
                        "bound capability constraint is invalid",
                    ));
                }
                parsed.blob.max_put_bytes =
                    parsed.blob.max_put_bytes.min(constraint.max_blob_bytes);
            } else {
                let constraint: BlobConstraint = serde_json::from_slice(&bytes).map_err(|_| {
                    failure("invalid-constraint", "blob constraint is not valid JSON")
                })?;
                if constraint.schema != BLOB_CONSTRAINT_SCHEMA || constraint.max_put_bytes == 0 {
                    return Err(failure(
                        "invalid-constraint",
                        "blob constraint schema or bound is invalid",
                    ));
                }
                parsed.blob.max_put_bytes = parsed.blob.max_put_bytes.min(constraint.max_put_bytes);
            }
        }
        match grant.capability.as_str() {
            "blob-store" => match grant.scope.as_str() {
                "read" => parsed.blob.read = true,
                "write" => parsed.blob.write = true,
                "read-write" => {
                    parsed.blob.read = true;
                    parsed.blob.write = true;
                }
                _ => {
                    return Err(failure(
                        "out-of-scope",
                        "blob grant scope is not recognized",
                    ));
                }
            },
            "transaction-store" => {
                validate_opaque_scope(&grant.scope)?;
                if bound_ceiling
                    .as_ref()
                    .is_some_and(|ceiling| !ceiling.transaction_namespaces.contains(&grant.scope))
                {
                    return Err(failure(
                        "not-granted",
                        "transaction namespace exceeds the bound constraint document",
                    ));
                }
                parsed.transaction_namespace = Some(grant.scope.clone());
            }
            "clock" if grant.scope == "wake" => parsed.clock = true,
            "component-runner" if grant.scope == "run" => parsed.component_runner = true,
            "http-transport" if grant.scope == "request" => parsed.http_transport = true,
            "key-service" if grant.scope == "use" => parsed.key_service = true,
            "activation" if grant.scope == "switch" => parsed.activation = true,
            "audit-log" => match grant.scope.as_str() {
                "append" => parsed.audit_append = true,
                "read" => parsed.audit_read = true,
                "append-read" => {
                    parsed.audit_append = true;
                    parsed.audit_read = true;
                }
                _ => {
                    return Err(failure(
                        "out-of-scope",
                        "audit grant scope is not recognized",
                    ));
                }
            },
            _ => {
                return Err(failure(
                    "out-of-scope",
                    "run grant scope is not recognized for its host interface",
                ));
            }
        }
    }
    Ok((parsed, bound_ceiling))
}

fn match_admitted_run_grant<'a>(
    admitted: Option<&'a [AdmittedGrant]>,
    requested: &foundation::CapabilityGrant,
) -> Result<Option<&'a AdmittedGrant>, foundation::Failure> {
    let bound = admitted.and_then(|grants| {
        grants.iter().find(|candidate| {
            candidate.capability == requested.capability
                && scope_is_subset(
                    requested.capability.as_str(),
                    requested.scope.as_str(),
                    candidate.scope.as_str(),
                )
        })
    });
    if admitted.is_some() && bound.is_none() {
        return Err(failure(
            "not-granted",
            "requested run grant exceeds the target executable's signed principal grant set",
        ));
    }
    Ok(bound)
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

fn load_bound_ceiling(
    mechanisms: &LocalMechanisms,
    grants: &[AdmittedGrant],
) -> Result<CapabilityConstraints, foundation::Failure> {
    let mut merged: Option<CapabilityConstraints> = None;
    let mut seen = BTreeSet::new();
    for grant in grants {
        if grant.capability == "http-transport" {
            continue;
        }
        if !seen.insert(grant.constraint_digest) {
            continue;
        }
        let bytes = mechanisms.constraint_bytes(grant.constraint_digest)?;
        let value: CapabilityConstraints =
            parse_canonical_wit_json(&bytes, "bound capability constraints")?;
        if !valid_capability_constraints(&value) {
            return Err(failure(
                "invalid-constraint",
                "bound capability constraint is invalid",
            ));
        }
        merged = Some(match merged {
            None => value,
            Some(previous) => intersect_constraints(previous, value),
        });
    }
    merged.ok_or_else(|| {
        failure(
            "invalid-constraint",
            "manifest-bound executable has no constraint document",
        )
    })
}

fn intersect_constraints(
    left: CapabilityConstraints,
    right: CapabilityConstraints,
) -> CapabilityConstraints {
    let left_namespaces = left
        .transaction_namespaces
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let right_namespaces = right
        .transaction_namespaces
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    CapabilityConstraints {
        schema: CAPABILITY_CONSTRAINTS_SCHEMA.to_string(),
        max_blob_bytes: left.max_blob_bytes.min(right.max_blob_bytes),
        max_total_blob_bytes: left.max_total_blob_bytes.min(right.max_total_blob_bytes),
        max_random_bytes: left.max_random_bytes.min(right.max_random_bytes),
        max_wake_delay_ms: left.max_wake_delay_ms.min(right.max_wake_delay_ms),
        max_http_timeout_ms: left.max_http_timeout_ms.min(right.max_http_timeout_ms),
        max_component_fuel: left.max_component_fuel.min(right.max_component_fuel),
        max_component_memory_bytes: left
            .max_component_memory_bytes
            .min(right.max_component_memory_bytes),
        max_component_output_bytes: left
            .max_component_output_bytes
            .min(right.max_component_output_bytes),
        max_component_wall_time_ms: left
            .max_component_wall_time_ms
            .min(right.max_component_wall_time_ms),
        transaction_namespaces: left_namespaces
            .intersection(&right_namespaces)
            .cloned()
            .collect(),
    }
}

fn parse_canonical_wit_json<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    subject: &str,
) -> Result<T, foundation::Failure> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|_| failure("invalid-constraint", format!("{subject} is not JSON")))?;
    let mut canonical = Vec::new();
    write_canonical_value(&value, &mut canonical)
        .map_err(|_| failure("invalid-constraint", format!("{subject} is not canonical")))?;
    if canonical != bytes {
        return Err(failure(
            "invalid-constraint",
            format!("{subject} is not canonical JSON"),
        ));
    }
    serde_json::from_value(value).map_err(|_| {
        failure(
            "invalid-constraint",
            format!("{subject} has the wrong schema"),
        )
    })
}

fn validate_opaque_scope(scope: &str) -> Result<(), foundation::Failure> {
    if scope.trim().is_empty() || scope.len() > 512 || scope.chars().any(char::is_control) {
        Err(failure(
            "invalid-request",
            "grant scope is empty, too large or contains control characters",
        ))
    } else {
        Ok(())
    }
}

fn validate_requested_limits(
    mechanisms: &LocalMechanisms,
    requested: &foundation::ResourceLimits,
    bound: Option<&CapabilityConstraints>,
) -> Result<TaskExecutionLimits, foundation::Failure> {
    let ceiling = mechanisms.component_limit_ceiling();
    let declared = bound
        .map(|value| {
            (
                value.max_component_fuel,
                value.max_component_memory_bytes,
                value.max_component_output_bytes,
                value.max_component_wall_time_ms,
            )
        })
        .unwrap_or((u64::MAX, u64::MAX, u64::MAX, u64::MAX));
    let values = [
        (requested.fuel, ceiling.0.min(declared.0)),
        (requested.memory_bytes, ceiling.1.min(declared.1)),
        (requested.output_bytes, ceiling.2.min(declared.2)),
        (requested.wall_time_ms, ceiling.3.min(declared.3)),
    ];
    if values
        .into_iter()
        .any(|(requested, ceiling)| requested == 0 || requested > ceiling)
    {
        return Err(failure(
            "limit-exceeded",
            "component limit is zero or exceeds the local ceiling",
        ));
    }
    Ok(TaskExecutionLimits {
        fuel: requested.fuel,
        memory: requested.memory_bytes,
        output: requested.output_bytes,
        wall_time_ms: requested.wall_time_ms,
    })
}

fn validate_launch_admission(admission: &RootAdmission) -> Result<ValidatedLaunch, KernelError> {
    let manifest: LaunchManifest =
        parse_canonical_json(&admission.manifest_bytes, "graph manifest")?;
    if manifest.schema != GRAPH_SCHEMA || manifest.wit_package != FACTORY_WIT_PACKAGE {
        return Err(KernelError::InvalidConfiguration(
            "graph manifest schema or WIT package is unsupported".to_string(),
        ));
    }
    if manifest.nodes.is_empty() {
        return Err(KernelError::EmptyGraph);
    }
    if !strictly_sorted_by(&manifest.nodes, |node| node.id.as_str()) {
        return Err(KernelError::InvalidConfiguration(
            "manifest nodes are not in strict node-id order".to_string(),
        ));
    }

    let metadata_digest = manifest.metadata.ok_or_else(|| {
        KernelError::InvalidConfiguration("graph manifest has no metadata digest".to_string())
    })?;
    verify_content_artifact(&admission.evidence.metadata, "graph metadata")?;
    if admission.evidence.metadata.digest != metadata_digest {
        return Err(KernelError::InvalidConfiguration(
            "graph metadata bytes are not selected by the manifest".to_string(),
        ));
    }
    let metadata: LaunchMetadata =
        parse_canonical_json(&admission.evidence.metadata.bytes, "graph metadata")?;
    if metadata.schema != GRAPH_METADATA_SCHEMA {
        return Err(KernelError::InvalidConfiguration(
            "graph metadata schema is unsupported".to_string(),
        ));
    }

    verify_content_artifact(
        &admission.evidence.derivation_descriptor,
        "derivation descriptor",
    )?;
    verify_content_artifact(&admission.evidence.substrate_profile, "substrate profile")?;
    verify_content_artifact(&admission.evidence.wit_package, "WIT package")?;
    if metadata.derivation_descriptor_digest != admission.evidence.derivation_descriptor.digest
        || metadata.substrate_profile_digest != admission.evidence.substrate_profile.digest
        || metadata.wit_package_digest != admission.evidence.wit_package.digest
    {
        return Err(KernelError::InvalidConfiguration(
            "metadata does not bind the supplied descriptor, substrate profile and WIT package"
                .to_string(),
        ));
    }
    let expected_wit_package: Sha256Digest = FACTORY_WIT_PACKAGE_DIGEST
        .parse()
        .expect("compiled WIT package digest is valid");
    if admission.evidence.wit_package.digest != expected_wit_package {
        return Err(KernelError::InvalidConfiguration(format!(
            "graph WIT package {} differs from the package compiled into the kernel {}",
            admission.evidence.wit_package.digest, expected_wit_package,
        )));
    }

    let world_artifacts = content_artifact_map(&admission.evidence.wit_worlds, "WIT world")?;
    let expected_world_digests = metadata
        .wit_world_digests
        .values()
        .copied()
        .collect::<BTreeSet<_>>();
    if world_artifacts.keys().copied().collect::<BTreeSet<_>>() != expected_world_digests {
        return Err(KernelError::InvalidConfiguration(
            "supplied WIT world artifacts do not exactly match graph metadata".to_string(),
        ));
    }
    let manifest_worlds = manifest
        .nodes
        .iter()
        .map(|node| node.world.as_str())
        .collect::<BTreeSet<_>>();
    if metadata
        .wit_world_digests
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != manifest_worlds
    {
        return Err(KernelError::InvalidConfiguration(
            "WIT world metadata does not exactly cover the manifest worlds".to_string(),
        ));
    }

    let profile: SubstrateProfile = parse_canonical_json(
        &admission.evidence.substrate_profile.bytes,
        "substrate profile",
    )?;
    let profile_primitives = profile
        .primitives
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected_primitives = crate::HOST_INTERFACE_ALLOWLIST
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let profile_v1 = profile.schema == SUBSTRATE_PROFILE_SCHEMA
        && profile.static_grant_model == "composed-root-graph-union"
        && profile.import_alias_scheme.is_none()
        && profile.principal_id_scheme.is_none()
        && profile.principals.is_empty()
        && profile.http_transport.is_none()
        && strictly_sorted_launch_grants(&profile.root_grants);
    let profile_v2 = profile.schema == SUBSTRATE_PROFILE_SCHEMA_V2
        && profile.static_grant_model == R2_STATIC_GRANT_MODEL
        && profile.import_alias_scheme.as_deref() == Some(R2_IMPORT_ALIAS_SCHEME)
        && profile.principal_id_scheme.as_deref() == Some(R2_PRINCIPAL_ID_SCHEME)
        && profile.root_grants.is_empty()
        && profile.http_transport.is_none()
        && strictly_sorted_by(&profile.principals, |principal| principal.consumer.as_str());
    let profile_v3 = profile.schema == SUBSTRATE_PROFILE_SCHEMA_V3
        && profile.static_grant_model == R2_STATIC_GRANT_MODEL
        && profile.import_alias_scheme.as_deref() == Some(R2_IMPORT_ALIAS_SCHEME)
        && profile.principal_id_scheme.as_deref() == Some(R2_PRINCIPAL_ID_SCHEME)
        && profile.root_grants.is_empty()
        && profile
            .http_transport
            .as_ref()
            .is_some_and(valid_http_transport_profile_shape)
        && strictly_sorted_by(&profile.principals, |principal| principal.consumer.as_str());
    let profile_scoped = profile_v2 || profile_v3;
    if (!profile_v1 && !profile_scoped)
        || profile.wit_package != FACTORY_WIT_PACKAGE
        || profile.root_node != manifest.root_node
        || profile.primitives.len() != expected_primitives.len()
        || profile_primitives != expected_primitives
        || !valid_capability_constraints(&profile.ceilings)
    {
        return Err(KernelError::InvalidConfiguration(
            "substrate profile is not an admitted v1 union, v2 local alias, or v3 bounded-HTTP alias boundary"
                .to_string(),
        ));
    }

    let descriptor: DerivationDescriptor = parse_canonical_json(
        &admission.evidence.derivation_descriptor.bytes,
        "derivation descriptor",
    )?;
    let (descriptor_v1, descriptor_v2) = descriptor_version_flags(&descriptor);
    if (!descriptor_v1 && !descriptor_v2)
        || descriptor_v1 != profile_v1
        || descriptor.wit_package_digest != metadata.wit_package_digest
        || descriptor.tool.name.trim().is_empty()
        || descriptor.tool.version.trim().is_empty()
        || descriptor
            .tool
            .options
            .iter()
            .any(|option| option.chars().any(char::is_control))
    {
        return Err(KernelError::InvalidConfiguration(
            "derivation descriptor schema, WIT binding or tool recipe is invalid".to_string(),
        ));
    }

    let mut nodes = BTreeMap::new();
    for node in &manifest.nodes {
        validate_opaque_scope(&node.id).map_err(|error| {
            KernelError::InvalidConfiguration(format!("invalid graph node id: {}", error.message))
        })?;
        if nodes.insert(node.id.as_str(), node).is_some() {
            return Err(KernelError::DuplicateNode(node.id.clone()));
        }
        if !strictly_sorted_launch_grants(&node.grants) {
            return Err(KernelError::InvalidConfiguration(format!(
                "node '{}' grants are not in strict canonical order",
                node.id
            )));
        }
        for grant in &node.grants {
            validate_launch_grant(grant)?;
        }
    }
    if !nodes.contains_key(manifest.root_node.as_str()) {
        return Err(KernelError::InvalidEntryPoint);
    }

    let mut r2_principals = BTreeMap::new();
    let mut scoped_components = BTreeMap::new();
    for artifact in &admission.evidence.scoped_components {
        validate_admitted_component(artifact)?;
        if scoped_components
            .insert(artifact.digest, artifact)
            .is_some()
        {
            return Err(KernelError::DuplicateNode(artifact.digest.to_string()));
        }
    }
    if profile_scoped {
        if profile.principals.len() != manifest.nodes.len() {
            return Err(KernelError::InvalidConfiguration(
                "R2 profile principals do not exactly cover graph nodes".to_string(),
            ));
        }
        for principal in &profile.principals {
            let node = nodes
                .get(principal.consumer.as_str())
                .ok_or_else(|| KernelError::UnknownNode(principal.consumer.clone()))?;
            let expected_seed = r2_principal_seed(&principal.consumer, node.component_digest)?;
            if principal.authority_component_digest != node.component_digest
                || principal.principal_seed != expected_seed
                || principal
                    .host_imports
                    .windows(2)
                    .any(|pair| pair[0] >= pair[1])
                || !scoped_components.contains_key(&principal.scoped_component_digest)
            {
                return Err(KernelError::InvalidConfiguration(format!(
                    "R2 principal '{}' is not canonical or lacks exact scoped bytes",
                    principal.consumer
                )));
            }
            if r2_principals
                .insert(principal.consumer.as_str(), principal)
                .is_some()
            {
                return Err(KernelError::DuplicateNode(principal.consumer.clone()));
            }
        }
        if scoped_components.keys().copied().collect::<BTreeSet<_>>()
            != profile
                .principals
                .iter()
                .map(|principal| principal.scoped_component_digest)
                .collect::<BTreeSet<_>>()
        {
            return Err(KernelError::InvalidConfiguration(
                "supplied scoped components do not exactly match R2 principals".to_string(),
            ));
        }
    } else if !scoped_components.is_empty() {
        return Err(KernelError::InvalidConfiguration(
            "v1 admission unexpectedly supplied scoped components".to_string(),
        ));
    }

    let manifest_sources = manifest
        .nodes
        .iter()
        .map(|node| DerivationSource {
            node_id: node.id.clone(),
            component_digest: node.component_digest,
            world: node.world.clone(),
        })
        .collect::<Vec<_>>();
    if descriptor.sources != manifest_sources {
        return Err(KernelError::InvalidConfiguration(
            "derivation sources are not exactly the manifest source nodes".to_string(),
        ));
    }

    let expected_source_digests = manifest
        .nodes
        .iter()
        .map(|node| node.component_digest)
        .collect::<BTreeSet<_>>();
    let mut source_components = BTreeMap::new();
    for artifact in &admission.source_components {
        validate_admitted_component(artifact)?;
        if source_components
            .insert(artifact.digest, artifact)
            .is_some()
        {
            return Err(KernelError::DuplicateNode(artifact.digest.to_string()));
        }
    }
    let supplied_source_digests = source_components.keys().copied().collect::<BTreeSet<_>>();
    if let Some(missing) = expected_source_digests
        .difference(&supplied_source_digests)
        .next()
    {
        return Err(KernelError::MissingComponent(*missing));
    }
    if let Some(extra) = supplied_source_digests
        .difference(&expected_source_digests)
        .next()
    {
        return Err(KernelError::UnlistedComponent(*extra));
    }

    let constraint_artifacts =
        content_artifact_map(&admission.evidence.constraints, "grant constraint")?;
    let expected_constraints = manifest
        .nodes
        .iter()
        .flat_map(|node| node.grants.iter().map(|grant| grant.constraints))
        .collect::<BTreeSet<_>>();
    if constraint_artifacts
        .keys()
        .copied()
        .collect::<BTreeSet<_>>()
        != expected_constraints
    {
        return Err(KernelError::InvalidConfiguration(
            "constraint artifacts do not exactly match manifest grants".to_string(),
        ));
    }
    if profile_v2 {
        let ceiling_digest = Sha256Digest::from_bytes(&canonical_json_bytes(&profile.ceilings)?);
        if manifest
            .nodes
            .iter()
            .flat_map(|node| &node.grants)
            .any(|grant| {
                grant.constraints != ceiling_digest
                    || !valid_r2_direct_scope(&grant.capability, &grant.scope, &profile.ceilings)
            })
        {
            return Err(KernelError::InvalidConfiguration(
                "R2 direct grants must bind the exact profile ceiling and a supported primitive scope"
                    .to_string(),
            ));
        }
    }
    if profile_v3 {
        let ceiling_digest = Sha256Digest::from_bytes(&canonical_json_bytes(&profile.ceilings)?);
        let http_profile = profile
            .http_transport
            .as_ref()
            .expect("profile-v3 shape requires HTTP bindings");
        let mut projected = profile
            .principals
            .iter()
            .flat_map(|principal| {
                principal
                    .host_imports
                    .iter()
                    .filter(|import| import.capability == "http-transport")
                    .map(|import| HttpTransportBindingV1 {
                        consumer: principal.consumer.clone(),
                        alias: import.alias.clone(),
                        constraints: import.constraints,
                    })
            })
            .collect::<Vec<_>>();
        projected.sort_by(|left, right| http_binding_key(left).cmp(&http_binding_key(right)));
        if projected != http_profile.bindings {
            return Err(KernelError::InvalidConfiguration(
                "profile-v3 HTTP bindings are not the exact principal-import projection"
                    .to_string(),
            ));
        }
        let http_constraint_digests = http_profile
            .bindings
            .iter()
            .map(|binding| binding.constraints)
            .collect::<BTreeSet<_>>();
        for node in &manifest.nodes {
            for grant in &node.grants {
                if !valid_r2_direct_scope(&grant.capability, &grant.scope, &profile.ceilings) {
                    return Err(KernelError::InvalidConfiguration(
                        "profile-v3 grant contains an unsupported primitive scope".to_string(),
                    ));
                }
                if grant.capability == "http-transport" {
                    if grant.constraints == ceiling_digest
                        || !http_constraint_digests.contains(&grant.constraints)
                    {
                        return Err(KernelError::InvalidConfiguration(
                            "profile-v3 HTTP grant does not bind its separate alias constraint"
                                .to_string(),
                        ));
                    }
                } else if grant.constraints != ceiling_digest {
                    return Err(KernelError::InvalidConfiguration(
                        "profile-v3 non-HTTP grant does not bind the exact shared ceiling"
                            .to_string(),
                    ));
                }
            }
        }
        for digest in http_constraint_digests {
            let artifact = constraint_artifacts.get(&digest).ok_or_else(|| {
                KernelError::InvalidConfiguration(
                    "profile-v3 HTTP constraint artifact is absent".to_string(),
                )
            })?;
            let constraints = bounded_http::parse_constraints(&artifact.bytes)?;
            if constraints.max_timeout_ms > profile.ceilings.max_http_timeout_ms
                || constraints.max_request_body_bytes > profile.ceilings.max_blob_bytes
                || constraints.max_response_body_bytes > profile.ceilings.max_blob_bytes
            {
                return Err(KernelError::InvalidConfiguration(
                    "profile-v3 HTTP constraint exceeds the shared mechanism ceiling".to_string(),
                ));
            }
        }
    }

    let mut adjacency = manifest
        .nodes
        .iter()
        .map(|node| (node.id.as_str(), Vec::new()))
        .collect::<BTreeMap<_, _>>();
    let mut bound_imports = BTreeSet::new();
    for binding in &manifest.bindings {
        if !bound_imports.insert((binding.consumer.as_str(), binding.import_name.as_str())) {
            return Err(KernelError::DuplicateImport {
                node: binding.consumer.clone(),
                import: binding.import_name.clone(),
            });
        }
        let consumer = nodes
            .get(binding.consumer.as_str())
            .ok_or_else(|| KernelError::UnknownNode(binding.consumer.clone()))?;
        match &binding.provider {
            LaunchProvider::Component { node, export } => {
                let target = nodes
                    .get(node.as_str())
                    .ok_or_else(|| KernelError::UnknownNode(node.clone()))?;
                if !target.exports.contains(export) {
                    return Err(KernelError::UnknownExport {
                        node: node.clone(),
                        export: export.clone(),
                    });
                }
                adjacency
                    .get_mut(binding.consumer.as_str())
                    .expect("indexed consumer")
                    .push(node.as_str());
            }
            LaunchProvider::Host { capability } => {
                if !crate::HOST_INTERFACE_ALLOWLIST.contains(&capability.as_str())
                    || !consumer
                        .grants
                        .iter()
                        .any(|grant| grant.capability == *capability)
                {
                    return Err(KernelError::InvalidConfiguration(
                        "host binding is outside the closed grant vocabulary".to_string(),
                    ));
                }
            }
        }
    }
    if profile_scoped {
        for node in &manifest.nodes {
            let principal = r2_principals[node.id.as_str()];
            let mut expected_imports = Vec::new();
            for binding in manifest
                .bindings
                .iter()
                .filter(|binding| binding.consumer == node.id)
            {
                let LaunchProvider::Host { capability } = &binding.provider else {
                    continue;
                };
                let grant = node
                    .grants
                    .iter()
                    .find(|grant| grant.capability == *capability)
                    .ok_or_else(|| {
                        KernelError::InvalidConfiguration(format!(
                            "R2 node '{}' lacks its direct '{}' grant",
                            node.id, capability
                        ))
                    })?;
                let source_import = canonical_host_import(capability).ok_or_else(|| {
                    KernelError::InvalidConfiguration(
                        "R2 host capability is outside the closed vocabulary".to_string(),
                    )
                })?;
                if binding.import_name != source_import {
                    return Err(KernelError::InvalidConfiguration(format!(
                        "R2 host binding for '{}' is not the canonical source import",
                        node.id
                    )));
                }
                expected_imports.push(LaunchHostImport {
                    alias: r2_host_alias(&node.id, node.component_digest, capability)?,
                    source_import: source_import.to_string(),
                    capability: capability.clone(),
                    scope: grant.scope.clone(),
                    constraints: grant.constraints,
                });
            }
            expected_imports.sort();
            if principal.host_imports != expected_imports {
                return Err(KernelError::InvalidConfiguration(format!(
                    "R2 principal '{}' imports differ from direct graph bindings and grants",
                    node.id
                )));
            }
            let expected_capabilities = expected_imports
                .iter()
                .map(|import| import.capability.as_str())
                .collect::<BTreeSet<_>>();
            if node.grants.len() != expected_imports.len()
                || node
                    .grants
                    .iter()
                    .map(|grant| grant.capability.as_str())
                    .collect::<BTreeSet<_>>()
                    != expected_capabilities
            {
                return Err(KernelError::InvalidConfiguration(format!(
                    "R2 node '{}' contains residual or unused grants",
                    node.id
                )));
            }
        }
    }
    let validation_engine = component_validation_engine()?;
    validate_source_component_surfaces(&validation_engine, &manifest, &nodes, &source_components)?;
    if profile_scoped {
        validate_scoped_component_surfaces(
            &validation_engine,
            &manifest,
            &r2_principals,
            &scoped_components,
        )?;
    }

    let mut expected_authorities = BTreeSet::from([manifest.root_node.as_str()]);
    let mut seen_invocations = BTreeSet::new();
    for invocation in &manifest.invocations {
        if !seen_invocations.insert((
            invocation.consumer.as_str(),
            invocation.target.as_str(),
            invocation.export.as_str(),
        )) {
            return Err(KernelError::InvalidConfiguration(
                "manifest contains a duplicate dynamic invocation edge".to_string(),
            ));
        }
        let consumer = nodes
            .get(invocation.consumer.as_str())
            .ok_or_else(|| KernelError::UnknownNode(invocation.consumer.clone()))?;
        let target = nodes
            .get(invocation.target.as_str())
            .ok_or_else(|| KernelError::UnknownNode(invocation.target.clone()))?;
        if !target.exports.contains(&invocation.export) {
            return Err(KernelError::UnknownExport {
                node: invocation.target.clone(),
                export: invocation.export.clone(),
            });
        }
        let runner_bound = manifest.bindings.iter().any(|binding| {
            binding.consumer == invocation.consumer
                && matches!(
                    &binding.provider,
                    LaunchProvider::Host { capability }
                        if capability == "component-runner"
                )
        });
        if !runner_bound
            || !consumer
                .grants
                .iter()
                .any(|grant| grant.capability == "component-runner")
        {
            return Err(KernelError::InvalidConfiguration(
                "dynamic invocation consumer lacks a bound runner grant".to_string(),
            ));
        }
        expected_authorities.insert(invocation.target.as_str());
    }
    if !strictly_sorted_by(&descriptor.executables, |value| {
        value.authority_node.as_str()
    }) {
        return Err(KernelError::InvalidConfiguration(
            "derived executables are not in strict authority-node order".to_string(),
        ));
    }
    let configuration_artifacts = content_artifact_map(
        &admission.evidence.composition_configurations,
        "composition configuration",
    )?;
    let expected_configuration_digests = descriptor
        .executables
        .iter()
        .map(|executable| executable.configuration_digest)
        .collect::<BTreeSet<_>>();
    if configuration_artifacts
        .keys()
        .copied()
        .collect::<BTreeSet<_>>()
        != expected_configuration_digests
    {
        return Err(KernelError::InvalidConfiguration(
            "composition configurations do not exactly match the descriptor".to_string(),
        ));
    }

    let mut executable_artifacts = BTreeMap::new();
    for artifact in &admission.execution_artifacts {
        validate_admitted_component(artifact)?;
        if executable_artifacts
            .insert(artifact.digest, artifact)
            .is_some()
        {
            return Err(KernelError::DuplicateNode(artifact.digest.to_string()));
        }
    }
    validate_admitted_component(&admission.composed_root)?;

    let mut actual_authorities = BTreeSet::new();
    let mut execution_bindings = Vec::new();
    let mut referenced_execution_artifacts = BTreeSet::new();
    for executable in &descriptor.executables {
        if !actual_authorities.insert(executable.authority_node.as_str()) {
            return Err(KernelError::DuplicateNode(
                executable.authority_node.clone(),
            ));
        }
        let authority = nodes
            .get(executable.authority_node.as_str())
            .ok_or_else(|| KernelError::UnknownNode(executable.authority_node.clone()))?;
        if executable.authority_digest != authority.component_digest
            || profile_v1
                && executable.grants.as_ref().is_none_or(|grants| {
                    grants != &authority.grants || !strictly_sorted_launch_grants(grants)
                })
            || profile_scoped && executable.grants.is_some()
        {
            return Err(KernelError::InvalidConfiguration(
                "executable authority digest or grants differ from the manifest node".to_string(),
            ));
        }
        let dependencies = reachable_components(executable.authority_node.as_str(), &adjacency);
        let mut dependency_digests = dependencies
            .iter()
            .map(|node| nodes[node].component_digest)
            .collect::<Vec<_>>();
        dependency_digests.sort_unstable();
        dependency_digests.dedup();
        if executable.source_digests != dependency_digests
            || executable
                .source_digests
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(KernelError::InvalidConfiguration(
                "executable source digests do not equal its reachable component set".to_string(),
            ));
        }
        if profile_scoped {
            let mut expected_scoped = dependencies
                .iter()
                .map(|node| r2_principals[node].scoped_component_digest)
                .collect::<Vec<_>>();
            expected_scoped.sort_unstable();
            expected_scoped.dedup();
            let mut expected_seeds = dependencies
                .iter()
                .map(|node| r2_principals[node].principal_seed)
                .collect::<Vec<_>>();
            expected_seeds.sort_unstable();
            expected_seeds.dedup();
            if executable.scoped_source_digests != expected_scoped
                || executable.principal_seeds != expected_seeds
                || executable
                    .scoped_source_digests
                    .windows(2)
                    .any(|pair| pair[0] >= pair[1])
                || executable
                    .principal_seeds
                    .windows(2)
                    .any(|pair| pair[0] >= pair[1])
            {
                return Err(KernelError::InvalidConfiguration(
                    "R2 executable scoped sources or principals differ from its static source set"
                        .to_string(),
                ));
            }
        }
        let is_root = executable.authority_node == manifest.root_node;
        if executable.world != authority.world {
            return Err(KernelError::InvalidConfiguration(
                "derived executable world differs from its authority node".to_string(),
            ));
        }
        let executable_bytes = if is_root {
            if executable.executable_digest != admission.composed_root.digest {
                return Err(KernelError::InvalidConfiguration(
                    "composed root bytes do not match the descriptor".to_string(),
                ));
            }
            admission.composed_root.bytes.as_slice()
        } else {
            if executable.executable_digest != executable.authority_digest {
                let artifact = executable_artifacts
                    .get(&executable.executable_digest)
                    .ok_or(KernelError::MissingComponent(executable.executable_digest))?;
                referenced_execution_artifacts.insert(executable.executable_digest);
                artifact.bytes.as_slice()
            } else if !source_components.contains_key(&executable.executable_digest) {
                return Err(KernelError::MissingComponent(executable.executable_digest));
            } else {
                source_components[&executable.executable_digest]
                    .bytes
                    .as_slice()
            }
        };
        validate_derived_component_surface(
            &validation_engine,
            executable_bytes,
            authority,
            executable,
            profile_scoped,
            &r2_principals,
        )?;
        if !is_root {
            // V1 stores the authority node's graph-union-compatible grants.
            // R2 keeps only non-escalating RunRequest compatibility metadata:
            // the canonical union of exact grants already fixed by this
            // executable's signed per-consumer principal grant set. Actual R2
            // calls remain authorized exclusively by the selected alias's
            // immutable ActivePrincipal context.
            let legacy_run_grants = if profile_v1 {
                executable
                    .grants
                    .as_ref()
                    .expect("v1 descriptor grant shape was validated")
                    .iter()
                    .map(admitted_grant)
                    .collect()
            } else {
                r2_legacy_run_grant_closure(executable, &r2_principals)?
            };
            execution_bindings.push((
                executable.authority_digest,
                executable.executable_digest,
                executable.source_digests.clone(),
                legacy_run_grants,
                executable.principal_seeds.clone(),
            ));
        }
    }
    if actual_authorities != expected_authorities {
        return Err(KernelError::InvalidConfiguration(
            "descriptor executables do not exactly cover root and invocation targets".to_string(),
        ));
    }
    if executable_artifacts
        .keys()
        .copied()
        .collect::<BTreeSet<_>>()
        != referenced_execution_artifacts
    {
        return Err(KernelError::InvalidConfiguration(
            "derived executable artifacts do not exactly match the descriptor".to_string(),
        ));
    }

    let root = nodes[manifest.root_node.as_str()];
    let root_nodes = reachable_components(manifest.root_node.as_str(), &adjacency);
    let root_grants = if profile_v1 {
        if profile.root_grants != root.grants {
            return Err(KernelError::InvalidConfiguration(
                "substrate profile root grants differ from the root authority".to_string(),
            ));
        }
        let ceilings_bytes = canonical_json_bytes(&profile.ceilings)?;
        let ceilings_digest = Sha256Digest::from_bytes(&ceilings_bytes);
        if profile
            .root_grants
            .iter()
            .any(|grant| grant.constraints != ceilings_digest)
        {
            return Err(KernelError::InvalidConfiguration(
                "root grants do not bind the exact substrate ceiling document".to_string(),
            ));
        }
        for binding in &manifest.bindings {
            let LaunchProvider::Host { capability } = &binding.provider else {
                continue;
            };
            if !root_nodes.contains(binding.consumer.as_str()) {
                continue;
            }
            let expected = profile
                .root_grants
                .iter()
                .find(|grant| grant.capability == *capability);
            let actual = nodes[binding.consumer.as_str()]
                .grants
                .iter()
                .find(|grant| grant.capability == *capability);
            if actual != expected {
                return Err(KernelError::InvalidConfiguration(
                    "statically composed host grant differs from the root principal".to_string(),
                ));
            }
        }
        profile.root_grants.iter().map(admitted_grant).collect()
    } else {
        Vec::new()
    };
    let admitted_principals = profile
        .principals
        .iter()
        .map(|principal| AdmittedPrincipal {
            consumer: principal.consumer.clone(),
            authority_component_digest: principal.authority_component_digest,
            principal_seed: principal.principal_seed,
            scoped_component_digest: principal.scoped_component_digest,
            host_imports: principal
                .host_imports
                .iter()
                .map(|import| AdmittedHostImport {
                    alias: import.alias.clone(),
                    source_import: import.source_import.clone(),
                    capability: import.capability.clone(),
                    scope: import.scope.clone(),
                    constraint_digest: import.constraints,
                })
                .collect(),
        })
        .collect::<Vec<_>>();
    let r2_invocations = if profile_scoped {
        manifest
            .invocations
            .iter()
            .map(|invocation| {
                (
                    r2_principals[invocation.consumer.as_str()].principal_seed,
                    nodes[invocation.target.as_str()].component_digest,
                )
            })
            .collect()
    } else {
        Vec::new()
    };
    let mut r2_root_principal_seeds = if profile_scoped {
        root_nodes
            .iter()
            .map(|node| r2_principals[node].principal_seed)
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    r2_root_principal_seeds.sort_unstable();
    r2_root_principal_seeds.dedup();
    let mut certified_derived_artifacts = descriptor
        .executables
        .iter()
        .map(|executable| {
            (
                executable.authority_node.clone(),
                executable.executable_digest,
            )
        })
        .collect::<BTreeMap<_, _>>();
    if profile_scoped {
        for principal in &profile.principals {
            if certified_derived_artifacts
                .insert(
                    format!("scoped:{}", principal.consumer),
                    principal.scoped_component_digest,
                )
                .is_some()
            {
                return Err(KernelError::InvalidConfiguration(
                    "R2 scoped certification key collides with an executable authority key"
                        .to_string(),
                ));
            }
        }
    }
    let certification_closure = CertificationClosure {
        graph_manifest_digest: admission.manifest_digest,
        wit_package_digest: metadata.wit_package_digest,
        metadata_digest,
        raw_artifacts: manifest
            .nodes
            .iter()
            .map(|node| (node.id.clone(), node.component_digest))
            .collect(),
        derived_artifacts: certified_derived_artifacts,
        derivation_descriptor_digest: admission.evidence.derivation_descriptor.digest,
        substrate_profile_digest: admission.evidence.substrate_profile.digest,
        wit_world_digests: metadata.wit_world_digests,
        composition_configuration_digests: expected_configuration_digests.into_iter().collect(),
        constraint_digests: expected_constraints.into_iter().collect(),
    };
    Ok(ValidatedLaunch {
        source_digests: expected_source_digests.into_iter().collect(),
        execution_bindings,
        root_grants,
        r2_principals: admitted_principals,
        r2_invocations,
        r2_root_principal_seeds,
        ceilings: profile.ceilings,
        certification_closure,
    })
}

fn descriptor_version_flags(descriptor: &DerivationDescriptor) -> (bool, bool) {
    let v1 = descriptor.schema == DERIVATION_DESCRIPTOR_SCHEMA
        && descriptor.executables.iter().all(|executable| {
            executable.scoped_source_digests.is_empty()
                && executable.principal_seeds.is_empty()
                && executable.grants.is_some()
        });
    let v2 = descriptor.schema == DERIVATION_DESCRIPTOR_SCHEMA_V2
        && descriptor.executables.iter().all(|executable| {
            executable.grants.is_none()
                && !executable.scoped_source_digests.is_empty()
                && !executable.principal_seeds.is_empty()
        });
    (v1, v2)
}

#[derive(Default)]
struct ObservedSurface {
    imports: BTreeSet<String>,
    exports: BTreeSet<String>,
}

fn component_validation_engine() -> Result<Engine, KernelError> {
    let mut config = Config::new();
    config.wasm_component_model(true);
    Engine::new(&config).map_err(|error| KernelError::Engine(error.to_string()))
}

fn observe_component_surface(
    engine: &Engine,
    bytes: &[u8],
    identity: &str,
) -> Result<ObservedSurface, KernelError> {
    let component = Component::new(engine, bytes).map_err(|error| KernelError::Compile {
        node: identity.to_string(),
        reason: error.to_string(),
    })?;
    let component_type = component.component_type();
    Ok(ObservedSurface {
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

fn validate_source_component_surfaces(
    engine: &Engine,
    manifest: &LaunchManifest,
    nodes: &BTreeMap<&str, &LaunchNode>,
    components: &BTreeMap<Sha256Digest, &AdmittedComponent>,
) -> Result<(), KernelError> {
    for node in &manifest.nodes {
        let artifact = components
            .get(&node.component_digest)
            .ok_or(KernelError::MissingComponent(node.component_digest))?;
        let surface = observe_component_surface(engine, &artifact.bytes, &node.id)?;
        let expected_imports = manifest
            .bindings
            .iter()
            .filter(|binding| binding.consumer == node.id)
            .map(|binding| binding.import_name.clone())
            .collect::<BTreeSet<_>>();
        let expected_exports = node.exports.iter().cloned().collect::<BTreeSet<_>>();
        if surface.imports != expected_imports || surface.exports != expected_exports {
            return Err(KernelError::InvalidConfiguration(format!(
                "component '{}' callable surface differs from its manifest bindings",
                node.id
            )));
        }
        for binding in manifest
            .bindings
            .iter()
            .filter(|binding| binding.consumer == node.id)
        {
            if let LaunchProvider::Component { node: target, .. } = &binding.provider
                && !nodes.contains_key(target.as_str())
            {
                return Err(KernelError::UnknownNode(target.clone()));
            }
        }
    }
    Ok(())
}

fn validate_derived_component_surface(
    engine: &Engine,
    bytes: &[u8],
    authority: &LaunchNode,
    descriptor: &DerivedExecutable,
    r2: bool,
    principals: &BTreeMap<&str, &LaunchPrincipal>,
) -> Result<(), KernelError> {
    let surface =
        observe_component_surface(engine, bytes, &descriptor.executable_digest.to_string())?;
    let expected_exports = authority.exports.iter().cloned().collect::<BTreeSet<_>>();
    if surface.exports != expected_exports {
        return Err(KernelError::InvalidConfiguration(
            "derived executable exports differ from its raw authority".to_string(),
        ));
    }
    if r2 {
        let expected = principals
            .values()
            .filter(|principal| {
                descriptor
                    .principal_seeds
                    .contains(&principal.principal_seed)
            })
            .flat_map(|principal| {
                principal
                    .host_imports
                    .iter()
                    .map(|import| import.alias.clone())
            })
            .collect::<BTreeSet<_>>();
        if surface.imports != expected {
            return Err(KernelError::InvalidConfiguration(
                "R2 derived executable residual imports differ from exact per-consumer aliases"
                    .to_string(),
            ));
        }
    } else {
        for import in &surface.imports {
            let capability = host_capability_from_import(import).ok_or_else(|| {
                KernelError::InvalidConfiguration(
                    "derived executable retains a non-substrate callable import".to_string(),
                )
            })?;
            if !descriptor
                .grants
                .as_ref()
                .expect("v1 descriptor grant shape was validated")
                .iter()
                .any(|grant| grant.capability == capability)
            {
                return Err(KernelError::InvalidConfiguration(
                    "derived executable imports an ungranted host primitive".to_string(),
                ));
            }
        }
    }
    Ok(())
}

fn validate_scoped_component_surfaces(
    engine: &Engine,
    manifest: &LaunchManifest,
    principals: &BTreeMap<&str, &LaunchPrincipal>,
    components: &BTreeMap<Sha256Digest, &AdmittedComponent>,
) -> Result<(), KernelError> {
    for node in &manifest.nodes {
        let principal = principals[node.id.as_str()];
        let artifact = components.get(&principal.scoped_component_digest).ok_or(
            KernelError::MissingComponent(principal.scoped_component_digest),
        )?;
        let surface =
            observe_component_surface(engine, &artifact.bytes, &format!("scoped:{}", node.id))?;
        let mut expected_imports = BTreeSet::new();
        for binding in manifest
            .bindings
            .iter()
            .filter(|binding| binding.consumer == node.id)
        {
            match &binding.provider {
                LaunchProvider::Component { .. } => {
                    expected_imports.insert(binding.import_name.clone());
                }
                LaunchProvider::Host { capability } => {
                    let alias = principal
                        .host_imports
                        .iter()
                        .find(|import| import.capability == *capability)
                        .ok_or_else(|| {
                            KernelError::InvalidConfiguration(
                                "scoped component has no matching authority alias".to_string(),
                            )
                        })?;
                    expected_imports.insert(alias.alias.clone());
                }
            }
        }
        let expected_exports = node.exports.iter().cloned().collect::<BTreeSet<_>>();
        if surface.imports != expected_imports || surface.exports != expected_exports {
            return Err(KernelError::InvalidConfiguration(format!(
                "scoped component '{}' surface differs from its exact alias rewrite",
                node.id
            )));
        }
    }
    Ok(())
}

fn canonical_host_import(capability: &str) -> Option<String> {
    crate::HOST_INTERFACE_ALLOWLIST
        .contains(&capability)
        .then(|| format!("wasm-biotic:factory/{capability}@0.1.0"))
}

fn r2_principal_seed(
    consumer: &str,
    authority_component_digest: Sha256Digest,
) -> Result<Sha256Digest, KernelError> {
    let bytes = canonical_json_bytes(&serde_json::json!({
        "authority_component_digest": authority_component_digest,
        "consumer": consumer,
        "schema": R2_PRINCIPAL_SEED_SCHEMA,
    }))?;
    Ok(Sha256Digest::from_bytes(&bytes))
}

fn r2_host_alias(
    consumer: &str,
    authority_component_digest: Sha256Digest,
    capability: &str,
) -> Result<String, KernelError> {
    let source_import = canonical_host_import(capability).ok_or_else(|| {
        KernelError::InvalidConfiguration("alias names an unknown host capability".to_string())
    })?;
    let bytes = canonical_json_bytes(&serde_json::json!({
        "authority_component_digest": authority_component_digest,
        "capability": capability,
        "consumer": consumer,
        "schema": R2_ALIAS_MATERIAL_SCHEMA,
        "source_import": source_import,
    }))?;
    Ok(format!(
        "wasm-biotic:factory/host-{}@0.1.0",
        Sha256Digest::from_bytes(&bytes)
            .to_string()
            .trim_start_matches("sha256:")
    ))
}

fn r2_runtime_principal(
    graph_manifest_digest: Sha256Digest,
    principal_seed: Sha256Digest,
) -> Result<Sha256Digest, KernelError> {
    let bytes = canonical_json_bytes(&serde_json::json!({
        "graph_manifest_digest": graph_manifest_digest,
        "principal_seed": principal_seed,
        "schema": R2_RUNTIME_PRINCIPAL_SCHEMA,
    }))?;
    Ok(Sha256Digest::from_bytes(&bytes))
}

fn active_principals(
    graph_manifest_digest: Sha256Digest,
    executable_component_digest: Sha256Digest,
    selected_seeds: &[Sha256Digest],
    principals: &[AdmittedPrincipal],
) -> Result<Vec<ActivePrincipal>, KernelError> {
    let selected = selected_seeds.iter().copied().collect::<BTreeSet<_>>();
    let mut aliases = BTreeSet::new();
    let mut active = Vec::new();
    for principal in principals
        .iter()
        .filter(|principal| selected.contains(&principal.principal_seed))
    {
        let runtime_principal_digest =
            r2_runtime_principal(graph_manifest_digest, principal.principal_seed)?;
        for host_import in &principal.host_imports {
            if !aliases.insert(host_import.alias.as_str()) {
                return Err(KernelError::InvalidConfiguration(
                    "R2 executable contains a duplicate residual alias".to_string(),
                ));
            }
            active.push(ActivePrincipal {
                graph_manifest_digest,
                consumer: principal.consumer.clone(),
                authority_component_digest: principal.authority_component_digest,
                principal_seed: principal.principal_seed,
                runtime_principal_digest,
                scoped_component_digest: principal.scoped_component_digest,
                executable_component_digest,
                host_import: host_import.clone(),
            });
        }
    }
    if selected.len()
        != principals
            .iter()
            .filter(|principal| selected.contains(&principal.principal_seed))
            .count()
    {
        return Err(KernelError::InvalidConfiguration(
            "R2 executable selects an unknown principal seed".to_string(),
        ));
    }
    active.sort_by(|left, right| left.host_import.alias.cmp(&right.host_import.alias));
    Ok(active)
}

fn host_capability_from_import(name: &str) -> Option<&'static str> {
    match name {
        "wasm-biotic:factory/blob-store@0.1.0" => Some("blob-store"),
        "wasm-biotic:factory/transaction-store@0.1.0" => Some("transaction-store"),
        "wasm-biotic:factory/clock@0.1.0" => Some("clock"),
        "wasm-biotic:factory/component-runner@0.1.0" => Some("component-runner"),
        "wasm-biotic:factory/http-transport@0.1.0" => Some("http-transport"),
        "wasm-biotic:factory/key-service@0.1.0" => Some("key-service"),
        "wasm-biotic:factory/activation@0.1.0" => Some("activation"),
        "wasm-biotic:factory/audit-log@0.1.0" => Some("audit-log"),
        _ => None,
    }
}

fn admitted_grant(grant: &LaunchGrant) -> AdmittedGrant {
    AdmittedGrant {
        capability: grant.capability.clone(),
        scope: grant.scope.clone(),
        constraint_digest: grant.constraints,
    }
}

fn r2_legacy_run_grant_closure(
    executable: &DerivedExecutable,
    principals: &BTreeMap<&str, &LaunchPrincipal>,
) -> Result<Vec<AdmittedGrant>, KernelError> {
    let selected = executable
        .principal_seeds
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let mut matched = BTreeSet::new();
    let mut grants = BTreeSet::new();
    for principal in principals.values() {
        if !selected.contains(&principal.principal_seed) {
            continue;
        }
        matched.insert(principal.principal_seed);
        grants.extend(principal.host_imports.iter().map(|import| LaunchGrant {
            capability: import.capability.clone(),
            scope: import.scope.clone(),
            constraints: import.constraints,
        }));
    }
    if matched != selected {
        return Err(KernelError::InvalidConfiguration(
            "R2 executable legacy grant set names an unknown principal".to_string(),
        ));
    }
    Ok(grants.iter().map(admitted_grant).collect())
}

fn valid_r2_direct_scope(capability: &str, scope: &str, ceilings: &CapabilityConstraints) -> bool {
    match capability {
        "blob-store" => matches!(scope, "read" | "write" | "read-write"),
        "transaction-store" => ceilings
            .transaction_namespaces
            .iter()
            .any(|namespace| namespace == scope),
        "clock" => scope == "wake",
        "component-runner" => scope == "run",
        "http-transport" => scope == "request",
        "key-service" => scope == "use",
        "activation" => scope == "switch",
        "audit-log" => matches!(scope, "append" | "read" | "append-read"),
        _ => false,
    }
}

fn build_root_grants(validated: &ValidatedLaunch) -> Result<RootGrants, KernelError> {
    let mut grants = RootGrants {
        blob: BlobAccess {
            max_put_bytes: validated.ceilings.max_blob_bytes,
            ..BlobAccess::default()
        },
        transaction_namespaces: validated
            .ceilings
            .transaction_namespaces
            .iter()
            .cloned()
            .collect(),
        ..RootGrants::default()
    };
    if !validated.r2_principals.is_empty() {
        return Ok(grants);
    }
    let mut seen = BTreeSet::new();
    for grant in &validated.root_grants {
        if !seen.insert(grant.capability.as_str()) {
            return Err(KernelError::InvalidConfiguration(
                "root principal contains a duplicate primitive grant".to_string(),
            ));
        }
        match (grant.capability.as_str(), grant.scope.as_str()) {
            ("blob-store", "read-write") => {
                grants.blob.read = true;
                grants.blob.write = true;
            }
            ("transaction-store", "namespaces") => {}
            ("clock", "wake") => grants.clock = true,
            ("component-runner", "run") => grants.component_runner = true,
            ("http-transport", "request") => grants.http_transport = true,
            ("key-service", "use") => grants.key_service = true,
            ("activation", "switch") => grants.activation = true,
            ("audit-log", "append-read") => {
                grants.audit_append = true;
                grants.audit_read = true;
            }
            _ => {
                return Err(KernelError::InvalidConfiguration(
                    "root principal contains an unsupported primitive scope".to_string(),
                ));
            }
        }
    }
    if seen.len() != crate::HOST_INTERFACE_ALLOWLIST.len() {
        return Err(KernelError::InvalidConfiguration(
            "root principal does not grant exactly the eight host primitives".to_string(),
        ));
    }
    Ok(grants)
}

fn require_root_grant(granted: bool, capability: &str) -> Result<(), foundation::Failure> {
    if granted {
        Ok(())
    } else {
        Err(failure(
            "not-granted",
            format!("{capability} is outside the composed-root graph grant"),
        ))
    }
}

fn validate_launch_grant(grant: &LaunchGrant) -> Result<(), KernelError> {
    if !crate::HOST_INTERFACE_ALLOWLIST.contains(&grant.capability.as_str()) {
        return Err(KernelError::InvalidConfiguration(
            "manifest grant names a non-host interface".to_string(),
        ));
    }
    validate_opaque_scope(&grant.scope)
        .map_err(|error| KernelError::InvalidConfiguration(error.message))?;
    Ok(())
}

fn reachable_components<'a>(
    start: &'a str,
    adjacency: &BTreeMap<&'a str, Vec<&'a str>>,
) -> BTreeSet<&'a str> {
    let mut reached = BTreeSet::new();
    let mut pending = vec![start];
    while let Some(node) = pending.pop() {
        if reached.insert(node) {
            pending.extend(adjacency.get(node).into_iter().flatten().copied());
        }
    }
    reached
}

fn strictly_sorted_by<T>(values: &[T], key: impl Fn(&T) -> &str) -> bool {
    values.windows(2).all(|pair| key(&pair[0]) < key(&pair[1]))
}

fn strictly_sorted_launch_grants(values: &[LaunchGrant]) -> bool {
    values.windows(2).all(|pair| {
        (primitive_rank(&pair[0].capability), pair[0].scope.as_str())
            < (primitive_rank(&pair[1].capability), pair[1].scope.as_str())
    })
}

fn primitive_rank(value: &str) -> u8 {
    match value {
        "blob-store" => 0,
        "transaction-store" => 1,
        "clock" => 2,
        "component-runner" => 3,
        "http-transport" => 4,
        "key-service" => 5,
        "activation" => 6,
        "audit-log" => 7,
        _ => u8::MAX,
    }
}

fn content_artifact_map<'a>(
    artifacts: &'a [ContentArtifact],
    subject: &str,
) -> Result<BTreeMap<Sha256Digest, &'a ContentArtifact>, KernelError> {
    let mut mapped = BTreeMap::new();
    for artifact in artifacts {
        verify_content_artifact(artifact, subject)?;
        if mapped.insert(artifact.digest, artifact).is_some() {
            return Err(KernelError::InvalidConfiguration(format!(
                "duplicate {subject} digest"
            )));
        }
    }
    Ok(mapped)
}

fn verify_content_artifact(artifact: &ContentArtifact, subject: &str) -> Result<(), KernelError> {
    let actual = Sha256Digest::from_bytes(&artifact.bytes);
    if actual != artifact.digest {
        return Err(KernelError::ComponentDigestMismatch {
            node: subject.to_string(),
            expected: artifact.digest,
            actual,
        });
    }
    Ok(())
}

fn parse_canonical_json<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    subject: &str,
) -> Result<T, KernelError> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| KernelError::ManifestDecode(format!("{subject}: {error}")))?;
    let mut canonical = Vec::new();
    write_canonical_value(&value, &mut canonical)?;
    if canonical != bytes {
        return Err(KernelError::ManifestDecode(format!(
            "{subject} is not canonical JSON"
        )));
    }
    serde_json::from_value(value)
        .map_err(|error| KernelError::ManifestDecode(format!("{subject}: {error}")))
}

fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, KernelError> {
    let value = serde_json::to_value(value)
        .map_err(|error| KernelError::ManifestDecode(error.to_string()))?;
    let mut bytes = Vec::new();
    write_canonical_value(&value, &mut bytes)?;
    Ok(bytes)
}

fn valid_http_transport_profile_shape(value: &HttpTransportProfileV1) -> bool {
    !value.bindings.is_empty()
        && value
            .bindings
            .windows(2)
            .all(|pair| http_binding_key(&pair[0]) < http_binding_key(&pair[1]))
        && value.bindings.iter().all(|binding| {
            !binding.consumer.trim().is_empty()
                && !binding.alias.trim().is_empty()
                && !binding.consumer.chars().any(char::is_control)
                && !binding.alias.chars().any(char::is_control)
        })
}

fn http_binding_key(value: &HttpTransportBindingV1) -> (&str, &str, Sha256Digest) {
    (
        value.consumer.as_str(),
        value.alias.as_str(),
        value.constraints,
    )
}

fn valid_capability_constraints(value: &CapabilityConstraints) -> bool {
    value.schema == CAPABILITY_CONSTRAINTS_SCHEMA
        && value.max_blob_bytes > 0
        && value.max_total_blob_bytes >= value.max_blob_bytes
        && value.max_random_bytes > 0
        && value.max_wake_delay_ms > 0
        && value.max_http_timeout_ms > 0
        && value.max_component_fuel > 0
        && value.max_component_memory_bytes > 0
        && value.max_component_output_bytes > 0
        && value.max_component_wall_time_ms > 0
        && strictly_sorted_by(&value.transaction_namespaces, String::as_str)
        && value
            .transaction_namespaces
            .iter()
            .all(|namespace| !namespace.trim().is_empty())
}

fn required_capacity(value: &CapabilityConstraints) -> RequiredCapacity {
    RequiredCapacity {
        max_blob_bytes: value.max_blob_bytes,
        max_total_blob_bytes: value.max_total_blob_bytes,
        max_random_bytes: value.max_random_bytes,
        max_wake_delay_ms: value.max_wake_delay_ms,
        max_http_timeout_ms: value.max_http_timeout_ms,
        max_component_fuel: value.max_component_fuel,
        max_component_memory_bytes: value.max_component_memory_bytes,
        max_component_output_bytes: value.max_component_output_bytes,
        max_component_wall_time_ms: value.max_component_wall_time_ms,
        transaction_namespaces: value.transaction_namespaces.iter().cloned().collect(),
    }
}

fn write_canonical_value(
    value: &serde_json::Value,
    output: &mut Vec<u8>,
) -> Result<(), KernelError> {
    match value {
        serde_json::Value::Null => output.extend_from_slice(b"null"),
        serde_json::Value::Bool(value) => {
            output.extend_from_slice(if *value { b"true" } else { b"false" });
        }
        serde_json::Value::Number(number) => {
            if number.is_f64() {
                return Err(KernelError::ManifestDecode(
                    "floating-point values are outside the canonical graph domain".to_string(),
                ));
            }
            output.extend_from_slice(number.to_string().as_bytes());
        }
        serde_json::Value::String(value) => output.extend_from_slice(
            &serde_json::to_vec(value)
                .map_err(|error| KernelError::ManifestDecode(error.to_string()))?,
        ),
        serde_json::Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_value(value, output)?;
            }
            output.push(b']');
        }
        serde_json::Value::Object(values) => {
            output.push(b'{');
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_value(&serde_json::Value::String(key.clone()), output)?;
                output.push(b':');
                write_canonical_value(&values[key], output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn validate_admitted_component(artifact: &AdmittedComponent) -> Result<(), KernelError> {
    let actual = Sha256Digest::from_bytes(&artifact.bytes);
    if actual != artifact.digest {
        return Err(KernelError::ComponentDigestMismatch {
            node: artifact.digest.to_string(),
            expected: artifact.digest,
            actual,
        });
    }
    if !wasmparser::Parser::is_component(&artifact.bytes) {
        return Err(KernelError::Compile {
            node: artifact.digest.to_string(),
            reason: "bytes are not a Component Model binary".to_string(),
        });
    }
    Ok(())
}

fn validate_runtime_limits(limits: &ResourceLimits) -> Result<(), KernelError> {
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

fn task_blob_from_root(
    value: foundation::BlobRef,
) -> task::wasm_biotic::factory::foundation::BlobRef {
    task::wasm_biotic::factory::foundation::BlobRef {
        content_digest: task_digest_from_root(value.content_digest),
        size_bytes: value.size_bytes,
        media_type: value.media_type,
    }
}

fn task_blob_to_root(
    value: task::wasm_biotic::factory::foundation::BlobRef,
) -> foundation::BlobRef {
    foundation::BlobRef {
        content_digest: task_digest_to_root(value.content_digest),
        size_bytes: value.size_bytes,
        media_type: value.media_type,
    }
}

fn root_blob_to_task(
    value: foundation::BlobRef,
) -> task::wasm_biotic::factory::foundation::BlobRef {
    task_blob_from_root(value)
}

fn task_digest_from_root(
    value: foundation::Digest,
) -> task::wasm_biotic::factory::foundation::Digest {
    task::wasm_biotic::factory::foundation::Digest {
        algorithm: task::wasm_biotic::factory::foundation::HashAlgorithm::Sha256,
        hex: value.hex,
    }
}

fn task_digest_to_root(
    value: task::wasm_biotic::factory::foundation::Digest,
) -> foundation::Digest {
    foundation::Digest {
        algorithm: foundation::HashAlgorithm::Sha256,
        hex: value.hex,
    }
}

fn root_failure_to_task(
    value: foundation::Failure,
) -> task::wasm_biotic::factory::foundation::Failure {
    task::wasm_biotic::factory::foundation::Failure {
        code: value.code,
        message: value.message,
        retryable: value.retryable,
        evidence: value.evidence.map(task_blob_from_root),
    }
}

fn task_failure_to_root(
    value: task::wasm_biotic::factory::foundation::Failure,
) -> foundation::Failure {
    foundation::Failure {
        code: value.code,
        message: value.message,
        retryable: value.retryable,
        evidence: value.evidence.map(task_blob_to_root),
    }
}

fn require_task_grant(
    granted: bool,
    capability: &str,
) -> Result<(), task::wasm_biotic::factory::foundation::Failure> {
    if granted {
        Ok(())
    } else {
        Err(task_failure(
            "not-granted",
            format!("{capability} was not granted for this run"),
        ))
    }
}

fn convert_task_value<T, U>(value: T) -> Result<U, task::wasm_biotic::factory::foundation::Failure>
where
    T: Serialize,
    U: DeserializeOwned,
{
    let bytes = serde_json::to_vec(&value)
        .map_err(|_| task_failure("encoding-error", "could not encode host request"))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| task_failure("encoding-error", "could not bridge host request"))
}

fn convert_root_value<T, U>(value: T) -> Result<U, task::wasm_biotic::factory::foundation::Failure>
where
    T: Serialize,
    U: DeserializeOwned,
{
    let bytes = serde_json::to_vec(&value)
        .map_err(|_| task_failure("encoding-error", "could not encode host response"))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| task_failure("encoding-error", "could not bridge host response"))
}

fn task_failure(
    code: impl Into<String>,
    message: impl Into<String>,
) -> task::wasm_biotic::factory::foundation::Failure {
    task::wasm_biotic::factory::foundation::Failure {
        code: code.into(),
        message: message.into(),
        retryable: false,
        evidence: None,
    }
}

#[cfg(test)]
mod r2_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::{env, fs};

    static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

    struct TestDirectory(std::path::PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = env::temp_dir().join(format!(
                "wasm-biotic-r2-authority-test-{}",
                NEXT_DIRECTORY.fetch_add(1, Ordering::SeqCst)
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::from_bytes(&[byte])
    }

    fn descriptor(executable: DerivedExecutable, schema: &str) -> DerivationDescriptor {
        DerivationDescriptor {
            schema: schema.to_string(),
            wit_package_digest: digest(1),
            sources: vec![DerivationSource {
                node_id: "node".to_string(),
                component_digest: digest(2),
                world: "world".to_string(),
            }],
            executables: vec![executable],
            tool: CompositionTool {
                name: "tool".to_string(),
                version: "1".to_string(),
                options: Vec::new(),
            },
        }
    }

    fn executable() -> DerivedExecutable {
        DerivedExecutable {
            authority_node: "node".to_string(),
            authority_digest: digest(2),
            executable_digest: digest(3),
            source_digests: vec![digest(2)],
            world: "world".to_string(),
            configuration_digest: digest(4),
            grants: Some(Vec::new()),
            scoped_source_digests: Vec::new(),
            principal_seeds: Vec::new(),
        }
    }

    fn launch_principal(
        consumer: &str,
        seed: Sha256Digest,
        constraint: Sha256Digest,
        imports: &[(&str, &str)],
    ) -> LaunchPrincipal {
        let mut host_imports = imports
            .iter()
            .map(|(capability, scope)| LaunchHostImport {
                alias: format!("alias-{consumer}-{capability}"),
                source_import: canonical_host_import(capability).unwrap(),
                capability: (*capability).to_string(),
                scope: (*scope).to_string(),
                constraints: constraint,
            })
            .collect::<Vec<_>>();
        host_imports.sort();
        LaunchPrincipal {
            consumer: consumer.to_string(),
            authority_component_digest: digest(30),
            principal_seed: seed,
            scoped_component_digest: digest(31),
            host_imports,
        }
    }

    fn active_principal(
        consumer: &str,
        identity: u8,
        capability: &str,
        scope: &str,
    ) -> ActivePrincipal {
        ActivePrincipal {
            graph_manifest_digest: digest(40),
            consumer: consumer.to_string(),
            authority_component_digest: digest(identity),
            principal_seed: digest(identity.saturating_add(1)),
            runtime_principal_digest: digest(identity.saturating_add(2)),
            scoped_component_digest: digest(identity.saturating_add(3)),
            executable_component_digest: digest(50),
            host_import: AdmittedHostImport {
                alias: format!("alias-{consumer}-{capability}"),
                source_import: canonical_host_import(capability).unwrap(),
                capability: capability.to_string(),
                scope: scope.to_string(),
                constraint_digest: digest(51),
            },
        }
    }

    #[test]
    fn descriptor_versions_require_exact_grant_and_principal_field_shapes() {
        let v1 = descriptor(executable(), DERIVATION_DESCRIPTOR_SCHEMA);
        assert_eq!(descriptor_version_flags(&v1), (true, false));
        let v1_bytes = canonical_json_bytes(&v1).unwrap();
        assert!(
            std::str::from_utf8(&v1_bytes)
                .unwrap()
                .contains("\"grants\":[]")
        );

        let mut missing_v1_grants = executable();
        missing_v1_grants.grants = None;
        assert_eq!(
            descriptor_version_flags(&descriptor(missing_v1_grants, DERIVATION_DESCRIPTOR_SCHEMA)),
            (false, false)
        );

        let mut v2_executable = executable();
        v2_executable.grants = None;
        v2_executable.scoped_source_digests = vec![digest(5)];
        v2_executable.principal_seeds = vec![digest(6)];
        let v2 = descriptor(v2_executable.clone(), DERIVATION_DESCRIPTOR_SCHEMA_V2);
        assert_eq!(descriptor_version_flags(&v2), (false, true));
        let v2_text = String::from_utf8(canonical_json_bytes(&v2).unwrap()).unwrap();
        assert!(!v2_text.contains("\"grants\""));
        assert!(v2_text.contains("\"scoped_source_digests\""));
        assert!(v2_text.contains("\"principal_seeds\""));

        v2_executable.grants = Some(Vec::new());
        assert_eq!(
            descriptor_version_flags(&descriptor(
                v2_executable.clone(),
                DERIVATION_DESCRIPTOR_SCHEMA_V2
            )),
            (false, false)
        );
        v2_executable.grants = None;
        v2_executable.principal_seeds.clear();
        assert_eq!(
            descriptor_version_flags(&descriptor(v2_executable, DERIVATION_DESCRIPTOR_SCHEMA_V2)),
            (false, false)
        );
    }

    #[test]
    fn legacy_grants_are_exactly_the_signed_r2_static_closure() {
        let constraint = digest(20);
        let consumer_seed = digest(21);
        let build_seed = digest(22);
        let scheduling_seed = digest(23);
        let consumer = launch_principal(
            "caller-consumer",
            consumer_seed,
            constraint,
            &[("blob-store", "read-write")],
        );
        let build = launch_principal(
            "resource-owner-a",
            build_seed,
            constraint,
            &[("blob-store", "read-write")],
        );
        let scheduling = launch_principal(
            "resource-owner-b",
            scheduling_seed,
            constraint,
            &[
                ("clock", "wake"),
                ("transaction-store", "wasm-biotic.schedule.v1"),
            ],
        );
        let principals = BTreeMap::from([
            ("resource-owner-a", &build),
            ("caller-consumer", &consumer),
            ("resource-owner-b", &scheduling),
        ]);
        let mut consumer_executable = executable();
        consumer_executable.grants = None;
        consumer_executable.principal_seeds = vec![consumer_seed, build_seed, scheduling_seed];
        consumer_executable.principal_seeds.sort_unstable();

        let grant_ceiling = r2_legacy_run_grant_closure(&consumer_executable, &principals).unwrap();
        let canonical = grant_ceiling
            .iter()
            .map(|grant| {
                (
                    grant.capability.as_str(),
                    grant.scope.as_str(),
                    grant.constraint_digest,
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            canonical,
            vec![
                ("blob-store", "read-write", constraint),
                ("clock", "wake", constraint),
                ("transaction-store", "wasm-biotic.schedule.v1", constraint),
            ]
        );

        for (capability, scope) in [
            ("blob-store", "read-write"),
            ("clock", "wake"),
            ("transaction-store", "wasm-biotic.schedule.v1"),
        ] {
            let requested = foundation::CapabilityGrant {
                capability: capability.to_string(),
                scope: scope.to_string(),
                constraints: None,
            };
            assert!(
                match_admitted_run_grant(Some(&grant_ceiling), &requested)
                    .unwrap()
                    .is_some()
            );
        }

        let outside = foundation::CapabilityGrant {
            capability: "key-service".to_string(),
            scope: "use".to_string(),
            constraints: None,
        };
        assert_eq!(
            match_admitted_run_grant(Some(&grant_ceiling), &outside)
                .unwrap_err()
                .code,
            "not-granted"
        );
    }

    #[test]
    fn alias_calls_observe_only_their_captured_principal_scope() {
        let directory = TestDirectory::new();
        let mechanisms =
            LocalMechanisms::open(&directory.0, crate::LocalConfig::default()).unwrap();
        let reader = active_principal("reader", 60, "blob-store", "read");
        let writer = active_principal("writer", 70, "blob-store", "write");
        let broad_legacy_metadata = TaskGrants {
            blob: BlobAccess {
                read: true,
                write: true,
                max_put_bytes: u64::MAX,
            },
            key_service: true,
            activation: true,
            ..TaskGrants::default()
        };
        let mut state = TaskState {
            mechanisms: mechanisms.clone(),
            grants: broad_legacy_metadata,
            active_principal: None,
            limits: StoreLimitsBuilder::new().build(),
        };

        let reader_scope: Result<
            (bool, bool, bool, bool),
            task::wasm_biotic::factory::foundation::Failure,
        > = invoke_as_principal(&mut state, &reader, "get", digest(80), |state| {
            let access = state.blob_access();
            Ok((
                access.read,
                access.write,
                state.granted("key-service", "use"),
                state.granted("activation", "switch"),
            ))
        });
        let writer_scope: Result<
            (bool, bool, bool, bool),
            task::wasm_biotic::factory::foundation::Failure,
        > = invoke_as_principal(&mut state, &writer, "put", digest(81), |state| {
            let access = state.blob_access();
            Ok((
                access.read,
                access.write,
                state.granted("key-service", "use"),
                state.granted("activation", "switch"),
            ))
        });
        assert_eq!(reader_scope.unwrap(), (true, false, false, false));
        assert_eq!(writer_scope.unwrap(), (false, true, false, false));
        assert!(state.active_principal.is_none());

        let trace = mechanisms.authority_trace().unwrap();
        assert_eq!(trace.len(), 2);
        assert_eq!(trace[0].principal_seed, reader.principal_seed);
        assert_eq!(trace[0].scope, "read");
        assert_eq!(trace[1].principal_seed, writer.principal_seed);
        assert_eq!(trace[1].scope, "write");
    }

    #[test]
    fn guest_identity_claim_cannot_select_an_alias_principal() {
        #[derive(Serialize)]
        struct GuestIdentityClaim {
            caller_principal_seed: Sha256Digest,
            alias: String,
        }

        let directory = TestDirectory::new();
        let mechanisms =
            LocalMechanisms::open(&directory.0, crate::LocalConfig::default()).unwrap();
        let admitted = active_principal("admitted", 90, "clock", "wake");
        let claim = GuestIdentityClaim {
            caller_principal_seed: digest(100),
            alias: "alias-attacker-clock".to_string(),
        };
        let request_digest = authority_request_digest(&claim);
        let mut state = TaskState {
            mechanisms: mechanisms.clone(),
            grants: TaskGrants::default(),
            active_principal: None,
            limits: StoreLimitsBuilder::new().build(),
        };
        let selected: Result<
            (Sha256Digest, String),
            task::wasm_biotic::factory::foundation::Failure,
        > = invoke_as_principal(
            &mut state,
            &admitted,
            "schedule-wake",
            request_digest,
            |state| {
                let selected = state.active_principal.as_ref().unwrap();
                Ok((selected.principal_seed, selected.host_import.alias.clone()))
            },
        );
        assert_eq!(
            selected.unwrap(),
            (admitted.principal_seed, admitted.host_import.alias.clone())
        );
        assert_ne!(admitted.principal_seed, claim.caller_principal_seed);
        assert_ne!(admitted.host_import.alias, claim.alias);

        let trace = mechanisms.authority_trace().unwrap();
        assert_eq!(trace.len(), 1);
        assert_eq!(trace[0].principal_seed, admitted.principal_seed);
        assert_eq!(trace[0].alias, admitted.host_import.alias);
        assert_eq!(trace[0].request_digest, request_digest);
    }

    #[test]
    fn principal_alias_and_runtime_identity_material_is_exact_and_graph_qualified() {
        let authority = digest(7);
        let graph = digest(8);
        let seed_material = format!(
            "{{\"authority_component_digest\":\"{authority}\",\"consumer\":\"consumer\",\"schema\":\"{R2_PRINCIPAL_SEED_SCHEMA}\"}}"
        );
        let seed = r2_principal_seed("consumer", authority).unwrap();
        assert_eq!(seed, Sha256Digest::from_bytes(seed_material.as_bytes()));

        let source_import = "wasm-biotic:factory/clock@0.1.0";
        let alias_material = format!(
            "{{\"authority_component_digest\":\"{authority}\",\"capability\":\"clock\",\"consumer\":\"consumer\",\"schema\":\"{R2_ALIAS_MATERIAL_SCHEMA}\",\"source_import\":\"{source_import}\"}}"
        );
        let token = Sha256Digest::from_bytes(alias_material.as_bytes());
        assert_eq!(
            r2_host_alias("consumer", authority, "clock").unwrap(),
            format!(
                "wasm-biotic:factory/host-{}@0.1.0",
                token.to_string().trim_start_matches("sha256:")
            )
        );

        let runtime_material = format!(
            "{{\"graph_manifest_digest\":\"{graph}\",\"principal_seed\":\"{seed}\",\"schema\":\"{R2_RUNTIME_PRINCIPAL_SCHEMA}\"}}"
        );
        assert_eq!(
            r2_runtime_principal(graph, seed).unwrap(),
            Sha256Digest::from_bytes(runtime_material.as_bytes())
        );
        assert_ne!(
            r2_runtime_principal(digest(9), seed).unwrap(),
            r2_runtime_principal(graph, seed).unwrap()
        );
    }

    #[test]
    fn authority_trace_binds_executable_request_and_stable_outcome() {
        let directory = TestDirectory::new();
        let mechanisms =
            LocalMechanisms::open(&directory.0, crate::LocalConfig::default()).unwrap();
        let principal = ActivePrincipal {
            graph_manifest_digest: digest(10),
            consumer: "consumer".to_string(),
            authority_component_digest: digest(11),
            principal_seed: digest(12),
            runtime_principal_digest: digest(13),
            scoped_component_digest: digest(14),
            executable_component_digest: digest(15),
            host_import: AdmittedHostImport {
                alias: "wasm-biotic:factory/host-test@0.1.0".to_string(),
                source_import: "wasm-biotic:factory/clock@0.1.0".to_string(),
                capability: "clock".to_string(),
                scope: "wake".to_string(),
                constraint_digest: digest(16),
            },
        };
        let mut state = TaskState {
            mechanisms: mechanisms.clone(),
            grants: TaskGrants::default(),
            active_principal: None,
            limits: StoreLimitsBuilder::new().build(),
        };
        let request_digest = authority_request_digest(&("wake-id", 42_u64));
        let denied: Result<(), task::wasm_biotic::factory::foundation::Failure> =
            invoke_as_principal(&mut state, &principal, "poll-wake", request_digest, |_| {
                Err(task_failure("not-granted", "denied"))
            });
        assert_eq!(denied.unwrap_err().code, "not-granted");
        assert!(state.active_principal.is_none());
        let trace = mechanisms.authority_trace().unwrap();
        assert_eq!(trace.len(), 1);
        assert_eq!(trace[0].request_digest, request_digest);
        assert_eq!(trace[0].outcome, "not-granted");
        assert_eq!(trace[0].executable_component_digest, digest(15));
        assert_eq!(trace[0].runtime_principal_digest, digest(13));
    }
}
