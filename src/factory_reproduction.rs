//! Bounded, durable factory reproduction for the M5 reference path.
//!
//! This module deliberately does not implement unrestricted repository
//! self-modification. The mutable genome is exactly one reference-task Wasm
//! component plus a small generation policy. Everything else in a
//! [`FactoryPackage`] is immutable, explicit, and content addressed.
//!
//! Effects are injected behind phase-specific M1--M4 ports. The engine treats
//! every port result as untrusted evidence: request, package, interface, gate,
//! approval, and execution digests are recomputed before state changes. Package
//! activation is over the exact canonical bytes approved by the supervisor.
//!
//! The durable journal is written atomically. An effect intent is persisted
//! before migration or activation. Reopening with an unfinished intent invokes
//! the M3 recovery port and will not continue until the retained incumbent and
//! its readable state schema are confirmed.

use crate::execution::artifact::ContentDigest;
use crate::execution::component::ComponentI32ExecutionTrace;
use crate::execution::inference::{
    InferenceFinishReason, InferenceRetryClassification, normalize_safe_provider_api_base_url,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

pub const REPRODUCTION_STATE_SCHEMA_VERSION: u32 = 6;
pub const FACTORY_PACKAGE_SCHEMA: &str = "wasm-biotic.factory-package.v1";
pub const FACTORY_BOOT_MANIFEST_SCHEMA: &str = "wasm-biotic.factory-boot-manifest.v1";
pub const FACTORY_GENOME_SCHEMA: &str = "wasm-biotic.factory-genome.v1";
pub const RELEASE_GATE_SCHEMA: &str = "wasm-biotic.factory-release-gate.v1";
pub const LINEAGE_RECORD_SCHEMA: &str = "wasm-biotic.factory-lineage.v1";
pub const LIVE_PROVIDER_QUALIFICATION_SCHEMA: &str = "wasm-biotic.live-provider-qualification.v4";
pub const M5_PROVIDER_ACCOUNTING_SCHEMA: &str = "wasm-biotic.m5-provider-accounting-summary.v3";
pub const M5_PROVIDER_INTENT_SCHEMA: &str = "wasm-biotic.m5-provider-intent.v2";
pub const PROVIDER_REPLAY_CAPSULE_SCHEMA: &str = "wasm-biotic.provider-replay-capsule.v2";
pub const CYCLE_EXECUTION_POLICY_SCHEMA: &str = "wasm-biotic.factory-cycle-execution-policy.v1";
pub const M5_UNBOUND_INVOCATION_CHALLENGE_DOMAIN: &[u8] =
    b"wasm-biotic:m5-unbound-invocation-challenge:v1";

pub fn unbound_provider_invocation_challenge_digest() -> ContentDigest {
    ContentDigest::from_bytes(M5_UNBOUND_INVOCATION_CHALLENGE_DOMAIN)
}

pub const REFERENCE_INTERFACE_REF: &str = "wit:wasm-biotic:reference-task/reference-task@v1";
pub const REFERENCE_WORLD: &str = "reference-task";
pub const REFERENCE_EXPORT: &str = "transform";
pub const REFERENCE_WIT: &str = "package wasm-biotic:reference-task;\n\nworld reference-task {\n    export transform: func(input: s32) -> s32;\n}\n";
pub const REFERENCE_GENERATION_DRIVER_SCHEMA: &str =
    "wasm-biotic.reference-transform-generation-driver.v1";
pub const REFERENCE_GENERATION_DRIVER_INPUT: i32 = i32::MIN;
pub const REFERENCE_GENERATION_DIRECTIVE_MIN: i32 = 1;
pub const REFERENCE_GENERATION_DIRECTIVE_MAX: i32 = 16;

const STATE_FILE_NAME: &str = "factory-reproduction-state.json";
const ENGINE_OWNER_LOCK_FILE: &str = ".factory-reproduction-owner.lock";
const PACKAGE_DIRECTORY_NAME: &str = "factory-packages";
const ENGINE_MIGRATION_INTENT_FILE: &str = "factory-state-schema-migration.json";
const ENGINE_MIGRATION_BACKUP_FILE: &str = "factory-state-schema-backup.json";
const MAX_COMPONENT_BYTES: usize = 1_048_576;
const MAX_PACKAGE_BYTES: usize = 16 * 1_048_576;
const MAX_RECORDS: usize = 10_000;
const MAX_TEXT_BYTES: usize = 16_384;
const MAX_PROVIDER_TRANSCRIPT_BYTES: usize = 256 * 1_024;
const MAX_PROVIDER_CAPSULE_BYTES: usize = 512 * 1_024;
const MAX_M5_PROVIDER_ATTEMPTS: usize = 4;
pub const MAX_M5_PROVIDER_RETRIES: u32 = (MAX_M5_PROVIDER_ATTEMPTS - 1) as u32;
pub const MAX_M5_PROVIDER_OUTPUT_TOKENS: u32 = 4_096;
const MAX_BENCHMARKS: usize = 256;
const MAX_OBSERVATIONS: usize = 4_096;
const MAX_GENERATION_DEPTH: u32 = 64;

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StableInterfaceContract {
    pub interface_ref: String,
    pub world: String,
    pub exported_function: String,
    pub wit_bytes: Vec<u8>,
    pub wit_digest: ContentDigest,
}

impl StableInterfaceContract {
    pub fn reference() -> Self {
        let wit_bytes = REFERENCE_WIT.as_bytes().to_vec();
        Self {
            interface_ref: REFERENCE_INTERFACE_REF.to_string(),
            world: REFERENCE_WORLD.to_string(),
            exported_function: REFERENCE_EXPORT.to_string(),
            wit_digest: ContentDigest::from_bytes(&wit_bytes),
            wit_bytes,
        }
    }

    pub fn validate(&self) -> Result<(), ReproductionError> {
        if self.interface_ref != REFERENCE_INTERFACE_REF
            || self.world != REFERENCE_WORLD
            || self.exported_function != REFERENCE_EXPORT
            || self.wit_bytes != REFERENCE_WIT.as_bytes()
        {
            return Err(ReproductionError::InterfaceMismatch {
                expected: REFERENCE_INTERFACE_REF.to_string(),
                actual: self.interface_ref.clone(),
            });
        }
        require_digest(
            "stable interface WIT",
            &self.wit_digest,
            &ContentDigest::from_bytes(&self.wit_bytes),
        )
    }

    pub fn contract_digest(&self) -> Result<ContentDigest, ReproductionError> {
        self.validate()?;
        digest_serializable(&(
            "wasm-biotic:stable-interface-contract:v1",
            &self.interface_ref,
            &self.world,
            &self.exported_function,
            &self.wit_digest,
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerRole {
    Planner,
    Builder,
    Validator,
    Reviewer,
    Packager,
    Continuity,
}

impl WorkerRole {
    fn required() -> [Self; 6] {
        [
            Self::Planner,
            Self::Builder,
            Self::Validator,
            Self::Reviewer,
            Self::Packager,
            Self::Continuity,
        ]
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerCatalogEntry {
    pub role: WorkerRole,
    pub implementation_ref: String,
    pub implementation_digest: ContentDigest,
    pub required_service_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerCatalog {
    pub entries: Vec<WorkerCatalogEntry>,
    pub catalog_digest: ContentDigest,
}

impl WorkerCatalog {
    pub fn reference() -> Result<Self, ReproductionError> {
        let entries = WorkerRole::required()
            .into_iter()
            .map(|role| {
                let implementation_ref = format!("worker:{role:?}:v1").to_lowercase();
                WorkerCatalogEntry {
                    implementation_digest: ContentDigest::from_bytes(implementation_ref.as_bytes()),
                    implementation_ref,
                    role,
                    required_service_ids: required_services_for_role(role),
                }
            })
            .collect();
        Self::new(entries)
    }

    pub fn new(entries: Vec<WorkerCatalogEntry>) -> Result<Self, ReproductionError> {
        let mut catalog = Self {
            entries,
            catalog_digest: ContentDigest::from_bytes(&[]),
        };
        catalog.validate_entries()?;
        catalog.catalog_digest =
            digest_serializable(&("wasm-biotic:worker-catalog:v1", &catalog.entries))?;
        Ok(catalog)
    }

    pub fn validate(&self) -> Result<(), ReproductionError> {
        self.validate_entries()?;
        require_digest(
            "worker catalog",
            &self.catalog_digest,
            &digest_serializable(&("wasm-biotic:worker-catalog:v1", &self.entries))?,
        )
    }

    fn validate_entries(&self) -> Result<(), ReproductionError> {
        let mut roles = BTreeSet::new();
        for entry in &self.entries {
            validate_identifier("worker implementation ref", &entry.implementation_ref)?;
            if !roles.insert(entry.role) {
                return Err(ReproductionError::InvalidConfiguration(format!(
                    "worker role '{:?}' is duplicated",
                    entry.role
                )));
            }
            if entry.required_service_ids.is_empty() {
                return Err(ReproductionError::InvalidConfiguration(format!(
                    "worker role '{:?}' must declare nonblank service dependencies",
                    entry.role
                )));
            }
            let mut required_service_ids = BTreeSet::new();
            for service_id in &entry.required_service_ids {
                validate_identifier("worker required service id", service_id)?;
                if !required_service_ids.insert(service_id.as_str()) {
                    return Err(ReproductionError::InvalidConfiguration(format!(
                        "worker role '{:?}' declares required service '{}' more than once",
                        entry.role, service_id
                    )));
                }
            }
            require_digest(
                "worker implementation",
                &entry.implementation_digest,
                &ContentDigest::from_bytes(entry.implementation_ref.as_bytes()),
            )?;
        }
        let required = WorkerRole::required().into_iter().collect::<BTreeSet<_>>();
        if roles != required {
            return Err(ReproductionError::InvalidConfiguration(
                "worker catalog must contain Planner, Builder, Validator, Reviewer, Packager, and Continuity exactly once"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

fn required_services_for_role(role: WorkerRole) -> Vec<String> {
    match role {
        WorkerRole::Planner => vec!["supervisor".to_string(), "evidence".to_string()],
        WorkerRole::Builder => vec!["candidate".to_string(), "build".to_string()],
        WorkerRole::Validator => vec!["validation".to_string()],
        // The package schema models validation/review and build/packaging as
        // combined service boundaries. Both worker roles therefore reference
        // the one catalog id that owns their shared boundary.
        WorkerRole::Reviewer => vec!["validation".to_string(), "supervisor".to_string()],
        WorkerRole::Packager => vec!["build".to_string()],
        WorkerRole::Continuity => vec!["evidence".to_string(), "deployment".to_string()],
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceRole {
    CandidateWorkspace,
    BuildPackaging,
    ValidationReview,
    Supervisor,
    DeploymentRollback,
    EvidencePublication,
    WorkerExecution,
}

impl ServiceRole {
    fn required() -> [Self; 7] {
        [
            Self::CandidateWorkspace,
            Self::BuildPackaging,
            Self::ValidationReview,
            Self::Supervisor,
            Self::DeploymentRollback,
            Self::EvidencePublication,
            Self::WorkerExecution,
        ]
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceDependency {
    pub service_id: String,
    pub role: ServiceRole,
    pub interface_ref: String,
    pub implementation_digest: ContentDigest,
    pub required: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceDependencyCatalog {
    pub dependencies: Vec<ServiceDependency>,
    pub catalog_digest: ContentDigest,
}

impl ServiceDependencyCatalog {
    pub fn reference() -> Result<Self, ReproductionError> {
        let dependencies = ServiceRole::required()
            .into_iter()
            .map(|role| {
                let service_id = match role {
                    ServiceRole::CandidateWorkspace => "candidate",
                    ServiceRole::BuildPackaging => "build",
                    ServiceRole::ValidationReview => "validation",
                    ServiceRole::Supervisor => "supervisor",
                    ServiceRole::DeploymentRollback => "deployment",
                    ServiceRole::EvidencePublication => "evidence",
                    ServiceRole::WorkerExecution => "workers",
                }
                .to_string();
                let interface_ref = format!("wasm-biotic:service/{service_id}@v1");
                ServiceDependency {
                    implementation_digest: ContentDigest::from_bytes(
                        format!("{service_id}:local-v1").as_bytes(),
                    ),
                    service_id,
                    role,
                    interface_ref,
                    required: true,
                }
            })
            .collect();
        Self::new(dependencies)
    }

    pub fn new(dependencies: Vec<ServiceDependency>) -> Result<Self, ReproductionError> {
        let mut catalog = Self {
            dependencies,
            catalog_digest: ContentDigest::from_bytes(&[]),
        };
        catalog.validate_dependencies()?;
        catalog.catalog_digest = digest_serializable(&(
            "wasm-biotic:service-dependency-catalog:v1",
            &catalog.dependencies,
        ))?;
        Ok(catalog)
    }

    pub fn validate(&self) -> Result<(), ReproductionError> {
        self.validate_dependencies()?;
        require_digest(
            "service dependency catalog",
            &self.catalog_digest,
            &digest_serializable(&(
                "wasm-biotic:service-dependency-catalog:v1",
                &self.dependencies,
            ))?,
        )
    }

    fn validate_dependencies(&self) -> Result<(), ReproductionError> {
        let mut roles = BTreeSet::new();
        let mut ids = BTreeSet::new();
        for dependency in &self.dependencies {
            validate_identifier("service id", &dependency.service_id)?;
            validate_identifier("service interface ref", &dependency.interface_ref)?;
            if !dependency.required {
                return Err(ReproductionError::InvalidConfiguration(format!(
                    "bounded service '{}' cannot be optional",
                    dependency.service_id
                )));
            }
            if !roles.insert(dependency.role) || !ids.insert(dependency.service_id.as_str()) {
                return Err(ReproductionError::InvalidConfiguration(
                    "service dependency roles and ids must be unique".to_string(),
                ));
            }
        }
        let required = ServiceRole::required().into_iter().collect::<BTreeSet<_>>();
        if roles != required {
            return Err(ReproductionError::InvalidConfiguration(
                "service catalog does not cover the required M1-M4 boundaries".to_string(),
            ));
        }
        Ok(())
    }
}

fn validate_worker_service_references(
    workers: &WorkerCatalog,
    services: &ServiceDependencyCatalog,
) -> Result<(), ReproductionError> {
    let mut services_by_id = BTreeMap::<&str, &ServiceDependency>::new();
    let mut services_by_role = BTreeMap::<ServiceRole, &ServiceDependency>::new();
    for dependency in &services.dependencies {
        services_by_id.insert(dependency.service_id.as_str(), dependency);
        services_by_role.insert(dependency.role, dependency);
    }

    for worker in &workers.entries {
        let expected_roles = expected_service_roles_for_worker(worker.role)
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let mut resolved_roles = BTreeSet::new();
        for required_service_id in &worker.required_service_ids {
            let Some((referenced_role, is_legacy_alias)) =
                admitted_worker_service_reference(worker.role, required_service_id)
            else {
                return Err(ReproductionError::InvalidConfiguration(format!(
                    "worker role '{:?}' requires service '{}' but the package service catalog resolves it 0 times; only exact current service ids and the frozen R8 aliases are admitted",
                    worker.role, required_service_id
                )));
            };
            let resolved = if is_legacy_alias {
                services_by_role.get(&referenced_role).copied()
            } else {
                services_by_id.get(required_service_id.as_str()).copied()
            };
            let Some(resolved) = resolved else {
                return Err(ReproductionError::InvalidConfiguration(format!(
                    "worker role '{:?}' requires service '{}' but the package service catalog resolves it 0 times; exactly one resolution is required",
                    worker.role, required_service_id
                )));
            };
            if resolved.role != referenced_role {
                return Err(ReproductionError::InvalidConfiguration(format!(
                    "worker role '{:?}' requires service '{}' as role '{referenced_role:?}', but that exact service id resolves to role '{:?}'",
                    worker.role, required_service_id, resolved.role
                )));
            }
            if !resolved_roles.insert(resolved.role) {
                return Err(ReproductionError::InvalidConfiguration(format!(
                    "worker role '{:?}' resolves service role '{:?}' more than once",
                    worker.role, resolved.role
                )));
            }
        }
        if resolved_roles != expected_roles {
            return Err(ReproductionError::InvalidConfiguration(format!(
                "worker role '{:?}' resolves service roles {resolved_roles:?}, but its exact required role set is {expected_roles:?}",
                worker.role
            )));
        }
    }
    Ok(())
}

fn expected_service_roles_for_worker(role: WorkerRole) -> &'static [ServiceRole] {
    match role {
        WorkerRole::Planner => &[ServiceRole::Supervisor, ServiceRole::EvidencePublication],
        WorkerRole::Builder => &[ServiceRole::CandidateWorkspace, ServiceRole::BuildPackaging],
        WorkerRole::Validator => &[ServiceRole::ValidationReview],
        WorkerRole::Reviewer => &[ServiceRole::ValidationReview, ServiceRole::Supervisor],
        WorkerRole::Packager => &[ServiceRole::BuildPackaging],
        WorkerRole::Continuity => &[
            ServiceRole::EvidencePublication,
            ServiceRole::DeploymentRollback,
        ],
    }
}

/// Resolve the current package vocabulary without weakening exact-id binding.
///
/// R8 emitted two worker-side names that never existed as service ids:
/// Reviewer used `review` for the `ValidationReview` boundary and Packager used
/// `packaging` for `BuildPackaging`. Those two aliases are frozen to their
/// historical worker roles and resolve through the service catalog's semantic
/// role. Every other reference is a current id and must resolve by exact id.
fn admitted_worker_service_reference(
    worker_role: WorkerRole,
    service_id: &str,
) -> Option<(ServiceRole, bool)> {
    let current = match service_id {
        "candidate" => Some(ServiceRole::CandidateWorkspace),
        "build" => Some(ServiceRole::BuildPackaging),
        "validation" => Some(ServiceRole::ValidationReview),
        "supervisor" => Some(ServiceRole::Supervisor),
        "deployment" => Some(ServiceRole::DeploymentRollback),
        "evidence" => Some(ServiceRole::EvidencePublication),
        "workers" => Some(ServiceRole::WorkerExecution),
        _ => None,
    };
    if let Some(role) = current {
        return Some((role, false));
    }
    match (worker_role, service_id) {
        (WorkerRole::Reviewer, "review") => Some((ServiceRole::ValidationReview, true)),
        (WorkerRole::Packager, "packaging") => Some((ServiceRole::BuildPackaging, true)),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GenerationRendererProfile {
    ReferenceDeltaV1,
}

/// The one frozen generation-driver protocol admitted by the bounded M5 path.
///
/// The active package is invoked through the same stable reference-task
/// interface used for ordinary work. A distinguished input turns the returned
/// `s32` into a bounded directive for a trusted canonical renderer. The
/// contract deliberately contains no successor source, bytes, or digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationDriverContract {
    pub schema: String,
    pub interface_ref: String,
    pub exported_function: String,
    pub driver_input: i32,
    pub directive_min: i32,
    pub directive_max: i32,
    pub renderer_profile: GenerationRendererProfile,
}

impl GenerationDriverContract {
    pub fn reference() -> Self {
        Self {
            schema: REFERENCE_GENERATION_DRIVER_SCHEMA.to_string(),
            interface_ref: REFERENCE_INTERFACE_REF.to_string(),
            exported_function: REFERENCE_EXPORT.to_string(),
            driver_input: REFERENCE_GENERATION_DRIVER_INPUT,
            directive_min: REFERENCE_GENERATION_DIRECTIVE_MIN,
            directive_max: REFERENCE_GENERATION_DIRECTIVE_MAX,
            renderer_profile: GenerationRendererProfile::ReferenceDeltaV1,
        }
    }

    pub fn validate(&self) -> Result<(), ReproductionError> {
        if self != &Self::reference() {
            return Err(ReproductionError::InvalidConfiguration(
                "generation driver must use the frozen reference driver contract".to_string(),
            ));
        }
        Ok(())
    }

    pub fn contract_digest(&self) -> Result<ContentDigest, ReproductionError> {
        self.validate()?;
        digest_serializable(&(
            "wasm-biotic:generation-driver-contract:v1",
            &self.schema,
            &self.interface_ref,
            &self.exported_function,
            self.driver_input,
            self.directive_min,
            self.directive_max,
            self.renderer_profile,
        ))
    }

    fn validate_directive(&self, directive: i32) -> Result<(), ReproductionError> {
        self.validate()?;
        if !(self.directive_min..=self.directive_max).contains(&directive) {
            return Err(ReproductionError::EvidenceRejected(format!(
                "generation directive {directive} is outside {}..={}",
                self.directive_min, self.directive_max
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationLoopInstruction {
    pub instruction_id: String,
    pub driver_contract: GenerationDriverContract,
    pub successor_policy_revision: u32,
    pub max_executions: u32,
}

impl GenerationLoopInstruction {
    pub fn instruction_digest(&self) -> Result<ContentDigest, ReproductionError> {
        self.validate()?;
        digest_serializable(&("wasm-biotic:generation-loop-instruction:v2", self))
    }

    pub fn validate(&self) -> Result<(), ReproductionError> {
        validate_identifier("generation instruction id", &self.instruction_id)?;
        self.driver_contract.validate()?;
        if self.successor_policy_revision == 0 {
            return Err(ReproductionError::InvalidConfiguration(
                "successor policy revision must be nonzero".to_string(),
            ));
        }
        if self.max_executions == 0 {
            return Err(ReproductionError::InvalidConfiguration(
                "generation instruction must permit at least one execution".to_string(),
            ));
        }
        Ok(())
    }
}

/// Render the canonical bounded successor source selected by one active-driver
/// directive. The deliberately redundant arithmetic keeps the generated
/// component byte-distinct from the usual hand-authored `x + d` seed while
/// preserving its observable result.
pub fn render_reference_delta_v1(directive: i32) -> Result<Vec<u8>, ReproductionError> {
    GenerationDriverContract::reference().validate_directive(directive)?;
    let raised = directive.checked_add(1).ok_or_else(|| {
        ReproductionError::BudgetExceeded("generation directive arithmetic overflowed".to_string())
    })?;
    Ok(format!(
        r#"(component
    (core module $implementation
        (func (export "transform") (param i32) (result i32)
            local.get 0
            i32.const {raised}
            i32.add
            i32.const 1
            i32.sub))
    (core instance $instance (instantiate $implementation))
    (func (export "transform") (param "input" s32) (result s32)
        (canon lift (core func $instance "transform"))))"#
    )
    .into_bytes())
}

fn compile_reference_delta_v1(wat_bytes: &[u8]) -> Result<Vec<u8>, ReproductionError> {
    if wat_bytes.is_empty() || wat_bytes.len() > MAX_COMPONENT_BYTES {
        return Err(ReproductionError::BudgetExceeded(
            "rendered successor WAT is outside the component byte bound".to_string(),
        ));
    }
    wat::parse_bytes(wat_bytes)
        .map(|bytes| bytes.into_owned())
        .map_err(|error| {
            ReproductionError::EvidenceRejected(format!(
                "rendered successor WAT did not compile: {error}"
            ))
        })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutableFactoryPolicy {
    pub policy_revision: u32,
    pub generation_enabled: bool,
    pub generation_instruction: Option<GenerationLoopInstruction>,
    pub max_canary_tasks: u32,
}

impl MutableFactoryPolicy {
    pub fn terminal(policy_revision: u32, max_canary_tasks: u32) -> Self {
        Self {
            policy_revision,
            generation_enabled: false,
            generation_instruction: None,
            max_canary_tasks,
        }
    }

    pub fn validate(&self) -> Result<(), ReproductionError> {
        if self.policy_revision == 0 {
            return Err(ReproductionError::InvalidConfiguration(
                "policy revision must be nonzero".to_string(),
            ));
        }
        if self.max_canary_tasks == 0 || self.max_canary_tasks as usize > MAX_BENCHMARKS {
            return Err(ReproductionError::InvalidConfiguration(format!(
                "max_canary_tasks must be between 1 and {MAX_BENCHMARKS}"
            )));
        }
        match (self.generation_enabled, &self.generation_instruction) {
            (true, Some(instruction)) => instruction.validate(),
            (false, None) => Ok(()),
            _ => Err(ReproductionError::InvalidConfiguration(
                "generation_enabled and generation_instruction must agree".to_string(),
            )),
        }
    }

    pub fn policy_digest(&self) -> Result<ContentDigest, ReproductionError> {
        self.validate()?;
        digest_serializable(&("wasm-biotic:mutable-factory-policy:v1", self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutableGenome {
    pub schema: String,
    pub parent_package_digest: Option<ContentDigest>,
    pub stable_interface_ref: String,
    pub component_bytes: Vec<u8>,
    pub component_digest: ContentDigest,
    pub policy: MutableFactoryPolicy,
    pub policy_digest: ContentDigest,
    pub genome_digest: ContentDigest,
}

impl MutableGenome {
    pub fn new(
        parent_package_digest: Option<ContentDigest>,
        component_bytes: Vec<u8>,
        policy: MutableFactoryPolicy,
    ) -> Result<Self, ReproductionError> {
        policy.validate()?;
        if component_bytes.is_empty() || component_bytes.len() > MAX_COMPONENT_BYTES {
            return Err(ReproductionError::InvalidConfiguration(format!(
                "component must contain 1..={MAX_COMPONENT_BYTES} bytes"
            )));
        }
        let component_digest = ContentDigest::from_bytes(&component_bytes);
        let policy_digest = policy.policy_digest()?;
        let mut genome = Self {
            schema: FACTORY_GENOME_SCHEMA.to_string(),
            parent_package_digest,
            stable_interface_ref: REFERENCE_INTERFACE_REF.to_string(),
            component_bytes,
            component_digest,
            policy,
            policy_digest,
            genome_digest: ContentDigest::from_bytes(&[]),
        };
        genome.genome_digest = genome.expected_genome_digest()?;
        Ok(genome)
    }

    pub fn validate(&self) -> Result<(), ReproductionError> {
        if self.schema != FACTORY_GENOME_SCHEMA {
            return Err(ReproductionError::InvalidConfiguration(format!(
                "unsupported genome schema '{}'",
                self.schema
            )));
        }
        if self.stable_interface_ref != REFERENCE_INTERFACE_REF {
            return Err(ReproductionError::InterfaceMismatch {
                expected: REFERENCE_INTERFACE_REF.to_string(),
                actual: self.stable_interface_ref.clone(),
            });
        }
        if self.component_bytes.is_empty() || self.component_bytes.len() > MAX_COMPONENT_BYTES {
            return Err(ReproductionError::InvalidConfiguration(format!(
                "component must contain 1..={MAX_COMPONENT_BYTES} bytes"
            )));
        }
        self.policy.validate()?;
        require_digest(
            "genome component",
            &self.component_digest,
            &ContentDigest::from_bytes(&self.component_bytes),
        )?;
        require_digest(
            "genome policy",
            &self.policy_digest,
            &self.policy.policy_digest()?,
        )?;
        require_digest(
            "genome",
            &self.genome_digest,
            &self.expected_genome_digest()?,
        )
    }

    fn expected_genome_digest(&self) -> Result<ContentDigest, ReproductionError> {
        digest_serializable(&(
            FACTORY_GENOME_SCHEMA,
            &self.parent_package_digest,
            &self.stable_interface_ref,
            &self.component_digest,
            &self.policy_digest,
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateCompatibility {
    pub readable_schema_min: u32,
    pub readable_schema_max: u32,
    pub written_schema: u32,
    pub incumbent_rollback_readable_through: u32,
}

impl StateCompatibility {
    pub fn validate(&self) -> Result<(), ReproductionError> {
        if self.readable_schema_min == 0
            || self.readable_schema_min > self.readable_schema_max
            || self.written_schema < self.readable_schema_min
            || self.written_schema > self.readable_schema_max
            || self.incumbent_rollback_readable_through == 0
        {
            return Err(ReproductionError::InvalidConfiguration(
                "invalid package state-schema compatibility range".to_string(),
            ));
        }
        Ok(())
    }

    fn can_read(&self, schema: u32) -> bool {
        (self.readable_schema_min..=self.readable_schema_max).contains(&schema)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactoryBootManifest {
    pub schema: String,
    pub package_format_version: u32,
    pub interface_digest: ContentDigest,
    pub component_digest: ContentDigest,
    pub policy_digest: ContentDigest,
    pub worker_catalog_digest: ContentDigest,
    pub service_catalog_digest: ContentDigest,
    pub generation_instruction_digest: Option<ContentDigest>,
    pub state_compatibility: StateCompatibility,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactoryPackagePayload {
    pub schema: String,
    pub factory_id: String,
    pub generation: u32,
    pub parent_package_digest: Option<ContentDigest>,
    pub genome: MutableGenome,
    pub boot_manifest: FactoryBootManifest,
    pub stable_interface: StableInterfaceContract,
    pub worker_catalog: WorkerCatalog,
    pub service_dependencies: ServiceDependencyCatalog,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactoryPackage {
    pub payload: FactoryPackagePayload,
    pub package_digest: ContentDigest,
    pub byte_len: u64,
}

impl FactoryPackage {
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        factory_id: impl Into<String>,
        generation: u32,
        genome: MutableGenome,
        stable_interface: StableInterfaceContract,
        worker_catalog: WorkerCatalog,
        service_dependencies: ServiceDependencyCatalog,
        state_compatibility: StateCompatibility,
    ) -> Result<Self, ReproductionError> {
        let factory_id = factory_id.into();
        validate_identifier("factory id", &factory_id)?;
        if generation > MAX_GENERATION_DEPTH {
            return Err(ReproductionError::BudgetExceeded(
                "package generation exceeds the hard depth bound".to_string(),
            ));
        }
        genome.validate()?;
        stable_interface.validate()?;
        worker_catalog.validate()?;
        service_dependencies.validate()?;
        validate_worker_service_references(&worker_catalog, &service_dependencies)?;
        state_compatibility.validate()?;
        let generation_instruction_digest = genome
            .policy
            .generation_instruction
            .as_ref()
            .map(GenerationLoopInstruction::instruction_digest)
            .transpose()?;
        let boot_manifest = FactoryBootManifest {
            schema: FACTORY_BOOT_MANIFEST_SCHEMA.to_string(),
            package_format_version: 1,
            interface_digest: stable_interface.contract_digest()?,
            component_digest: genome.component_digest.clone(),
            policy_digest: genome.policy_digest.clone(),
            worker_catalog_digest: worker_catalog.catalog_digest.clone(),
            service_catalog_digest: service_dependencies.catalog_digest.clone(),
            generation_instruction_digest,
            state_compatibility,
        };
        let payload = FactoryPackagePayload {
            schema: FACTORY_PACKAGE_SCHEMA.to_string(),
            factory_id,
            generation,
            parent_package_digest: genome.parent_package_digest.clone(),
            genome,
            boot_manifest,
            stable_interface,
            worker_catalog,
            service_dependencies,
        };
        let bytes = canonical_json(&payload)?;
        if bytes.len() > MAX_PACKAGE_BYTES {
            return Err(ReproductionError::BudgetExceeded(format!(
                "factory package is {} bytes; limit is {MAX_PACKAGE_BYTES}",
                bytes.len()
            )));
        }
        let package = Self {
            package_digest: ContentDigest::from_bytes(&bytes),
            byte_len: bytes.len() as u64,
            payload,
        };
        package.validate()?;
        Ok(package)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ReproductionError> {
        self.validate()?;
        canonical_json(&self.payload)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ReproductionError> {
        if bytes.is_empty() || bytes.len() > MAX_PACKAGE_BYTES {
            return Err(ReproductionError::InvalidPackage(
                "canonical package byte length is outside bounds".to_string(),
            ));
        }
        let payload: FactoryPackagePayload = serde_json::from_slice(bytes)
            .map_err(|error| ReproductionError::Serialization(error.to_string()))?;
        let canonical = canonical_json(&payload)?;
        if canonical != bytes {
            return Err(ReproductionError::InvalidPackage(
                "package bytes are not in the canonical representation".to_string(),
            ));
        }
        let package = Self {
            payload,
            package_digest: ContentDigest::from_bytes(bytes),
            byte_len: bytes.len() as u64,
        };
        package.validate()?;
        Ok(package)
    }

    pub fn validate(&self) -> Result<(), ReproductionError> {
        let payload = &self.payload;
        if payload.schema != FACTORY_PACKAGE_SCHEMA {
            return Err(ReproductionError::InvalidPackage(format!(
                "unsupported package schema '{}'",
                payload.schema
            )));
        }
        validate_identifier("factory id", &payload.factory_id)?;
        if payload.generation > MAX_GENERATION_DEPTH {
            return Err(ReproductionError::BudgetExceeded(
                "package generation exceeds the hard depth bound".to_string(),
            ));
        }
        payload.genome.validate()?;
        payload.stable_interface.validate()?;
        payload.worker_catalog.validate()?;
        payload.service_dependencies.validate()?;
        validate_worker_service_references(&payload.worker_catalog, &payload.service_dependencies)?;
        payload.boot_manifest.state_compatibility.validate()?;
        if payload.parent_package_digest != payload.genome.parent_package_digest {
            return Err(ReproductionError::InvalidPackage(
                "package and genome parent identities differ".to_string(),
            ));
        }
        let boot = &payload.boot_manifest;
        if boot.schema != FACTORY_BOOT_MANIFEST_SCHEMA || boot.package_format_version != 1 {
            return Err(ReproductionError::InvalidPackage(
                "unsupported boot manifest schema or package format".to_string(),
            ));
        }
        require_digest(
            "boot interface",
            &boot.interface_digest,
            &payload.stable_interface.contract_digest()?,
        )?;
        require_digest(
            "boot component",
            &boot.component_digest,
            &payload.genome.component_digest,
        )?;
        require_digest(
            "boot policy",
            &boot.policy_digest,
            &payload.genome.policy_digest,
        )?;
        require_digest(
            "boot worker catalog",
            &boot.worker_catalog_digest,
            &payload.worker_catalog.catalog_digest,
        )?;
        require_digest(
            "boot service catalog",
            &boot.service_catalog_digest,
            &payload.service_dependencies.catalog_digest,
        )?;
        let instruction_digest = payload
            .genome
            .policy
            .generation_instruction
            .as_ref()
            .map(GenerationLoopInstruction::instruction_digest)
            .transpose()?;
        if boot.generation_instruction_digest != instruction_digest {
            return Err(ReproductionError::DigestMismatch {
                subject: "generation instruction".to_string(),
                expected: boot
                    .generation_instruction_digest
                    .clone()
                    .unwrap_or_else(|| ContentDigest::from_bytes(&[])),
                actual: instruction_digest.unwrap_or_else(|| ContentDigest::from_bytes(&[])),
            });
        }
        let bytes = canonical_json(payload)?;
        if bytes.len() > MAX_PACKAGE_BYTES {
            return Err(ReproductionError::BudgetExceeded(
                "factory package exceeds the package byte budget".to_string(),
            ));
        }
        if self.byte_len != bytes.len() as u64 {
            return Err(ReproductionError::InvalidPackage(
                "recorded package byte length is incorrect".to_string(),
            ));
        }
        require_digest(
            "factory package",
            &self.package_digest,
            &ContentDigest::from_bytes(&bytes),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BenchmarkSpec {
    pub benchmark_id: String,
    pub request_bytes: Vec<u8>,
    pub expected_output_digest: ContentDigest,
    pub max_duration_ms: u64,
    pub required: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvariantKind {
    StableInterface,
    RunnableComponent,
    ExactPackageIdentity,
    BoundedCapabilities,
    DurableRollback,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvariantSpec {
    pub invariant_id: String,
    pub kind: InvariantKind,
    pub required: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecursionBudgets {
    pub max_generation_depth: u32,
    pub max_total_cycles: u32,
    pub max_shadow_tasks: u32,
    pub max_component_bytes: u64,
    pub max_state_bytes: u64,
    pub max_provider_turns: u32,
}

impl RecursionBudgets {
    fn validate(&self) -> Result<(), ReproductionError> {
        if self.max_generation_depth == 0
            || self.max_generation_depth > MAX_GENERATION_DEPTH
            || self.max_total_cycles == 0
            || self.max_shadow_tasks == 0
            || self.max_shadow_tasks as usize > MAX_OBSERVATIONS
            || self.max_component_bytes == 0
            || self.max_component_bytes > MAX_COMPONENT_BYTES as u64
            || self.max_state_bytes == 0
            || self.max_provider_turns == 0
        {
            return Err(ReproductionError::InvalidConfiguration(
                "release-gate budgets are zero or exceed hard bounds".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseThresholds {
    pub minimum_passed_benchmarks: u32,
    pub minimum_success_basis_points: u16,
    pub maximum_regressions: u32,
    pub require_all_required_invariants: bool,
    pub minimum_post_activation_successes: u32,
}

impl ReleaseThresholds {
    fn validate(&self, benchmark_count: usize) -> Result<(), ReproductionError> {
        if self.minimum_passed_benchmarks == 0
            || self.minimum_passed_benchmarks as usize > benchmark_count
            || self.minimum_success_basis_points > 10_000
            || self.minimum_post_activation_successes == 0
        {
            return Err(ReproductionError::InvalidConfiguration(
                "release thresholds are outside declared benchmark bounds".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseGate {
    pub schema: String,
    pub gate_id: String,
    pub benchmarks: Vec<BenchmarkSpec>,
    pub invariants: Vec<InvariantSpec>,
    pub budgets: RecursionBudgets,
    pub thresholds: ReleaseThresholds,
    pub gate_digest: ContentDigest,
}

impl ReleaseGate {
    pub fn new(
        gate_id: impl Into<String>,
        benchmarks: Vec<BenchmarkSpec>,
        invariants: Vec<InvariantSpec>,
        budgets: RecursionBudgets,
        thresholds: ReleaseThresholds,
    ) -> Result<Self, ReproductionError> {
        let mut gate = Self {
            schema: RELEASE_GATE_SCHEMA.to_string(),
            gate_id: gate_id.into(),
            benchmarks,
            invariants,
            budgets,
            thresholds,
            gate_digest: ContentDigest::from_bytes(&[]),
        };
        gate.validate_fields()?;
        gate.gate_digest = gate.expected_digest()?;
        Ok(gate)
    }

    pub fn validate(&self) -> Result<(), ReproductionError> {
        self.validate_fields()?;
        require_digest("release gate", &self.gate_digest, &self.expected_digest()?)
    }

    fn validate_fields(&self) -> Result<(), ReproductionError> {
        if self.schema != RELEASE_GATE_SCHEMA {
            return Err(ReproductionError::InvalidConfiguration(
                "unsupported release-gate schema".to_string(),
            ));
        }
        validate_identifier("release gate id", &self.gate_id)?;
        if self.benchmarks.is_empty() || self.benchmarks.len() > MAX_BENCHMARKS {
            return Err(ReproductionError::InvalidConfiguration(format!(
                "release gate requires 1..={MAX_BENCHMARKS} benchmarks"
            )));
        }
        let mut benchmark_ids = BTreeSet::new();
        for benchmark in &self.benchmarks {
            validate_identifier("benchmark id", &benchmark.benchmark_id)?;
            if !benchmark_ids.insert(benchmark.benchmark_id.as_str()) {
                return Err(ReproductionError::InvalidConfiguration(
                    "benchmark ids must be unique".to_string(),
                ));
            }
            if benchmark.request_bytes.is_empty() || benchmark.max_duration_ms == 0 {
                return Err(ReproductionError::InvalidConfiguration(
                    "benchmark requests and duration budgets must be nonzero".to_string(),
                ));
            }
        }
        if self.invariants.is_empty() {
            return Err(ReproductionError::InvalidConfiguration(
                "release gate requires invariants".to_string(),
            ));
        }
        let mut invariant_ids = BTreeSet::new();
        let mut invariant_kinds = BTreeSet::new();
        for invariant in &self.invariants {
            validate_identifier("invariant id", &invariant.invariant_id)?;
            if !invariant_ids.insert(invariant.invariant_id.as_str())
                || !invariant_kinds.insert(format!("{:?}", invariant.kind))
            {
                return Err(ReproductionError::InvalidConfiguration(
                    "invariant ids and kinds must be unique".to_string(),
                ));
            }
        }
        for required in [
            InvariantKind::StableInterface,
            InvariantKind::RunnableComponent,
            InvariantKind::ExactPackageIdentity,
            InvariantKind::BoundedCapabilities,
            InvariantKind::DurableRollback,
        ] {
            if !self
                .invariants
                .iter()
                .any(|invariant| invariant.kind == required && invariant.required)
            {
                return Err(ReproductionError::InvalidConfiguration(format!(
                    "required invariant '{required:?}' is missing"
                )));
            }
        }
        self.budgets.validate()?;
        if self.benchmarks.len() > self.budgets.max_shadow_tasks as usize {
            return Err(ReproductionError::InvalidConfiguration(
                "benchmark count exceeds the declared shadow-task budget".to_string(),
            ));
        }
        self.thresholds.validate(self.benchmarks.len())
    }

    fn expected_digest(&self) -> Result<ContentDigest, ReproductionError> {
        digest_serializable(&(
            RELEASE_GATE_SCHEMA,
            &self.gate_id,
            &self.benchmarks,
            &self.invariants,
            &self.budgets,
            &self.thresholds,
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortFailureKind {
    Unavailable,
    TimedOut,
    Cancelled,
    Rejected,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PortFailure {
    pub kind: PortFailureKind,
    pub code: String,
    pub message: String,
}

impl PortFailure {
    pub fn unavailable(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            kind: PortFailureKind::Unavailable,
            code: code.into(),
            message: message.into(),
        }
    }

    pub fn failed(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            kind: PortFailureKind::Failed,
            code: code.into(),
            message: message.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M1BuildRequest {
    pub cycle_id: String,
    pub genome_digest: ContentDigest,
    pub component_digest: ContentDigest,
    pub component_bytes: Vec<u8>,
    pub stable_interface_digest: ContentDigest,
    pub request_digest: ContentDigest,
}

impl M1BuildRequest {
    fn new(
        cycle_id: &str,
        genome: &MutableGenome,
        interface: &StableInterfaceContract,
    ) -> Result<Self, ReproductionError> {
        let mut request = Self {
            cycle_id: cycle_id.to_string(),
            genome_digest: genome.genome_digest.clone(),
            component_digest: genome.component_digest.clone(),
            component_bytes: genome.component_bytes.clone(),
            stable_interface_digest: interface.contract_digest()?,
            request_digest: ContentDigest::from_bytes(&[]),
        };
        request.request_digest = digest_serializable(&(
            "wasm-biotic:m1-build-request:v1",
            &request.cycle_id,
            &request.genome_digest,
            &request.component_digest,
            &request.component_bytes,
            &request.stable_interface_digest,
        ))?;
        Ok(request)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M1BuildEvidence {
    pub request_digest: ContentDigest,
    pub component_digest: ContentDigest,
    pub stable_interface_digest: ContentDigest,
    pub observed_export: String,
    pub runnable: bool,
    pub proving_record_digest: ContentDigest,
    pub evidence_digest: ContentDigest,
}

impl M1BuildEvidence {
    pub fn seal(mut self) -> Result<Self, ReproductionError> {
        self.evidence_digest = m1_evidence_digest(&self)?;
        Ok(self)
    }
}

fn m1_evidence_digest(evidence: &M1BuildEvidence) -> Result<ContentDigest, ReproductionError> {
    digest_serializable(&(
        "wasm-biotic:m1-build-evidence:v1",
        &evidence.request_digest,
        &evidence.component_digest,
        &evidence.stable_interface_digest,
        &evidence.observed_export,
        evidence.runnable,
        &evidence.proving_record_digest,
    ))
}

pub trait M1CandidatePort: Send + Sync {
    /// Builds and executes proving against the exact supplied component bytes.
    fn build_and_prove(&self, request: &M1BuildRequest) -> Result<M1BuildEvidence, PortFailure>;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerWorkflowRequest {
    pub cycle_id: String,
    pub incumbent_package_digest: ContentDigest,
    pub challenger_package_digest: ContentDigest,
    pub challenger_package_bytes_digest: ContentDigest,
    pub genome_digest: ContentDigest,
    pub gate_digest: ContentDigest,
    pub required_roles: Vec<WorkerRole>,
    pub request_digest: ContentDigest,
}

impl WorkerWorkflowRequest {
    fn new(
        cycle_id: &str,
        incumbent: &ContentDigest,
        challenger: &FactoryPackage,
        gate: &ReleaseGate,
    ) -> Result<Self, ReproductionError> {
        let mut request = Self {
            cycle_id: cycle_id.to_string(),
            incumbent_package_digest: incumbent.clone(),
            challenger_package_digest: challenger.package_digest.clone(),
            challenger_package_bytes_digest: ContentDigest::from_bytes(
                &challenger.canonical_bytes()?,
            ),
            genome_digest: challenger.payload.genome.genome_digest.clone(),
            gate_digest: gate.gate_digest.clone(),
            required_roles: WorkerRole::required().to_vec(),
            request_digest: ContentDigest::from_bytes(&[]),
        };
        request.request_digest = digest_serializable(&(
            "wasm-biotic:worker-workflow-request:v1",
            &request.cycle_id,
            &request.incumbent_package_digest,
            &request.challenger_package_digest,
            &request.challenger_package_bytes_digest,
            &request.genome_digest,
            &request.gate_digest,
            &request.required_roles,
        ))?;
        Ok(request)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerTerminalStatus {
    Succeeded,
    Failed,
    TimedOut,
    Cancelled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerReceipt {
    pub role: WorkerRole,
    pub execution_id: String,
    pub terminal_status: WorkerTerminalStatus,
    pub input_digest: ContentDigest,
    pub output_digest: Option<ContentDigest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerWorkflowEvidence {
    pub request_digest: ContentDigest,
    pub challenger_package_digest: ContentDigest,
    pub receipts: Vec<WorkerReceipt>,
    pub evidence_digest: ContentDigest,
}

impl WorkerWorkflowEvidence {
    pub fn seal(mut self) -> Result<Self, ReproductionError> {
        self.evidence_digest = worker_evidence_digest(&self)?;
        Ok(self)
    }
}

fn worker_evidence_digest(
    evidence: &WorkerWorkflowEvidence,
) -> Result<ContentDigest, ReproductionError> {
    digest_serializable(&(
        "wasm-biotic:worker-workflow-evidence:v1",
        &evidence.request_digest,
        &evidence.challenger_package_digest,
        &evidence.receipts,
    ))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationDriverRequest {
    pub cycle_id: String,
    pub executor_package_digest: ContentDigest,
    pub executor_package_bytes_digest: ContentDigest,
    pub executor_component_digest: ContentDigest,
    pub stable_interface_digest: ContentDigest,
    pub instruction_digest: ContentDigest,
    pub driver_contract: GenerationDriverContract,
    pub gate_digest: ContentDigest,
    pub next_generation: u32,
    pub idempotency_key: String,
    pub request_digest: ContentDigest,
}

impl GenerationDriverRequest {
    fn new(
        cycle_id: &str,
        executor: &FactoryPackage,
        instruction: &GenerationLoopInstruction,
        gate: &ReleaseGate,
        execution_policy: &CycleExecutionPolicy,
    ) -> Result<Self, ReproductionError> {
        instruction.validate()?;
        gate.validate()?;
        if execution_policy.gate_digest != gate.gate_digest
            || execution_policy.budgets != gate.budgets
        {
            return Err(ReproductionError::StateIntegrity(
                "generation driver execution policy differs from the release gate".to_string(),
            ));
        }
        let mut request = Self {
            cycle_id: cycle_id.to_string(),
            executor_package_digest: executor.package_digest.clone(),
            executor_package_bytes_digest: ContentDigest::from_bytes(&executor.canonical_bytes()?),
            executor_component_digest: executor.payload.genome.component_digest.clone(),
            stable_interface_digest: executor.payload.stable_interface.contract_digest()?,
            instruction_digest: instruction.instruction_digest()?,
            driver_contract: instruction.driver_contract.clone(),
            gate_digest: gate.gate_digest.clone(),
            next_generation: executor.payload.generation.checked_add(1).ok_or_else(|| {
                ReproductionError::BudgetExceeded("generation counter overflow".to_string())
            })?,
            idempotency_key: String::new(),
            request_digest: ContentDigest::from_bytes(&[]),
        };
        request.idempotency_key = execution_policy
            .phase_idempotency_key("generation-driver", &request.instruction_digest)?;
        request.request_digest = digest_serializable(&(
            "wasm-biotic:generation-driver-request:v1",
            &request.cycle_id,
            &request.executor_package_digest,
            &request.executor_package_bytes_digest,
            &request.executor_component_digest,
            &request.stable_interface_digest,
            &request.instruction_digest,
            &request.driver_contract,
            &request.gate_digest,
            request.next_generation,
            &request.idempotency_key,
        ))?;
        Ok(request)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationDriverEvidence {
    pub request_digest: ContentDigest,
    pub invocation_id: String,
    pub executor_package_digest: ContentDigest,
    pub executor_package_bytes_digest: ContentDigest,
    pub executor_component_digest: ContentDigest,
    pub instruction_digest: ContentDigest,
    pub trace: ComponentI32ExecutionTrace,
    pub directive: i32,
    pub service_receipt_digest: ContentDigest,
    pub service_attestation_digest: ContentDigest,
    pub evidence_digest: ContentDigest,
}

impl GenerationDriverEvidence {
    pub fn seal(mut self) -> Result<Self, ReproductionError> {
        self.evidence_digest = generation_driver_evidence_digest(&self)?;
        Ok(self)
    }
}

fn generation_driver_evidence_digest(
    evidence: &GenerationDriverEvidence,
) -> Result<ContentDigest, ReproductionError> {
    digest_serializable(&(
        "wasm-biotic:generation-driver-evidence:v1",
        &evidence.request_digest,
        &evidence.invocation_id,
        &evidence.executor_package_digest,
        &evidence.executor_package_bytes_digest,
        &evidence.executor_component_digest,
        &evidence.instruction_digest,
        &evidence.trace,
        evidence.directive,
        &evidence.service_receipt_digest,
        &evidence.service_attestation_digest,
    ))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationMaterializationRequest {
    pub cycle_id: String,
    pub driver_request_digest: ContentDigest,
    pub driver_evidence_digest: ContentDigest,
    pub instruction_digest: ContentDigest,
    pub renderer_profile: GenerationRendererProfile,
    pub directive: i32,
    pub maximum_component_bytes: u64,
    pub idempotency_key: String,
    pub request_digest: ContentDigest,
}

impl GenerationMaterializationRequest {
    fn new(
        request: &GenerationDriverRequest,
        evidence: &GenerationDriverEvidence,
        maximum_component_bytes: u64,
        execution_policy: &CycleExecutionPolicy,
    ) -> Result<Self, ReproductionError> {
        if execution_policy.gate_digest != request.gate_digest
            || execution_policy.budgets.max_component_bytes != maximum_component_bytes
        {
            return Err(ReproductionError::StateIntegrity(
                "generation materialization execution policy differs from the driver or byte budget"
                    .to_string(),
            ));
        }
        let mut materialization = Self {
            cycle_id: request.cycle_id.clone(),
            driver_request_digest: request.request_digest.clone(),
            driver_evidence_digest: evidence.evidence_digest.clone(),
            instruction_digest: request.instruction_digest.clone(),
            renderer_profile: request.driver_contract.renderer_profile,
            directive: evidence.directive,
            maximum_component_bytes,
            idempotency_key: execution_policy
                .phase_idempotency_key("generation-materialization", &evidence.evidence_digest)?,
            request_digest: ContentDigest::from_bytes(&[]),
        };
        materialization.request_digest = digest_serializable(&(
            "wasm-biotic:generation-materialization-request:v1",
            &materialization.cycle_id,
            &materialization.driver_request_digest,
            &materialization.driver_evidence_digest,
            &materialization.instruction_digest,
            materialization.renderer_profile,
            materialization.directive,
            materialization.maximum_component_bytes,
            &materialization.idempotency_key,
        ))?;
        Ok(materialization)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationMaterializationEvidence {
    pub request_digest: ContentDigest,
    pub driver_evidence_digest: ContentDigest,
    pub rendered_wat_bytes: Vec<u8>,
    pub rendered_wat_digest: ContentDigest,
    pub successor_component_bytes: Vec<u8>,
    pub successor_component_digest: ContentDigest,
    pub workflow_id: String,
    pub worker_receipts: Vec<WorkerReceipt>,
    pub workflow_evidence_digest: ContentDigest,
    pub evidence_digest: ContentDigest,
}

impl GenerationMaterializationEvidence {
    pub fn seal(mut self) -> Result<Self, ReproductionError> {
        self.evidence_digest = generation_materialization_evidence_digest(&self)?;
        Ok(self)
    }
}

fn generation_materialization_evidence_digest(
    evidence: &GenerationMaterializationEvidence,
) -> Result<ContentDigest, ReproductionError> {
    digest_serializable(&(
        "wasm-biotic:generation-materialization-evidence:v1",
        &evidence.request_digest,
        &evidence.driver_evidence_digest,
        &evidence.rendered_wat_digest,
        &evidence.successor_component_digest,
        &evidence.workflow_id,
        &evidence.worker_receipts,
        &evidence.workflow_evidence_digest,
    ))
}

pub trait M4WorkerPort: Send + Sync {
    /// Executes the six-role governed workflow and returns durable receipts.
    fn execute_workflow(
        &self,
        request: &WorkerWorkflowRequest,
    ) -> Result<WorkerWorkflowEvidence, PortFailure>;

    /// Materializes the bounded directive returned by the active package. The
    /// engine independently rerenders and recompiles the returned successor.
    fn materialize_generation(
        &self,
        request: &GenerationMaterializationRequest,
    ) -> Result<GenerationMaterializationEvidence, PortFailure>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionTerminal {
    Succeeded,
    Failed,
    TimedOut,
    Trapped,
    Cancelled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskExecutionObservation {
    pub execution_id: String,
    pub benchmark_id: String,
    pub package_digest: ContentDigest,
    pub request_digest: ContentDigest,
    pub output_digest: Option<ContentDigest>,
    pub terminal: ExecutionTerminal,
    pub health: HealthStatus,
    pub duration_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvariantObservation {
    pub invariant_id: String,
    pub package_digest: ContentDigest,
    pub satisfied: bool,
    pub evidence_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceUsage {
    pub shadow_tasks: u32,
    pub component_bytes: u64,
    pub state_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowExecutionRequest {
    pub cycle_id: String,
    pub incumbent_package_digest: ContentDigest,
    pub incumbent_package_bytes: Vec<u8>,
    pub challenger_package_digest: ContentDigest,
    pub challenger_package_bytes: Vec<u8>,
    pub gate: ReleaseGate,
    pub request_digest: ContentDigest,
}

impl ShadowExecutionRequest {
    fn new(
        cycle_id: &str,
        incumbent: &FactoryPackage,
        challenger: &FactoryPackage,
        gate: &ReleaseGate,
    ) -> Result<Self, ReproductionError> {
        let mut request = Self {
            cycle_id: cycle_id.to_string(),
            incumbent_package_digest: incumbent.package_digest.clone(),
            incumbent_package_bytes: incumbent.canonical_bytes()?,
            challenger_package_digest: challenger.package_digest.clone(),
            challenger_package_bytes: challenger.canonical_bytes()?,
            gate: gate.clone(),
            request_digest: ContentDigest::from_bytes(&[]),
        };
        request.request_digest = digest_serializable(&(
            "wasm-biotic:shadow-execution-request:v1",
            &request.cycle_id,
            &request.incumbent_package_digest,
            &request.incumbent_package_bytes,
            &request.challenger_package_digest,
            &request.challenger_package_bytes,
            &request.gate.gate_digest,
        ))?;
        Ok(request)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowExecutionEvidence {
    pub request_digest: ContentDigest,
    pub incumbent_observations: Vec<TaskExecutionObservation>,
    pub challenger_observations: Vec<TaskExecutionObservation>,
    pub invariant_observations: Vec<InvariantObservation>,
    pub resource_usage: ResourceUsage,
    pub evidence_digest: ContentDigest,
}

impl ShadowExecutionEvidence {
    pub fn seal(mut self) -> Result<Self, ReproductionError> {
        self.evidence_digest = shadow_evidence_digest(&self)?;
        Ok(self)
    }
}

fn shadow_evidence_digest(
    evidence: &ShadowExecutionEvidence,
) -> Result<ContentDigest, ReproductionError> {
    digest_serializable(&(
        "wasm-biotic:shadow-execution-evidence:v1",
        &evidence.request_digest,
        &evidence.incumbent_observations,
        &evidence.challenger_observations,
        &evidence.invariant_observations,
        &evidence.resource_usage,
    ))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateDecision {
    pub gate_digest: ContentDigest,
    pub shadow_evidence_digest: ContentDigest,
    pub passed_benchmarks: u32,
    pub success_basis_points: u16,
    pub regressions: u32,
    pub required_invariants_satisfied: bool,
    pub within_budgets: bool,
    pub eligible: bool,
    pub decision_digest: ContentDigest,
}

fn gate_decision_digest(decision: &GateDecision) -> Result<ContentDigest, ReproductionError> {
    digest_serializable(&(
        "wasm-biotic:gate-decision:v1",
        &decision.gate_digest,
        &decision.shadow_evidence_digest,
        decision.passed_benchmarks,
        decision.success_basis_points,
        decision.regressions,
        decision.required_invariants_satisfied,
        decision.within_budgets,
        decision.eligible,
    ))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorApprovalRequest {
    pub cycle_id: String,
    pub incumbent_package_digest: ContentDigest,
    pub challenger_package_digest: ContentDigest,
    pub challenger_package_bytes_digest: ContentDigest,
    pub gate_digest: ContentDigest,
    pub gate_decision_digest: ContentDigest,
    pub m1_evidence_digest: ContentDigest,
    pub worker_evidence_digest: ContentDigest,
    pub shadow_evidence_digest: ContentDigest,
    pub migration_plan_digest: Option<ContentDigest>,
    pub operator_context_digest: ContentDigest,
    pub request_digest: ContentDigest,
}

impl SupervisorApprovalRequest {
    #[allow(clippy::too_many_arguments)]
    fn new(
        cycle_id: &str,
        incumbent: &ContentDigest,
        challenger: &FactoryPackage,
        gate: &ReleaseGate,
        decision: &GateDecision,
        m1: &M1BuildEvidence,
        workers: &WorkerWorkflowEvidence,
        shadow: &ShadowExecutionEvidence,
        migration_plan_digest: Option<ContentDigest>,
        operator_context_digest: ContentDigest,
    ) -> Result<Self, ReproductionError> {
        let mut request = Self {
            cycle_id: cycle_id.to_string(),
            incumbent_package_digest: incumbent.clone(),
            challenger_package_digest: challenger.package_digest.clone(),
            challenger_package_bytes_digest: ContentDigest::from_bytes(
                &challenger.canonical_bytes()?,
            ),
            gate_digest: gate.gate_digest.clone(),
            gate_decision_digest: decision.decision_digest.clone(),
            m1_evidence_digest: m1.evidence_digest.clone(),
            worker_evidence_digest: workers.evidence_digest.clone(),
            shadow_evidence_digest: shadow.evidence_digest.clone(),
            migration_plan_digest,
            operator_context_digest,
            request_digest: ContentDigest::from_bytes(&[]),
        };
        request.request_digest = digest_serializable(&(
            "wasm-biotic:supervisor-approval-request:v1",
            &request.cycle_id,
            &request.incumbent_package_digest,
            &request.challenger_package_digest,
            &request.challenger_package_bytes_digest,
            &request.gate_digest,
            &request.gate_decision_digest,
            &request.m1_evidence_digest,
            &request.worker_evidence_digest,
            &request.shadow_evidence_digest,
            &request.migration_plan_digest,
            &request.operator_context_digest,
        ))?;
        Ok(request)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    Approved,
    Rejected,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorApprovalRecord {
    pub approval_id: String,
    pub request_digest: ContentDigest,
    pub decision: ApprovalDecision,
    pub approved_package_digest: Option<ContentDigest>,
    pub approved_package_bytes_digest: Option<ContentDigest>,
    pub gate_decision_digest: ContentDigest,
    pub evidence_digests: Vec<ContentDigest>,
    pub approver_ref: String,
    pub rationale: String,
    pub approval_digest: ContentDigest,
}

impl SupervisorApprovalRecord {
    pub fn seal(mut self) -> Result<Self, ReproductionError> {
        self.approval_digest = supervisor_approval_digest(&self)?;
        Ok(self)
    }
}

fn supervisor_approval_digest(
    approval: &SupervisorApprovalRecord,
) -> Result<ContentDigest, ReproductionError> {
    digest_serializable(&(
        "wasm-biotic:supervisor-approval-record:v1",
        &approval.approval_id,
        &approval.request_digest,
        approval.decision,
        &approval.approved_package_digest,
        &approval.approved_package_bytes_digest,
        &approval.gate_decision_digest,
        &approval.evidence_digests,
        &approval.approver_ref,
        &approval.rationale,
    ))
}

pub trait M2SupervisorPort: Send + Sync {
    /// The supervisor may approve only the exact request and evidence bundle.
    fn decide(
        &self,
        request: &SupervisorApprovalRequest,
    ) -> Result<SupervisorApprovalRecord, PortFailure>;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateMigrationPlan {
    pub migration_id: String,
    pub from_schema: u32,
    pub to_schema: u32,
    pub rollback_schema: u32,
    pub migration_program_digest: ContentDigest,
    pub maximum_state_bytes: u64,
    pub plan_digest: ContentDigest,
}

impl StateMigrationPlan {
    pub fn new(
        migration_id: impl Into<String>,
        from_schema: u32,
        to_schema: u32,
        rollback_schema: u32,
        migration_program_digest: ContentDigest,
        maximum_state_bytes: u64,
    ) -> Result<Self, ReproductionError> {
        let mut plan = Self {
            migration_id: migration_id.into(),
            from_schema,
            to_schema,
            rollback_schema,
            migration_program_digest,
            maximum_state_bytes,
            plan_digest: ContentDigest::from_bytes(&[]),
        };
        plan.validate_fields()?;
        plan.plan_digest = plan.expected_digest()?;
        Ok(plan)
    }

    pub fn validate(&self) -> Result<(), ReproductionError> {
        self.validate_fields()?;
        require_digest(
            "state migration plan",
            &self.plan_digest,
            &self.expected_digest()?,
        )
    }

    fn validate_fields(&self) -> Result<(), ReproductionError> {
        validate_identifier("migration id", &self.migration_id)?;
        if self.from_schema == 0
            || self.to_schema == 0
            || self.rollback_schema == 0
            || self.maximum_state_bytes == 0
        {
            return Err(ReproductionError::InvalidConfiguration(
                "migration schema numbers and state budget must be nonzero".to_string(),
            ));
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, ReproductionError> {
        digest_serializable(&(
            "wasm-biotic:state-migration-plan:v1",
            &self.migration_id,
            self.from_schema,
            self.to_schema,
            self.rollback_schema,
            &self.migration_program_digest,
            self.maximum_state_bytes,
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationRequest {
    pub cycle_id: String,
    pub incumbent_package_digest: ContentDigest,
    pub challenger_package_digest: ContentDigest,
    pub plan: StateMigrationPlan,
    pub request_digest: ContentDigest,
}

impl MigrationRequest {
    fn new(
        cycle_id: &str,
        incumbent: &ContentDigest,
        challenger: &ContentDigest,
        plan: &StateMigrationPlan,
    ) -> Result<Self, ReproductionError> {
        let mut request = Self {
            cycle_id: cycle_id.to_string(),
            incumbent_package_digest: incumbent.clone(),
            challenger_package_digest: challenger.clone(),
            plan: plan.clone(),
            request_digest: ContentDigest::from_bytes(&[]),
        };
        request.request_digest = digest_serializable(&(
            "wasm-biotic:migration-request:v1",
            &request.cycle_id,
            &request.incumbent_package_digest,
            &request.challenger_package_digest,
            &request.plan.plan_digest,
        ))?;
        Ok(request)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationReceipt {
    pub request_digest: ContentDigest,
    pub migration_id: String,
    pub from_schema: u32,
    pub to_schema: u32,
    pub pre_migration_state_digest: ContentDigest,
    pub post_migration_state_digest: ContentDigest,
    pub rollback_backup_digest: ContentDigest,
    pub rollback_verified: bool,
    pub receipt_digest: ContentDigest,
}

impl MigrationReceipt {
    pub fn seal(mut self) -> Result<Self, ReproductionError> {
        self.receipt_digest = migration_receipt_digest(&self)?;
        Ok(self)
    }
}

fn migration_receipt_digest(
    receipt: &MigrationReceipt,
) -> Result<ContentDigest, ReproductionError> {
    digest_serializable(&(
        "wasm-biotic:migration-receipt:v1",
        &receipt.request_digest,
        &receipt.migration_id,
        receipt.from_schema,
        receipt.to_schema,
        &receipt.pre_migration_state_digest,
        &receipt.post_migration_state_digest,
        &receipt.rollback_backup_digest,
        receipt.rollback_verified,
    ))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationRequest {
    pub cycle_id: String,
    pub incumbent_package_digest: ContentDigest,
    pub challenger_package_digest: ContentDigest,
    pub challenger_package_bytes: Vec<u8>,
    pub approval_digest: ContentDigest,
    pub gate_decision_digest: ContentDigest,
    pub target_state_schema: u32,
    pub request_digest: ContentDigest,
}

impl ActivationRequest {
    fn new(
        cycle_id: &str,
        incumbent: &ContentDigest,
        challenger: &FactoryPackage,
        approval: &SupervisorApprovalRecord,
        decision: &GateDecision,
        target_state_schema: u32,
    ) -> Result<Self, ReproductionError> {
        let mut request = Self {
            cycle_id: cycle_id.to_string(),
            incumbent_package_digest: incumbent.clone(),
            challenger_package_digest: challenger.package_digest.clone(),
            challenger_package_bytes: challenger.canonical_bytes()?,
            approval_digest: approval.approval_digest.clone(),
            gate_decision_digest: decision.decision_digest.clone(),
            target_state_schema,
            request_digest: ContentDigest::from_bytes(&[]),
        };
        request.request_digest = digest_serializable(&(
            "wasm-biotic:activation-request:v1",
            &request.cycle_id,
            &request.incumbent_package_digest,
            &request.challenger_package_digest,
            &request.challenger_package_bytes,
            &request.approval_digest,
            &request.gate_decision_digest,
            request.target_state_schema,
        ))?;
        Ok(request)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationReceipt {
    pub activation_id: String,
    pub request_digest: ContentDigest,
    pub previous_package_digest: ContentDigest,
    pub active_package_digest: ContentDigest,
    pub active_package_bytes_digest: ContentDigest,
    pub active_state_schema: u32,
    pub receipt_digest: ContentDigest,
}

impl ActivationReceipt {
    pub fn seal(mut self) -> Result<Self, ReproductionError> {
        self.receipt_digest = activation_receipt_digest(&self)?;
        Ok(self)
    }
}

fn activation_receipt_digest(
    receipt: &ActivationReceipt,
) -> Result<ContentDigest, ReproductionError> {
    digest_serializable(&(
        "wasm-biotic:activation-receipt:v1",
        &receipt.activation_id,
        &receipt.request_digest,
        &receipt.previous_package_digest,
        &receipt.active_package_digest,
        &receipt.active_package_bytes_digest,
        receipt.active_state_schema,
    ))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostActivationRequest {
    pub cycle_id: String,
    pub activation_id: String,
    pub active_package_digest: ContentDigest,
    pub active_package_bytes_digest: ContentDigest,
    pub minimum_successes: u32,
    pub request_digest: ContentDigest,
}

impl PostActivationRequest {
    fn new(
        cycle_id: &str,
        activation: &ActivationReceipt,
        minimum_successes: u32,
    ) -> Result<Self, ReproductionError> {
        let mut request = Self {
            cycle_id: cycle_id.to_string(),
            activation_id: activation.activation_id.clone(),
            active_package_digest: activation.active_package_digest.clone(),
            active_package_bytes_digest: activation.active_package_bytes_digest.clone(),
            minimum_successes,
            request_digest: ContentDigest::from_bytes(&[]),
        };
        request.request_digest = digest_serializable(&(
            "wasm-biotic:post-activation-request:v1",
            &request.cycle_id,
            &request.activation_id,
            &request.active_package_digest,
            &request.active_package_bytes_digest,
            request.minimum_successes,
        ))?;
        Ok(request)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthObservation {
    pub check_id: String,
    pub active_package_digest: ContentDigest,
    pub status: HealthStatus,
    pub measurement_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostActivationEvidence {
    pub request_digest: ContentDigest,
    pub active_package_digest: ContentDigest,
    pub task_observations: Vec<TaskExecutionObservation>,
    pub health_observations: Vec<HealthObservation>,
    pub evidence_digest: ContentDigest,
}

impl PostActivationEvidence {
    pub fn seal(mut self) -> Result<Self, ReproductionError> {
        self.evidence_digest = post_activation_evidence_digest(&self)?;
        Ok(self)
    }
}

fn post_activation_evidence_digest(
    evidence: &PostActivationEvidence,
) -> Result<ContentDigest, ReproductionError> {
    digest_serializable(&(
        "wasm-biotic:post-activation-evidence:v1",
        &evidence.request_digest,
        &evidence.active_package_digest,
        &evidence.task_observations,
        &evidence.health_observations,
    ))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRequest {
    pub recovery_id: String,
    pub cycle_id: String,
    pub restore_package_digest: ContentDigest,
    pub restore_package_bytes: Vec<u8>,
    pub restore_state_schema: u32,
    pub interrupted_stage: PendingStage,
    pub migration_receipt: Option<MigrationReceipt>,
    pub activation_receipt: Option<ActivationReceipt>,
    pub reason: String,
    pub request_digest: ContentDigest,
}

impl RecoveryRequest {
    fn from_pending(
        pending: &PendingEffect,
        incumbent_bytes: Vec<u8>,
        reason: impl Into<String>,
    ) -> Result<Self, ReproductionError> {
        let reason = reason.into();
        let mut request = Self {
            recovery_id: format!("recovery:{}", pending.cycle_id),
            cycle_id: pending.cycle_id.clone(),
            restore_package_digest: pending.incumbent_package_digest.clone(),
            restore_package_bytes: incumbent_bytes,
            restore_state_schema: pending.incumbent_state_schema,
            interrupted_stage: pending.stage,
            migration_receipt: pending.migration_receipt.clone(),
            activation_receipt: pending.activation_receipt.clone(),
            reason,
            request_digest: ContentDigest::from_bytes(&[]),
        };
        request.request_digest = digest_serializable(&(
            "wasm-biotic:recovery-request:v1",
            &request.recovery_id,
            &request.cycle_id,
            &request.restore_package_digest,
            &request.restore_package_bytes,
            request.restore_state_schema,
            request.interrupted_stage,
            &request.migration_receipt,
            &request.activation_receipt,
            &request.reason,
        ))?;
        Ok(request)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryReceipt {
    pub recovery_id: String,
    pub request_digest: ContentDigest,
    pub restored_package_digest: ContentDigest,
    pub restored_package_bytes_digest: ContentDigest,
    pub restored_state_schema: u32,
    pub state_readable: bool,
    pub receipt_digest: ContentDigest,
}

impl RecoveryReceipt {
    pub fn seal(mut self) -> Result<Self, ReproductionError> {
        self.receipt_digest = recovery_receipt_digest(&self)?;
        Ok(self)
    }
}

fn recovery_receipt_digest(receipt: &RecoveryReceipt) -> Result<ContentDigest, ReproductionError> {
    digest_serializable(&(
        "wasm-biotic:recovery-receipt:v1",
        &receipt.recovery_id,
        &receipt.request_digest,
        &receipt.restored_package_digest,
        &receipt.restored_package_bytes_digest,
        receipt.restored_state_schema,
        receipt.state_readable,
    ))
}

pub trait M3CapabilityPort: Send + Sync {
    /// Executes the frozen generation-driver export through the exact active
    /// deployment route and returns the complete bounded Wasmtime trace.
    fn execute_generation_driver(
        &self,
        request: &GenerationDriverRequest,
    ) -> Result<GenerationDriverEvidence, PortFailure>;

    /// Executes incumbent and challenger against the predeclared gate inputs.
    fn run_shadow(
        &self,
        request: &ShadowExecutionRequest,
    ) -> Result<ShadowExecutionEvidence, PortFailure>;

    /// Applies a bounded, rollback-tested state migration.
    fn migrate_state(&self, request: &MigrationRequest) -> Result<MigrationReceipt, PortFailure>;

    /// Atomically routes work to the exact supplied package bytes.
    fn activate_exact(&self, request: &ActivationRequest)
    -> Result<ActivationReceipt, PortFailure>;

    /// Runs actual post-activation tasks and health checks.
    fn observe_active(
        &self,
        request: &PostActivationRequest,
    ) -> Result<PostActivationEvidence, PortFailure>;

    /// Idempotently restores the retained incumbent package and state.
    fn recover_to_incumbent(
        &self,
        request: &RecoveryRequest,
    ) -> Result<RecoveryReceipt, PortFailure>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum M5ProviderEndpointClassV1 {
    ExternalHttps,
    LoopbackTest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfiguration {
    pub provider_id: String,
    pub model_id: String,
    pub provider_profile: M5ProviderProfileV1,
    pub api_base_url: String,
    pub endpoint_class: M5ProviderEndpointClassV1,
    pub driver_profile_digest: ContentDigest,
    pub generation_policy_id: String,
    pub generation_policy_digest: ContentDigest,
    pub maximum_retries: u32,
    pub maximum_output_tokens: u32,
    pub input_cost_per_million_microunits: u64,
    pub output_cost_per_million_microunits: u64,
    pub cost_currency: String,
    pub parser_digest: ContentDigest,
    pub response_schema_digest: ContentDigest,
    pub prompt_renderer_digest: ContentDigest,
    pub tool_catalog_digest: ContentDigest,
}

impl ProviderConfiguration {
    pub fn fingerprint(&self) -> Result<ContentDigest, ReproductionError> {
        validate_identifier("provider id", &self.provider_id)?;
        validate_identifier("model id", &self.model_id)?;
        validate_identifier("generation policy id", &self.generation_policy_id)?;
        if self.maximum_retries > MAX_M5_PROVIDER_RETRIES {
            return Err(ReproductionError::InvalidConfiguration(format!(
                "provider configuration maximum retries exceeds {MAX_M5_PROVIDER_RETRIES}"
            )));
        }
        if self.maximum_output_tokens == 0
            || self.maximum_output_tokens > MAX_M5_PROVIDER_OUTPUT_TOKENS
        {
            return Err(ReproductionError::InvalidConfiguration(format!(
                "provider configuration maximum output tokens must be within 1..={MAX_M5_PROVIDER_OUTPUT_TOKENS}"
            )));
        }
        let (normalized_api_base_url, loopback) =
            normalize_safe_provider_api_base_url(&self.api_base_url).map_err(|error| {
                ReproductionError::InvalidConfiguration(format!(
                    "provider API base URL is invalid: {error}"
                ))
            })?;
        let expected_endpoint_class = if loopback {
            M5ProviderEndpointClassV1::LoopbackTest
        } else {
            M5ProviderEndpointClassV1::ExternalHttps
        };
        if normalized_api_base_url != self.api_base_url
            || self.endpoint_class != expected_endpoint_class
        {
            return Err(ReproductionError::InvalidConfiguration(
                "provider API base URL or endpoint class is not the exact normalized safe endpoint"
                    .to_string(),
            ));
        }
        if self.cost_currency.is_empty()
            || self.cost_currency.len() > 16
            || !self
                .cost_currency
                .bytes()
                .all(|byte| byte.is_ascii_lowercase())
        {
            return Err(ReproductionError::InvalidConfiguration(
                "provider configuration cost currency must contain 1..=16 lowercase ASCII letters"
                    .to_string(),
            ));
        }
        digest_serializable(&(
            "wasm-biotic:provider-configuration:v3",
            (
                &self.provider_id,
                &self.model_id,
                self.provider_profile,
                &self.api_base_url,
                self.endpoint_class,
                &self.driver_profile_digest,
            ),
            (
                &self.generation_policy_id,
                &self.generation_policy_digest,
                self.maximum_retries,
                self.maximum_output_tokens,
            ),
            (
                self.input_cost_per_million_microunits,
                self.output_cost_per_million_microunits,
                &self.cost_currency,
            ),
            (
                &self.parser_digest,
                &self.response_schema_digest,
                &self.prompt_renderer_digest,
                &self.tool_catalog_digest,
            ),
        ))
    }
}

/// Immutable application-level replay material for one exact provider turn.
///
/// The capsule stores bytes, not only version labels, so offline replay never
/// silently consults a newer prompt, catalog, tool schema, or response schema.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderReplayCapsule {
    pub schema: String,
    pub configuration_fingerprint: ContentDigest,
    pub rendered_prompt_bytes: Vec<u8>,
    pub filtered_tool_catalog_bytes: Vec<u8>,
    pub selected_tool_definition_bytes: Vec<u8>,
    pub selected_argument_schema_bytes: Vec<u8>,
    pub response_schema_bytes: Vec<u8>,
    pub capsule_digest: ContentDigest,
}

impl ProviderReplayCapsule {
    pub fn new(
        configuration: &ProviderConfiguration,
        rendered_prompt_bytes: Vec<u8>,
        filtered_tool_catalog_bytes: Vec<u8>,
        selected_tool_definition_bytes: Vec<u8>,
        selected_argument_schema_bytes: Vec<u8>,
        response_schema_bytes: Vec<u8>,
    ) -> Result<Self, ReproductionError> {
        let mut capsule = Self {
            schema: PROVIDER_REPLAY_CAPSULE_SCHEMA.to_string(),
            configuration_fingerprint: configuration.fingerprint()?,
            rendered_prompt_bytes,
            filtered_tool_catalog_bytes,
            selected_tool_definition_bytes,
            selected_argument_schema_bytes,
            response_schema_bytes,
            capsule_digest: ContentDigest::from_bytes(&[]),
        };
        capsule.validate_fields(configuration)?;
        capsule.capsule_digest = capsule.expected_digest()?;
        Ok(capsule)
    }

    pub fn validate(&self, configuration: &ProviderConfiguration) -> Result<(), ReproductionError> {
        self.validate_fields(configuration)?;
        require_digest(
            "provider replay capsule",
            &self.capsule_digest,
            &self.expected_digest()?,
        )
    }

    fn validate_fields(
        &self,
        configuration: &ProviderConfiguration,
    ) -> Result<(), ReproductionError> {
        if self.schema != PROVIDER_REPLAY_CAPSULE_SCHEMA {
            return Err(ReproductionError::ProviderQualification(
                "unsupported provider replay capsule schema".to_string(),
            ));
        }
        require_digest(
            "provider replay capsule configuration",
            &self.configuration_fingerprint,
            &configuration.fingerprint()?,
        )?;
        let total_bytes = self
            .rendered_prompt_bytes
            .len()
            .saturating_add(self.filtered_tool_catalog_bytes.len())
            .saturating_add(self.selected_tool_definition_bytes.len())
            .saturating_add(self.selected_argument_schema_bytes.len())
            .saturating_add(self.response_schema_bytes.len());
        if self.rendered_prompt_bytes.is_empty() || total_bytes > MAX_PROVIDER_CAPSULE_BYTES {
            return Err(ReproductionError::ProviderQualification(
                "provider replay capsule is empty or outside its byte bound".to_string(),
            ));
        }
        require_digest(
            "frozen provider tool catalog",
            &ContentDigest::from_bytes(&self.filtered_tool_catalog_bytes),
            &configuration.tool_catalog_digest,
        )?;
        require_digest(
            "frozen provider response schema",
            &ContentDigest::from_bytes(&self.response_schema_bytes),
            &configuration.response_schema_digest,
        )?;
        let catalog: serde_json::Value = serde_json::from_slice(&self.filtered_tool_catalog_bytes)
            .map_err(|error| {
                ReproductionError::ProviderQualification(format!(
                    "frozen provider tool catalog is invalid JSON: {error}"
                ))
            })?;
        let definitions = catalog.as_array().ok_or_else(|| {
            ReproductionError::ProviderQualification(
                "frozen provider tool catalog is not an array".to_string(),
            )
        })?;
        if definitions.len() != 1 {
            return Err(ReproductionError::ProviderQualification(
                "provider replay capsule must expose exactly one proposal tool".to_string(),
            ));
        }
        let selected: serde_json::Value =
            serde_json::from_slice(&self.selected_tool_definition_bytes).map_err(|error| {
                ReproductionError::ProviderQualification(format!(
                    "selected provider tool definition is invalid JSON: {error}"
                ))
            })?;
        let arguments: serde_json::Value =
            serde_json::from_slice(&self.selected_argument_schema_bytes).map_err(|error| {
                ReproductionError::ProviderQualification(format!(
                    "selected provider argument schema is invalid JSON: {error}"
                ))
            })?;
        let _: serde_json::Value =
            serde_json::from_slice(&self.response_schema_bytes).map_err(|error| {
                ReproductionError::ProviderQualification(format!(
                    "frozen provider response schema is invalid JSON: {error}"
                ))
            })?;
        if definitions.first() != Some(&selected)
            || selected.get("type").and_then(serde_json::Value::as_str) != Some("function")
            || selected.get("name").and_then(serde_json::Value::as_str)
                != Some("candidate.materialize_patchset")
            || selected.get("parameters") != Some(&arguments)
            || !is_exact_provider_argument_schema(&arguments)
        {
            return Err(ReproductionError::ProviderQualification(
                "selected proposal tool or argument schema differs from the frozen one-tool catalog"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn expected_digest(&self) -> Result<ContentDigest, ReproductionError> {
        digest_serializable(&(
            PROVIDER_REPLAY_CAPSULE_SCHEMA,
            &self.configuration_fingerprint,
            &self.rendered_prompt_bytes,
            &self.filtered_tool_catalog_bytes,
            &self.selected_tool_definition_bytes,
            &self.selected_argument_schema_bytes,
            &self.response_schema_bytes,
        ))
    }
}

fn is_exact_provider_argument_schema(arguments: &serde_json::Value) -> bool {
    let required = arguments
        .get("required")
        .and_then(serde_json::Value::as_array);
    let properties = arguments
        .get("properties")
        .and_then(serde_json::Value::as_object);
    let expected = BTreeSet::from([
        "challenger_wat_digest",
        "cycle_id",
        "invocation_challenge_digest",
        "policy_digest",
    ]);
    arguments.get("type").and_then(serde_json::Value::as_str) == Some("object")
        && arguments
            .get("additionalProperties")
            .and_then(serde_json::Value::as_bool)
            == Some(false)
        && required.is_some_and(|items| {
            items.len() == expected.len()
                && items
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .collect::<BTreeSet<_>>()
                    == expected
        })
        && properties.is_some_and(|items| {
            items.len() == expected.len()
                && items.keys().map(String::as_str).collect::<BTreeSet<_>>() == expected
        })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderQualificationRequest {
    pub qualification_id: String,
    pub package_digest: ContentDigest,
    pub target_digest: ContentDigest,
    pub configuration: ProviderConfiguration,
    pub prompt_bytes: Vec<u8>,
    pub replay_capsule: ProviderReplayCapsule,
    pub invocation_challenge_digest: Option<ContentDigest>,
    pub request_digest: ContentDigest,
}

impl ProviderQualificationRequest {
    pub fn new(
        qualification_id: impl Into<String>,
        package_digest: ContentDigest,
        target_digest: ContentDigest,
        configuration: ProviderConfiguration,
        prompt_bytes: Vec<u8>,
        replay_capsule: ProviderReplayCapsule,
    ) -> Result<Self, ReproductionError> {
        Self::new_with_invocation_challenge(
            qualification_id,
            package_digest,
            target_digest,
            configuration,
            prompt_bytes,
            replay_capsule,
            None,
        )
    }

    pub(crate) fn new_challenged(
        qualification_id: impl Into<String>,
        package_digest: ContentDigest,
        target_digest: ContentDigest,
        configuration: ProviderConfiguration,
        prompt_bytes: Vec<u8>,
        replay_capsule: ProviderReplayCapsule,
        invocation_challenge_digest: ContentDigest,
    ) -> Result<Self, ReproductionError> {
        Self::new_with_invocation_challenge(
            qualification_id,
            package_digest,
            target_digest,
            configuration,
            prompt_bytes,
            replay_capsule,
            Some(invocation_challenge_digest),
        )
    }

    fn new_with_invocation_challenge(
        qualification_id: impl Into<String>,
        package_digest: ContentDigest,
        target_digest: ContentDigest,
        configuration: ProviderConfiguration,
        prompt_bytes: Vec<u8>,
        replay_capsule: ProviderReplayCapsule,
        invocation_challenge_digest: Option<ContentDigest>,
    ) -> Result<Self, ReproductionError> {
        let mut request = Self {
            qualification_id: qualification_id.into(),
            package_digest,
            target_digest,
            configuration,
            prompt_bytes,
            replay_capsule,
            invocation_challenge_digest,
            request_digest: ContentDigest::from_bytes(&[]),
        };
        validate_identifier("qualification id", &request.qualification_id)?;
        if request.prompt_bytes.is_empty() || request.prompt_bytes.len() > MAX_TEXT_BYTES {
            return Err(ReproductionError::InvalidConfiguration(format!(
                "provider prompt must contain 1..={MAX_TEXT_BYTES} bytes"
            )));
        }
        request.replay_capsule.validate(&request.configuration)?;
        if request.prompt_bytes != request.replay_capsule.rendered_prompt_bytes {
            return Err(ReproductionError::ProviderQualification(
                "qualification prompt differs from the frozen replay capsule".to_string(),
            ));
        }
        let configuration_digest = request.configuration.fingerprint()?;
        request.request_digest = digest_serializable(&(
            "wasm-biotic:provider-qualification-request:v4",
            &request.qualification_id,
            &request.package_digest,
            &request.target_digest,
            &configuration_digest,
            &request.prompt_bytes,
            &request.replay_capsule.capsule_digest,
            &request.invocation_challenge_digest,
        ))?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), ReproductionError> {
        validate_identifier("qualification id", &self.qualification_id)?;
        if self.prompt_bytes.is_empty() || self.prompt_bytes.len() > MAX_TEXT_BYTES {
            return Err(ReproductionError::InvalidConfiguration(format!(
                "provider prompt must contain 1..={MAX_TEXT_BYTES} bytes"
            )));
        }
        self.replay_capsule.validate(&self.configuration)?;
        if self.prompt_bytes != self.replay_capsule.rendered_prompt_bytes {
            return Err(ReproductionError::ProviderQualification(
                "qualification prompt differs from the frozen replay capsule".to_string(),
            ));
        }
        require_digest(
            "provider qualification request",
            &self.request_digest,
            &digest_serializable(&(
                "wasm-biotic:provider-qualification-request:v4",
                &self.qualification_id,
                &self.package_digest,
                &self.target_digest,
                &self.configuration.fingerprint()?,
                &self.prompt_bytes,
                &self.replay_capsule.capsule_digest,
                &self.invocation_challenge_digest,
            ))?,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderTransport {
    LiveProviderApi,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactedTranscript {
    pub request_digest: ContentDigest,
    pub redacted_prompt: String,
    pub redacted_response: String,
    pub raw_prompt_digest: ContentDigest,
    pub raw_response_digest: ContentDigest,
    pub redaction_applied: bool,
}

impl RedactedTranscript {
    fn validate(&self, request: &ProviderQualificationRequest) -> Result<(), ReproductionError> {
        require_digest(
            "provider transcript request",
            &self.request_digest,
            &request.request_digest,
        )?;
        require_digest(
            "provider raw prompt",
            &self.raw_prompt_digest,
            &ContentDigest::from_bytes(&request.prompt_bytes),
        )?;
        if !self.redaction_applied
            || self.redacted_prompt.trim().is_empty()
            || self.redacted_response.trim().is_empty()
        {
            return Err(ReproductionError::ProviderQualification(
                "provider transcript is absent or was not redacted".to_string(),
            ));
        }
        let byte_len = self.redacted_prompt.len() + self.redacted_response.len();
        if byte_len > MAX_PROVIDER_TRANSCRIPT_BYTES {
            return Err(ReproductionError::ProviderQualification(
                "redacted transcript exceeds its byte budget".to_string(),
            ));
        }
        if contains_obvious_secret(&self.redacted_prompt)
            || contains_obvious_secret(&self.redacted_response)
        {
            return Err(ReproductionError::ProviderQualification(
                "redacted transcript contains an obvious credential-shaped token".to_string(),
            ));
        }
        Ok(())
    }

    pub fn transcript_digest(&self) -> Result<ContentDigest, ReproductionError> {
        digest_serializable(&("wasm-biotic:redacted-provider-transcript:v1", self))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParsedProviderIntent {
    pub intent_schema: String,
    pub operation: String,
    pub target_genome_digest: ContentDigest,
    pub arguments: BTreeMap<String, String>,
}

impl ParsedProviderIntent {
    pub fn intent_digest(&self) -> Result<ContentDigest, ReproductionError> {
        validate_identifier("provider intent schema", &self.intent_schema)?;
        validate_identifier("provider intent operation", &self.operation)?;
        if self.arguments.len() > 64
            || self
                .arguments
                .iter()
                .any(|(key, value)| key.trim().is_empty() || value.len() > MAX_TEXT_BYTES)
        {
            return Err(ReproductionError::ProviderQualification(
                "parsed provider intent arguments are outside bounds".to_string(),
            ));
        }
        digest_serializable(&("wasm-biotic:parsed-provider-intent:v2", self))
    }
}

/// The exact live HTTP adapter profile used for one qualified provider turn.
///
/// Fixture and disabled modes are deliberately absent: M5 qualification is a
/// separate proof that a real provider boundary was crossed, not a substitute
/// for the deterministic release gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum M5ProviderProfileV1 {
    OpenAiResponses,
    OpenRouterChatCompletions,
}

/// Redacted, bounded facts for one HTTP or transport attempt.
///
/// Only content digests are retained for request and response bodies. Provider
/// request ids, response ids, transport summaries, URLs, and credentials stay
/// outside the durable factory state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M5ProviderAttemptSummaryV1 {
    pub attempt_number: u32,
    pub http_status: Option<u16>,
    pub latency_ms: u64,
    pub retry_classification: InferenceRetryClassification,
    pub request_body_digest: ContentDigest,
    pub raw_response_digest: ContentDigest,
}

/// Structured, digest-sealed accounting for one successful live-provider
/// qualification turn.
///
/// This is intentionally a summary rather than a copy of the inference
/// adapter's raw bundle. It retains the provider/model/schema identity, usage,
/// latency, retry decisions, and content-addressed request/response evidence
/// required for audit while excluding secrets and provider-controlled text.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct M5ProviderAccountingSummaryV1 {
    pub schema: String,
    pub provider_id: String,
    pub model_id: String,
    pub provider_profile: M5ProviderProfileV1,
    pub response_contract_schema: String,
    pub response_schema_digest: ContentDigest,
    pub generation_policy_id: String,
    pub generation_policy_digest: ContentDigest,
    pub maximum_retries: u32,
    pub maximum_output_tokens: u32,
    pub input_cost_per_million_microunits: u64,
    pub output_cost_per_million_microunits: u64,
    pub finish_reason: InferenceFinishReason,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
    pub estimated_cost_microunits: u64,
    pub currency: String,
    pub total_latency_ms: u64,
    pub attempts: Vec<M5ProviderAttemptSummaryV1>,
    pub redacted_transcript_digest: ContentDigest,
    pub accounting_digest: ContentDigest,
}

#[derive(Serialize)]
struct M5ProviderAccountingDigestMaterial<'a> {
    domain: &'static str,
    schema: &'a str,
    provider_id: &'a str,
    model_id: &'a str,
    provider_profile: M5ProviderProfileV1,
    response_contract_schema: &'a str,
    response_schema_digest: &'a ContentDigest,
    generation_policy_id: &'a str,
    generation_policy_digest: &'a ContentDigest,
    maximum_retries: u32,
    maximum_output_tokens: u32,
    input_cost_per_million_microunits: u64,
    output_cost_per_million_microunits: u64,
    finish_reason: InferenceFinishReason,
    input_tokens: u64,
    output_tokens: u64,
    total_tokens: u64,
    estimated_cost_microunits: u64,
    currency: &'a str,
    total_latency_ms: u64,
    attempts: &'a [M5ProviderAttemptSummaryV1],
    redacted_transcript_digest: &'a ContentDigest,
}

impl M5ProviderAccountingSummaryV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider_id: impl Into<String>,
        model_id: impl Into<String>,
        provider_profile: M5ProviderProfileV1,
        response_schema_digest: ContentDigest,
        generation_policy_id: impl Into<String>,
        generation_policy_digest: ContentDigest,
        maximum_retries: u32,
        maximum_output_tokens: u32,
        input_cost_per_million_microunits: u64,
        output_cost_per_million_microunits: u64,
        finish_reason: InferenceFinishReason,
        input_tokens: u64,
        output_tokens: u64,
        total_tokens: u64,
        estimated_cost_microunits: u64,
        currency: impl Into<String>,
        total_latency_ms: u64,
        attempts: Vec<M5ProviderAttemptSummaryV1>,
        transcript: &RedactedTranscript,
    ) -> Result<Self, ReproductionError> {
        let mut accounting = Self {
            schema: M5_PROVIDER_ACCOUNTING_SCHEMA.to_string(),
            provider_id: provider_id.into(),
            model_id: model_id.into(),
            provider_profile,
            response_contract_schema: M5_PROVIDER_INTENT_SCHEMA.to_string(),
            response_schema_digest,
            generation_policy_id: generation_policy_id.into(),
            generation_policy_digest,
            maximum_retries,
            maximum_output_tokens,
            input_cost_per_million_microunits,
            output_cost_per_million_microunits,
            finish_reason,
            input_tokens,
            output_tokens,
            total_tokens,
            estimated_cost_microunits,
            currency: currency.into(),
            total_latency_ms,
            attempts,
            redacted_transcript_digest: transcript.transcript_digest()?,
            accounting_digest: ContentDigest::from_bytes(&[]),
        };
        accounting.accounting_digest = accounting.expected_digest()?;
        accounting.validate()?;
        Ok(accounting)
    }

    /// Reseal the summary when trusted fixture construction updates only the
    /// retained redacted transcript. Runtime validation never invokes this
    /// method on loaded evidence.
    pub fn reseal_for_transcript(
        mut self,
        transcript: &RedactedTranscript,
    ) -> Result<Self, ReproductionError> {
        self.redacted_transcript_digest = transcript.transcript_digest()?;
        self.accounting_digest = self.expected_digest()?;
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), ReproductionError> {
        if self.schema != M5_PROVIDER_ACCOUNTING_SCHEMA {
            return Err(provider_accounting_error(
                "unsupported M5 provider accounting schema",
            ));
        }
        validate_identifier("provider accounting provider id", &self.provider_id)?;
        validate_identifier("provider accounting model id", &self.model_id)?;
        validate_identifier(
            "provider accounting generation policy id",
            &self.generation_policy_id,
        )?;
        if self.response_contract_schema != M5_PROVIDER_INTENT_SCHEMA {
            return Err(provider_accounting_error(
                "provider accounting names an unsupported response contract",
            ));
        }
        if self.maximum_retries > MAX_M5_PROVIDER_RETRIES {
            return Err(provider_accounting_error(format!(
                "provider accounting maximum retries exceeds {MAX_M5_PROVIDER_RETRIES}"
            )));
        }
        if self.maximum_output_tokens == 0
            || self.maximum_output_tokens > MAX_M5_PROVIDER_OUTPUT_TOKENS
        {
            return Err(provider_accounting_error(format!(
                "provider accounting maximum output tokens must be within 1..={MAX_M5_PROVIDER_OUTPUT_TOKENS}"
            )));
        }
        if self.finish_reason != InferenceFinishReason::Completed {
            return Err(provider_accounting_error(
                "qualified provider accounting must have a completed finish reason",
            ));
        }
        let expected_total_tokens = self
            .input_tokens
            .checked_add(self.output_tokens)
            .ok_or_else(|| provider_accounting_error("provider token accounting overflow"))?;
        if expected_total_tokens != self.total_tokens {
            return Err(provider_accounting_error(
                "provider token accounting does not add up",
            ));
        }
        if self.output_tokens > u64::from(self.maximum_output_tokens) {
            return Err(provider_accounting_error(
                "provider output-token usage exceeds the frozen generation ceiling",
            ));
        }
        let expected_cost = estimate_provider_cost_microunits(
            self.input_tokens,
            self.output_tokens,
            self.input_cost_per_million_microunits,
            self.output_cost_per_million_microunits,
        )?;
        if self.estimated_cost_microunits != expected_cost {
            return Err(provider_accounting_error(
                "provider cost accounting does not match the retained token counts and pricing rates",
            ));
        }
        if self.currency.is_empty()
            || self.currency.len() > 16
            || !self.currency.bytes().all(|byte| byte.is_ascii_lowercase())
        {
            return Err(provider_accounting_error(
                "provider accounting currency must contain 1..=16 lowercase ASCII letters",
            ));
        }
        let maximum_attempts = usize::try_from(self.maximum_retries)
            .map_err(|_| provider_accounting_error("provider retry bound is not representable"))?
            .checked_add(1)
            .ok_or_else(|| provider_accounting_error("provider attempt bound overflow"))?;
        if self.attempts.is_empty()
            || self.attempts.len() > maximum_attempts
            || self.attempts.len() > MAX_M5_PROVIDER_ATTEMPTS
        {
            return Err(provider_accounting_error(format!(
                "provider accounting must retain 1..={maximum_attempts} attempts within the global {MAX_M5_PROVIDER_ATTEMPTS}-attempt bound"
            )));
        }
        let mut summed_latency_ms = 0_u64;
        let expected_request_body_digest = self
            .attempts
            .first()
            .map(|attempt| &attempt.request_body_digest)
            .expect("nonempty provider attempts checked above");
        for (index, attempt) in self.attempts.iter().enumerate() {
            let expected_attempt_number = u32::try_from(index + 1).map_err(|_| {
                provider_accounting_error("provider attempt number is not representable")
            })?;
            if attempt.attempt_number != expected_attempt_number {
                return Err(provider_accounting_error(
                    "provider accounting attempt numbers must be contiguous from one",
                ));
            }
            if &attempt.request_body_digest != expected_request_body_digest {
                return Err(provider_accounting_error(
                    "all provider retries must retain the same frozen request-body digest",
                ));
            }
            if attempt
                .http_status
                .is_some_and(|status| !(100..=599).contains(&status))
            {
                return Err(provider_accounting_error(
                    "provider accounting contains an invalid HTTP status",
                ));
            }
            if !retry_classification_matches_status(
                attempt.retry_classification,
                attempt.http_status,
            ) {
                return Err(provider_accounting_error(
                    "provider retry classification contradicts its HTTP/transport outcome",
                ));
            }
            let is_last = index + 1 == self.attempts.len();
            if (!is_last && !is_retried_classification(attempt.retry_classification))
                || (is_last
                    && attempt.retry_classification != InferenceRetryClassification::NoRetryNeeded)
            {
                return Err(provider_accounting_error(
                    "provider accounting requires retried intermediate attempts and one successful terminal attempt",
                ));
            }
            summed_latency_ms = summed_latency_ms
                .checked_add(attempt.latency_ms)
                .ok_or_else(|| provider_accounting_error("provider latency accounting overflow"))?;
        }
        if summed_latency_ms != self.total_latency_ms {
            return Err(provider_accounting_error(
                "provider attempt latency does not equal total latency",
            ));
        }
        require_digest(
            "M5 provider accounting",
            &self.accounting_digest,
            &self.expected_digest()?,
        )
    }

    fn expected_digest(&self) -> Result<ContentDigest, ReproductionError> {
        digest_serializable(&M5ProviderAccountingDigestMaterial {
            domain: "wasm-biotic:m5-provider-accounting-summary:v3",
            schema: &self.schema,
            provider_id: &self.provider_id,
            model_id: &self.model_id,
            provider_profile: self.provider_profile,
            response_contract_schema: &self.response_contract_schema,
            response_schema_digest: &self.response_schema_digest,
            generation_policy_id: &self.generation_policy_id,
            generation_policy_digest: &self.generation_policy_digest,
            maximum_retries: self.maximum_retries,
            maximum_output_tokens: self.maximum_output_tokens,
            input_cost_per_million_microunits: self.input_cost_per_million_microunits,
            output_cost_per_million_microunits: self.output_cost_per_million_microunits,
            finish_reason: self.finish_reason,
            input_tokens: self.input_tokens,
            output_tokens: self.output_tokens,
            total_tokens: self.total_tokens,
            estimated_cost_microunits: self.estimated_cost_microunits,
            currency: &self.currency,
            total_latency_ms: self.total_latency_ms,
            attempts: &self.attempts,
            redacted_transcript_digest: &self.redacted_transcript_digest,
        })
    }
}

fn estimate_provider_cost_microunits(
    input_tokens: u64,
    output_tokens: u64,
    input_cost_per_million_microunits: u64,
    output_cost_per_million_microunits: u64,
) -> Result<u64, ReproductionError> {
    let input_cost = u128::from(input_tokens)
        .checked_mul(u128::from(input_cost_per_million_microunits))
        .ok_or_else(|| provider_accounting_error("provider input-cost multiplication overflow"))?
        / 1_000_000_u128;
    let output_cost = u128::from(output_tokens)
        .checked_mul(u128::from(output_cost_per_million_microunits))
        .ok_or_else(|| provider_accounting_error("provider output-cost multiplication overflow"))?
        / 1_000_000_u128;
    let total = input_cost
        .checked_add(output_cost)
        .ok_or_else(|| provider_accounting_error("provider cost estimate overflow"))?;
    u64::try_from(total).map_err(|_| {
        provider_accounting_error("provider cost estimate is not representable as microunits")
    })
}

fn provider_accounting_error(message: impl Into<String>) -> ReproductionError {
    ReproductionError::ProviderQualification(message.into())
}

fn is_retried_classification(classification: InferenceRetryClassification) -> bool {
    matches!(
        classification,
        InferenceRetryClassification::RetriedTimeout
            | InferenceRetryClassification::RetriedTransportFailure
            | InferenceRetryClassification::RetriedRateLimited
            | InferenceRetryClassification::RetriedServerError
    )
}

fn retry_classification_matches_status(
    classification: InferenceRetryClassification,
    http_status: Option<u16>,
) -> bool {
    match classification {
        InferenceRetryClassification::NoRetryNeeded => {
            http_status.is_some_and(|status| (200..=299).contains(&status))
        }
        InferenceRetryClassification::RetriedTimeout
        | InferenceRetryClassification::RetriedTransportFailure
        | InferenceRetryClassification::ExhaustedTimeout
        | InferenceRetryClassification::ExhaustedTransportFailure => http_status.is_none(),
        InferenceRetryClassification::RetriedRateLimited
        | InferenceRetryClassification::ExhaustedRateLimited => http_status == Some(429),
        InferenceRetryClassification::RetriedServerError
        | InferenceRetryClassification::ExhaustedServerError => {
            http_status.is_some_and(|status| (500..=599).contains(&status))
        }
        InferenceRetryClassification::NonRetryableClientError => {
            http_status.is_some_and(|status| (400..=499).contains(&status) && status != 429)
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveProviderTurn {
    pub request_digest: ContentDigest,
    pub configuration_fingerprint: ContentDigest,
    pub replay_capsule_digest: ContentDigest,
    pub transport: ProviderTransport,
    pub external_turn_id: String,
    pub provider_receipt_digest: ContentDigest,
    pub provider_accounting: M5ProviderAccountingSummaryV1,
    pub transcript: RedactedTranscript,
    pub normalized_parser_input_bytes: Vec<u8>,
    pub parsed_intent: ParsedProviderIntent,
    pub turn_digest: ContentDigest,
}

impl LiveProviderTurn {
    pub fn seal(mut self) -> Result<Self, ReproductionError> {
        self.provider_accounting = self
            .provider_accounting
            .reseal_for_transcript(&self.transcript)?;
        self.provider_receipt_digest = self.provider_accounting.accounting_digest.clone();
        validate_provider_accounting_for_turn(&self)?;
        self.turn_digest = live_provider_turn_digest(&self)?;
        Ok(self)
    }
}

fn live_provider_turn_digest(turn: &LiveProviderTurn) -> Result<ContentDigest, ReproductionError> {
    digest_serializable(&(
        "wasm-biotic:live-provider-turn:v4",
        &turn.request_digest,
        &turn.configuration_fingerprint,
        &turn.replay_capsule_digest,
        &turn.transport,
        &turn.external_turn_id,
        &turn.provider_receipt_digest,
        &turn.provider_accounting,
        &turn.transcript,
        &turn.normalized_parser_input_bytes,
        &turn.parsed_intent,
    ))
}

fn validate_provider_accounting_for_turn(turn: &LiveProviderTurn) -> Result<(), ReproductionError> {
    turn.provider_accounting.validate()?;
    require_digest(
        "live provider receipt/accounting alias",
        &turn.provider_receipt_digest,
        &turn.provider_accounting.accounting_digest,
    )?;
    require_digest(
        "live provider redacted transcript accounting",
        &turn.provider_accounting.redacted_transcript_digest,
        &turn.transcript.transcript_digest()?,
    )?;
    let terminal_attempt = turn.provider_accounting.attempts.last().ok_or_else(|| {
        provider_accounting_error("live provider accounting has no terminal attempt")
    })?;
    require_digest(
        "live provider terminal raw response",
        &terminal_attempt.raw_response_digest,
        &turn.transcript.raw_response_digest,
    )?;
    if turn.parsed_intent.intent_schema != M5_PROVIDER_INTENT_SCHEMA
        || turn.provider_accounting.response_contract_schema != turn.parsed_intent.intent_schema
    {
        return Err(provider_accounting_error(
            "live provider accounting and parsed intent name different response contracts",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderReplayRequest {
    pub qualification_request_digest: ContentDigest,
    pub configuration_fingerprint: ContentDigest,
    pub replay_capsule: ProviderReplayCapsule,
    pub normalized_parser_input_bytes: Vec<u8>,
    pub expected_parser_digest: ContentDigest,
    pub transcript: RedactedTranscript,
    pub expected_intent_digest: ContentDigest,
    pub network_forbidden: bool,
    pub request_digest: ContentDigest,
}

impl ProviderReplayRequest {
    pub fn new(
        request: &ProviderQualificationRequest,
        turn: &LiveProviderTurn,
    ) -> Result<Self, ReproductionError> {
        request.replay_capsule.validate(&request.configuration)?;
        require_digest(
            "live-turn replay capsule",
            &turn.replay_capsule_digest,
            &request.replay_capsule.capsule_digest,
        )?;
        if turn.normalized_parser_input_bytes.is_empty()
            || turn.normalized_parser_input_bytes.len() > MAX_PROVIDER_TRANSCRIPT_BYTES
            || turn.normalized_parser_input_bytes != turn.transcript.redacted_response.as_bytes()
        {
            return Err(ReproductionError::ProviderQualification(
                "normalized parser input is absent, out of bounds, or differs from the retained redacted response"
                    .to_string(),
            ));
        }
        let mut replay = Self {
            qualification_request_digest: request.request_digest.clone(),
            configuration_fingerprint: request.configuration.fingerprint()?,
            replay_capsule: request.replay_capsule.clone(),
            normalized_parser_input_bytes: turn.normalized_parser_input_bytes.clone(),
            expected_parser_digest: request.configuration.parser_digest.clone(),
            transcript: turn.transcript.clone(),
            expected_intent_digest: turn.parsed_intent.intent_digest()?,
            network_forbidden: true,
            request_digest: ContentDigest::from_bytes(&[]),
        };
        replay.request_digest = digest_serializable(&(
            "wasm-biotic:provider-replay-request:v2",
            &replay.qualification_request_digest,
            &replay.configuration_fingerprint,
            &replay.replay_capsule,
            &replay.normalized_parser_input_bytes,
            &replay.expected_parser_digest,
            &replay.transcript,
            &replay.expected_intent_digest,
            replay.network_forbidden,
        ))?;
        Ok(replay)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderReplayRecord {
    pub request_digest: ContentDigest,
    pub network_used: bool,
    pub parsed_intent: ParsedProviderIntent,
    pub parser_digest: ContentDigest,
    pub replay_digest: ContentDigest,
}

impl ProviderReplayRecord {
    pub fn seal(mut self) -> Result<Self, ReproductionError> {
        self.replay_digest = provider_replay_digest(&self)?;
        Ok(self)
    }
}

fn provider_replay_digest(
    replay: &ProviderReplayRecord,
) -> Result<ContentDigest, ReproductionError> {
    digest_serializable(&(
        "wasm-biotic:provider-replay-record:v2",
        &replay.request_digest,
        replay.network_used,
        &replay.parsed_intent,
        &replay.parser_digest,
    ))
}

/// Trust boundary for the separate M5 live-provider qualification.
///
/// Implementations must perform a provider-backed turn for `perform_live_turn`
/// and must prohibit all network access for `replay_offline`. The engine never
/// accepts the provider response as release authority; it only checks whether
/// the independently governed intent can be replayed exactly.
pub trait LiveProviderQualificationPort: Send + Sync {
    fn perform_live_turn(
        &self,
        request: &ProviderQualificationRequest,
    ) -> Result<LiveProviderTurn, PortFailure>;

    fn replay_offline(
        &self,
        request: &ProviderReplayRequest,
    ) -> Result<ProviderReplayRecord, PortFailure>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderQualificationStatus {
    Qualified,
    Unavailable,
    LiveTurnFailed,
    InvalidLiveEvidence,
    ReplayFailed,
    ReplayMismatch,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveProviderQualificationRecord {
    pub schema: String,
    pub qualification_id: String,
    pub package_digest: ContentDigest,
    pub target_digest: ContentDigest,
    pub replay_capsule_digest: ContentDigest,
    pub configuration_fingerprint: ContentDigest,
    pub request_digest: ContentDigest,
    pub status: ProviderQualificationStatus,
    pub live_turn: Option<LiveProviderTurn>,
    pub replay: Option<ProviderReplayRecord>,
    pub failure: Option<PortFailure>,
    pub record_digest: ContentDigest,
}

impl LiveProviderQualificationRecord {
    pub fn is_qualified_for(
        &self,
        configuration: &ProviderConfiguration,
    ) -> Result<bool, ReproductionError> {
        Ok(self.status == ProviderQualificationStatus::Qualified
            && self.configuration_fingerprint == configuration.fingerprint()?)
    }

    fn seal(mut self) -> Result<Self, ReproductionError> {
        self.record_digest = live_provider_qualification_digest(&self)?;
        Ok(self)
    }
}

fn live_provider_qualification_digest(
    record: &LiveProviderQualificationRecord,
) -> Result<ContentDigest, ReproductionError> {
    digest_serializable(&(
        LIVE_PROVIDER_QUALIFICATION_SCHEMA,
        &record.qualification_id,
        &record.package_digest,
        &record.target_digest,
        &record.replay_capsule_digest,
        &record.configuration_fingerprint,
        &record.request_digest,
        record.status,
        &record.live_turn,
        &record.replay,
        &record.failure,
    ))
}

pub struct ReproductionPorts {
    pub m1_candidate: Arc<dyn M1CandidatePort>,
    pub m2_supervisor: Arc<dyn M2SupervisorPort>,
    pub m3_capability: Arc<dyn M3CapabilityPort>,
    pub m4_workers: Arc<dyn M4WorkerPort>,
    pub live_provider: Option<Arc<dyn LiveProviderQualificationPort>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CycleIntentKind {
    Seeded,
    AdoptedSuccessor,
}

/// Immutable execution bounds and idempotency domain for one reproduction cycle.
///
/// The release gate remains the source of truth. Copying its bounded recursion
/// budget into the intent prevents a later caller from reusing the cycle id
/// under a different execution envelope, while the namespace gives every
/// phase-specific idempotency key one common, exact root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CycleExecutionPolicy {
    pub schema: String,
    pub gate_digest: ContentDigest,
    pub budgets: RecursionBudgets,
    pub idempotency_namespace: String,
    pub policy_digest: ContentDigest,
}

impl CycleExecutionPolicy {
    fn new(
        cycle_id: &str,
        kind: CycleIntentKind,
        active_package_digest: &ContentDigest,
        active_package_bytes_digest: &ContentDigest,
        gate: &ReleaseGate,
    ) -> Result<Self, ReproductionError> {
        gate.validate()?;
        let idempotency_namespace = cycle_idempotency_namespace(
            cycle_id,
            kind,
            active_package_digest,
            active_package_bytes_digest,
            &gate.gate_digest,
            &gate.budgets,
        )?;
        let mut policy = Self {
            schema: CYCLE_EXECUTION_POLICY_SCHEMA.to_string(),
            gate_digest: gate.gate_digest.clone(),
            budgets: gate.budgets.clone(),
            idempotency_namespace,
            policy_digest: ContentDigest::from_bytes(&[]),
        };
        policy.policy_digest = cycle_execution_policy_digest(&policy)?;
        policy.validate_for(
            cycle_id,
            kind,
            active_package_digest,
            active_package_bytes_digest,
            &gate.gate_digest,
        )?;
        Ok(policy)
    }

    fn validate_for(
        &self,
        cycle_id: &str,
        kind: CycleIntentKind,
        active_package_digest: &ContentDigest,
        active_package_bytes_digest: &ContentDigest,
        expected_gate_digest: &ContentDigest,
    ) -> Result<(), ReproductionError> {
        if self.schema != CYCLE_EXECUTION_POLICY_SCHEMA {
            return Err(ReproductionError::StateIntegrity(
                "cycle intent contains an unsupported execution policy".to_string(),
            ));
        }
        self.budgets.validate()?;
        validate_identifier("cycle idempotency namespace", &self.idempotency_namespace)?;
        require_digest(
            "cycle execution policy gate",
            &self.gate_digest,
            expected_gate_digest,
        )?;
        let expected_namespace = cycle_idempotency_namespace(
            cycle_id,
            kind,
            active_package_digest,
            active_package_bytes_digest,
            expected_gate_digest,
            &self.budgets,
        )?;
        if self.idempotency_namespace != expected_namespace {
            return Err(ReproductionError::StateIntegrity(
                "cycle idempotency namespace differs from its immutable inputs".to_string(),
            ));
        }
        require_digest(
            "cycle execution policy",
            &self.policy_digest,
            &cycle_execution_policy_digest(self)?,
        )
    }

    fn phase_idempotency_key(
        &self,
        phase: &str,
        binding_digest: &ContentDigest,
    ) -> Result<String, ReproductionError> {
        validate_identifier("cycle phase", phase)?;
        Ok(format!(
            "{}:{phase}:{}",
            self.idempotency_namespace,
            binding_digest.file_stem()
        ))
    }
}

fn cycle_idempotency_namespace(
    cycle_id: &str,
    kind: CycleIntentKind,
    active_package_digest: &ContentDigest,
    active_package_bytes_digest: &ContentDigest,
    gate_digest: &ContentDigest,
    budgets: &RecursionBudgets,
) -> Result<String, ReproductionError> {
    validate_identifier("cycle id", cycle_id)?;
    budgets.validate()?;
    let digest = digest_serializable(&(
        "wasm-biotic:factory-cycle-idempotency-namespace:v1",
        cycle_id,
        kind,
        active_package_digest,
        active_package_bytes_digest,
        gate_digest,
        budgets,
    ))?;
    Ok(format!("m5-cycle:{}", digest.file_stem()))
}

fn cycle_execution_policy_digest(
    policy: &CycleExecutionPolicy,
) -> Result<ContentDigest, ReproductionError> {
    digest_serializable(&(
        CYCLE_EXECUTION_POLICY_SCHEMA,
        &policy.gate_digest,
        &policy.budgets,
        &policy.idempotency_namespace,
    ))
}

/// Immutable, exact cycle input retained before the first phase port is called.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CycleIntent {
    pub cycle_id: String,
    pub kind: CycleIntentKind,
    pub expected_active_package_digest: ContentDigest,
    pub expected_active_package_bytes_digest: ContentDigest,
    pub expected_gate_digest: ContentDigest,
    pub seed_genome: Option<MutableGenome>,
    pub generation_instruction_digest: Option<ContentDigest>,
    pub state_compatibility: StateCompatibility,
    pub migration_plan: Option<StateMigrationPlan>,
    pub operator_context_digest: ContentDigest,
    pub execution_policy: CycleExecutionPolicy,
    pub intent_digest: ContentDigest,
}

impl CycleIntent {
    fn seeded(
        request: &SeedCycleRequest,
        active: &FactoryPackage,
        gate: &ReleaseGate,
    ) -> Result<Self, ReproductionError> {
        let active_package_bytes_digest = ContentDigest::from_bytes(&active.canonical_bytes()?);
        if active.package_digest != request.expected_active_package_digest {
            return Err(ReproductionError::ActivePackageMismatch {
                expected: active.package_digest.clone(),
                actual: request.expected_active_package_digest.clone(),
            });
        }
        if gate.gate_digest != request.expected_gate_digest {
            return Err(ReproductionError::GateMismatch {
                expected: gate.gate_digest.clone(),
                actual: request.expected_gate_digest.clone(),
            });
        }
        let mut intent = Self {
            cycle_id: request.cycle_id.clone(),
            kind: CycleIntentKind::Seeded,
            expected_active_package_digest: request.expected_active_package_digest.clone(),
            expected_active_package_bytes_digest: active_package_bytes_digest.clone(),
            expected_gate_digest: request.expected_gate_digest.clone(),
            seed_genome: Some(request.genome.clone()),
            generation_instruction_digest: None,
            state_compatibility: request.state_compatibility.clone(),
            migration_plan: request.migration_plan.clone(),
            operator_context_digest: request.operator_context_digest.clone(),
            execution_policy: CycleExecutionPolicy::new(
                &request.cycle_id,
                CycleIntentKind::Seeded,
                &request.expected_active_package_digest,
                &active_package_bytes_digest,
                gate,
            )?,
            intent_digest: ContentDigest::from_bytes(&[]),
        };
        intent.seal()?;
        Ok(intent)
    }

    fn adopted(
        request: &AdoptedSuccessorRequest,
        executor: &FactoryPackage,
        gate: &ReleaseGate,
    ) -> Result<Self, ReproductionError> {
        let executor_package_bytes_digest = ContentDigest::from_bytes(&executor.canonical_bytes()?);
        if executor.package_digest != request.expected_active_package_digest {
            return Err(ReproductionError::ActivePackageMismatch {
                expected: executor.package_digest.clone(),
                actual: request.expected_active_package_digest.clone(),
            });
        }
        if gate.gate_digest != request.expected_gate_digest {
            return Err(ReproductionError::GateMismatch {
                expected: gate.gate_digest.clone(),
                actual: request.expected_gate_digest.clone(),
            });
        }
        let mut intent = Self {
            cycle_id: request.cycle_id.clone(),
            kind: CycleIntentKind::AdoptedSuccessor,
            expected_active_package_digest: request.expected_active_package_digest.clone(),
            expected_active_package_bytes_digest: executor_package_bytes_digest.clone(),
            expected_gate_digest: request.expected_gate_digest.clone(),
            seed_genome: None,
            generation_instruction_digest: executor
                .payload
                .genome
                .policy
                .generation_instruction
                .as_ref()
                .map(GenerationLoopInstruction::instruction_digest)
                .transpose()?,
            state_compatibility: executor.payload.boot_manifest.state_compatibility.clone(),
            migration_plan: request.migration_plan.clone(),
            operator_context_digest: request.operator_context_digest.clone(),
            execution_policy: CycleExecutionPolicy::new(
                &request.cycle_id,
                CycleIntentKind::AdoptedSuccessor,
                &request.expected_active_package_digest,
                &executor_package_bytes_digest,
                gate,
            )?,
            intent_digest: ContentDigest::from_bytes(&[]),
        };
        intent.seal()?;
        Ok(intent)
    }

    fn seal(&mut self) -> Result<(), ReproductionError> {
        validate_identifier("cycle intent id", &self.cycle_id)?;
        match self.kind {
            CycleIntentKind::Seeded if self.seed_genome.is_none() => {
                return Err(ReproductionError::StateIntegrity(
                    "seeded cycle intent has no exact genome".to_string(),
                ));
            }
            CycleIntentKind::AdoptedSuccessor if self.seed_genome.is_some() => {
                return Err(ReproductionError::StateIntegrity(
                    "adopted-successor intent unexpectedly contains a seed genome".to_string(),
                ));
            }
            _ => {}
        }
        if let Some(genome) = &self.seed_genome {
            genome.validate()?;
        }
        self.state_compatibility.validate()?;
        if let Some(plan) = &self.migration_plan {
            plan.validate()?;
        }
        // Package payload identity and canonical package-byte identity are
        // intentionally distinct digests. The byte digest is re-derived from
        // the indexed package when the complete engine state is validated.
        self.execution_policy.validate_for(
            &self.cycle_id,
            self.kind,
            &self.expected_active_package_digest,
            &self.expected_active_package_bytes_digest,
            &self.expected_gate_digest,
        )?;
        self.intent_digest = cycle_intent_digest(self)?;
        Ok(())
    }

    fn validate(&self) -> Result<(), ReproductionError> {
        let mut material = self.clone();
        material.seal()?;
        require_digest("cycle intent", &self.intent_digest, &material.intent_digest)
    }
}

fn cycle_intent_digest(intent: &CycleIntent) -> Result<ContentDigest, ReproductionError> {
    digest_serializable(&(
        "wasm-biotic:factory-cycle-intent:v2",
        &intent.cycle_id,
        intent.kind,
        &intent.expected_active_package_digest,
        &intent.expected_active_package_bytes_digest,
        &intent.expected_gate_digest,
        &intent.seed_genome,
        &intent.generation_instruction_digest,
        &intent.state_compatibility,
        &intent.migration_plan,
        &intent.operator_context_digest,
        &intent.execution_policy,
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingStage {
    MigrationRequested,
    MigrationApplied,
    ActivationRequested,
    Activated,
    ObservationRequested,
    RollbackRequested,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingEffect {
    pub cycle_id: String,
    pub incumbent_package_digest: ContentDigest,
    pub challenger_package_digest: ContentDigest,
    pub incumbent_state_schema: u32,
    pub target_state_schema: u32,
    pub stage: PendingStage,
    pub migration_receipt: Option<MigrationReceipt>,
    pub activation_receipt: Option<ActivationReceipt>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CycleStatus {
    Evaluating,
    GateRejected,
    ApprovalRejected,
    Approved,
    Adopted,
    QuarantinedAndRolledBack,
    RecoveredToIncumbent,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationInitiationRecord {
    pub cycle_id: String,
    pub executor_package_digest: ContentDigest,
    pub executor_package_bytes_digest: ContentDigest,
    pub instruction_digest: ContentDigest,
    pub driver_request: GenerationDriverRequest,
    pub driver_evidence: GenerationDriverEvidence,
    pub materialization_request: GenerationMaterializationRequest,
    pub materialization_evidence: GenerationMaterializationEvidence,
    pub successor_genome_digest: ContentDigest,
    pub material_step_digest: ContentDigest,
}

impl GenerationInitiationRecord {
    fn new(
        cycle_id: &str,
        request: &GenerationDriverRequest,
        evidence: &GenerationDriverEvidence,
        materialization_request: &GenerationMaterializationRequest,
        materialization_evidence: &GenerationMaterializationEvidence,
        successor_genome: &MutableGenome,
    ) -> Result<Self, ReproductionError> {
        let material_step_digest = digest_serializable(&(
            "wasm-biotic:material-generation-step:v2",
            cycle_id,
            &request.executor_package_digest,
            &request.executor_package_bytes_digest,
            &request.instruction_digest,
            &evidence.evidence_digest,
            &materialization_evidence.evidence_digest,
            &successor_genome.genome_digest,
        ))?;
        Ok(Self {
            cycle_id: cycle_id.to_string(),
            executor_package_digest: request.executor_package_digest.clone(),
            executor_package_bytes_digest: request.executor_package_bytes_digest.clone(),
            instruction_digest: request.instruction_digest.clone(),
            driver_request: request.clone(),
            driver_evidence: evidence.clone(),
            materialization_request: materialization_request.clone(),
            materialization_evidence: materialization_evidence.clone(),
            successor_genome_digest: successor_genome.genome_digest.clone(),
            material_step_digest,
        })
    }

    fn validate(&self) -> Result<(), ReproductionError> {
        validate_identifier("generation initiation cycle id", &self.cycle_id)?;
        validate_generation_driver_evidence(&self.driver_request, &self.driver_evidence)?;
        validate_generation_materialization_evidence(
            &self.driver_request,
            &self.driver_evidence,
            &self.materialization_request,
            &self.materialization_evidence,
        )?;
        if self.cycle_id != self.driver_request.cycle_id
            || self.executor_package_digest != self.driver_request.executor_package_digest
            || self.executor_package_bytes_digest
                != self.driver_request.executor_package_bytes_digest
            || self.instruction_digest != self.driver_request.instruction_digest
        {
            return Err(ReproductionError::StateIntegrity(
                "generation initiation summary differs from its exact driver request".to_string(),
            ));
        }
        require_digest(
            "material generation step",
            &self.material_step_digest,
            &digest_serializable(&(
                "wasm-biotic:material-generation-step:v2",
                &self.cycle_id,
                &self.executor_package_digest,
                &self.executor_package_bytes_digest,
                &self.instruction_digest,
                &self.driver_evidence.evidence_digest,
                &self.materialization_evidence.evidence_digest,
                &self.successor_genome_digest,
            ))?,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CycleRecord {
    pub cycle_id: String,
    pub generation: u32,
    pub parent_package_digest: ContentDigest,
    pub challenger_package_digest: ContentDigest,
    pub challenger_package_bytes_digest: ContentDigest,
    pub genome_digest: ContentDigest,
    pub gate_digest: ContentDigest,
    pub initiation: Option<GenerationInitiationRecord>,
    pub m1_evidence: M1BuildEvidence,
    pub worker_evidence: WorkerWorkflowEvidence,
    pub shadow_evidence: ShadowExecutionEvidence,
    pub gate_decision: GateDecision,
    pub approval: Option<SupervisorApprovalRecord>,
    pub migration_plan: Option<StateMigrationPlan>,
    pub migration_receipt: Option<MigrationReceipt>,
    pub activation_receipt: Option<ActivationReceipt>,
    pub observation_evidence: Option<PostActivationEvidence>,
    pub recovery_receipt: Option<RecoveryReceipt>,
    pub status: CycleStatus,
    pub record_digest: ContentDigest,
}

impl CycleRecord {
    fn seal(&mut self) -> Result<(), ReproductionError> {
        self.record_digest = cycle_record_digest(self)?;
        Ok(())
    }
}

fn cycle_record_digest(record: &CycleRecord) -> Result<ContentDigest, ReproductionError> {
    let mut material = record.clone();
    material.record_digest = ContentDigest::from_bytes(&[]);
    digest_serializable(&("wasm-biotic:factory-cycle-record:v1", material))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LineageDisposition {
    Root,
    GateRejected,
    ApprovalRejected,
    Adopted,
    Quarantined,
    RecoveryRollback,
    OperatorRollback,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactoryLineageRecord {
    pub schema: String,
    pub lineage_id: String,
    pub generation: u32,
    pub parent_package_digest: Option<ContentDigest>,
    pub package_digest: ContentDigest,
    pub package_bytes_digest: ContentDigest,
    pub genome_digest: ContentDigest,
    pub cycle_record_digest: Option<ContentDigest>,
    pub generation_initiation_digest: Option<ContentDigest>,
    pub disposition: LineageDisposition,
    pub prior_state_schema: u32,
    pub resulting_state_schema: u32,
    pub recovery_receipt_digest: Option<ContentDigest>,
    pub lineage_digest: ContentDigest,
}

impl FactoryLineageRecord {
    #[allow(clippy::too_many_arguments)]
    fn new(
        lineage_id: impl Into<String>,
        generation: u32,
        parent_package_digest: Option<ContentDigest>,
        package: &FactoryPackage,
        cycle_record_digest: Option<ContentDigest>,
        generation_initiation_digest: Option<ContentDigest>,
        disposition: LineageDisposition,
        prior_state_schema: u32,
        resulting_state_schema: u32,
        recovery_receipt_digest: Option<ContentDigest>,
    ) -> Result<Self, ReproductionError> {
        let mut record = Self {
            schema: LINEAGE_RECORD_SCHEMA.to_string(),
            lineage_id: lineage_id.into(),
            generation,
            parent_package_digest,
            package_digest: package.package_digest.clone(),
            package_bytes_digest: ContentDigest::from_bytes(&package.canonical_bytes()?),
            genome_digest: package.payload.genome.genome_digest.clone(),
            cycle_record_digest,
            generation_initiation_digest,
            disposition,
            prior_state_schema,
            resulting_state_schema,
            recovery_receipt_digest,
            lineage_digest: ContentDigest::from_bytes(&[]),
        };
        validate_identifier("lineage id", &record.lineage_id)?;
        record.lineage_digest = lineage_record_digest(&record)?;
        Ok(record)
    }
}

fn lineage_record_digest(
    record: &FactoryLineageRecord,
) -> Result<ContentDigest, ReproductionError> {
    digest_serializable(&(
        LINEAGE_RECORD_SCHEMA,
        &record.lineage_id,
        record.generation,
        &record.parent_package_digest,
        &record.package_digest,
        &record.package_bytes_digest,
        &record.genome_digest,
        &record.cycle_record_digest,
        &record.generation_initiation_digest,
        record.disposition,
        record.prior_state_schema,
        record.resulting_state_schema,
        &record.recovery_receipt_digest,
    ))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuarantineRecord {
    pub quarantine_id: String,
    pub cycle_id: String,
    pub package_digest: ContentDigest,
    pub observation_evidence_digest: Option<ContentDigest>,
    pub recovery_receipt_digest: ContentDigest,
    pub reason: String,
    pub record_digest: ContentDigest,
}

impl QuarantineRecord {
    fn seal(mut self) -> Result<Self, ReproductionError> {
        self.record_digest = quarantine_record_digest(&self)?;
        Ok(self)
    }
}

fn quarantine_record_digest(record: &QuarantineRecord) -> Result<ContentDigest, ReproductionError> {
    digest_serializable(&(
        "wasm-biotic:factory-quarantine:v1",
        &record.quarantine_id,
        &record.cycle_id,
        &record.package_digest,
        &record.observation_evidence_digest,
        &record.recovery_receipt_digest,
        &record.reason,
    ))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorRollbackRecord {
    pub rollback_id: String,
    pub from_package_digest: ContentDigest,
    pub restored_package_digest: ContentDigest,
    pub reason_ref: String,
    pub recovery_receipt: RecoveryReceipt,
    pub record_digest: ContentDigest,
}

impl OperatorRollbackRecord {
    fn seal(mut self) -> Result<Self, ReproductionError> {
        self.record_digest = operator_rollback_record_digest(&self)?;
        Ok(self)
    }
}

fn operator_rollback_record_digest(
    record: &OperatorRollbackRecord,
) -> Result<ContentDigest, ReproductionError> {
    digest_serializable(&(
        "wasm-biotic:operator-factory-rollback:v1",
        &record.rollback_id,
        &record.from_package_digest,
        &record.restored_package_digest,
        &record.reason_ref,
        &record.recovery_receipt,
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    GenerationDisabled,
    MissingInstruction,
    InstructionExecutionBudgetExhausted,
    GenerationDepthExhausted,
    TotalCycleBudgetExhausted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StopConditionRecord {
    pub stop_id: String,
    pub requested_cycle_id: String,
    pub active_package_digest: ContentDigest,
    pub generation: u32,
    pub reason: StopReason,
    pub record_digest: ContentDigest,
}

impl StopConditionRecord {
    fn seal(mut self) -> Result<Self, ReproductionError> {
        self.record_digest = stop_condition_record_digest(&self)?;
        Ok(self)
    }
}

fn stop_condition_record_digest(
    record: &StopConditionRecord,
) -> Result<ContentDigest, ReproductionError> {
    digest_serializable(&(
        "wasm-biotic:generation-stop-condition:v1",
        &record.stop_id,
        &record.requested_cycle_id,
        &record.active_package_digest,
        record.generation,
        record.reason,
    ))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageIndexRecord {
    pub package_digest: ContentDigest,
    pub byte_len: u64,
    pub generation: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedIncumbent {
    pub package_digest: ContentDigest,
    pub state_schema: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReproductionState {
    pub schema_version: u32,
    pub factory_id: String,
    pub release_gate: ReleaseGate,
    pub active_package_digest: ContentDigest,
    pub active_generation: u32,
    pub active_state_schema: u32,
    pub retained_incumbent: Option<RetainedIncumbent>,
    pub package_index: BTreeMap<String, PackageIndexRecord>,
    pub cycle_intents: Vec<CycleIntent>,
    pub prepared_successors: Vec<PreparedSuccessorCycle>,
    pub cycles: Vec<CycleRecord>,
    pub lineage: Vec<FactoryLineageRecord>,
    pub generation_initiations: Vec<GenerationInitiationRecord>,
    pub instruction_uses: BTreeMap<String, u32>,
    pub quarantines: Vec<QuarantineRecord>,
    pub operator_rollbacks: Vec<OperatorRollbackRecord>,
    pub recovery_receipts: Vec<RecoveryReceipt>,
    pub provider_qualifications: Vec<LiveProviderQualificationRecord>,
    pub stop_conditions: Vec<StopConditionRecord>,
    pub in_flight: Option<PendingEffect>,
    pub state_digest: ContentDigest,
}

impl ReproductionState {
    fn seal(&mut self) -> Result<(), ReproductionError> {
        self.state_digest = reproduction_state_digest(self)?;
        Ok(())
    }

    /// Validate the complete durable reproduction journal and its digest.
    ///
    /// This is public so a detached, immutable export can be verified without
    /// reopening the originating runtime. Package bytes are deliberately
    /// validated separately by that export boundary.
    pub fn validate(&self) -> Result<(), ReproductionError> {
        if self.schema_version != REPRODUCTION_STATE_SCHEMA_VERSION {
            return Err(ReproductionError::UnsupportedStateSchema(
                self.schema_version,
            ));
        }
        validate_identifier("factory id", &self.factory_id)?;
        self.release_gate.validate()?;
        if self.cycles.len() > MAX_RECORDS
            || self.cycle_intents.len() > MAX_RECORDS
            || self.prepared_successors.len() > MAX_RECORDS
            || self.lineage.len() > MAX_RECORDS
            || self.generation_initiations.len() > MAX_RECORDS
            || self.quarantines.len() > MAX_RECORDS
            || self.operator_rollbacks.len() > MAX_RECORDS
            || self.recovery_receipts.len() > MAX_RECORDS
            || self.provider_qualifications.len() > MAX_RECORDS
            || self.stop_conditions.len() > MAX_RECORDS
        {
            return Err(ReproductionError::BudgetExceeded(
                "durable journal record limit exceeded".to_string(),
            ));
        }
        let mut intent_ids = BTreeSet::new();
        for intent in &self.cycle_intents {
            intent.validate()?;
            if !intent_ids.insert(intent.cycle_id.as_str()) {
                return Err(ReproductionError::StateIntegrity(
                    "cycle intent ids must be unique".to_string(),
                ));
            }
            if intent.execution_policy.gate_digest != self.release_gate.gate_digest
                || intent.execution_policy.budgets != self.release_gate.budgets
                || !self
                    .package_index
                    .contains_key(intent.expected_active_package_digest.as_str())
            {
                return Err(ReproductionError::StateIntegrity(
                    "cycle intent differs from the durable release gate or package index"
                        .to_string(),
                ));
            }
        }
        let mut prepared_ids = BTreeSet::new();
        for prepared in &self.prepared_successors {
            prepared.validate()?;
            if !prepared_ids.insert(prepared.cycle_id.as_str()) {
                return Err(ReproductionError::StateIntegrity(
                    "prepared successor cycle ids must be unique".to_string(),
                ));
            }
            let intent = self
                .cycle_intents
                .iter()
                .find(|intent| intent.cycle_id == prepared.cycle_id)
                .ok_or_else(|| {
                    ReproductionError::StateIntegrity(
                        "prepared successor has no immutable cycle intent".to_string(),
                    )
                })?;
            if intent.kind != CycleIntentKind::AdoptedSuccessor
                || intent.intent_digest != prepared.intent_digest
                || prepared.initiation.driver_request.gate_digest != self.release_gate.gate_digest
                || prepared
                    .initiation
                    .materialization_request
                    .maximum_component_bytes
                    != self.release_gate.budgets.max_component_bytes
            {
                return Err(ReproductionError::StateIntegrity(
                    "prepared successor does not match its adopted cycle intent".to_string(),
                ));
            }
            if !self
                .package_index
                .contains_key(prepared.executor_package_digest.as_str())
            {
                return Err(ReproductionError::StateIntegrity(
                    "prepared successor executor is absent from the package index".to_string(),
                ));
            }
            if self
                .instruction_uses
                .get(&prepared.instruction_use_key)
                .copied()
                != Some(prepared.instruction_use_number)
                || !self.generation_initiations.iter().any(|initiation| {
                    initiation.cycle_id == prepared.cycle_id
                        && initiation.material_step_digest
                            == prepared.initiation.material_step_digest
                })
            {
                return Err(ReproductionError::StateIntegrity(
                    "prepared successor is not bound to its durable instruction use and initiation"
                        .to_string(),
                ));
            }
        }
        if !self
            .package_index
            .contains_key(self.active_package_digest.as_str())
        {
            return Err(ReproductionError::StateIntegrity(
                "active package is absent from the package index".to_string(),
            ));
        }
        if self.package_index.len() > MAX_RECORDS {
            return Err(ReproductionError::BudgetExceeded(
                "package index record limit exceeded".to_string(),
            ));
        }
        let active_record = self
            .package_index
            .get(self.active_package_digest.as_str())
            .ok_or_else(|| {
                ReproductionError::StateIntegrity(
                    "active package disappeared from the package index".to_string(),
                )
            })?;
        if active_record.generation != self.active_generation {
            return Err(ReproductionError::StateIntegrity(
                "active generation differs from the active package index".to_string(),
            ));
        }
        if let Some(retained) = &self.retained_incumbent
            && !self
                .package_index
                .contains_key(retained.package_digest.as_str())
        {
            return Err(ReproductionError::StateIntegrity(
                "retained incumbent is absent from the package index".to_string(),
            ));
        }
        let mut cycle_ids = BTreeSet::new();
        for cycle in &self.cycles {
            validate_identifier("cycle id", &cycle.cycle_id)?;
            if !cycle_ids.insert(cycle.cycle_id.as_str()) {
                return Err(ReproductionError::StateIntegrity(
                    "durable cycle ids must be unique".to_string(),
                ));
            }
            let intent = self
                .cycle_intents
                .iter()
                .find(|intent| intent.cycle_id == cycle.cycle_id)
                .ok_or_else(|| {
                    ReproductionError::StateIntegrity(
                        "durable cycle has no immutable cycle intent".to_string(),
                    )
                })?;
            if cycle.parent_package_digest != intent.expected_active_package_digest
                || cycle.gate_digest != intent.expected_gate_digest
            {
                return Err(ReproductionError::StateIntegrity(
                    "durable cycle differs from its immutable cycle intent".to_string(),
                ));
            }
            require_digest(
                "cycle record",
                &cycle.record_digest,
                &cycle_record_digest(cycle)?,
            )?;
            require_digest(
                "cycle release gate",
                &cycle.gate_digest,
                &self.release_gate.gate_digest,
            )?;
            require_digest(
                "cycle M1 evidence",
                &cycle.m1_evidence.evidence_digest,
                &m1_evidence_digest(&cycle.m1_evidence)?,
            )?;
            require_digest(
                "cycle worker evidence",
                &cycle.worker_evidence.evidence_digest,
                &worker_evidence_digest(&cycle.worker_evidence)?,
            )?;
            require_digest(
                "cycle shadow evidence",
                &cycle.shadow_evidence.evidence_digest,
                &shadow_evidence_digest(&cycle.shadow_evidence)?,
            )?;
            require_digest(
                "cycle gate decision",
                &cycle.gate_decision.decision_digest,
                &gate_decision_digest(&cycle.gate_decision)?,
            )?;
            if let Some(initiation) = &cycle.initiation {
                initiation.validate()?;
            }
            if let Some(approval) = &cycle.approval {
                require_digest(
                    "cycle approval",
                    &approval.approval_digest,
                    &supervisor_approval_digest(approval)?,
                )?;
            }
            if let Some(plan) = &cycle.migration_plan {
                plan.validate()?;
            }
            if let Some(receipt) = &cycle.migration_receipt {
                require_digest(
                    "cycle migration receipt",
                    &receipt.receipt_digest,
                    &migration_receipt_digest(receipt)?,
                )?;
            }
            if let Some(receipt) = &cycle.activation_receipt {
                require_digest(
                    "cycle activation receipt",
                    &receipt.receipt_digest,
                    &activation_receipt_digest(receipt)?,
                )?;
            }
            if let Some(evidence) = &cycle.observation_evidence {
                require_digest(
                    "cycle observation evidence",
                    &evidence.evidence_digest,
                    &post_activation_evidence_digest(evidence)?,
                )?;
            }
            if let Some(receipt) = &cycle.recovery_receipt {
                require_digest(
                    "cycle recovery receipt",
                    &receipt.receipt_digest,
                    &recovery_receipt_digest(receipt)?,
                )?;
            }
        }
        let mut lineage_ids = BTreeSet::new();
        for record in &self.lineage {
            if record.schema != LINEAGE_RECORD_SCHEMA {
                return Err(ReproductionError::StateIntegrity(
                    "unsupported lineage record schema".to_string(),
                ));
            }
            validate_identifier("lineage id", &record.lineage_id)?;
            if !lineage_ids.insert(record.lineage_id.as_str()) {
                return Err(ReproductionError::StateIntegrity(
                    "lineage ids must be unique".to_string(),
                ));
            }
            require_digest(
                "lineage record",
                &record.lineage_digest,
                &lineage_record_digest(record)?,
            )?;
            if !self
                .package_index
                .contains_key(record.package_digest.as_str())
            {
                return Err(ReproductionError::StateIntegrity(
                    "lineage references an absent package".to_string(),
                ));
            }
        }
        let mut initiation_ids = BTreeSet::new();
        for initiation in &self.generation_initiations {
            initiation.validate()?;
            if !initiation_ids.insert(initiation.cycle_id.as_str()) {
                return Err(ReproductionError::StateIntegrity(
                    "generation initiation cycle ids must be unique".to_string(),
                ));
            }
            let intent = self
                .cycle_intents
                .iter()
                .find(|intent| intent.cycle_id == initiation.cycle_id)
                .ok_or_else(|| {
                    ReproductionError::StateIntegrity(
                        "generation initiation has no immutable cycle intent".to_string(),
                    )
                })?;
            let expected_driver_idempotency_key = intent.execution_policy.phase_idempotency_key(
                "generation-driver",
                &initiation.driver_request.instruction_digest,
            )?;
            let expected_materialization_idempotency_key =
                intent.execution_policy.phase_idempotency_key(
                    "generation-materialization",
                    &initiation.driver_evidence.evidence_digest,
                )?;
            if intent.kind != CycleIntentKind::AdoptedSuccessor
                || intent.generation_instruction_digest.as_ref()
                    != Some(&initiation.instruction_digest)
                || initiation.executor_package_digest != intent.expected_active_package_digest
                || initiation.executor_package_bytes_digest
                    != intent.expected_active_package_bytes_digest
                || initiation.driver_request.gate_digest != self.release_gate.gate_digest
                || initiation.materialization_request.maximum_component_bytes
                    != self.release_gate.budgets.max_component_bytes
                || initiation.driver_request.idempotency_key != expected_driver_idempotency_key
                || initiation.materialization_request.idempotency_key
                    != expected_materialization_idempotency_key
            {
                return Err(ReproductionError::StateIntegrity(
                    "generation initiation differs from its immutable intent or release gate"
                        .to_string(),
                ));
            }
        }
        for quarantine in &self.quarantines {
            validate_identifier("quarantine id", &quarantine.quarantine_id)?;
            require_digest(
                "quarantine record",
                &quarantine.record_digest,
                &quarantine_record_digest(quarantine)?,
            )?;
        }
        for rollback in &self.operator_rollbacks {
            validate_identifier("operator rollback id", &rollback.rollback_id)?;
            require_digest(
                "operator rollback record",
                &rollback.record_digest,
                &operator_rollback_record_digest(rollback)?,
            )?;
        }
        for recovery in &self.recovery_receipts {
            require_digest(
                "durable recovery receipt",
                &recovery.receipt_digest,
                &recovery_receipt_digest(recovery)?,
            )?;
        }
        let mut qualification_ids = BTreeSet::new();
        for qualification in &self.provider_qualifications {
            if qualification.schema != LIVE_PROVIDER_QUALIFICATION_SCHEMA {
                return Err(ReproductionError::StateIntegrity(
                    "unsupported provider qualification schema".to_string(),
                ));
            }
            validate_identifier("provider qualification id", &qualification.qualification_id)?;
            if !qualification_ids.insert(qualification.qualification_id.as_str()) {
                return Err(ReproductionError::StateIntegrity(
                    "provider qualification ids must be unique".to_string(),
                ));
            }
            require_digest(
                "provider qualification record",
                &qualification.record_digest,
                &live_provider_qualification_digest(qualification)?,
            )?;
            if let Some(turn) = &qualification.live_turn {
                validate_provider_accounting_for_turn(turn)?;
                require_digest(
                    "durable live-provider turn",
                    &turn.turn_digest,
                    &live_provider_turn_digest(turn)?,
                )?;
            }
            if let Some(replay) = &qualification.replay {
                require_digest(
                    "durable provider replay",
                    &replay.replay_digest,
                    &provider_replay_digest(replay)?,
                )?;
            }
            if qualification.status == ProviderQualificationStatus::Qualified {
                let turn = qualification.live_turn.as_ref().ok_or_else(|| {
                    ReproductionError::StateIntegrity(
                        "qualified provider record has no live turn".to_string(),
                    )
                })?;
                let replay = qualification.replay.as_ref().ok_or_else(|| {
                    ReproductionError::StateIntegrity(
                        "qualified provider record has no offline replay".to_string(),
                    )
                })?;
                if qualification.failure.is_some()
                    || replay.network_used
                    || turn.request_digest != qualification.request_digest
                    || turn.configuration_fingerprint != qualification.configuration_fingerprint
                    || turn.replay_capsule_digest != qualification.replay_capsule_digest
                    || turn.normalized_parser_input_bytes
                        != turn.transcript.redacted_response.as_bytes()
                    || turn.parsed_intent.intent_digest()?
                        != replay.parsed_intent.intent_digest()?
                {
                    return Err(ReproductionError::StateIntegrity(
                        "qualified provider record does not contain matching live and offline evidence"
                            .to_string(),
                    ));
                }
            }
        }
        let mut stop_ids = BTreeSet::new();
        let mut stopped_cycle_ids = BTreeSet::new();
        for stop in &self.stop_conditions {
            validate_identifier("stop condition id", &stop.stop_id)?;
            if !stop_ids.insert(stop.stop_id.as_str()) {
                return Err(ReproductionError::StateIntegrity(
                    "stop condition ids must be unique".to_string(),
                ));
            }
            if !stopped_cycle_ids.insert(stop.requested_cycle_id.as_str()) {
                return Err(ReproductionError::StateIntegrity(
                    "a cycle id may have only one terminal stop condition".to_string(),
                ));
            }
            let intent = self
                .cycle_intents
                .iter()
                .find(|intent| intent.cycle_id == stop.requested_cycle_id)
                .ok_or_else(|| {
                    ReproductionError::StateIntegrity(
                        "stop condition has no immutable cycle intent".to_string(),
                    )
                })?;
            let package = self
                .package_index
                .get(stop.active_package_digest.as_str())
                .ok_or_else(|| {
                    ReproductionError::StateIntegrity(
                        "stop condition references an absent package".to_string(),
                    )
                })?;
            if stop.active_package_digest != intent.expected_active_package_digest
                || stop.generation != package.generation
            {
                return Err(ReproductionError::StateIntegrity(
                    "stop condition differs from its immutable cycle intent".to_string(),
                ));
            }
            require_digest(
                "stop condition record",
                &stop.record_digest,
                &stop_condition_record_digest(stop)?,
            )?;
        }
        if let Some(pending) = &self.in_flight {
            validate_identifier("pending cycle id", &pending.cycle_id)?;
            if !self
                .package_index
                .contains_key(pending.incumbent_package_digest.as_str())
                || !self
                    .package_index
                    .contains_key(pending.challenger_package_digest.as_str())
            {
                return Err(ReproductionError::StateIntegrity(
                    "pending effect references an absent package".to_string(),
                ));
            }
        }
        require_digest(
            "reproduction state",
            &self.state_digest,
            &reproduction_state_digest(self)?,
        )
    }
}

fn reproduction_state_digest(
    state: &ReproductionState,
) -> Result<ContentDigest, ReproductionError> {
    reproduction_state_digest_in_domain(state, "wasm-biotic:factory-reproduction-state:v6")
}

fn reproduction_state_digest_in_domain(
    state: &ReproductionState,
    domain: &'static str,
) -> Result<ContentDigest, ReproductionError> {
    let mut material = state.clone();
    material.state_digest = ContentDigest::from_bytes(&[]);
    digest_serializable(&(domain, material))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyReproductionStateV1 {
    schema_version: u32,
    factory_id: String,
    release_gate: ReleaseGate,
    active_package_digest: ContentDigest,
    active_generation: u32,
    active_state_schema: u32,
    retained_incumbent: Option<RetainedIncumbent>,
    package_index: BTreeMap<String, PackageIndexRecord>,
    cycles: Vec<CycleRecord>,
    lineage: Vec<FactoryLineageRecord>,
    generation_initiations: Vec<GenerationInitiationRecord>,
    instruction_uses: BTreeMap<String, u32>,
    quarantines: Vec<QuarantineRecord>,
    in_flight: Option<PendingEffect>,
}

impl LegacyReproductionStateV1 {
    fn migrate(self) -> Result<ReproductionState, ReproductionError> {
        if self.schema_version != 1 {
            return Err(ReproductionError::UnsupportedStateSchema(
                self.schema_version,
            ));
        }
        if !self.cycles.is_empty()
            || !self.generation_initiations.is_empty()
            || !self.instruction_uses.is_empty()
            || self.in_flight.is_some()
        {
            return Err(ReproductionError::StateIntegrity(
                "legacy state with executed cycles cannot be upgraded without immutable cycle intents"
                    .to_string(),
            ));
        }
        let mut migrated = ReproductionState {
            schema_version: REPRODUCTION_STATE_SCHEMA_VERSION,
            factory_id: self.factory_id,
            release_gate: self.release_gate,
            active_package_digest: self.active_package_digest,
            active_generation: self.active_generation,
            active_state_schema: self.active_state_schema,
            retained_incumbent: self.retained_incumbent,
            package_index: self.package_index,
            cycle_intents: Vec::new(),
            prepared_successors: Vec::new(),
            cycles: self.cycles,
            lineage: self.lineage,
            generation_initiations: self.generation_initiations,
            instruction_uses: self.instruction_uses,
            quarantines: self.quarantines,
            operator_rollbacks: Vec::new(),
            recovery_receipts: Vec::new(),
            provider_qualifications: Vec::new(),
            stop_conditions: Vec::new(),
            in_flight: self.in_flight,
            state_digest: ContentDigest::from_bytes(&[]),
        };
        migrated.seal()?;
        migrated.validate()?;
        Ok(migrated)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EngineSchemaMigrationIntent {
    from_schema: u32,
    to_schema: u32,
    source_digest: ContentDigest,
    backup_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeedCycleRequest {
    pub cycle_id: String,
    pub expected_active_package_digest: ContentDigest,
    pub expected_gate_digest: ContentDigest,
    pub genome: MutableGenome,
    pub state_compatibility: StateCompatibility,
    pub migration_plan: Option<StateMigrationPlan>,
    pub operator_context_digest: ContentDigest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdoptedSuccessorRequest {
    pub cycle_id: String,
    pub expected_active_package_digest: ContentDigest,
    pub expected_gate_digest: ContentDigest,
    pub migration_plan: Option<StateMigrationPlan>,
    pub operator_context_digest: ContentDigest,
}

/// Exact, restart-safe output of the active N+1 driver and governed M4
/// materialization. Callers may authorize `successor_package` only after this
/// record exists, then pass the same record to
/// [`FactoryReproductionEngine::complete_prepared_successor_cycle`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedSuccessorCycle {
    pub cycle_id: String,
    pub intent_digest: ContentDigest,
    pub instruction_use_key: String,
    pub instruction_use_number: u32,
    pub executor_package_digest: ContentDigest,
    pub executor_package_bytes_digest: ContentDigest,
    pub successor_genome: MutableGenome,
    pub successor_package: FactoryPackage,
    pub initiation: GenerationInitiationRecord,
    pub state_compatibility: StateCompatibility,
    pub migration_plan: Option<StateMigrationPlan>,
    pub operator_context_digest: ContentDigest,
    pub preparation_digest: ContentDigest,
}

impl PreparedSuccessorCycle {
    fn seal(&mut self) -> Result<(), ReproductionError> {
        self.validate_fields()?;
        self.preparation_digest = prepared_successor_digest(self)?;
        Ok(())
    }

    fn validate(&self) -> Result<(), ReproductionError> {
        self.validate_fields()?;
        require_digest(
            "prepared successor",
            &self.preparation_digest,
            &prepared_successor_digest(self)?,
        )
    }

    fn validate_fields(&self) -> Result<(), ReproductionError> {
        validate_identifier("prepared successor cycle id", &self.cycle_id)?;
        if self.instruction_use_key.trim().is_empty() || self.instruction_use_number == 0 {
            return Err(ReproductionError::StateIntegrity(
                "prepared successor has an invalid instruction-use identity".to_string(),
            ));
        }
        self.successor_genome.validate()?;
        self.successor_package.validate()?;
        self.initiation.validate()?;
        self.state_compatibility.validate()?;
        if let Some(plan) = &self.migration_plan {
            plan.validate()?;
        }
        if self.executor_package_digest != self.initiation.executor_package_digest
            || self.executor_package_bytes_digest != self.initiation.executor_package_bytes_digest
            || self.successor_genome.genome_digest != self.initiation.successor_genome_digest
            || self.successor_package.payload.genome != self.successor_genome
            || self
                .successor_package
                .payload
                .parent_package_digest
                .as_ref()
                != Some(&self.executor_package_digest)
            || self.successor_package.payload.generation
                != self.initiation.driver_request.next_generation
            || self.successor_genome.component_bytes
                != self
                    .initiation
                    .materialization_evidence
                    .successor_component_bytes
        {
            return Err(ReproductionError::StateIntegrity(
                "prepared successor package is not the exact materialized child".to_string(),
            ));
        }
        Ok(())
    }
}

fn prepared_successor_digest(
    prepared: &PreparedSuccessorCycle,
) -> Result<ContentDigest, ReproductionError> {
    digest_serializable(&(
        "wasm-biotic:prepared-successor-cycle:v1",
        &prepared.cycle_id,
        &prepared.intent_digest,
        &prepared.instruction_use_key,
        prepared.instruction_use_number,
        &prepared.executor_package_digest,
        &prepared.executor_package_bytes_digest,
        &prepared.successor_genome,
        &prepared.successor_package,
        &prepared.initiation,
        &prepared.state_compatibility,
        &prepared.migration_plan,
        &prepared.operator_context_digest,
    ))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrepareSuccessorOutcome {
    Prepared(PreparedSuccessorCycle),
    Stopped(StopConditionRecord),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CycleOutcome {
    Adopted {
        package_digest: ContentDigest,
        cycle_record_digest: ContentDigest,
    },
    GateRejected {
        package_digest: ContentDigest,
        cycle_record_digest: ContentDigest,
    },
    ApprovalRejected {
        package_digest: ContentDigest,
        cycle_record_digest: ContentDigest,
    },
    QuarantinedAndRolledBack {
        package_digest: ContentDigest,
        restored_package_digest: ContentDigest,
        cycle_record_digest: ContentDigest,
    },
    Stopped(StopConditionRecord),
}

pub struct FactoryReproductionEngine {
    canonical_root: PathBuf,
    package_directory: PathBuf,
    state: ReproductionState,
    ports: ReproductionPorts,
    _owner_lock: File,
}

impl FactoryReproductionEngine {
    pub fn initialize(
        root: impl AsRef<Path>,
        factory_id: impl Into<String>,
        incumbent: FactoryPackage,
        release_gate: ReleaseGate,
        ports: ReproductionPorts,
    ) -> Result<Self, ReproductionError> {
        let (canonical_root, package_directory) = prepare_root(root.as_ref())?;
        let owner_lock = acquire_engine_owner_lock(&canonical_root)?;
        let state_path = canonical_root.join(STATE_FILE_NAME);
        if state_path.exists() {
            return Err(ReproductionError::AlreadyInitialized);
        }
        let factory_id = factory_id.into();
        validate_identifier("factory id", &factory_id)?;
        incumbent.validate()?;
        release_gate.validate()?;
        if incumbent.payload.factory_id != factory_id {
            return Err(ReproductionError::InvalidPackage(
                "incumbent package factory id differs from engine factory id".to_string(),
            ));
        }
        if incumbent.payload.generation != 0 || incumbent.payload.parent_package_digest.is_some() {
            return Err(ReproductionError::InvalidPackage(
                "initial incumbent must be generation zero without a parent".to_string(),
            ));
        }
        if incumbent.byte_len
            > release_gate.budgets.max_component_bytes + MAX_TEXT_BYTES as u64 * 16
        {
            return Err(ReproductionError::BudgetExceeded(
                "initial package is outside the declared package envelope".to_string(),
            ));
        }
        if incumbent.payload.genome.component_bytes.len() as u64
            > release_gate.budgets.max_component_bytes
        {
            return Err(ReproductionError::BudgetExceeded(
                "initial component exceeds the release-gate component budget".to_string(),
            ));
        }
        let active_state_schema = incumbent
            .payload
            .boot_manifest
            .state_compatibility
            .written_schema;
        let package_record = persist_package_to(&package_directory, &incumbent)?;
        let root_lineage = FactoryLineageRecord::new(
            "lineage:root",
            0,
            None,
            &incumbent,
            None,
            None,
            LineageDisposition::Root,
            active_state_schema,
            active_state_schema,
            None,
        )?;
        let mut package_index = BTreeMap::new();
        package_index.insert(
            incumbent.package_digest.as_str().to_string(),
            package_record,
        );
        let mut state = ReproductionState {
            schema_version: REPRODUCTION_STATE_SCHEMA_VERSION,
            factory_id,
            release_gate,
            active_package_digest: incumbent.package_digest,
            active_generation: 0,
            active_state_schema,
            retained_incumbent: None,
            package_index,
            cycle_intents: Vec::new(),
            prepared_successors: Vec::new(),
            cycles: Vec::new(),
            lineage: vec![root_lineage],
            generation_initiations: Vec::new(),
            instruction_uses: BTreeMap::new(),
            quarantines: Vec::new(),
            operator_rollbacks: Vec::new(),
            recovery_receipts: Vec::new(),
            provider_qualifications: Vec::new(),
            stop_conditions: Vec::new(),
            in_flight: None,
            state_digest: ContentDigest::from_bytes(&[]),
        };
        state.seal()?;
        atomic_write_json(&state_path, &state)?;
        Ok(Self {
            canonical_root,
            package_directory,
            state,
            ports,
            _owner_lock: owner_lock,
        })
    }

    pub fn open(
        root: impl AsRef<Path>,
        ports: ReproductionPorts,
    ) -> Result<Self, ReproductionError> {
        let (canonical_root, package_directory) = prepare_root(root.as_ref())?;
        let owner_lock = acquire_engine_owner_lock(&canonical_root)?;
        recover_or_migrate_engine_state(&canonical_root)?;
        let state_path = canonical_root.join(STATE_FILE_NAME);
        if !state_path.exists() {
            return Err(ReproductionError::NotInitialized);
        }
        let state: ReproductionState = read_json(&state_path)?;
        state.validate()?;
        verify_package_index(&package_directory, &state)?;
        let mut engine = Self {
            canonical_root,
            package_directory,
            state,
            ports,
            _owner_lock: owner_lock,
        };
        engine.validate_causal_evidence_against_packages()?;
        engine.recover_pending_effect()?;
        Ok(engine)
    }

    pub fn state(&self) -> &ReproductionState {
        &self.state
    }

    pub fn active_package(&self) -> Result<FactoryPackage, ReproductionError> {
        self.load_package(&self.state.active_package_digest)
    }

    pub fn package(&self, digest: &ContentDigest) -> Result<FactoryPackage, ReproductionError> {
        self.load_package(digest)
    }

    /// Durably records the complete seeded-cycle input before any external
    /// recipe, migration, supervisor, provider, or capability call is made.
    ///
    /// Repeating the exact request returns the already-recorded intent.
    /// Reusing the cycle id for any different immutable input is rejected.
    pub fn record_seeded_cycle_intent(
        &mut self,
        request: &SeedCycleRequest,
    ) -> Result<CycleIntent, ReproductionError> {
        let intent = self.seeded_cycle_intent(request)?;
        request.genome.validate()?;
        if request.genome.parent_package_digest.as_ref()
            != Some(&intent.expected_active_package_digest)
        {
            return Err(ReproductionError::ParentMismatch {
                expected: intent.expected_active_package_digest.clone(),
                actual: request.genome.parent_package_digest.clone(),
            });
        }
        self.record_cycle_intent(intent.clone())?;
        Ok(intent)
    }

    /// Resolve an exact, already-terminal seeded cycle without mutating engine
    /// state or invoking any reproduction port.
    ///
    /// The request is reconstructed against the package named by its durable
    /// cycle intent, so a caller can replay an adopted cycle even after the
    /// active package has advanced. Reusing the cycle id for different input
    /// remains a conflict.
    pub fn terminal_seeded_cycle_replay(
        &self,
        request: &SeedCycleRequest,
    ) -> Result<Option<CycleOutcome>, ReproductionError> {
        let intent = self.seeded_cycle_intent(request)?;
        self.terminal_cycle_replay(&intent)
    }

    pub fn run_seeded_cycle(
        &mut self,
        request: SeedCycleRequest,
    ) -> Result<CycleOutcome, ReproductionError> {
        let intent = self.seeded_cycle_intent(&request)?;
        if let Some(outcome) = self.terminal_cycle_replay(&intent)? {
            return Ok(outcome);
        }
        self.ensure_ready_for_cycle(
            &request.cycle_id,
            &request.expected_active_package_digest,
            &request.expected_gate_digest,
        )?;
        request.genome.validate()?;
        if request.genome.parent_package_digest.as_ref() != Some(&self.state.active_package_digest)
        {
            return Err(ReproductionError::ParentMismatch {
                expected: self.state.active_package_digest.clone(),
                actual: request.genome.parent_package_digest.clone(),
            });
        }
        self.record_cycle_intent(intent)?;
        self.run_cycle(
            request.cycle_id,
            request.genome,
            request.state_compatibility,
            request.migration_plan,
            request.operator_context_digest,
            None,
        )
    }

    /// Execute the active successor's fixed generation driver, materialize its
    /// directive through M4, and durably retain the exact package preview.
    ///
    /// No approval port is called here. This gives the caller the exact package
    /// bytes needed to arrange authorization before completion.
    pub fn prepare_adopted_successor_cycle(
        &mut self,
        request: AdoptedSuccessorRequest,
    ) -> Result<PrepareSuccessorOutcome, ReproductionError> {
        self.ensure_expected_boundary(
            &request.cycle_id,
            &request.expected_active_package_digest,
            &request.expected_gate_digest,
        )?;
        let executor = self.active_package()?;
        let intent = CycleIntent::adopted(&request, &executor, &self.state.release_gate)?;
        if let Some(prepared) = self
            .state
            .prepared_successors
            .iter()
            .find(|prepared| prepared.cycle_id == request.cycle_id)
            .cloned()
        {
            self.record_cycle_intent(intent.clone())?;
            prepared.validate()?;
            if prepared.intent_digest != intent.intent_digest {
                return Err(ReproductionError::DuplicateCycleId(request.cycle_id));
            }
            return Ok(PrepareSuccessorOutcome::Prepared(prepared));
        }
        self.ensure_ready_for_cycle(
            &request.cycle_id,
            &request.expected_active_package_digest,
            &request.expected_gate_digest,
        )?;
        // This is the write-ahead boundary for every driver or worker call.
        self.record_cycle_intent(intent.clone())?;

        let stop_reason = if executor.payload.generation
            >= self.state.release_gate.budgets.max_generation_depth
        {
            Some(StopReason::GenerationDepthExhausted)
        } else if self.state.cycles.len() as u32 >= self.state.release_gate.budgets.max_total_cycles
        {
            Some(StopReason::TotalCycleBudgetExhausted)
        } else if !executor.payload.genome.policy.generation_enabled {
            Some(StopReason::GenerationDisabled)
        } else if executor
            .payload
            .genome
            .policy
            .generation_instruction
            .is_none()
        {
            Some(StopReason::MissingInstruction)
        } else {
            None
        };
        if let Some(reason) = stop_reason {
            return match self.record_stop(&request.cycle_id, reason)? {
                CycleOutcome::Stopped(record) => Ok(PrepareSuccessorOutcome::Stopped(record)),
                _ => Err(ReproductionError::StateIntegrity(
                    "generation stop did not produce a stop record".to_string(),
                )),
            };
        }

        let instruction = executor
            .payload
            .genome
            .policy
            .generation_instruction
            .as_ref()
            .ok_or_else(|| {
                ReproductionError::StateIntegrity(
                    "enabled generation policy lost its driver instruction".to_string(),
                )
            })?
            .clone();
        let instruction_digest = instruction.instruction_digest()?;
        let use_key = instruction_use_key(&executor.package_digest, &instruction_digest);
        let uses = self
            .state
            .instruction_uses
            .get(&use_key)
            .copied()
            .unwrap_or(0);
        if uses >= instruction.max_executions {
            return match self.record_stop(
                &request.cycle_id,
                StopReason::InstructionExecutionBudgetExhausted,
            )? {
                CycleOutcome::Stopped(record) => Ok(PrepareSuccessorOutcome::Stopped(record)),
                _ => Err(ReproductionError::StateIntegrity(
                    "instruction budget stop did not produce a stop record".to_string(),
                )),
            };
        }

        let driver_request = GenerationDriverRequest::new(
            &request.cycle_id,
            &executor,
            &instruction,
            &self.state.release_gate,
            &intent.execution_policy,
        )?;
        let driver_evidence = self
            .ports
            .m3_capability
            .execute_generation_driver(&driver_request)
            .map_err(|failure| ReproductionError::port("m3_generation_driver", failure))?;
        validate_generation_driver_evidence(&driver_request, &driver_evidence)?;

        let materialization_request = GenerationMaterializationRequest::new(
            &driver_request,
            &driver_evidence,
            self.state.release_gate.budgets.max_component_bytes,
            &intent.execution_policy,
        )?;
        let materialization_evidence = self
            .ports
            .m4_workers
            .materialize_generation(&materialization_request)
            .map_err(|failure| ReproductionError::port("m4_generation_materialization", failure))?;
        validate_generation_materialization_evidence(
            &driver_request,
            &driver_evidence,
            &materialization_request,
            &materialization_evidence,
        )?;

        let successor_policy = MutableFactoryPolicy::terminal(
            instruction.successor_policy_revision,
            executor.payload.genome.policy.max_canary_tasks,
        );
        let successor_genome = MutableGenome::new(
            Some(executor.package_digest.clone()),
            materialization_evidence.successor_component_bytes.clone(),
            successor_policy,
        )?;
        let successor_package = self.preview_successor_package(
            &executor,
            successor_genome.clone(),
            executor.payload.boot_manifest.state_compatibility.clone(),
        )?;
        let initiation = GenerationInitiationRecord::new(
            &request.cycle_id,
            &driver_request,
            &driver_evidence,
            &materialization_request,
            &materialization_evidence,
            &successor_genome,
        )?;
        let mut prepared = PreparedSuccessorCycle {
            cycle_id: request.cycle_id.clone(),
            intent_digest: intent.intent_digest,
            instruction_use_key: use_key.clone(),
            instruction_use_number: uses + 1,
            executor_package_digest: executor.package_digest.clone(),
            executor_package_bytes_digest: ContentDigest::from_bytes(&executor.canonical_bytes()?),
            successor_genome,
            successor_package,
            initiation: initiation.clone(),
            state_compatibility: executor.payload.boot_manifest.state_compatibility.clone(),
            migration_plan: request.migration_plan,
            operator_context_digest: request.operator_context_digest,
            preparation_digest: ContentDigest::from_bytes(&[]),
        };
        prepared.seal()?;
        self.state.instruction_uses.insert(use_key, uses + 1);
        self.state.generation_initiations.push(initiation);
        self.state.prepared_successors.push(prepared.clone());
        self.persist_state()?;
        Ok(PrepareSuccessorOutcome::Prepared(prepared))
    }

    /// Complete the exact durable preparation after its successor package has
    /// received exact-byte authorization.
    pub fn complete_prepared_successor_cycle(
        &mut self,
        request: AdoptedSuccessorRequest,
        prepared: &PreparedSuccessorCycle,
    ) -> Result<CycleOutcome, ReproductionError> {
        let intent = self.adopted_cycle_intent(&request)?;
        if let Some(outcome) = self.terminal_cycle_replay(&intent)? {
            prepared.validate()?;
            if prepared.cycle_id != request.cycle_id
                || prepared.intent_digest != intent.intent_digest
                || prepared.migration_plan != request.migration_plan
                || prepared.operator_context_digest != request.operator_context_digest
            {
                return Err(ReproductionError::EvidenceMismatch(
                    "replayed completion differs from the exact prepared cycle intent".to_string(),
                ));
            }
            return Ok(outcome);
        }
        self.ensure_expected_boundary(
            &request.cycle_id,
            &request.expected_active_package_digest,
            &request.expected_gate_digest,
        )?;
        prepared.validate()?;
        let durable = self
            .state
            .prepared_successors
            .iter()
            .find(|candidate| candidate.cycle_id == request.cycle_id)
            .cloned()
            .ok_or_else(|| {
                ReproductionError::StateIntegrity(format!(
                    "cycle '{}' has no durable prepared successor",
                    request.cycle_id
                ))
            })?;
        if &durable != prepared {
            return Err(ReproductionError::EvidenceMismatch(
                "supplied prepared successor differs from durable preparation".to_string(),
            ));
        }
        let executor = self.active_package()?;
        if prepared.intent_digest != intent.intent_digest
            || prepared.executor_package_digest != executor.package_digest
            || prepared.migration_plan != request.migration_plan
            || prepared.operator_context_digest != request.operator_context_digest
        {
            return Err(ReproductionError::EvidenceMismatch(
                "completion request differs from the exact prepared cycle intent".to_string(),
            ));
        }
        let expected_package = self.preview_successor_package(
            &executor,
            prepared.successor_genome.clone(),
            prepared.state_compatibility.clone(),
        )?;
        if expected_package != prepared.successor_package {
            return Err(ReproductionError::EvidenceMismatch(
                "prepared package is not the deterministic successor preview".to_string(),
            ));
        }
        let outcome = self.run_cycle(
            request.cycle_id.clone(),
            prepared.successor_genome.clone(),
            prepared.state_compatibility.clone(),
            request.migration_plan,
            request.operator_context_digest,
            Some(prepared.initiation.clone()),
        )?;
        self.state
            .prepared_successors
            .retain(|candidate| candidate.cycle_id != request.cycle_id);
        self.persist_state()?;
        Ok(outcome)
    }

    pub fn run_adopted_successor_cycle(
        &mut self,
        request: AdoptedSuccessorRequest,
    ) -> Result<CycleOutcome, ReproductionError> {
        let intent = self.adopted_cycle_intent(&request)?;
        if let Some(outcome) = self.terminal_cycle_replay(&intent)? {
            return Ok(outcome);
        }
        match self.prepare_adopted_successor_cycle(request.clone())? {
            PrepareSuccessorOutcome::Stopped(record) => Ok(CycleOutcome::Stopped(record)),
            PrepareSuccessorOutcome::Prepared(prepared) => {
                self.complete_prepared_successor_cycle(request, &prepared)
            }
        }
    }

    /// Resolve an exact, already-terminal adopted-successor cycle without
    /// mutating engine state or invoking its driver, worker, or effect ports.
    pub fn terminal_adopted_successor_cycle_replay(
        &self,
        request: &AdoptedSuccessorRequest,
    ) -> Result<Option<CycleOutcome>, ReproductionError> {
        let intent = self.adopted_cycle_intent(request)?;
        self.terminal_cycle_replay(&intent)
    }

    pub fn qualify_live_provider(
        &mut self,
        request: ProviderQualificationRequest,
    ) -> Result<LiveProviderQualificationRecord, ReproductionError> {
        request.validate()?;
        if self
            .state
            .provider_qualifications
            .iter()
            .any(|record| record.qualification_id == request.qualification_id)
        {
            return Err(ReproductionError::InvalidConfiguration(format!(
                "provider qualification id '{}' is already recorded",
                request.qualification_id
            )));
        }
        if request.package_digest != self.state.active_package_digest {
            return Err(ReproductionError::ActivePackageMismatch {
                expected: self.state.active_package_digest.clone(),
                actual: request.package_digest,
            });
        }
        if self.state.provider_qualifications.len() as u32
            >= self.state.release_gate.budgets.max_provider_turns
        {
            return Err(ReproductionError::BudgetExceeded(
                "live-provider qualification turn budget exhausted".to_string(),
            ));
        }
        let configuration_fingerprint = request.configuration.fingerprint()?;
        let Some(port) = self.ports.live_provider.as_ref() else {
            let record = LiveProviderQualificationRecord {
                schema: LIVE_PROVIDER_QUALIFICATION_SCHEMA.to_string(),
                qualification_id: request.qualification_id,
                package_digest: request.package_digest,
                target_digest: request.target_digest,
                replay_capsule_digest: request.replay_capsule.capsule_digest,
                configuration_fingerprint,
                request_digest: request.request_digest,
                status: ProviderQualificationStatus::Unavailable,
                live_turn: None,
                replay: None,
                failure: Some(PortFailure::unavailable(
                    "live_provider_not_configured",
                    "no live-provider qualification port is configured",
                )),
                record_digest: ContentDigest::from_bytes(&[]),
            }
            .seal()?;
            self.state.provider_qualifications.push(record.clone());
            self.persist_state()?;
            return Ok(record);
        };
        let turn = match port.perform_live_turn(&request) {
            Ok(turn) => turn,
            Err(failure) => {
                let status = if failure.kind == PortFailureKind::Unavailable {
                    ProviderQualificationStatus::Unavailable
                } else {
                    ProviderQualificationStatus::LiveTurnFailed
                };
                let record = LiveProviderQualificationRecord {
                    schema: LIVE_PROVIDER_QUALIFICATION_SCHEMA.to_string(),
                    qualification_id: request.qualification_id,
                    package_digest: request.package_digest,
                    target_digest: request.target_digest,
                    replay_capsule_digest: request.replay_capsule.capsule_digest,
                    configuration_fingerprint,
                    request_digest: request.request_digest,
                    status,
                    live_turn: None,
                    replay: None,
                    failure: Some(failure),
                    record_digest: ContentDigest::from_bytes(&[]),
                }
                .seal()?;
                self.state.provider_qualifications.push(record.clone());
                self.persist_state()?;
                return Ok(record);
            }
        };
        if let Err(error) = validate_live_turn(&request, &turn) {
            let record = LiveProviderQualificationRecord {
                schema: LIVE_PROVIDER_QUALIFICATION_SCHEMA.to_string(),
                qualification_id: request.qualification_id,
                package_digest: request.package_digest,
                target_digest: request.target_digest,
                replay_capsule_digest: request.replay_capsule.capsule_digest,
                configuration_fingerprint,
                request_digest: request.request_digest,
                status: ProviderQualificationStatus::InvalidLiveEvidence,
                live_turn: Some(turn),
                replay: None,
                failure: Some(PortFailure::failed(
                    "invalid_live_evidence",
                    error.to_string(),
                )),
                record_digest: ContentDigest::from_bytes(&[]),
            }
            .seal()?;
            self.state.provider_qualifications.push(record.clone());
            self.persist_state()?;
            return Ok(record);
        }
        let replay_request = ProviderReplayRequest::new(&request, &turn)?;
        let replay = match port.replay_offline(&replay_request) {
            Ok(replay) => replay,
            Err(failure) => {
                let record = LiveProviderQualificationRecord {
                    schema: LIVE_PROVIDER_QUALIFICATION_SCHEMA.to_string(),
                    qualification_id: request.qualification_id,
                    package_digest: request.package_digest,
                    target_digest: request.target_digest,
                    replay_capsule_digest: request.replay_capsule.capsule_digest,
                    configuration_fingerprint,
                    request_digest: request.request_digest,
                    status: ProviderQualificationStatus::ReplayFailed,
                    live_turn: Some(turn),
                    replay: None,
                    failure: Some(failure),
                    record_digest: ContentDigest::from_bytes(&[]),
                }
                .seal()?;
                self.state.provider_qualifications.push(record.clone());
                self.persist_state()?;
                return Ok(record);
            }
        };
        let replay_matches = validate_provider_replay(&replay_request, &replay).is_ok()
            && replay.parsed_intent.intent_digest()? == turn.parsed_intent.intent_digest()?;
        let record = LiveProviderQualificationRecord {
            schema: LIVE_PROVIDER_QUALIFICATION_SCHEMA.to_string(),
            qualification_id: request.qualification_id,
            package_digest: request.package_digest,
            target_digest: request.target_digest,
            replay_capsule_digest: request.replay_capsule.capsule_digest,
            configuration_fingerprint,
            request_digest: request.request_digest,
            status: if replay_matches {
                ProviderQualificationStatus::Qualified
            } else {
                ProviderQualificationStatus::ReplayMismatch
            },
            live_turn: Some(turn),
            replay: Some(replay),
            failure: None,
            record_digest: ContentDigest::from_bytes(&[]),
        }
        .seal()?;
        self.state.provider_qualifications.push(record.clone());
        self.persist_state()?;
        Ok(record)
    }

    pub fn operator_revert_active(
        &mut self,
        rollback_id: impl Into<String>,
        expected_active_package_digest: &ContentDigest,
        reason_ref: impl Into<String>,
    ) -> Result<OperatorRollbackRecord, ReproductionError> {
        if self.state.in_flight.is_some() {
            return Err(ReproductionError::RecoveryRequired);
        }
        if &self.state.active_package_digest != expected_active_package_digest {
            return Err(ReproductionError::ActivePackageMismatch {
                expected: self.state.active_package_digest.clone(),
                actual: expected_active_package_digest.clone(),
            });
        }
        let rollback_id = rollback_id.into();
        let reason_ref = reason_ref.into();
        validate_identifier("rollback id", &rollback_id)?;
        validate_identifier("rollback reason ref", &reason_ref)?;
        let retained = self
            .state
            .retained_incumbent
            .clone()
            .ok_or(ReproductionError::NoRetainedIncumbent)?;
        let from_digest = self.state.active_package_digest.clone();
        let pending = PendingEffect {
            cycle_id: rollback_id.clone(),
            incumbent_package_digest: retained.package_digest.clone(),
            challenger_package_digest: from_digest.clone(),
            incumbent_state_schema: retained.state_schema,
            target_state_schema: self.state.active_state_schema,
            stage: PendingStage::RollbackRequested,
            migration_receipt: None,
            activation_receipt: None,
        };
        self.state.in_flight = Some(pending.clone());
        self.persist_state()?;
        let recovery = self.perform_recovery(&pending, format!("operator:{reason_ref}"))?;
        let restored = self.load_package(&retained.package_digest)?;
        self.state.active_package_digest = retained.package_digest.clone();
        self.state.active_generation = restored.payload.generation;
        self.state.active_state_schema = retained.state_schema;
        self.state.retained_incumbent = None;
        self.state.in_flight = None;
        self.state.recovery_receipts.push(recovery.clone());
        let record = OperatorRollbackRecord {
            rollback_id: rollback_id.clone(),
            from_package_digest: from_digest,
            restored_package_digest: retained.package_digest.clone(),
            reason_ref,
            recovery_receipt: recovery.clone(),
            record_digest: ContentDigest::from_bytes(&[]),
        }
        .seal()?;
        self.state.operator_rollbacks.push(record.clone());
        let lineage = FactoryLineageRecord::new(
            format!("lineage:rollback:{rollback_id}"),
            restored.payload.generation,
            restored.payload.parent_package_digest.clone(),
            &restored,
            None,
            None,
            LineageDisposition::OperatorRollback,
            pending.target_state_schema,
            pending.incumbent_state_schema,
            Some(recovery.receipt_digest),
        )?;
        self.state.lineage.push(lineage);
        self.persist_state()?;
        Ok(record)
    }

    #[allow(clippy::too_many_arguments)]
    fn run_cycle(
        &mut self,
        cycle_id: String,
        genome: MutableGenome,
        state_compatibility: StateCompatibility,
        migration_plan: Option<StateMigrationPlan>,
        operator_context_digest: ContentDigest,
        initiation: Option<GenerationInitiationRecord>,
    ) -> Result<CycleOutcome, ReproductionError> {
        let incumbent = self.active_package()?;
        let next_generation = incumbent.payload.generation.checked_add(1).ok_or_else(|| {
            ReproductionError::BudgetExceeded("generation counter overflow".to_string())
        })?;
        if next_generation > self.state.release_gate.budgets.max_generation_depth {
            return self.record_stop(&cycle_id, StopReason::GenerationDepthExhausted);
        }
        if genome.component_bytes.len() as u64 > self.state.release_gate.budgets.max_component_bytes
        {
            return Err(ReproductionError::BudgetExceeded(
                "candidate component exceeds the predeclared budget".to_string(),
            ));
        }
        validate_state_transition(
            self.state.active_state_schema,
            &incumbent.payload.boot_manifest.state_compatibility,
            &state_compatibility,
            migration_plan.as_ref(),
            &self.state.release_gate.budgets,
        )?;
        let m1_request =
            M1BuildRequest::new(&cycle_id, &genome, &incumbent.payload.stable_interface)?;
        let m1_evidence = self
            .ports
            .m1_candidate
            .build_and_prove(&m1_request)
            .map_err(|failure| ReproductionError::port("m1_candidate", failure))?;
        validate_m1_evidence(&m1_request, &m1_evidence)?;
        let challenger = FactoryPackage::build(
            self.state.factory_id.clone(),
            next_generation,
            genome,
            incumbent.payload.stable_interface.clone(),
            incumbent.payload.worker_catalog.clone(),
            incumbent.payload.service_dependencies.clone(),
            state_compatibility,
        )?;
        let package_record = persist_package_to(&self.package_directory, &challenger)?;
        self.state.package_index.insert(
            challenger.package_digest.as_str().to_string(),
            package_record,
        );
        self.persist_state()?;

        let worker_request = WorkerWorkflowRequest::new(
            &cycle_id,
            &incumbent.package_digest,
            &challenger,
            &self.state.release_gate,
        )?;
        let worker_evidence = self
            .ports
            .m4_workers
            .execute_workflow(&worker_request)
            .map_err(|failure| ReproductionError::port("m4_worker_workflow", failure))?;
        validate_worker_evidence(&worker_request, &worker_evidence)?;

        let shadow_request = ShadowExecutionRequest::new(
            &cycle_id,
            &incumbent,
            &challenger,
            &self.state.release_gate,
        )?;
        let shadow_evidence = self
            .ports
            .m3_capability
            .run_shadow(&shadow_request)
            .map_err(|failure| ReproductionError::port("m3_shadow", failure))?;
        let gate_decision =
            evaluate_shadow_evidence(&shadow_request, &shadow_evidence, &self.state.release_gate)?;
        let challenger_bytes_digest = ContentDigest::from_bytes(&challenger.canonical_bytes()?);
        let mut cycle = CycleRecord {
            cycle_id: cycle_id.clone(),
            generation: next_generation,
            parent_package_digest: incumbent.package_digest.clone(),
            challenger_package_digest: challenger.package_digest.clone(),
            challenger_package_bytes_digest: challenger_bytes_digest,
            genome_digest: challenger.payload.genome.genome_digest.clone(),
            gate_digest: self.state.release_gate.gate_digest.clone(),
            initiation,
            m1_evidence,
            worker_evidence,
            shadow_evidence,
            gate_decision,
            approval: None,
            migration_plan,
            migration_receipt: None,
            activation_receipt: None,
            observation_evidence: None,
            recovery_receipt: None,
            status: CycleStatus::Evaluating,
            record_digest: ContentDigest::from_bytes(&[]),
        };
        if !cycle.gate_decision.eligible {
            cycle.status = CycleStatus::GateRejected;
            cycle.seal()?;
            self.store_cycle(cycle.clone())?;
            self.append_cycle_lineage(
                &cycle,
                &challenger,
                LineageDisposition::GateRejected,
                self.state.active_state_schema,
                self.state.active_state_schema,
                None,
            )?;
            self.persist_state()?;
            return Ok(CycleOutcome::GateRejected {
                package_digest: challenger.package_digest,
                cycle_record_digest: cycle.record_digest,
            });
        }

        let approval_request = SupervisorApprovalRequest::new(
            &cycle_id,
            &incumbent.package_digest,
            &challenger,
            &self.state.release_gate,
            &cycle.gate_decision,
            &cycle.m1_evidence,
            &cycle.worker_evidence,
            &cycle.shadow_evidence,
            cycle
                .migration_plan
                .as_ref()
                .map(|plan| plan.plan_digest.clone()),
            operator_context_digest,
        )?;
        let approval = self
            .ports
            .m2_supervisor
            .decide(&approval_request)
            .map_err(|failure| ReproductionError::port("m2_supervisor", failure))?;
        validate_supervisor_approval(&approval_request, &approval)?;
        cycle.approval = Some(approval.clone());
        if approval.decision == ApprovalDecision::Rejected {
            cycle.status = CycleStatus::ApprovalRejected;
            cycle.seal()?;
            self.store_cycle(cycle.clone())?;
            self.append_cycle_lineage(
                &cycle,
                &challenger,
                LineageDisposition::ApprovalRejected,
                self.state.active_state_schema,
                self.state.active_state_schema,
                None,
            )?;
            self.persist_state()?;
            return Ok(CycleOutcome::ApprovalRejected {
                package_digest: challenger.package_digest,
                cycle_record_digest: cycle.record_digest,
            });
        }

        cycle.status = CycleStatus::Approved;
        cycle.seal()?;
        self.store_cycle(cycle.clone())?;
        let target_state_schema = challenger
            .payload
            .boot_manifest
            .state_compatibility
            .written_schema;
        let mut pending = PendingEffect {
            cycle_id: cycle_id.clone(),
            incumbent_package_digest: incumbent.package_digest.clone(),
            challenger_package_digest: challenger.package_digest.clone(),
            incumbent_state_schema: self.state.active_state_schema,
            target_state_schema,
            stage: if cycle.migration_plan.is_some() {
                PendingStage::MigrationRequested
            } else {
                PendingStage::ActivationRequested
            },
            migration_receipt: None,
            activation_receipt: None,
        };
        self.state.in_flight = Some(pending.clone());
        self.persist_state()?;

        if let Some(plan) = cycle.migration_plan.as_ref() {
            let migration_request = MigrationRequest::new(
                &cycle_id,
                &incumbent.package_digest,
                &challenger.package_digest,
                plan,
            )?;
            let migration_receipt = self
                .ports
                .m3_capability
                .migrate_state(&migration_request)
                .map_err(|failure| ReproductionError::port("m3_state_migration", failure))?;
            validate_migration_receipt(&migration_request, &migration_receipt)?;
            cycle.migration_receipt = Some(migration_receipt.clone());
            cycle.seal()?;
            self.store_cycle(cycle.clone())?;
            pending.stage = PendingStage::MigrationApplied;
            pending.migration_receipt = Some(migration_receipt);
            self.state.in_flight = Some(pending.clone());
            self.persist_state()?;
        }

        pending.stage = PendingStage::ActivationRequested;
        self.state.in_flight = Some(pending.clone());
        self.persist_state()?;
        let activation_request = ActivationRequest::new(
            &cycle_id,
            &incumbent.package_digest,
            &challenger,
            &approval,
            &cycle.gate_decision,
            target_state_schema,
        )?;
        let activation = self
            .ports
            .m3_capability
            .activate_exact(&activation_request)
            .map_err(|failure| ReproductionError::port("m3_activation", failure))?;
        validate_activation_receipt(&activation_request, &activation)?;
        cycle.activation_receipt = Some(activation.clone());
        cycle.seal()?;
        self.store_cycle(cycle.clone())?;
        pending.stage = PendingStage::Activated;
        pending.activation_receipt = Some(activation.clone());
        self.state.in_flight = Some(pending.clone());
        self.persist_state()?;

        pending.stage = PendingStage::ObservationRequested;
        self.state.in_flight = Some(pending.clone());
        self.persist_state()?;
        let observation_request = PostActivationRequest::new(
            &cycle_id,
            &activation,
            self.state
                .release_gate
                .thresholds
                .minimum_post_activation_successes,
        )?;
        let observation = self
            .ports
            .m3_capability
            .observe_active(&observation_request)
            .map_err(|failure| ReproductionError::port("m3_observation", failure))?;
        let healthy = validate_post_activation_evidence(&observation_request, &observation)?;
        cycle.observation_evidence = Some(observation.clone());
        if !healthy {
            pending.stage = PendingStage::RollbackRequested;
            self.state.in_flight = Some(pending.clone());
            self.persist_state()?;
            let recovery =
                self.perform_recovery(&pending, "post-activation task or health regression")?;
            cycle.recovery_receipt = Some(recovery.clone());
            cycle.status = CycleStatus::QuarantinedAndRolledBack;
            cycle.seal()?;
            self.store_cycle(cycle.clone())?;
            let quarantine = QuarantineRecord {
                quarantine_id: format!("quarantine:{cycle_id}"),
                cycle_id: cycle_id.clone(),
                package_digest: challenger.package_digest.clone(),
                observation_evidence_digest: Some(observation.evidence_digest),
                recovery_receipt_digest: recovery.receipt_digest.clone(),
                reason: "post-activation task or health regression".to_string(),
                record_digest: ContentDigest::from_bytes(&[]),
            }
            .seal()?;
            self.state.quarantines.push(quarantine);
            self.state.recovery_receipts.push(recovery.clone());
            self.state.in_flight = None;
            self.append_cycle_lineage(
                &cycle,
                &challenger,
                LineageDisposition::Quarantined,
                pending.incumbent_state_schema,
                pending.incumbent_state_schema,
                Some(recovery.receipt_digest),
            )?;
            self.persist_state()?;
            return Ok(CycleOutcome::QuarantinedAndRolledBack {
                package_digest: challenger.package_digest,
                restored_package_digest: incumbent.package_digest,
                cycle_record_digest: cycle.record_digest,
            });
        }

        cycle.status = CycleStatus::Adopted;
        cycle.seal()?;
        self.store_cycle(cycle.clone())?;
        self.state.retained_incumbent = Some(RetainedIncumbent {
            package_digest: incumbent.package_digest.clone(),
            state_schema: pending.incumbent_state_schema,
        });
        self.state.active_package_digest = challenger.package_digest.clone();
        self.state.active_generation = challenger.payload.generation;
        self.state.active_state_schema = target_state_schema;
        self.state.in_flight = None;
        self.append_cycle_lineage(
            &cycle,
            &challenger,
            LineageDisposition::Adopted,
            pending.incumbent_state_schema,
            target_state_schema,
            None,
        )?;
        self.persist_state()?;
        Ok(CycleOutcome::Adopted {
            package_digest: challenger.package_digest,
            cycle_record_digest: cycle.record_digest,
        })
    }

    fn preview_successor_package(
        &self,
        executor: &FactoryPackage,
        genome: MutableGenome,
        state_compatibility: StateCompatibility,
    ) -> Result<FactoryPackage, ReproductionError> {
        let next_generation = executor.payload.generation.checked_add(1).ok_or_else(|| {
            ReproductionError::BudgetExceeded("generation counter overflow".to_string())
        })?;
        FactoryPackage::build(
            self.state.factory_id.clone(),
            next_generation,
            genome,
            executor.payload.stable_interface.clone(),
            executor.payload.worker_catalog.clone(),
            executor.payload.service_dependencies.clone(),
            state_compatibility,
        )
    }

    fn seeded_cycle_intent(
        &self,
        request: &SeedCycleRequest,
    ) -> Result<CycleIntent, ReproductionError> {
        self.ensure_cycle_intent_boundary_compatible(
            &request.cycle_id,
            CycleIntentKind::Seeded,
            &request.expected_active_package_digest,
            &request.expected_gate_digest,
        )?;
        let active = self.load_package(&request.expected_active_package_digest)?;
        CycleIntent::seeded(request, &active, &self.state.release_gate)
    }

    fn adopted_cycle_intent(
        &self,
        request: &AdoptedSuccessorRequest,
    ) -> Result<CycleIntent, ReproductionError> {
        self.ensure_cycle_intent_boundary_compatible(
            &request.cycle_id,
            CycleIntentKind::AdoptedSuccessor,
            &request.expected_active_package_digest,
            &request.expected_gate_digest,
        )?;
        let executor = self.load_package(&request.expected_active_package_digest)?;
        CycleIntent::adopted(request, &executor, &self.state.release_gate)
    }

    fn ensure_cycle_intent_boundary_compatible(
        &self,
        cycle_id: &str,
        kind: CycleIntentKind,
        expected_active: &ContentDigest,
        expected_gate: &ContentDigest,
    ) -> Result<(), ReproductionError> {
        validate_identifier("cycle id", cycle_id)?;
        if let Some(existing) = self
            .state
            .cycle_intents
            .iter()
            .find(|intent| intent.cycle_id == cycle_id)
        {
            if existing.kind != kind
                || &existing.expected_active_package_digest != expected_active
                || &existing.expected_gate_digest != expected_gate
            {
                return Err(ReproductionError::DuplicateCycleId(cycle_id.to_string()));
            }
            return Ok(());
        }
        self.ensure_expected_boundary(cycle_id, expected_active, expected_gate)
    }

    fn terminal_cycle_replay(
        &self,
        intent: &CycleIntent,
    ) -> Result<Option<CycleOutcome>, ReproductionError> {
        intent.validate()?;
        let Some(existing_intent) = self
            .state
            .cycle_intents
            .iter()
            .find(|existing| existing.cycle_id == intent.cycle_id)
        else {
            return Ok(None);
        };
        if existing_intent != intent {
            return Err(ReproductionError::DuplicateCycleId(intent.cycle_id.clone()));
        }

        let mut matching_cycles = self
            .state
            .cycles
            .iter()
            .filter(|cycle| cycle.cycle_id == intent.cycle_id);
        let cycle = matching_cycles.next();
        if matching_cycles.next().is_some() {
            return Err(ReproductionError::StateIntegrity(
                "terminal replay found duplicate durable cycles".to_string(),
            ));
        }
        let mut matching_stops = self
            .state
            .stop_conditions
            .iter()
            .filter(|stop| stop.requested_cycle_id == intent.cycle_id);
        let stop = matching_stops.next();
        if matching_stops.next().is_some() {
            return Err(ReproductionError::StateIntegrity(
                "terminal replay found duplicate stop conditions".to_string(),
            ));
        }
        if cycle.is_some() && stop.is_some() {
            return Err(ReproductionError::StateIntegrity(
                "cycle id has both a durable cycle and a stop condition".to_string(),
            ));
        }
        if let Some(stop) = stop {
            if stop.active_package_digest != intent.expected_active_package_digest {
                return Err(ReproductionError::StateIntegrity(
                    "terminal stop differs from its immutable cycle intent".to_string(),
                ));
            }
            return Ok(Some(CycleOutcome::Stopped(stop.clone())));
        }

        let Some(cycle) = cycle else {
            return Ok(None);
        };
        let outcome = match cycle.status {
            CycleStatus::GateRejected => Some(CycleOutcome::GateRejected {
                package_digest: cycle.challenger_package_digest.clone(),
                cycle_record_digest: cycle.record_digest.clone(),
            }),
            CycleStatus::ApprovalRejected => Some(CycleOutcome::ApprovalRejected {
                package_digest: cycle.challenger_package_digest.clone(),
                cycle_record_digest: cycle.record_digest.clone(),
            }),
            CycleStatus::Adopted => Some(CycleOutcome::Adopted {
                package_digest: cycle.challenger_package_digest.clone(),
                cycle_record_digest: cycle.record_digest.clone(),
            }),
            CycleStatus::QuarantinedAndRolledBack | CycleStatus::RecoveredToIncumbent => {
                let recovery = cycle.recovery_receipt.as_ref().ok_or_else(|| {
                    ReproductionError::StateIntegrity(
                        "rolled-back terminal cycle has no recovery receipt".to_string(),
                    )
                })?;
                if recovery.restored_package_digest != cycle.parent_package_digest {
                    return Err(ReproductionError::StateIntegrity(
                        "terminal recovery restored a package other than the cycle parent"
                            .to_string(),
                    ));
                }
                Some(CycleOutcome::QuarantinedAndRolledBack {
                    package_digest: cycle.challenger_package_digest.clone(),
                    restored_package_digest: recovery.restored_package_digest.clone(),
                    cycle_record_digest: cycle.record_digest.clone(),
                })
            }
            CycleStatus::Evaluating | CycleStatus::Approved => None,
        };
        Ok(outcome)
    }

    fn record_cycle_intent(&mut self, intent: CycleIntent) -> Result<(), ReproductionError> {
        intent.validate()?;
        if let Some(existing) = self
            .state
            .cycle_intents
            .iter()
            .find(|existing| existing.cycle_id == intent.cycle_id)
        {
            if existing == &intent {
                return Ok(());
            }
            return Err(ReproductionError::DuplicateCycleId(intent.cycle_id));
        }
        if self.state.cycle_intents.len() >= MAX_RECORDS {
            return Err(ReproductionError::BudgetExceeded(
                "cycle intent journal is full".to_string(),
            ));
        }
        self.state.cycle_intents.push(intent);
        self.persist_state()
    }

    fn ensure_expected_boundary(
        &self,
        cycle_id: &str,
        expected_active: &ContentDigest,
        expected_gate: &ContentDigest,
    ) -> Result<(), ReproductionError> {
        validate_identifier("cycle id", cycle_id)?;
        if self.state.in_flight.is_some() {
            return Err(ReproductionError::RecoveryRequired);
        }
        if &self.state.active_package_digest != expected_active {
            return Err(ReproductionError::ActivePackageMismatch {
                expected: self.state.active_package_digest.clone(),
                actual: expected_active.clone(),
            });
        }
        if &self.state.release_gate.gate_digest != expected_gate {
            return Err(ReproductionError::GateMismatch {
                expected: self.state.release_gate.gate_digest.clone(),
                actual: expected_gate.clone(),
            });
        }
        Ok(())
    }

    fn ensure_ready_for_cycle(
        &self,
        cycle_id: &str,
        expected_active: &ContentDigest,
        expected_gate: &ContentDigest,
    ) -> Result<(), ReproductionError> {
        self.ensure_expected_boundary(cycle_id, expected_active, expected_gate)?;
        if self
            .state
            .cycles
            .iter()
            .any(|cycle| cycle.cycle_id == cycle_id)
            || self
                .state
                .generation_initiations
                .iter()
                .any(|record| record.cycle_id == cycle_id)
        {
            return Err(ReproductionError::DuplicateCycleId(cycle_id.to_string()));
        }
        if self.state.cycles.len() as u32 >= self.state.release_gate.budgets.max_total_cycles {
            return Err(ReproductionError::BudgetExceeded(
                "total generation-cycle budget exhausted".to_string(),
            ));
        }
        Ok(())
    }

    fn record_stop(
        &mut self,
        cycle_id: &str,
        reason: StopReason,
    ) -> Result<CycleOutcome, ReproductionError> {
        if let Some(existing) = self.state.stop_conditions.iter().find(|record| {
            record.requested_cycle_id == cycle_id
                && record.active_package_digest == self.state.active_package_digest
                && record.generation == self.state.active_generation
                && record.reason == reason
        }) {
            return Ok(CycleOutcome::Stopped(existing.clone()));
        }
        let record = StopConditionRecord {
            stop_id: format!("stop:{cycle_id}:{}", self.state.stop_conditions.len() + 1),
            requested_cycle_id: cycle_id.to_string(),
            active_package_digest: self.state.active_package_digest.clone(),
            generation: self.state.active_generation,
            reason,
            record_digest: ContentDigest::from_bytes(&[]),
        }
        .seal()?;
        self.state.stop_conditions.push(record.clone());
        self.persist_state()?;
        Ok(CycleOutcome::Stopped(record))
    }

    fn store_cycle(&mut self, cycle: CycleRecord) -> Result<(), ReproductionError> {
        require_digest(
            "cycle record",
            &cycle.record_digest,
            &cycle_record_digest(&cycle)?,
        )?;
        if let Some(existing) = self
            .state
            .cycles
            .iter_mut()
            .find(|existing| existing.cycle_id == cycle.cycle_id)
        {
            *existing = cycle;
        } else {
            if self.state.cycles.len() >= MAX_RECORDS {
                return Err(ReproductionError::BudgetExceeded(
                    "cycle journal is full".to_string(),
                ));
            }
            self.state.cycles.push(cycle);
        }
        Ok(())
    }

    fn append_cycle_lineage(
        &mut self,
        cycle: &CycleRecord,
        package: &FactoryPackage,
        disposition: LineageDisposition,
        prior_state_schema: u32,
        resulting_state_schema: u32,
        recovery_receipt_digest: Option<ContentDigest>,
    ) -> Result<(), ReproductionError> {
        let initiation_digest = cycle
            .initiation
            .as_ref()
            .map(|record| record.material_step_digest.clone());
        let record = FactoryLineageRecord::new(
            format!(
                "lineage:{}:{:?}:{}",
                cycle.cycle_id, disposition, cycle.generation
            )
            .to_lowercase(),
            cycle.generation,
            Some(cycle.parent_package_digest.clone()),
            package,
            Some(cycle.record_digest.clone()),
            initiation_digest,
            disposition,
            prior_state_schema,
            resulting_state_schema,
            recovery_receipt_digest,
        )?;
        self.state.lineage.push(record);
        Ok(())
    }

    fn recover_pending_effect(&mut self) -> Result<(), ReproductionError> {
        let Some(pending) = self.state.in_flight.clone() else {
            return Ok(());
        };
        let recovery = self.perform_recovery(&pending, "restart recovery of interrupted effect")?;
        let challenger = self.load_package(&pending.challenger_package_digest)?;
        self.state.active_package_digest = pending.incumbent_package_digest.clone();
        let incumbent = self.load_package(&pending.incumbent_package_digest)?;
        self.state.active_generation = incumbent.payload.generation;
        self.state.active_state_schema = pending.incumbent_state_schema;
        self.state.retained_incumbent = None;
        self.state.recovery_receipts.push(recovery.clone());
        self.state.in_flight = None;

        if let Some(index) = self
            .state
            .cycles
            .iter()
            .position(|cycle| cycle.cycle_id == pending.cycle_id)
        {
            let mut cycle = self.state.cycles[index].clone();
            cycle.recovery_receipt = Some(recovery.clone());
            cycle.status = CycleStatus::RecoveredToIncumbent;
            cycle.seal()?;
            self.state.cycles[index] = cycle.clone();
            let quarantine = QuarantineRecord {
                quarantine_id: format!("quarantine:recovery:{}", pending.cycle_id),
                cycle_id: pending.cycle_id.clone(),
                package_digest: pending.challenger_package_digest.clone(),
                observation_evidence_digest: cycle
                    .observation_evidence
                    .as_ref()
                    .map(|evidence| evidence.evidence_digest.clone()),
                recovery_receipt_digest: recovery.receipt_digest.clone(),
                reason: "restart recovered an interrupted migration or activation".to_string(),
                record_digest: ContentDigest::from_bytes(&[]),
            }
            .seal()?;
            self.state.quarantines.push(quarantine);
            self.append_cycle_lineage(
                &cycle,
                &challenger,
                LineageDisposition::RecoveryRollback,
                pending.incumbent_state_schema,
                pending.incumbent_state_schema,
                Some(recovery.receipt_digest),
            )?;
        }
        self.persist_state()
    }

    fn perform_recovery(
        &self,
        pending: &PendingEffect,
        reason: impl Into<String>,
    ) -> Result<RecoveryReceipt, ReproductionError> {
        let incumbent = self.load_package(&pending.incumbent_package_digest)?;
        let incumbent_bytes = incumbent.canonical_bytes()?;
        let request = RecoveryRequest::from_pending(pending, incumbent_bytes, reason)?;
        let receipt = self
            .ports
            .m3_capability
            .recover_to_incumbent(&request)
            .map_err(|failure| ReproductionError::port("m3_recovery", failure))?;
        validate_recovery_receipt(&request, &receipt)?;
        Ok(receipt)
    }

    fn load_package(&self, digest: &ContentDigest) -> Result<FactoryPackage, ReproductionError> {
        let record = self
            .state
            .package_index
            .get(digest.as_str())
            .ok_or_else(|| {
                ReproductionError::StateIntegrity(format!(
                    "package '{digest}' is absent from the index"
                ))
            })?;
        let path = package_path(&self.package_directory, digest);
        let bytes = read_bounded(&path, MAX_PACKAGE_BYTES)?;
        if bytes.len() as u64 != record.byte_len {
            return Err(ReproductionError::StateIntegrity(format!(
                "package '{digest}' byte length differs from its index"
            )));
        }
        require_digest(
            "stored factory package",
            digest,
            &ContentDigest::from_bytes(&bytes),
        )?;
        let package = FactoryPackage::from_canonical_bytes(&bytes)?;
        if package.payload.generation != record.generation {
            return Err(ReproductionError::StateIntegrity(format!(
                "package '{digest}' generation differs from its index"
            )));
        }
        Ok(package)
    }

    fn validate_causal_evidence_against_packages(&self) -> Result<(), ReproductionError> {
        for intent in &self.state.cycle_intents {
            let active = self.load_package(&intent.expected_active_package_digest)?;
            require_digest(
                "cycle intent active package canonical bytes",
                &intent.expected_active_package_bytes_digest,
                &ContentDigest::from_bytes(&active.canonical_bytes()?),
            )?;
        }
        for initiation in &self.state.generation_initiations {
            let executor = self.load_package(&initiation.executor_package_digest)?;
            let exact_executor_bytes = executor.canonical_bytes()?;
            require_digest(
                "generation executor package bytes",
                &initiation.executor_package_bytes_digest,
                &ContentDigest::from_bytes(&exact_executor_bytes),
            )?;
            require_digest(
                "generation executor component",
                &initiation.driver_request.executor_component_digest,
                &executor.payload.genome.component_digest,
            )?;
            require_digest(
                "generation executor interface",
                &initiation.driver_request.stable_interface_digest,
                &executor.payload.stable_interface.contract_digest()?,
            )?;
            let instruction = executor
                .payload
                .genome
                .policy
                .generation_instruction
                .as_ref()
                .ok_or_else(|| {
                    ReproductionError::StateIntegrity(
                        "generation evidence executor has no driver instruction".to_string(),
                    )
                })?;
            require_digest(
                "generation executor instruction",
                &initiation.instruction_digest,
                &instruction.instruction_digest()?,
            )?;
            if initiation.driver_request.next_generation
                != executor.payload.generation.checked_add(1).ok_or_else(|| {
                    ReproductionError::BudgetExceeded("generation counter overflow".to_string())
                })?
                || initiation.driver_request.driver_contract != instruction.driver_contract
            {
                return Err(ReproductionError::StateIntegrity(
                    "generation request differs from its immutable executor package".to_string(),
                ));
            }
        }
        for prepared in &self.state.prepared_successors {
            let executor = self.load_package(&prepared.executor_package_digest)?;
            let expected = self.preview_successor_package(
                &executor,
                prepared.successor_genome.clone(),
                prepared.state_compatibility.clone(),
            )?;
            if expected != prepared.successor_package {
                return Err(ReproductionError::StateIntegrity(
                    "durable prepared package does not rederive from its executor and evidence"
                        .to_string(),
                ));
            }
        }
        Ok(())
    }

    fn persist_state(&mut self) -> Result<(), ReproductionError> {
        self.validate_causal_evidence_against_packages()?;
        self.state.seal()?;
        self.state.validate()?;
        atomic_write_json(&self.canonical_root.join(STATE_FILE_NAME), &self.state)
    }
}

fn validate_m1_evidence(
    request: &M1BuildRequest,
    evidence: &M1BuildEvidence,
) -> Result<(), ReproductionError> {
    require_digest(
        "M1 evidence request",
        &evidence.request_digest,
        &request.request_digest,
    )?;
    require_digest(
        "M1 component",
        &evidence.component_digest,
        &request.component_digest,
    )?;
    require_digest(
        "M1 stable interface",
        &evidence.stable_interface_digest,
        &request.stable_interface_digest,
    )?;
    require_digest(
        "M1 build evidence",
        &evidence.evidence_digest,
        &m1_evidence_digest(evidence)?,
    )?;
    if !evidence.runnable {
        return Err(ReproductionError::EvidenceRejected(
            "M1 proving did not establish a runnable component".to_string(),
        ));
    }
    if evidence.observed_export != REFERENCE_EXPORT {
        return Err(ReproductionError::InterfaceMismatch {
            expected: REFERENCE_EXPORT.to_string(),
            actual: evidence.observed_export.clone(),
        });
    }
    Ok(())
}

fn validate_worker_evidence(
    request: &WorkerWorkflowRequest,
    evidence: &WorkerWorkflowEvidence,
) -> Result<(), ReproductionError> {
    require_digest(
        "worker evidence request",
        &evidence.request_digest,
        &request.request_digest,
    )?;
    require_digest(
        "worker challenger package",
        &evidence.challenger_package_digest,
        &request.challenger_package_digest,
    )?;
    require_digest(
        "worker workflow evidence",
        &evidence.evidence_digest,
        &worker_evidence_digest(evidence)?,
    )?;
    let mut roles = BTreeSet::new();
    for receipt in &evidence.receipts {
        validate_identifier("worker execution id", &receipt.execution_id)?;
        if !roles.insert(receipt.role) {
            return Err(ReproductionError::EvidenceMismatch(
                "worker evidence contains a duplicate role".to_string(),
            ));
        }
        if receipt.terminal_status != WorkerTerminalStatus::Succeeded
            || receipt.output_digest.is_none()
        {
            return Err(ReproductionError::EvidenceRejected(format!(
                "worker '{:?}' did not complete successfully",
                receipt.role
            )));
        }
        require_digest(
            "worker input",
            &receipt.input_digest,
            &request.request_digest,
        )?;
    }
    let required = request
        .required_roles
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if roles != required {
        return Err(ReproductionError::EvidenceMismatch(
            "worker evidence does not cover every required role exactly once".to_string(),
        ));
    }
    Ok(())
}

fn validate_generation_driver_evidence(
    request: &GenerationDriverRequest,
    evidence: &GenerationDriverEvidence,
) -> Result<(), ReproductionError> {
    validate_identifier("generation driver cycle id", &request.cycle_id)?;
    validate_identifier(
        "generation driver idempotency key",
        &request.idempotency_key,
    )?;
    request.driver_contract.validate()?;
    require_digest(
        "generation driver contract",
        &request.driver_contract.contract_digest()?,
        &GenerationDriverContract::reference().contract_digest()?,
    )?;
    require_digest(
        "generation driver request",
        &request.request_digest,
        &digest_serializable(&(
            "wasm-biotic:generation-driver-request:v1",
            &request.cycle_id,
            &request.executor_package_digest,
            &request.executor_package_bytes_digest,
            &request.executor_component_digest,
            &request.stable_interface_digest,
            &request.instruction_digest,
            &request.driver_contract,
            &request.gate_digest,
            request.next_generation,
            &request.idempotency_key,
        ))?,
    )?;
    require_digest(
        "generation driver evidence request",
        &evidence.request_digest,
        &request.request_digest,
    )?;
    validate_identifier("generation driver invocation id", &evidence.invocation_id)?;
    require_digest(
        "generation driver executor",
        &evidence.executor_package_digest,
        &request.executor_package_digest,
    )?;
    require_digest(
        "generation driver executor package bytes",
        &evidence.executor_package_bytes_digest,
        &request.executor_package_bytes_digest,
    )?;
    require_digest(
        "generation driver executor component",
        &evidence.executor_component_digest,
        &request.executor_component_digest,
    )?;
    require_digest(
        "generation driver instruction",
        &evidence.instruction_digest,
        &request.instruction_digest,
    )?;
    request
        .driver_contract
        .validate_directive(evidence.directive)?;
    require_digest(
        "generation driver trace component",
        &evidence.trace.component_digest,
        &request.executor_component_digest,
    )?;
    if evidence.trace.export_name != request.driver_contract.exported_function
        || evidence.trace.input != request.driver_contract.driver_input
        || evidence.trace.output != Some(evidence.directive)
        || evidence.trace.trapped
        || evidence.trace.failure_phase.is_some()
        || evidence.trace.limit_exhausted.is_some()
        || !evidence.trace.invoked_imports.is_empty()
        || !evidence.trace.import_link_audits.is_empty()
    {
        return Err(ReproductionError::EvidenceMismatch(
            "generation driver trace is not the exact successful import-free reference invocation"
                .to_string(),
        ));
    }
    require_digest(
        "generation driver evidence",
        &evidence.evidence_digest,
        &generation_driver_evidence_digest(evidence)?,
    )
}

fn validate_generation_materialization_evidence(
    driver_request: &GenerationDriverRequest,
    driver_evidence: &GenerationDriverEvidence,
    request: &GenerationMaterializationRequest,
    evidence: &GenerationMaterializationEvidence,
) -> Result<(), ReproductionError> {
    validate_identifier("generation materialization cycle id", &request.cycle_id)?;
    validate_identifier(
        "generation materialization idempotency key",
        &request.idempotency_key,
    )?;
    if request.cycle_id != driver_request.cycle_id
        || request.driver_request_digest != driver_request.request_digest
        || request.driver_evidence_digest != driver_evidence.evidence_digest
        || request.instruction_digest != driver_request.instruction_digest
        || request.renderer_profile != driver_request.driver_contract.renderer_profile
        || request.directive != driver_evidence.directive
        || request.maximum_component_bytes == 0
        || request.maximum_component_bytes > MAX_COMPONENT_BYTES as u64
    {
        return Err(ReproductionError::EvidenceMismatch(
            "generation materialization request is not bound to the exact driver result and budget"
                .to_string(),
        ));
    }
    require_digest(
        "generation materialization request",
        &request.request_digest,
        &digest_serializable(&(
            "wasm-biotic:generation-materialization-request:v1",
            &request.cycle_id,
            &request.driver_request_digest,
            &request.driver_evidence_digest,
            &request.instruction_digest,
            request.renderer_profile,
            request.directive,
            request.maximum_component_bytes,
            &request.idempotency_key,
        ))?,
    )?;
    require_digest(
        "generation materialization evidence request",
        &evidence.request_digest,
        &request.request_digest,
    )?;
    require_digest(
        "generation materialization driver evidence",
        &evidence.driver_evidence_digest,
        &driver_evidence.evidence_digest,
    )?;
    let expected_wat = match request.renderer_profile {
        GenerationRendererProfile::ReferenceDeltaV1 => {
            render_reference_delta_v1(request.directive)?
        }
    };
    if evidence.rendered_wat_bytes != expected_wat {
        return Err(ReproductionError::EvidenceMismatch(
            "materializer returned source not produced by the canonical driver renderer"
                .to_string(),
        ));
    }
    require_digest(
        "rendered successor WAT",
        &evidence.rendered_wat_digest,
        &ContentDigest::from_bytes(&evidence.rendered_wat_bytes),
    )?;
    let expected_component = compile_reference_delta_v1(&expected_wat)?;
    if evidence.successor_component_bytes != expected_component
        || evidence.successor_component_bytes.len() as u64 > request.maximum_component_bytes
    {
        return Err(ReproductionError::EvidenceMismatch(
            "materialized component bytes differ from the independently compiled canonical source"
                .to_string(),
        ));
    }
    require_digest(
        "materialized successor component",
        &evidence.successor_component_digest,
        &ContentDigest::from_bytes(&expected_component),
    )?;
    validate_identifier(
        "generation materialization workflow id",
        &evidence.workflow_id,
    )?;
    let mut roles = BTreeSet::new();
    for receipt in &evidence.worker_receipts {
        validate_identifier(
            "generation materialization worker execution id",
            &receipt.execution_id,
        )?;
        if !roles.insert(receipt.role)
            || receipt.terminal_status != WorkerTerminalStatus::Succeeded
            || receipt.output_digest.is_none()
            || receipt.input_digest != request.request_digest
        {
            return Err(ReproductionError::EvidenceRejected(
                "generation materialization lacks one exact successful receipt per worker role"
                    .to_string(),
            ));
        }
    }
    if roles != WorkerRole::required().into_iter().collect::<BTreeSet<_>>() {
        return Err(ReproductionError::EvidenceMismatch(
            "generation materialization worker receipts do not cover all six roles".to_string(),
        ));
    }
    require_digest(
        "generation materialization evidence",
        &evidence.evidence_digest,
        &generation_materialization_evidence_digest(evidence)?,
    )
}

fn evaluate_shadow_evidence(
    request: &ShadowExecutionRequest,
    evidence: &ShadowExecutionEvidence,
    gate: &ReleaseGate,
) -> Result<GateDecision, ReproductionError> {
    require_digest(
        "shadow evidence request",
        &evidence.request_digest,
        &request.request_digest,
    )?;
    require_digest(
        "shadow execution evidence",
        &evidence.evidence_digest,
        &shadow_evidence_digest(evidence)?,
    )?;
    require_digest(
        "shadow release gate",
        &request.gate.gate_digest,
        &gate.gate_digest,
    )?;
    let incumbent = index_task_observations(
        &evidence.incumbent_observations,
        &request.incumbent_package_digest,
        "incumbent",
    )?;
    let challenger = index_task_observations(
        &evidence.challenger_observations,
        &request.challenger_package_digest,
        "challenger",
    )?;
    if incumbent.len() != gate.benchmarks.len() || challenger.len() != gate.benchmarks.len() {
        return Err(ReproductionError::EvidenceMismatch(
            "shadow evidence must contain exactly one incumbent and challenger execution per benchmark"
                .to_string(),
        ));
    }
    let mut passed_benchmarks = 0_u32;
    let mut regressions = 0_u32;
    for benchmark in &gate.benchmarks {
        let incumbent_observation =
            incumbent
                .get(benchmark.benchmark_id.as_str())
                .ok_or_else(|| {
                    ReproductionError::EvidenceMismatch(format!(
                        "missing incumbent benchmark '{}'",
                        benchmark.benchmark_id
                    ))
                })?;
        let challenger_observation =
            challenger
                .get(benchmark.benchmark_id.as_str())
                .ok_or_else(|| {
                    ReproductionError::EvidenceMismatch(format!(
                        "missing challenger benchmark '{}'",
                        benchmark.benchmark_id
                    ))
                })?;
        let request_digest = ContentDigest::from_bytes(&benchmark.request_bytes);
        require_digest(
            "incumbent benchmark request",
            &incumbent_observation.request_digest,
            &request_digest,
        )?;
        require_digest(
            "challenger benchmark request",
            &challenger_observation.request_digest,
            &request_digest,
        )?;
        let incumbent_passed = observation_passes(incumbent_observation, benchmark);
        let challenger_passed = observation_passes(challenger_observation, benchmark);
        if challenger_passed {
            passed_benchmarks += 1;
        }
        if incumbent_passed && !challenger_passed {
            regressions += 1;
        }
    }
    let invariant_index = index_invariants(
        &evidence.invariant_observations,
        &request.challenger_package_digest,
    )?;
    if invariant_index.len() != gate.invariants.len() {
        return Err(ReproductionError::EvidenceMismatch(
            "shadow evidence must contain exactly one result for every invariant".to_string(),
        ));
    }
    let required_invariants_satisfied = gate.invariants.iter().all(|invariant| {
        invariant_index
            .get(invariant.invariant_id.as_str())
            .is_some_and(|observation| observation.satisfied || !invariant.required)
    });
    let expected_shadow_tasks =
        (evidence.incumbent_observations.len() + evidence.challenger_observations.len()) as u32;
    if evidence.resource_usage.shadow_tasks != expected_shadow_tasks {
        return Err(ReproductionError::EvidenceMismatch(
            "reported shadow task usage differs from execution evidence".to_string(),
        ));
    }
    let within_budgets = evidence.resource_usage.shadow_tasks <= gate.budgets.max_shadow_tasks
        && evidence.resource_usage.component_bytes <= gate.budgets.max_component_bytes
        && evidence.resource_usage.state_bytes <= gate.budgets.max_state_bytes;
    let success_basis_points =
        ((u64::from(passed_benchmarks) * 10_000) / gate.benchmarks.len() as u64) as u16;
    let eligible = passed_benchmarks >= gate.thresholds.minimum_passed_benchmarks
        && success_basis_points >= gate.thresholds.minimum_success_basis_points
        && regressions <= gate.thresholds.maximum_regressions
        && (!gate.thresholds.require_all_required_invariants || required_invariants_satisfied)
        && within_budgets;
    let mut decision = GateDecision {
        gate_digest: gate.gate_digest.clone(),
        shadow_evidence_digest: evidence.evidence_digest.clone(),
        passed_benchmarks,
        success_basis_points,
        regressions,
        required_invariants_satisfied,
        within_budgets,
        eligible,
        decision_digest: ContentDigest::from_bytes(&[]),
    };
    decision.decision_digest = gate_decision_digest(&decision)?;
    Ok(decision)
}

fn index_task_observations<'a>(
    observations: &'a [TaskExecutionObservation],
    package_digest: &ContentDigest,
    side: &str,
) -> Result<BTreeMap<&'a str, &'a TaskExecutionObservation>, ReproductionError> {
    let mut indexed = BTreeMap::new();
    for observation in observations {
        validate_identifier("task execution id", &observation.execution_id)?;
        validate_identifier("task benchmark id", &observation.benchmark_id)?;
        require_digest(
            &format!("{side} observation package"),
            &observation.package_digest,
            package_digest,
        )?;
        if indexed
            .insert(observation.benchmark_id.as_str(), observation)
            .is_some()
        {
            return Err(ReproductionError::EvidenceMismatch(format!(
                "{side} shadow evidence contains duplicate benchmark ids"
            )));
        }
    }
    Ok(indexed)
}

fn index_invariants<'a>(
    observations: &'a [InvariantObservation],
    package_digest: &ContentDigest,
) -> Result<BTreeMap<&'a str, &'a InvariantObservation>, ReproductionError> {
    let mut indexed = BTreeMap::new();
    for observation in observations {
        validate_identifier("invariant observation id", &observation.invariant_id)?;
        require_digest(
            "invariant observation package",
            &observation.package_digest,
            package_digest,
        )?;
        if indexed
            .insert(observation.invariant_id.as_str(), observation)
            .is_some()
        {
            return Err(ReproductionError::EvidenceMismatch(
                "shadow evidence contains duplicate invariant ids".to_string(),
            ));
        }
    }
    Ok(indexed)
}

fn observation_passes(observation: &TaskExecutionObservation, benchmark: &BenchmarkSpec) -> bool {
    observation.terminal == ExecutionTerminal::Succeeded
        && observation.health == HealthStatus::Healthy
        && observation.output_digest.as_ref() == Some(&benchmark.expected_output_digest)
        && observation.duration_ms <= benchmark.max_duration_ms
}

fn validate_supervisor_approval(
    request: &SupervisorApprovalRequest,
    approval: &SupervisorApprovalRecord,
) -> Result<(), ReproductionError> {
    validate_identifier("approval id", &approval.approval_id)?;
    validate_identifier("approver ref", &approval.approver_ref)?;
    if approval.rationale.trim().is_empty() {
        return Err(ReproductionError::ApprovalMismatch(
            "approval rationale is blank".to_string(),
        ));
    }
    require_digest(
        "supervisor approval request",
        &approval.request_digest,
        &request.request_digest,
    )?;
    require_digest(
        "supervisor gate decision",
        &approval.gate_decision_digest,
        &request.gate_decision_digest,
    )?;
    require_digest(
        "supervisor approval record",
        &approval.approval_digest,
        &supervisor_approval_digest(approval)?,
    )?;
    let expected_evidence = [
        request.m1_evidence_digest.clone(),
        request.worker_evidence_digest.clone(),
        request.shadow_evidence_digest.clone(),
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let actual_evidence = approval
        .evidence_digests
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if actual_evidence != expected_evidence
        || actual_evidence.len() != approval.evidence_digests.len()
    {
        return Err(ReproductionError::ApprovalMismatch(
            "approval is not bound to the exact M1, worker, and shadow evidence".to_string(),
        ));
    }
    match approval.decision {
        ApprovalDecision::Approved => {
            if approval.approved_package_digest.as_ref() != Some(&request.challenger_package_digest)
                || approval.approved_package_bytes_digest.as_ref()
                    != Some(&request.challenger_package_bytes_digest)
            {
                return Err(ReproductionError::ApprovalMismatch(
                    "approval does not bind the exact challenger package bytes".to_string(),
                ));
            }
        }
        ApprovalDecision::Rejected => {
            if approval.approved_package_digest.is_some()
                || approval.approved_package_bytes_digest.is_some()
            {
                return Err(ReproductionError::ApprovalMismatch(
                    "a rejected decision cannot carry approved package identities".to_string(),
                ));
            }
        }
    }
    Ok(())
}

fn validate_state_transition(
    current_schema: u32,
    incumbent: &StateCompatibility,
    challenger: &StateCompatibility,
    migration_plan: Option<&StateMigrationPlan>,
    budgets: &RecursionBudgets,
) -> Result<(), ReproductionError> {
    incumbent.validate()?;
    challenger.validate()?;
    if !challenger.can_read(current_schema) {
        return Err(ReproductionError::StateCompatibility(format!(
            "challenger cannot read active state schema {current_schema}"
        )));
    }
    if challenger.written_schema == current_schema {
        if migration_plan.is_some() {
            return Err(ReproductionError::StateCompatibility(
                "a migration plan was supplied although the written schema is unchanged"
                    .to_string(),
            ));
        }
        return Ok(());
    }
    let plan = migration_plan.ok_or_else(|| {
        ReproductionError::StateCompatibility(
            "schema-changing challenger requires a predeclared migration plan".to_string(),
        )
    })?;
    plan.validate()?;
    if plan.from_schema != current_schema
        || plan.to_schema != challenger.written_schema
        || plan.rollback_schema != current_schema
    {
        return Err(ReproductionError::StateCompatibility(
            "migration plan schemas do not match active, challenger, and rollback schemas"
                .to_string(),
        ));
    }
    if plan.maximum_state_bytes > budgets.max_state_bytes {
        return Err(ReproductionError::BudgetExceeded(
            "migration state budget exceeds the predeclared release budget".to_string(),
        ));
    }
    if current_schema > incumbent.incumbent_rollback_readable_through {
        return Err(ReproductionError::StateCompatibility(
            "retained incumbent does not claim the current rollback schema readable".to_string(),
        ));
    }
    Ok(())
}

fn validate_migration_receipt(
    request: &MigrationRequest,
    receipt: &MigrationReceipt,
) -> Result<(), ReproductionError> {
    require_digest(
        "migration receipt request",
        &receipt.request_digest,
        &request.request_digest,
    )?;
    if receipt.migration_id != request.plan.migration_id
        || receipt.from_schema != request.plan.from_schema
        || receipt.to_schema != request.plan.to_schema
    {
        return Err(ReproductionError::EvidenceMismatch(
            "migration receipt does not match the approved migration plan".to_string(),
        ));
    }
    if !receipt.rollback_verified {
        return Err(ReproductionError::EvidenceRejected(
            "migration did not verify incumbent-state rollback".to_string(),
        ));
    }
    require_digest(
        "migration receipt",
        &receipt.receipt_digest,
        &migration_receipt_digest(receipt)?,
    )
}

fn validate_activation_receipt(
    request: &ActivationRequest,
    receipt: &ActivationReceipt,
) -> Result<(), ReproductionError> {
    validate_identifier("activation id", &receipt.activation_id)?;
    require_digest(
        "activation receipt request",
        &receipt.request_digest,
        &request.request_digest,
    )?;
    require_digest(
        "activation previous package",
        &receipt.previous_package_digest,
        &request.incumbent_package_digest,
    )?;
    require_digest(
        "activation active package",
        &receipt.active_package_digest,
        &request.challenger_package_digest,
    )?;
    require_digest(
        "activation active package bytes",
        &receipt.active_package_bytes_digest,
        &ContentDigest::from_bytes(&request.challenger_package_bytes),
    )?;
    if receipt.active_state_schema != request.target_state_schema {
        return Err(ReproductionError::EvidenceMismatch(
            "activation receipt reports an unexpected state schema".to_string(),
        ));
    }
    require_digest(
        "activation receipt",
        &receipt.receipt_digest,
        &activation_receipt_digest(receipt)?,
    )
}

fn validate_post_activation_evidence(
    request: &PostActivationRequest,
    evidence: &PostActivationEvidence,
) -> Result<bool, ReproductionError> {
    require_digest(
        "post-activation evidence request",
        &evidence.request_digest,
        &request.request_digest,
    )?;
    require_digest(
        "post-activation active package",
        &evidence.active_package_digest,
        &request.active_package_digest,
    )?;
    require_digest(
        "post-activation evidence",
        &evidence.evidence_digest,
        &post_activation_evidence_digest(evidence)?,
    )?;
    if evidence.task_observations.len() > MAX_OBSERVATIONS
        || evidence.health_observations.len() > MAX_OBSERVATIONS
    {
        return Err(ReproductionError::BudgetExceeded(
            "post-activation observation count exceeds the hard bound".to_string(),
        ));
    }
    let mut execution_ids = BTreeSet::new();
    for observation in &evidence.task_observations {
        validate_identifier("post-activation execution id", &observation.execution_id)?;
        validate_identifier("post-activation task id", &observation.benchmark_id)?;
        if !execution_ids.insert(observation.execution_id.as_str()) {
            return Err(ReproductionError::EvidenceMismatch(
                "post-activation execution ids must be unique".to_string(),
            ));
        }
        require_digest(
            "post-activation task package",
            &observation.package_digest,
            &request.active_package_digest,
        )?;
    }
    let mut health_ids = BTreeSet::new();
    for observation in &evidence.health_observations {
        validate_identifier("health check id", &observation.check_id)?;
        if !health_ids.insert(observation.check_id.as_str()) {
            return Err(ReproductionError::EvidenceMismatch(
                "health check ids must be unique".to_string(),
            ));
        }
        require_digest(
            "health observation package",
            &observation.active_package_digest,
            &request.active_package_digest,
        )?;
    }
    let successful_tasks = evidence
        .task_observations
        .iter()
        .filter(|observation| {
            observation.terminal == ExecutionTerminal::Succeeded
                && observation.health == HealthStatus::Healthy
                && observation.output_digest.is_some()
        })
        .count() as u32;
    let every_task_healthy = evidence.task_observations.iter().all(|observation| {
        observation.terminal == ExecutionTerminal::Succeeded
            && observation.health == HealthStatus::Healthy
            && observation.output_digest.is_some()
    });
    let health_checks_present_and_healthy = !evidence.health_observations.is_empty()
        && evidence
            .health_observations
            .iter()
            .all(|observation| observation.status == HealthStatus::Healthy);
    Ok(successful_tasks >= request.minimum_successes
        && every_task_healthy
        && health_checks_present_and_healthy)
}

fn validate_recovery_receipt(
    request: &RecoveryRequest,
    receipt: &RecoveryReceipt,
) -> Result<(), ReproductionError> {
    if receipt.recovery_id != request.recovery_id {
        return Err(ReproductionError::EvidenceMismatch(
            "recovery receipt id differs from request".to_string(),
        ));
    }
    require_digest(
        "recovery receipt request",
        &receipt.request_digest,
        &request.request_digest,
    )?;
    require_digest(
        "recovery restored package",
        &receipt.restored_package_digest,
        &request.restore_package_digest,
    )?;
    require_digest(
        "recovery restored bytes",
        &receipt.restored_package_bytes_digest,
        &ContentDigest::from_bytes(&request.restore_package_bytes),
    )?;
    if receipt.restored_state_schema != request.restore_state_schema || !receipt.state_readable {
        return Err(ReproductionError::RecoveryFailed(
            "recovery did not confirm the incumbent-readable state schema".to_string(),
        ));
    }
    require_digest(
        "recovery receipt",
        &receipt.receipt_digest,
        &recovery_receipt_digest(receipt)?,
    )
}

fn validate_live_turn(
    request: &ProviderQualificationRequest,
    turn: &LiveProviderTurn,
) -> Result<(), ReproductionError> {
    validate_provider_accounting_for_turn(turn)?;
    require_digest(
        "live provider request",
        &turn.request_digest,
        &request.request_digest,
    )?;
    require_digest(
        "live provider configuration",
        &turn.configuration_fingerprint,
        &request.configuration.fingerprint()?,
    )?;
    require_digest(
        "live provider replay capsule",
        &turn.replay_capsule_digest,
        &request.replay_capsule.capsule_digest,
    )?;
    if turn.normalized_parser_input_bytes.is_empty()
        || turn.normalized_parser_input_bytes.len() > MAX_PROVIDER_TRANSCRIPT_BYTES
        || turn.normalized_parser_input_bytes != turn.transcript.redacted_response.as_bytes()
    {
        return Err(ReproductionError::ProviderQualification(
            "live provider normalized parser input is absent, out of bounds, or differs from the retained response"
                .to_string(),
        ));
    }
    validate_identifier("external provider turn id", &turn.external_turn_id)?;
    turn.transcript.validate(request)?;
    turn.parsed_intent.intent_digest()?;
    if turn.provider_accounting.provider_id != request.configuration.provider_id
        || turn.provider_accounting.model_id != request.configuration.model_id
        || turn.provider_accounting.provider_profile != request.configuration.provider_profile
        || turn.provider_accounting.generation_policy_id
            != request.configuration.generation_policy_id
        || turn.provider_accounting.maximum_retries != request.configuration.maximum_retries
        || turn.provider_accounting.maximum_output_tokens
            != request.configuration.maximum_output_tokens
        || turn.provider_accounting.input_cost_per_million_microunits
            != request.configuration.input_cost_per_million_microunits
        || turn.provider_accounting.output_cost_per_million_microunits
            != request.configuration.output_cost_per_million_microunits
        || turn.provider_accounting.currency != request.configuration.cost_currency
    {
        return Err(provider_accounting_error(
            "live provider accounting names a different provider, model, profile, policy, generation bound, or pricing basis than the qualification request",
        ));
    }
    require_digest(
        "live provider accounting response schema",
        &turn.provider_accounting.response_schema_digest,
        &request.configuration.response_schema_digest,
    )?;
    require_digest(
        "live provider accounting generation policy",
        &turn.provider_accounting.generation_policy_digest,
        &request.configuration.generation_policy_digest,
    )?;
    require_digest(
        "live provider turn",
        &turn.turn_digest,
        &live_provider_turn_digest(turn)?,
    )
}

fn validate_provider_replay(
    request: &ProviderReplayRequest,
    replay: &ProviderReplayRecord,
) -> Result<(), ReproductionError> {
    if !request.network_forbidden || replay.network_used {
        return Err(ReproductionError::ProviderQualification(
            "deterministic replay used or permitted network access".to_string(),
        ));
    }
    require_digest(
        "provider replay request",
        &replay.request_digest,
        &request.request_digest,
    )?;
    require_digest(
        "provider replay intent",
        &replay.parsed_intent.intent_digest()?,
        &request.expected_intent_digest,
    )?;
    require_digest(
        "provider replay parser",
        &replay.parser_digest,
        &request.expected_parser_digest,
    )?;
    require_digest(
        "provider replay record",
        &replay.replay_digest,
        &provider_replay_digest(replay)?,
    )
}

fn instruction_use_key(
    package_digest: &ContentDigest,
    instruction_digest: &ContentDigest,
) -> String {
    format!("{package_digest}|{instruction_digest}")
}

fn contains_obvious_secret(value: &str) -> bool {
    let lowercase = value.to_ascii_lowercase();
    lowercase.contains("authorization: bearer ")
        || lowercase.contains("api_key=")
        || lowercase.contains("apikey=")
        || lowercase.contains("sk-proj-")
}

fn persist_package_to(
    package_directory: &Path,
    package: &FactoryPackage,
) -> Result<PackageIndexRecord, ReproductionError> {
    package.validate()?;
    let bytes = package.canonical_bytes()?;
    let path = package_path(package_directory, &package.package_digest);
    persist_immutable(&path, &bytes)?;
    Ok(PackageIndexRecord {
        package_digest: package.package_digest.clone(),
        byte_len: bytes.len() as u64,
        generation: package.payload.generation,
    })
}

fn verify_package_index(
    package_directory: &Path,
    state: &ReproductionState,
) -> Result<(), ReproductionError> {
    for (key, record) in &state.package_index {
        if key != record.package_digest.as_str() {
            return Err(ReproductionError::StateIntegrity(
                "package index key differs from record digest".to_string(),
            ));
        }
        let path = package_path(package_directory, &record.package_digest);
        let bytes = read_bounded(&path, MAX_PACKAGE_BYTES)?;
        if bytes.len() as u64 != record.byte_len {
            return Err(ReproductionError::StateIntegrity(format!(
                "indexed package '{}' has an unexpected byte length",
                record.package_digest
            )));
        }
        require_digest(
            "indexed package",
            &record.package_digest,
            &ContentDigest::from_bytes(&bytes),
        )?;
        let package = FactoryPackage::from_canonical_bytes(&bytes)?;
        if package.payload.generation != record.generation {
            return Err(ReproductionError::StateIntegrity(format!(
                "indexed package '{}' has an unexpected generation",
                record.package_digest
            )));
        }
    }
    Ok(())
}

fn package_path(package_directory: &Path, digest: &ContentDigest) -> PathBuf {
    package_directory.join(format!("{}.json", digest.file_stem()))
}

fn prepare_root(root: &Path) -> Result<(PathBuf, PathBuf), ReproductionError> {
    reject_symlink_if_present(root)?;
    fs::create_dir_all(root).map_err(|error| ReproductionError::io(root, error))?;
    let canonical_root =
        fs::canonicalize(root).map_err(|error| ReproductionError::io(root, error))?;
    let package_directory = canonical_root.join(PACKAGE_DIRECTORY_NAME);
    reject_symlink_if_present(&package_directory)?;
    fs::create_dir_all(&package_directory)
        .map_err(|error| ReproductionError::io(&package_directory, error))?;
    let canonical_packages = fs::canonicalize(&package_directory)
        .map_err(|error| ReproductionError::io(&package_directory, error))?;
    if canonical_packages.parent() != Some(canonical_root.as_path()) {
        return Err(ReproductionError::UnsafePath(
            "factory package directory escaped the engine root".to_string(),
        ));
    }
    Ok((canonical_root, canonical_packages))
}

fn acquire_engine_owner_lock(root: &Path) -> Result<File, ReproductionError> {
    let path = root.join(ENGINE_OWNER_LOCK_FILE);
    reject_symlink_if_present(&path)?;
    if path.exists() {
        let metadata =
            fs::symlink_metadata(&path).map_err(|error| ReproductionError::io(&path, error))?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(ReproductionError::UnsafePath(format!(
                "factory engine owner lock '{}' is not a regular file",
                path.display()
            )));
        }
    }
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|error| ReproductionError::io(&path, error))?;
    file.try_lock().map_err(|error| match error {
        std::fs::TryLockError::WouldBlock => {
            ReproductionError::StateOwnerConflict(root.to_path_buf())
        }
        std::fs::TryLockError::Error(error) => ReproductionError::io(&path, error),
    })?;
    Ok(file)
}

fn migrate_causally_clean_v2(bytes: &[u8]) -> Result<ReproductionState, ReproductionError> {
    let mut value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| ReproductionError::Serialization(error.to_string()))?;
    let object = value.as_object_mut().ok_or_else(|| {
        ReproductionError::StateIntegrity("legacy v2 state is not a JSON object".to_string())
    })?;
    for field in ["cycles", "generation_initiations"] {
        if object
            .get(field)
            .and_then(serde_json::Value::as_array)
            .is_none_or(|records| !records.is_empty())
        {
            return Err(ReproductionError::StateIntegrity(format!(
                "legacy v2 state with '{field}' cannot be upgraded without exact causal evidence"
            )));
        }
    }
    if object
        .get("instruction_uses")
        .and_then(serde_json::Value::as_object)
        .is_none_or(|uses| !uses.is_empty())
        || object
            .get("in_flight")
            .is_some_and(|pending| !pending.is_null())
    {
        return Err(ReproductionError::StateIntegrity(
            "legacy v2 state has generation uses or an in-flight effect without a cycle intent"
                .to_string(),
        ));
    }
    object.insert(
        "schema_version".to_string(),
        serde_json::Value::from(REPRODUCTION_STATE_SCHEMA_VERSION),
    );
    object.insert(
        "cycle_intents".to_string(),
        serde_json::Value::Array(Vec::new()),
    );
    object.insert(
        "prepared_successors".to_string(),
        serde_json::Value::Array(Vec::new()),
    );
    object.insert(
        "state_digest".to_string(),
        serde_json::to_value(ContentDigest::from_bytes(&[]))
            .map_err(|error| ReproductionError::Serialization(error.to_string()))?,
    );
    let mut migrated: ReproductionState = serde_json::from_value(value)
        .map_err(|error| ReproductionError::Serialization(error.to_string()))?;
    migrated.seal()?;
    migrated.validate()?;
    Ok(migrated)
}

/// Upgrade the immediately preceding durable state only when it contains no
/// opaque v1 live-provider records. Those records retain a receipt digest but
/// not the structured usage/retry facts required by schema v5, so fabricating
/// a replacement summary would turn an absence of evidence into evidence.
fn migrate_provider_accounting_clean_v4(
    bytes: &[u8],
) -> Result<ReproductionState, ReproductionError> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| ReproductionError::Serialization(error.to_string()))?;
    let object = value.as_object().ok_or_else(|| {
        ReproductionError::StateIntegrity("legacy v4 state is not a JSON object".to_string())
    })?;
    if object
        .get("provider_qualifications")
        .and_then(serde_json::Value::as_array)
        .is_none_or(|records| !records.is_empty())
    {
        return Err(ReproductionError::StateIntegrity(
            "legacy v4 state contains provider qualifications whose opaque receipt digests cannot be upgraded to structured accounting; run a fresh qualification"
                .to_string(),
        ));
    }
    let mut migrated: ReproductionState = serde_json::from_slice(bytes)
        .map_err(|error| ReproductionError::Serialization(error.to_string()))?;
    if migrated.schema_version != 4 {
        return Err(ReproductionError::UnsupportedStateSchema(
            migrated.schema_version,
        ));
    }
    require_digest(
        "legacy v4 reproduction state",
        &migrated.state_digest,
        &reproduction_state_digest_in_domain(
            &migrated,
            "wasm-biotic:factory-reproduction-state:v4",
        )?,
    )?;
    migrated.schema_version = REPRODUCTION_STATE_SCHEMA_VERSION;
    migrated.state_digest = ContentDigest::from_bytes(&[]);
    migrated.seal()?;
    migrated.validate()?;
    Ok(migrated)
}

/// Upgrade schema v5 only when no live-provider qualification is retained.
///
/// Schema v6 binds the configured output-token ceiling into each durable
/// provider accounting summary. A v5 provider record has no authoritative
/// value for that field, so it cannot be upgraded without inventing evidence.
fn migrate_provider_output_bound_clean_v5(
    bytes: &[u8],
) -> Result<ReproductionState, ReproductionError> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| ReproductionError::Serialization(error.to_string()))?;
    let object = value.as_object().ok_or_else(|| {
        ReproductionError::StateIntegrity("legacy v5 state is not a JSON object".to_string())
    })?;
    if object
        .get("provider_qualifications")
        .and_then(serde_json::Value::as_array)
        .is_none_or(|records| !records.is_empty())
    {
        return Err(ReproductionError::StateIntegrity(
            "legacy v5 state contains provider qualifications without an authoritative maximum-output-token accounting bound; run a fresh qualification"
                .to_string(),
        ));
    }
    let mut migrated: ReproductionState = serde_json::from_slice(bytes)
        .map_err(|error| ReproductionError::Serialization(error.to_string()))?;
    if migrated.schema_version != 5 {
        return Err(ReproductionError::UnsupportedStateSchema(
            migrated.schema_version,
        ));
    }
    require_digest(
        "legacy v5 reproduction state",
        &migrated.state_digest,
        &reproduction_state_digest_in_domain(
            &migrated,
            "wasm-biotic:factory-reproduction-state:v5",
        )?,
    )?;
    migrated.schema_version = REPRODUCTION_STATE_SCHEMA_VERSION;
    migrated.state_digest = ContentDigest::from_bytes(&[]);
    migrated.seal()?;
    migrated.validate()?;
    Ok(migrated)
}

fn recover_or_migrate_engine_state(root: &Path) -> Result<(), ReproductionError> {
    let state_path = root.join(STATE_FILE_NAME);
    let package_directory = root.join(PACKAGE_DIRECTORY_NAME);
    let intent_path = root.join(ENGINE_MIGRATION_INTENT_FILE);
    let backup_path = root.join(ENGINE_MIGRATION_BACKUP_FILE);
    if intent_path.exists() {
        let intent: EngineSchemaMigrationIntent = read_json(&intent_path)?;
        let backup = read_bounded(&backup_path, 32 * 1_048_576)?;
        require_digest(
            "engine state migration backup",
            &intent.backup_digest,
            &ContentDigest::from_bytes(&backup),
        )?;
        let current_is_valid_target = read_bounded(&state_path, 32 * 1_048_576)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<ReproductionState>(&bytes).ok())
            .is_some_and(|state| {
                state.validate().is_ok() && verify_package_index(&package_directory, &state).is_ok()
            });
        if !current_is_valid_target {
            atomic_write(&state_path, &backup)?;
        }
        remove_internal_file_if_present(&intent_path)?;
        remove_internal_file_if_present(&backup_path)?;
    }
    if !state_path.exists() {
        return Ok(());
    }
    let bytes = read_bounded(&state_path, 32 * 1_048_576)?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| ReproductionError::Serialization(error.to_string()))?;
    let version = value
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            ReproductionError::StateIntegrity(
                "durable state does not declare a schema version".to_string(),
            )
        })? as u32;
    if version == REPRODUCTION_STATE_SCHEMA_VERSION {
        return Ok(());
    }
    let migrated = match version {
        1 => {
            let legacy: LegacyReproductionStateV1 = serde_json::from_slice(&bytes)
                .map_err(|error| ReproductionError::Serialization(error.to_string()))?;
            legacy.migrate()?
        }
        2 => migrate_causally_clean_v2(&bytes)?,
        4 => migrate_provider_accounting_clean_v4(&bytes)?,
        5 => migrate_provider_output_bound_clean_v5(&bytes)?,
        _ => return Err(ReproductionError::UnsupportedStateSchema(version)),
    };
    // A schema migration must not make an otherwise recoverable legacy state
    // authoritative until every package referenced by the migrated index has
    // been re-opened and content-verified.  In particular, a missing or
    // substituted package must leave the exact legacy state bytes untouched.
    verify_package_index(&package_directory, &migrated)?;
    let intent = EngineSchemaMigrationIntent {
        from_schema: version,
        to_schema: REPRODUCTION_STATE_SCHEMA_VERSION,
        source_digest: ContentDigest::from_bytes(&bytes),
        backup_digest: ContentDigest::from_bytes(&bytes),
    };
    atomic_write(&backup_path, &bytes)?;
    atomic_write_json(&intent_path, &intent)?;
    atomic_write_json(&state_path, &migrated)?;
    let verified: ReproductionState = read_json(&state_path)?;
    verified.validate()?;
    // Recheck after the atomic state replacement and before deleting the
    // recovery material.  A concurrent package substitution therefore leaves
    // the migration intent and backup available for the next open to restore.
    verify_package_index(&package_directory, &verified)?;
    remove_internal_file_if_present(&intent_path)?;
    remove_internal_file_if_present(&backup_path)?;
    Ok(())
}

fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, ReproductionError> {
    serde_json::to_vec(value).map_err(|error| ReproductionError::Serialization(error.to_string()))
}

fn digest_serializable<T: Serialize>(value: &T) -> Result<ContentDigest, ReproductionError> {
    Ok(ContentDigest::from_bytes(&canonical_json(value)?))
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T, ReproductionError> {
    let bytes = read_bounded(path, 32 * 1_048_576)?;
    serde_json::from_slice(&bytes)
        .map_err(|error| ReproductionError::Serialization(error.to_string()))
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, ReproductionError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| ReproductionError::io(path, error))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ReproductionError::UnsafePath(format!(
            "'{}' must be a regular non-symlink file",
            path.display()
        )));
    }
    if metadata.len() > limit as u64 {
        return Err(ReproductionError::BudgetExceeded(format!(
            "'{}' exceeds its {limit}-byte read limit",
            path.display()
        )));
    }
    let mut file = File::open(path).map_err(|error| ReproductionError::io(path, error))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|error| ReproductionError::io(path, error))?;
    if bytes.len() > limit {
        return Err(ReproductionError::BudgetExceeded(format!(
            "'{}' exceeded its read limit while being read",
            path.display()
        )));
    }
    Ok(bytes)
}

fn persist_immutable(path: &Path, bytes: &[u8]) -> Result<(), ReproductionError> {
    if path.exists() {
        let existing = read_bounded(path, MAX_PACKAGE_BYTES)?;
        if existing == bytes {
            return Ok(());
        }
        return Err(ReproductionError::StateIntegrity(format!(
            "immutable content at '{}' differs from supplied bytes",
            path.display()
        )));
    }
    atomic_write(path, bytes)
}

fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), ReproductionError> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| ReproductionError::Serialization(error.to_string()))?;
    atomic_write(path, &bytes)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), ReproductionError> {
    let parent = path.parent().ok_or_else(|| {
        ReproductionError::UnsafePath(format!("'{}' has no parent", path.display()))
    })?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| {
            ReproductionError::UnsafePath(format!("'{}' has no UTF-8 file name", path.display()))
        })?;
    let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(
        ".{file_name}.tmp-{}-{sequence}",
        std::process::id()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| ReproductionError::io(&temporary, error))?;
        file.write_all(bytes)
            .map_err(|error| ReproductionError::io(&temporary, error))?;
        file.sync_all()
            .map_err(|error| ReproductionError::io(&temporary, error))?;
        drop(file);
        fs::rename(&temporary, path).map_err(|error| ReproductionError::io(path, error))?;
        let directory = File::open(parent).map_err(|error| ReproductionError::io(parent, error))?;
        directory
            .sync_all()
            .map_err(|error| ReproductionError::io(parent, error))
    })();
    if result.is_err() && temporary.exists() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn remove_internal_file_if_present(path: &Path) -> Result<(), ReproductionError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(ReproductionError::io(path, error)),
    }
}

fn reject_symlink_if_present(path: &Path) -> Result<(), ReproductionError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(ReproductionError::UnsafePath(
            format!("'{}' is a symbolic link", path.display()),
        )),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(ReproductionError::io(path, error)),
    }
}

fn validate_identifier(label: &str, value: &str) -> Result<(), ReproductionError> {
    if value.trim().is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        return Err(ReproductionError::InvalidConfiguration(format!(
            "{label} must contain 1..=512 non-control characters"
        )));
    }
    Ok(())
}

fn require_digest(
    subject: &str,
    actual: &ContentDigest,
    expected: &ContentDigest,
) -> Result<(), ReproductionError> {
    if actual != expected {
        return Err(ReproductionError::DigestMismatch {
            subject: subject.to_string(),
            expected: expected.clone(),
            actual: actual.clone(),
        });
    }
    Ok(())
}

#[derive(Debug)]
pub enum ReproductionError {
    AlreadyInitialized,
    NotInitialized,
    StateOwnerConflict(PathBuf),
    UnsupportedStateSchema(u32),
    InvalidConfiguration(String),
    InvalidPackage(String),
    InterfaceMismatch {
        expected: String,
        actual: String,
    },
    DigestMismatch {
        subject: String,
        expected: ContentDigest,
        actual: ContentDigest,
    },
    ParentMismatch {
        expected: ContentDigest,
        actual: Option<ContentDigest>,
    },
    ActivePackageMismatch {
        expected: ContentDigest,
        actual: ContentDigest,
    },
    GateMismatch {
        expected: ContentDigest,
        actual: ContentDigest,
    },
    EvidenceMismatch(String),
    EvidenceRejected(String),
    ApprovalMismatch(String),
    StateCompatibility(String),
    StateIntegrity(String),
    BudgetExceeded(String),
    DuplicateCycleId(String),
    NoRetainedIncumbent,
    RecoveryRequired,
    RecoveryFailed(String),
    ProviderQualification(String),
    Port {
        phase: &'static str,
        failure: PortFailure,
    },
    UnsafePath(String),
    Serialization(String),
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

impl ReproductionError {
    fn port(phase: &'static str, failure: PortFailure) -> Self {
        Self::Port { phase, failure }
    }

    fn io(path: &Path, source: std::io::Error) -> Self {
        Self::Io {
            path: path.to_path_buf(),
            source,
        }
    }
}

impl Display for ReproductionError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyInitialized => write!(formatter, "factory engine is already initialized"),
            Self::NotInitialized => write!(formatter, "factory engine is not initialized"),
            Self::StateOwnerConflict(path) => write!(
                formatter,
                "factory engine root '{}' already has a live owner",
                path.display()
            ),
            Self::UnsupportedStateSchema(version) => {
                write!(formatter, "unsupported reproduction state schema {version}")
            }
            Self::InvalidConfiguration(message) => {
                write!(formatter, "invalid reproduction configuration: {message}")
            }
            Self::InvalidPackage(message) => {
                write!(formatter, "invalid factory package: {message}")
            }
            Self::InterfaceMismatch { expected, actual } => write!(
                formatter,
                "stable interface mismatch: expected '{expected}', got '{actual}'"
            ),
            Self::DigestMismatch {
                subject,
                expected,
                actual,
            } => write!(
                formatter,
                "{subject} digest mismatch: expected {expected}, got {actual}"
            ),
            Self::ParentMismatch { expected, actual } => write!(
                formatter,
                "genome parent mismatch: expected {expected}, got {actual:?}"
            ),
            Self::ActivePackageMismatch { expected, actual } => write!(
                formatter,
                "active package mismatch: expected {expected}, got {actual}"
            ),
            Self::GateMismatch { expected, actual } => {
                write!(
                    formatter,
                    "release gate mismatch: expected {expected}, got {actual}"
                )
            }
            Self::EvidenceMismatch(message) => {
                write!(formatter, "evidence binding mismatch: {message}")
            }
            Self::EvidenceRejected(message) => {
                write!(formatter, "execution evidence rejected: {message}")
            }
            Self::ApprovalMismatch(message) => {
                write!(formatter, "supervisor approval mismatch: {message}")
            }
            Self::StateCompatibility(message) => {
                write!(formatter, "state compatibility failure: {message}")
            }
            Self::StateIntegrity(message) => {
                write!(formatter, "durable state integrity failure: {message}")
            }
            Self::BudgetExceeded(message) => write!(formatter, "budget exceeded: {message}"),
            Self::DuplicateCycleId(cycle_id) => {
                write!(formatter, "cycle id '{cycle_id}' is already recorded")
            }
            Self::NoRetainedIncumbent => write!(formatter, "no retained incumbent is available"),
            Self::RecoveryRequired => write!(
                formatter,
                "an interrupted effect must be recovered before another operation"
            ),
            Self::RecoveryFailed(message) => write!(formatter, "recovery failed: {message}"),
            Self::ProviderQualification(message) => {
                write!(formatter, "provider qualification failure: {message}")
            }
            Self::Port { phase, failure } => write!(
                formatter,
                "{phase} port {:?} ({}): {}",
                failure.kind, failure.code, failure.message
            ),
            Self::UnsafePath(message) => write!(formatter, "unsafe path: {message}"),
            Self::Serialization(message) => write!(formatter, "serialization failed: {message}"),
            Self::Io { path, source } => {
                write!(formatter, "I/O failed at '{}': {source}", path.display())
            }
        }
    }
}

impl Error for ReproductionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::sync::Mutex;

    static TEST_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(1);
    const ENGINE_LOCK_CHILD_ROOT_ENV: &str = "WASM_BIOTIC_ENGINE_LOCK_CHILD_ROOT";

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let sequence = TEST_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "wasm-biotic-m5-{label}-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create isolated test directory");
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            if self.0.exists() {
                fs::remove_dir_all(&self.0).expect("remove isolated test directory");
            }
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum M1Mode {
        Valid,
        WrongInterface,
        NotRunnable,
    }

    struct TestM1 {
        mode: Mutex<M1Mode>,
        calls: AtomicU64,
    }

    impl TestM1 {
        fn new() -> Self {
            Self {
                mode: Mutex::new(M1Mode::Valid),
                calls: AtomicU64::new(0),
            }
        }
    }

    impl M1CandidatePort for TestM1 {
        fn build_and_prove(
            &self,
            request: &M1BuildRequest,
        ) -> Result<M1BuildEvidence, PortFailure> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let mode = *self.mode.lock().expect("lock M1 mode");
            M1BuildEvidence {
                request_digest: request.request_digest.clone(),
                component_digest: request.component_digest.clone(),
                stable_interface_digest: if mode == M1Mode::WrongInterface {
                    ContentDigest::from_bytes(b"wrong-interface")
                } else {
                    request.stable_interface_digest.clone()
                },
                observed_export: REFERENCE_EXPORT.to_string(),
                runnable: mode != M1Mode::NotRunnable,
                proving_record_digest: ContentDigest::from_bytes(&request.component_bytes),
                evidence_digest: ContentDigest::from_bytes(&[]),
            }
            .seal()
            .map_err(|error| PortFailure::failed("fixture_seal", error.to_string()))
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum SupervisorMode {
        Approve,
        Reject,
        WrongPackage,
        WrongEvidence,
    }

    struct TestM2 {
        mode: Mutex<SupervisorMode>,
        calls: AtomicU64,
    }

    impl TestM2 {
        fn new() -> Self {
            Self {
                mode: Mutex::new(SupervisorMode::Approve),
                calls: AtomicU64::new(0),
            }
        }
    }

    impl M2SupervisorPort for TestM2 {
        fn decide(
            &self,
            request: &SupervisorApprovalRequest,
        ) -> Result<SupervisorApprovalRecord, PortFailure> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let mode = *self.mode.lock().expect("lock supervisor mode");
            let approved = mode != SupervisorMode::Reject;
            let package_digest = if mode == SupervisorMode::WrongPackage {
                ContentDigest::from_bytes(b"wrong-package")
            } else {
                request.challenger_package_digest.clone()
            };
            let mut evidence_digests = vec![
                request.m1_evidence_digest.clone(),
                request.worker_evidence_digest.clone(),
                request.shadow_evidence_digest.clone(),
            ];
            if mode == SupervisorMode::WrongEvidence {
                evidence_digests[0] = ContentDigest::from_bytes(b"wrong-evidence");
            }
            SupervisorApprovalRecord {
                approval_id: format!("approval:{}", request.cycle_id),
                request_digest: request.request_digest.clone(),
                decision: if approved {
                    ApprovalDecision::Approved
                } else {
                    ApprovalDecision::Rejected
                },
                approved_package_digest: approved.then_some(package_digest),
                approved_package_bytes_digest: approved
                    .then_some(request.challenger_package_bytes_digest.clone()),
                gate_decision_digest: request.gate_decision_digest.clone(),
                evidence_digests,
                approver_ref: "test-supervisor".to_string(),
                rationale: if approved {
                    "all independently derived gates passed".to_string()
                } else {
                    "operator rejected the candidate".to_string()
                },
                approval_digest: ContentDigest::from_bytes(&[]),
            }
            .seal()
            .map_err(|error| PortFailure::failed("fixture_seal", error.to_string()))
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ShadowMode {
        Valid,
        Regression,
        WrongPackage,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ActivationMode {
        Valid,
        Fail,
        WrongBytes,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ObservationMode {
        Healthy,
        Regression,
        WrongPackage,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum DriverMode {
        Valid(i32),
        WrongTraceInput,
        WrongTraceComponent,
    }

    #[derive(Default)]
    struct RuntimeState {
        active_package: Option<ContentDigest>,
        active_state_schema: u32,
        migration_calls: u64,
        activation_calls: u64,
        observation_calls: u64,
        recovery_calls: u64,
    }

    struct TestM3 {
        driver_mode: Mutex<DriverMode>,
        driver_calls: AtomicU64,
        shadow_mode: Mutex<ShadowMode>,
        activation_mode: Mutex<ActivationMode>,
        observation_mode: Mutex<ObservationMode>,
        runtime: Mutex<RuntimeState>,
    }

    impl TestM3 {
        fn new() -> Self {
            Self {
                driver_mode: Mutex::new(DriverMode::Valid(1)),
                driver_calls: AtomicU64::new(0),
                shadow_mode: Mutex::new(ShadowMode::Valid),
                activation_mode: Mutex::new(ActivationMode::Valid),
                observation_mode: Mutex::new(ObservationMode::Healthy),
                runtime: Mutex::new(RuntimeState::default()),
            }
        }
    }

    impl M3CapabilityPort for TestM3 {
        fn execute_generation_driver(
            &self,
            request: &GenerationDriverRequest,
        ) -> Result<GenerationDriverEvidence, PortFailure> {
            self.driver_calls.fetch_add(1, Ordering::Relaxed);
            let mode = *self.driver_mode.lock().expect("lock driver mode");
            let directive = match mode {
                DriverMode::Valid(directive) => directive,
                DriverMode::WrongTraceInput | DriverMode::WrongTraceComponent => 1,
            };
            let trace = ComponentI32ExecutionTrace {
                component_digest: if mode == DriverMode::WrongTraceComponent {
                    ContentDigest::from_bytes(b"wrong-driver-component")
                } else {
                    request.executor_component_digest.clone()
                },
                export_name: request.driver_contract.exported_function.clone(),
                input: if mode == DriverMode::WrongTraceInput {
                    request.driver_contract.driver_input.saturating_add(1)
                } else {
                    request.driver_contract.driver_input
                },
                output: Some(directive),
                trapped: false,
                failure_phase: None,
                limit_exhausted: None,
                limits: crate::execution::component::ComponentExecutionLimits::default(),
                fuel_consumed: 1,
                invoked_imports: Vec::new(),
                import_link_audits: Vec::new(),
                diagnostics: Vec::new(),
            };
            GenerationDriverEvidence {
                request_digest: request.request_digest.clone(),
                invocation_id: format!("driver:{}", request.cycle_id),
                executor_package_digest: request.executor_package_digest.clone(),
                executor_package_bytes_digest: request.executor_package_bytes_digest.clone(),
                executor_component_digest: request.executor_component_digest.clone(),
                instruction_digest: request.instruction_digest.clone(),
                trace,
                directive,
                service_receipt_digest: ContentDigest::from_bytes(
                    format!("driver-receipt:{}", request.cycle_id).as_bytes(),
                ),
                service_attestation_digest: ContentDigest::from_bytes(
                    format!("driver-attestation:{}", request.cycle_id).as_bytes(),
                ),
                evidence_digest: ContentDigest::from_bytes(&[]),
            }
            .seal()
            .map_err(|error| PortFailure::failed("fixture_seal", error.to_string()))
        }

        fn run_shadow(
            &self,
            request: &ShadowExecutionRequest,
        ) -> Result<ShadowExecutionEvidence, PortFailure> {
            let mode = *self.shadow_mode.lock().expect("lock shadow mode");
            let challenger_package =
                FactoryPackage::from_canonical_bytes(&request.challenger_package_bytes)
                    .map_err(|error| PortFailure::failed("fixture_package", error.to_string()))?;
            let mut incumbent_observations = Vec::new();
            let mut challenger_observations = Vec::new();
            for benchmark in &request.gate.benchmarks {
                let request_digest = ContentDigest::from_bytes(&benchmark.request_bytes);
                incumbent_observations.push(TaskExecutionObservation {
                    execution_id: format!("incumbent:{}", benchmark.benchmark_id),
                    benchmark_id: benchmark.benchmark_id.clone(),
                    package_digest: request.incumbent_package_digest.clone(),
                    request_digest: request_digest.clone(),
                    output_digest: Some(benchmark.expected_output_digest.clone()),
                    terminal: ExecutionTerminal::Succeeded,
                    health: HealthStatus::Healthy,
                    duration_ms: 1,
                });
                challenger_observations.push(TaskExecutionObservation {
                    execution_id: format!("challenger:{}", benchmark.benchmark_id),
                    benchmark_id: benchmark.benchmark_id.clone(),
                    package_digest: if mode == ShadowMode::WrongPackage {
                        ContentDigest::from_bytes(b"wrong-shadow-package")
                    } else {
                        request.challenger_package_digest.clone()
                    },
                    request_digest,
                    output_digest: Some(benchmark.expected_output_digest.clone()),
                    terminal: ExecutionTerminal::Succeeded,
                    health: HealthStatus::Healthy,
                    duration_ms: 1,
                });
            }
            if mode == ShadowMode::Regression {
                challenger_observations[0].output_digest =
                    Some(ContentDigest::from_bytes(b"regression"));
            }
            let invariant_observations = request
                .gate
                .invariants
                .iter()
                .map(|invariant| InvariantObservation {
                    invariant_id: invariant.invariant_id.clone(),
                    package_digest: request.challenger_package_digest.clone(),
                    satisfied: true,
                    evidence_digest: ContentDigest::from_bytes(invariant.invariant_id.as_bytes()),
                })
                .collect::<Vec<_>>();
            ShadowExecutionEvidence {
                request_digest: request.request_digest.clone(),
                resource_usage: ResourceUsage {
                    shadow_tasks: (incumbent_observations.len() + challenger_observations.len())
                        as u32,
                    component_bytes: challenger_package.payload.genome.component_bytes.len() as u64,
                    state_bytes: 64,
                },
                incumbent_observations,
                challenger_observations,
                invariant_observations,
                evidence_digest: ContentDigest::from_bytes(&[]),
            }
            .seal()
            .map_err(|error| PortFailure::failed("fixture_seal", error.to_string()))
        }

        fn migrate_state(
            &self,
            request: &MigrationRequest,
        ) -> Result<MigrationReceipt, PortFailure> {
            self.runtime.lock().expect("lock runtime").migration_calls += 1;
            MigrationReceipt {
                request_digest: request.request_digest.clone(),
                migration_id: request.plan.migration_id.clone(),
                from_schema: request.plan.from_schema,
                to_schema: request.plan.to_schema,
                pre_migration_state_digest: ContentDigest::from_bytes(b"state-v1"),
                post_migration_state_digest: ContentDigest::from_bytes(b"state-v2"),
                rollback_backup_digest: ContentDigest::from_bytes(b"state-v1-backup"),
                rollback_verified: true,
                receipt_digest: ContentDigest::from_bytes(&[]),
            }
            .seal()
            .map_err(|error| PortFailure::failed("fixture_seal", error.to_string()))
        }

        fn activate_exact(
            &self,
            request: &ActivationRequest,
        ) -> Result<ActivationReceipt, PortFailure> {
            let mode = *self.activation_mode.lock().expect("lock activation mode");
            if mode == ActivationMode::Fail {
                return Err(PortFailure::failed(
                    "induced_activation_failure",
                    "activation failed after the migration boundary",
                ));
            }
            let mut runtime = self.runtime.lock().expect("lock runtime");
            runtime.activation_calls += 1;
            runtime.active_package = Some(request.challenger_package_digest.clone());
            runtime.active_state_schema = request.target_state_schema;
            ActivationReceipt {
                activation_id: format!("activation:{}", request.cycle_id),
                request_digest: request.request_digest.clone(),
                previous_package_digest: request.incumbent_package_digest.clone(),
                active_package_digest: request.challenger_package_digest.clone(),
                active_package_bytes_digest: if mode == ActivationMode::WrongBytes {
                    ContentDigest::from_bytes(b"wrong-active-bytes")
                } else {
                    ContentDigest::from_bytes(&request.challenger_package_bytes)
                },
                active_state_schema: request.target_state_schema,
                receipt_digest: ContentDigest::from_bytes(&[]),
            }
            .seal()
            .map_err(|error| PortFailure::failed("fixture_seal", error.to_string()))
        }

        fn observe_active(
            &self,
            request: &PostActivationRequest,
        ) -> Result<PostActivationEvidence, PortFailure> {
            self.runtime.lock().expect("lock runtime").observation_calls += 1;
            let mode = *self.observation_mode.lock().expect("lock observation mode");
            let package_digest = if mode == ObservationMode::WrongPackage {
                ContentDigest::from_bytes(b"wrong-observation-package")
            } else {
                request.active_package_digest.clone()
            };
            let mut task_observations = (0..request.minimum_successes)
                .map(|index| TaskExecutionObservation {
                    execution_id: format!("live-task:{index}"),
                    benchmark_id: format!("live-reference-task:{index}"),
                    package_digest: package_digest.clone(),
                    request_digest: ContentDigest::from_bytes(
                        format!("live-request:{index}").as_bytes(),
                    ),
                    output_digest: Some(ContentDigest::from_bytes(
                        format!("live-output:{index}").as_bytes(),
                    )),
                    terminal: ExecutionTerminal::Succeeded,
                    health: HealthStatus::Healthy,
                    duration_ms: 1,
                })
                .collect::<Vec<_>>();
            if mode == ObservationMode::Regression {
                task_observations[0].terminal = ExecutionTerminal::Trapped;
                task_observations[0].output_digest = None;
            }
            let health_observations = vec![HealthObservation {
                check_id: "runtime-health".to_string(),
                active_package_digest: package_digest,
                status: if mode == ObservationMode::Regression {
                    HealthStatus::Unhealthy
                } else {
                    HealthStatus::Healthy
                },
                measurement_digest: ContentDigest::from_bytes(b"runtime-health"),
            }];
            PostActivationEvidence {
                request_digest: request.request_digest.clone(),
                active_package_digest: request.active_package_digest.clone(),
                task_observations,
                health_observations,
                evidence_digest: ContentDigest::from_bytes(&[]),
            }
            .seal()
            .map_err(|error| PortFailure::failed("fixture_seal", error.to_string()))
        }

        fn recover_to_incumbent(
            &self,
            request: &RecoveryRequest,
        ) -> Result<RecoveryReceipt, PortFailure> {
            let mut runtime = self.runtime.lock().expect("lock runtime");
            runtime.recovery_calls += 1;
            runtime.active_package = Some(request.restore_package_digest.clone());
            runtime.active_state_schema = request.restore_state_schema;
            RecoveryReceipt {
                recovery_id: request.recovery_id.clone(),
                request_digest: request.request_digest.clone(),
                restored_package_digest: request.restore_package_digest.clone(),
                restored_package_bytes_digest: ContentDigest::from_bytes(
                    &request.restore_package_bytes,
                ),
                restored_state_schema: request.restore_state_schema,
                state_readable: true,
                receipt_digest: ContentDigest::from_bytes(&[]),
            }
            .seal()
            .map_err(|error| PortFailure::failed("fixture_seal", error.to_string()))
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum WorkerMode {
        Valid,
        WrongPackage,
        WrongMaterialization,
    }

    struct TestM4 {
        mode: Mutex<WorkerMode>,
        workflow_calls: AtomicU64,
        materialization_calls: AtomicU64,
    }

    impl TestM4 {
        fn new() -> Self {
            Self {
                mode: Mutex::new(WorkerMode::Valid),
                workflow_calls: AtomicU64::new(0),
                materialization_calls: AtomicU64::new(0),
            }
        }
    }

    impl M4WorkerPort for TestM4 {
        fn execute_workflow(
            &self,
            request: &WorkerWorkflowRequest,
        ) -> Result<WorkerWorkflowEvidence, PortFailure> {
            self.workflow_calls.fetch_add(1, Ordering::Relaxed);
            let mode = *self.mode.lock().expect("lock worker mode");
            let receipts = request
                .required_roles
                .iter()
                .copied()
                .map(|role| WorkerReceipt {
                    role,
                    execution_id: format!("worker:{role:?}:{}", request.cycle_id),
                    terminal_status: WorkerTerminalStatus::Succeeded,
                    input_digest: request.request_digest.clone(),
                    output_digest: Some(ContentDigest::from_bytes(
                        format!("worker-output:{role:?}").as_bytes(),
                    )),
                })
                .collect();
            WorkerWorkflowEvidence {
                request_digest: request.request_digest.clone(),
                challenger_package_digest: if mode == WorkerMode::WrongPackage {
                    ContentDigest::from_bytes(b"wrong-worker-package")
                } else {
                    request.challenger_package_digest.clone()
                },
                receipts,
                evidence_digest: ContentDigest::from_bytes(&[]),
            }
            .seal()
            .map_err(|error| PortFailure::failed("fixture_seal", error.to_string()))
        }

        fn materialize_generation(
            &self,
            request: &GenerationMaterializationRequest,
        ) -> Result<GenerationMaterializationEvidence, PortFailure> {
            self.materialization_calls.fetch_add(1, Ordering::Relaxed);
            let mode = *self.mode.lock().expect("lock worker mode");
            let rendered_wat_bytes = render_reference_delta_v1(request.directive)
                .map_err(|error| PortFailure::failed("fixture_render", error.to_string()))?;
            let successor_component_bytes = if mode == WorkerMode::WrongMaterialization {
                component_bytes(99)
            } else {
                compile_reference_delta_v1(&rendered_wat_bytes)
                    .map_err(|error| PortFailure::failed("fixture_compile", error.to_string()))?
            };
            let worker_receipts = WorkerRole::required()
                .into_iter()
                .map(|role| WorkerReceipt {
                    role,
                    execution_id: format!("generation:{role:?}:{}", request.cycle_id),
                    terminal_status: WorkerTerminalStatus::Succeeded,
                    input_digest: request.request_digest.clone(),
                    output_digest: Some(ContentDigest::from_bytes(
                        format!("generation-output:{role:?}").as_bytes(),
                    )),
                })
                .collect();
            GenerationMaterializationEvidence {
                request_digest: request.request_digest.clone(),
                driver_evidence_digest: request.driver_evidence_digest.clone(),
                rendered_wat_digest: ContentDigest::from_bytes(&rendered_wat_bytes),
                rendered_wat_bytes,
                successor_component_digest: ContentDigest::from_bytes(&successor_component_bytes),
                successor_component_bytes,
                workflow_id: format!("generation-workflow:{}", request.cycle_id),
                worker_receipts,
                workflow_evidence_digest: ContentDigest::from_bytes(
                    format!("generation-workflow-evidence:{}", request.cycle_id).as_bytes(),
                ),
                evidence_digest: ContentDigest::from_bytes(&[]),
            }
            .seal()
            .map_err(|error| PortFailure::failed("fixture_seal", error.to_string()))
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ProviderMode {
        Valid,
        Unavailable,
        LiveFailure,
        ReplayMismatch,
        ReplayUsesNetwork,
    }

    struct TestProvider {
        mode: Mutex<ProviderMode>,
        last_intent: Mutex<Option<ParsedProviderIntent>>,
    }

    impl TestProvider {
        fn new() -> Self {
            Self {
                mode: Mutex::new(ProviderMode::Valid),
                last_intent: Mutex::new(None),
            }
        }
    }

    impl LiveProviderQualificationPort for TestProvider {
        fn perform_live_turn(
            &self,
            request: &ProviderQualificationRequest,
        ) -> Result<LiveProviderTurn, PortFailure> {
            let mode = *self.mode.lock().expect("lock provider mode");
            if mode == ProviderMode::Unavailable {
                return Err(PortFailure::unavailable(
                    "provider_unavailable",
                    "provider fixture unavailable",
                ));
            }
            if mode == ProviderMode::LiveFailure {
                return Err(PortFailure::failed(
                    "provider_failed",
                    "provider fixture failed",
                ));
            }
            let intent = ParsedProviderIntent {
                intent_schema: M5_PROVIDER_INTENT_SCHEMA.to_string(),
                operation: "propose_component".to_string(),
                target_genome_digest: ContentDigest::from_bytes(b"provider-target"),
                arguments: BTreeMap::from([(
                    "bounded_change".to_string(),
                    "increment".to_string(),
                )]),
            };
            *self.last_intent.lock().expect("lock provider intent") = Some(intent.clone());
            let normalized_parser_input_bytes = serde_json::to_vec(&intent)
                .map_err(|error| PortFailure::failed("fixture_encode", error.to_string()))?;
            let transcript = RedactedTranscript {
                request_digest: request.request_digest.clone(),
                redacted_prompt: "[REDACTED PROMPT]".to_string(),
                redacted_response: String::from_utf8(normalized_parser_input_bytes.clone())
                    .map_err(|error| PortFailure::failed("fixture_encode", error.to_string()))?,
                raw_prompt_digest: ContentDigest::from_bytes(&request.prompt_bytes),
                raw_response_digest: ContentDigest::from_bytes(b"raw-provider-response"),
                redaction_applied: true,
            };
            let provider_accounting = M5ProviderAccountingSummaryV1::new(
                request.configuration.provider_id.clone(),
                request.configuration.model_id.clone(),
                request.configuration.provider_profile,
                request.configuration.response_schema_digest.clone(),
                request.configuration.generation_policy_id.clone(),
                request.configuration.generation_policy_digest.clone(),
                request.configuration.maximum_retries,
                request.configuration.maximum_output_tokens,
                request.configuration.input_cost_per_million_microunits,
                request.configuration.output_cost_per_million_microunits,
                InferenceFinishReason::Completed,
                10,
                5,
                15,
                1,
                request.configuration.cost_currency.clone(),
                7,
                vec![M5ProviderAttemptSummaryV1 {
                    attempt_number: 1,
                    http_status: Some(200),
                    latency_ms: 7,
                    retry_classification: InferenceRetryClassification::NoRetryNeeded,
                    request_body_digest: ContentDigest::from_bytes(b"provider-request-body"),
                    raw_response_digest: transcript.raw_response_digest.clone(),
                }],
                &transcript,
            )
            .map_err(|error| PortFailure::failed("fixture_accounting", error.to_string()))?;
            LiveProviderTurn {
                request_digest: request.request_digest.clone(),
                configuration_fingerprint: request
                    .configuration
                    .fingerprint()
                    .map_err(|error| PortFailure::failed("fixture_config", error.to_string()))?,
                replay_capsule_digest: request.replay_capsule.capsule_digest.clone(),
                transport: ProviderTransport::LiveProviderApi,
                external_turn_id: "provider-turn:real-fixture".to_string(),
                provider_receipt_digest: provider_accounting.accounting_digest.clone(),
                provider_accounting,
                transcript,
                normalized_parser_input_bytes,
                parsed_intent: intent,
                turn_digest: ContentDigest::from_bytes(&[]),
            }
            .seal()
            .map_err(|error| PortFailure::failed("fixture_seal", error.to_string()))
        }

        fn replay_offline(
            &self,
            request: &ProviderReplayRequest,
        ) -> Result<ProviderReplayRecord, PortFailure> {
            let mode = *self.mode.lock().expect("lock provider mode");
            let mut intent = self
                .last_intent
                .lock()
                .expect("lock provider intent")
                .clone()
                .ok_or_else(|| {
                    PortFailure::failed("missing_live_intent", "live intent not retained")
                })?;
            if mode == ProviderMode::ReplayMismatch {
                intent.operation = "different_operation".to_string();
            }
            ProviderReplayRecord {
                request_digest: request.request_digest.clone(),
                network_used: mode == ProviderMode::ReplayUsesNetwork,
                parsed_intent: intent,
                parser_digest: request.expected_parser_digest.clone(),
                replay_digest: ContentDigest::from_bytes(&[]),
            }
            .seal()
            .map_err(|error| PortFailure::failed("fixture_seal", error.to_string()))
        }
    }

    struct TestRig {
        m1: Arc<TestM1>,
        m2: Arc<TestM2>,
        m3: Arc<TestM3>,
        m4: Arc<TestM4>,
        provider: Arc<TestProvider>,
    }

    impl TestRig {
        fn new() -> Self {
            Self {
                m1: Arc::new(TestM1::new()),
                m2: Arc::new(TestM2::new()),
                m3: Arc::new(TestM3::new()),
                m4: Arc::new(TestM4::new()),
                provider: Arc::new(TestProvider::new()),
            }
        }

        fn ports(&self) -> ReproductionPorts {
            ReproductionPorts {
                m1_candidate: self.m1.clone(),
                m2_supervisor: self.m2.clone(),
                m3_capability: self.m3.clone(),
                m4_workers: self.m4.clone(),
                live_provider: Some(self.provider.clone()),
            }
        }

        fn ports_without_provider(&self) -> ReproductionPorts {
            ReproductionPorts {
                m1_candidate: self.m1.clone(),
                m2_supervisor: self.m2.clone(),
                m3_capability: self.m3.clone(),
                m4_workers: self.m4.clone(),
                live_provider: None,
            }
        }
    }

    fn component_bytes(increment: i32) -> Vec<u8> {
        wat::parse_str(format!(
            r#"(component
                (core module $implementation
                    (func (export "transform") (param i32) (result i32)
                        local.get 0
                        i32.const {increment}
                        i32.add))
                (core instance $instance (instantiate $implementation))
                (func (export "transform") (param "input" s32) (result s32)
                    (canon lift (core func $instance "transform"))))"#
        ))
        .expect("compile fixture component")
    }

    fn compatibility(schema: u32) -> StateCompatibility {
        StateCompatibility {
            readable_schema_min: 1,
            readable_schema_max: 2,
            written_schema: schema,
            incumbent_rollback_readable_through: 2,
        }
    }

    fn release_gate() -> ReleaseGate {
        let benchmarks = [1_i32, 7_i32]
            .into_iter()
            .enumerate()
            .map(|(index, input)| BenchmarkSpec {
                benchmark_id: format!("benchmark:{index}"),
                request_bytes: input.to_le_bytes().to_vec(),
                expected_output_digest: ContentDigest::from_bytes(&(input + 1).to_le_bytes()),
                max_duration_ms: 100,
                required: true,
            })
            .collect();
        let invariants = [
            InvariantKind::StableInterface,
            InvariantKind::RunnableComponent,
            InvariantKind::ExactPackageIdentity,
            InvariantKind::BoundedCapabilities,
            InvariantKind::DurableRollback,
        ]
        .into_iter()
        .enumerate()
        .map(|(index, kind)| InvariantSpec {
            invariant_id: format!("invariant:{index}"),
            kind,
            required: true,
        })
        .collect();
        ReleaseGate::new(
            "reference-release-gate",
            benchmarks,
            invariants,
            RecursionBudgets {
                max_generation_depth: 4,
                max_total_cycles: 8,
                max_shadow_tasks: 4,
                max_component_bytes: MAX_COMPONENT_BYTES as u64,
                max_state_bytes: 4_096,
                max_provider_turns: 8,
            },
            ReleaseThresholds {
                minimum_passed_benchmarks: 2,
                minimum_success_basis_points: 10_000,
                maximum_regressions: 0,
                require_all_required_invariants: true,
                minimum_post_activation_successes: 2,
            },
        )
        .expect("valid fixture release gate")
    }

    fn package(
        generation: u32,
        parent: Option<ContentDigest>,
        component: Vec<u8>,
        policy: MutableFactoryPolicy,
        schema: u32,
    ) -> FactoryPackage {
        FactoryPackage::build(
            "factory:test",
            generation,
            MutableGenome::new(parent, component, policy).expect("valid fixture genome"),
            StableInterfaceContract::reference(),
            WorkerCatalog::reference().expect("valid worker catalog"),
            ServiceDependencyCatalog::reference().expect("valid service catalog"),
            compatibility(schema),
        )
        .expect("valid fixture package")
    }

    fn package_with_catalogs(
        worker_catalog: WorkerCatalog,
        service_dependencies: ServiceDependencyCatalog,
    ) -> Result<FactoryPackage, ReproductionError> {
        FactoryPackage::build(
            "factory:test",
            0,
            MutableGenome::new(
                None,
                component_bytes(0),
                MutableFactoryPolicy::terminal(1, 2),
            )
            .expect("valid fixture genome"),
            StableInterfaceContract::reference(),
            worker_catalog,
            service_dependencies,
            compatibility(1),
        )
    }

    fn r8_worker_catalog_fixture() -> WorkerCatalog {
        let mut entries = WorkerCatalog::reference()
            .expect("valid current worker catalog")
            .entries;
        entries
            .iter_mut()
            .find(|entry| entry.role == WorkerRole::Reviewer)
            .expect("reference reviewer")
            .required_service_ids = vec!["review".to_string(), "supervisor".to_string()];
        entries
            .iter_mut()
            .find(|entry| entry.role == WorkerRole::Packager)
            .expect("reference packager")
            .required_service_ids = vec!["packaging".to_string()];
        WorkerCatalog::new(entries).expect("exact R8 worker catalog shape")
    }

    // Literal canonical R8 package bytes. Keep this independent of today's
    // package builder/defaults: it is the compatibility boundary exercised by
    // the v4-root migration test below.
    const R8_ROOT_PACKAGE_FIXTURE_JSON: &str = concat!(
        r#"{"schema":"wasm-biotic.factory-package.v1","factory_id":"factory:test","generation":0,"parent_package_digest":null,"genome":{"schema":"wasm-biotic.factory-genome.v1","parent_package_digest":null,"stable_interface_ref":"wit:wasm-biotic:reference-task/reference-task@v1","component_bytes":[0,97,115,109,13,0,1,0,1,70,0,97,115,109,1,0,0,0,1,6,1,96,1,127,1,127,3,2,1,0,7,13,1,9,116,114,97,110,115,102,111,114,109,0,0,10,9,1,7,0,32,0,65,0,106,11,0,22,4,110,97,109,101,0,15,14,105,109,112,108,101,109,101,110,116,97,116,105,111,110,2,4,1,0,0,0,7,12,1,64,1,5,105,110,112,117,116,122,0,122,6,15,1,0,0,1,0,9,116,114,97,110,115,102,111,114,109,8,6,1,0,0,0,0,0,11,15,1,0,9,116,114,97,110,115,102,111,114,109,1,0,0,0,51,14,99,111,109,112,111,110,101,110,116,45,110,97,109,101,1,19,0,17,1,0,14,105,109,112,108,101,109,101,110,116,97,116,105,111,110,1,13,0,18,1,0,8,105,110,115,116,97,110,99,101],"component_digest":"sha256:72a020fb75e44c32b3ded71f3de4d9f3109e86151d6ea913370b97c7706df0b2","policy":{"policy_revision":1,"generation_enabled":false,"generation_instruction":null,"max_canary_tasks":2},"policy_digest":"sha256:e438f3c8b9f563fe739b5046c4c327802a319450a82771c8e764e4b6176ec9c6","genome_digest":"sha256:f9f37c85a1619032463dc6287b23c61be6e587def70233428e92d6fcd247fb50"}"#,
        r#","boot_manifest":{"schema":"wasm-biotic.factory-boot-manifest.v1","package_format_version":1,"interface_digest":"sha256:374fd5b36ad8b629cea21fdb591b82a3ce0db38585267a61648bfd3a1fda1dff","component_digest":"sha256:72a020fb75e44c32b3ded71f3de4d9f3109e86151d6ea913370b97c7706df0b2","policy_digest":"sha256:e438f3c8b9f563fe739b5046c4c327802a319450a82771c8e764e4b6176ec9c6","worker_catalog_digest":"sha256:d28d3096ed70d13eb94e8db59968ac409ec2499953e1fc477ba1986bad64ac9f","service_catalog_digest":"sha256:904a4f443f4aedcfa028622e4b1b9cf437ef66abb3016d829e4ccecdb9b9049d","generation_instruction_digest":null,"state_compatibility":{"readable_schema_min":1,"readable_schema_max":2,"written_schema":1,"incumbent_rollback_readable_through":2}}"#,
        r#","stable_interface":{"interface_ref":"wit:wasm-biotic:reference-task/reference-task@v1","world":"reference-task","exported_function":"transform","wit_bytes":[112,97,99,107,97,103,101,32,119,97,115,109,45,98,105,111,116,105,99,58,114,101,102,101,114,101,110,99,101,45,116,97,115,107,59,10,10,119,111,114,108,100,32,114,101,102,101,114,101,110,99,101,45,116,97,115,107,32,123,10,32,32,32,32,101,120,112,111,114,116,32,116,114,97,110,115,102,111,114,109,58,32,102,117,110,99,40,105,110,112,117,116,58,32,115,51,50,41,32,45,62,32,115,51,50,59,10,125,10],"wit_digest":"sha256:d6cefc4bfa4640786b8c754c880bdac577f2dd283fb08823f331d29fc4e6882b"}"#,
        r#","worker_catalog":{"entries":[{"role":"planner","implementation_ref":"worker:planner:v1","implementation_digest":"sha256:d1f135c4ec3bfeffe51b97cf32f8c11d08d9623dd5e6bd9659982bc476fb8544","required_service_ids":["supervisor","evidence"]},{"role":"builder","implementation_ref":"worker:builder:v1","implementation_digest":"sha256:c18109e66843f964724560917f528ea031a08a0674460319a9accdb6f38e70c4","required_service_ids":["candidate","build"]},{"role":"validator","implementation_ref":"worker:validator:v1","implementation_digest":"sha256:e104c6872d6a0b2fdd6af410edb364c4fd9f1355845a9f27df93ecf4def0c50b","required_service_ids":["validation"]},{"role":"reviewer","implementation_ref":"worker:reviewer:v1","implementation_digest":"sha256:953952ce262c8fb66458aa39ca2c4f190aac9409fda67a31788d2cf5777874dc","required_service_ids":["review","supervisor"]},{"role":"packager","implementation_ref":"worker:packager:v1","implementation_digest":"sha256:feff74f2d9096d9e78a78fce7d2b9f455afb6bccefe1efb0475016a0838b12b2","required_service_ids":["packaging"]},{"role":"continuity","implementation_ref":"worker:continuity:v1","implementation_digest":"sha256:c0e099b05117d91159021c43096811154379aa9972d21c29ef66894c394c218e","required_service_ids":["evidence","deployment"]}],"catalog_digest":"sha256:d28d3096ed70d13eb94e8db59968ac409ec2499953e1fc477ba1986bad64ac9f"}"#,
        r#","service_dependencies":{"dependencies":[{"service_id":"candidate","role":"candidate_workspace","interface_ref":"wasm-biotic:service/candidate@v1","implementation_digest":"sha256:d0d7eb90c45b18499f2ce054aa67e7563799fd189d69e4fa280155820b2c4a9c","required":true},{"service_id":"build","role":"build_packaging","interface_ref":"wasm-biotic:service/build@v1","implementation_digest":"sha256:df895a289a39e16c308c80fde955a484679f59e36e77ccc5bb5fd3ff307c7927","required":true},{"service_id":"validation","role":"validation_review","interface_ref":"wasm-biotic:service/validation@v1","implementation_digest":"sha256:568f965d407c793dc1d888500e72f915fb5bd3e7ad34031896aa82d64584f6b6","required":true},{"service_id":"supervisor","role":"supervisor","interface_ref":"wasm-biotic:service/supervisor@v1","implementation_digest":"sha256:978d825c0fff70e2053ff4f3e9044434e96da6ca3c2d2a177c8f068e24e8eb8f","required":true},{"service_id":"deployment","role":"deployment_rollback","interface_ref":"wasm-biotic:service/deployment@v1","implementation_digest":"sha256:f913dd0968608dd789ee4dc909843847534c60d2d64af179232da2b986563783","required":true},{"service_id":"evidence","role":"evidence_publication","interface_ref":"wasm-biotic:service/evidence@v1","implementation_digest":"sha256:50476b4b1e788cc8ca30e3512cd071322c66fa0e2eb6443d42a4475c3d5876bd","required":true},{"service_id":"workers","role":"worker_execution","interface_ref":"wasm-biotic:service/workers@v1","implementation_digest":"sha256:08f7e1b60242b0b19fc114575023f663c579256c9ed66f1bc3235f054384519b","required":true}],"catalog_digest":"sha256:904a4f443f4aedcfa028622e4b1b9cf437ef66abb3016d829e4ccecdb9b9049d"}}"#,
    );
    const R8_ROOT_PACKAGE_FIXTURE_DIGEST: &str =
        "sha256:23d53e46a9f03a3411d3b11bcb7cb87d20bc14cbfe235af05f1a6bc0fe1e6503";

    fn incumbent_package() -> FactoryPackage {
        package(
            0,
            None,
            component_bytes(0),
            MutableFactoryPolicy::terminal(1, 2),
            1,
        )
    }

    fn initialize_engine(directory: &TestDirectory, rig: &TestRig) -> FactoryReproductionEngine {
        FactoryReproductionEngine::initialize(
            &directory.0,
            "factory:test",
            incumbent_package(),
            release_gate(),
            rig.ports(),
        )
        .expect("initialize fixture engine")
    }

    #[test]
    fn engine_owner_lock_rejects_same_process_and_subprocess_open() {
        if let Some(root) = std::env::var_os(ENGINE_LOCK_CHILD_ROOT_ENV) {
            let rig = TestRig::new();
            assert!(matches!(
                FactoryReproductionEngine::open(PathBuf::from(root), rig.ports()),
                Err(ReproductionError::StateOwnerConflict(_))
            ));
            return;
        }

        let directory = TestDirectory::new("engine-owner-lock");
        let rig = TestRig::new();
        let engine = initialize_engine(&directory, &rig);
        assert!(matches!(
            FactoryReproductionEngine::open(&directory.0, rig.ports()),
            Err(ReproductionError::StateOwnerConflict(_))
        ));

        let child = Command::new(std::env::current_exe().expect("current test executable"))
            .arg("--exact")
            .arg("factory_reproduction::tests::engine_owner_lock_rejects_same_process_and_subprocess_open")
            .arg("--nocapture")
            .env(ENGINE_LOCK_CHILD_ROOT_ENV, &directory.0)
            .output()
            .expect("run independent engine-open child");
        assert!(
            child.status.success(),
            "independent engine-open child did not observe the owner conflict: stdout={} stderr={}",
            String::from_utf8_lossy(&child.stdout),
            String::from_utf8_lossy(&child.stderr)
        );

        drop(engine);
        FactoryReproductionEngine::open(&directory.0, rig.ports())
            .expect("engine lock is released when its owner drops");
    }

    fn seed_request(
        engine: &FactoryReproductionEngine,
        cycle_id: &str,
        component: Vec<u8>,
        policy: MutableFactoryPolicy,
    ) -> SeedCycleRequest {
        SeedCycleRequest {
            cycle_id: cycle_id.to_string(),
            expected_active_package_digest: engine.state.active_package_digest.clone(),
            expected_gate_digest: engine.state.release_gate.gate_digest.clone(),
            genome: MutableGenome::new(
                Some(engine.state.active_package_digest.clone()),
                component,
                policy,
            )
            .expect("valid seed genome"),
            state_compatibility: compatibility(engine.state.active_state_schema),
            migration_plan: None,
            operator_context_digest: ContentDigest::from_bytes(b"operator-context"),
        }
    }

    fn successor_policy() -> MutableFactoryPolicy {
        MutableFactoryPolicy {
            policy_revision: 2,
            generation_enabled: true,
            generation_instruction: Some(GenerationLoopInstruction {
                instruction_id: "generate-next-reference-component".to_string(),
                driver_contract: GenerationDriverContract::reference(),
                successor_policy_revision: 3,
                max_executions: 1,
            }),
            max_canary_tasks: 2,
        }
    }

    fn provider_configuration() -> ProviderConfiguration {
        let tool_catalog = provider_test_tool_catalog();
        let response_schema = provider_test_response_schema();
        ProviderConfiguration {
            provider_id: "provider:test".to_string(),
            model_id: "model:test".to_string(),
            provider_profile: M5ProviderProfileV1::OpenAiResponses,
            api_base_url: "https://provider.example.test/v1/".to_string(),
            endpoint_class: M5ProviderEndpointClassV1::ExternalHttps,
            driver_profile_digest: ContentDigest::from_bytes(b"driver-v1"),
            generation_policy_id: "fixture-generation-policy".to_string(),
            generation_policy_digest: ContentDigest::from_bytes(b"generation-policy-v1"),
            maximum_retries: 0,
            maximum_output_tokens: 512,
            input_cost_per_million_microunits: 100_000,
            output_cost_per_million_microunits: 0,
            cost_currency: "usd".to_string(),
            parser_digest: ContentDigest::from_bytes(b"deterministic-parser-v1"),
            response_schema_digest: ContentDigest::from_bytes(&response_schema),
            prompt_renderer_digest: ContentDigest::from_bytes(b"prompt-renderer-v1"),
            tool_catalog_digest: ContentDigest::from_bytes(&tool_catalog),
        }
    }

    fn provider_test_tool_catalog() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!([{
            "type": "function",
            "name": "candidate.materialize_patchset",
            "description": "test-only bounded proposal",
            "parameters": {
                "type": "object",
                "additionalProperties": false,
                "required": [
                    "cycle_id",
                    "challenger_wat_digest",
                    "policy_digest",
                    "invocation_challenge_digest"
                ],
                "properties": {
                    "cycle_id": {"type": "string"},
                    "challenger_wat_digest": {"type": "string"},
                    "policy_digest": {"type": "string"},
                    "invocation_challenge_digest": {"type": "string"}
                }
            }
        }]))
        .expect("test tool catalog")
    }

    fn provider_test_response_schema() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "type": "object",
            "additionalProperties": false
        }))
        .expect("test response schema")
    }

    fn provider_request(
        engine: &FactoryReproductionEngine,
        qualification_id: &str,
    ) -> ProviderQualificationRequest {
        let configuration = provider_configuration();
        let prompt = b"propose one bounded component change".to_vec();
        let catalog: serde_json::Value =
            serde_json::from_slice(&provider_test_tool_catalog()).expect("test catalog");
        let selected = catalog
            .as_array()
            .and_then(|items| items.first())
            .expect("one test tool");
        let capsule = ProviderReplayCapsule::new(
            &configuration,
            prompt.clone(),
            provider_test_tool_catalog(),
            serde_json::to_vec(selected).expect("selected tool"),
            serde_json::to_vec(selected.get("parameters").expect("selected arguments"))
                .expect("selected argument schema"),
            provider_test_response_schema(),
        )
        .expect("provider replay capsule");
        ProviderQualificationRequest::new(
            qualification_id,
            engine.state.active_package_digest.clone(),
            ContentDigest::from_bytes(b"provider-target-binding"),
            configuration,
            prompt,
            capsule,
        )
        .expect("valid provider request")
    }

    #[test]
    fn package_is_canonical_runnable_payload_with_sha256_identity() {
        let package = incumbent_package();
        let bytes = package.canonical_bytes().expect("canonical package bytes");
        assert_eq!(package.package_digest, ContentDigest::from_bytes(&bytes));
        assert_eq!(package.byte_len, bytes.len() as u64);
        let decoded =
            FactoryPackage::from_canonical_bytes(&bytes).expect("decode canonical package");
        assert_eq!(decoded, package);
        assert_eq!(
            package.payload.genome.component_digest,
            ContentDigest::from_bytes(&package.payload.genome.component_bytes)
        );
        assert_eq!(
            &package.package_digest.as_str()[..7],
            "sha256:",
            "package identity is explicitly SHA-256"
        );
    }

    #[test]
    fn reference_worker_service_dependencies_each_resolve_exactly_once() {
        let workers = WorkerCatalog::reference().expect("reference worker catalog");
        let services =
            ServiceDependencyCatalog::reference().expect("reference service dependency catalog");
        let service_id_counts = services.dependencies.iter().fold(
            BTreeMap::<&str, usize>::new(),
            |mut counts, dependency| {
                *counts.entry(dependency.service_id.as_str()).or_default() += 1;
                counts
            },
        );

        for worker in &workers.entries {
            for required_service_id in &worker.required_service_ids {
                assert_eq!(
                    service_id_counts.get(required_service_id.as_str()),
                    Some(&1),
                    "{:?} dependency '{}' must resolve exactly once",
                    worker.role,
                    required_service_id
                );
            }
        }
        let reviewer = workers
            .entries
            .iter()
            .find(|entry| entry.role == WorkerRole::Reviewer)
            .expect("reference reviewer");
        assert_eq!(reviewer.required_service_ids, ["validation", "supervisor"]);
        let packager = workers
            .entries
            .iter()
            .find(|entry| entry.role == WorkerRole::Packager)
            .expect("reference packager");
        assert_eq!(packager.required_service_ids, ["build"]);

        package_with_catalogs(workers, services)
            .expect("the complete reference catalogs form a valid package");
    }

    #[test]
    fn r8_worker_aliases_resolve_only_through_their_frozen_semantic_roles() {
        let workers = r8_worker_catalog_fixture();
        let services =
            ServiceDependencyCatalog::reference().expect("reference service dependency catalog");
        let package = package_with_catalogs(workers, services)
            .expect("the exact R8 worker vocabulary remains readable");

        let reviewer = package
            .payload
            .worker_catalog
            .entries
            .iter()
            .find(|entry| entry.role == WorkerRole::Reviewer)
            .expect("R8 reviewer");
        assert_eq!(reviewer.required_service_ids, ["review", "supervisor"]);
        let packager = package
            .payload
            .worker_catalog
            .entries
            .iter()
            .find(|entry| entry.role == WorkerRole::Packager)
            .expect("R8 packager");
        assert_eq!(packager.required_service_ids, ["packaging"]);
    }

    #[test]
    fn package_rejects_a_worker_crosswired_to_existing_service_ids() {
        let mut entries = WorkerCatalog::reference()
            .expect("reference worker catalog")
            .entries;
        entries
            .iter_mut()
            .find(|entry| entry.role == WorkerRole::Builder)
            .expect("reference builder")
            .required_service_ids = vec!["candidate".to_string(), "supervisor".to_string()];
        let workers = WorkerCatalog::new(entries)
            .expect("crosswired worker catalog remains structurally valid on its own");
        let services =
            ServiceDependencyCatalog::reference().expect("reference service dependency catalog");

        let error = package_with_catalogs(workers, services)
            .expect_err("an existing but semantically wrong service must not satisfy Builder");
        assert!(matches!(
            error,
            ReproductionError::InvalidConfiguration(message)
                if message.contains("worker role 'Builder'")
                    && message.contains("exact required role set")
        ));
    }

    #[test]
    fn package_rejects_legacy_aliases_outside_their_historical_worker_roles() {
        let mut entries = WorkerCatalog::reference()
            .expect("reference worker catalog")
            .entries;
        entries
            .iter_mut()
            .find(|entry| entry.role == WorkerRole::Validator)
            .expect("reference validator")
            .required_service_ids = vec!["review".to_string()];
        let workers = WorkerCatalog::new(entries)
            .expect("aliased worker catalog remains structurally valid on its own");
        let services =
            ServiceDependencyCatalog::reference().expect("reference service dependency catalog");

        let error = package_with_catalogs(workers, services)
            .expect_err("the R8 Reviewer alias must not be generalized to Validator");
        assert!(matches!(
            error,
            ReproductionError::InvalidConfiguration(message)
                if message.contains("worker role 'Validator' requires service 'review'")
                    && message.contains("frozen R8 aliases")
        ));
    }

    #[test]
    fn package_rejects_duplicate_semantic_roles_via_current_and_legacy_names() {
        let mut entries = r8_worker_catalog_fixture().entries;
        entries
            .iter_mut()
            .find(|entry| entry.role == WorkerRole::Reviewer)
            .expect("R8 reviewer")
            .required_service_ids
            .insert(0, "validation".to_string());
        let workers = WorkerCatalog::new(entries)
            .expect("semantic duplicate remains structurally valid by id");
        let services =
            ServiceDependencyCatalog::reference().expect("reference service dependency catalog");

        let error = package_with_catalogs(workers, services)
            .expect_err("two names for one semantic role must not satisfy the package");
        assert!(matches!(
            error,
            ReproductionError::InvalidConfiguration(message)
                if message.contains("worker role 'Reviewer'")
                    && message.contains("ValidationReview")
                    && message.contains("more than once")
        ));
    }

    #[test]
    fn package_rejects_a_missing_worker_service_dependency() {
        let workers = WorkerCatalog::reference().expect("reference worker catalog");
        let mut dependencies = ServiceDependencyCatalog::reference()
            .expect("reference service dependency catalog")
            .dependencies;
        let evidence = dependencies
            .iter_mut()
            .find(|dependency| dependency.service_id == "evidence")
            .expect("reference evidence service");
        evidence.service_id = "evidence-missing".to_string();
        evidence.interface_ref = "wasm-biotic:service/evidence-missing@v1".to_string();
        evidence.implementation_digest = ContentDigest::from_bytes(b"evidence-missing:local-v1");
        let services = ServiceDependencyCatalog::new(dependencies)
            .expect("the renamed catalog remains structurally valid on its own");

        let error = package_with_catalogs(workers, services)
            .expect_err("a package must reject the missing evidence dependency");
        assert!(matches!(
            error,
            ReproductionError::InvalidConfiguration(message)
                if message.contains("worker role 'Planner' requires service 'evidence'")
                    && message.contains("resolves it 0 times")
        ));
    }

    #[test]
    fn package_rejects_a_renamed_service_dependency() {
        let workers = WorkerCatalog::reference().expect("reference worker catalog");
        let mut dependencies = ServiceDependencyCatalog::reference()
            .expect("reference service dependency catalog")
            .dependencies;
        let validation = dependencies
            .iter_mut()
            .find(|dependency| dependency.service_id == "validation")
            .expect("reference validation/review service");
        validation.service_id = "review".to_string();
        validation.interface_ref = "wasm-biotic:service/review@v1".to_string();
        validation.implementation_digest = ContentDigest::from_bytes(b"review:local-v1");
        let services = ServiceDependencyCatalog::new(dependencies)
            .expect("the renamed catalog remains structurally valid on its own");

        let error = package_with_catalogs(workers, services)
            .expect_err("a renamed service must not silently retarget workers");
        assert!(matches!(
            error,
            ReproductionError::InvalidConfiguration(message)
                if message.contains("worker role 'Validator' requires service 'validation'")
                    && message.contains("resolves it 0 times")
        ));
    }

    #[test]
    fn package_rejects_an_unresolvable_worker_dependency() {
        let mut entries = WorkerCatalog::reference()
            .expect("reference worker catalog")
            .entries;
        entries
            .iter_mut()
            .find(|entry| entry.role == WorkerRole::Continuity)
            .expect("reference continuity worker")
            .required_service_ids
            .push("external-publication".to_string());
        let workers = WorkerCatalog::new(entries)
            .expect("the worker catalog remains structurally valid on its own");
        let services =
            ServiceDependencyCatalog::reference().expect("reference service dependency catalog");

        let error = package_with_catalogs(workers, services)
            .expect_err("an unresolved worker dependency must fail package construction");
        assert!(matches!(
            error,
            ReproductionError::InvalidConfiguration(message)
                if message.contains(
                    "worker role 'Continuity' requires service 'external-publication'"
                ) && message.contains("resolves it 0 times")
        ));
    }

    #[test]
    fn worker_catalog_rejects_duplicate_required_service_references() {
        let mut entries = WorkerCatalog::reference()
            .expect("reference worker catalog")
            .entries;
        entries
            .iter_mut()
            .find(|entry| entry.role == WorkerRole::Planner)
            .expect("reference planner")
            .required_service_ids
            .push("evidence".to_string());

        assert!(matches!(
            WorkerCatalog::new(entries),
            Err(ReproductionError::InvalidConfiguration(message))
                if message.contains(
                    "worker role 'Planner' declares required service 'evidence' more than once"
                )
        ));
    }

    #[test]
    fn interface_and_package_byte_mismatches_are_rejected() {
        let package = incumbent_package();
        let mut wrong_interface = package.clone();
        wrong_interface.payload.stable_interface.interface_ref =
            "wit:other/interface@v9".to_string();
        assert!(matches!(
            wrong_interface.validate(),
            Err(ReproductionError::InterfaceMismatch { .. })
        ));

        let mut wrong_digest = package.clone();
        wrong_digest.package_digest = ContentDigest::from_bytes(b"not-package-bytes");
        assert!(matches!(
            wrong_digest.validate(),
            Err(ReproductionError::DigestMismatch { .. })
        ));

        let mut noncanonical = package.canonical_bytes().expect("package bytes");
        noncanonical.push(b'\n');
        assert!(matches!(
            FactoryPackage::from_canonical_bytes(&noncanonical),
            Err(ReproductionError::InvalidPackage(_))
        ));
    }

    #[test]
    fn gate_mismatch_stops_before_any_phase_port() {
        let directory = TestDirectory::new("gate-mismatch");
        let rig = TestRig::new();
        let mut engine = initialize_engine(&directory, &rig);
        let mut request = seed_request(
            &engine,
            "cycle:gate-mismatch",
            component_bytes(1),
            MutableFactoryPolicy::terminal(2, 2),
        );
        request.expected_gate_digest = ContentDigest::from_bytes(b"other-gate");
        assert!(matches!(
            engine.run_seeded_cycle(request),
            Err(ReproductionError::GateMismatch { .. })
        ));
        assert_eq!(rig.m1.calls.load(Ordering::Relaxed), 0);
        assert_eq!(rig.m4.workflow_calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn m1_interface_and_runnable_evidence_are_independently_enforced() {
        let directory = TestDirectory::new("m1-evidence");
        let rig = TestRig::new();
        let mut engine = initialize_engine(&directory, &rig);
        *rig.m1.mode.lock().expect("lock M1 mode") = M1Mode::WrongInterface;
        let request = seed_request(
            &engine,
            "cycle:wrong-interface",
            component_bytes(1),
            MutableFactoryPolicy::terminal(2, 2),
        );
        assert!(matches!(
            engine.run_seeded_cycle(request),
            Err(ReproductionError::DigestMismatch { .. })
        ));
        assert_eq!(rig.m4.workflow_calls.load(Ordering::Relaxed), 0);

        *rig.m1.mode.lock().expect("lock M1 mode") = M1Mode::NotRunnable;
        let request = seed_request(
            &engine,
            "cycle:not-runnable",
            component_bytes(1),
            MutableFactoryPolicy::terminal(2, 2),
        );
        assert!(matches!(
            engine.run_seeded_cycle(request),
            Err(ReproductionError::EvidenceRejected(_))
        ));
    }

    #[test]
    fn shadow_identity_mismatch_is_not_a_gate_failure_shaped_as_success() {
        let directory = TestDirectory::new("shadow-mismatch");
        let rig = TestRig::new();
        let mut engine = initialize_engine(&directory, &rig);
        *rig.m3.shadow_mode.lock().expect("lock shadow mode") = ShadowMode::WrongPackage;
        let request = seed_request(
            &engine,
            "cycle:shadow-mismatch",
            component_bytes(1),
            MutableFactoryPolicy::terminal(2, 2),
        );
        assert!(matches!(
            engine.run_seeded_cycle(request),
            Err(ReproductionError::DigestMismatch { .. })
        ));
        assert_eq!(rig.m2.calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn predeclared_regression_threshold_rejects_before_approval() {
        let directory = TestDirectory::new("shadow-regression");
        let rig = TestRig::new();
        let mut engine = initialize_engine(&directory, &rig);
        let root_digest = engine.state.active_package_digest.clone();
        *rig.m3.shadow_mode.lock().expect("lock shadow mode") = ShadowMode::Regression;
        let request = seed_request(
            &engine,
            "cycle:gate-regression",
            component_bytes(1),
            MutableFactoryPolicy::terminal(2, 2),
        );
        let outcome = engine
            .run_seeded_cycle(request)
            .expect("gate rejection is a recorded outcome");
        assert!(matches!(outcome, CycleOutcome::GateRejected { .. }));
        assert_eq!(engine.state.active_package_digest, root_digest);
        assert_eq!(rig.m2.calls.load(Ordering::Relaxed), 0);
        assert_eq!(
            engine.state.cycles[0].gate_decision.regressions, 1,
            "the engine derives the regression from raw task outcomes"
        );
    }

    #[test]
    fn approval_must_bind_exact_package_bytes_and_all_evidence() {
        for mode in [SupervisorMode::WrongPackage, SupervisorMode::WrongEvidence] {
            let directory = TestDirectory::new("approval-mismatch");
            let rig = TestRig::new();
            *rig.m2.mode.lock().expect("lock supervisor mode") = mode;
            let mut engine = initialize_engine(&directory, &rig);
            let request = seed_request(
                &engine,
                &format!("cycle:{mode:?}"),
                component_bytes(1),
                MutableFactoryPolicy::terminal(2, 2),
            );
            assert!(matches!(
                engine.run_seeded_cycle(request),
                Err(ReproductionError::ApprovalMismatch(_))
            ));
            assert_eq!(
                rig.m3
                    .runtime
                    .lock()
                    .expect("lock runtime")
                    .activation_calls,
                0
            );
            assert!(engine.state.in_flight.is_none());
        }
    }

    #[test]
    fn supervisor_rejection_is_durable_and_never_activates() {
        let directory = TestDirectory::new("approval-rejection");
        let rig = TestRig::new();
        *rig.m2.mode.lock().expect("lock supervisor mode") = SupervisorMode::Reject;
        let mut engine = initialize_engine(&directory, &rig);
        let root_digest = engine.state.active_package_digest.clone();
        let request = seed_request(
            &engine,
            "cycle:approval-rejected",
            component_bytes(1),
            MutableFactoryPolicy::terminal(2, 2),
        );
        let outcome = engine
            .run_seeded_cycle(request)
            .expect("approval rejection is a recorded outcome");
        assert!(matches!(outcome, CycleOutcome::ApprovalRejected { .. }));
        assert_eq!(engine.state.active_package_digest, root_digest);
        assert_eq!(engine.state.cycles[0].status, CycleStatus::ApprovalRejected);
        assert_eq!(
            rig.m3
                .runtime
                .lock()
                .expect("lock runtime")
                .activation_calls,
            0
        );
    }

    #[test]
    fn activation_receipt_must_name_exact_approved_bytes() {
        let directory = TestDirectory::new("activation-bytes");
        let rig = TestRig::new();
        *rig.m3.activation_mode.lock().expect("lock activation mode") = ActivationMode::WrongBytes;
        let mut engine = initialize_engine(&directory, &rig);
        let request = seed_request(
            &engine,
            "cycle:wrong-active-bytes",
            component_bytes(1),
            MutableFactoryPolicy::terminal(2, 2),
        );
        assert!(matches!(
            engine.run_seeded_cycle(request),
            Err(ReproductionError::DigestMismatch { .. })
        ));
        assert!(engine.state.in_flight.is_some());
        assert_eq!(
            engine.state.active_generation, 0,
            "durable active state does not advance on an invalid receipt"
        );
    }

    #[test]
    fn post_activation_regression_quarantines_and_restores_incumbent() {
        let directory = TestDirectory::new("regression-rollback");
        let rig = TestRig::new();
        *rig.m3
            .observation_mode
            .lock()
            .expect("lock observation mode") = ObservationMode::Regression;
        let mut engine = initialize_engine(&directory, &rig);
        let root_digest = engine.state.active_package_digest.clone();
        let request = seed_request(
            &engine,
            "cycle:runtime-regression",
            component_bytes(1),
            MutableFactoryPolicy::terminal(2, 2),
        );
        let outcome = engine
            .run_seeded_cycle(request)
            .expect("regression produces governed rollback outcome");
        let challenger_digest = match outcome {
            CycleOutcome::QuarantinedAndRolledBack {
                package_digest,
                restored_package_digest,
                ..
            } => {
                assert_eq!(restored_package_digest, root_digest);
                package_digest
            }
            other => panic!("unexpected outcome: {other:?}"),
        };
        assert_eq!(engine.state.active_package_digest, root_digest);
        assert_eq!(engine.state.active_generation, 0);
        assert_eq!(engine.state.quarantines.len(), 1);
        assert_eq!(
            engine.state.quarantines[0].package_digest,
            challenger_digest
        );
        assert_eq!(
            engine.state.cycles[0].status,
            CycleStatus::QuarantinedAndRolledBack
        );
        let runtime = rig.m3.runtime.lock().expect("lock runtime");
        assert_eq!(runtime.recovery_calls, 1);
        assert_eq!(runtime.active_package.as_ref(), Some(&root_digest));
    }

    #[test]
    fn successful_activation_and_restart_preserve_exact_active_package() {
        let directory = TestDirectory::new("restart");
        let rig = TestRig::new();
        let mut engine = initialize_engine(&directory, &rig);
        let request = seed_request(
            &engine,
            "cycle:adopt",
            component_bytes(1),
            MutableFactoryPolicy::terminal(2, 2),
        );
        let adopted = match engine
            .run_seeded_cycle(request)
            .expect("adopt healthy challenger")
        {
            CycleOutcome::Adopted { package_digest, .. } => package_digest,
            other => panic!("unexpected outcome: {other:?}"),
        };
        let exact_bytes = engine
            .package(&adopted)
            .expect("load adopted package")
            .canonical_bytes()
            .expect("canonical adopted bytes");
        drop(engine);

        let reopened = FactoryReproductionEngine::open(&directory.0, rig.ports())
            .expect("reopen durable engine");
        assert_eq!(reopened.state.active_package_digest, adopted);
        assert_eq!(reopened.state.active_generation, 1);
        assert!(reopened.state.in_flight.is_none());
        assert_eq!(
            reopened
                .active_package()
                .expect("load reopened active package")
                .canonical_bytes()
                .expect("canonical reopened package"),
            exact_bytes
        );
        assert_eq!(
            rig.m3.runtime.lock().expect("lock runtime").recovery_calls,
            0,
            "a completed activation does not spuriously roll back on restart"
        );
    }

    #[test]
    fn seeded_terminal_cycle_replays_exact_outcome_and_rejects_changed_intent() {
        let directory = TestDirectory::new("seeded-terminal-replay");
        let rig = TestRig::new();
        let mut engine = initialize_engine(&directory, &rig);
        let active_digest = engine.state.active_package_digest.clone();
        let request = seed_request(
            &engine,
            "cycle:seeded-terminal-replay",
            component_bytes(1),
            MutableFactoryPolicy::terminal(2, 2),
        );

        let intent = engine
            .record_seeded_cycle_intent(&request)
            .expect("write ahead exact seeded intent");
        assert_eq!(
            intent.expected_active_package_bytes_digest, active_digest,
            "the immutable intent binds the canonical active-package bytes"
        );
        assert_eq!(
            intent.execution_policy.gate_digest,
            engine.state.release_gate.gate_digest
        );
        assert_eq!(
            intent.execution_policy.budgets,
            engine.state.release_gate.budgets
        );
        assert!(
            intent
                .execution_policy
                .idempotency_namespace
                .starts_with("m5-cycle:")
        );
        let write_ahead_state_digest = engine.state.state_digest.clone();
        assert_eq!(
            engine
                .record_seeded_cycle_intent(&request)
                .expect("repeat exact write-ahead intent"),
            intent
        );
        assert_eq!(engine.state.state_digest, write_ahead_state_digest);
        assert_eq!(rig.m1.calls.load(Ordering::Relaxed), 0);
        assert_eq!(rig.m2.calls.load(Ordering::Relaxed), 0);
        assert_eq!(rig.m4.workflow_calls.load(Ordering::Relaxed), 0);

        let first_outcome = engine
            .run_seeded_cycle(request.clone())
            .expect("adopt seeded challenger");
        assert!(matches!(&first_outcome, CycleOutcome::Adopted { .. }));
        let calls_after_terminal = {
            let runtime = rig.m3.runtime.lock().expect("lock runtime");
            (
                rig.m1.calls.load(Ordering::Relaxed),
                rig.m2.calls.load(Ordering::Relaxed),
                rig.m3.driver_calls.load(Ordering::Relaxed),
                rig.m4.workflow_calls.load(Ordering::Relaxed),
                rig.m4.materialization_calls.load(Ordering::Relaxed),
                runtime.migration_calls,
                runtime.activation_calls,
                runtime.observation_calls,
                runtime.recovery_calls,
            )
        };
        let terminal_state_digest = engine.state.state_digest.clone();

        assert_eq!(
            engine
                .run_seeded_cycle(request.clone())
                .expect("replay exact seeded terminal cycle"),
            first_outcome
        );
        let calls_after_replay = {
            let runtime = rig.m3.runtime.lock().expect("lock runtime");
            (
                rig.m1.calls.load(Ordering::Relaxed),
                rig.m2.calls.load(Ordering::Relaxed),
                rig.m3.driver_calls.load(Ordering::Relaxed),
                rig.m4.workflow_calls.load(Ordering::Relaxed),
                rig.m4.materialization_calls.load(Ordering::Relaxed),
                runtime.migration_calls,
                runtime.activation_calls,
                runtime.observation_calls,
                runtime.recovery_calls,
            )
        };
        assert_eq!(calls_after_replay, calls_after_terminal);
        assert_eq!(engine.state.state_digest, terminal_state_digest);

        let mut changed = request;
        changed.operator_context_digest = ContentDigest::from_bytes(b"different-operator");
        assert!(matches!(
            engine.run_seeded_cycle(changed),
            Err(ReproductionError::DuplicateCycleId(cycle_id))
                if cycle_id == "cycle:seeded-terminal-replay"
        ));
        assert_eq!(engine.state.state_digest, terminal_state_digest);
    }

    #[test]
    fn adopted_n_plus_one_executes_digest_bound_instruction_for_n_plus_two() {
        let directory = TestDirectory::new("two-cycles");
        let rig = TestRig::new();
        let mut engine = initialize_engine(&directory, &rig);
        let first_request = seed_request(
            &engine,
            "cycle:n-to-n1",
            component_bytes(1),
            successor_policy(),
        );
        let n1_digest = match engine.run_seeded_cycle(first_request).expect("adopt N+1") {
            CycleOutcome::Adopted { package_digest, .. } => package_digest,
            other => panic!("unexpected first outcome: {other:?}"),
        };
        let n1 = engine.package(&n1_digest).expect("load N+1");
        assert_ne!(
            n1.payload.genome.component_digest,
            incumbent_package().payload.genome.component_digest
        );

        let second_request = AdoptedSuccessorRequest {
            cycle_id: "cycle:n1-to-n2".to_string(),
            expected_active_package_digest: n1_digest.clone(),
            expected_gate_digest: engine.state.release_gate.gate_digest.clone(),
            migration_plan: None,
            operator_context_digest: ContentDigest::from_bytes(b"operator:n2"),
        };
        let prepared = match engine
            .prepare_adopted_successor_cycle(second_request.clone())
            .expect("N+1 executes and prepares exact N+2")
        {
            PrepareSuccessorOutcome::Prepared(prepared) => prepared,
            other => panic!("unexpected preparation outcome: {other:?}"),
        };
        assert_eq!(
            prepared.initiation.driver_evidence.trace.input,
            REFERENCE_GENERATION_DRIVER_INPUT
        );
        assert_eq!(prepared.initiation.driver_evidence.directive, 1);
        assert_eq!(
            prepared
                .initiation
                .materialization_evidence
                .worker_receipts
                .len(),
            6
        );
        let durable_preparation_digest = prepared.preparation_digest.clone();
        drop(engine);
        let mut engine = FactoryReproductionEngine::open(&directory.0, rig.ports())
            .expect("reopen exact prepared successor");
        let reopened_prepared = engine
            .state
            .prepared_successors
            .iter()
            .find(|candidate| candidate.cycle_id == second_request.cycle_id)
            .cloned()
            .expect("durable prepared successor");
        assert_eq!(
            reopened_prepared.preparation_digest,
            durable_preparation_digest
        );
        let n2_digest = match engine
            .complete_prepared_successor_cycle(second_request, &reopened_prepared)
            .expect("authorize and complete exact N+2")
        {
            CycleOutcome::Adopted { package_digest, .. } => package_digest,
            other => panic!("unexpected second outcome: {other:?}"),
        };
        let n2 = engine.package(&n2_digest).expect("load N+2");
        let generation_two_component = compile_reference_delta_v1(
            &render_reference_delta_v1(1).expect("render directive one"),
        )
        .expect("compile directive one");
        assert_eq!(engine.state.active_generation, 2);
        assert_eq!(n2.payload.parent_package_digest.as_ref(), Some(&n1_digest));
        assert_eq!(n2.payload.genome.component_bytes, generation_two_component);
        assert_eq!(engine.state.generation_initiations.len(), 1);
        let initiation = &engine.state.generation_initiations[0];
        assert_eq!(initiation.executor_package_digest, n1_digest);
        assert_eq!(
            initiation.executor_package_bytes_digest,
            ContentDigest::from_bytes(&n1.canonical_bytes().expect("canonical N+1 bytes"))
        );
        assert_eq!(
            engine.state.cycles[1]
                .initiation
                .as_ref()
                .expect("N+2 cycle initiation")
                .material_step_digest,
            initiation.material_step_digest
        );
        assert_eq!(rig.m3.driver_calls.load(Ordering::Relaxed), 1);
        assert_eq!(rig.m4.materialization_calls.load(Ordering::Relaxed), 1);
        assert!(engine.state.lineage.iter().any(|record| {
            record.package_digest == n2_digest
                && record.parent_package_digest.as_ref() == Some(&n1_digest)
                && record.generation_initiation_digest.is_some()
                && record.disposition == LineageDisposition::Adopted
        }));
    }

    #[test]
    fn adopted_terminal_cycle_replays_exact_outcome_and_rejects_changed_intent() {
        let directory = TestDirectory::new("adopted-terminal-replay");
        let rig = TestRig::new();
        let mut engine = initialize_engine(&directory, &rig);
        let first_request = seed_request(
            &engine,
            "cycle:replay-n-to-n1",
            component_bytes(1),
            successor_policy(),
        );
        let n1_digest = match engine
            .run_seeded_cycle(first_request)
            .expect("adopt generation N+1")
        {
            CycleOutcome::Adopted { package_digest, .. } => package_digest,
            other => panic!("unexpected N+1 outcome: {other:?}"),
        };
        let request = AdoptedSuccessorRequest {
            cycle_id: "cycle:adopted-terminal-replay".to_string(),
            expected_active_package_digest: n1_digest,
            expected_gate_digest: engine.state.release_gate.gate_digest.clone(),
            migration_plan: None,
            operator_context_digest: ContentDigest::from_bytes(b"operator:replay-n2"),
        };
        let first_outcome = engine
            .run_adopted_successor_cycle(request.clone())
            .expect("adopt generated generation N+2");
        assert!(matches!(&first_outcome, CycleOutcome::Adopted { .. }));

        let intent = engine
            .state
            .cycle_intents
            .iter()
            .find(|intent| intent.cycle_id == request.cycle_id)
            .expect("durable adopted intent");
        let initiation = engine
            .state
            .generation_initiations
            .iter()
            .find(|initiation| initiation.cycle_id == request.cycle_id)
            .expect("durable generation initiation");
        assert_eq!(
            initiation.driver_request.idempotency_key,
            intent
                .execution_policy
                .phase_idempotency_key(
                    "generation-driver",
                    &initiation.driver_request.instruction_digest,
                )
                .expect("derive driver idempotency key")
        );
        assert_eq!(
            initiation.materialization_request.idempotency_key,
            intent
                .execution_policy
                .phase_idempotency_key(
                    "generation-materialization",
                    &initiation.driver_evidence.evidence_digest,
                )
                .expect("derive materialization idempotency key")
        );

        let calls_after_terminal = {
            let runtime = rig.m3.runtime.lock().expect("lock runtime");
            (
                rig.m1.calls.load(Ordering::Relaxed),
                rig.m2.calls.load(Ordering::Relaxed),
                rig.m3.driver_calls.load(Ordering::Relaxed),
                rig.m4.workflow_calls.load(Ordering::Relaxed),
                rig.m4.materialization_calls.load(Ordering::Relaxed),
                runtime.migration_calls,
                runtime.activation_calls,
                runtime.observation_calls,
                runtime.recovery_calls,
            )
        };
        let terminal_state_digest = engine.state.state_digest.clone();
        assert_eq!(
            engine
                .run_adopted_successor_cycle(request.clone())
                .expect("replay exact adopted terminal cycle"),
            first_outcome
        );
        let calls_after_replay = {
            let runtime = rig.m3.runtime.lock().expect("lock runtime");
            (
                rig.m1.calls.load(Ordering::Relaxed),
                rig.m2.calls.load(Ordering::Relaxed),
                rig.m3.driver_calls.load(Ordering::Relaxed),
                rig.m4.workflow_calls.load(Ordering::Relaxed),
                rig.m4.materialization_calls.load(Ordering::Relaxed),
                runtime.migration_calls,
                runtime.activation_calls,
                runtime.observation_calls,
                runtime.recovery_calls,
            )
        };
        assert_eq!(calls_after_replay, calls_after_terminal);
        assert_eq!(engine.state.state_digest, terminal_state_digest);

        let mut changed = request;
        changed.operator_context_digest = ContentDigest::from_bytes(b"different-operator");
        assert!(matches!(
            engine.run_adopted_successor_cycle(changed),
            Err(ReproductionError::DuplicateCycleId(cycle_id))
                if cycle_id == "cycle:adopted-terminal-replay"
        ));
        assert_eq!(engine.state.state_digest, terminal_state_digest);
    }

    #[test]
    fn active_driver_directives_materialize_distinct_successor_artifacts() {
        fn prepare_for(directive: i32) -> PreparedSuccessorCycle {
            let directory = TestDirectory::new(&format!("driver-directive-{directive}"));
            let rig = TestRig::new();
            let mut engine = initialize_engine(&directory, &rig);
            let n1 = match engine
                .run_seeded_cycle(seed_request(
                    &engine,
                    "cycle:n-to-n1",
                    component_bytes(1),
                    successor_policy(),
                ))
                .expect("adopt causal N+1")
            {
                CycleOutcome::Adopted { package_digest, .. } => package_digest,
                other => panic!("unexpected N+1 outcome: {other:?}"),
            };
            *rig.m3.driver_mode.lock().expect("lock driver mode") = DriverMode::Valid(directive);
            match engine
                .prepare_adopted_successor_cycle(AdoptedSuccessorRequest {
                    cycle_id: "cycle:n1-to-n2".to_string(),
                    expected_active_package_digest: n1,
                    expected_gate_digest: engine.state.release_gate.gate_digest.clone(),
                    migration_plan: None,
                    operator_context_digest: ContentDigest::from_bytes(b"operator"),
                })
                .expect("prepare directive-selected successor")
            {
                PrepareSuccessorOutcome::Prepared(prepared) => prepared,
                other => panic!("unexpected preparation outcome: {other:?}"),
            }
        }

        let first = prepare_for(1);
        let second = prepare_for(2);
        assert_eq!(first.initiation.driver_evidence.directive, 1);
        assert_eq!(second.initiation.driver_evidence.directive, 2);
        assert_ne!(
            first.successor_genome.component_digest,
            second.successor_genome.component_digest
        );
        assert_ne!(
            first.successor_package.package_digest,
            second.successor_package.package_digest
        );
        assert_eq!(
            first.initiation.materialization_evidence.rendered_wat_bytes,
            render_reference_delta_v1(1).expect("render directive one")
        );
        assert_eq!(
            second
                .initiation
                .materialization_evidence
                .rendered_wat_bytes,
            render_reference_delta_v1(2).expect("render directive two")
        );
    }

    #[test]
    fn disabling_generation_in_n_plus_one_prevents_n_plus_two() {
        let directory = TestDirectory::new("causality-disabled");
        let rig = TestRig::new();
        let mut engine = initialize_engine(&directory, &rig);
        let request = seed_request(
            &engine,
            "cycle:disabled-n1",
            component_bytes(1),
            MutableFactoryPolicy::terminal(2, 2),
        );
        let n1_digest = match engine
            .run_seeded_cycle(request)
            .expect("adopt terminal N+1")
        {
            CycleOutcome::Adopted { package_digest, .. } => package_digest,
            other => panic!("unexpected first outcome: {other:?}"),
        };
        let outcome = engine
            .run_adopted_successor_cycle(AdoptedSuccessorRequest {
                cycle_id: "cycle:blocked-n2".to_string(),
                expected_active_package_digest: n1_digest,
                expected_gate_digest: engine.state.release_gate.gate_digest.clone(),
                migration_plan: None,
                operator_context_digest: ContentDigest::from_bytes(b"operator"),
            })
            .expect("disabled instruction is a durable stop");
        match outcome {
            CycleOutcome::Stopped(record) => {
                assert_eq!(record.reason, StopReason::GenerationDisabled);
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
        assert_eq!(engine.state.active_generation, 1);
        assert_eq!(rig.m3.driver_calls.load(Ordering::Relaxed), 0);
        assert_eq!(rig.m4.materialization_calls.load(Ordering::Relaxed), 0);
        assert!(engine.state.generation_initiations.is_empty());
    }

    #[test]
    fn reverting_n_plus_one_removes_its_causal_instruction() {
        let directory = TestDirectory::new("causality-revert");
        let rig = TestRig::new();
        let mut engine = initialize_engine(&directory, &rig);
        let root_digest = engine.state.active_package_digest.clone();
        let request = seed_request(
            &engine,
            "cycle:causal-n1",
            component_bytes(1),
            successor_policy(),
        );
        let n1_digest = match engine.run_seeded_cycle(request).expect("adopt causal N+1") {
            CycleOutcome::Adopted { package_digest, .. } => package_digest,
            other => panic!("unexpected first outcome: {other:?}"),
        };
        assert!(
            engine
                .active_package()
                .expect("load N+1")
                .payload
                .genome
                .policy
                .generation_instruction
                .is_some()
        );
        engine
            .operator_revert_active("rollback:remove-n1", &n1_digest, "operator:causality-test")
            .expect("revert N+1");
        assert_eq!(engine.state.active_package_digest, root_digest);
        let outcome = engine
            .run_adopted_successor_cycle(AdoptedSuccessorRequest {
                cycle_id: "cycle:after-revert".to_string(),
                expected_active_package_digest: root_digest,
                expected_gate_digest: engine.state.release_gate.gate_digest.clone(),
                migration_plan: None,
                operator_context_digest: ContentDigest::from_bytes(b"operator"),
            })
            .expect("root package has explicit stop condition");
        assert!(matches!(
            outcome,
            CycleOutcome::Stopped(StopConditionRecord {
                reason: StopReason::GenerationDisabled,
                ..
            })
        ));
        assert_eq!(rig.m3.driver_calls.load(Ordering::Relaxed), 0);
        assert_eq!(rig.m4.materialization_calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn generation_materializer_cannot_substitute_successor_bytes() {
        let directory = TestDirectory::new("causality-digest");
        let rig = TestRig::new();
        let mut engine = initialize_engine(&directory, &rig);
        let request = seed_request(&engine, "cycle:n1", component_bytes(1), successor_policy());
        let n1_digest = match engine.run_seeded_cycle(request).expect("adopt N+1") {
            CycleOutcome::Adopted { package_digest, .. } => package_digest,
            other => panic!("unexpected first outcome: {other:?}"),
        };
        *rig.m4.mode.lock().expect("lock worker mode") = WorkerMode::WrongMaterialization;
        let result = engine.run_adopted_successor_cycle(AdoptedSuccessorRequest {
            cycle_id: "cycle:substituted-n2".to_string(),
            expected_active_package_digest: n1_digest,
            expected_gate_digest: engine.state.release_gate.gate_digest.clone(),
            migration_plan: None,
            operator_context_digest: ContentDigest::from_bytes(b"operator"),
        });
        assert!(matches!(
            result,
            Err(ReproductionError::EvidenceMismatch(_))
        ));
        assert_eq!(engine.state.active_generation, 1);
        assert!(engine.state.generation_initiations.is_empty());
        assert!(
            engine
                .state
                .cycle_intents
                .iter()
                .any(|intent| intent.cycle_id == "cycle:substituted-n2"),
            "the immutable cycle intent precedes the rejected materializer call"
        );
    }

    #[test]
    fn driver_trace_and_prepared_cycle_tampering_are_rejected() {
        let directory = TestDirectory::new("causality-driver-trace");
        let rig = TestRig::new();
        let mut engine = initialize_engine(&directory, &rig);
        let n1_digest = match engine
            .run_seeded_cycle(seed_request(
                &engine,
                "cycle:n1",
                component_bytes(1),
                successor_policy(),
            ))
            .expect("adopt causal N+1")
        {
            CycleOutcome::Adopted { package_digest, .. } => package_digest,
            other => panic!("unexpected N+1 outcome: {other:?}"),
        };
        *rig.m3.driver_mode.lock().expect("lock driver mode") = DriverMode::WrongTraceInput;
        let bad_request = AdoptedSuccessorRequest {
            cycle_id: "cycle:bad-driver-trace".to_string(),
            expected_active_package_digest: n1_digest.clone(),
            expected_gate_digest: engine.state.release_gate.gate_digest.clone(),
            migration_plan: None,
            operator_context_digest: ContentDigest::from_bytes(b"operator"),
        };
        assert!(matches!(
            engine.prepare_adopted_successor_cycle(bad_request),
            Err(ReproductionError::EvidenceMismatch(_))
        ));
        assert_eq!(rig.m3.driver_calls.load(Ordering::Relaxed), 1);
        assert_eq!(rig.m4.materialization_calls.load(Ordering::Relaxed), 0);
        assert!(engine.state.generation_initiations.is_empty());

        *rig.m3.driver_mode.lock().expect("lock driver mode") = DriverMode::Valid(1);
        let request = AdoptedSuccessorRequest {
            cycle_id: "cycle:tampered-preparation".to_string(),
            expected_active_package_digest: n1_digest,
            expected_gate_digest: engine.state.release_gate.gate_digest.clone(),
            migration_plan: None,
            operator_context_digest: ContentDigest::from_bytes(b"operator"),
        };
        let mut prepared = match engine
            .prepare_adopted_successor_cycle(request.clone())
            .expect("prepare exact successor")
        {
            PrepareSuccessorOutcome::Prepared(prepared) => prepared,
            other => panic!("unexpected preparation outcome: {other:?}"),
        };
        prepared.initiation.driver_evidence.trace.output = Some(2);
        assert!(matches!(
            engine.complete_prepared_successor_cycle(request, &prepared),
            Err(ReproductionError::EvidenceMismatch(_))
                | Err(ReproductionError::DigestMismatch { .. })
        ));
        assert_eq!(engine.state.active_generation, 1);
        assert_eq!(engine.state.prepared_successors.len(), 1);
    }

    #[test]
    fn schema_change_requires_exact_rollback_plan() {
        let directory = TestDirectory::new("migration-plan");
        let rig = TestRig::new();
        let mut engine = initialize_engine(&directory, &rig);
        let mut request = seed_request(
            &engine,
            "cycle:no-migration-plan",
            component_bytes(1),
            MutableFactoryPolicy::terminal(2, 2),
        );
        request.state_compatibility = compatibility(2);
        assert!(matches!(
            engine.run_seeded_cycle(request),
            Err(ReproductionError::StateCompatibility(_))
        ));
        assert_eq!(rig.m1.calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn partial_runtime_migration_is_recovered_on_restart() {
        let directory = TestDirectory::new("partial-runtime-migration");
        let rig = TestRig::new();
        let mut engine = initialize_engine(&directory, &rig);
        let root_digest = engine.state.active_package_digest.clone();
        *rig.m3.activation_mode.lock().expect("lock activation mode") = ActivationMode::Fail;
        let mut request = seed_request(
            &engine,
            "cycle:migration-interrupted",
            component_bytes(1),
            MutableFactoryPolicy::terminal(2, 2),
        );
        request.state_compatibility = compatibility(2);
        request.migration_plan = Some(
            StateMigrationPlan::new(
                "migration:v1-to-v2",
                1,
                2,
                1,
                ContentDigest::from_bytes(b"migration-program"),
                4_096,
            )
            .expect("valid migration plan"),
        );
        assert!(matches!(
            engine.run_seeded_cycle(request),
            Err(ReproductionError::Port {
                phase: "m3_activation",
                ..
            })
        ));
        let pending = engine
            .state
            .in_flight
            .as_ref()
            .expect("durable effect intent");
        assert_eq!(pending.stage, PendingStage::ActivationRequested);
        assert!(pending.migration_receipt.is_some());
        assert_eq!(
            rig.m3.runtime.lock().expect("lock runtime").migration_calls,
            1
        );
        drop(engine);

        *rig.m3.activation_mode.lock().expect("lock activation mode") = ActivationMode::Valid;
        let recovered = FactoryReproductionEngine::open(&directory.0, rig.ports())
            .expect("restart recovers partial migration");
        assert_eq!(recovered.state.active_package_digest, root_digest);
        assert_eq!(recovered.state.active_state_schema, 1);
        assert!(recovered.state.in_flight.is_none());
        assert_eq!(
            recovered.state.cycles[0].status,
            CycleStatus::RecoveredToIncumbent
        );
        assert_eq!(recovered.state.quarantines.len(), 1);
        let runtime = rig.m3.runtime.lock().expect("lock runtime");
        assert_eq!(runtime.recovery_calls, 1);
        assert_eq!(runtime.active_package.as_ref(), Some(&root_digest));
        assert_eq!(runtime.active_state_schema, 1);
    }

    #[test]
    fn interrupted_engine_schema_migration_restores_backup_then_migrates() {
        let directory = TestDirectory::new("engine-schema-migration");
        let rig = TestRig::new();
        let engine = initialize_engine(&directory, &rig);
        let state = engine.state.clone();
        let legacy = LegacyReproductionStateV1 {
            schema_version: 1,
            factory_id: state.factory_id,
            release_gate: state.release_gate,
            active_package_digest: state.active_package_digest,
            active_generation: state.active_generation,
            active_state_schema: state.active_state_schema,
            retained_incumbent: state.retained_incumbent,
            package_index: state.package_index,
            cycles: state.cycles,
            lineage: state.lineage,
            generation_initiations: state.generation_initiations,
            instruction_uses: state.instruction_uses,
            quarantines: state.quarantines,
            in_flight: state.in_flight,
        };
        drop(engine);
        let legacy_bytes = serde_json::to_vec_pretty(&legacy).expect("serialize legacy state");
        let state_path = directory.0.join(STATE_FILE_NAME);
        let backup_path = directory.0.join(ENGINE_MIGRATION_BACKUP_FILE);
        let intent_path = directory.0.join(ENGINE_MIGRATION_INTENT_FILE);
        atomic_write(&backup_path, &legacy_bytes).expect("write migration backup");
        atomic_write_json(
            &intent_path,
            &EngineSchemaMigrationIntent {
                from_schema: 1,
                to_schema: REPRODUCTION_STATE_SCHEMA_VERSION,
                source_digest: ContentDigest::from_bytes(&legacy_bytes),
                backup_digest: ContentDigest::from_bytes(&legacy_bytes),
            },
        )
        .expect("write migration intent");
        atomic_write(&state_path, b"{partial-v3").expect("write induced partial target");

        let reopened = FactoryReproductionEngine::open(&directory.0, rig.ports())
            .expect("restore legacy backup and migrate atomically");
        assert_eq!(
            reopened.state.schema_version,
            REPRODUCTION_STATE_SCHEMA_VERSION
        );
        reopened.state.validate().expect("migrated state validates");
        assert!(!backup_path.exists());
        assert!(!intent_path.exists());
    }

    #[test]
    fn causally_clean_v2_state_migrates_to_cycle_intent_schema() {
        let directory = TestDirectory::new("engine-v2-to-v3");
        let rig = TestRig::new();
        let engine = initialize_engine(&directory, &rig);
        let mut legacy =
            serde_json::to_value(&engine.state).expect("serialize causally clean state");
        let object = legacy.as_object_mut().expect("state object");
        object.insert("schema_version".to_string(), serde_json::Value::from(2));
        object.remove("cycle_intents");
        object.remove("prepared_successors");
        object.insert(
            "state_digest".to_string(),
            serde_json::to_value(ContentDigest::from_bytes(b"legacy-v2-state"))
                .expect("legacy digest"),
        );
        drop(engine);
        atomic_write(
            &directory.0.join(STATE_FILE_NAME),
            &serde_json::to_vec_pretty(&legacy).expect("legacy state bytes"),
        )
        .expect("write causally clean v2 state");

        let reopened = FactoryReproductionEngine::open(&directory.0, rig.ports())
            .expect("migrate causally clean v2 state");
        assert_eq!(
            reopened.state.schema_version,
            REPRODUCTION_STATE_SCHEMA_VERSION
        );
        assert!(reopened.state.cycle_intents.is_empty());
        assert!(reopened.state.prepared_successors.is_empty());
        reopened
            .state
            .validate()
            .expect("migrated v3 state validates");
    }

    #[test]
    fn genuine_r8_root_survives_v4_migration_without_package_rewrite() {
        let directory = TestDirectory::new("engine-r8-root-v4-to-v5");
        let rig = TestRig::new();
        let frozen_package_bytes = R8_ROOT_PACKAGE_FIXTURE_JSON.as_bytes();
        let frozen_package_digest = ContentDigest::from_bytes(frozen_package_bytes);
        assert_eq!(
            frozen_package_digest.as_str(),
            R8_ROOT_PACKAGE_FIXTURE_DIGEST,
            "the checked-in R8 package fixture is an immutable compatibility anchor"
        );
        let r8_package = FactoryPackage::from_canonical_bytes(frozen_package_bytes)
            .expect("decode the canonical R8-shaped root package");
        assert_eq!(r8_package.package_digest, frozen_package_digest);
        let frozen_worker_catalog_digest = r8_package.payload.worker_catalog.catalog_digest.clone();

        let engine = FactoryReproductionEngine::initialize(
            &directory.0,
            "factory:test",
            r8_package,
            release_gate(),
            rig.ports(),
        )
        .expect("initialize an R8-shaped root before simulating its v4 state");
        assert!(engine.state.provider_qualifications.is_empty());
        let frozen_package_path = package_path(&engine.package_directory, &frozen_package_digest);
        assert_eq!(
            fs::read(&frozen_package_path)
                .expect("read persisted R8 root package")
                .as_slice(),
            frozen_package_bytes,
            "fixture setup must persist the historical canonical bytes verbatim"
        );
        let mut legacy = engine.state.clone();
        legacy.schema_version = 4;
        legacy.state_digest = ContentDigest::from_bytes(&[]);
        legacy.state_digest = reproduction_state_digest_in_domain(
            &legacy,
            "wasm-biotic:factory-reproduction-state:v4",
        )
        .expect("seal exact legacy v4 state around the R8 root");
        drop(engine);
        atomic_write(
            &directory.0.join(STATE_FILE_NAME),
            &serde_json::to_vec_pretty(&legacy).expect("legacy v4 state bytes"),
        )
        .expect("write the R8-rooted v4 state");

        let reopened = FactoryReproductionEngine::open(&directory.0, rig.ports())
            .expect("migrate a genuine R8-shaped root to v5");
        assert_eq!(
            reopened.state.schema_version,
            REPRODUCTION_STATE_SCHEMA_VERSION
        );
        assert_eq!(reopened.state.active_package_digest, frozen_package_digest);
        assert_eq!(
            fs::read(&frozen_package_path)
                .expect("reread migrated R8 root package")
                .as_slice(),
            frozen_package_bytes,
            "state migration must never normalize or rewrite historical package bytes"
        );
        let reopened_package = reopened.active_package().expect("load migrated R8 root");
        assert_eq!(reopened_package.package_digest, frozen_package_digest);
        assert_eq!(
            reopened_package.payload.worker_catalog.catalog_digest, frozen_worker_catalog_digest,
            "state migration must retain the historical worker catalog identity"
        );
        let reviewer = reopened_package
            .payload
            .worker_catalog
            .entries
            .iter()
            .find(|entry| entry.role == WorkerRole::Reviewer)
            .expect("migrated R8 reviewer");
        assert_eq!(reviewer.required_service_ids, ["review", "supervisor"]);
        let packager = reopened_package
            .payload
            .worker_catalog
            .entries
            .iter()
            .find(|entry| entry.role == WorkerRole::Packager)
            .expect("migrated R8 packager");
        assert_eq!(packager.required_service_ids, ["packaging"]);
    }

    #[test]
    fn provider_clean_v4_state_migrates_to_structured_accounting_schema() {
        let directory = TestDirectory::new("engine-v4-to-v5-provider-clean");
        let rig = TestRig::new();
        let engine = initialize_engine(&directory, &rig);
        assert!(engine.state.provider_qualifications.is_empty());
        let mut legacy = engine.state.clone();
        legacy.schema_version = 4;
        legacy.state_digest = ContentDigest::from_bytes(&[]);
        legacy.state_digest = reproduction_state_digest_in_domain(
            &legacy,
            "wasm-biotic:factory-reproduction-state:v4",
        )
        .expect("seal exact legacy v4 state");
        drop(engine);
        atomic_write(
            &directory.0.join(STATE_FILE_NAME),
            &serde_json::to_vec_pretty(&legacy).expect("legacy v4 state bytes"),
        )
        .expect("write provider-clean v4 state");

        let reopened = FactoryReproductionEngine::open(&directory.0, rig.ports())
            .expect("migrate provider-clean v4 state");
        assert_eq!(
            reopened.state.schema_version,
            REPRODUCTION_STATE_SCHEMA_VERSION
        );
        assert!(reopened.state.provider_qualifications.is_empty());
        reopened
            .state
            .validate()
            .expect("migrated v5 state validates");
    }

    #[test]
    fn v4_migration_rejects_package_substitution_before_state_commit() {
        let directory = TestDirectory::new("engine-v4-package-precommit");
        let rig = TestRig::new();
        let engine = initialize_engine(&directory, &rig);
        assert!(engine.state.provider_qualifications.is_empty());
        let active_package_digest = engine.state.active_package_digest.clone();
        let package_path = package_path(&engine.package_directory, &active_package_digest);
        let mut substituted_package_bytes =
            fs::read(&package_path).expect("read indexed package before substitution");
        substituted_package_bytes[0] ^= 1;
        let mut legacy = engine.state.clone();
        legacy.schema_version = 4;
        legacy.state_digest = ContentDigest::from_bytes(&[]);
        legacy.state_digest = reproduction_state_digest_in_domain(
            &legacy,
            "wasm-biotic:factory-reproduction-state:v4",
        )
        .expect("seal exact legacy v4 state");
        let legacy_bytes = serde_json::to_vec_pretty(&legacy).expect("legacy v4 state bytes");
        drop(engine);

        let state_path = directory.0.join(STATE_FILE_NAME);
        let intent_path = directory.0.join(ENGINE_MIGRATION_INTENT_FILE);
        let backup_path = directory.0.join(ENGINE_MIGRATION_BACKUP_FILE);
        atomic_write(&state_path, &legacy_bytes).expect("write provider-clean v4 state");
        atomic_write(&package_path, &substituted_package_bytes)
            .expect("substitute the indexed package");

        assert!(matches!(
            FactoryReproductionEngine::open(&directory.0, rig.ports()),
            Err(ReproductionError::DigestMismatch { subject, .. })
                if subject == "indexed package"
        ));
        assert_eq!(
            fs::read(&state_path).expect("reread legacy state after rejected migration"),
            legacy_bytes,
            "package verification failure must leave the exact legacy state authoritative"
        );
        assert!(!intent_path.exists());
        assert!(!backup_path.exists());
    }

    #[test]
    fn provider_clean_v4_migration_rejects_source_or_digest_tampering() {
        for (label, tamper_state) in [("source", true), ("digest", false)] {
            let directory = TestDirectory::new(&format!("engine-v4-tamper-{label}"));
            let rig = TestRig::new();
            let engine = initialize_engine(&directory, &rig);
            let mut legacy = engine.state.clone();
            legacy.schema_version = 4;
            legacy.state_digest = ContentDigest::from_bytes(&[]);
            legacy.state_digest = reproduction_state_digest_in_domain(
                &legacy,
                "wasm-biotic:factory-reproduction-state:v4",
            )
            .expect("seal exact legacy v4 state");
            if tamper_state {
                legacy.active_generation = legacy.active_generation.saturating_add(1);
            } else {
                legacy.state_digest = ContentDigest::from_bytes(b"substituted-v4-state-digest");
            }
            drop(engine);
            atomic_write_json(&directory.0.join(STATE_FILE_NAME), &legacy)
                .expect("write tampered v4 state");

            assert!(matches!(
                FactoryReproductionEngine::open(&directory.0, rig.ports()),
                Err(ReproductionError::DigestMismatch { subject, .. })
                    if subject == "legacy v4 reproduction state"
            ));
        }
    }

    #[test]
    fn provider_clean_v5_state_migrates_to_output_bound_accounting_schema() {
        let directory = TestDirectory::new("engine-v5-to-v6-provider-clean");
        let rig = TestRig::new();
        let engine = initialize_engine(&directory, &rig);
        assert!(engine.state.provider_qualifications.is_empty());
        let mut legacy = engine.state.clone();
        legacy.schema_version = 5;
        legacy.state_digest = ContentDigest::from_bytes(&[]);
        legacy.state_digest = reproduction_state_digest_in_domain(
            &legacy,
            "wasm-biotic:factory-reproduction-state:v5",
        )
        .expect("seal exact provider-clean v5 state");
        drop(engine);
        atomic_write(
            &directory.0.join(STATE_FILE_NAME),
            &serde_json::to_vec_pretty(&legacy).expect("legacy v5 state bytes"),
        )
        .expect("write provider-clean v5 state");

        let reopened = FactoryReproductionEngine::open(&directory.0, rig.ports())
            .expect("migrate provider-clean v5 state");
        assert_eq!(
            reopened.state.schema_version,
            REPRODUCTION_STATE_SCHEMA_VERSION
        );
        assert!(reopened.state.provider_qualifications.is_empty());
        reopened
            .state
            .validate()
            .expect("migrated v6 state validates");
    }

    #[test]
    fn v5_migration_rejects_package_substitution_before_state_commit() {
        let directory = TestDirectory::new("engine-v5-package-precommit");
        let rig = TestRig::new();
        let engine = initialize_engine(&directory, &rig);
        assert!(engine.state.provider_qualifications.is_empty());
        let active_package_digest = engine.state.active_package_digest.clone();
        let package_path = package_path(&engine.package_directory, &active_package_digest);
        let mut substituted_package_bytes =
            fs::read(&package_path).expect("read indexed package before substitution");
        substituted_package_bytes[0] ^= 1;
        let mut legacy = engine.state.clone();
        legacy.schema_version = 5;
        legacy.state_digest = ContentDigest::from_bytes(&[]);
        legacy.state_digest = reproduction_state_digest_in_domain(
            &legacy,
            "wasm-biotic:factory-reproduction-state:v5",
        )
        .expect("seal exact provider-clean v5 state");
        let legacy_bytes = serde_json::to_vec_pretty(&legacy).expect("legacy v5 state bytes");
        drop(engine);

        let state_path = directory.0.join(STATE_FILE_NAME);
        let intent_path = directory.0.join(ENGINE_MIGRATION_INTENT_FILE);
        let backup_path = directory.0.join(ENGINE_MIGRATION_BACKUP_FILE);
        atomic_write(&state_path, &legacy_bytes).expect("write provider-clean v5 state");
        atomic_write(&package_path, &substituted_package_bytes)
            .expect("substitute the indexed package");

        assert!(matches!(
            FactoryReproductionEngine::open(&directory.0, rig.ports()),
            Err(ReproductionError::DigestMismatch { subject, .. })
                if subject == "indexed package"
        ));
        assert_eq!(
            fs::read(&state_path).expect("reread legacy state after rejected migration"),
            legacy_bytes,
            "package verification failure must leave the exact legacy state authoritative"
        );
        assert!(!intent_path.exists());
        assert!(!backup_path.exists());
    }

    #[test]
    fn provider_clean_v5_migration_rejects_source_or_digest_tampering() {
        for (label, tamper_state) in [("source", true), ("digest", false)] {
            let directory = TestDirectory::new(&format!("engine-v5-tamper-{label}"));
            let rig = TestRig::new();
            let engine = initialize_engine(&directory, &rig);
            let mut legacy = engine.state.clone();
            legacy.schema_version = 5;
            legacy.state_digest = ContentDigest::from_bytes(&[]);
            legacy.state_digest = reproduction_state_digest_in_domain(
                &legacy,
                "wasm-biotic:factory-reproduction-state:v5",
            )
            .expect("seal exact provider-clean v5 state");
            if tamper_state {
                legacy.active_generation = legacy.active_generation.saturating_add(1);
            } else {
                legacy.state_digest = ContentDigest::from_bytes(b"substituted-v5-state-digest");
            }
            drop(engine);
            atomic_write_json(&directory.0.join(STATE_FILE_NAME), &legacy)
                .expect("write tampered v5 state");

            assert!(matches!(
                FactoryReproductionEngine::open(&directory.0, rig.ports()),
                Err(ReproductionError::DigestMismatch { subject, .. })
                    if subject == "legacy v5 reproduction state"
            ));
        }
    }

    #[test]
    fn v5_state_with_unbounded_provider_accounting_fails_closed() {
        let directory = TestDirectory::new("engine-v5-provider-fail-closed");
        let rig = TestRig::new();
        let mut engine = initialize_engine(&directory, &rig);
        let request = provider_request(&engine, "qualification:legacy-v5");
        engine
            .qualify_live_provider(request)
            .expect("persist one provider qualification");
        let mut legacy = serde_json::to_value(&engine.state).expect("serialize v6 state");
        let object = legacy.as_object_mut().expect("state object");
        object.insert("schema_version".to_string(), serde_json::Value::from(5));
        object.insert(
            "state_digest".to_string(),
            serde_json::to_value(ContentDigest::from_bytes(b"legacy-v5-provider-state"))
                .expect("legacy digest"),
        );
        drop(engine);
        atomic_write(
            &directory.0.join(STATE_FILE_NAME),
            &serde_json::to_vec_pretty(&legacy).expect("legacy v5 provider state bytes"),
        )
        .expect("write v5 state with provider evidence");

        let error = match FactoryReproductionEngine::open(&directory.0, rig.ports()) {
            Ok(_) => panic!("unbounded provider evidence must not be fabricated into accounting"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            ReproductionError::StateIntegrity(message)
                if message.contains("maximum-output-token")
                    && message.contains("fresh qualification")
        ));
    }

    #[test]
    fn v4_state_with_opaque_provider_qualification_fails_closed() {
        let directory = TestDirectory::new("engine-v4-provider-fail-closed");
        let rig = TestRig::new();
        let mut engine = initialize_engine(&directory, &rig);
        let request = provider_request(&engine, "qualification:legacy-v4");
        engine
            .qualify_live_provider(request)
            .expect("persist one provider qualification");
        let mut legacy = serde_json::to_value(&engine.state).expect("serialize v5 state");
        let object = legacy.as_object_mut().expect("state object");
        object.insert("schema_version".to_string(), serde_json::Value::from(4));
        object.insert(
            "state_digest".to_string(),
            serde_json::to_value(ContentDigest::from_bytes(b"legacy-v4-provider-state"))
                .expect("legacy digest"),
        );
        drop(engine);
        atomic_write(
            &directory.0.join(STATE_FILE_NAME),
            &serde_json::to_vec_pretty(&legacy).expect("legacy v4 provider state bytes"),
        )
        .expect("write v4 state with provider evidence");

        let error = match FactoryReproductionEngine::open(&directory.0, rig.ports()) {
            Ok(_) => panic!("opaque provider evidence must not be fabricated into accounting"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            ReproductionError::StateIntegrity(message)
                if message.contains("opaque receipt digests")
                    && message.contains("fresh qualification")
        ));
    }

    #[test]
    fn worker_package_evidence_mismatch_prevents_shadow_and_approval() {
        let directory = TestDirectory::new("worker-mismatch");
        let rig = TestRig::new();
        *rig.m4.mode.lock().expect("lock worker mode") = WorkerMode::WrongPackage;
        let mut engine = initialize_engine(&directory, &rig);
        let request = seed_request(
            &engine,
            "cycle:worker-mismatch",
            component_bytes(1),
            MutableFactoryPolicy::terminal(2, 2),
        );
        assert!(matches!(
            engine.run_seeded_cycle(request),
            Err(ReproductionError::DigestMismatch { .. })
        ));
        assert_eq!(rig.m2.calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn observation_package_mismatch_is_integrity_failure_not_regression() {
        let directory = TestDirectory::new("observation-mismatch");
        let rig = TestRig::new();
        *rig.m3
            .observation_mode
            .lock()
            .expect("lock observation mode") = ObservationMode::WrongPackage;
        let mut engine = initialize_engine(&directory, &rig);
        let request = seed_request(
            &engine,
            "cycle:observation-mismatch",
            component_bytes(1),
            MutableFactoryPolicy::terminal(2, 2),
        );
        assert!(matches!(
            engine.run_seeded_cycle(request),
            Err(ReproductionError::DigestMismatch { .. })
        ));
        assert!(engine.state.in_flight.is_some());
        assert!(engine.state.quarantines.is_empty());
    }

    #[test]
    fn absent_and_unavailable_provider_remain_explicitly_unqualified() {
        let directory = TestDirectory::new("provider-absent");
        let rig = TestRig::new();
        let mut engine = FactoryReproductionEngine::initialize(
            &directory.0,
            "factory:test",
            incumbent_package(),
            release_gate(),
            rig.ports_without_provider(),
        )
        .expect("initialize without provider");
        let request = provider_request(&engine, "qualification:absent");
        let absent = engine
            .qualify_live_provider(request)
            .expect("persist absent qualification");
        assert_eq!(absent.status, ProviderQualificationStatus::Unavailable);
        assert!(absent.live_turn.is_none());
        assert!(
            !absent
                .is_qualified_for(&provider_configuration())
                .expect("check qualification")
        );

        let directory = TestDirectory::new("provider-unavailable");
        let mut engine = initialize_engine(&directory, &rig);
        *rig.provider.mode.lock().expect("lock provider mode") = ProviderMode::Unavailable;
        let request = provider_request(&engine, "qualification:unavailable");
        let unavailable = engine
            .qualify_live_provider(request)
            .expect("persist unavailable provider");
        assert_eq!(unavailable.status, ProviderQualificationStatus::Unavailable);
        assert!(unavailable.failure.is_some());
        assert!(unavailable.live_turn.is_none());
    }

    #[test]
    fn provider_failure_and_bad_replay_cannot_manufacture_qualification() {
        let directory = TestDirectory::new("provider-failures");
        let rig = TestRig::new();
        let mut engine = initialize_engine(&directory, &rig);

        *rig.provider.mode.lock().expect("lock provider mode") = ProviderMode::LiveFailure;
        let failed = engine
            .qualify_live_provider(provider_request(&engine, "qualification:live-failure"))
            .expect("persist live failure");
        assert_eq!(failed.status, ProviderQualificationStatus::LiveTurnFailed);

        *rig.provider.mode.lock().expect("lock provider mode") = ProviderMode::ReplayMismatch;
        let mismatch = engine
            .qualify_live_provider(provider_request(&engine, "qualification:replay-mismatch"))
            .expect("persist replay mismatch");
        assert_eq!(mismatch.status, ProviderQualificationStatus::ReplayMismatch);
        assert!(mismatch.live_turn.is_some());
        assert!(mismatch.replay.is_some());

        *rig.provider.mode.lock().expect("lock provider mode") = ProviderMode::ReplayUsesNetwork;
        let networked = engine
            .qualify_live_provider(provider_request(&engine, "qualification:networked-replay"))
            .expect("persist networked replay rejection");
        assert_eq!(
            networked.status,
            ProviderQualificationStatus::ReplayMismatch
        );
        assert!(
            engine
                .state
                .provider_qualifications
                .iter()
                .all(|record| record.status != ProviderQualificationStatus::Qualified)
        );
    }

    #[test]
    fn live_provider_qualification_requires_matching_offline_replay_and_expires_on_change() {
        let directory = TestDirectory::new("provider-qualified");
        let rig = TestRig::new();
        let mut engine = initialize_engine(&directory, &rig);
        let request = provider_request(&engine, "qualification:valid");
        let record = engine
            .qualify_live_provider(request.clone())
            .expect("qualify provider turn");
        assert_eq!(record.status, ProviderQualificationStatus::Qualified);
        assert!(record.live_turn.is_some());
        assert!(record.replay.is_some());
        assert!(
            record
                .is_qualified_for(&provider_configuration())
                .expect("current qualification")
        );
        let turn = record.live_turn.as_ref().expect("qualified live turn");
        validate_live_turn(&request, turn).expect("structured live evidence validates");
        assert_eq!(turn.provider_accounting.provider_id, "provider:test");
        assert_eq!(turn.provider_accounting.model_id, "model:test");
        assert_eq!(turn.provider_accounting.total_tokens, 15);
        assert_eq!(turn.provider_accounting.total_latency_ms, 7);
        assert_eq!(turn.provider_accounting.attempts.len(), 1);
        assert_eq!(
            turn.provider_receipt_digest,
            turn.provider_accounting.accounting_digest
        );
        let encoded = serde_json::to_string(&turn.provider_accounting)
            .expect("serialize bounded provider accounting");
        for forbidden in [
            "raw-provider-response",
            "provider-request-body",
            "authorization",
            "api_key",
            "sk-proj-",
        ] {
            assert!(
                !encoded.to_ascii_lowercase().contains(forbidden),
                "provider accounting leaked forbidden material '{forbidden}'"
            );
        }

        let mut changed = provider_configuration();
        changed.tool_catalog_digest = ContentDigest::from_bytes(b"tool-catalog-v2");
        assert!(
            !record
                .is_qualified_for(&changed)
                .expect("changed configuration expires qualification")
        );

        let retained_accounting = turn.provider_accounting.clone();
        drop(engine);
        let reopened = FactoryReproductionEngine::open(&directory.0, rig.ports())
            .expect("reopen qualified provider state");
        assert_eq!(
            reopened.state.provider_qualifications[0]
                .live_turn
                .as_ref()
                .expect("reopened live turn")
                .provider_accounting,
            retained_accounting
        );
        reopened
            .state
            .validate()
            .expect("reopened structured provider accounting validates");
    }

    #[test]
    fn provider_accounting_tampering_fails_closed_at_the_live_turn_boundary() {
        let directory = TestDirectory::new("provider-accounting-tamper");
        let rig = TestRig::new();
        let engine = initialize_engine(&directory, &rig);
        let request = provider_request(&engine, "qualification:accounting-tamper");
        let turn = rig
            .provider
            .perform_live_turn(&request)
            .expect("fixture live turn");
        validate_live_turn(&request, &turn).expect("untampered live turn validates");

        let reseal = |turn: &mut LiveProviderTurn| {
            turn.provider_accounting.accounting_digest = turn
                .provider_accounting
                .expected_digest()
                .expect("accounting digest");
            turn.provider_receipt_digest = turn.provider_accounting.accounting_digest.clone();
            turn.turn_digest = live_provider_turn_digest(turn).expect("turn digest");
        };

        let mut wrong_provider = turn.clone();
        wrong_provider.provider_accounting.provider_id = "provider:other".to_string();
        reseal(&mut wrong_provider);
        assert!(matches!(
            validate_live_turn(&request, &wrong_provider),
            Err(ReproductionError::ProviderQualification(message))
                if message.contains("different provider, model")
        ));

        let mut wrong_profile = turn.clone();
        wrong_profile.provider_accounting.provider_profile =
            M5ProviderProfileV1::OpenRouterChatCompletions;
        reseal(&mut wrong_profile);
        assert!(matches!(
            validate_live_turn(&request, &wrong_profile),
            Err(ReproductionError::ProviderQualification(message))
                if message.contains("profile, policy, generation bound")
        ));

        let mut wrong_policy = turn.clone();
        wrong_policy.provider_accounting.generation_policy_id = "policy:substituted".to_string();
        reseal(&mut wrong_policy);
        assert!(matches!(
            validate_live_turn(&request, &wrong_policy),
            Err(ReproductionError::ProviderQualification(message))
                if message.contains("profile, policy, generation bound")
        ));

        let mut wrong_retry_bound = turn.clone();
        wrong_retry_bound.provider_accounting.maximum_retries = 1;
        reseal(&mut wrong_retry_bound);
        assert!(matches!(
            validate_live_turn(&request, &wrong_retry_bound),
            Err(ReproductionError::ProviderQualification(message))
                if message.contains("profile, policy, generation bound")
        ));

        let mut wrong_output_bound = turn.clone();
        wrong_output_bound.provider_accounting.maximum_output_tokens += 1;
        reseal(&mut wrong_output_bound);
        assert!(matches!(
            validate_live_turn(&request, &wrong_output_bound),
            Err(ReproductionError::ProviderQualification(message))
                if message.contains("profile, policy, generation bound")
        ));

        let mut malicious_usage = turn.clone();
        malicious_usage.provider_accounting.maximum_output_tokens = 4;
        malicious_usage.provider_accounting.output_tokens = 5;
        malicious_usage.provider_accounting.total_tokens =
            malicious_usage.provider_accounting.input_tokens + 5;
        malicious_usage
            .provider_accounting
            .estimated_cost_microunits = estimate_provider_cost_microunits(
            malicious_usage.provider_accounting.input_tokens,
            malicious_usage.provider_accounting.output_tokens,
            malicious_usage
                .provider_accounting
                .input_cost_per_million_microunits,
            malicious_usage
                .provider_accounting
                .output_cost_per_million_microunits,
        )
        .expect("recompute malicious usage cost");
        malicious_usage.provider_accounting.accounting_digest = malicious_usage
            .provider_accounting
            .expected_digest()
            .expect("reseal malicious usage accounting");
        malicious_usage.provider_receipt_digest = malicious_usage
            .provider_accounting
            .accounting_digest
            .clone();
        malicious_usage.turn_digest =
            live_provider_turn_digest(&malicious_usage).expect("reseal malicious usage turn");
        assert!(matches!(
            validate_live_turn(&request, &malicious_usage),
            Err(ReproductionError::ProviderQualification(message))
                if message.contains("output-token usage exceeds")
        ));

        let mut wrong_pricing_basis = turn.clone();
        wrong_pricing_basis
            .provider_accounting
            .input_cost_per_million_microunits += 1;
        reseal(&mut wrong_pricing_basis);
        assert!(matches!(
            validate_live_turn(&request, &wrong_pricing_basis),
            Err(ReproductionError::ProviderQualification(message))
                if message.contains("pricing basis")
        ));

        let mut wrong_cost = turn.clone();
        wrong_cost.provider_accounting.estimated_cost_microunits += 1;
        reseal(&mut wrong_cost);
        assert!(matches!(
            validate_live_turn(&request, &wrong_cost),
            Err(ReproductionError::ProviderQualification(message))
                if message.contains("cost accounting")
        ));

        let mut wrong_tokens = turn.clone();
        wrong_tokens.provider_accounting.total_tokens += 1;
        reseal(&mut wrong_tokens);
        assert!(matches!(
            validate_live_turn(&request, &wrong_tokens),
            Err(ReproductionError::ProviderQualification(message))
                if message.contains("token accounting does not add up")
        ));

        let mut wrong_retry = turn.clone();
        wrong_retry.provider_accounting.maximum_retries = 1;
        wrong_retry.provider_accounting.attempts[0].http_status = Some(500);
        wrong_retry.provider_accounting.attempts[0].retry_classification =
            InferenceRetryClassification::RetriedServerError;
        reseal(&mut wrong_retry);
        assert!(matches!(
            validate_live_turn(&request, &wrong_retry),
            Err(ReproductionError::ProviderQualification(message))
                if message.contains("successful terminal attempt")
        ));

        let mut missing_success_status = turn.clone();
        missing_success_status.provider_accounting.attempts[0].http_status = None;
        reseal(&mut missing_success_status);
        assert!(matches!(
            validate_live_turn(&request, &missing_success_status),
            Err(ReproductionError::ProviderQualification(message))
                if message.contains("contradicts its HTTP/transport outcome")
        ));

        let mut wrong_response = turn;
        wrong_response.provider_accounting.attempts[0].raw_response_digest =
            ContentDigest::from_bytes(b"substituted-response");
        reseal(&mut wrong_response);
        assert!(matches!(
            validate_live_turn(&request, &wrong_response),
            Err(ReproductionError::DigestMismatch { subject, .. })
                if subject == "live provider terminal raw response"
        ));
    }
}
