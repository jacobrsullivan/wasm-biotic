use crate::execution::artifact::{
    ArtifactDigest, ArtifactError, BuildClosureManifest, ContentDigest, GenerationManifest,
    PackageBundleManifest, digest_json,
};
use crate::execution::capability::{
    ApprovalClass, AuthorityClass, CapabilityEnvelope, CapabilityWorld,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::sync::Arc;
use wasmparser::{Encoding, Parser, Payload};
use wasmtime::component::{Component, Linker};
use wasmtime::{Config, StoreLimits, StoreLimitsBuilder, Trap};
use wit_parser::{Resolve, WorldKey};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentBuildRequest {
    pub build_id: String,
    pub manifest: GenerationManifest,
    pub wit_source: String,
    pub component_source: String,
    pub required_capability_world_refs: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentInspection {
    pub component_digest: ArtifactDigest,
    pub executable: bool,
    pub wit_world: String,
    pub interface_exports: Vec<String>,
    pub interface_imports: Vec<String>,
    pub capability_world_refs: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentBuildOutput {
    pub build_id: String,
    pub generation_id: crate::execution::artifact::GenerationArtifactId,
    pub component_bytes: Vec<u8>,
    pub component_digest: ArtifactDigest,
    pub inspection: ComponentInspection,
    pub build_closure: BuildClosureManifest,
    pub package_manifest: PackageBundleManifest,
    pub diagnostics: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentImportBinding {
    pub import_name: String,
    pub world: CapabilityWorld,
    pub operation: String,
    pub resource_scope: String,
    pub required_authority_class: AuthorityClass,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentImportLinkAudit {
    pub import_name: String,
    pub world: CapabilityWorld,
    pub operation: String,
    pub resource_scope: String,
    pub approval_class: ApprovalClass,
    pub linked: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentExecutionContext {
    pub capability_envelope: CapabilityEnvelope,
    pub import_bindings: Vec<ComponentImportBinding>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentExecutionTrace {
    pub export_name: String,
    pub result_ref: String,
    pub trapped: bool,
    pub invoked_imports: Vec<String>,
    pub import_link_audits: Vec<ComponentImportLinkAudit>,
    pub diagnostics: Vec<String>,
}

/// Content-bound proof that one linked component import reached an effect
/// owner rather than a success-shaped host stub.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentImportEffectReceipt {
    pub import_name: String,
    pub binding_digest: ContentDigest,
    pub service_id: String,
    pub invocation_id: String,
    pub implementation_digest: ContentDigest,
    pub input_digest: ContentDigest,
    pub output_digest: ContentDigest,
    pub receipt_digest: ContentDigest,
    pub attestation_digest: ContentDigest,
    pub terminal_success: bool,
}

/// Trusted host bridge used by effectful component imports.
///
/// The handler must invoke the configured effect owner and return its durable
/// attestation material. Returning an error, a failed receipt, or a receipt
/// bound to another import traps the component call.
pub trait ComponentImportEffectHandler: Send + Sync {
    fn invoke(
        &self,
        binding: &ComponentImportBinding,
    ) -> Result<ComponentImportEffectReceipt, String>;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectfulComponentExecutionTrace {
    pub execution: ComponentExecutionTrace,
    pub effects: Vec<ComponentImportEffectReceipt>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentExecutionLimits {
    pub fuel: u64,
    pub max_memory_bytes: u64,
    pub max_instances: u32,
    pub max_memories: u32,
    pub max_tables: u32,
    pub max_table_elements: u32,
}

impl Default for ComponentExecutionLimits {
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComponentExecutionFailurePhase {
    Instantiation,
    Invocation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComponentExecutionLimitKind {
    Fuel,
    LinearMemory,
    StoreResources,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentI32ExecutionTrace {
    pub component_digest: ContentDigest,
    pub export_name: String,
    pub input: i32,
    pub output: Option<i32>,
    pub trapped: bool,
    pub failure_phase: Option<ComponentExecutionFailurePhase>,
    pub limit_exhausted: Option<ComponentExecutionLimitKind>,
    pub limits: ComponentExecutionLimits,
    pub fuel_consumed: u64,
    pub invoked_imports: Vec<String>,
    pub import_link_audits: Vec<ComponentImportLinkAudit>,
    pub diagnostics: Vec<String>,
}

pub fn build_component_package(
    request: ComponentBuildRequest,
) -> Result<ComponentBuildOutput, ComponentBuildError> {
    request.manifest.validate()?;
    if request.build_id.trim().is_empty() {
        return Err(ComponentBuildError::MissingBuildId);
    }
    if request.manifest.wit_world.trim().is_empty() {
        return Err(ComponentBuildError::MissingWitWorld);
    }
    if request.component_source.trim().is_empty() {
        return Err(ComponentBuildError::MissingComponentSource);
    }
    if request.required_capability_world_refs.is_empty() {
        return Err(ComponentBuildError::MissingCapabilityWorlds);
    }

    let manifest_digest = request.manifest.manifest_digest()?;
    let wit_world = parse_wit_world(&request.wit_source, &request.manifest.wit_world)?;

    let component_bytes = wat::parse_str(&request.component_source)
        .map_err(|error| ComponentBuildError::WatParse(error.to_string()))?;
    validate_component_encoding(&component_bytes)?;
    let component_digest = ArtifactDigest::from_bytes(&component_bytes);
    let inspection = inspect_component_bytes(
        &component_bytes,
        wit_world.world_name.clone(),
        request.required_capability_world_refs.clone(),
    )?;
    ensure_export_match(&wit_world.exports, &inspection.interface_exports)?;
    ensure_import_match(&wit_world.imports, &inspection.interface_imports)?;

    let build_closure = BuildClosureManifest::new(
        request.build_id.clone(),
        request.manifest.artifact_id.clone(),
        "aiaf-wasmtime-component-packager-v3.3",
        vec![
            manifest_digest.clone(),
            digest_json(&request.wit_source)?,
            digest_json(&request.component_source)?,
        ],
        component_digest.clone(),
        vec![
            "WIT parsed with wit-parser".to_string(),
            "component WAT lowered to bytes with wat".to_string(),
            "component bytes parsed with wasmparser and compiled with Wasmtime".to_string(),
        ],
    )?;
    let package_manifest = PackageBundleManifest::new(
        format!("package-{}", request.manifest.artifact_id.as_str()),
        request.manifest.artifact_id.clone(),
        manifest_digest,
        component_digest.clone(),
        inspection.interface_exports.clone(),
        inspection.interface_imports.clone(),
        request.required_capability_world_refs,
    )?;

    Ok(ComponentBuildOutput {
        build_id: request.build_id,
        generation_id: request.manifest.artifact_id,
        component_bytes,
        component_digest,
        inspection,
        build_closure,
        package_manifest,
        diagnostics: vec![
            "real Wasmtime component build and packaging completed deterministically".to_string(),
        ],
    })
}

pub fn inspect_component_bytes(
    component_bytes: &[u8],
    wit_world: impl Into<String>,
    capability_world_refs: Vec<String>,
) -> Result<ComponentInspection, ComponentBuildError> {
    validate_component_encoding(component_bytes)?;
    let wit_world = wit_world.into();
    if wit_world.trim().is_empty() {
        return Err(ComponentBuildError::MissingWitWorld);
    }
    if capability_world_refs.is_empty() {
        return Err(ComponentBuildError::MissingCapabilityWorlds);
    }
    let engine = wasmtime::Engine::default();
    let component = compile_component(&engine, component_bytes)?;
    let (interface_imports, interface_exports) = component_interface_terms(&engine, &component);

    Ok(ComponentInspection {
        component_digest: ArtifactDigest::from_bytes(component_bytes),
        executable: true,
        wit_world,
        interface_exports,
        interface_imports,
        capability_world_refs,
    })
}

pub fn execute_component_export(
    component_bytes: &[u8],
    export_name: impl Into<String>,
) -> Result<ComponentExecutionTrace, ComponentBuildError> {
    Ok(execute_component_export_inner(component_bytes, export_name.into(), None, None)?.execution)
}

pub fn execute_component_export_with_context(
    component_bytes: &[u8],
    export_name: impl Into<String>,
    context: &ComponentExecutionContext,
) -> Result<ComponentExecutionTrace, ComponentBuildError> {
    Ok(
        execute_component_export_inner(component_bytes, export_name.into(), Some(context), None)?
            .execution,
    )
}

pub fn execute_component_export_with_effects(
    component_bytes: &[u8],
    export_name: impl Into<String>,
    context: &ComponentExecutionContext,
    effect_handler: Arc<dyn ComponentImportEffectHandler>,
) -> Result<EffectfulComponentExecutionTrace, ComponentBuildError> {
    execute_component_export_inner(
        component_bytes,
        export_name.into(),
        Some(context),
        Some(effect_handler),
    )
}

pub fn execute_component_i32_export(
    component_bytes: &[u8],
    export_name: impl Into<String>,
    input: i32,
    limits: &ComponentExecutionLimits,
) -> Result<ComponentI32ExecutionTrace, ComponentBuildError> {
    execute_component_i32_export_inner(component_bytes, export_name.into(), input, limits, None)
}

pub fn execute_component_i32_export_with_context(
    component_bytes: &[u8],
    export_name: impl Into<String>,
    input: i32,
    limits: &ComponentExecutionLimits,
    context: &ComponentExecutionContext,
) -> Result<ComponentI32ExecutionTrace, ComponentBuildError> {
    execute_component_i32_export_inner(
        component_bytes,
        export_name.into(),
        input,
        limits,
        Some(context),
    )
}

fn execute_component_export_inner(
    component_bytes: &[u8],
    export_name: String,
    context: Option<&ComponentExecutionContext>,
    effect_handler: Option<Arc<dyn ComponentImportEffectHandler>>,
) -> Result<EffectfulComponentExecutionTrace, ComponentBuildError> {
    if export_name.trim().is_empty() {
        return Err(ComponentBuildError::MissingComponentExport(export_name));
    }
    validate_component_encoding(component_bytes)?;
    let engine = wasmtime::Engine::default();
    let component = compile_component(&engine, component_bytes)?;
    let (interface_imports, interface_exports) = component_interface_terms(&engine, &component);
    if !interface_exports
        .iter()
        .any(|export| export == &export_name)
    {
        return Err(ComponentBuildError::MissingComponentExport(export_name));
    }

    let (linker, import_link_audits) =
        build_linker(&engine, &interface_imports, context, effect_handler)?;
    let mut store = wasmtime::Store::new(&engine, ComponentHostState::default());
    let instance = linker
        .instantiate(&mut store, &component)
        .map_err(|error| ComponentBuildError::Wasmtime(error.to_string()))?;
    let run = instance
        .get_typed_func::<(), ()>(&mut store, export_name.as_str())
        .map_err(|error| ComponentBuildError::Wasmtime(error.to_string()))?;
    run.call(&mut store, ())
        .map_err(|error| ComponentBuildError::Wasmtime(error.to_string()))?;

    Ok(EffectfulComponentExecutionTrace {
        execution: ComponentExecutionTrace {
            result_ref: component_success_result_ref(component_bytes, &export_name),
            export_name,
            trapped: false,
            invoked_imports: store.data().invoked_imports.clone(),
            import_link_audits,
            diagnostics: vec!["component export executed successfully under Wasmtime".to_string()],
        },
        effects: store.data().import_effect_receipts.clone(),
    })
}

fn execute_component_i32_export_inner(
    component_bytes: &[u8],
    export_name: String,
    input: i32,
    limits: &ComponentExecutionLimits,
    context: Option<&ComponentExecutionContext>,
) -> Result<ComponentI32ExecutionTrace, ComponentBuildError> {
    if export_name.trim().is_empty() {
        return Err(ComponentBuildError::MissingComponentExport(export_name));
    }
    let store_limits = validated_store_limits(limits)?;
    validate_component_encoding(component_bytes)?;

    let mut config = Config::new();
    config.consume_fuel(true);
    let engine = wasmtime::Engine::new(&config)
        .map_err(|error| ComponentBuildError::Wasmtime(error.to_string()))?;
    let component = compile_component(&engine, component_bytes)?;
    let (interface_imports, interface_exports) = component_interface_terms(&engine, &component);
    if !interface_exports
        .iter()
        .any(|export| export == &export_name)
    {
        return Err(ComponentBuildError::MissingComponentExport(export_name));
    }

    let (linker, import_link_audits) = build_linker(&engine, &interface_imports, context, None)?;
    let mut store = wasmtime::Store::new(
        &engine,
        ComponentHostState {
            invoked_imports: Vec::new(),
            import_effect_receipts: Vec::new(),
            limits: store_limits,
        },
    );
    store.limiter(|state| &mut state.limits);
    store
        .set_fuel(limits.fuel)
        .map_err(|error| ComponentBuildError::Wasmtime(error.to_string()))?;

    let instance = match linker.instantiate(&mut store, &component) {
        Ok(instance) => instance,
        Err(error) => {
            return Ok(component_i32_failure_trace(
                component_bytes,
                export_name,
                input,
                limits,
                &store,
                import_link_audits,
                ComponentExecutionFailurePhase::Instantiation,
                &error,
            ));
        }
    };
    let run = instance
        .get_typed_func::<(i32,), (i32,)>(&mut store, export_name.as_str())
        .map_err(|error| ComponentBuildError::Wasmtime(error.to_string()))?;
    let (output,) = match run.call(&mut store, (input,)) {
        Ok(output) => output,
        Err(error) => {
            return Ok(component_i32_failure_trace(
                component_bytes,
                export_name,
                input,
                limits,
                &store,
                import_link_audits,
                ComponentExecutionFailurePhase::Invocation,
                &error,
            ));
        }
    };
    let fuel_consumed = fuel_consumed(&store, limits.fuel);

    Ok(ComponentI32ExecutionTrace {
        component_digest: ContentDigest::from_bytes(component_bytes),
        export_name,
        input,
        output: Some(output),
        trapped: false,
        failure_phase: None,
        limit_exhausted: None,
        limits: limits.clone(),
        fuel_consumed,
        invoked_imports: store.data().invoked_imports.clone(),
        import_link_audits,
        diagnostics: vec![
            "typed component export executed successfully under bounded Wasmtime".to_string(),
        ],
    })
}

fn validated_store_limits(
    limits: &ComponentExecutionLimits,
) -> Result<StoreLimits, ComponentBuildError> {
    if limits.fuel == 0 {
        return Err(ComponentBuildError::InvalidExecutionLimit {
            limit: "fuel".to_string(),
            value: limits.fuel,
        });
    }
    if limits.max_memory_bytes == 0 {
        return Err(ComponentBuildError::InvalidExecutionLimit {
            limit: "max_memory_bytes".to_string(),
            value: limits.max_memory_bytes,
        });
    }
    for (limit, value) in [
        ("max_instances", u64::from(limits.max_instances)),
        ("max_memories", u64::from(limits.max_memories)),
        ("max_tables", u64::from(limits.max_tables)),
        ("max_table_elements", u64::from(limits.max_table_elements)),
    ] {
        if value == 0 {
            return Err(ComponentBuildError::InvalidExecutionLimit {
                limit: limit.to_string(),
                value,
            });
        }
    }
    let max_memory_bytes = usize::try_from(limits.max_memory_bytes).map_err(|_| {
        ComponentBuildError::ExecutionLimitOutOfRange {
            limit: "max_memory_bytes".to_string(),
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

fn component_i32_failure_trace(
    component_bytes: &[u8],
    export_name: String,
    input: i32,
    limits: &ComponentExecutionLimits,
    store: &wasmtime::Store<ComponentHostState>,
    import_link_audits: Vec<ComponentImportLinkAudit>,
    failure_phase: ComponentExecutionFailurePhase,
    error: &wasmtime::Error,
) -> ComponentI32ExecutionTrace {
    let limit_exhausted = classify_execution_limit(error, &failure_phase);
    let diagnostic = match &limit_exhausted {
        Some(limit) => format!(
            "typed component {:?} terminated at configured {limit:?} limit: {error:#}",
            failure_phase
        ),
        None => format!(
            "typed component {:?} trapped under bounded Wasmtime: {error:#}",
            failure_phase
        ),
    };
    ComponentI32ExecutionTrace {
        component_digest: ContentDigest::from_bytes(component_bytes),
        export_name,
        input,
        output: None,
        trapped: true,
        failure_phase: Some(failure_phase),
        limit_exhausted,
        limits: limits.clone(),
        fuel_consumed: fuel_consumed(store, limits.fuel),
        invoked_imports: store.data().invoked_imports.clone(),
        import_link_audits,
        diagnostics: vec![diagnostic],
    }
}

fn classify_execution_limit(
    error: &wasmtime::Error,
    failure_phase: &ComponentExecutionFailurePhase,
) -> Option<ComponentExecutionLimitKind> {
    if error.downcast_ref::<Trap>() == Some(&Trap::OutOfFuel) {
        return Some(ComponentExecutionLimitKind::Fuel);
    }
    let error_text = error.to_string().to_ascii_lowercase();
    if error_text.contains("memory")
        && (error_text.contains("grow")
            || error_text.contains("minimum size")
            || error_text.contains("resource limit"))
    {
        return Some(ComponentExecutionLimitKind::LinearMemory);
    }
    if matches!(failure_phase, ComponentExecutionFailurePhase::Instantiation)
        && (error_text.contains("limit")
            || error_text.contains("instance")
            || error_text.contains("table"))
    {
        return Some(ComponentExecutionLimitKind::StoreResources);
    }
    None
}

fn fuel_consumed(store: &wasmtime::Store<ComponentHostState>, fuel_limit: u64) -> u64 {
    store
        .get_fuel()
        .map(|remaining| fuel_limit.saturating_sub(remaining))
        .unwrap_or_default()
}

fn build_linker(
    engine: &wasmtime::Engine,
    interface_imports: &[String],
    context: Option<&ComponentExecutionContext>,
    effect_handler: Option<Arc<dyn ComponentImportEffectHandler>>,
) -> Result<(Linker<ComponentHostState>, Vec<ComponentImportLinkAudit>), ComponentBuildError> {
    if interface_imports.is_empty() {
        if let Some(context) = context {
            if let Some(binding) = context.import_bindings.first() {
                return Err(ComponentBuildError::UnusedImportBinding {
                    import_name: binding.import_name.clone(),
                });
            }
        }
        return Ok((Linker::new(engine), Vec::new()));
    }

    let context = context
        .ok_or_else(|| ComponentBuildError::UnsupportedImports(interface_imports.to_vec()))?;
    let mut linker = Linker::<ComponentHostState>::new(engine);
    let import_set = interface_imports.iter().cloned().collect::<BTreeSet<_>>();
    let mut binding_map = BTreeMap::new();
    for binding in &context.import_bindings {
        if binding.import_name.trim().is_empty()
            || binding.operation.trim().is_empty()
            || binding.resource_scope.trim().is_empty()
        {
            return Err(ComponentBuildError::MalformedImportBinding {
                import_name: binding.import_name.clone(),
            });
        }
        if !import_set.contains(&binding.import_name) {
            return Err(ComponentBuildError::UnusedImportBinding {
                import_name: binding.import_name.clone(),
            });
        }
        if binding_map
            .insert(binding.import_name.clone(), binding)
            .is_some()
        {
            return Err(ComponentBuildError::DuplicateImportBinding {
                import_name: binding.import_name.clone(),
            });
        }
    }

    let mut audits = Vec::new();
    for import_name in interface_imports {
        let binding = binding_map.get(import_name).ok_or_else(|| {
            ComponentBuildError::UnboundComponentImport {
                import_name: import_name.clone(),
            }
        })?;
        validate_import_binding(&context.capability_envelope, binding)?;
        let approval_class = context
            .capability_envelope
            .approval_for(&binding.world, &binding.operation)
            .expect("validated import binding must have an approval class");
        let import_name_for_callback = import_name.clone();
        let binding_for_callback = (*binding).clone();
        let effect_handler_for_callback = effect_handler.clone();
        linker
            .root()
            .func_wrap(
                import_name,
                move |mut store: wasmtime::StoreContextMut<'_, ComponentHostState>,
                      (): ()|
                      -> wasmtime::Result<()> {
                    if let Some(handler) = &effect_handler_for_callback {
                        let receipt = handler.invoke(&binding_for_callback).map_err(|reason| {
                            wasmtime::Error::msg(format!(
                                "component import '{}' effect failed: {reason}",
                                binding_for_callback.import_name
                            ))
                        })?;
                        validate_effect_receipt(&binding_for_callback, &receipt).map_err(
                            |reason| {
                                wasmtime::Error::msg(format!(
                                    "component import '{}' returned invalid effect evidence: {reason}",
                                    binding_for_callback.import_name
                                ))
                            },
                        )?;
                        store.data_mut().import_effect_receipts.push(receipt);
                    }
                    store
                        .data_mut()
                        .invoked_imports
                        .push(import_name_for_callback.clone());
                    Ok(())
                },
            )
            .map_err(|error| ComponentBuildError::Wasmtime(error.to_string()))?;
        audits.push(ComponentImportLinkAudit {
            import_name: import_name.clone(),
            world: binding.world.clone(),
            operation: binding.operation.clone(),
            resource_scope: binding.resource_scope.clone(),
            approval_class,
            linked: true,
        });
    }

    Ok((linker, audits))
}

struct ComponentHostState {
    invoked_imports: Vec<String>,
    import_effect_receipts: Vec<ComponentImportEffectReceipt>,
    limits: StoreLimits,
}

impl Default for ComponentHostState {
    fn default() -> Self {
        Self {
            invoked_imports: Vec::new(),
            import_effect_receipts: Vec::new(),
            limits: StoreLimits::default(),
        }
    }
}

fn validate_effect_receipt(
    binding: &ComponentImportBinding,
    receipt: &ComponentImportEffectReceipt,
) -> Result<(), String> {
    let binding_bytes = serde_json::to_vec(binding)
        .map_err(|error| format!("cannot encode import binding: {error}"))?;
    let expected_binding_digest = ContentDigest::from_bytes(&binding_bytes);
    if receipt.import_name != binding.import_name {
        return Err(format!(
            "receipt import '{}' does not match '{}'",
            receipt.import_name, binding.import_name
        ));
    }
    if receipt.binding_digest != expected_binding_digest {
        return Err("receipt binding digest does not match the authorized binding".to_string());
    }
    for (field, value) in [
        ("service_id", receipt.service_id.as_str()),
        ("invocation_id", receipt.invocation_id.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(format!("receipt {field} must not be blank"));
        }
    }
    if !receipt.terminal_success {
        return Err("effect owner did not report terminal success".to_string());
    }
    Ok(())
}

fn validate_import_binding(
    capability_envelope: &CapabilityEnvelope,
    binding: &ComponentImportBinding,
) -> Result<(), ComponentBuildError> {
    if !capability_envelope.grants_world(&binding.world) {
        return Err(ComponentBuildError::ImportCapabilityWorldMissing {
            import_name: binding.import_name.clone(),
            world: format!("{:?}", binding.world),
            envelope_id: capability_envelope.envelope_id.clone(),
        });
    }
    if !capability_envelope.scope_allows(&binding.resource_scope) {
        return Err(ComponentBuildError::ImportResourceScopeNotAllowed {
            import_name: binding.import_name.clone(),
            resource_scope: binding.resource_scope.clone(),
            envelope_id: capability_envelope.envelope_id.clone(),
        });
    }
    if !capability_envelope.allows_operation(&binding.world, &binding.operation) {
        return Err(ComponentBuildError::ImportOperationNotAllowed {
            import_name: binding.import_name.clone(),
            world: format!("{:?}", binding.world),
            operation: binding.operation.clone(),
            envelope_id: capability_envelope.envelope_id.clone(),
        });
    }
    if !capability_envelope.authority_allows(&binding.required_authority_class) {
        return Err(ComponentBuildError::ImportAuthorityExceedsEnvelope {
            import_name: binding.import_name.clone(),
            required: format!("{:?}", binding.required_authority_class),
            envelope_ceiling: format!("{:?}", capability_envelope.authority_ceiling),
        });
    }
    let approval_class = capability_envelope
        .approval_for(&binding.world, &binding.operation)
        .expect("allowed operation must have an approval class");
    match approval_class {
        ApprovalClass::AutoAllowed | ApprovalClass::SupervisorAllowed => Ok(()),
        ApprovalClass::HumanRequired
        | ApprovalClass::QuarantineOnExpand
        | ApprovalClass::Forbidden => Err(ComponentBuildError::ImportApprovalBlocked {
            import_name: binding.import_name.clone(),
            approval_class: format!("{approval_class:?}"),
        }),
    }
}

pub fn component_success_result_ref(_component_bytes: &[u8], export_name: &str) -> String {
    format!("wasmtime:export:{export_name}:ok")
}

pub fn component_failure_result_ref(
    component_bytes: &[u8],
    export_name: &str,
    error: &str,
) -> String {
    let digest = ArtifactDigest::from_bytes(component_bytes);
    let error_digest = ArtifactDigest::from_bytes(error.as_bytes());
    let error_fragment = error_digest.as_str().chars().take(12).collect::<String>();
    format!(
        "component:{}:export:{export_name}:failed:{error_fragment}",
        digest.as_str()
    )
}

fn validate_component_encoding(component_bytes: &[u8]) -> Result<(), ComponentBuildError> {
    let mut saw_header = false;
    for payload in Parser::new(0).parse_all(component_bytes) {
        let payload = payload.map_err(|error| ComponentBuildError::WasmParse(error.to_string()))?;
        if saw_header {
            continue;
        }
        if let Payload::Version { encoding, .. } = payload {
            saw_header = true;
            match encoding {
                Encoding::Component => {}
                Encoding::Module => return Err(ComponentBuildError::CoreWasmModuleRejected),
            }
        }
    }
    if !saw_header {
        return Err(ComponentBuildError::InvalidComponentEncoding);
    }
    Ok(())
}

fn compile_component(
    engine: &wasmtime::Engine,
    component_bytes: &[u8],
) -> Result<Component, ComponentBuildError> {
    Component::new(engine, component_bytes)
        .map_err(|error| ComponentBuildError::Wasmtime(error.to_string()))
}

fn component_interface_terms(
    engine: &wasmtime::Engine,
    component: &Component,
) -> (Vec<String>, Vec<String>) {
    let component_type = component.component_type();
    let mut imports = component_type
        .imports(engine)
        .map(|(name, _item)| name.to_string())
        .collect::<Vec<_>>();
    let mut exports = component_type
        .exports(engine)
        .map(|(name, _item)| name.to_string())
        .collect::<Vec<_>>();
    imports.sort();
    exports.sort();
    (imports, exports)
}

fn parse_wit_world(
    wit_source: &str,
    expected_world: &str,
) -> Result<ParsedWitWorld, ComponentBuildError> {
    if wit_source.trim().is_empty() {
        return Err(ComponentBuildError::MissingWitWorld);
    }
    let mut resolve = Resolve::default();
    let package_id = match resolve.push_str("inline.wit", wit_source) {
        Ok(package_id) => package_id,
        Err(error) if error.to_string().contains("no `package` header") => {
            let wit_source = format!("package aiaf:inline;\n{wit_source}");
            resolve
                .push_str("inline.wit", &wit_source)
                .map_err(|error| ComponentBuildError::WitParse(error.to_string()))?
        }
        Err(error) => return Err(ComponentBuildError::WitParse(error.to_string())),
    };
    let package = &resolve.packages[package_id];
    let world_id = package.worlds.get(expected_world).copied().ok_or_else(|| {
        ComponentBuildError::WitWorldMismatch {
            expected: expected_world.to_string(),
            available: package.worlds.keys().cloned().collect(),
        }
    })?;
    let world = &resolve.worlds[world_id];
    Ok(ParsedWitWorld {
        world_name: world.name.clone(),
        exports: sorted_world_terms(world.exports.keys()),
        imports: sorted_world_terms(world.imports.keys()),
    })
}

fn sorted_world_terms<'a>(keys: impl Iterator<Item = &'a WorldKey>) -> Vec<String> {
    let mut terms = keys.map(world_key_name).collect::<Vec<_>>();
    terms.sort();
    terms
}

fn world_key_name(key: &WorldKey) -> String {
    match key {
        WorldKey::Name(name) => name.clone(),
        WorldKey::Interface(id) => format!("interface-{}", id.index()),
    }
}

fn ensure_export_match(
    expected_exports: &[String],
    actual_exports: &[String],
) -> Result<(), ComponentBuildError> {
    let expected = expected_exports.iter().cloned().collect::<BTreeSet<_>>();
    let actual = actual_exports.iter().cloned().collect::<BTreeSet<_>>();
    if expected != actual {
        return Err(ComponentBuildError::ComponentExportMismatch {
            expected: expected.into_iter().collect(),
            actual: actual.into_iter().collect(),
        });
    }
    Ok(())
}

fn ensure_import_match(
    expected_imports: &[String],
    actual_imports: &[String],
) -> Result<(), ComponentBuildError> {
    let expected = expected_imports.iter().cloned().collect::<BTreeSet<_>>();
    let actual = actual_imports.iter().cloned().collect::<BTreeSet<_>>();
    if expected != actual {
        return Err(ComponentBuildError::ComponentImportMismatch {
            expected: expected.into_iter().collect(),
            actual: actual.into_iter().collect(),
        });
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ParsedWitWorld {
    world_name: String,
    exports: Vec<String>,
    imports: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ComponentBuildError {
    MissingBuildId,
    MissingWitWorld,
    MissingComponentSource,
    MissingCapabilityWorlds,
    MissingComponentExport(String),
    InvalidComponentEncoding,
    CoreWasmModuleRejected,
    UnsupportedImports(Vec<String>),
    UnboundComponentImport {
        import_name: String,
    },
    UnusedImportBinding {
        import_name: String,
    },
    DuplicateImportBinding {
        import_name: String,
    },
    MalformedImportBinding {
        import_name: String,
    },
    ImportCapabilityWorldMissing {
        import_name: String,
        world: String,
        envelope_id: String,
    },
    ImportResourceScopeNotAllowed {
        import_name: String,
        resource_scope: String,
        envelope_id: String,
    },
    ImportOperationNotAllowed {
        import_name: String,
        world: String,
        operation: String,
        envelope_id: String,
    },
    ImportAuthorityExceedsEnvelope {
        import_name: String,
        required: String,
        envelope_ceiling: String,
    },
    ImportApprovalBlocked {
        import_name: String,
        approval_class: String,
    },
    InvalidExecutionLimit {
        limit: String,
        value: u64,
    },
    ExecutionLimitOutOfRange {
        limit: String,
        value: u64,
    },
    ComponentExportMismatch {
        expected: Vec<String>,
        actual: Vec<String>,
    },
    ComponentImportMismatch {
        expected: Vec<String>,
        actual: Vec<String>,
    },
    WitWorldMismatch {
        expected: String,
        available: Vec<String>,
    },
    WitParse(String),
    WatParse(String),
    WasmParse(String),
    Wasmtime(String),
    Artifact(ArtifactError),
    Serialization(String),
}

impl From<ArtifactError> for ComponentBuildError {
    fn from(value: ArtifactError) -> Self {
        Self::Artifact(value)
    }
}

impl Display for ComponentBuildError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingBuildId => write!(f, "component build requires a build id"),
            Self::MissingWitWorld => write!(f, "component build requires a WIT world"),
            Self::MissingComponentSource => write!(f, "component build requires component source"),
            Self::MissingCapabilityWorlds => {
                write!(f, "component build requires capability world refs")
            }
            Self::MissingComponentExport(export) => {
                write!(f, "component export is missing or empty: {export}")
            }
            Self::InvalidComponentEncoding => {
                write!(f, "component bytes do not contain a WebAssembly header")
            }
            Self::CoreWasmModuleRejected => {
                write!(
                    f,
                    "core WebAssembly module rejected where a component is required"
                )
            }
            Self::UnsupportedImports(imports) => {
                write!(
                    f,
                    "component imports are not supported in this runtime scope: {imports:?}"
                )
            }
            Self::UnboundComponentImport { import_name } => {
                write!(f, "component import has no explicit binding: {import_name}")
            }
            Self::UnusedImportBinding { import_name } => {
                write!(
                    f,
                    "component import binding does not correspond to a component import: {import_name}"
                )
            }
            Self::DuplicateImportBinding { import_name } => {
                write!(f, "component import binding is duplicated: {import_name}")
            }
            Self::MalformedImportBinding { import_name } => {
                write!(f, "component import binding is malformed: {import_name}")
            }
            Self::ImportCapabilityWorldMissing {
                import_name,
                world,
                envelope_id,
            } => write!(
                f,
                "component import {import_name} requires missing capability world {world} in envelope {envelope_id}"
            ),
            Self::ImportResourceScopeNotAllowed {
                import_name,
                resource_scope,
                envelope_id,
            } => write!(
                f,
                "component import {import_name} resource scope {resource_scope} is not allowed by envelope {envelope_id}"
            ),
            Self::ImportOperationNotAllowed {
                import_name,
                world,
                operation,
                envelope_id,
            } => write!(
                f,
                "component import {import_name} operation {world}::{operation} is not allowed by envelope {envelope_id}"
            ),
            Self::ImportAuthorityExceedsEnvelope {
                import_name,
                required,
                envelope_ceiling,
            } => write!(
                f,
                "component import {import_name} requires authority {required} above envelope ceiling {envelope_ceiling}"
            ),
            Self::ImportApprovalBlocked {
                import_name,
                approval_class,
            } => write!(
                f,
                "component import {import_name} is blocked by approval class {approval_class}"
            ),
            Self::InvalidExecutionLimit { limit, value } => {
                write!(
                    f,
                    "component execution limit {limit} must be non-zero, got {value}"
                )
            }
            Self::ExecutionLimitOutOfRange { limit, value } => {
                write!(
                    f,
                    "component execution limit {limit} is out of range for this host: {value}"
                )
            }
            Self::ComponentExportMismatch { expected, actual } => {
                write!(
                    f,
                    "component exports do not match WIT world exports; expected {expected:?}, actual {actual:?}"
                )
            }
            Self::ComponentImportMismatch { expected, actual } => {
                write!(
                    f,
                    "component imports do not match WIT world imports; expected {expected:?}, actual {actual:?}"
                )
            }
            Self::WitWorldMismatch {
                expected,
                available,
            } => {
                write!(
                    f,
                    "WIT world {expected} was not found; available worlds: {available:?}"
                )
            }
            Self::WitParse(error) => write!(f, "WIT parse error: {error}"),
            Self::WatParse(error) => write!(f, "component WAT parse error: {error}"),
            Self::WasmParse(error) => write!(f, "component wasm parse error: {error}"),
            Self::Wasmtime(error) => write!(f, "Wasmtime component error: {error}"),
            Self::Artifact(error) => write!(f, "{error}"),
            Self::Serialization(error) => write!(f, "component serialization error: {error}"),
        }
    }
}

impl Error for ComponentBuildError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::artifact::GenerationManifest;
    use crate::execution::capability::{
        ApprovalClass, AuthorityClass, CapabilityEnvelope, CapabilityWorld, CapabilityWorldGrant,
        IsolationProfile,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn manifest() -> GenerationManifest {
        GenerationManifest::new(
            "generation-test",
            None,
            "package:aiaf/supervisor@test",
            "aiaf-supervisor-v3",
            vec!["src:test".to_string()],
            vec!["policy:test".to_string()],
            vec!["input:test".to_string()],
            "test manifest",
        )
        .unwrap()
    }

    fn request(wit_source: &str, component_source: &str) -> ComponentBuildRequest {
        ComponentBuildRequest {
            build_id: "build-test".to_string(),
            manifest: manifest(),
            wit_source: wit_source.to_string(),
            component_source: component_source.to_string(),
            required_capability_world_refs: vec!["world:test".to_string()],
        }
    }

    fn wit_run() -> &'static str {
        "world aiaf-supervisor-v3 { export run: func(); }"
    }

    fn wit_import_run() -> &'static str {
        "world aiaf-supervisor-v3 { import host-pulse: func(); export run: func(); }"
    }

    fn wit_transform() -> &'static str {
        "world aiaf-supervisor-v3 { export transform: func(value: s32) -> s32; }"
    }

    fn component_run() -> &'static str {
        r#"
            (component
                (core module $m
                    (func (export "run")))
                (core instance $i (instantiate $m))
                (func $run (canon lift (core func $i "run")))
                (export "run" (func $run)))
        "#
    }

    fn component_import_run() -> &'static str {
        r#"
            (component
                (import "host-pulse" (func $host-pulse))
                (core func $host-pulse-core (canon lower (func $host-pulse)))
                (core module $m
                    (import "" "host-pulse" (func $host-pulse))
                    (func (export "run")
                        call $host-pulse))
                (core instance $i (instantiate $m
                    (with "" (instance
                        (export "host-pulse" (func $host-pulse-core))))))
                (func $run (canon lift (core func $i "run")))
                (export "run" (func $run)))
        "#
    }

    fn component_transform_add_one() -> &'static str {
        r#"
            (component
                (core module $m
                    (func (export "transform") (param i32) (result i32)
                        local.get 0
                        i32.const 1
                        i32.add))
                (core instance $i (instantiate $m))
                (func $transform (param "value" s32) (result s32)
                    (canon lift (core func $i "transform")))
                (export "transform" (func $transform)))
        "#
    }

    fn component_transform_trap() -> &'static str {
        r#"
            (component
                (core module $m
                    (func (export "transform") (param i32) (result i32)
                        unreachable))
                (core instance $i (instantiate $m))
                (func $transform (param "value" s32) (result s32)
                    (canon lift (core func $i "transform")))
                (export "transform" (func $transform)))
        "#
    }

    fn component_transform_forever() -> &'static str {
        r#"
            (component
                (core module $m
                    (func (export "transform") (param i32) (result i32)
                        (loop $spin
                            br $spin)
                        local.get 0))
                (core instance $i (instantiate $m))
                (func $transform (param "value" s32) (result s32)
                    (canon lift (core func $i "transform")))
                (export "transform" (func $transform)))
        "#
    }

    fn component_transform_with_memory() -> &'static str {
        r#"
            (component
                (core module $m
                    (memory 1)
                    (func (export "transform") (param i32) (result i32)
                        local.get 0))
                (core instance $i (instantiate $m))
                (func $transform (param "value" s32) (result s32)
                    (canon lift (core func $i "transform")))
                (export "transform" (func $transform)))
        "#
    }

    fn component_transform_with_two_instances() -> &'static str {
        r#"
            (component
                (core module $m
                    (func (export "transform") (param i32) (result i32)
                        local.get 0))
                (core instance $i (instantiate $m))
                (core instance $extra (instantiate $m))
                (func $transform (param "value" s32) (result s32)
                    (canon lift (core func $i "transform")))
                (export "transform" (func $transform)))
        "#
    }

    fn context(
        world: CapabilityWorld,
        operation: &str,
        resource_scope: &str,
        approval_class: ApprovalClass,
        envelope_authority: AuthorityClass,
        required_authority: AuthorityClass,
    ) -> ComponentExecutionContext {
        ComponentExecutionContext {
            capability_envelope: CapabilityEnvelope {
                envelope_id: "envelope-component-test".to_string(),
                actor_scope: "component-test".to_string(),
                world_grants: vec![CapabilityWorldGrant {
                    world: world.clone(),
                    allowed_operations: vec![operation.to_string()],
                    default_authority_class: required_authority.clone(),
                    default_approval_class: approval_class,
                    operation_approval_overrides: Vec::new(),
                }],
                authority_ceiling: envelope_authority,
                isolation_profile: IsolationProfile::ArtifactSandbox,
                allowed_resource_scopes: vec![resource_scope.to_string()],
                approval_overrides: Vec::new(),
                quota_policy: None,
                campaign_scope: None,
                epoch_scope: None,
            },
            import_bindings: vec![ComponentImportBinding {
                import_name: "host-pulse".to_string(),
                world,
                operation: operation.to_string(),
                resource_scope: resource_scope.to_string(),
                required_authority_class: required_authority,
            }],
        }
    }

    fn approved_context() -> ComponentExecutionContext {
        context(
            CapabilityWorld::ServiceOrganelle,
            "pulse",
            "scope:host-pulse",
            ApprovalClass::AutoAllowed,
            AuthorityClass::Observe,
            AuthorityClass::Observe,
        )
    }

    struct RecordingEffectHandler {
        calls: Arc<AtomicUsize>,
        wrong_import: bool,
        terminal_success: bool,
    }

    impl ComponentImportEffectHandler for RecordingEffectHandler {
        fn invoke(
            &self,
            binding: &ComponentImportBinding,
        ) -> Result<ComponentImportEffectReceipt, String> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let binding_bytes = serde_json::to_vec(binding).expect("serialize test binding");
            Ok(ComponentImportEffectReceipt {
                import_name: if self.wrong_import {
                    "another-import".to_string()
                } else {
                    binding.import_name.clone()
                },
                binding_digest: ContentDigest::from_bytes(&binding_bytes),
                service_id: "test.effect-owner.v1".to_string(),
                invocation_id: "invocation:component-import".to_string(),
                implementation_digest: ContentDigest::from_bytes(b"implementation"),
                input_digest: ContentDigest::from_bytes(b"input"),
                output_digest: ContentDigest::from_bytes(b"output"),
                receipt_digest: ContentDigest::from_bytes(b"receipt"),
                attestation_digest: ContentDigest::from_bytes(b"attestation"),
                terminal_success: self.terminal_success,
            })
        }
    }

    #[test]
    fn rejects_invalid_wit() {
        let error = build_component_package(request("not valid wit", component_run()))
            .expect_err("invalid WIT must be rejected");
        assert!(matches!(error, ComponentBuildError::WitParse(_)));
    }

    #[test]
    fn rejects_invalid_component_bytes() {
        let error = inspect_component_bytes(
            b"not wasm",
            "aiaf-supervisor-v3",
            vec!["world:test".to_string()],
        )
        .expect_err("invalid component bytes must be rejected");
        assert!(matches!(error, ComponentBuildError::WasmParse(_)));
    }

    #[test]
    fn rejects_core_wasm_when_component_is_required() {
        let error = build_component_package(request(wit_run(), "(module)"))
            .expect_err("core wasm module must be rejected");
        assert_eq!(error, ComponentBuildError::CoreWasmModuleRejected);
    }

    #[test]
    fn rejects_wit_component_export_mismatch() {
        let component = r#"
            (component
                (core module $m
                    (func (export "other")))
                (core instance $i (instantiate $m))
                (func $other (canon lift (core func $i "other")))
                (export "other" (func $other)))
        "#;
        let error = build_component_package(request(wit_run(), component))
            .expect_err("mismatched component exports must be rejected");
        assert!(matches!(
            error,
            ComponentBuildError::ComponentExportMismatch { .. }
        ));
    }

    #[test]
    fn build_accepts_matching_wit_and_component_imports() {
        let build = build_component_package(request(wit_import_run(), component_import_run()))
            .expect("matching WIT/component imports should build");
        assert_eq!(
            build.package_manifest.interface_imports,
            vec!["host-pulse".to_string()]
        );
        assert!(build.inspection.executable);
    }

    #[test]
    fn rejects_wit_component_import_mismatch() {
        let error = build_component_package(request(wit_import_run(), component_run()))
            .expect_err("mismatched imports must be rejected");
        assert!(matches!(
            error,
            ComponentBuildError::ComponentImportMismatch { .. }
        ));
    }

    #[test]
    fn executes_capability_bound_import() {
        let build = build_component_package(request(wit_import_run(), component_import_run()))
            .expect("matching import package should build");
        let execution = execute_component_export_with_context(
            &build.component_bytes,
            "run",
            &approved_context(),
        )
        .expect("approved import should link and execute");
        assert_eq!(execution.import_link_audits.len(), 1);
        assert_eq!(execution.import_link_audits[0].import_name, "host-pulse");
        assert!(execution.import_link_audits[0].linked);
    }

    #[test]
    fn effectful_component_import_requires_and_returns_owner_evidence() {
        let build = build_component_package(request(wit_import_run(), component_import_run()))
            .expect("matching import package should build");
        let calls = Arc::new(AtomicUsize::new(0));
        let execution = execute_component_export_with_effects(
            &build.component_bytes,
            "run",
            &approved_context(),
            Arc::new(RecordingEffectHandler {
                calls: Arc::clone(&calls),
                wrong_import: false,
                terminal_success: true,
            }),
        )
        .expect("effect owner should execute");

        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(execution.execution.invoked_imports, ["host-pulse"]);
        assert_eq!(execution.effects.len(), 1);
        assert_eq!(execution.effects[0].service_id, "test.effect-owner.v1");
        assert!(execution.effects[0].terminal_success);
    }

    #[test]
    fn effectful_component_import_traps_on_failed_or_mismatched_evidence() {
        let build = build_component_package(request(wit_import_run(), component_import_run()))
            .expect("matching import package should build");
        for (wrong_import, terminal_success) in [(false, false), (true, true)] {
            let error = execute_component_export_with_effects(
                &build.component_bytes,
                "run",
                &approved_context(),
                Arc::new(RecordingEffectHandler {
                    calls: Arc::new(AtomicUsize::new(0)),
                    wrong_import,
                    terminal_success,
                }),
            )
            .expect_err("invalid effect evidence must trap");
            assert!(matches!(error, ComponentBuildError::Wasmtime(_)));
        }
    }

    #[test]
    fn rejects_unbound_component_imports() {
        let build = build_component_package(request(wit_import_run(), component_import_run()))
            .expect("matching import package should build");
        let mut context = approved_context();
        context.import_bindings.clear();
        let error = execute_component_export_with_context(&build.component_bytes, "run", &context)
            .expect_err("unbound import must be rejected");
        assert_eq!(
            error,
            ComponentBuildError::UnboundComponentImport {
                import_name: "host-pulse".to_string()
            }
        );
    }

    #[test]
    fn rejects_unused_import_bindings() {
        let build = build_component_package(request(wit_import_run(), component_import_run()))
            .expect("matching import package should build");
        let mut context = approved_context();
        context.import_bindings.push(ComponentImportBinding {
            import_name: "unused".to_string(),
            world: CapabilityWorld::ServiceOrganelle,
            operation: "pulse".to_string(),
            resource_scope: "scope:host-pulse".to_string(),
            required_authority_class: AuthorityClass::Observe,
        });
        let error = execute_component_export_with_context(&build.component_bytes, "run", &context)
            .expect_err("unused import binding must be rejected");
        assert_eq!(
            error,
            ComponentBuildError::UnusedImportBinding {
                import_name: "unused".to_string()
            }
        );
    }

    #[test]
    fn rejects_wrong_import_capability_world() {
        let build = build_component_package(request(wit_import_run(), component_import_run()))
            .expect("matching import package should build");
        let mut context = approved_context();
        context.import_bindings[0].world = CapabilityWorld::MemoryAccess;
        let error = execute_component_export_with_context(&build.component_bytes, "run", &context)
            .expect_err("wrong import world must be rejected");
        assert!(matches!(
            error,
            ComponentBuildError::ImportCapabilityWorldMissing { .. }
        ));
    }

    #[test]
    fn rejects_missing_import_operation() {
        let build = build_component_package(request(wit_import_run(), component_import_run()))
            .expect("matching import package should build");
        let mut context = approved_context();
        context.import_bindings[0].operation = "other".to_string();
        let error = execute_component_export_with_context(&build.component_bytes, "run", &context)
            .expect_err("missing operation must be rejected");
        assert!(matches!(
            error,
            ComponentBuildError::ImportOperationNotAllowed { .. }
        ));
    }

    #[test]
    fn rejects_disallowed_import_scope() {
        let build = build_component_package(request(wit_import_run(), component_import_run()))
            .expect("matching import package should build");
        let mut context = approved_context();
        context.import_bindings[0].resource_scope = "scope:other".to_string();
        let error = execute_component_export_with_context(&build.component_bytes, "run", &context)
            .expect_err("disallowed scope must be rejected");
        assert!(matches!(
            error,
            ComponentBuildError::ImportResourceScopeNotAllowed { .. }
        ));
    }

    #[test]
    fn rejects_insufficient_import_authority() {
        let build = build_component_package(request(wit_import_run(), component_import_run()))
            .expect("matching import package should build");
        let context = context(
            CapabilityWorld::ServiceOrganelle,
            "pulse",
            "scope:host-pulse",
            ApprovalClass::AutoAllowed,
            AuthorityClass::Observe,
            AuthorityClass::LocalMutate,
        );
        let error = execute_component_export_with_context(&build.component_bytes, "run", &context)
            .expect_err("insufficient authority must be rejected");
        assert!(matches!(
            error,
            ComponentBuildError::ImportAuthorityExceedsEnvelope { .. }
        ));
    }

    #[test]
    fn rejects_blocking_import_approval_classes() {
        let build = build_component_package(request(wit_import_run(), component_import_run()))
            .expect("matching import package should build");
        for approval_class in [
            ApprovalClass::HumanRequired,
            ApprovalClass::QuarantineOnExpand,
            ApprovalClass::Forbidden,
        ] {
            let context = context(
                CapabilityWorld::ServiceOrganelle,
                "pulse",
                "scope:host-pulse",
                approval_class,
                AuthorityClass::Observe,
                AuthorityClass::Observe,
            );
            let error =
                execute_component_export_with_context(&build.component_bytes, "run", &context)
                    .expect_err("blocking approval class must be rejected");
            assert!(matches!(
                error,
                ComponentBuildError::ImportApprovalBlocked { .. }
            ));
        }
    }

    #[test]
    fn executes_import_free_run_export() {
        let build = build_component_package(request(wit_run(), component_run())).unwrap();
        let execution = execute_component_export(&build.component_bytes, "run").unwrap();
        assert_eq!(
            execution.result_ref,
            component_success_result_ref(&build.component_bytes, "run")
        );
        assert!(!execution.trapped);
    }

    #[test]
    fn executes_bounded_i32_transform_with_exact_trace() {
        let build =
            build_component_package(request(wit_transform(), component_transform_add_one()))
                .expect("typed transform component should build");
        let limits = ComponentExecutionLimits::default();
        let execution =
            execute_component_i32_export(&build.component_bytes, "transform", 41, &limits)
                .expect("typed transform should execute");

        assert_eq!(
            execution.component_digest,
            ContentDigest::from_bytes(&build.component_bytes)
        );
        assert_eq!(execution.export_name, "transform");
        assert_eq!(execution.input, 41);
        assert_eq!(execution.output, Some(42));
        assert!(!execution.trapped);
        assert_eq!(execution.failure_phase, None);
        assert_eq!(execution.limit_exhausted, None);
        assert_eq!(execution.limits, limits);
        assert!(execution.fuel_consumed > 0);
        assert!(execution.invoked_imports.is_empty());
    }

    #[test]
    fn records_guest_trap_without_misclassifying_a_limit() {
        let component_bytes = wat::parse_str(component_transform_trap()).unwrap();
        let execution = execute_component_i32_export(
            &component_bytes,
            "transform",
            7,
            &ComponentExecutionLimits::default(),
        )
        .expect("guest trap should be represented by a trace");

        assert_eq!(execution.input, 7);
        assert_eq!(execution.output, None);
        assert!(execution.trapped);
        assert_eq!(
            execution.failure_phase,
            Some(ComponentExecutionFailurePhase::Invocation)
        );
        assert_eq!(execution.limit_exhausted, None);
        assert!(
            execution
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.contains("unreachable"))
        );
    }

    #[test]
    fn terminates_infinite_transform_at_fuel_limit() {
        let component_bytes = wat::parse_str(component_transform_forever()).unwrap();
        let limits = ComponentExecutionLimits {
            fuel: 50,
            ..ComponentExecutionLimits::default()
        };
        let execution = execute_component_i32_export(&component_bytes, "transform", 7, &limits)
            .expect("fuel exhaustion should be represented by a trace");

        assert!(execution.trapped);
        assert_eq!(execution.output, None);
        assert_eq!(
            execution.failure_phase,
            Some(ComponentExecutionFailurePhase::Invocation)
        );
        assert_eq!(
            execution.limit_exhausted,
            Some(ComponentExecutionLimitKind::Fuel)
        );
        assert_eq!(execution.fuel_consumed, limits.fuel);
        assert!(
            execution
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.contains("Fuel"))
        );
    }

    #[test]
    fn refuses_component_above_linear_memory_limit() {
        let component_bytes = wat::parse_str(component_transform_with_memory()).unwrap();
        let limits = ComponentExecutionLimits {
            max_memory_bytes: 32 * 1024,
            ..ComponentExecutionLimits::default()
        };
        let execution = execute_component_i32_export(&component_bytes, "transform", 7, &limits)
            .expect("memory refusal should be represented by a trace");

        assert!(execution.trapped);
        assert_eq!(execution.output, None);
        assert_eq!(
            execution.failure_phase,
            Some(ComponentExecutionFailurePhase::Instantiation)
        );
        assert_eq!(
            execution.limit_exhausted,
            Some(ComponentExecutionLimitKind::LinearMemory)
        );
        assert!(
            execution
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.contains("LinearMemory"))
        );
    }

    #[test]
    fn refuses_component_above_store_instance_limit() {
        let component_bytes = wat::parse_str(component_transform_with_two_instances()).unwrap();
        let limits = ComponentExecutionLimits {
            max_instances: 1,
            ..ComponentExecutionLimits::default()
        };
        let execution = execute_component_i32_export(&component_bytes, "transform", 7, &limits)
            .expect("instance refusal should be represented by a trace");

        assert!(execution.trapped);
        assert_eq!(execution.output, None);
        assert_eq!(
            execution.failure_phase,
            Some(ComponentExecutionFailurePhase::Instantiation)
        );
        assert_eq!(
            execution.limit_exhausted,
            Some(ComponentExecutionLimitKind::StoreResources)
        );
    }

    #[test]
    fn rejects_zero_typed_execution_limits() {
        for limits in [
            ComponentExecutionLimits {
                fuel: 0,
                ..ComponentExecutionLimits::default()
            },
            ComponentExecutionLimits {
                max_memory_bytes: 0,
                ..ComponentExecutionLimits::default()
            },
            ComponentExecutionLimits {
                max_instances: 0,
                ..ComponentExecutionLimits::default()
            },
        ] {
            let component_bytes = wat::parse_str(component_transform_add_one()).unwrap();
            let error = execute_component_i32_export(&component_bytes, "transform", 7, &limits)
                .expect_err("zero execution limits must be rejected");
            assert!(matches!(
                error,
                ComponentBuildError::InvalidExecutionLimit { .. }
            ));
        }
    }
}
