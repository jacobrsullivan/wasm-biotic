#![cfg_attr(all(target_arch = "wasm32", not(test)), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

//! Component-owned, deterministic state-schema migration.

extern crate alloc;

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};

/// Current supervisor state schema.
pub const CURRENT_SCHEMA: &str = "wasm-biotic.supervisor-state.v1";
/// The only predecessor accepted by this migration component.
pub const PREVIOUS_SCHEMA: &str = "wasm-biotic.supervisor-state.v0";
/// Canonical state media type.
pub const JSON_MEDIA_TYPE: &str = "application/json";
/// Canonical graph schema interpreted by the migration component.
pub const FACTORY_GRAPH_SCHEMA: &str = "wasm-biotic.factory-graph.v1";
/// Canonical WIT package for the bounded component-complete graph.
pub const FACTORY_WIT_PACKAGE: &str = "wasm-biotic:factory@0.1.0";
/// Media type used for admitted canonical graph manifests.
pub const FACTORY_GRAPH_MEDIA_TYPE: &str = "application/vnd.wasm-biotic.graph+json";

const WORKER_BINDINGS: [(&str, &str); 6] = [
    ("planner", "planner-worker"),
    ("builder", "builder-worker"),
    ("validator", "validator-worker"),
    ("reviewer", "reviewer-worker"),
    ("packager", "packager-worker"),
    ("continuity-worker", "continuity-worker"),
];

const SERVICE_BINDINGS: [(&str, &str); 7] = [
    ("build", "build-service"),
    ("packaging", "packaging-service"),
    ("validation", "validation-service"),
    ("review", "review-service"),
    ("continuity", "continuity-service"),
    ("scheduling", "scheduling-service"),
    ("operations", "operations-service"),
];

type ComponentBindingMaps = (Map<String, Value>, Map<String, Value>);

/// A policy failure returned without host interpretation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationError {
    /// Stable machine code.
    pub code: String,
    /// Human-readable context.
    pub message: String,
}

impl MigrationError {
    fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

impl core::fmt::Display for MigrationError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl core::error::Error for MigrationError {}

/// Migrates exact JSON bytes from `source_schema` into canonical v1 bytes.
///
/// The transformation is deterministic and has no substrate access.
pub fn migrate_policy(source_schema: &str, body: &[u8]) -> Result<Vec<u8>, MigrationError> {
    let value: Value = serde_json::from_slice(body).map_err(|error| {
        MigrationError::new("invalid-state-json", format!("state is not JSON: {error}"))
    })?;
    let mut object = match value {
        Value::Object(object) => object,
        _ => {
            return Err(MigrationError::new(
                "invalid-state-shape",
                "supervisor state must be a JSON object",
            ));
        }
    };

    let embedded_schema = object
        .get("schema")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            MigrationError::new("missing-state-schema", "state.schema must be a string")
        })?;
    if embedded_schema != source_schema {
        return Err(MigrationError::new(
            "state-schema-mismatch",
            format!("document declares {source_schema}, body declares {embedded_schema}"),
        ));
    }

    match source_schema {
        CURRENT_SCHEMA => validate_current(&object)?,
        PREVIOUS_SCHEMA => migrate_v0(&mut object)?,
        other => {
            return Err(MigrationError::new(
                "unsupported-state-schema",
                format!("no migration from {other} to {CURRENT_SCHEMA}"),
            ));
        }
    }

    serde_json::to_vec(&Value::Object(object)).map_err(|error| {
        MigrationError::new(
            "state-serialization-failed",
            format!("cannot encode migrated state: {error}"),
        )
    })
}

/// Migrates state and rebinds every role/service identity to one exact
/// content-addressed successor manifest. The native substrate passes bytes and
/// enforces their digest; all graph meaning remains in this component policy.
pub fn migrate_to_graph_policy(
    source_schema: &str,
    body: &[u8],
    target_graph_hex: &str,
    target_manifest: &[u8],
) -> Result<Vec<u8>, MigrationError> {
    validate_hex("target_graph", target_graph_hex)?;
    let actual_target = sha256_hex(target_manifest);
    if actual_target != target_graph_hex {
        return Err(MigrationError::new(
            "target-manifest-digest-mismatch",
            "target manifest bytes do not match the declared graph digest",
        ));
    }

    let migrated = migrate_policy(source_schema, body)?;
    let mut state = match serde_json::from_slice::<Value>(&migrated).map_err(|error| {
        MigrationError::new(
            "invalid-migrated-state-json",
            format!("migrated state is not JSON: {error}"),
        )
    })? {
        Value::Object(object) => object,
        _ => {
            return Err(MigrationError::new(
                "invalid-state-shape",
                "migrated supervisor state must be a JSON object",
            ));
        }
    };
    let previous_graph =
        digest_hex_from_value(state.get("graph_digest"), "migrated_state.graph_digest")?;
    let (workers, services) = target_bindings(target_manifest, &previous_graph, target_graph_hex)?;

    state.insert("graph_digest".to_string(), digest_value(target_graph_hex));
    state.insert("worker_components".to_string(), Value::Object(workers));
    state.insert("service_components".to_string(), Value::Object(services));
    validate_current(&state)?;
    serde_json::to_vec(&Value::Object(state)).map_err(|error| {
        MigrationError::new(
            "state-serialization-failed",
            format!("cannot encode graph-bound migrated state: {error}"),
        )
    })
}

fn target_bindings(
    target_manifest: &[u8],
    previous_graph_hex: &str,
    target_graph_hex: &str,
) -> Result<ComponentBindingMaps, MigrationError> {
    let manifest: Value = serde_json::from_slice(target_manifest).map_err(|error| {
        MigrationError::new(
            "invalid-target-manifest-json",
            format!("target manifest is not JSON: {error}"),
        )
    })?;
    let object = manifest.as_object().ok_or_else(|| {
        MigrationError::new(
            "invalid-target-manifest-shape",
            "target manifest must be a JSON object",
        )
    })?;
    if object.get("schema").and_then(Value::as_str) != Some(FACTORY_GRAPH_SCHEMA)
        || object.get("wit_package").and_then(Value::as_str) != Some(FACTORY_WIT_PACKAGE)
        || object.get("state_schema").and_then(Value::as_str) != Some(CURRENT_SCHEMA)
    {
        return Err(MigrationError::new(
            "unsupported-target-manifest",
            "target must be the bounded factory graph and supervisor state schema",
        ));
    }
    if target_graph_hex != previous_graph_hex {
        let expected_previous = format!("sha256:{previous_graph_hex}");
        if object.get("previous_graph").and_then(Value::as_str) != Some(expected_previous.as_str())
        {
            return Err(MigrationError::new(
                "successor-lineage-mismatch",
                "target manifest does not name the current state graph as its predecessor",
            ));
        }
    }
    let nodes = object
        .get("nodes")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            MigrationError::new(
                "invalid-target-manifest-nodes",
                "target manifest nodes must be an array",
            )
        })?;
    let collect = |expected: &[(&str, &str)]| -> Result<Map<String, Value>, MigrationError> {
        let mut result = Map::new();
        for (name, kind) in expected {
            let matches = nodes
                .iter()
                .filter(|node| node.get("kind").and_then(Value::as_str) == Some(*kind))
                .collect::<Vec<_>>();
            if matches.len() != 1 {
                return Err(MigrationError::new(
                    "incomplete-target-component-bindings",
                    format!("target manifest must contain exactly one {kind}"),
                ));
            }
            let content_digest = matches[0]
                .get("component_digest")
                .and_then(Value::as_str)
                .and_then(|value| value.strip_prefix("sha256:"))
                .ok_or_else(|| {
                    MigrationError::new(
                        "invalid-target-component-digest",
                        format!("target {kind} component digest is not SHA-256"),
                    )
                })?;
            validate_hex(&format!("target.{kind}.component_digest"), content_digest)?;
            result.insert((*name).to_string(), digest_value(content_digest));
        }
        Ok(result)
    };
    Ok((collect(&WORKER_BINDINGS)?, collect(&SERVICE_BINDINGS)?))
}

fn digest_hex_from_value(value: Option<&Value>, field: &str) -> Result<String, MigrationError> {
    let digest = value.and_then(Value::as_object).ok_or_else(|| {
        MigrationError::new("invalid-state-field", format!("{field} must be a digest"))
    })?;
    if digest.get("algorithm").and_then(Value::as_str) != Some("sha256") {
        return Err(MigrationError::new(
            "invalid-state-field",
            format!("{field}.algorithm must be sha256"),
        ));
    }
    let hex = digest.get("hex").and_then(Value::as_str).ok_or_else(|| {
        MigrationError::new(
            "invalid-state-field",
            format!("{field}.hex must be a string"),
        )
    })?;
    validate_hex(field, hex)?;
    Ok(hex.to_string())
}

fn digest_value(hex: &str) -> Value {
    let mut digest = Map::new();
    digest.insert("algorithm".to_string(), Value::String("sha256".to_string()));
    digest.insert("hex".to_string(), Value::String(hex.to_string()));
    Value::Object(digest)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in digest {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn validate_current(object: &Map<String, Value>) -> Result<(), MigrationError> {
    require_exact_fields(
        object,
        &[
            "schema",
            "graph_digest",
            "last_event_sequence",
            "worker_components",
            "service_components",
            "jobs",
            "active_executions",
            "completed_executions",
        ],
    )?;
    require_digest(object, "graph_digest")?;
    require_u64(object, "last_event_sequence")?;
    require_exact_digest_map(
        object,
        "worker_components",
        &[
            "builder",
            "continuity-worker",
            "packager",
            "planner",
            "reviewer",
            "validator",
        ],
    )?;
    require_exact_digest_map(
        object,
        "service_components",
        &[
            "build",
            "continuity",
            "operations",
            "packaging",
            "review",
            "scheduling",
            "validation",
        ],
    )?;
    for field in ["jobs", "active_executions", "completed_executions"] {
        require_object(object, field)?;
    }
    Ok(())
}

fn migrate_v0(object: &mut Map<String, Value>) -> Result<(), MigrationError> {
    require_exact_fields(
        object,
        &[
            "schema",
            "graph_digest",
            "sequence",
            "worker_components",
            "service_components",
            "jobs",
            "active_executions",
            "completed_executions",
        ],
    )?;
    let legacy_graph = object.remove("graph_digest").ok_or_else(|| {
        MigrationError::new("missing-state-field", "v0 state requires graph_digest")
    })?;
    let graph_hex = legacy_graph.as_str().ok_or_else(|| {
        MigrationError::new("invalid-state-field", "v0 graph_digest must be SHA-256 hex")
    })?;
    validate_hex("graph_digest", graph_hex)?;
    let sequence = object
        .remove("sequence")
        .ok_or_else(|| MigrationError::new("missing-state-field", "v0 state requires sequence"))?;
    if sequence.as_u64().is_none() {
        return Err(MigrationError::new(
            "invalid-state-field",
            "sequence must be u64",
        ));
    }
    object.insert(
        "schema".to_string(),
        Value::String(CURRENT_SCHEMA.to_string()),
    );
    let mut digest = Map::new();
    digest.insert("algorithm".to_string(), Value::String("sha256".to_string()));
    digest.insert("hex".to_string(), Value::String(graph_hex.to_string()));
    object.insert("graph_digest".to_string(), Value::Object(digest));
    object.insert("last_event_sequence".to_string(), sequence);
    require_exact_digest_map(
        object,
        "worker_components",
        &[
            "builder",
            "continuity-worker",
            "packager",
            "planner",
            "reviewer",
            "validator",
        ],
    )?;
    require_exact_digest_map(
        object,
        "service_components",
        &[
            "build",
            "continuity",
            "operations",
            "packaging",
            "review",
            "scheduling",
            "validation",
        ],
    )?;
    for field in ["jobs", "active_executions", "completed_executions"] {
        object
            .entry(field.to_string())
            .or_insert_with(|| Value::Object(Map::new()));
        require_object(object, field)?;
    }
    Ok(())
}

fn require_exact_fields(
    object: &Map<String, Value>,
    expected: &[&str],
) -> Result<(), MigrationError> {
    if object.len() != expected.len() || expected.iter().any(|field| !object.contains_key(*field)) {
        return Err(MigrationError::new(
            "unexpected-state-fields",
            "state document must contain exactly the declared schema fields",
        ));
    }
    Ok(())
}

fn require_digest(object: &Map<String, Value>, field: &'static str) -> Result<(), MigrationError> {
    let Some(Value::Object(digest)) = object.get(field) else {
        return Err(MigrationError::new(
            "invalid-state-field",
            format!("{field} must be a digest object"),
        ));
    };
    if digest.get("algorithm").and_then(Value::as_str) != Some("sha256") {
        return Err(MigrationError::new(
            "invalid-state-field",
            format!("{field}.algorithm must be sha256"),
        ));
    }
    let hex = digest.get("hex").and_then(Value::as_str).ok_or_else(|| {
        MigrationError::new(
            "invalid-state-field",
            format!("{field}.hex must be a string"),
        )
    })?;
    validate_hex(field, hex)
}

fn validate_hex(field: &str, hex: &str) -> Result<(), MigrationError> {
    if hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(MigrationError::new(
            "invalid-state-field",
            format!("{field} must be lower-case SHA-256 hex"),
        ))
    }
}

fn require_u64(object: &Map<String, Value>, field: &'static str) -> Result<(), MigrationError> {
    match object.get(field).and_then(Value::as_u64) {
        Some(_) => Ok(()),
        None => Err(MigrationError::new(
            "invalid-state-field",
            format!("{field} must be u64"),
        )),
    }
}

fn require_object(object: &Map<String, Value>, field: &'static str) -> Result<(), MigrationError> {
    match object.get(field) {
        Some(Value::Object(_)) => Ok(()),
        _ => Err(MigrationError::new(
            "invalid-state-field",
            format!("{field} must be an object"),
        )),
    }
}

fn require_exact_digest_map(
    object: &Map<String, Value>,
    field: &'static str,
    expected_keys: &[&str],
) -> Result<(), MigrationError> {
    let Some(Value::Object(bindings)) = object.get(field) else {
        return Err(MigrationError::new(
            "invalid-state-field",
            format!("{field} must be an object"),
        ));
    };
    if bindings.len() != expected_keys.len()
        || expected_keys.iter().any(|key| !bindings.contains_key(*key))
    {
        return Err(MigrationError::new(
            "incomplete-component-bindings",
            format!("{field} must bind exactly its canonical component set"),
        ));
    }
    for key in expected_keys {
        let Some(Value::Object(digest)) = bindings.get(*key) else {
            return Err(MigrationError::new(
                "invalid-state-field",
                format!("{field}.{key} must be a digest object"),
            ));
        };
        if digest.get("algorithm").and_then(Value::as_str) != Some("sha256") {
            return Err(MigrationError::new(
                "invalid-state-field",
                format!("{field}.{key}.algorithm must be sha256"),
            ));
        }
        let hex = digest.get("hex").and_then(Value::as_str).ok_or_else(|| {
            MigrationError::new(
                "invalid-state-field",
                format!("{field}.{key}.hex must be a string"),
            )
        })?;
        validate_hex(&format!("{field}.{key}"), hex)?;
    }
    Ok(())
}

#[cfg(all(target_arch = "wasm32", not(test)))]
#[global_allocator]
static ALLOCATOR: dlmalloc::GlobalDlmalloc = dlmalloc::GlobalDlmalloc;

#[cfg(all(target_arch = "wasm32", not(test)))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}

#[cfg(all(target_arch = "wasm32", not(test)))]
#[unsafe(no_mangle)]
unsafe extern "C" fn cabi_realloc(
    old_pointer: *mut u8,
    old_length: usize,
    alignment: usize,
    new_length: usize,
) -> *mut u8 {
    use alloc::alloc::{Layout, alloc, dealloc, handle_alloc_error, realloc};
    let alignment = alignment.max(1);
    if old_pointer.is_null() {
        if new_length == 0 {
            return core::ptr::null_mut();
        }
        let layout = Layout::from_size_align(new_length, alignment)
            .unwrap_or_else(|_| core::arch::wasm32::unreachable());
        let pointer = unsafe { alloc(layout) };
        if pointer.is_null() {
            handle_alloc_error(layout);
        }
        pointer
    } else {
        let old_layout = Layout::from_size_align(old_length.max(1), alignment)
            .unwrap_or_else(|_| core::arch::wasm32::unreachable());
        if new_length == 0 {
            unsafe { dealloc(old_pointer, old_layout) };
            core::ptr::null_mut()
        } else {
            let pointer = unsafe { realloc(old_pointer, old_layout, new_length) };
            if pointer.is_null() {
                let layout = Layout::from_size_align(new_length, alignment)
                    .unwrap_or_else(|_| core::arch::wasm32::unreachable());
                handle_alloc_error(layout);
            }
            pointer
        }
    }
}

#[cfg(all(target_arch = "wasm32", not(test)))]
#[unsafe(no_mangle)]
unsafe extern "C" fn memcmp(left: *const u8, right: *const u8, length: usize) -> i32 {
    for offset in 0..length {
        let left_byte = unsafe { *left.add(offset) };
        let right_byte = unsafe { *right.add(offset) };
        if left_byte != right_byte {
            return i32::from(left_byte) - i32::from(right_byte);
        }
    }
    0
}

#[cfg(target_arch = "wasm32")]
mod component {
    use super::*;

    wit_bindgen::generate!({
        path: "../../wit/wasm-biotic",
        world: "state-migration-component",
    });

    use exports::wasm_biotic::factory::component_task::Guest as TaskGuest;
    use exports::wasm_biotic::factory::state_migration::{
        Guest as MigrationGuest, StateMigrationRequest,
    };
    use wasm_biotic::factory::foundation::{BlobRef, Document, Failure, HashAlgorithm};

    struct StateMigrationComponent;

    impl MigrationGuest for StateMigrationComponent {
        fn migrate(request: StateMigrationRequest) -> Result<Document, Failure> {
            if request.previous_state.media_type != JSON_MEDIA_TYPE
                || request.target_manifest.media_type != FACTORY_GRAPH_MEDIA_TYPE
                || request.target_manifest.schema != FACTORY_GRAPH_SCHEMA
                || !matches!(request.target_graph.algorithm, HashAlgorithm::Sha256)
            {
                return Err(failure(
                    "unsupported-media-type",
                    "state and exact target manifest use unsupported schemas or media types",
                ));
            }
            let body = migrate_to_graph_policy(
                &request.previous_state.schema,
                &request.previous_state.body,
                &request.target_graph.hex,
                &request.target_manifest.body,
            )
            .map_err(policy_failure)?;
            Ok(Document {
                schema: CURRENT_SCHEMA.to_string(),
                media_type: JSON_MEDIA_TYPE.to_string(),
                body,
            })
        }
    }

    impl TaskGuest for StateMigrationComponent {
        fn run(input: BlobRef) -> Result<BlobRef, Failure> {
            let bytes = wasm_biotic::factory::blob_store::get(&input)?;
            let value: Value = serde_json::from_slice(&bytes).map_err(|error| {
                failure("invalid-state-json", format!("state is not JSON: {error}"))
            })?;
            let schema = value
                .get("schema")
                .and_then(Value::as_str)
                .ok_or_else(|| failure("missing-state-schema", "state.schema must be a string"))?;
            let output = migrate_policy(schema, &bytes).map_err(policy_failure)?;
            Ok(wasm_biotic::factory::blob_store::put(
                JSON_MEDIA_TYPE,
                &output,
            )?)
        }
    }

    fn policy_failure(error: MigrationError) -> Failure {
        failure(error.code, error.message)
    }

    fn failure(code: impl Into<String>, message: impl Into<String>) -> Failure {
        Failure {
            code: code.into(),
            message: message.into(),
            retryable: false,
            evidence: None,
        }
    }

    export!(StateMigrationComponent);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn current() -> Vec<u8> {
        let digest = serde_json::json!({"algorithm":"sha256","hex":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"});
        let workers = [
            "builder",
            "continuity-worker",
            "packager",
            "planner",
            "reviewer",
            "validator",
        ]
        .into_iter()
        .map(|key| (key.to_string(), digest.clone()))
        .collect::<Map<_, _>>();
        let services = [
            "build",
            "continuity",
            "operations",
            "packaging",
            "review",
            "scheduling",
            "validation",
        ]
        .into_iter()
        .map(|key| (key.to_string(), digest.clone()))
        .collect::<Map<_, _>>();
        serde_json::to_vec(&serde_json::json!({
            "schema": CURRENT_SCHEMA, "graph_digest": digest, "last_event_sequence": 2,
            "worker_components": workers, "service_components": services,
            "jobs": {}, "active_executions": {}, "completed_executions": {}
        }))
        .unwrap()
    }

    fn target_manifest(previous: Option<&str>) -> Vec<u8> {
        let kinds = WORKER_BINDINGS
            .iter()
            .chain(SERVICE_BINDINGS.iter())
            .enumerate()
            .map(|(index, (_, kind))| {
                let character = char::from_digit((index % 9 + 1) as u32, 10).unwrap();
                serde_json::json!({
                    "component_digest": format!("sha256:{}", core::iter::repeat_n(character, 64).collect::<String>()),
                    "exports": [format!("export-{index}")],
                    "grants": [],
                    "id": format!("node-{index}"),
                    "kind": kind,
                    "world": format!("world-{index}"),
                })
            })
            .collect::<Vec<_>>();
        let mut manifest = serde_json::json!({
            "bindings": [],
            "invocations": [],
            "nodes": kinds,
            "root_node": "node-0",
            "schema": FACTORY_GRAPH_SCHEMA,
            "state_schema": CURRENT_SCHEMA,
            "wit_package": FACTORY_WIT_PACKAGE,
        });
        if let Some(previous) = previous {
            manifest["previous_graph"] = Value::String(format!("sha256:{previous}"));
        }
        serde_json::to_vec(&manifest).unwrap()
    }

    #[test]
    fn current_state_is_canonical_and_idempotent() {
        let first = migrate_policy(CURRENT_SCHEMA, &current()).unwrap();
        let second = migrate_policy(CURRENT_SCHEMA, &first).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn v0_is_upgraded_without_host_policy() {
        let mut old: Value = serde_json::from_slice(&current()).unwrap();
        old["schema"] = Value::String(PREVIOUS_SCHEMA.to_string());
        old["graph_digest"] = Value::String(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        );
        old.as_object_mut().unwrap().remove("last_event_sequence");
        old["sequence"] = Value::from(7);
        let migrated = migrate_policy(PREVIOUS_SCHEMA, &serde_json::to_vec(&old).unwrap()).unwrap();
        let value: Value = serde_json::from_slice(&migrated).unwrap();
        assert_eq!(value["schema"], CURRENT_SCHEMA);
        assert_eq!(value["last_event_sequence"], 7);
        assert!(value["service_components"].is_object());
    }

    #[test]
    fn schema_mismatch_and_unknown_version_fail_closed() {
        assert_eq!(
            migrate_policy(PREVIOUS_SCHEMA, &current())
                .unwrap_err()
                .code,
            "state-schema-mismatch"
        );
        let unknown = br#"{"schema":"wasm-biotic.supervisor-state.v9"}"#;
        assert_eq!(
            migrate_policy("wasm-biotic.supervisor-state.v9", unknown)
                .unwrap_err()
                .code,
            "unsupported-state-schema"
        );
    }

    #[test]
    fn current_and_legacy_state_reject_unknown_semantic_fields() {
        let mut current: Value = serde_json::from_slice(&current()).unwrap();
        current["native_policy"] = Value::Bool(true);
        assert_eq!(
            migrate_policy(CURRENT_SCHEMA, &serde_json::to_vec(&current).unwrap())
                .unwrap_err()
                .code,
            "unexpected-state-fields"
        );

        current["schema"] = Value::String(PREVIOUS_SCHEMA.to_string());
        current["graph_digest"] = Value::String(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        );
        current
            .as_object_mut()
            .unwrap()
            .remove("last_event_sequence");
        current["sequence"] = Value::from(7);
        assert_eq!(
            migrate_policy(PREVIOUS_SCHEMA, &serde_json::to_vec(&current).unwrap())
                .unwrap_err()
                .code,
            "unexpected-state-fields"
        );
    }

    #[test]
    fn successor_migration_rebinds_graph_workers_and_services_in_component_policy() {
        let manifest = target_manifest(Some(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ));
        let target = sha256_hex(&manifest);
        let migrated = migrate_to_graph_policy(CURRENT_SCHEMA, &current(), &target, &manifest)
            .expect("component-owned successor migration");
        let value: Value = serde_json::from_slice(&migrated).unwrap();
        assert_eq!(value["graph_digest"]["hex"], target);
        let planner = WORKER_BINDINGS
            .iter()
            .position(|(name, _)| *name == "planner")
            .unwrap();
        let expected =
            core::iter::repeat_n(char::from_digit((planner % 9 + 1) as u32, 10).unwrap(), 64)
                .collect::<String>();
        assert_eq!(value["worker_components"]["planner"]["hex"], expected);
        assert_eq!(value["last_event_sequence"], 2);
    }

    #[test]
    fn target_digest_lineage_and_component_coverage_fail_closed() {
        let manifest = target_manifest(Some(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ));
        assert_eq!(
            migrate_to_graph_policy(
                CURRENT_SCHEMA,
                &current(),
                &core::iter::repeat_n('f', 64).collect::<String>(),
                &manifest,
            )
            .unwrap_err()
            .code,
            "target-manifest-digest-mismatch"
        );

        let wrong_lineage = target_manifest(Some(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ));
        assert_eq!(
            migrate_to_graph_policy(
                CURRENT_SCHEMA,
                &current(),
                &sha256_hex(&wrong_lineage),
                &wrong_lineage,
            )
            .unwrap_err()
            .code,
            "successor-lineage-mismatch"
        );

        let mut missing: Value = serde_json::from_slice(&manifest).unwrap();
        missing["nodes"].as_array_mut().unwrap().pop();
        let missing = serde_json::to_vec(&missing).unwrap();
        assert_eq!(
            migrate_to_graph_policy(CURRENT_SCHEMA, &current(), &sha256_hex(&missing), &missing,)
                .unwrap_err()
                .code,
            "incomplete-target-component-bindings"
        );
    }
}
