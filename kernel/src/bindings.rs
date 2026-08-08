//! Generated Component Model bindings for the closed native boundary.

/// Bindings for the deployable graph root.
#[allow(missing_docs, unsafe_code)]
pub mod root {
    wasmtime::component::bindgen!({
        path: "../wit/wasm-biotic",
        world: "factory-root",
        additional_derives: [serde::Deserialize, serde::Serialize],
    });
}

/// Bindings for digest-selected tasks with the closed, grant-gated host set.
#[allow(missing_docs, unsafe_code)]
pub mod task {
    wasmtime::component::bindgen!({
        path: "../wit/wasm-biotic",
        world: "admitted-task-component",
        additional_derives: [serde::Deserialize, serde::Serialize],
    });
}
