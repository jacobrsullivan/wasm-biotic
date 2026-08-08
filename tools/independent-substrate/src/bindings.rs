//! Bindings generated directly from the release WIT contract.

#[allow(missing_docs, unsafe_code)]
pub mod root {
    wasmtime::component::bindgen!({
        path: "../../wit/wasm-biotic",
        world: "factory-root",
        additional_derives: [serde::Deserialize, serde::Serialize],
    });
}

#[allow(missing_docs, unsafe_code)]
pub mod task {
    wasmtime::component::bindgen!({
        path: "../../wit/wasm-biotic",
        world: "admitted-task-component",
        additional_derives: [serde::Deserialize, serde::Serialize],
    });
}
