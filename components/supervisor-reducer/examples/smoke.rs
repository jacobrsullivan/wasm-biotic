//! Executes the compiled component through Wasmtime and its generated WIT host
//! bindings. Pass the release `.wasm` path as the sole argument.

use std::{collections::BTreeMap, path::PathBuf};
use wasm_biotic_supervisor_reducer::{
    DigestValue, ServiceFamilyValue, Stage, SupervisorStateV1,
};
use wasmtime::{Config, Engine, Store, component::{Component, Linker}};

wasmtime::component::bindgen!({
    path: "../../wit/wasm-biotic",
    world: "supervisor-reducer-component",
});

use exports::wasm_biotic::factory::supervisor_reducer::{
    ReductionRequest, SupervisorCommand, SupervisorEvent,
};
use wasm_biotic::factory::foundation::{BlobRef, Digest, Document, HashAlgorithm};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let component_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("usage: cargo run --example smoke -- <component.wasm>")?;

    let mut config = Config::new();
    config.wasm_component_model(true);
    let engine = Engine::new(&config)?;
    let component = Component::from_file(&engine, &component_path)?;
    let linker = Linker::<()>::new(&engine);
    let mut store = Store::new(&engine, ());
    let bindings = SupervisorReducerComponent::instantiate(&mut store, &component, &linker)?;

    let graph = pure_digest('a');
    let worker_components = Stage::ALL
        .into_iter()
        .zip(['1', '2', '3', '4', '5', '6'].into_iter().map(pure_digest))
        .collect::<BTreeMap<_, _>>();
    let service_components = ServiceFamilyValue::ALL
        .into_iter()
        .zip(
            ['7', '8', '9', '0', 'a', 'b', 'c']
                .into_iter()
                .map(pure_digest),
        )
        .collect::<BTreeMap<_, _>>();
    let state = SupervisorStateV1::empty(graph.clone(), worker_components, service_components)?;
    let source = BlobRef {
        content_digest: host_digest('b'),
        size_bytes: 16,
        media_type: "application/octet-stream".to_string(),
    };
    let request = ReductionRequest {
        graph_digest: host_digest('a'),
        state: Document {
            schema: wasm_biotic_supervisor_reducer::STATE_SCHEMA.to_string(),
            media_type: wasm_biotic_supervisor_reducer::JSON_MEDIA_TYPE.to_string(),
            body: state.to_json()?,
        },
        event_sequence: 1,
        event: SupervisorEvent::JobSubmitted(source),
    };

    let reduction = bindings
        .wasm_biotic_factory_supervisor_reducer()
        .call_reduce(&mut store, &request)?
        .map_err(|failure| format!("component rejected smoke event: {}: {}", failure.code, failure.message))?;
    assert_eq!(reduction.commands.len(), 1);
    assert!(matches!(
        &reduction.commands[0],
        SupervisorCommand::DispatchWorker(_)
    ));
    assert_ne!(reduction.next_state.body, request.state.body);
    println!(
        "executed {}: decision sha256:{}",
        component_path.display(),
        reduction.decision_digest.hex
    );
    Ok(())
}

fn pure_digest(character: char) -> DigestValue {
    DigestValue {
        algorithm: "sha256".to_string(),
        hex: std::iter::repeat_n(character, 64).collect(),
    }
}

fn host_digest(character: char) -> Digest {
    Digest {
        algorithm: HashAlgorithm::Sha256,
        hex: std::iter::repeat_n(character, 64).collect(),
    }
}
