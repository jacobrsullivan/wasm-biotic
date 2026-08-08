fn main() {
    if let Err(error) = wasm_biotic_component_graph_package::run_from_env() {
        eprintln!("component graph packaging failed: {error}");
        std::process::exit(1);
    }
}
