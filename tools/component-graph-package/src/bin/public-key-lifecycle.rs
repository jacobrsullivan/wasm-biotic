fn main() {
    if let Err(error) = wasm_biotic_component_graph_package::run_public_key_lifecycle_from_env() {
        eprintln!("public-key lifecycle failed: {error}");
        std::process::exit(1);
    }
}
