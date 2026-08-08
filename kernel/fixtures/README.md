# Kernel component fixtures

These fixtures exercise the production-shaped generated WIT bindings. They are
test components, not members of a release graph.

- `root-component` exports `factory-control` and `factory-api`; it uses the
  normative blob-store import without WASI.
- `task-component` exports `component-task`; it reads and republishes an input
  blob through its explicitly granted blob-store import.
- `mechanism-task-component` exports the generic `admitted-task-component`
  world and exercises independently gated blob, transaction and clock imports.
- `adversarial-task-component` exports that same generic task world and
  deliberately traps, loops, exceeds bounds, forges references and attempts
  primitive-scope escapes. It is used only for fail-closed isolation evidence.

All four crates are `no_std` Component Model builds. Regenerate the checked-in exact
fixtures with the isolated toolchain:

```sh
CARGO_HOME=/tmp/wasmbiotic-cargo \
RUSTUP_HOME=/tmp/wasmbiotic-rustup \
CARGO_TARGET_DIR=/tmp/wasmbiotic-root-fixture-target \
cargo build --offline --release --target wasm32-wasip2 \
  --manifest-path kernel/fixtures/root-component/Cargo.toml

CARGO_HOME=/tmp/wasmbiotic-cargo \
RUSTUP_HOME=/tmp/wasmbiotic-rustup \
CARGO_TARGET_DIR=/tmp/wasmbiotic-task-fixture-target \
cargo build --offline --release --target wasm32-wasip2 \
  --manifest-path kernel/fixtures/task-component/Cargo.toml

CARGO_HOME=/tmp/wasmbiotic-cargo \
RUSTUP_HOME=/tmp/wasmbiotic-rustup \
CARGO_TARGET_DIR=/tmp/wasmbiotic-mechanism-task-fixture-target \
cargo build --offline --release --target wasm32-wasip2 \
  --manifest-path kernel/fixtures/mechanism-task-component/Cargo.toml

CARGO_HOME=/tmp/wasmbiotic-cargo \
RUSTUP_HOME=/tmp/wasmbiotic-rustup \
CARGO_TARGET_DIR=/tmp/wasmbiotic-adversarial-task-fixture-target \
cargo build --offline --release --target wasm32-wasip2 \
  --manifest-path kernel/fixtures/adversarial-task-component/Cargo.toml
```

The committed artifacts and digests are under `artifacts/`.
