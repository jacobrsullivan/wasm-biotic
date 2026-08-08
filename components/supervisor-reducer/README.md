# Supervisor Reducer Component

This is the first production-shaped control-plane component for the
component-complete Wasm-Biotic architecture. It implements
`wasm-biotic:factory/supervisor-reducer@0.1.0` in the
`supervisor-reducer-component` world.

The component has no callable, resource or substrate imports. Its complete
operation is a pure, deterministic reduction:

```text
versioned JSON state + graph digest + sequenced event
    -> versioned JSON state + declarative supervisor commands
```

The initial bounded policy accepts job submission and worker-completion events.
It drives the fixed six-role chain:

```text
planner -> builder -> validator -> reviewer -> packager -> continuity-worker
```

Each transition checks the event sequence, active execution identity and exact
worker component digest. Duplicate job submissions and byte-identical duplicate
worker completions are deterministic no-ops. Unsupported events, skipped event
sequences, conflicting duplicate completions and mismatched worker identities
fail closed.

The versioned state binds all six workers and all seven capability-service
families to component digests. A dispatch contains only the service bindings
required by that stage: build plus scheduling for the planner, then build,
validation, review, packaging and continuity respectively. The reducer never
selects a native service implementation.

The component references the canonical WIT package at
`../../wit/wasm-biotic/`; it does not carry a divergent copy.

Build and test from this directory:

```sh
cargo test
cargo build --release --target wasm32-wasip2
cargo run --example smoke -- \
  target/wasm32-wasip2/release/wasm_biotic_supervisor_reducer.wasm
```

The release component is emitted as
`target/wasm32-wasip2/release/wasm_biotic_supervisor_reducer.wasm`.

## Verified artifact

The 2026-08-02 release build was produced with:

```sh
CARGO_TARGET_DIR=/tmp/aiaf-supervisor-component-target \
  cargo build --release --target wasm32-wasip2
```

- Size: `265517` bytes.
- SHA-256: `11b8aa804928fda544d98c8daff3e6e91af12f04c030939731c94a6a43fa996e`.
- Encoding: WebAssembly Component Model.
- Export: `wasm-biotic:factory/supervisor-reducer@0.1.0`.
- Callable/resource imports: none.
- WASI imports: none.
- Declarative type-instance imports: `foundation`, `capability-contract`, and a
  pruned `worker-workflow`. Inspection confirmed these instances expose only
  shared value types—no functions or resources—so they confer no effect
  authority.

The Wasmtime smoke host instantiated those exact bytes with an empty linker and
executed a real `job-submitted` reduction. It returned one planner-dispatch
command and decision digest
`b5a78de697e56738c978a6d0e32438099100671e6a4056c3e1e5da752ecf9cab`.

## no-std boundary

The wasm build is `no_std` so Rust does not introduce implicit WASI CLI, I/O,
clock or environment imports. `dlmalloc` supplies private component memory.
Two wasm-only unsafe ABI shims are required: Canonical ABI `cabi_realloc` and
the `memcmp` symbol emitted by `core`. Both are locally implemented, documented
and compiled with `deny(unsafe_op_in_unsafe_fn)`. Consequently a crate-wide
`forbid(unsafe_code)` is not compatible with the zero-WASI `wasm32-wasip2`
build; no policy path itself uses unsafe code.
