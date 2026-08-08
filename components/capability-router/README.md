# Capability router component

This component, rather than native Rust, owns the exhaustive mapping of all 27
capability operations to seven service families. It also enforces the minimum
authority class and the bounded v1 approval rule before delegating to the exact
typed service import selected by the graph.

The graph/runner proves which service artifact is actually bound. The request
carries that expected digest and the router rejects a service response that
does not echo it. Native code never switches on an operation, service family,
authority meaning or approval meaning.

## Compiled approval adapter evidence

`tests/wasm_adapter.rs` instantiates the checked compiled component artifact in
Wasmtime with deterministic Ed25519 verification and in-memory implementations
of only the declared blob and transaction primitives. It proves valid first
use, byte-exact replay, changed-request reuse rejection, forged-signer
rejection, forged-signature rejection, and that no rejected request reaches a
service delegate. The host implementations are test fixtures; they do not move
routing, approval, or service policy back into native code.

From `components/`:

```console
cargo test --locked --offline -p wasm-biotic-capability-router --test wasm_adapter
```
