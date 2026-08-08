# Native TCB inventory generator

`native_tcb_inventory.py` deterministically regenerates the byte-derived fields
of `kernel/native-tcb.json`. A plain invocation is read-only and behaves like
`--check`:

```sh
python3 kernel/tools/native_tcb_inventory.py
python3 kernel/tools/native_tcb_inventory.py --check
```

Updating the checked-in inventory requires an explicit write:

```sh
python3 kernel/tools/native_tcb_inventory.py --write
```

The generator preserves reviewed declarations, limitations, and policy prose.
It derives only the crate and pinned Wasmtime identity, the documented native
source-closure digest, the compiled WIT package digest, the dependency lock and
operator-example digests, and the complete sorted fixture/production-module
digest lists. Production modules are the crate-root `kernel/src/*.rs` files and
`kernel/src/bin/*.rs` binaries; cfg(test)-only nested modules remain covered by
the recursive source closure but are not described as runtime-reachable.
The source closure is exactly `kernel/Cargo.toml`, `kernel/Cargo.lock`, every
`kernel/src/**/*.rs` file, and each top-level `wit/wasm-biotic/*.wit` file in
UTF-8 bytewise path order. The inventory and this non-runtime tool are excluded
from that closure, avoiding a self-reference and keeping release tooling out of
the reachable native substrate.

Run the standalone regression tests with:

```sh
python3 kernel/tools/test_native_tcb_inventory.py
```

The tests generate in an isolated copy, prove repeated output is stable and
independent of the current working directory, and prove default check mode
detects stale retained bytes without changing the inventory.
