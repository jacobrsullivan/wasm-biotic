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

All four crates are `no_std` Component Model builds. Their exact fixture bytes
are generated and ignored build output, not Git-owned source. The top-level
`./scripts/verify.sh python` scope builds them, installs the four stable names
under `kernel/fixtures/artifacts/`, and checks their hashes against
`native-tcb.json`.

To build one fixture manually in an ordinary pinned checkout, use its lockfile
and an explicit target directory. For example:

```sh
CARGO_TARGET_DIR=/tmp/wasmbiotic-root-fixture-target \
cargo build --locked --release --target wasm32-wasip2 \
  --manifest-path kernel/fixtures/root-component/Cargo.toml
```

That command writes beneath the named `/tmp` target directory; it does not
install into `kernel/fixtures/artifacts/`. Use `./scripts/verify.sh python` to
build all four, install the stable ignored filenames and check their reviewed
digests in `../native-tcb.json`. The signed offline source snapshot instead
uses its already hydrated Rust/Cargo homes and authenticated vendor closure.
