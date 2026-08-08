# Wasm-Biotic worker components

This workspace contains six actual WebAssembly Component Model workers for the
bounded v1 factory. They are the graph-owned implementations of factory roles,
not native callbacks and not claims of full legacy-worker equivalence.

| Component | Typed service imports | Bounded v1 workflow |
| --- | --- | --- |
| Planner | build, scheduling | open, snapshot and patch the workspace, then schedule the job |
| Builder | build | build a candidate |
| Validator | validation | bind a provider proposal, then produce validation evidence |
| Reviewer | review | review a candidate without promotion authority |
| Packager | packaging | publish and verify a package |
| Continuity worker | continuity | publish and resolve continuity evidence |

Every component exports both the typed `worker-workflow.execute` interface and
the uniform blob-oriented `component-task.run` interface. The latter is what
the digest-selected native component runner instantiates. It imports
`blob-store` only to resolve the versioned request envelope and persist the
versioned response envelope; the [task ABI](TASK-ABI.md) is owned and decoded by
components, not by native code.

Each worker validates its role, request identifiers, worker digest syntax,
lease digest, input blobs, and the exact graph-bound service bindings it needs.
It sends every service component identity in the capability request and rejects
duplicate, missing, extra or malformed bindings. Service rejection, failure,
exhaustion, cancellation, invalid output or response-identity mismatch can
never turn into success.

The planner deliberately demonstrates composition across two component
services. The validator, packager and continuity worker each perform paired
operations whose second step verifies or resolves the first step's exact
content-addressed output. Extending these workflows requires a new component
version and graph digest.

Scheduling is replay-stable: an omitted deadline produces the deterministic
immediate `not-before` value `0`, while an explicit deadline is passed through
unchanged for the substrate to bound. The scheduling component never derives
durable wake bytes from the current wall clock.

## Native boundary

The components use `no_std` on `wasm32-wasip2`, import no WASI interface and
have no ambient filesystem, network, process, clock or environment access.
Their only imports are the typed services declared by their WIT world plus the
generic blob store needed by `component-task`. Small allocator, panic and
canonical-ABI shims are native-to-Wasm implementation mechanics, not factory
policy.

The generic runner, not the guest, hashes the selected component bytes. A
worker validates the claimed digest structure and echoes it in the response;
the router must verify that value against the active graph. See the task ABI's
identity-boundary section for the complete split.

## Build and verification

From the repository root, with `wasm32-wasip2` installed:

```sh
cargo build --manifest-path components/workers/Cargo.toml \
  --release --target wasm32-wasip2 \
  -p wasm-biotic-planner-worker \
  -p wasm-biotic-builder-worker \
  -p wasm-biotic-validator-worker \
  -p wasm-biotic-reviewer-worker \
  -p wasm-biotic-packager-worker \
  -p wasm-biotic-continuity-worker

cargo test --manifest-path components/workers/Cargo.toml \
  -p wasm-biotic-worker-policy

cargo run --manifest-path components/workers/Cargo.toml \
  -p wasm-biotic-worker-smoke -- \
  target/wasm32-wasip2/release/wasm_biotic_planner_worker.wasm
```

The Wasmtime smoke test instantiates the compiled planner, links only an
in-memory blob substrate plus the planner's build and scheduling service
imports, executes both the typed workflow and its blob-oriented
`component-task` adapter, and observes the exact four-step result.

## Historical R0 release artifacts

The 2026-08-02 R0 release build was validated with `wasm-tools` and executed
with Wasmtime. These identities describe that immutable historical cohort;
the expanded R1 workflows necessarily produce new component and graph
identities. The binaries remain build outputs rather than checked-in files:

| Role | Bytes | SHA-256 |
| --- | ---: | --- |
| Planner | 203121 | `29b04f686a83aded3b93d016583eb6cffd940602c8ce8d7cac83ed5ecb34f99b` |
| Builder | 200613 | `ca662153a2cf520fcc29adf1e27b63ff6ac9e2e8f931e08da2d64267261265ae` |
| Validator | 200660 | `16b23a86000498d6bc6a6fa6ff0ec4910fd8a895b5d5ea17ada0695c4bf426bd` |
| Reviewer | 200624 | `d91a481d11f8204a4e94800826e9423b01b7b8bf801f77c00f1dc60bf3e08059` |
| Packager | 200651 | `f3093fce30b729bf9c60a5d4b6b875e601e6b84a9c189b9af043c8450bdb8086` |
| Continuity worker | 200660 | `53bfa52368bdf047beedf98fb654c3d9848f6e34933f84c9e14b0edb064e5aea` |

All six artifacts export `worker-workflow` and `component-task`. Inspection
found only the WIT type instances, each role's declared service interface and
`blob-store`; no artifact has a `wasi:*` import.
