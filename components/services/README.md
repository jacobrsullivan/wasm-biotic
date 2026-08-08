# Capability-service components

This directory contains seven admitted WebAssembly Component Model services for
`wasm-biotic:factory@0.1.0`. Each service exports one typed `invoke` function;
the component owns operation meaning, validation and result construction. The
native substrate supplies only the mechanisms imported by the component. It
does not implement a service, workflow, provider, deployment policy or success
result.

The implemented R1 contract is useful but deliberately bounded. It can apply a
content-addressed patch to an inline workspace, compile and test a small
Wasm-Biotic text program, produce a deterministic local provider proposal,
review the resulting lineage, close and verify a package record, resolve its
evidence, schedule one durable wake, and advance a local deployment-state
document. It is not a general software-development environment.

In particular:

- the supported language is `wasm-biotic:text-program@1`, not Rust, Cargo,
  arbitrary Wasm, a shell or a general toolchain;
- provider policy is `local-fixture` only—there is no live model/API provider;
- deployment is a local content-addressed state machine only—it does not start
  a process, contact a platform, or switch the factory's active graph;
- these service worlds import no HTTP transport, key service, credentials,
  filesystem, environment, process, shell, socket or WASI APIs; and
- there are no external effects. Durable local bytes, one scheduling intent
  and one wake are the only effects requested from the mechanism substrate.

The detailed source-level contract is recorded in
[`notes/R1-CAPABILITY-CONTRACT.md`](../../notes/R1-CAPABILITY-CONTRACT.md). That
document intentionally does not assert that an R1 release has completed.

## The bounded R1 workflow

The six workers invoke the service components in this exact order:

1. `workspace-open`
2. `workspace-snapshot`
3. `workspace-patch`
4. `schedule-job`
5. `candidate-build`
6. `factory-provider-proposal`
7. `validation-prove`
8. `review-candidate`
9. `package-publish`
10. `package-verify`
11. `evidence-publish`
12. `evidence-resolve`

The work starts as canonical
`application/vnd.wasm-biotic.r1-change-request.v1+json`. `workspace-open`
turns it into canonical
`application/vnd.wasm-biotic.r1-work-state.v1+json`; every later
blob-transforming semantic operation validates and extends that exact state.
`schedule-job` deliberately returns the immutable state reference unchanged,
while its transaction and wake provide separate durable evidence.

The operations service also implements a separate local deployment chain:

`deployment-initialize -> deployment-activate -> deployment-observe`

An unhealthy fixture observation permits `deployment-rollback`. A healthy
observation terminates at `observed-healthy`.

## Service contracts

| Component | Strict bounded R1 semantics | Imported mechanism and graph grant | Authority floor |
| --- | --- | --- | --- |
| `build-service` | Opens and hashes an inline workspace; snapshots sorted paths; applies one digest-checked CAS patch; compiles the patched entry point to bounded text-program bytecode | `blob-store`, scope `read-write` | Observe for open/snapshot; local-mutate for patch/build |
| `validation-service` | Creates one deterministic `local-fixture` provider record, then discovers and executes bounded text-program tests | `blob-store`, scope `read-write` | Local-mutate for provider proposal; automation-control for proof |
| `review-service` | Checks exact patch/build/provider/test lineage and records an approval boolean | `blob-store`, scope `read-write` | Observe |
| `packaging-service` | Creates a digest closure over the approved tree/artifact/records and then independently recomputes it | `blob-store`, scope `read-write` | Local-mutate to publish; observe to verify |
| `continuity-service` | Creates an evidence closure over the complete work record and resolves it back to the exact package/evidence identities | `blob-store`, scope `read-write` | Local-mutate to publish; observe to resolve |
| `scheduling-service` | Persists one idempotent schedule intent and requests one durable wake; omitted deadline is encoded as replay-stable `not-before = 0` | `transaction-store`, scope `wasm-biotic.schedule.v1`; `clock`, scope `wake` | Automation-control |
| `operations-service` | Advances canonical local deployment plan/state documents through initialize, activate, observe and conditional rollback | `blob-store`, scope `read-write` | Automation-control to initialize; promotion-control plus approval to activate/rollback; observe to inspect health |

The operation enum still contains all 27 names carried from the transitional
reference implementation. Sixteen names have strict bounded R1 semantics: the
12 workflow calls above plus four deployment calls. Other operations retain a
deterministic non-R1 compatibility envelope for historical octet-stream
inputs. They are not claims of command execution, general validation, live
factory execution, migration, activation or external operations. If an input
uses a reserved R1 media type, an operation without an R1 implementation fails;
it cannot fall back to the compatibility envelope.

`command-execute` never means spawning a native command. General admitted
component execution, where used elsewhere in the factory, crosses the generic
`component-runner` mechanism and is selected by exact component digest.

## Bounded text-program language

The only compiled source language in this contract is canonical JSON with
these stack instructions:

- `input`
- `literal { value }`
- `concat`
- `ascii-upper`
- `ascii-lower`
- `sha256-hex`

The build service emits deterministic `WBTX` bytecode. The validation service
interprets that bytecode against canonical test suites under
`tests/*.wbt-test.json`. This demonstrates real patch/build/test semantics
inside components, but it is not a Rust compiler, Cargo, a linker, a Wasm
component toolchain, arbitrary code execution, or access to a host workspace.

## Persistence and replay

The six blob-transforming services fetch the requested input, verify its
declared SHA-256 and size, produce deterministic canonical bytes, persist them
through `blob-store.put`, and verify that the returned reference identifies the
exact bytes and media type. A repeated identical invocation therefore names
the same content-addressed output. Each record binds its input-state digest,
semantic lineage and producing service-component identity.

Scheduling has no blob-store import. It atomically commits the input reference
under namespace `wasm-biotic.schedule.v1` using the request's idempotency key,
then schedules a wake whose ID is the capability request ID and whose payload
is the same input digest. An omitted deadline is always zero; an explicit
deadline is passed through to the substrate, which enforces its configured
future horizon. Conflicting replay is rejected by the mechanisms.

Deployment persistence is only the returned canonical deployment-state blob.
Its revision must equal the complete contiguous transition chain, and every
transition is digest-bound. The operations component does not import the
native `activation` mechanism.

## Bounds and fail-closed behavior

The semantic core enforces these internal limits before host quotas:

- canonical document: at most 1 MiB;
- workspace: 1–256 sorted unique files, at most 256 KiB each and 4 MiB in
  aggregate;
- canonical relative path: at most 240 bytes;
- labels: 1–64 restricted ASCII characters;
- program: 1–256 instructions and at most 64 KiB of literals;
- test corpus: at most 256 cases; and
- input, expected and produced values: at most 64 KiB each.

The graph/profile additionally meters fuel, memory, output size and wall time;
the operator-capacity example currently caps those at 50,000,000 fuel, 64 MiB
memory, 16 MiB output and 30 seconds. Those mechanism ceilings come from the
admitted graph/operator capacity; the service components cannot select or
raise them.

All services reject the wrong family, an unowned operation, insufficient
authority, a missing required approval, malformed SHA-256 identity, false blob
reference, noncanonical JSON, unknown fields, path traversal, duplicate or
unsorted records, stale stage/revision, failed CAS, broken digest lineage,
invalid bytecode stack, missing tests, remote provider/deployment mode, and
untruthful host receipts. A failed test may be recorded and reviewed, but it
cannot be packaged. No rejection manufactures a success-shaped output.

## Effect boundary

The canonical service worlds are declared in
[`wit/wasm-biotic/worlds.wit`](../../wit/wasm-biotic/worlds.wit). Build,
packaging, validation, review, continuity and operations import only
`blob-store`. Scheduling imports only `transaction-store` and `clock`.
`foundation` and `capability-contract` provide types, not ambient effects.

Any future network provider, credential use, general compiler, external
package registry or real deployment connector must itself be an admitted,
content-addressed Wasm-Biotic component with an explicitly reviewed WIT
capability. It may not be added as native service logic. The native substrate
remains limited to instantiation, metering, opaque persistence, communication
and enforcement of declared grants.

## Build and inspect

From the repository root:

```sh
cargo test --manifest-path components/Cargo.toml \
  -p wasm-biotic-service-policy-core
cargo build --manifest-path components/Cargo.toml --workspace \
  --release --target wasm32-wasip2
wasm-tools validate \
  components/target/wasm32-wasip2/release/wasm_biotic_review_service.wasm
```

The relevant implementation and contracts are:

- [`service-policy-core/src/r1.rs`](../service-policy-core/src/r1.rs)
- [`service-policy-core/src/lib.rs`](../service-policy-core/src/lib.rs)
- [`wit/wasm-biotic/services.wit`](../../wit/wasm-biotic/services.wit)
- [`wit/wasm-biotic/worlds.wit`](../../wit/wasm-biotic/worlds.wit)
- [`wit/wasm-biotic/substrate.wit`](../../wit/wasm-biotic/substrate.wit)
