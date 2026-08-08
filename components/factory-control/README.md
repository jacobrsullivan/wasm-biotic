# Factory control root component

This crate is the production-shaped bounded-v1 driver for a component-complete
Wasm-Biotic factory. It exports `factory-control` and `factory-api` from the
canonical `factory-control-component` world. Factory workflow and routing
remain inside this WebAssembly component; native code supplies only generic
storage and enforcement primitives.

## Durable execution

Submission uses the [versioned submit blob ABI](SUBMIT-ABI.md). For every
reducer transition the driver:

1. resolves and verifies the current immutable state bytes;
2. invokes the graph-composed supervisor reducer;
3. verifies the reducer's previous-state digest and next document;
4. stores the next immutable state and a control record containing its outbox;
5. atomically advances the job pointer through an optimistic transaction; and
6. only then invokes the worker router or acknowledges an emitted result.

A returned worker response replaces the pending-dispatch outbox in a second
atomic commit before it is fed to the reducer. Consequently the recoverable
states around a worker effect are `dispatch-pending` and `worker-returned`, not
an unjournalled semantic gap. Replaying a dispatch uses the same graph-bound
execution identity and lease; idempotency is enforced by the worker router and
generic runner.

The bounded successful path is:

```text
submit -> planner -> builder -> validator -> reviewer -> packager
       -> continuity-worker -> durable job result
```

Rejected, failed, blocked and cancelled worker outcomes remain distinct and
produce inspectable versioned result documents. Cancellation is represented as
a worker-cancelled event sent through the reducer; native state is never edited
to manufacture a cancellation.

## Component-owned API routes

`factory-api.handle` owns method/path routing. Unknown or unsupported routes
return `unsupported-api-route`; there is no native fallback.

| Route | Imported component semantic |
| --- | --- |
| `POST /v1/jobs` | submit and drive a durable job |
| `GET /v1/jobs/{job-id}` | inspect durable result or control record |
| `POST /v1/jobs/{job-id}/cancel` | journal cancellation through the reducer |
| `POST /v1/recover` | recover a journalled job |
| `POST /v1/capabilities/route` | capability-router route |
| `POST /v1/exchange/envelopes` | exchange create-envelope |
| `POST /v1/exchange/receive` | exchange receive-envelope |
| `POST /v1/exchange/revoke` | exchange revoke-authority |
| `GET /v1/exchange/transfers/{id}` | exchange inspect-transfer |
| `POST /v1/evolution/propose` | factory-evolution propose |
| `POST /v1/evolution/shadow` | factory-evolution shadow |
| `POST /v1/evolution/assess` | factory-evolution assess |
| `POST /v1/evolution/apply` | component-owned initialize/migrate/activate decision; the substrate only commits the returned opaque graph/state pair |
| `POST /v1/evolution/observe` | component-owned post-activation health interpretation and rollback decision |
| `POST /v1/state/migrate` | typed state-migration migrate |
| `POST /v1/closure/evaluate` | closure-evaluator evaluate |
| `POST /v1/activation/stage` | activation stage |
| `POST /v1/activation/{id}/commit` | activation commit |
| `GET /v1/activation/{id}` | activation status |
| `POST /v1/activation/{id}/rollback` | activation rollback |
| `POST /v1/audit` | audit-log append |
| `GET /v1/audit/{sequence}` | audit-log resolve |

The deterministic `GET /__wasm-biotic/component-boundary-probe` route returns
status 200 and an `x-wasm-biotic-component-root: ok` header without state or
dependency access. It proves that the composed component root can execute—not
that the whole release has passed component-complete conformance.

Capability, activation, audit and migration record-valued routes accept strict
versioned JSON envelopes defined in `src/policy.rs`. Blob-valued component
operations receive the body reference unchanged. Factory evolution may request
dynamic component execution, but the native runner must still reject any
digest/capability edge absent from the activated graph manifest.

## Imports and native boundary

The compiled root calls these semantic component imports directly:

- supervisor reducer and worker router;
- capability router, exchange service and factory evolution;
- state migration and closure evaluator;
- activation and audit log.

It also uses only `blob-store` and `transaction-store` from the generic native
substrate. It imports no WASI filesystem, network, process, environment or
clock interface. Other substrate primitives remain transitively reachable
through their graph components and the fixed native `factory-root` boundary.

## Build and verify

From the repository root:

```sh
cargo test --manifest-path components/factory-control/Cargo.toml --lib
cargo build --manifest-path components/factory-control/Cargo.toml \
  --release --target wasm32-wasip2
wasm-tools validate --features component-model \
  components/target/wasm32-wasip2/release/wasm_biotic_factory_control.wasm
cargo run --manifest-path components/factory-control/Cargo.toml \
  --example smoke -- \
  components/target/wasm32-wasip2/release/wasm_biotic_factory_control.wasm
```

The Wasmtime smoke host is a test fixture. It exercises the compiled root
through six deterministic reducer/router stages, verifies the persisted
terminal result and executes the dependency-free component-root boundary probe.

## Verified artifact

The exact 2026-08-02 signed release-candidate component is 540675 bytes with
SHA-256
`037216740953a89d54da79d4d9e1f9058887881a5d8940b9bcf054ae506e1ccf`.
Its composed root is
`sha256:2e501d72f5d411f05af6b32ed657f32478dca2810fa09805fff19772ea4c2830`.
`wasm-tools validate --features component-model` passed. Interface inspection
confirmed the semantic imports listed above, only the declared substrate
primitives, and no residual `wasi:*` imports. The lifecycle harness also used
this component to initialize state, request a successor activation, interpret
an unhealthy observation, request rollback and then complete a post-rollback
factory cycle.
