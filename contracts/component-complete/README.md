# Component-Complete Factory Contract

Status: normative contract, version `0.1.0`; implemented by the exact signed R3 closure  
WIT package: `wasm-biotic:factory@0.1.0`

This contract makes “only run Wasm-Biotic components” precise:

> A Wasm-Biotic factory is a versioned, content-addressed graph of WebAssembly
> components. Its native substrate may instantiate, meter, persist, communicate
> and enforce declared capabilities, but may not implement factory roles,
> services, workflows or policy.

The current native Rust control plane and native capability services are
transitional reference implementations. They are an oracle for compatibility
tests, not part of the conforming final architecture. Rust remains an intended
implementation language: Rust code satisfies this contract when it is compiled
to a Component Model component and admitted by digest into the graph.

`MUST`, `MUST NOT`, `SHOULD` and `MAY` are normative terms.

## Meaning of “only run components”

A production factory workload MUST be a WebAssembly Component Model component.
That rule covers supervisors, workers, service implementations, routers,
connectors, compilers, validators, migrations, protocol handlers and policy.
The substrate, Wasm engine, operating system and hardware form the trusted
computing base (TCB); they are mechanisms on which components run, not factory
workloads.

A conforming graph is portable when another substrate implementation can run the
same component bytes and manifest while implementing the versioned WIT host
interfaces. Self-contained therefore means “complete component graph plus
explicit imports”, not “requires no runtime or operating system”.

The production path MUST NOT expose native process execution, a shell, ambient
filesystem access, ambient environment variables, or unrestricted sockets.
`command-execute` means “execute an admitted tool component by exact digest”.
If a compiler, test runner or helper cannot be supplied as a component, the
factory cannot run it as factory software.

## Graph identity and binding

The graph manifest conforms to
[`factory-graph.schema.json`](factory-graph.schema.json). Its identity is:

```text
sha256(RFC-8785-canonical-UTF-8(manifest-without-an-embedded-self-digest))
```

Every node is selected by SHA-256 digest and declares one world from
`wasm-biotic:factory@0.1.0`. Every import is bound either to an export of another
manifest node or to one of the eight allowed substrate interfaces below. A
binding to anything else is invalid. The substrate MUST verify all component,
manifest and immutable-blob digests before use.

Service selection is also explicit in the typed call path. A worker request
carries the exact component digest bound to each service family, and every
capability request names the selected `service-component`. The component echoes
that value, while the generic runner MUST compare it with the digest of the
artifact it instantiated. A native adapter may enforce that equality; it MUST
NOT choose a service by operation or family, substitute a native service, or
interpret the service response. The target digest cannot be embedded as a
self-identity constant in the component because doing so would make the final
artifact digest circular.

### R2-and-later authority and principal binding

R2 assigns one immutable authority principal to every graph consumer. Its
principal seed is derived from the consumer node ID and raw authority-component
digest; it is not a role name, service-family name or value asserted by the
guest. Every direct substrate import in that consumer's retained bytes is
rewritten to a unique, content-derived alias binding the consumer, raw authority
digest, source interface and generic capability. The signed descriptor,
substrate profile and release closure bind the principal inventory, alias map,
per-consumer scoped component digests and enclosing executable digests.

Production admission independently recomputes those identities and rejects any
different mapping. Before a root or dynamic executable starts, the linker binds
each residual alias to one immutable context: admitted graph digest, consumer,
principal seed, graph-qualified runtime-principal digest, scoped component,
enclosing executable, generic capability, opaque scope and constraint digest.
The R2-and-later linker exposes no canonical host import that could bypass that
context. Guest payloads therefore cannot choose their caller identity or borrow
another consumer's authority.

Component-run operations are authorized twice: the request's target must be an
admitted exact component digest, and the alias-bound caller principal must have
an explicit invocation edge to that target. For R2 and later, the kernel canonically
derives the legacy `RunRequest` grant ceiling from the target executable's
signed `principal_seeds` and their static host imports. Request-carried grants
may only narrow that ceiling and remain compatibility and resource metadata;
they do not supply callable authority. Only the immutable alias-selected active
principal can call a host mechanism. Component-run operation handles, clock
wake handles, activation handles and transaction idempotency records are
qualified by the admitted graph and owning principal. Poll, cancel, commit,
rollback or replay by another principal must fail without changing the owner's
state.

Activation is the one deliberate graph transition. Commit atomically moves the
single activation-handle record from the source graph principal to the admitted
target graph, but only if the target contains that exact principal seed with
the exact `activation`/`switch` import. Rollback atomically moves it to the
verified last-known-good graph under the same rule. At no point do two graphs
share the handle: stale-source, wrong-graph, wrong-seed and missing-import calls
fail without changing the graph selection or the current owner.

The local release harness may inspect the already-persisted generic completion
and provenance through a native read-only evidence API. That API is outside all
component worlds and cannot be used as component poll or cancel authority; the
same unscoped or wrong-principal WIT call remains rejected.

All of this is substrate enforcement over opaque identities. The native kernel
may recognize one of the eight mechanisms and its generic WIT method, but it may
not infer that a principal is a planner, a target is a service, an operation is
a workflow step, or a result satisfies factory policy.

### R3 bounded transport binding

Profile v3 enables one external mechanism without adding native factory
semantics. The `exchange-service` component's content-derived HTTP alias is
bound to one closed, separately digested
`wasm-biotic.http-transport-constraints.v1` document. The signed constraint
fixes destination, path, DNS, TLS 1.3 peer identity, method, visible headers,
body sizes, timeout, concurrency, redirect denial and credential placement.
The effective grant is its intersection with shared signed ceilings and smaller
operator capacity. Operator configuration may disable or narrow the mechanism;
it cannot create authority absent from the signed graph.

The host performs only byte transport and generic durable-operation mechanics.
The component chooses the provider, forms the application request, interprets
the response and decides retry, cancellation, fallback, accounting and terminal
policy. A native `start` is one dispatch attempt. An issued operation is polled,
not resent, after restart; a crash after possible byte escape and before a
durable terminal fact becomes a stable non-retryable indeterminate outcome.

Credentials remain non-exportable. A component supplies an opaque handle and
the exact non-secret header prefix fixed by the signed binding. The host appends
the secret only after destination and TLS authorization, and the secret may not
enter component memory or persisted, logged or returned evidence bytes.

The complete WIT contract lives in [`../../wit/wasm-biotic/`](../../wit/wasm-biotic/):

- `foundation.wit` defines common content, authority and receipt types.
- `substrate.wit` defines the entire native boundary.
- `services.wit` defines all capability-service and exchange interfaces.
- `workers.wit` defines the six governed worker roles.
- `control-plane.wit` defines pure supervision, durable control and API policy.
- `worlds.wit` defines component worlds and the composed `factory-root` world.

## Exhaustive factory-semantic map

The following inventory is normative and exhaustive for the present factory.
Each listed semantic MUST execute in the named component class. Adding a new
semantic requires adding or versioning a component interface; it MUST NOT be
implemented as an unrecorded host special case.

### Control plane and governance

| Factory semantic | Owning component |
| --- | --- |
| Job admission, rejection and lifecycle transitions | `supervisor-reducer-component` |
| Retry, cancellation, deadline and stop decisions | `supervisor-reducer-component` |
| Worker sequence and workflow choreography | `supervisor-reducer-component` |
| Approval requirements and authority escalation policy | `capability-router-component` plus reducer decisions |
| Durable event/command outbox choreography | `factory-control-component` |
| Worker-role/digest/world matching and selection | `worker-router-component` |
| Capability operation/family matching and service selection | `capability-router-component` |
| Operator/API routing, request validation and response meaning | `factory-control-component` via `factory-api` |
| Recovery, checkpoint and replay decisions | `supervisor-reducer-component` and `factory-control-component` |
| Scheduling priority, fairness, retry and wake policy | `scheduling-service-component` |
| Audit event meaning and payload construction | The component performing the decision; host only appends bytes |
| Graph proposal, shadow comparison and promotion recommendation | `factory-evolution-component` |
| State-schema transformation | `state-migration-component` |
| Activation health interpretation and rollback decision | `operations-service-component` and supervisor reducer |

The reducer is pure: `durable state + one durable event -> new state + commands`.
The component-owned driver journals state and commands before asking the
substrate to perform an effect. The substrate never invents a retry, approval,
workflow transition or rollback decision.

### Worker ecology

| Role semantic | Owning component | Component service imports |
| --- | --- | --- |
| Planning and observation | `planner-worker-component` | build, scheduling |
| Candidate mutation | `builder-worker-component` | build |
| Independent proving and comparison | `validator-worker-component` | validation |
| Governed review and recommendation | `reviewer-worker-component` | review |
| Artifact consolidation and packaging | `packager-worker-component` | packaging |
| Memory, evidence and checkpoint consolidation | `continuity-worker-component` | continuity |

Worker packages MUST contain their actual behaviour. A role-marker component
whose operation is completed by native Rust does not conform.

### Capability operations

All 27 operations carried from the native reference implementation remain
explicit. Their input/output document schemas may evolve independently, but the
operation routing and semantics belong to components.

| Capability-service component | Operations whose semantics it owns |
| --- | --- |
| `build-service-component` | `workspace-open`, `workspace-snapshot`, `workspace-patch`, `candidate-build`, `command-execute` |
| `packaging-service-component` | `package-publish`, `package-verify` |
| `validation-service-component` | `validation-prove`, `validation-compare`, `factory-execute`, `factory-provider-proposal`, `factory-shadow` |
| `review-service-component` | `review-candidate` |
| `continuity-service-component` | `evidence-publish`, `evidence-resolve` |
| `scheduling-service-component` | `schedule-job` |
| `operations-service-component` | `deployment-initialize`, `deployment-activate`, `deployment-observe`, `deployment-rollback`, `operations-inspect`, `factory-initialize`, `factory-state-migrate`, `factory-activate`, `factory-observe`, `factory-rollback`, `factory-inspect` |

For clarity, storing a workspace tree is a generic blob/transaction mechanism;
deciding how a patch changes that tree is build-service semantics. Instantiating
a component is a generic runner mechanism; deciding what constitutes a valid
build or proving result is service semantics. Switching an already-approved
graph digest is an activation mechanism; deciding whether it should be promoted
or rolled back is operations/supervisor policy.

### Reproduction, exchange, providers and closure

| Factory semantic | Owning component |
| --- | --- |
| Candidate factory construction and graph manifest production | `factory-evolution-component` |
| Provider request construction, response parsing and admission policy | `validation-service-component` or a graph-bound provider component behind it |
| Provider selection, budget and fallback policy | `validation-service-component` and supervisor reducer |
| Factory shadowing, comparison and promotion evidence | `factory-evolution-component` plus validation/review components |
| Successor initialization, migration and activation policy | operations, migration and supervisor components |
| Exchange envelope, authorization, replay and revocation semantics | `exchange-service-component` |
| Exchange transport choice and retry policy | `exchange-service-component`; raw HTTP is host mechanism only |
| North-Star dossier interpretation and closure decision | `closure-evaluator-component` |
| External evidence request and qualification policy | closure/review components; signatures use key handles |

### Admitted tools

Every compiler, code generator, test runner, parser, validator and migration tool
invoked by a factory MUST be an admitted component node or immutable component
artifact referenced by the active manifest. `admitted-tool-component` is the
minimum tool world. Tool admission, expected world, grants and resource limits
are graph data inspected by component policy and enforced by the substrate.

Host utilities MAY be used outside the factory to build or inspect a release;
they MUST NOT be reachable from a conforming production graph.

## Exhaustive allowed native primitives

The composed `factory-root` world imports exactly these interfaces. They are the
only allowed host primitives.

| Host interface | Permitted mechanism | Explicitly forbidden host behaviour |
| --- | --- | --- |
| `blob-store` | Verify, quota, put and get immutable bytes by digest | Interpret packages, evidence, workspaces or policy |
| `transaction-store` | Opaque namespaced read and atomic compare-and-swap of blob references | Choose state transitions, retries or domain invariants |
| `clock` | Report wall time and durably deliver a requested wake | Choose schedules, deadlines or retry policy |
| `component-runner` | Verify, instantiate, meter, interrupt and collect results from admitted component digests | Run native programs; select roles; interpret success semantics |
| `http-transport` | Apply declared destination/size/time bounds and perform byte-oriented HTTP/TLS/DNS | Construct prompts, select providers, parse responses or choose retry policy |
| `key-service` | Hold non-exportable credentials/keys, sign/verify digests and provide secure entropy | Decide what to sign, authorize promotion or expose secret bytes |
| `activation` | Stage and atomically switch an already-declared graph digest; restore an exact prior digest | Decide promotion, health meaning, migration policy or rollback criteria |
| `audit-log` | Append and resolve immutable hash-chained entries | Decide what an event means, redact policy, or manufacture success evidence |

Inbound HTTP listening is the transport side of `factory-api`: the host converts
an HTTP envelope to WIT values and invokes the exported handler without semantic
route logic. Resource ceilings, digest verification, grant checking and denial
are enforcement, not policy. Host grants contain only primitive name, opaque
scope and immutable constraints; authority and approval meaning is evaluated by
components. Grants themselves are immutable graph inputs chosen through
component governance.

There is deliberately no native filesystem, shell, process, database-query,
provider, worker, scheduler, reviewer or “factory” interface.

## Durability and async rule

Long-running substrate effects use `start -> operation-id -> poll/cancel` rather
than retaining a suspended Wasm stack. Operation IDs, requests and receipts are
durable and, in R2 and later, graph- and principal-owned. Idempotency identity includes the
alias-bound caller principal; the same guest string from another consumer is a
different authority scope and cannot replay or observe the first operation.
Components MUST make effect requests idempotent. The driver MUST commit an
outbox record before dispatch and commit the terminal receipt before reducing
the next event. A crash at any boundary must recover without duplicating an
irreversible effect or weakening principal isolation.

For enabled R3 HTTP, recovery distinguishes a prepared intent from an issued
operation. It may start the former once or poll the latter; it MUST NOT
redispatch an issued or indeterminate operation. Component policy can choose a
subsequent retry only by making a new explicit request under its own durable
state and idempotency identity.

## Versioning

- Breaking WIT changes require a new package version.
- Component and graph identities never use mutable tags.
- A graph manifest binds exact WIT package, world and component digests.
- State migration is an explicit component digest; the host never rewrites
  factory state according to compiled-in schema knowledge.
- A last-known-good graph remains addressable until activation and recovery
  evidence prove the successor safe to retain.

The bounded-local R1 releases used the earlier v1 graph-union static-grant
model. Their evidence remains valid only for those named historical release
closures. New component-complete claims use the R2 per-consumer alias model; an
implementation may retain the explicit v1 path for historical replay, but it
must not select it for a v2 descriptor/profile or present R1 union evidence as
R2 isolation evidence.

Profile v2 retains disabled HTTP. Profile v3 is the only enabled form and MUST
bind an exact HTTP constraint as defined by
[`decisions/CD-0002-bounded-http-transport-v1.md`](decisions/CD-0002-bounded-http-transport-v1.md).
R2 isolation evidence alone cannot qualify the enabled transport.

## Conformance

[`NATIVE_TCB.md`](NATIVE_TCB.md) is the normative native-code boundary.
[`CONFORMANCE.md`](CONFORMANCE.md) defines the required evidence and tests.
The contract text alone never establishes conformance. A claim becomes true
only for an exact signed closure after every mandatory gate passes on the
production execution path and the evidence is retained in the aggregate.
