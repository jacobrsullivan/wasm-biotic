# Component-Complete Conformance

A factory MUST pass every gate below before claiming `component-complete`. There
is no partial conformance label and no production waiver for a native reference
implementation.

The claim is always scoped to one exact graph, native TCB and substrate profile.
A mechanism that the signed profile explicitly disables has no effect-dispatch
success path to qualify; it MUST instead pass its fail-closed envelope and
escape tests. Enabling that mechanism later creates a new profile and requires
the corresponding effect, crash, credential and confinement evidence before
the new profile can inherit the claim.

Mechanism tests may use an admitted fixture component when the native path is
proved parametric in component identity and domain bytes: the same primitive,
grant, limit, journal and receipt code must run for every admitted digest. Such
seam-level evidence MUST be paired with at least one complete graph lifecycle
that crosses normal restart, successor activation and rollback. This avoids
pretending that repeating an identical native seam once for each semantic node
adds isolation, while still requiring the real graph to execute end to end.

## 1. Contract and graph gates

- Parse every file in `wit/wasm-biotic/` with `wit-parser` `0.246.x` or a parser
  proven compatible with the package version.
- Validate the graph manifest against `factory-graph.schema.json`.
- Recompute the manifest, component, constraints and blob digests from bytes.
- Resolve every component import. Non-component bindings MUST be one of the
  eight `factory-root` substrate interfaces.
- A component declared pure MUST have no callable, resource, module, component
  or value import. Type-only instance imports used to preserve shared WIT value
  identity are permitted only when recursive type inspection proves every
  member is a type—never a function or resource. Such declarations confer no
  effect authority and are not substrate bindings.
- Reject mutable component tags, undeclared dynamic component digests, duplicate
  node IDs, duplicate import bindings and WIT world mismatches.
- Verify that all six worker roles, seven capability families, the supervisor,
  both routers, exchange, evolution, migration and closure semantics have
  component nodes and required bindings.
- Verify that all 27 capability operations are advertised by exactly one
  activated service family according to the map in `README.md`.
- Derive one immutable principal for every graph consumer from its node ID and
  raw authority-component digest. A composed root MUST NOT collapse these
  principals into a graph-wide union grant.
- Rewrite every direct substrate import in each consumer's retained component
  bytes to a unique, content-derived import alias. The alias MUST bind the
  consumer, raw authority digest, source interface and capability; aliases may
  not be selected or forged by guest-supplied payload fields.
- Retain every per-consumer scoped component by digest. The descriptor,
  substrate profile, strict-validation report and release certificate MUST
  bind the same exact consumer/principal/alias/scoped-byte mapping.
- Emit a canonical strict-validation report and detached signed certification
  binding its digest to the exact manifest, native inventory, WIT, raw/derived
  artifacts, descriptor, profile, composition configurations and constraints.
  Production admission MUST verify that closure against an independently
  operator-pinned certifier key without interpreting the report's semantics.
- For profile v3, require exactly one HTTP binding matching the
  `exchange-service` consumer's content-derived alias and separate canonical
  HTTP-constraint digest. Reject missing, extra, reordered, cross-consumer or
  digest-swapped bindings. Profile v1/v2 MUST keep HTTP disabled.

## 2. Native-boundary gates

- Produce the native inventory required by `NATIVE_TCB.md`.
- Show that the production root has no native filesystem, process, shell,
  environment, database-query, provider or domain-service import.
- Statically inspect the TCB and fail on domain dispatch keyed by worker role,
  capability operation, milestone, provider, promotion or closure values.
- Demonstrate that domain payload bytes can be replaced with arbitrary opaque
  bytes without selecting a different native code path except size/digest/grant
  rejection.
- Demonstrate that private key and credential bytes never enter component
  memory, blobs, journals, logs, receipts, responses or audit bytes.
- Demonstrate that every instantiated workload digest is present in the active
  manifest and parses as a Component Model component.
- Demonstrate that each host import alias is linked to an immutable
  consumer/grant context before guest execution. Native code may enforce that
  context, but may not infer a worker role, service family or policy identity
  from domain payloads.
- Qualify runtime principal identities by the admitted graph digest. Every
  durable handle, idempotency record and component-run caller/target decision
  MUST use that alias-derived principal, never a graph-union or guest-asserted
  caller identity.
- On the R2-and-later path, expose only the verified content-derived aliases. A legacy
  `RunRequest` grant list may carry a canonical, non-escalating compatibility or
  resource ceiling derived from the signed executable closure, but it MUST NOT
  create callable authority or select the active principal.
- Treat cross-graph activation as an atomic ownership move, not an exception to
  graph-qualified isolation. Commit MUST move exactly one activation handle
  from the source graph principal to the admitted target graph's exact same
  principal seed only if that target retains the exact activation import.
  Rollback MUST move it back to the verified last-known-good graph under the
  same checks. Native code may enforce this ownership transition; the decision
  to activate or roll back remains component policy.
- For enabled HTTP, demonstrate that the effective origin, path, DNS, TLS,
  method, header, body, timeout, concurrency, redirect and credential bounds
  are the intersection of signed constraints and smaller operator capacity.
  Operator configuration MUST NOT widen signed authority.
- Demonstrate that native transport treats status, exposed headers and body as
  opaque bytes and performs no provider selection, parsing, retry, fallback,
  accounting or workflow transition.

## 3. Behavioural-equivalence gates

For the frozen acceptance corpus, execute the transitional native reference and
the component graph from the same canonical initial state and event stream.
Require identical:

- admission and terminal decisions;
- state, command and evidence digests;
- worker selection and capability requests;
- approval and authority outcomes;
- promotion, rollback and closure decisions; and
- stable receipt fields after normalizing declared clock/entropy inputs.

Any intentional difference requires a versioned contract decision and new
fixture; it cannot be hidden as host behaviour.

## 4. Crash, replay and durability gates

Inject a crash before and after every durable write, host-effect dispatch,
component completion and receipt commit. On restart:

- no committed event or receipt is lost;
- no irreversible effect is duplicated;
- pending effects resume by idempotency key;
- component linear memory may be discarded completely;
- reducer state reconstructs from durable bytes;
- stale writers fail fencing; and
- an activation recovers either the complete old graph/state or the complete new
  graph/state, never a mixture; its handle is durably owned by exactly the graph
  principal corresponding to that recovered side, never both.

For an explicitly disabled transport, the absence of a dispatch success path is
part of the signed profile rather than a waived remote-effect test. Every local
write/effect seam that remains reachable must still be covered.

For enabled R3 HTTP, inject faults before durable intent, before dispatch, after
possible byte escape, before operation identity is durable, before terminal
fact commit and after terminal commit. Prove that a prepared intent may start
once, a pending operation is polled without resend, terminal replay is exact,
and possible byte escape without a committed response becomes durable
non-retryable indeterminate state. Native code MUST NOT retry. Cancellation may
prevent a not-yet-issued dispatch but cannot claim to reverse bytes already
sent.

## 5. Isolation and adversarial gates

Exercise components that loop, trap, allocate beyond limits, produce oversized
output, forge digests, request undeclared imports, call an unlisted component,
reuse an approval, replay exchange traffic and return malformed documents. The
substrate MUST bound or reject them and append a truthful mechanism receipt. It
MUST NOT convert failure into domain success.

Run origin/path, DNS/IP, TLS version/hostname/SPKI, method, request/response
header, body, timeout, concurrency, redirect and credential-handle/placement
escape tests against HTTP grants. Exercise signed/operator-limit intersection,
ambient proxy denial, changed-request idempotency conflicts and cross-owner
poll/cancel. Run transaction scope, key namespace, blob quota, wake target and
activation expected-digest escape tests against their respective grants.

Exercise cross-principal attacks against both the production substrate and an
independent substrate implementation. At minimum, attempt an undeclared alias,
another consumer's capability, another principal's wake/run/activation handle,
another principal's idempotency identity and a component-run target outside the
caller's declared invocation edges. Every rejection MUST leave protected
mechanism state unchanged and the owning principal MUST retain access.

Activation isolation MUST additionally cover the lifecycle boundary: reject a
target graph that lacks the exact source principal seed, reject that seed when
it lacks the activation import, reject a wrong seed in either graph, and reject
the stale source after a successful handoff. A failed commit MUST leave both the
active graph and source-owned staged record unchanged. A successful handoff or
handback MUST survive restart with exactly one graph-qualified owner.

## 6. Root upgrade and reproduction gates

- Shadow a candidate supervisor and service graph against the active event
  corpus without granting mutation authority.
- Activate through an admitted migration component and atomic graph switch.
- Prove automatic boot-failure recovery to the last-known-good graph.
- Prove component-decided rollback after a post-activation observation failure.
- Have the activated successor graph perform the next complete factory cycle.
- Export the graph manifest, exact component bytes, WIT package and evidence;
  run them unchanged on an independent substrate implementation.
- Prove that the exact consumer-to-principal mapping and graph-qualified caller
  provenance survive normal replay, successor activation, rollback and process
  restart. Lifecycle evidence MUST summarize the authority trace for each
  phase and bind both package principal-inventory digests.
- Prove that successor activation hands the activation record to the exact
  target graph principal, that successor policy can observe and request
  rollback through that record, and that rollback hands it back to the exact
  last-known-good graph principal. The native substrate proves only the atomic
  graph/identity/import checks; component evidence proves the observation and
  rollback decision.
- For an enabled-transport cohort, reproduce the same constraint parsing,
  destination/TLS confinement, single-dispatch durability, principal ownership
  and secret non-disclosure on an independent substrate.

## 7. Required evidence bundle

The release evidence is content-addressed and contains:

1. graph manifest and its digest;
2. all component bytes and computed digests;
3. exact WIT package and digest;
4. native TCB inventory and digest;
   the native executable digest and source-closure identity may be carried by a
   detached build attestation because an executable cannot contain its own
   SHA-256 without a circular identity; that attestation MUST bind the compiled
   inventory digest and exact toolchain;
5. canonical strict-validation/import-resolution/semantic-coverage report and
   its digest;
6. canonical signed release certification and certifier public-key identity;
7. behavioural-equivalence report;
8. crash/fault matrix and receipts;
9. adversarial-isolation report;
10. activation, rollback and successor-cycle receipts;
11. independent-substrate reproduction attestation;
12. canonical per-package principal inventories and per-consumer scoped
    component bytes;
13. a cross-principal isolation report binding production-kernel and
    independent-substrate campaigns to the exact graph/principal inventories;
    and
14. activation ownership evidence proving one-owner handoff, successor use,
    handback, rejection cases and restart durability; and
15. for an enabled-transport profile, production, independent and joined
    transport-confinement evidence covering the complete signed constraint,
    durability, ownership, non-retry and secret-boundary case inventory.

The component-complete claim is true only for the exact graph and TCB digests in
that bundle. Separate North-Star external qualification requirements remain
separate; component-complete architecture alone does not satisfy them.
