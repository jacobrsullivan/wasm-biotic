# Native Trusted-Computing-Base Rule

## Normative rule

The native TCB MAY implement only the eight generic substrate mechanisms defined
by the interfaces of `wasm-biotic:factory/factory-root@0.1.0`, plus bootstrapping
and crash recovery needed to instantiate that root. R2 and later executables
receive those mechanisms only through their verified, content-derived
per-consumer import aliases. The TCB MUST NOT implement or branch on factory
roles, service families, operation tokens, workflows, milestones, approval
meaning, promotion criteria, provider policy, exchange policy or closure logic.

The TCB is conforming only when it can be replaced by an independent
implementation without changing any factory decision, given identical WIT
inputs, durable state and declared nondeterministic inputs.

For an R2 or later package, authority is attached to the exact import selected by
Wasmtime, not to a graph-wide grant or a caller field supplied by guest code.
The substrate independently recomputes one principal seed from each consumer
node ID and raw authority-component digest. Before guest execution it links each
residual host-import alias to an immutable context containing the admitted graph,
consumer, principal, scoped and enclosing executable identities, generic
capability, opaque scope and constraint digest. The runtime principal identity
is the digest of the admitted graph digest and principal seed, so the same raw
component in two graphs does not share mechanism authority.

For the v2/v3 per-consumer model, the native substrate derives the legacy
`RunRequest` grant ceiling from the target executable's signed
`principal_seeds` and their static host
imports, then sorts and deduplicates it canonically. Request-carried grants may
only narrow that ceiling and are compatibility and resource metadata, not a
callable authority source. Actual host authority remains exclusively the
immutable alias-selected active principal. An R2-or-later linker MUST expose
neither a canonical host import nor a graph-union fallback path.

For an R3 profile-v3 package, enabled HTTP authority is additionally bound to
the exact `exchange-service` consumer alias and one separately digested
`wasm-biotic.http-transport-constraints.v1` document. The effective authority
is the intersection of that signed document, the shared signed ceilings and
smaller operator capacity. Operator state may disable transport, reduce limits
and provide a declared opaque credential handle; it MUST NOT add or widen an
origin, path, DNS range, TLS identity, method, header, body limit, timeout,
concurrency, redirect rule or credential placement.

The substrate may interpret only the closed transport envelope needed to apply
those bounds. HTTP status, exposed response headers and response body remain
opaque application facts. Provider selection, request construction, response
meaning, accounting, retry, fallback and workflow effects are component
semantics even when the native mechanism performed the underlying connection.

## Permitted native responsibilities

The native TCB may:

1. Parse and verify Component Model binaries and SHA-256 references.
2. Instantiate, link, meter, interrupt and terminate components.
3. Enforce memory, fuel, wall-time, output, concurrency and grant limits.
4. Store immutable blobs and atomically commit opaque key-to-blob references.
5. Manage locks, leases, fencing, fsync and crash-safe storage mechanics.
6. Read clocks and deliver explicitly requested durable wake events.
7. Perform byte-oriented HTTP/TLS/DNS transport under an immutable alias-bound
   grant: resolve and filter addresses, connect only to a checked address,
   enforce TLS 1.3 hostname and SPKI pins, deny redirects, meter headers, bodies,
   time and concurrency, and expose only signed response fields.
8. Hold non-exportable keys/credentials and perform requested cryptographic
   operations without exposing secret bytes. For R3 HTTP, append a credential
   only to its signed origin/header/prefix placement after destination and TLS
   authorization.
9. Append and resolve opaque, hash-chained audit bytes.
10. Stage and atomically route to an exact graph digest, retain a
    last-known-good digest, and restore it when a component-issued decision or
    boot-failure rule requests recovery.
11. Accept an inbound byte-oriented HTTP envelope and invoke the activated
    root's exported `factory-api.handle` function.
12. Verify a canonical content-closure statement and detached signature against
    an independently operator-pinned public key. The signed semantic report is
    opaque to native code; native verification may compare only schema, bytes,
    digests, signer identity and signature validity.
13. Independently recompute and verify R2-or-later principal seeds, import aliases,
    per-consumer scoped component bytes and their signed descriptor/profile
    mappings, then install the exact immutable alias linker contexts.
14. Qualify durable component-run operations, clock wakes, activation handles
    and transaction idempotency records by the graph-bound caller principal, and
    reject access from any other principal. When an R2-or-later activation commits, move
    its single handle owner atomically from the source graph principal to the
    admitted target graph's exact same principal seed, but only when that target
    principal retains the exact `activation`/`switch` host import. Rollback
    applies the same rule to the verified last-known-good graph.
15. Enforce that a component-run caller principal may instantiate only an exact
    target digest named by that caller's admitted manifest invocation edge.
16. Persist an exact HTTP request intent before dispatch, bind operation and
    idempotency identity to graph, alias-derived principal and request digest,
    and durably store one terminal or indeterminate transport fact.
17. Poll a previously issued HTTP operation after restart without redispatching
    it. If bytes may have escaped but no terminal response fact was committed,
    return a durable non-retryable indeterminate outcome.
18. Intersect signed HTTP constraints with operator capacity while rejecting
    every attempted operator widening or unavailable credential handle.

Items 13–18 are generic authority, durability and confinement enforcement.
Consumer IDs, component digests, aliases, edge endpoints and transport payloads
are opaque content identities or bytes to native code; they do not authorize
the substrate to infer a worker role, service family, provider, workflow step
or policy meaning.

Native release tooling may use a read-only, non-WIT evidence API to inspect a
persisted generic component completion or its provenance. That API is not
linked into any component world and conveys no poll or cancel authority. An
unscoped or wrong-principal WIT call to the same operation MUST still fail.

Boot-failure recovery is the sole built-in rollback condition: failure to parse,
link or start the selected root within fixed substrate limits. Health meaning,
observation windows and post-start rollback policy belong to components.

## Forbidden native responsibilities

Native code must not:

- implement a planner, builder, validator, reviewer, packager, continuity worker
  or supervisor state transition;
- contain service routing keyed by `CapabilityOperation` or service-family
  meaning;
- decide whether authority or approval is sufficient (it only verifies that an
  exact signed grant authorizes the requested host import and bounds);
- choose jobs, retries, priorities, schedules, providers, prompts, tests,
  evidence, candidates, promotion, rollback or North-Star results;
- parse a factory-domain document to determine behaviour;
- spawn a shell or native workload on behalf of a graph;
- expose ambient filesystem, environment, sockets, clocks or credentials;
- collapse R2-or-later consumer principals into a root or graph-wide union
  grant;
- accept a guest-authored caller/principal identity, share a principal-owned
  operation or handle across consumers, or dispatch outside an admitted
  caller-to-target invocation edge;
- select an HTTP provider, construct an application request, interpret a status
  or response document, retry, redirect, fall back or silently redispatch an
  ambiguous operation;
- widen a signed HTTP constraint from operator configuration, ambient proxy or
  DNS state;
- place credential bytes in component memory, blobs, journals, logs, receipts,
  responses or audit records; authenticate before the signed destination and
  TLS peer have been authorized;
- silently substitute a native implementation when a component fails; or
- generate success-shaped domain receipts.

Native code may parse only substrate envelopes and signed graph authority data
needed to enforce byte limits, digests, exact aliases, principal ownership,
caller-target edges, grants, HTTP origin/DNS/TLS/header constraints,
idempotency and transactional integrity. Domain documents and exposed transport
bytes remain opaque. Native enforcement may identify a generic substrate
capability and WIT method, but it may not assign factory meaning to the caller,
target, status or payload.

## Production execution inventory

A release MUST publish a machine-readable native inventory containing:

- a content-addressed native source closure (a Git revision is sufficient only
  when it names those exact bytes);
- Wasm engine version and enabled proposals;
- host interface names and WIT package digest;
- operating-system dependencies;
- storage, networking, key and clock adapters;
- all compiled native modules reachable from the factory process; and
- an attestation that no native process/shell execution import is reachable.

The exact native executable/library digest belongs in a detached build
attestation that binds the executable bytes to the compiled native-inventory
digest, source closure, dependency lock, target and toolchain. It cannot be a
self-asserted field compiled into the same executable: embedding that digest
would change the executable and make its identity circular. The signed graph
certificate binds the compiled inventory; the release evidence bundle binds the
post-build executable to that inventory. Both links are required for a released
claim.

Transitional reference implementations MAY remain in the repository and in
tests, but they MUST be unreachable from the production `factory-root` launch
path. Shadow comparison MAY invoke them only in a separately labelled,
non-conforming test harness whose results cannot mutate production state.

## Root of trust and activation

The local substrate persists two independent immutable trust anchors at
mechanism-state initialization:

1. one exact graph-manifest digest permitted to become the first active root;
   and
2. one raw Ed25519 public key permitted to certify every admitted release.

The offline strict validator emits a canonical semantic report and a canonical
signed statement binding the graph manifest, native inventory, WIT package and
worlds, metadata, every raw and derived component, derivation descriptor,
substrate profile, composition configurations, constraints and the report
itself. The native substrate verifies that complete byte/digest closure and the
signature. It MUST NOT parse the report to interpret component kinds, service
families, operation ownership or any other factory meaning.

Every initial or successor candidate requires a valid certificate from the
pinned key. The first active root additionally requires the separate exact
manifest pin; a correctly certified inactive candidate may be verified, stored
and instantiated without being selected. Dynamic component-runner requests are
restricted both to digests/worlds admitted by the active manifest and, for R2
and later, to the exact invocation targets declared for the immutable
alias-bound caller principal. The mechanism-state v1 format does not permit package-driven key
rotation: certifier rotation or revocation requires an explicit operator
migration and remains release governance, not component policy. The certifier
private key remains external to both release packages and native mechanism
state.

The active and last-known-good graph pointers are atomically persisted with the
activation handle's one-owner transfer. A successful commit makes the source
graph unable to inspect, replay, commit or roll back that handle; only the exact
same principal seed in the verified target graph can use it. A successful
rollback transfers ownership back under the same checks. A missing target seed,
missing host-import alias, stale source, wrong graph or wrong seed fails without
changing the active graph or source-owned staged record. This is an atomic
ownership move, never cross-graph sharing.

A state migration is an admitted component; the substrate supplies old state
bytes and commits returned bytes only as specified by the activation
transaction. It does not contain schema-specific migration code.

For profile v3, HTTP operation records are likewise graph- and
principal-qualified. `start` creates at most one native dispatch attempt for an
exact request digest. Restart may resume a not-yet-issued prepared intent or
poll an already-issued operation, but it may not turn an issued or indeterminate
record back into a fresh send. A terminal result is replayed from durable bytes.
This rule prevents native retry policy while allowing the exchange component to
make a later, explicit policy decision using a new component-owned
idempotency/request identity.

## Versioned compatibility

The named bounded-local R1 releases used a v1 derivation/profile model in which
the statically composed root received a graph-union grant. Their retained
reports remain historical evidence for those exact releases; they do not prove
the R2/R3 isolation rule. A kernel may retain the explicitly versioned v1 path
to replay or inspect those packages, but every new component-complete release
MUST use the per-consumer alias model above. Profile v2 keeps HTTP disabled.
Only profile v3 plus the exact separate HTTP constraint may enable it. The v1
compatibility path cannot be silently selected for a v2/v3 descriptor/profile
or used as evidence for an R2/R3 claim, and v2 evidence cannot qualify R3
transport.
