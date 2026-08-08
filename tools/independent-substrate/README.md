# Independent substrate reproducer

This crate is a dependency-independent implementation of the native
Wasm-Biotic substrate boundary. It does not depend on `wasm-biotic-kernel` or
`aiaf-v1`. Native code implements only the eight fixed WIT mechanisms:
blob-store, transaction-store, clock, component-runner, HTTP transport, key
service, activation and audit log. It contains no dispatch on worker roles,
service families, workflows or factory policy.

Package admission verifies the pinned Ed25519 signature and reconstructs the
complete content-addressed artifact closure from package bytes. Profile v1
retains the R1 graph-union host context. Profile v2 additionally verifies every
principal seed and import alias by canonical recomputation, the exact equality
of direct grants, host bindings and aliases, the scoped-component closure, and
the callable import/export surfaces of every scoped and derived component.
Canonical host imports are rejected from R2 scoped and derived surfaces.

Profile v3 retains that exact principal and scoped-component model and admits
one additional signed projection: the `exchange-service` HTTP import alias is
bound to a separate canonical
`wasm-biotic.http-transport-constraints.v1` object. Admission independently
closes the origin, canonical path, whole DNS answer-set policy, TLS 1.3 server
name and SPKI pins, methods, header names, byte/time/concurrency limits,
redirect denial and opaque credential placement. Every non-HTTP import must
still reference the exact shared ceiling bytes.

At R2 runtime each signed alias is linked to one immutable consumer context.
That context supplies the caller principal; components cannot choose or forge
it as an input. Poll, cancel and idempotency identities are caller-owned, and
component-runner targets must be declared invocation edges of that caller.
Activation ownership is graph-qualified: commit atomically hands the same
activation-authorized principal seed from the active source graph to the
admitted target graph, and rollback hands it back only to the verified
last-known-good graph. Stale graph contexts, wrong seeds and targets without
the same `activation:switch` authority fail closed.
The same generic WIT mechanism implementation remains in use for R1 and R2.

For R3 only, the HTTP mechanism performs one asynchronous bounded HTTPS
dispatch. Its journal identity includes graph, principal, alias, constraint
and idempotency key. Exact replay returns the same operation; changed request
bytes conflict. A durable `Dispatching` record with no terminal fact recovers
as `Indeterminate` and is never automatically resent. DNS is resolved once;
the complete sorted answer set must pass both the signed address policy and an
immutable local operator CIDR capacity, after which one deterministic address
is pinned while preserving the original Host and TLS server name. The same
intersection is applied independently to exact origins, methods, request and
response headers, credential handles and every numeric ceiling. Operator
widening cannot add authority absent from the signed graph.

`InMemorySubstrate::new` leaves HTTP disabled even for profile v3. An embedding
must opt in with `InMemorySubstrate::new_with_http_capacity` and a closed,
enabled `HttpOperatorCapacity`; a missing, disabled, malformed or narrower
capacity fails closed. Redirects, proxies, client defaults and ambient
credentials are disabled. Operator credential bytes live only in a separate
in-memory vault, are appended after authorization, and are scanned out of
every response header and body before guest exposure. The substrate returns
only raw status, exposed headers, optional opaque body bytes and a factual
receipt; provider meaning, retry, fallback and response policy remain
component-owned.

Profile v1 and v2 retain their prior HTTP behavior exactly: `start` reports
`transport-unavailable`, `poll` returns no completion and `cancel` returns
false.

## Independent reproduction

The reproduction client constructs the canonical bounded `kernel-probe`
source-change fixture. It validates the resolved 12-operation semantic
closure, proves exact submit replay leaves bytes, provenance and mechanism
state unchanged, and verifies that all six workers plus the admitted tool ran
with descriptor-exact signed provenance. Package reference evidence is
compared only after those independent checks.

```sh
RUSTUP_HOME=/private/tmp/wasmbiotic-rustup \
CARGO_HOME=/tmp/wasmbiotic-cargo \
CARGO_TARGET_DIR=/tmp/wasmbiotic-independent-release-target \
cargo run --locked --offline --release \
  --manifest-path tools/independent-substrate/Cargo.toml \
  --bin wasm-biotic-independent-substrate -- \
  --release /path/to/sha256-graph-package \
  --certifier-public-key-hex RAW_PUBLIC_KEY_HEX
```

The profile selects the report contract and default output:

- R1: `wasm-biotic.independent-substrate-reproduction.v1` at
  `artifacts/component-complete/2026-08-03-r1-independent-substrate-reproduction.v1.json`.
- R2: `wasm-biotic.independent-substrate-reproduction.v2` at
  `artifacts/component-complete/2026-08-03-r2-independent-substrate-reproduction.v2.json`.
- R3: the same principal-evidence report shape at
  `artifacts/component-complete/2026-08-03-r3-independent-substrate-reproduction.v2.json`;
  the embedded profile identity and schema distinguish the R3 release.

Use `--attestation PATH` to override the output. R2 adds signed principal
inventory identity, fixed-alias enforcement facts and observed caller
principals. R1 omits those optional fields and retains its v1 JSON shape.

## Candidate graph shadow

The shadow binary compares an incumbent and signed successor before
activation. It runs the same bounded source/event corpus in two separately
allocated mechanism roots, exercises the complete six-worker cycle and all
seven declared capability-service families, and compares terminal, service,
provenance and generic-mechanism behavior after normalizing only the
graph-derived identities listed in the report.

```sh
RUSTUP_HOME=/private/tmp/wasmbiotic-rustup \
CARGO_HOME=/tmp/wasmbiotic-cargo \
CARGO_TARGET_DIR=/tmp/wasmbiotic-candidate-shadow-target \
cargo run --locked --offline --release \
  --manifest-path tools/independent-substrate/Cargo.toml \
  --bin candidate-graph-shadow -- \
  --incumbent /path/to/incumbent-package \
  --candidate /path/to/successor-package \
  --certifier-public-key-hex RAW_PUBLIC_KEY_HEX
```

An R2 pair emits `wasm-biotic.candidate-graph-shadow.v3` by default at
`artifacts/component-complete/2026-08-03-r2-candidate-graph-shadow.v3.json`.
The v3 graph identities bind the derivation descriptor, substrate profile and
principal inventory, and normalized provenance retains caller principal
seeds. Use `--report PATH` to override the output. The retained R1 path still
emits `wasm-biotic.candidate-graph-shadow.v2`.

## Principal-isolation campaign

The R2-only adversarial client independently proves the fixed alias boundary.
It attempts a forged alias, cross-capability use, cross-principal wake
poll/cancel, transaction idempotency theft, an undeclared caller-to-target run,
cross-principal run poll/cancel, and a graph-qualified activation owner handoff
across an exact signed incumbent/successor pair. The handoff campaign rejects
stale graph contexts, wrong seeds and wrong rollback targets, reconstructs the
target context before rollback, and proves owner handback after reconstructing
the source context. Every rejected action must leave the mechanism snapshot
unchanged and protected operations intact. The report self-binds the exact
certification, graph, descriptor, profile and principal-inventory identities
of both signed releases.

```sh
RUSTUP_HOME=/private/tmp/wasmbiotic-rustup \
CARGO_HOME=/tmp/wasmbiotic-cargo \
CARGO_TARGET_DIR=/tmp/wasmbiotic-principal-isolation-target \
cargo run --locked --offline --release \
  --manifest-path tools/independent-substrate/Cargo.toml \
  --bin principal-isolation -- \
  --incumbent /path/to/r2-incumbent-package \
  --successor /path/to/r2-successor-package \
  --certifier-public-key-hex RAW_PUBLIC_KEY_HEX
```

It emits `wasm-biotic.independent-principal-isolation.v1` at
`artifacts/component-complete/2026-08-03-r2-independent-principal-isolation.v1.json`.
Use `--report PATH` to override it.

The release private key is neither needed nor accepted. All three reports
leave `component_complete_claim` false; the aggregate release process owns
that all-gates claim. Shadow equivalence is intentionally bounded to its exact
declared corpus rather than every possible future input.
