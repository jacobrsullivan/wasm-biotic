# Component graph package

This tool builds the 22 raw Wasm-Biotic nodes to `wasm32-wasip2`, derives one
deterministic scoped component and immutable principal for every node, and
renames each direct substrate import to a globally unique, digest-derived
Component Model import alias. It composes the real root and every admitted
dynamic target from those scoped components with `wasm-tools compose`, repeats
every rewrite and composition to prove byte reproducibility, and rejects any
canonical substrate import that survives in a derived executable. Pure nodes
are scoped and retained too, so the principal inventory always covers the
complete graph.

The resulting R2 profile grants only each node's direct host imports. It does
not collapse the host requirements of a composed closure into its root or
worker authority. The package retains raw authority digests, scoped source
digests, principal seeds, derived executable digests, and composition recipes
as distinct content-addressed provenance. The strict report also proves exact
ownership of the 21 required semantic component kinds, seven activated service
families, and all 27 operation-to-family mappings. The native kernel never
interprets those factory facts; it verifies their report digest, exact artifact
closure, and operator-pinned signature.

The integration execution is a complete lifecycle, not only a root probe. It
runs an incumbent six-worker cycle, asks the incumbent components to bind their
initial opaque state, admits a signed successor without selecting it, asks the
components to migrate and activate the successor, reloads and runs a successor
six-worker cycle, feeds an unhealthy observation to successor policy, commits
the component-requested rollback, reopens the mechanism state and runs another
incumbent cycle. The canonical
`evidence/component-lifecycle.json` retains the exact component result objects,
generic mechanism completions, receipts and graph-bound provenance for those
steps.

No `.wasm` file is checked into the repository. Build targets and release
artifacts live under `/tmp` by default. The certifier private key is an external
PKCS#8 input and is never copied into the release or mechanism state.

```sh
# Example local evidence key only; release key custody is an operator process.
openssl genpkey -algorithm ED25519 -outform DER \
  -out /tmp/wasm-biotic-certifier.pk8

RUSTUP_HOME=/tmp/wasmbiotic-rustup \
CARGO_HOME=/tmp/wasmbiotic-cargo \
WASM_TOOLS=/tmp/wasmbiotic-cargo/bin/wasm-tools \
/tmp/wasmbiotic-cargo/bin/cargo run \
  --manifest-path tools/component-graph-package/Cargo.toml --locked -- \
  --certifier-pkcs8 /tmp/wasm-biotic-certifier.pk8 \
  --certifier-identity local-offline-strict-validator \
  --out /tmp/wasm-biotic-component-graph
```

The default command remains the byte-compatible R2 package path. Supplying
`--r3-http-constraints PATH` selects profile v3, validates the closed JSON
configuration, canonicalizes it, assigns its digest only to the
`exchange-service` HTTP alias, and emits it beside the unchanged shared v1
ceiling under `constraints/`:

```sh
/tmp/wasmbiotic-cargo/bin/cargo run \
  --manifest-path tools/component-graph-package/Cargo.toml --locked -- \
  --certifier-pkcs8 /tmp/wasm-biotic-certifier.pk8 \
  --certifier-identity local-offline-strict-validator \
  --r3-http-constraints \
    tools/component-graph-package/r3-http-constraints.example.json \
  --out /tmp/wasm-biotic-component-graph-r3
```

The checked-in example is a shape and local-fixture template, not production
network authority: replace its address, port and placeholder SPKI pin with the
exact reviewed TLS endpoint before signing a release. Its `exchange-api`
handle names only non-exportable operator custody; no secret belongs in the
constraint file.

The tool prints the certificate, report and certifier-key digests plus the raw
public-key hexadecimal value required by the separate `kernel init` trust
configuration. `certification/release-certification.json` signs the manifest,
native-TCB inventory, exact WIT/worlds, metadata, raw, scoped and derived artifacts,
derivation descriptor, substrate profile, composition configurations,
constraints and `evidence/strict-validation.json` digest.

Both OpenSSL Ed25519 PKCS#8 v1 documents and Ring-style PKCS#8 v2 documents are
accepted. For v1, the public key is derived from the private seed; for v2, the
embedded public key is additionally checked. The private document is read only
for signing and is never copied into either release package or mechanism state.

The authoritative identities for a run are the digests printed by the tool.
Each `scoped-components/<digest>.wasm` artifact is bound by
`substrate-profile.json` to one graph-node principal and its exact direct host
aliases. Each executable in `derivation-descriptor.json` binds the complete
sorted raw, scoped, and principal-seed closure that produced it. The kernel
links an alias only to that principal's declared scope and constraints; no
caller identity is accepted from component-controlled memory.
