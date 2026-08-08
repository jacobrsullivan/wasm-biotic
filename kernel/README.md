# Wasm-Biotic native kernel

This standalone crate is the policy-neutral native substrate for a versioned,
content-addressed WebAssembly component graph. It does not depend on the
repository's transitional native control plane or native capability services.

The local production path:

- generates typed bindings from `wasm-biotic:factory@0.1.0` and links only the
  eight declared substrate mechanisms, with no WASI linker;
- verifies canonical graph, metadata, substrate-profile and derivation-
  descriptor bytes through their complete SHA-256 chain;
- requires every admission to carry a canonical Ed25519 release certification
  from the independently operator-pinned public key; the signed statement
  binds the manifest, native inventory, WIT, raw and derived components,
  metadata, descriptor, profile, configurations, constraints and the opaque
  offline strict-validation report;
- validates every raw component's declared imports and exports, every derived
  executable's closed host surface, and the exact root/invocation-target set;
- independently recomputes every R2 principal seed and content-derived import
  alias, then links each alias to one immutable context containing the admitted
  graph, consumer, principal, scoped component, executable, capability, scope
  and constraint identities;
- exposes no canonical host import on the R2 path: callable authority comes
  only from the active principal selected by the immutable alias closure, while
  legacy `RunRequest` grants are canonical non-escalating compatibility and
  resource metadata derived from the target executable's signed principals;
- persists immutable blobs, opaque transactions, requested wakes, component
  completions, verified activation references, audit entries and non-exportable
  Ed25519 key material under one explicitly configured directory, with R2
  operations, handles and idempotency state owned by the graph-qualified caller
  principal; and
- provides a bounded external HTTP byte mechanism only for an exact v3
  alias-bound constraint intersected with immutable operator v2 capacity. The
  adapter pins a fully validated DNS answer, requires TLS 1.3, WebPKI trust and
  a signed peer-SPKI pin, sends exact HTTP/1.1 request semantics, follows no
  redirects, retries nothing, bounds every resource and durably records the
  dispatch uncertainty boundary; and
- instantiates Component Model artifacts under the intersection of immutable
  operator capacity, the exact alias-bound principal scope and per-run resource
  limits.

The native substrate never dispatches on factory role, service, workflow or
policy names. The offline tool proves semantic coverage and signs its canonical
report. Native admission hashes that report but never parses its role or
operation contents; it verifies only the closed content statement, signature
and operator trust identity. HTTP origin labels, credential handles, request
bytes and response bytes are likewise opaque to native workflow logic. Signed
v1/v2 profiles and operator capacity v1 remain transport-disabled.

## Activation and launch

`activation.active-manifest()` returns the exact verified canonical manifest
`BlobRef`. A root export cannot run unless its graph is the durable active
manifest. Activation stage and rollback accept only manifests with a fully
verified root binding; storing or merely naming a graph digest is insufficient.
An R2 commit also atomically transfers its single activation-handle owner from
the source graph principal to the admitted target graph's exact same principal
seed, after verifying that target principal retains the `activation`/`switch`
import. Rollback transfers it back to the verified last-known-good graph under
the same rule. This preserves graph-qualified ownership across a lifecycle
without ever sharing the handle between graphs.

The manager supports a one-time compare-and-set bootstrap, restart from the
content store, inactive candidate admission, activation reload and restoration
to the verified last-known-good graph when a selected graph fails integrity or
instantiation. Initialization persists both operator-selected mechanism
capacity, one exact trusted bootstrap-manifest digest and one raw Ed25519
certifier public key. None can be changed by presenting a package or reopening
the state directory. Every candidate must have a valid certificate from that
key. A package whose manifest differs from the separate initial trust anchor is
also rejected before it can become the first active root. The `admit` path may
instantiate a correctly certified inactive candidate without selecting it.
Later activation remains a decision of the active Wasm component graph.

The policy-neutral local launcher consumes the deterministic graph-package
layout and separates operator initialization from package admission:

```sh
# Persist safe generic defaults (including no transaction namespaces), one
# exact initial manifest trust anchor and the reviewed certifier's raw Ed25519
# public key. Pass the reviewed config below when the graph needs explicitly
# allowed opaque namespaces or different generic bounds.
cargo run --locked --offline --manifest-path kernel/Cargo.toml --bin wasm-biotic-kernel -- \
  init PATH_TO_MECHANISM_STATE sha256:TRUSTED_MANIFEST CERTIFIER_PUBLIC_KEY_HEX [kernel/operator-config.example.json]

# Verify, store and instantiate a candidate without switching activation.
cargo run --locked --offline --manifest-path kernel/Cargo.toml --bin wasm-biotic-kernel -- \
  admit PATH_TO_GRAPH_PACKAGE PATH_TO_MECHANISM_STATE [PATH_TO_HTTP_MATERIALS]

# Bootstrap or boot the active graph, then accept one typed JSON ingress
# envelope per stdin line and emit one typed JSON result per stdout line.
cargo run --locked --offline --manifest-path kernel/Cargo.toml --bin wasm-biotic-kernel -- \
  serve PATH_TO_ACTIVE_GRAPH_PACKAGE PATH_TO_MECHANISM_STATE [PATH_TO_HTTP_MATERIALS]
```

`operator-config.example.json` is canonical JSON using the closed
`wasm-biotic.operator-mechanism-capacity.v1` schema. It contains only generic
mechanism bounds and the three opaque transaction namespaces reviewed for the
current release graph. It is an explicit operator input, never package
authority. Unknown fields, duplicate or non-canonical namespace sets,
non-canonical JSON, capacity changes, bootstrap-anchor changes and certifier-key
changes fail closed. The certifier's PKCS#8 private key is an external offline
packager input; it is never copied into a release package or mechanism state.

`operator-config.http.example.json` is the canonical closed v2 form. Its HTTP
section is an operator ceiling, so the effective capacity may be narrower than
the signed constraint but can never widen it. External material is supplied in
an owner-only directory and is never persisted:

```text
PATH_TO_HTTP_MATERIALS/       mode 0700
  credentials/               mode 0700
    OPAQUE_HANDLE             regular file, mode 0600
  tls-roots/                  mode 0700
    OPERATOR_ROOT.der         DER certificate, mode 0600
```

Components receive only an opaque credential handle. The adapter validates the
destination and TLS peer before reading the credential, injects it at the exact
signed header/prefix binding, rejects any response that reflects the bytes and
stores neither the credential nor the material path.

## Verification

Run isolated verification with:

```sh
CARGO_HOME=/tmp/wasmbiotic-cargo \
RUSTUP_HOME=/tmp/wasmbiotic-rustup \
CARGO_TARGET_DIR=/tmp/wasmbiotic-kernel-target \
cargo test --locked --offline --manifest-path kernel/Cargo.toml

python3 kernel/tools/native_tcb_inventory.py --check
python3 -m unittest kernel/tools/test_native_tcb_inventory.py
```

[`native-tcb.json`](native-tcb.json) is the machine-readable native boundary
inventory. For the exact signed graph, TCB and bounded-local profile named by
the current R2 release, it declares the component-complete architecture claim.
That claim is deliberately exact to its signed bounded-external profile: the
services implement bounded semantics, and a changed graph, profile, native
closure or target requires a new release. Release certification
authenticates offline semantic validation and exact bytes; it does not move
semantic policy into native code or replace the separate exact
initial-manifest pin.

The versioned v1 path is retained only for replaying the named R1 packages,
whose composed root used a graph-union grant. It cannot be selected by an R2
descriptor or substrate profile and is not evidence for R2 isolation.

Release tooling can inspect a persisted generic completion or provenance
through native read-only evidence methods. They are not linked into any
component world and do not weaken the principal-owned WIT poll/cancel path.

The current bounded-external native closure is content-addressed by source
closure `sha256:474e316efc9a8a3686300fd0ed0ea274a9780b096e0f3d2dad57473c99cd4322`
and inventory
`sha256:3b7cf13a9308e94d4847d3cfceb80e6a4304f00482f4a83507091f4c24fbebf0`.
The optimized native artifact and detached build attestation are generated and
bound by the release gate; this source document does not predeclare a host- or
toolchain-specific artifact digest.

The ignored `r3_signed_http_gate` integration test is the exact-package public
execution gate. A release harness provisions an ephemeral TLS endpoint and the
owner-only material directory, then supplies `WASM_BIOTIC_R3_PACKAGE`,
`WASM_BIOTIC_R3_STATE`, `WASM_BIOTIC_R3_HTTP_MATERIALS`,
`WASM_BIOTIC_R3_ARTIFACT`, `WASM_BIOTIC_R3_TRANSFER_TEMPLATE_JSON`,
`WASM_BIOTIC_R3_CONSTRAINT_DIGEST` and `WASM_BIOTIC_R3_SECRET_SENTINEL` before
running that ignored test explicitly. The gate uses public mechanism APIs to
store the artifact, replace the template's artifact digest/size with the exact
result, create the named non-exportable Ed25519 key, store the canonical
transfer and construct its ingress BlobRef. A template has this shape (the
endpoint is the ephemeral gate URL and expiry must be in the future):

```json
{
  "artifact": {
    "digest": "replaced-by-gate",
    "media_type": "application/wasm",
    "size_bytes": 0
  },
  "destination_url": "https://127.0.0.1:PORT/exchange",
  "expires_at_ms": 4102444800000,
  "idempotency_key": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "receiver": "factory-b",
  "schema": "wasm-biotic.transfer-request.v1",
  "sender": "factory-a",
  "signing_key_handle": "r3-exchange-signing-key",
  "transfer_id": "r3-signed-http-gate",
  "transport_credential_handle": "exchange-api"
}
```
