# Wasm-Biotic

Wasm-Biotic is a bounded, local-first factory whose production workload is a
versioned, content-addressed graph of WebAssembly Component Model components.

> A Wasm-Biotic factory is a versioned, content-addressed graph of Wasm
> components. Its native substrate may instantiate, meter, persist,
> communicate and enforce declared capabilities, but may not implement factory
> roles, services, workflows or policy.

Rust is welcome inside the factory when it is compiled to a component and
admitted by digest. Native Rust is limited to substrate mechanism. The native
`aiaf-v1` control plane and capability services at the repository root are
transitional reference implementations, not the final architecture.

<!-- wasm-biotic.active-truth.v1:begin -->
{"schema":"wasm-biotic.active-truth.v1","operational_decision":"not_yet","historical_phase04_scope":"historical_record_completeness_only","historical_lineage_decision":"closed","federation_posture":"bounded_local_first_no_public_federation","roadmap_status_authority":"notes/ROADMAP.md","claim_catalog_version":"1.0.0","claim_catalog_digest":"sha256:428a5e6620591198c7b0fe9e923956e4b807cb5a74a9d374f86131b8f589fe02"}
<!-- wasm-biotic.active-truth.v1:end -->

## Current status

R3 is the current bounded release. Its signed claim profile is
`r3-bounded-external-transport-v1`. It retains R2's per-consumer least-authority
model: each of the 22 graph nodes has a sealed principal record, and the graph's
34 residual host imports are rewritten to 34 unique content-derived aliases.
The kernel resolves each alias to that exact consumer's declared capability,
scope and constraints. Guest-supplied metadata cannot select or widen the
principal.

R3 adds one content-derived `http-transport` alias for the `exchange-service`
component. A signed constraint fixes the exact origin, path, address rule, TLS
peer, methods, visible headers, byte/time/concurrency limits, redirect denial
and credential placement. Operator configuration may disable or narrow the
grant, never widen it. Provider choice, request construction, response meaning,
accounting, retry, fallback and workflow decisions remain in Wasm components;
native code transports opaque bytes and records generic durable operation facts.

The incumbent and successor were composed, strictly validated, signed,
admitted and run. They retain the bounded software-change workflow established
in R1, R2's graph-qualified activation handoff/rollback and per-consumer
isolation, and add exact single-dispatch HTTP durability. The production gate
passed 76/76 tests. A one-shot pinned TLS peer saw exactly one TLS 1.3
`POST /exchange`; restart replay saw no second request. Production and
separately implemented substrates agree on the signed transport and principal
boundaries.

The complete Ed25519-signed R3 byte closure records C0–C7 `pass`, no blockers,
`component_complete_claim: true` and `external_north_star_claim: false` for the
exact cohort below. This is a component-complete factory with one qualified,
bounded transport mechanism. It is not the broader external North Star.

The useful workflow remains deliberately narrow. Its language is
`wasm-biotic:text-program@1`, its workspace is supplied inline, its ordinary
provider is `local-fixture`, and package/evidence stores and deployment records
are local. The R3 transport proof uses one explicitly reviewed loopback TLS
peer; it is not a qualified live-provider integration. The project still does
not claim arbitrary Rust/Cargo builds, unrestricted repository editing, remote
registries, general internet access or production deployment. The broader
external North Star remains **Not yet**.

[`notes/ROADMAP.md`](notes/ROADMAP.md) is the status authority. Historical test
counts and native-reference milestones prove only the exact reference trees
and scopes named by their evidence; they do not prove the component graph.

## Exact production-shaped evidence

The exact signed R3 release completed on 2026-08-03 is:

| Evidence item | Exact identity or result |
| --- | --- |
| Durable signed release root | [`sha256:ed9eedf3633533cb877a0e0636f9b75a1a0050f426af623fc1ab5e934849e8c9`](artifacts/component-complete/releases/sha256-ed9eedf3633533cb877a0e0636f9b75a1a0050f426af623fc1ab5e934849e8c9/) |
| Signed claim manifest | `sha256:d4004e13e7e4b4bfdea4a77ad6a217e575a82df91af9b9c5dec156448bf74d74`; profile `r3-bounded-external-transport-v1`; component-complete true; external North Star false; C0–C7 `pass`; blockers empty |
| Incumbent / successor graph | `sha256:ef9c8aac3b08848d3df56d069df0df405251786e4afb3dd95e1098dd08195eb4` / `sha256:f98f2f8b6be93e3d9342472a54c08ffa7e976d49a796e8f300a116650d6bbebd` |
| Incumbent / successor principal inventory | `sha256:c010527b30e7da663b50c3f11c202a92ac8c5e3625198a40827be9c835686f48` / `sha256:0cfff11ab294c9c9f6c2a0311f8e1e544cf220ff02d66a1888a9e720639572b5`; 22 principals and 34 unique host-import aliases in each graph |
| Per-consumer derivation descriptor | `sha256:2dd99c6f220ae0a724aa61f3d5cdfde96cab3b51eb613d2ba27914412c19250a` for both graph packages |
| Capability profile / WIT / HTTP constraint | `sha256:2fb2661abe9fa3d6f4bc390e0b6f4d4d2c86a6f4aa821c793148562940660719` / `sha256:b7e64a6a131af7a89ab27a0488b1f020f5e26620a1c10abbaeb06f27d6ed2633` / `sha256:1c8129a9af4cd3fdd7d1a355de8f82182255d160ce65ddf2a6f499490f746bf8` |
| Certified kernel TCB / optimized substrate | `sha256:3b7cf13a9308e94d4847d3cfceb80e6a4304f00482f4a83507091f4c24fbebf0` / `sha256:4e5f138bed257dd644e9d7738d9679985552c2c6e988e997e36e2a8aa9337df9`; `aarch64-apple-darwin` |
| Incumbent / successor certificates | `sha256:4d520c4ba12e90fc7eb459dc133e2f9688de247174620ae7c8237c2d688e4333` / `sha256:ff35d0ad652fbc3f384d8d95f7f517bc18eb079a5d4d49bf37a6397d0a758313` |
| Certifier public key | Raw Ed25519 key `033212831d4f2022bce8bc70e8f4d7d970b41e1d32a35a207dd0d7731db9352a`; identity `sha256:7bbbb6a94cb24edf5ccbaa34129598698deaf3aa5115130abb85602ab68f3014` |
| Signed semantic admission / lifecycle | `sha256:1fe8505236908af56e20c10f7a2b4fde96fb7230580197ba6ab8b0d32048b750` / `sha256:5dff70d768861479ef967b54e4e7f0cf6dde464e209817f29eb43dd685b1d70d` |
| Principal / transport confinement | `sha256:e9dd426d9547265bdce371e9f37174b752ec167ac5cfe71c0f44ab5e99964333` / `sha256:769dd9cedaef040b166b07d48bba6540cf6f5d81e139bb0e8a14f3e082ebdb16` |
| Behavioural / adversarial / durability | `sha256:dddccefcdacc4342570551554cbf867bc0c5c53762b063c2d6202d95a916680f` / `sha256:242dca1a6558232ce10455e174ad707d71a522f978fbcbc5a9f72e4066029abd` / `sha256:09ed7cfa28140a2141551f4f493ff2822980523744ea55a75cb42559149e5ca2` |
| Candidate shadow / independent substrate | `sha256:b29c9d1447ac3d702adeaaee23c58d385135d418fb55bedec9430ff000cd7d36` / `sha256:7e638f17f3b6f3fa92fb43ca193334bbb6cdf8f58e081fd692fb9d0d471a7ed2` |
| Native build attestation | `sha256:968ccf4bbd3dbb28c16178009398f12f883f570d2db353f5e0b74a458a5b3993` |
| Post-publication bundle negatives | 17/17 tamper controls rejected; report `sha256:dfac56a36bcfa2c11e068857c5e472230a29bbabd8832b8db248c90848575be3`; pristine 239-file closure unchanged |
| Retained closure | Both exact package trees, native executable and source, public key, normative contract, signed admission and all mandatory R3 reports under bundle-relative paths |

The R3 root above is the current aggregate authority. R2 remains preserved at
[`sha256:0cb0ba1aad8676e38f535bdf1dfac030e43d2891704a0e629844bdb0a2bd4a52`](artifacts/component-complete/releases/sha256-0cb0ba1aad8676e38f535bdf1dfac030e43d2891704a0e629844bdb0a2bd4a52/)
as the historical per-consumer bounded-local baseline. R1 and R0 retain their
earlier scopes; none is the current release identity.

## What the bounded factory represents

The present component graph represents one bounded local source-change
workflow, not an unrestricted autonomous computer. Its components can:

- accept and durably inspect a factory job;
- reduce supervisor events into durable state and commands;
- route the fixed six-stage workflow through planner, builder, validator,
  reviewer, packager and continuity workers;
- open and snapshot an inline workspace, apply one exact-CAS text patch, and
  schedule the resulting local job;
- compile a declared `wasm-biotic:text-program@1` program, discover and run its
  test, and block packaging when validation or review fails;
- obtain a deterministic `local-fixture` proposal, review it, publish and
  verify a local content-addressed package, and publish and resolve evidence;
- store immutable inputs, state, outputs, receipts and audit material by
  content digest;
- perform bounded exchange, state-migration, graph-evolution and closure
  evaluation semantics;
- invoke a graph-admitted tool component by exact digest; and
- expose the component-owned factory API through the generic root launcher.

The bounded cycle executes 12 service operations across all seven service
families. R3 also demonstrates signed admission, component-owned evolution and
rollback, admitted-tool execution, isolated successor shadowing,
restart-stable state, exact replay and per-consumer enforcement on two
substrates. It does not claim exhaustive useful-work coverage of all 27 named
operations. It has no host filesystem, shell or native-process escape. HTTP is
available only through the exact signed, consumer-bound R3 grant.

## The 22-node release graph

The current 22-node topology is frozen in
[`tools/component-graph-package/release-v1.json`](tools/component-graph-package/release-v1.json).
R3 retains a separately scoped component and principal record for every node;
the topology stayed stable while the bounded transport profile changed.

| Group | Component nodes | Count |
| --- | --- | ---: |
| Durable control and routing | `factory-control`, `supervisor-reducer`, `worker-router`, `capability-router` | 4 |
| Workers | `planner-worker`, `builder-worker`, `validator-worker`, `reviewer-worker`, `packager-worker`, `continuity-worker` | 6 |
| Capability services | `build-service`, `validation-service`, `review-service`, `packaging-service`, `continuity-service`, `scheduling-service`, `operations-service` | 7 |
| Evolution and protocols | `factory-evolution`, `state-migration`, `exchange-service`, `closure-evaluator` | 4 |
| Admitted tool fixture | `admitted-tool-probe` | 1 |
| **Total** |  | **22** |

The seven capability services own the 27 operation meanings carried from the
native oracle. The exhaustive semantic and operation map is in
[`contracts/component-complete/README.md`](contracts/component-complete/README.md).

The bounded operation inventory is:

| Capability-service component | Component-owned operations |
| --- | --- |
| `build-service` | `workspace-open`, `workspace-snapshot`, `workspace-patch`, `candidate-build`, `command-execute` |
| `packaging-service` | `package-publish`, `package-verify` |
| `validation-service` | `validation-prove`, `validation-compare`, `factory-execute`, `factory-provider-proposal`, `factory-shadow` |
| `review-service` | `review-candidate` |
| `continuity-service` | `evidence-publish`, `evidence-resolve` |
| `scheduling-service` | `schedule-job` |
| `operations-service` | `deployment-initialize`, `deployment-activate`, `deployment-observe`, `deployment-rollback`, `operations-inspect`, `factory-initialize`, `factory-state-migrate`, `factory-activate`, `factory-observe`, `factory-rollback`, `factory-inspect` |

The operation token, request and response meanings are evaluated in those
components. The substrate sees only the primitive requested, an opaque scope,
immutable constraints and bytes needed for enforcement.

## The native boundary

The standalone [`kernel/`](kernel/) crate is the production native substrate.
It does not depend on the transitional `aiaf-v1` package. It may implement only
these eight WIT interfaces:

| Native mechanism | What it may do | What remains component-owned |
| --- | --- | --- |
| `blob-store` | Verify, quota, put and get immutable bytes | Meaning of packages, evidence and workspaces |
| `transaction-store` | Opaque namespaced reads and atomic reference updates | State transitions, retries and invariants |
| `clock` | Return time and deliver an explicitly requested wake | Scheduling, deadlines and retry policy |
| `component-runner` | Verify, instantiate, meter, interrupt and collect a result | Role selection and success meaning |
| `http-transport` | Enforce declared byte-oriented destination, size and time bounds | Provider choice, prompts, parsing and retry policy |
| `key-service` | Hold non-exportable keys, sign or verify digests, provide entropy | Authorization, promotion and what should be signed |
| `activation` | Stage or atomically select an exact verified graph digest and restore last-known-good | Promotion, health, migration and rollback policy |
| `audit-log` | Append and resolve opaque hash-chained bytes | Event meaning and success evidence |

There is no production native worker, supervisor, scheduler, provider, service
router, workflow, policy engine, shell, process launcher, ambient filesystem or
ambient environment interface. `command-execute` means running an admitted
tool component, never spawning a native command.

“Self-contained” therefore means the complete component graph plus explicit,
versioned WIT imports. It does not mean the graph needs no Wasm engine,
operating system or hardware.

## Authority and composition model

Every raw component, manifest, WIT package, constraint document, composition
configuration and derived executable is content-addressed. The release tooling
checks declared WIT surfaces and reproducible composition; the kernel verifies
the sealed digest chain and enforces grants and resource ceilings before
instantiation.

R3 uses **per-consumer least authority**, not a graph-union principal. For each
graph, deterministic derivation produces:

- 22 graph-qualified principals, one for every component node;
- 22 scoped component artifacts, one for every graph node; and
- 34 unique content-derived import aliases, each bound to one consumer,
  capability, scope and constraint digest.

The package certificate seals the graph, derivation descriptor, principal
inventory, capability profile and native TCB identities. At admission the
kernel reconstructs and verifies that closure. At execution it identifies the
caller from the resolved import alias, not guest metadata, and keys mechanism
state by the graph-qualified runtime principal. Cross-principal access to runs,
wakes, clocks, idempotency records and activation handles fails closed.

Corresponding nodes retain a stable principal seed across graph versions, but
their runtime identities include the graph digest. Activation commit can move
ownership only from the admitted incumbent graph to its admitted successor for
the same seed and exact activation import. Rollback hands it back to the
last-known-good graph. Both transitions are atomic, stale owners are denied and
the ownership mapping survives restart.

## Build graph packages

The graph packager builds the 22 raw components, composes the root and dynamic
targets twice, checks byte reproducibility and WIT surfaces, writes a
content-addressed graph package, and runs its kernel integration probe. It
accepts `--out` and `--wasm-tools`; the final two output lines report the graph
manifest digest and exact package directory. Aggregate signing and durable
closure are a separate release-bundle step.

```bash
RUSTUP_HOME=/tmp/wasmbiotic-rustup \
CARGO_HOME=/tmp/wasmbiotic-cargo \
CARGO=/tmp/wasmbiotic-cargo/bin/cargo \
WASM_TOOLS=/tmp/wasmbiotic-cargo/bin/wasm-tools \
/tmp/wasmbiotic-cargo/bin/cargo run --locked \
  --manifest-path tools/component-graph-package/Cargo.toml -- \
  --certifier-pkcs8 /tmp/wasm-biotic-certifier.pk8 \
  --certifier-identity local-offline-strict-validator \
  --out /tmp/wasm-biotic-component-graph
```

Do not infer a package directory name in advance: it contains the computed
manifest digest. Retained historical package trees remain in their immutable
R0–R2 releases; the R3 package trees and native executable are inside the
current signed release root linked above. Temporary build output is not release
authority; a later build is authoritative only after it is assembled, signed
and verified as a new content-addressed release cohort.

Verify the current R3 closure with only its independently pinned public key:

```bash
python3 tools/component-release-bundle.py verify \
  artifacts/component-complete/releases/sha256-ed9eedf3633533cb877a0e0636f9b75a1a0050f426af623fc1ab5e934849e8c9 \
  --expected-public-key-hex \
  033212831d4f2022bce8bc70e8f4d7d970b41e1d32a35a207dd0d7731db9352a
```

## Admit and serve a sealed graph

The policy-neutral launcher syntax is:

```bash
# One-time initialization: persist immutable operator capacity and the exact
# graph digest trusted for first bootstrap.
cargo run --locked --offline --manifest-path kernel/Cargo.toml \
  --bin wasm-biotic-kernel -- \
  init PATH_TO_MECHANISM_STATE TRUSTED_MANIFEST_SHA256 \
  CERTIFIER_PUBLIC_KEY_HEX kernel/operator-config.example.json

# Verify, store and instantiate an inactive candidate without switching it.
cargo run --locked --offline --manifest-path kernel/Cargo.toml \
  --bin wasm-biotic-kernel -- \
  admit PATH_TO_GRAPH_PACKAGE PATH_TO_MECHANISM_STATE

# Bootstrap or boot the active graph, then process one typed JSON ingress
# envelope per stdin line and emit one typed JSON result per stdout line.
cargo run --locked --offline --manifest-path kernel/Cargo.toml \
  --bin wasm-biotic-kernel -- \
  serve PATH_TO_ACTIVE_GRAPH_PACKAGE PATH_TO_MECHANISM_STATE
```

`init` must happen before either other command. It records the operator-reviewed
generic mechanism ceilings, opaque transaction namespaces and exact manifest
trusted for first bootstrap. Omitting the optional config uses safe defaults
with no transaction namespaces; the current graph therefore uses the explicit
canonical example config. `admit` may verify and store another inactive
candidate, but first `serve` rejects a package whose manifest is not the
immutable bootstrap digest.

`serve` is a generic stdin/stdout transport. Route meaning and response policy
remain in the `factory-control` component. After bootstrap, the launcher
verifies that the supplied package is the durable active manifest, reloads a
newly activated verified graph, and retains a verified last-known-good graph
for boot failure.

The R3 admission evidence uses a canonical operator-capacity document and the
exact incumbent and successor packages named above. The production kernel
admits both signed closures, boots the incumbent, transfers graph-qualified
activation ownership to the successor and hands it back on rollback. The
component boundary probe and HTTP request/response meaning remain
component-owned; the launcher exposes only typed ingress and generic bounded
transport.

Verify the standalone kernel independently with:

```bash
CARGO_HOME=/tmp/wasmbiotic-cargo \
RUSTUP_HOME=/tmp/wasmbiotic-rustup \
CARGO_TARGET_DIR=/tmp/wasmbiotic-kernel-target \
cargo test --locked --offline --manifest-path kernel/Cargo.toml
```

## Transitional native reference oracle

The repository root package, `aiaf-v1`, contains the mature native control
plane, workers and capability services developed before the component-complete
boundary was made normative. It remains valuable for fixtures, compatibility,
behavioural comparison and historical evidence. It is not the production
factory.

Its operator binary is deliberately excluded from the default build. Invoke it
only when intentionally running the transitional oracle:

```bash
CARGO_TARGET_DIR=/tmp/aiaf-v1-target \
cargo run --locked --features transitional-native-reference \
  --bin aiaf-v1-runner -- list-scenarios
```

Only `aiaf-v1-runner` is feature-gated. The root library compiles normally
because tests use it as the behavioural oracle and the release packager uses
its offline graph validator. That build-time dependency is not linked into the
standalone production kernel.

Nothing launched through `aiaf-v1-runner` is evidence that the canonical
component factory is component-complete. The production kernel does not link
that binary or its native domain implementations. Build-time graph validation
may use host tooling outside the factory; such tools are not reachable from a
launched graph.

## Claim boundary

The architectural invariant and the complete release claim are deliberately
separate:

| Question | Current answer |
| --- | --- |
| Is the intended production workload a digest-bound component graph? | **Yes.** The contract, WIT, component sources, release definition and standalone kernel encode that architecture. |
| Is the native domain runtime the final architecture? | **No.** It is a transitional oracle; its `aiaf-v1-runner` binary is feature-gated. |
| Have exact incumbent and successor graphs executed successfully? | **Yes.** Incumbent `sha256:ef9c8a...` and successor `sha256:f98f2f...` completed substantive source-change cycles across graph-qualified activation, rollback and restart. |
| Is authority isolated per component consumer? | **Yes, for this cohort.** Each graph seals 22 principals and 34 content-derived import aliases; production and independent substrates pass the exact 26-case isolation campaign. |
| Does the exact bounded path satisfy the “only run components” architecture invariant? | **Yes.** Components own roles, services, workflow and policy; native code exposes and enforces only the eight generic WIT mechanisms. |
| Is the formal aggregate `component_complete_claim` true? | **Yes, for the exact R3 release.** The signed claim records profile `r3-bounded-external-transport-v1`, C0–C7 `pass`, no blockers and the complete bundle-relative byte closure under root `sha256:ed9eed...`. |
| Can it build arbitrary Rust/Cargo repositories or use live providers, remote registries or production deployment? | **No.** The useful workflow remains limited to an inline workspace, `wasm-biotic:text-program@1`, `local-fixture` and local content-addressed outputs. R3 adds only one signed, pinned transport grant qualified against a reviewed loopback TLS peer. |
| Is the broader North Star closed? | **No.** The active operational decision is **Not yet**; external provider, custody, review and publication requirements remain separate. |

## Transitional-oracle validation lineage (retained)

The facts below are retained because they are evidence-bound history for the
transitional native oracle, whose operator runner is feature-gated. They are
not production component-graph results.

The immutable R8 reference point is
[`artifacts/baseline/2026-07-31/m5-m7-hardened-detached-clean-evidence.json`](artifacts/baseline/2026-07-31/m5-m7-hardened-detached-clean-evidence.json),
synthetic commit `3204a1a60c289be98b2b77ac78c6451fbccc2159`, tree
`28de5fa7fece9d2ecf18ae242da84bedbec32ce0`. It recorded 967 tests and a
`NotYet` decision for that exact historical tree. The reserved R9 path is
`artifacts/baseline/2026-08-01/m5-m7-accounting-hardened-detached-clean-evidence.json`;
current-candidate validation remains conditional on that record existing and
validating. Neither record is component-factory release evidence.

The validation attempts keep reports, inferences and results distinct:

- R4, commit `c79c255ebfe48d3540adcccf37731ef3e41b16a7`, had two later
  individual passes that were operator-reported, reused a post-run target and
  were not evidence-bound. Their location supports a contention inference; it
  does not prove one.
- R5, commit `e5dbcfc385d99b8f870bfc75082f1ab28f0d9d73`, is an interrupted,
  non-authoritative attempt. The operator reported that the transcript
  invocation was attempted. Retained evidence has the invocation argv and
  empty stdout/stderr, but no start, exit, or terminal metadata. It does not
  independently establish that nested Cargo started; no canonical result
  exists.
- R6, commit `d84b491b48d96438cf3b8d8a3e60aed8664ca573`, passed five focused
  checks and was stopped during manifest preflight. It has no canonical result.
- R7, commit `eb3858f21024ab1363f224e844e63a0c64c2624a`, observed Cargo stdout
  at or above 33,561,477 bytes and combined output at or above 33,569,491
  bytes, beyond the 33,554,432-byte caps. It retained no transcript, Cargo
  exit, terminal summary, test count or cause. Later diagnostic runs are not
  evidence-bound and do not identify its cause. The repair retains no raw
  output, only an untrusted and possibly incomplete bounded hint; a fresh
  canonical run remains required.

One exact M6 diagnostic later passed in 1,473.39 seconds with 230 bytes of
stdout and no competing harness observed at 23 checkpoints sampled during the
run. An earlier process-wide file-limit attempt was an instrumentation
non-result. These observations were not evidence-bound.

A separate operator-observed stress run found that parallel M6 fixtures could
cross Bobs-mini's 256-descriptor soft limit. It is not evidence-bound here and
is not release evidence; it motivated a test-harness concurrency cap, not a
production capability claim.

## Repository layout

```text
wasm-biotic/
  wit/wasm-biotic/             # versioned Component Model contract
  contracts/component-complete/# semantic map, native rule and conformance gates
  components/                  # component implementations
  kernel/                      # standalone policy-neutral native substrate
  tools/component-graph-package/# deterministic release builder and probe
  notes/ROADMAP.md             # current implementation order and status authority
  Cargo.toml, src/, tests/     # transitional native reference oracle and fixtures
  design-and-planning/         # historical AIAF/NorthStar design lineage
  reference-docs/              # broader reference material
```

## Key documents

- [`notes/ROADMAP.md`](notes/ROADMAP.md) — completed component-complete R3 claim,
  current priorities, remaining external scope and retained R0–R2 lineage
- [`contracts/component-complete/README.md`](contracts/component-complete/README.md)
  — normative component ownership and capability inventory
- [`contracts/component-complete/NATIVE_TCB.md`](contracts/component-complete/NATIVE_TCB.md)
  — allowed and forbidden native responsibilities
- [`contracts/component-complete/CONFORMANCE.md`](contracts/component-complete/CONFORMANCE.md)
  — mandatory claim gates
- [`wit/wasm-biotic/`](wit/wasm-biotic/) — exact WIT package
- [`kernel/README.md`](kernel/README.md) — standalone kernel operation
- [`tools/component-graph-package/README.md`](tools/component-graph-package/README.md)
  — release packaging workflow

Historical material under `design-and-planning/` and `reference-docs/` remains
design lineage, not current production authority. All repositories for this
project must remain private.
