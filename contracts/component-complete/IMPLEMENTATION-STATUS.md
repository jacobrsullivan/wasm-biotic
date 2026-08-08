# Component-Complete R3 Implementation Status

Status date: 2026-08-03

Contract: `wasm-biotic:factory@0.1.0`

Scope: one exact R3 incumbent/successor cohort with bounded external transport;
historical R0/R1/R2 release records remain below

| Decision | Status |
| --- | --- |
| “Only run Wasm-Biotic components” architecture | **Satisfied for the exact R3 cohort** |
| Per-consumer least authority | **Satisfied: 22 principals, 34 unique aliases, one pure principal** |
| Atomic graph-qualified activation ownership | **Satisfied through handoff, successor use, handback and restart** |
| Bounded external HTTP mechanism | **Satisfied for one signed, alias-bound exchange grant** |
| Transport durability | **Satisfied: no native retry; ambiguous dispatch is durable and non-retryable** |
| Credential custody | **Satisfied: opaque handle only; secret bytes stay outside component and durable evidence bytes** |
| Formal aggregate `component_complete_claim` | **`true` for this exact R3 cohort** |
| Aggregate conformance gates | **C0–C7 pass; blockers empty** |
| Broader external North Star | **`false`; not claimed** |

## Plain R3 verdict

R3 keeps the R2 component graph and per-consumer least-authority model, then
enables one tightly bounded external mechanism: byte-oriented HTTPS for the
`exchange-service` component. The selected import is a content-derived alias
bound to that consumer and to one canonical
`wasm-biotic.http-transport-constraints.v1` document. No canonical HTTP import,
graph-wide grant or guest-selected caller identity exists.

The effective network grant is the intersection of signed constraints and
operator capacity. The signed side fixes the origin, path prefixes, DNS policy,
TLS 1.3 hostname and peer-SPKI pins, methods, visible headers, body sizes,
timeout, concurrency, redirect denial and credential placement. The operator
may disable or narrow those limits and make a named credential handle
available; operator configuration cannot add a destination, method, header,
pin, secret placement or other authority absent from the signed graph.

The native substrate resolves, filters and connects addresses, authenticates
the pinned TLS peer, appends a non-exportable credential after authorization,
meters bytes and time, and durably records generic operation facts. It does not
choose a provider, construct an application request, parse a response, decide
which status means success, retry, fall back, account for use or advance a
workflow. Those decisions remain in the admitted `exchange-service` and
control components.

One native `start` is one dispatch attempt. The component persists its exact
outbox envelope before dispatch and reuses those bytes on recovery. A pending
operation is polled, never resent. If bytes may have escaped but no terminal
response was durably committed, the substrate persists an indeterminate,
non-retryable result; neither native code nor restart silently redispatches it.
Terminal replay returns the stable stored fact. Cancellation may prevent a
not-yet-issued dispatch; it cannot pretend to undo bytes already sent.

Components see only the non-secret credential handle and the signed visible
header prefix. Secret bytes are appended inside native custody only after the
destination and TLS checks pass. They do not enter component memory, blobs,
journals, logs, receipts, response bodies or audit bytes.

The exact R3 release passed the reopened C0–C7 gates on production and
independent substrates, including destination/DNS/TLS confinement, signed and
operator-limit intersection, durable dispatch boundaries, replay, principal
ownership, secret scanning and single-dispatch controls. The aggregate release
manifest and content-addressed bundle are the identity authority for the exact
graphs, reports and public key. This document deliberately does not copy the
aggregate root: the normative contract tree is itself an input to that root.

R3 qualifies the mechanism against an exact pinned TLS peer; it does not prove
a general live-provider integration, external evidence custody, independent
reviewer authority, publication authority or the broader external North Star.
`external_north_star_claim` remains `false`.

## Frozen R3 non-circular identities

| Artifact | SHA-256 |
| --- | --- |
| Incumbent graph manifest | `ef9c8aac3b08848d3df56d069df0df405251786e4afb3dd95e1098dd08195eb4` |
| Successor graph manifest | `f98f2f8b6be93e3d9342472a54c08ffa7e976d49a796e8f300a116650d6bbebd` |
| Compiled exchange component | `896c0760707a661933ad6f4af8c60e01a7cd6eb855545c586e161311d57c43f8` |
| HTTP transport constraint | `1c8129a9af4cd3fdd7d1a355de8f82182255d160ce65ddf2a6f499490f746bf8` |
| Native TCB inventory | `3b7cf13a9308e94d4847d3cfceb80e6a4304f00482f4a83507091f4c24fbebf0` |
| Certifier key ID | `7bbbb6a94cb24edf5ccbaa34129598698deaf3aa5115130abb85602ab68f3014` |
| Pinned raw Ed25519 public key | `033212831d4f2022bce8bc70e8f4d7d970b41e1d32a35a207dd0d7731db9352a` |

The successor certificate binds `previous_graph` to the incumbent manifest.
Both certificates bind the exact v3 substrate profile, HTTP constraint and
native inventory. The signed aggregate supplies the remaining package,
executable, source, normative-contract and evidence identities.

## Executed R3 conformance

| Gate | Evidence established | Status |
| --- | --- | --- |
| C0 — contract | Profile v3 and the closed HTTP constraint schema bind the exact exchange consumer, alias and constraint digest | **Pass** |
| C1 — graph | Signed incumbent and successor retain exact R2 principal provenance plus one canonical R3 HTTP binding | **Pass** |
| C2 — native boundary | Production and independent substrates enforce the same byte-oriented transport contract without provider or workflow branches | **Pass** |
| C3 — behaviour | Component-owned exchange semantics form the request, interpret the response and decide every retry/terminal outcome | **Pass** |
| C4 — durability | Prepared intent, pending operation, terminal fact, indeterminate dispatch and restart replay preserve a single native attempt | **Pass** |
| C5 — isolation | Destination, DNS, TLS, method, header, size, timeout, redirect, credential, owner and idempotency escapes fail closed | **Pass** |
| C6 — lifecycle and reproduction | The signed pair, candidate shadow, independent execution and exact public transport gate bind to the same closure | **Pass** |
| C7 — retained release | The signed aggregate retains the packages, native/source/contract trees and all mandatory R3 reports with blockers empty | **Pass** |

The R3 evidence cohort adds production, independent and joined transport
confinement reports to the R2 evidence classes. It also retains signed semantic
admission, behavioural equivalence, adversarial isolation, the durability fault
matrix, candidate shadow, independent reproduction, joined principal isolation,
native-build attestation and package lifecycle evidence. Report digests live in
the signed aggregate manifest, which is authoritative and avoids copying stale
identities into the contract input that it hashes.

## R3 claim boundary

R3 broadens mechanism capability, not native semantics. The useful factory
workflow remains the bounded inline-workspace, declared text-program and local
content-addressed package/evidence slice inherited from R2. It can additionally
ask the exchange component to perform an exactly constrained HTTPS exchange
whose application meaning and retry decision are component-owned. It is not a
general internet client, ambient networking grant, provider SDK, remote
registry, production deployment platform or proof of external North-Star
closure.

Changing any graph byte, consumer/alias mapping, HTTP constraint, operator
capacity, credential binding, native source or executable, WIT package or
evidence object creates a different claim and reopens the applicable gates.

## Historical R2 release record

For the exact cohort named below, `component_complete_claim` is `true`, C0–C7
pass and the blocker set is empty.

R2 keeps the useful bounded-local component factory introduced by R1 and closes
R1's graph-wide-authority limitation. Each graph consumer now has its own
content-derived authority principal. Each direct substrate import is rewritten
to a unique per-consumer alias, and the runtime links that alias to an immutable
context containing the admitted graph, principal, scoped component, enclosing
executable, capability, scope and constraint. Guest data cannot select that
identity or borrow another consumer's host authority.

The native substrate remains mechanism-only. It may instantiate and meter
components, persist opaque bytes and handles, deliver requested wakes, enforce
exact graph edges and declared host capabilities, and atomically switch an
already admitted graph. It does not implement a factory role, capability
service, workflow, health decision, approval rule or rollback policy. Those
semantics remain inside admitted Wasm-Biotic components.

R2 is still the same deliberately narrow local software-change factory. It can
open and snapshot an inline workspace, apply a deterministic text change,
schedule work, compile and test the declared text program, review it, publish
and verify a local package, and publish and resolve evidence through the six
worker roles and seven capability-service families. It does not thereby become
a general Rust/Cargo builder, arbitrary-repository agent, live provider client,
remote registry, production deployment system or internet-enabled autonomous
software company. HTTP remains disabled in this profile.

### Implemented R2 authority model

Each exact package contains 22 independently recomputed consumer principals and
34 unique content-derived host aliases. One pure consumer principal has no host
alias; it receives no substrate authority.

- A principal seed is independently recomputed from each consumer node ID and
  raw authority-component digest.
- Every retained consumer component has its direct substrate imports rewritten
  to content-derived aliases. The signed descriptor, profile, validation report
  and package closure bind the raw, scoped and executable bytes plus the exact
  principal/alias mapping.
- R2 linkers expose only those aliases. They do not expose a canonical host
  import or graph-union fallback.
- The legacy `RunRequest` grant list is derived canonically from the signed
  executable closure and can only narrow compatibility/resource bounds. It
  does not create callable authority; the selected alias does.
- Component-run targets require an exact admitted caller-to-target edge.
  Component-run operations, clock wakes, activation handles and transaction
  idempotency are graph-qualified and principal-owned.
- Alias calls record the admitted graph, enclosing executable, runtime
  principal, exact request digest and stable result for conformance evidence.

### Activation ownership across graph changes

Activation is a generic mechanism with a necessary cross-graph lifecycle, but
it is not cross-graph sharing. A component first stages a handle owned by its
source graph and principal. Commit verifies that the exact target graph is
signed and admitted, contains the same principal seed and retains that
principal's exact `activation`/`switch` import. In the same durable transaction
that changes the active graph, the substrate rekeys the single handle record and
its idempotency pointer to the target graph principal.

After commit, the source graph cannot inspect, replay, commit or roll back the
handle. The exact successor principal can observe it and component policy can
decide whether to request rollback. Rollback verifies the last-known-good graph
under the same seed/import rule and atomically hands the record back. Missing
seed, missing import, wrong principal and stale-source attempts fail without
changing the active graph or current owner. Restart preserves exactly one
owner.

The mechanism proves identity, admission, import and atomicity. Components
still decide whether a candidate is acceptable, what observations mean and
whether activation or rollback should happen.

### Frozen R2 cohort identities

| Artifact | SHA-256 |
| --- | --- |
| Incumbent graph manifest | `0a5698fb0e22cdd9deb2b32e0bf8d3c23ec76cb3b2743c67e9f20a48a7fc943d` |
| Successor graph manifest | `75b4dc5de918865d0b73bb77fc32c41f30a0c3bbe2058ebb2c624bb58a11a2d7` |
| Composed root executable | `1f68ce6d18315b89024df39307eff27391a36dc1e2a4b28af8dbb2c59dbd09ab` |
| WIT package | `b7e64a6a131af7a89ab27a0488b1f020f5e26620a1c10abbaeb06f27d6ed2633` |
| R2 substrate profile | `916cb55f0ce3623378854b974536d9f58a7ce489f0d41437f71ee7b4f5c92835` |
| Native TCB inventory | `7d6ea4fb0e4c62084d645844c5f894f9be1eb453f6ab45bcfcecf7f52a2b01f3` |
| Native source closure | `bfb266dc2780cd143614bf16f4b16520f62d6e761e3b548c7152fcb5dfa57aba` |
| Optimized native executable | `fa6dc67649ba00421b7817909c5e5e0a7a487815c70c363ddde6a04f9f0d8944` |
| Incumbent strict-validation report | `954f7179c2b342cdb374e09e67dd56a08c37d54d2a9c6b1a3c2844152ceeaf27` |
| Successor strict-validation report | `1eb47d89a45d4fc67b3a0f5440e3660ab0716ad67b77135e16a5e92eccd2e8bb` |
| Incumbent certificate | `c468fe52a6ce7aa5b8ef5af1d2e155d783f4d2d308a2f60c262554e2edbcf768` |
| Successor certificate | `7d27387f0b2583b87ca8a379ec68adf963bf42facf6d72bfc51bd5dd5d1bee75` |
| Incumbent principal inventory | `4211d410fbc1a592d11c0b270d41157683f9f69abaa93960da1e09bef07462bf` |
| Successor principal inventory | `fdf426ed4d8ec1fbefbdc3b1cce681f0d8bd57d5f0b9c1f05bf9e966fecb693e` |
| Package lifecycle | `a6d02c8fd7d0e2423d4bab13654488f1ed6a4dc22431133991eb9a99e301762c` |
| Certifier key ID | `9429f2f6adde0bc33cafedd85d219c1e5a7e8c3ffee2a93661b34e46a6c22594` |

The successor certificate binds its `previous_graph` field to the incumbent
manifest. Both certificates bind the exact R2 profile and native inventory.
Admission verifies them against the independently pinned raw Ed25519 public key
`70bb289c70ee950e7dd85db57a873cd4771fa618c54720a48ee22da749521223`.

This staging document deliberately does not name the aggregate release root.
The aggregate builder includes this document in the retained closure, and the
public-key verifier checks that closure; inserting the resulting root here
would make the identity circular.

### Executed R2 conformance

| Gate | Evidence established | Status |
| --- | --- | --- |
| C0 — contract | Exact WIT, v2 descriptor/profile, principal inventory and content-derived alias rules are digest-bound | **Pass** |
| C1 — graph | Two signed 22-principal component graphs retain exact lineage, raw/scoped/derived bytes and 34 unique aliases | **Pass** |
| C2 — native boundary | Alias-only R2 linkers, graph-qualified principals, exact invocation edges and the eight generic mechanisms pass audit | **Pass** |
| C3 — behaviour | The useful bounded-local change path completes all six roles, seven services and 12 ordered operations | **Pass** |
| C4 — durability | Fault injection, exact replay, one-owner activation handoff/handback and restart preserve state and authority | **Pass** |
| C5 — isolation | Production and independent substrates reject cross-principal grant, handle, idempotency and target theft | **Pass** |
| C6 — lifecycle and reproduction | Incumbent, successor, component-decided rollback, restart, post-rollback cycle, shadow and independent execution pass | **Pass** |
| C7 — retained release | Aggregate builder and public-key verifier enforce the exact package, native, source, contract, principal and report closure with blockers empty | **Pass** |

The definitive R2 gate passed 48/48 named tests. The joined production-kernel
and independent-substrate principal-isolation campaign passed 26/26 cases. The
independent substrate passed 17/17 reproduction checks plus 7/7
cross-principal isolation controls. Formatting, all-target compilation, strict
Clippy, optimized build, native-inventory embedding and retained R1
compatibility also pass.

The four-phase package lifecycle executes the incumbent cycle, successor
activation and cycle, component-decided rollback, and restart plus a
post-rollback incumbent cycle. Its authority traces contain 148, 168, 5 and 148
alias calls respectively. The principal mapping remains exact across every
phase, and the activation handle has exactly one graph-qualified owner before
and after each atomic handoff.

### R2 evidence cohort

| Report | SHA-256 |
| --- | --- |
| Signed semantic admission | `91e80bc413a82265e10cc399484d1ae8dc45a9ed274aac339ded8d358aef37d7` |
| Behavioural equivalence | `dbc4c8be342d874697b2780192ec55ec62ec857bd17d56bce3f21adb0359d6b9` |
| Adversarial isolation | `15cd84b4b4926f7b782de396035dc16483d3c3f5e82477a0b166955580ec9f0c` |
| Durability fault matrix | `8a0183c25eafd1688384b829d9865bbb44034d5f246ddacda09e62bc545cadd5` |
| Candidate-graph shadow | `bd47736ad8ae5b86d2f4642f3140bad84739a6171ce124a0d230a3a98c7b7a96` |
| Independent-substrate reproduction | `a32598fdab107ddce3de7335685075f1b7b210c281200a0204cdca76ec412f5f` |
| Independent principal isolation | `258f088ca5e3acaa865376db03e19b3d1685eec0adb2868d895ce8bd40f6cf38` |
| Aggregate principal isolation | `0bd5e3f7540dbfe13624bb3147477fc2ace8e61c48c38d68c989440a1ce0ddc5` |
| Native-build attestation | `007f01d62b23423a4a24449052612735b75dc52b5d7fd49683f051a41c019237` |
| Package lifecycle | `a6d02c8fd7d0e2423d4bab13654488f1ed6a4dc22431133991eb9a99e301762c` |

### Historical R2 claim boundary

The R2 component-complete claim is true only for the exact bounded-local cohort,
native TCB and substrate profile named above. It does not claim live external
providers, enabled HTTP, remote effects, general Rust/Cargo compilation,
arbitrary repositories, production deployment, multiple native platforms or
the external North Star. Expanding those capabilities requires new admitted
components or a narrowly justified generic substrate profile, plus a new signed
release and reopened conformance gates.

## Historical R1 release record

R1 is a component-complete factory for one useful but deliberately narrow local
software-change workflow. Every factory role, capability service, workflow and
policy is an admitted WebAssembly Component Model component. Native code is
limited to generic mechanisms that instantiate, meter, persist and connect
components and enforce their declared capabilities.

The admitted factory accepts a canonical content-addressed change request,
opens and snapshots an inline workspace, applies a deterministic text change,
schedules work, compiles a small declared text program, discovers and runs its
test, reviews the result, publishes and verifies a package, and publishes and
resolves evidence. It does this through all six worker roles and all seven
capability-service families, then reproduces the exact output and provenance
after restart and exact replay.

The R1 release was intentionally limited to `wasm-biotic:text-program@1`, an
inline workspace, the `local-fixture` provider, local content-addressed package
and evidence records, and disabled HTTP. It did not claim the external North
Star. R1's exact aggregate claim remains historical and is not broadened by the
R2 implementation.

### Frozen identities

| Artifact | SHA-256 |
| --- | --- |
| Incumbent graph manifest | `4d4bca5c0fbcb5651bbc326049a08bf495b555392a83093cdf756fd213d0dd09` |
| Successor graph manifest | `a6a7e4d049198bf2ee06b97e6f2bb13ba367bc3367e42c7fff378f8c6f81c4b9` |
| Raw root authority component | `037216740953a89d54da79d4d9e1f9058887881a5d8940b9bcf054ae506e1ccf` |
| Composed root executable | `46e3c691e600500c61839558315d600b9bfea688b2fe3dd68ef8b2617a6d4b47` |
| WIT package | `b7e64a6a131af7a89ab27a0488b1f020f5e26620a1c10abbaeb06f27d6ed2633` |
| Substrate profile | `2d73bdf3094193cbed4a546d70a7dc668cc8f1008a059ecd3a778d1057874020` |
| Native TCB inventory | `99c226f238bc1c265dd98966fcf5d956e4ae15ae3c27b164a1fcb9f71b274e0a` |
| Native source closure | `71ea37dd9b0734b852acf8a5322ee19075099dd4a16520723e5103a8f01b3d31` |
| Optimized native executable | `adacc276abf9a4349ce6a8cdf07edcc2b0ba7e3e3c1e1d80f99109a8f9177e67` |
| Incumbent strict-validation report | `5bbcf38797a8a8a2a913f9a2546381da4688ca1d872b2975a5cbe1149aaedb06` |
| Successor strict-validation report | `443e60219f4e2e1154c51dc162879ff30609d24ec7dbbdcf65559b00c3276e51` |
| Incumbent certificate | `8ca5e0e82e732bf5d4674d57254bf65cd89bf0aef32485fd8c4f5be4efcbc271` |
| Successor certificate | `321284fc0235786fecb36626f4e64733a46f71bb0235f0c01b5ebcdb4cbc9498` |
| Lifecycle evidence | `0511d305c7f462ba121442c05ab2b0f7e838a61f6bee37b8de8de08b02dfe7a7` |
| Certifier key ID | `23fb37234c10651624be7a6b15d94440412bd85c8041dbfe55d4240f6efbeacc` |

The successor certificate binds `previous_graph` to the incumbent manifest.
Both package closures carry the same exact signed TCB inventory. Admission
checks the complete artifact set and certificates using the independently
pinned raw Ed25519 public key
`7b28a8de3427caf35341e72c56d83b1b250e2e0a599c11259becf69148f7eb07`.

### What is actually in the factory

The admitted graph contains 22 semantic nodes:

- component-owned supervisor reduction and durable workflow driving;
- planner, builder, validator, reviewer, packager and continuity workers;
- build, packaging, validation, review, continuity, scheduling and operations
  capability services;
- capability routing, signed approval and exact-replay policy;
- local exchange, evolution, state-migration, closure and API policy; and
- exact-digest component-tool execution.

The useful R1 path performs exactly these service operations, in order:

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

The canonical positive fixture changes `Hello, Factory` to
`Hello, Factory!`, discovers one test and passes it. Reserved malformed R1
media fail closed rather than falling back to the retained historical
octet-stream compatibility envelope.

### Native boundary

The exact host allowlist remains:

1. `activation`
2. `audit-log`
3. `blob-store`
4. `clock`
5. `component-runner`
6. `http-transport`
7. `key-service`
8. `transaction-store`

The host may instantiate and meter components; store opaque bytes and
transactions; provide clock, key and disabled-transport primitives; connect
declared imports; atomically pair graph and opaque-state references; and enforce
resource and capability limits. It may not interpret factory-domain documents,
choose workflow transitions, implement a worker or service operation, decide
approval, exchange or evolution policy, or substitute a native success path.

The exact profile sets HTTP to `bounded-disabled`. Enabling transport, changing
the graph, inventory, WIT, profile, native target or admitted corpus creates a
different claim and requires fresh evidence.

### Executed conformance

| Gate | Evidence established | Status |
| --- | --- | --- |
| C0 — contract | WIT parses; raw/composed interfaces and normative contract are digest-bound | **Pass** |
| C1 — graph | Two complete signed, content-addressed 22-node package graphs have exact lineage | **Pass** |
| C2 — native boundary | Reachable inventory, denylist audit and substitution tests admit only generic mechanisms | **Pass** |
| C3 — behaviour | The real R1 source-change path completes all 6 roles, 7 services and 12 operations | **Pass** |
| C4 — durability | 73 injected fault cases plus restart, exact replay, activation and rollback preserve identities and idempotence | **Pass** |
| C5 — isolation | Traps, bounds, forged references, malformed media, undeclared imports/targets and authority escapes fail closed | **Pass** |
| C6 — lifecycle and reproduction | Incumbent, successor, rollback, restart, post-rollback cycle, candidate shadow and independent substrate pass | **Pass** |
| C7 — retained release | Signed aggregate retains and verifies every exact package, native, source, contract and report byte | **Pass** |

The lifecycle sequence is substantive: the incumbent completes the R1
source-change cycle; component policy selects and activates the signed
successor; the successor completes a cycle; component policy requests rollback
after an unhealthy observation; restart restores the exact incumbent
graph/state pair; and the incumbent completes another cycle. The independent
Wasmtime substrate then runs the unchanged signed graph and matches final
output bytes, terminal result, all seven dynamic provenance records, the R1
semantic summary and exact replay.

The successor also runs in an isolated pre-activation shadow over the canonical
R1 corpus. All six workers and seven services match, terminal output is
byte-exact, the incumbent active pair does not change and no activation occurs.

### Evidence cohort

| Report | SHA-256 |
| --- | --- |
| Signed R1 semantic admission | `b18404fa1296056a48233951b3e8c853bf9793589f3253b182ace8307ddc1341` |
| Behavioural equivalence | `79f4c7e00bb6c9b83e69fcf5a7edc57264b7ccd9a3070ff84ac115add990257c` |
| Adversarial isolation | `4fddc8d43a00478b67da680e0b26d0d2230dc0c4fcb1b940916e5d17383ac4cb` |
| Durability fault matrix | `81c5f8816dfcfa8f00fe869bc949e56932456af9701376f14b04d381381d0ffb` |
| Candidate-graph shadow | `ed84b4229c990397d3027e178ebecb3b980c2ac45f95834548621f8e1452d1af` |
| Independent-substrate reproduction | `31fcb54e0db5edc9702428483c03c7470c218c438b4dcb0e5370ae89aef6ed89` |
| Native-build attestation | `c5616bbfdf2d2b53daa128990aa2db51a3f248f2da377980b9711bb3b679ed90` |
| Package lifecycle | `0511d305c7f462ba121442c05ab2b0f7e838a61f6bee37b8de8de08b02dfe7a7` |

The behavioural-equivalence policy trace is deliberately identified as a
synthetic no-useful-semantics boundary check. Useful R1 semantics are proven by
the lifecycle, candidate-shadow, kernel admission and independent-substrate
reports. Component-level negative semantics are exercised against the shared
`no_std` policy source; positive compiled-component traversal is exercised by
the lifecycle. These distinctions are retained rather than overstated.

### Historical R1 claim boundary

R1 proves a bounded local, component-complete architecture for one exact useful
cohort. It does not claim live external providers, remote effects, a general
Rust or Cargo toolchain, arbitrary repositories, production deployment,
per-consumer host principals within the composed static root, multiple native
platforms, or the external North Star. Per-consumer authority was deferred from
that release to R2; implementing it now does not retroactively broaden the R1
claim. Live HTTP/provider integration remains later work. Any expansion must
arrive as admitted Wasm-Biotic components or as a narrowly justified generic
mechanism, with a new signed release and reopened conformance gates.

## Historical R0 baseline

R0 established the first retained component-complete architecture baseline
before the useful bounded service semantics added in R1. Its exact release,
reports, 11/11 post-publication negative matrix and verification procedure
remain regression evidence. R1 superseded its capability description. R2 added
the per-consumer authority model and R3 added bounded external transport;
neither later release rewrites the claims attached to historical R0/R1 bytes.
