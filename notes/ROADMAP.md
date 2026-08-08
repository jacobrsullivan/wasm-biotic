# Wasm-Biotic Roadmap

- **Status authority:** this file
- **Last reviewed:** 2026-08-03
- **Current completed phase:** R3 — bounded external transport
- **Next phase:** R4 — reproducible multi-platform release and key governance
- **Architecture invariant:** **Satisfied for the exact R3 release**
- **Formal aggregate `component_complete_claim`:** `true` for the exact signed
  R3 closure; the signed manifest is the identity authority
- **External operational North Star:** **Not yet**
- **Production workload model:** WebAssembly Component Model only
- **Native `aiaf-v1` implementation:** transitional behavioural oracle only

<!-- wasm-biotic.active-truth.v1:begin -->
{"schema":"wasm-biotic.active-truth.v1","operational_decision":"not_yet","historical_phase04_scope":"historical_record_completeness_only","historical_lineage_decision":"closed","federation_posture":"bounded_local_first_no_public_federation","roadmap_status_authority":"notes/ROADMAP.md","claim_catalog_version":"1.0.0","claim_catalog_digest":"sha256:428a5e6620591198c7b0fe9e923956e4b807cb5a74a9d374f86131b8f589fe02"}
<!-- wasm-biotic.active-truth.v1:end -->

## 1. The decision

The project rule is literal:

> A Wasm-Biotic factory is a versioned, content-addressed graph of Wasm
> components. Its native substrate may instantiate, meter, persist,
> communicate and enforce declared capabilities, but may not implement factory
> roles, services, workflows or policy.

R3 is the current completed baseline for that rule. Its exact signed release
contains an incumbent and successor graph. Each graph has 22 admitted Component
Model nodes, 22 independently derived consumer principals and 34 unique
content-derived host aliases. One pure principal has no host alias and therefore
no substrate authority.

Factory control, supervision, six workers, seven capability-service families,
exchange, migration, evolution, closure and API meaning execute in components.
The native kernel supplies eight generic mechanisms. It does not contain a
reachable native factory role, capability service, workflow or policy fallback.

R3 retains R2's closure of R1's graph-union authority limitation. Host
authority is selected by the exact per-consumer alias linked before guest
execution. Component payload fields and legacy request metadata cannot choose a
principal or widen callable authority.

R3 additionally enables one content-derived `http-transport` alias for the
`exchange-service` component. A separately signed constraint fixes the exact
origin, paths, DNS rule, TLS peer, methods, visible headers, byte/time/
concurrency limits, redirect denial and credential placement. The operator may
disable or narrow those limits; it cannot widen them. Native code transports
opaque bytes and preserves a durable single-dispatch fact. Components retain
provider choice, request construction, response meaning, accounting, retry,
fallback and workflow policy.

## 2. Three claims that must stay separate

| Claim | Current answer | Meaning |
| --- | --- | --- |
| Does the bounded execution path obey “only run Wasm-Biotic components”? | **Yes** | Factory semantics execute in admitted components; native code provides only the declared generic substrate. |
| Is the formal aggregate `component_complete_claim` released? | **Yes, for the exact R3 cohort** | The signed release records C0–C7 `pass`, has no blockers and retains its complete content closure. |
| Is the broader external North Star operationally closed? | **No — Not yet** | Live-provider qualification, external custody, independent review and publication authority remain separate work. |

The formal claim attaches only to the exact graphs, WIT package, principal
inventories, native TCB, substrate profile, target and evidence below. It is not
a claim about every repository checkout or future profile.

The external North Star is deliberately stricter and broader. Component
completeness cannot manufacture external facts that have not happened.

## 3. Current R3 release

The exact current package pair is:

| Item | Exact identity |
| --- | --- |
| Durable signed release root | [`sha256:ed9eedf3633533cb877a0e0636f9b75a1a0050f426af623fc1ab5e934849e8c9`](../artifacts/component-complete/releases/sha256-ed9eedf3633533cb877a0e0636f9b75a1a0050f426af623fc1ab5e934849e8c9/) |
| Signed claim manifest | `sha256:d4004e13e7e4b4bfdea4a77ad6a217e575a82df91af9b9c5dec156448bf74d74` |
| Claim signature document | `sha256:2205f7c6400c0ee3d7172a50116baac99fd42dcfe1c5c2ca00777b4131dc52f1` |
| Incumbent graph manifest | `sha256:ef9c8aac3b08848d3df56d069df0df405251786e4afb3dd95e1098dd08195eb4` |
| Successor graph manifest | `sha256:f98f2f8b6be93e3d9342472a54c08ffa7e976d49a796e8f300a116650d6bbebd` |
| Successor lineage | `previous_graph = sha256:ef9c8aac3b08848d3df56d069df0df405251786e4afb3dd95e1098dd08195eb4` |
| Compiled exchange component | `sha256:896c0760707a661933ad6f4af8c60e01a7cd6eb855545c586e161311d57c43f8` |
| HTTP transport constraint | `sha256:1c8129a9af4cd3fdd7d1a355de8f82182255d160ce65ddf2a6f499490f746bf8` |
| Native TCB inventory | `sha256:3b7cf13a9308e94d4847d3cfceb80e6a4304f00482f4a83507091f4c24fbebf0` |
| Optimized native executable | `sha256:4e5f138bed257dd644e9d7738d9679985552c2c6e988e997e36e2a8aa9337df9`; `aarch64-apple-darwin` |
| Native build attestation | `sha256:968ccf4bbd3dbb28c16178009398f12f883f570d2db353f5e0b74a458a5b3993` |
| Certifier key identity | `sha256:7bbbb6a94cb24edf5ccbaa34129598698deaf3aa5115130abb85602ab68f3014` |
| Pinned raw Ed25519 public key | `033212831d4f2022bce8bc70e8f4d7d970b41e1d32a35a207dd0d7731db9352a` |

The signed aggregate manifest is authoritative for the release root, public
key, complete package/native/source/contract trees and every report digest.
This roadmap is deliberately outside the signed normative-contract tree, so it
can mirror the final root without making that identity circular.

R3's transport qualification uses an exact explicitly reviewed TLS peer. It
proves bounded destination and peer confinement, not general internet access or
a qualified live provider. `external_north_star_claim` remains `false`.

### Retained exact R2 release

| Item | Exact identity |
| --- | --- |
| Durable signed release root | [`sha256:0cb0ba1aad8676e38f535bdf1dfac030e43d2891704a0e629844bdb0a2bd4a52`](../artifacts/component-complete/releases/sha256-0cb0ba1aad8676e38f535bdf1dfac030e43d2891704a0e629844bdb0a2bd4a52/) |
| Signed claim manifest | `sha256:c951ebfb7a2f66a3644c548d2a2581d6188929f63975b242f5f3b727f80d04d7` |
| Claim signature document | `sha256:877a8a708adee53bec2c6af66e87887958516df0da2dcfc77a68c31be0d864f0` |
| Incumbent graph manifest | `sha256:0a5698fb0e22cdd9deb2b32e0bf8d3c23ec76cb3b2743c67e9f20a48a7fc943d` |
| Successor graph manifest | `sha256:75b4dc5de918865d0b73bb77fc32c41f30a0c3bbe2058ebb2c624bb58a11a2d7` |
| Successor lineage | `previous_graph = sha256:0a5698fb0e22cdd9deb2b32e0bf8d3c23ec76cb3b2743c67e9f20a48a7fc943d` |
| Raw root authority component | `sha256:037216740953a89d54da79d4d9e1f9058887881a5d8940b9bcf054ae506e1ccf` |
| Composed root executable | `sha256:1f68ce6d18315b89024df39307eff27391a36dc1e2a4b28af8dbb2c59dbd09ab` |
| WIT package | `sha256:b7e64a6a131af7a89ab27a0488b1f020f5e26620a1c10abbaeb06f27d6ed2633` |
| R2 derivation descriptor | `sha256:dd64424e2021cdab3c8dfd6070995d163e1d3d6993234e0f01d0998c887eec82` |
| R2 substrate profile | `sha256:916cb55f0ce3623378854b974536d9f58a7ce489f0d41437f71ee7b4f5c92835` |
| Incumbent principal inventory | `sha256:4211d410fbc1a592d11c0b270d41157683f9f69abaa93960da1e09bef07462bf` |
| Successor principal inventory | `sha256:fdf426ed4d8ec1fbefbdc3b1cce681f0d8bd57d5f0b9c1f05bf9e966fecb693e` |
| Incumbent strict validation | `sha256:954f7179c2b342cdb374e09e67dd56a08c37d54d2a9c6b1a3c2844152ceeaf27` |
| Successor strict validation | `sha256:1eb47d89a45d4fc67b3a0f5440e3660ab0716ad67b77135e16a5e92eccd2e8bb` |
| Incumbent release certificate | `sha256:c468fe52a6ce7aa5b8ef5af1d2e155d783f4d2d308a2f60c262554e2edbcf768` |
| Successor release certificate | `sha256:7d27387f0b2583b87ca8a379ec68adf963bf42facf6d72bfc51bd5dd5d1bee75` |
| Native TCB inventory | `sha256:7d6ea4fb0e4c62084d645844c5f894f9be1eb453f6ab45bcfcecf7f52a2b01f3` |
| Native source closure | `sha256:bfb266dc2780cd143614bf16f4b16520f62d6e761e3b548c7152fcb5dfa57aba` |
| Optimized native executable | `sha256:fa6dc67649ba00421b7817909c5e5e0a7a487815c70c363ddde6a04f9f0d8944` |
| Native build attestation | `sha256:007f01d62b23423a4a24449052612735b75dc52b5d7fd49683f051a41c019237` |
| Component-complete contract | `sha256:ca64029f074420a0b7d1b1f36b75dc16e135a3e8ff27ca9b8e08781426ed3a75` |
| Certifier key identity | `sha256:9429f2f6adde0bc33cafedd85d219c1e5a7e8c3ffee2a93661b34e46a6c22594` |
| Pinned raw public key | `70bb289c70ee950e7dd85db57a873cd4771fa618c54720a48ee22da749521223` |

The historical R2 aggregate retains both package trees, the native executable,
native source, normative contract tree, public key and nine required evidence objects.
The public-key verifier recomputes every file, tree, object, claim and directory
identity before accepting the root.

The private signing key is external to the release and native mechanism state.
Possessing a signed package does not permit replacement of the operator-pinned
public key.

## 4. What the factory is made of

### 4.1 Component graph

| Group | Component nodes | Count |
| --- | --- | ---: |
| Durable control and routing | `factory-control`, `supervisor-reducer`, `worker-router`, `capability-router` | 4 |
| Workers | `planner-worker`, `builder-worker`, `validator-worker`, `reviewer-worker`, `packager-worker`, `continuity-worker` | 6 |
| Capability services | `build-service`, `validation-service`, `review-service`, `packaging-service`, `continuity-service`, `scheduling-service`, `operations-service` | 7 |
| Evolution and protocols | `factory-evolution`, `state-migration`, `exchange-service`, `closure-evaluator` | 4 |
| Admitted tool fixture | `admitted-tool-probe` | 1 |
| **Total** |  | **22** |

The manifest has 55 explicit bindings. Every node is selected by SHA-256 and
declares a Component Model world. The root, six workers and admitted tool are
retained as reproducibly derived executables.

Each package also retains one scoped component for every consumer. Those bytes
bind the consumer's rewritten imports before composition. The raw, scoped and
derived artifacts all remain content-addressed.

### 4.2 Exact native boundary

| Native mechanism | Allowed responsibility | Forbidden meaning |
| --- | --- | --- |
| `blob-store` | Quota, hash, store and resolve immutable bytes | Workspace, package or evidence interpretation |
| `transaction-store` | Opaque namespaced reads and atomic CAS | Workflow transitions, retries or policy |
| `clock` | Wall time and explicitly requested durable wakes | Schedules, deadlines or retry decisions |
| `component-runner` | Verify, instantiate, meter, interrupt and collect component results | Role selection, native programs or success interpretation |
| `http-transport` | Validate byte-oriented bounds and perform transport when enabled | Providers, prompts, parsing or retry policy |
| `key-service` | Hold non-exportable keys, sign/verify and provide entropy | Approval or promotion meaning |
| `activation` | Atomically carry exact verified graph/state pointers and their one-owner handle | Migration, health, promotion or rollback policy |
| `audit-log` | Append and resolve opaque hash-chained bytes | Event meaning or manufactured success evidence |

The exact R3 profile v3 sets `http-transport` to `bounded-external` only for the
exchange consumer's content-derived alias and exact constraint digest. The
effective runtime grant is the intersection of that signed constraint, shared
signed ceilings and smaller operator capacity. Every other network path remains
absent. The retained R2 profile remains `bounded-disabled`; R3 does not rewrite
its meaning.

The standalone `kernel/` crate does not depend on `aiaf-v1`. The retained native
control plane and capability services are transitional reference implementations
and cannot become a production fallback.

## 5. R2 per-consumer authority retained by R3

### 5.1 Principal and alias derivation

For each consumer, the release tooling and substrate independently derive a
principal seed from the consumer node ID and raw authority-component digest.
The same raw component used by two consumers therefore does not imply shared
authority.

Every direct substrate import is rewritten to a unique content-derived alias.
The alias binds:

- the consumer node;
- the raw authority-component digest;
- the source WIT import;
- the generic capability and opaque scope; and
- the constraint digest.

The v2 descriptor, profile, strict-validation report, certificate and principal
inventory all bind the same mapping. Production admission recomputes it.

Before execution, the linker captures an immutable context containing the
admitted graph, consumer, principal seed, graph-qualified runtime principal,
scoped component, enclosing executable, capability, scope and constraint.

R2 and R3 expose no canonical host import and no graph-union fallback. The legacy
`RunRequest` grant list is canonical compatibility and resource metadata derived
from the target executable's signed principal closure. It can narrow bounds but
cannot install callable authority.

### 5.2 Graph-qualified operations

Component-run operations, clock wakes, activation handles and transaction
idempotency records are qualified by the admitted graph and alias-bound caller
principal. Another principal cannot poll, cancel, replay or mutate them.

Component-run requests also require an exact caller-to-target invocation edge
from the signed graph. Global admission of a component is not sufficient.

Authority traces bind each alias call to its graph, consumer, enclosing
executable, runtime principal, exact request digest and stable result.

### 5.3 Activation ownership handoff

Activation is the one deliberate graph transition, but it is not cross-graph
sharing.

1. The incumbent stages an activation handle owned by its graph and principal.
2. Commit verifies that the target graph is signed and admitted.
3. Commit verifies that the target contains the exact same principal seed with
   its exact `activation`/`switch` alias.
4. The active graph/state pointer, activation record and idempotency pointer
   change in one durable transaction.
5. The incumbent immediately loses access to that handle.
6. The exact successor principal can inspect it and component policy can decide
   whether rollback is warranted.
7. Rollback verifies the last-known-good graph under the same seed/import rule
   and atomically hands the record back.

Wrong graph, wrong seed, missing import and stale-source attempts fail without
changing the active graph or current owner. Restart preserves exactly one
graph-qualified owner.

The substrate enforces admission, identity, capability and atomicity. Components
still decide what a candidate means, whether it should be activated, what an
observation means and whether rollback should happen.

## 6. What the factory can actually do today

R3 retains the useful bounded-local capability slice completed in R1/R2. It can:

1. Accept a canonical content-addressed change request.
2. Open and snapshot an inline workspace.
3. Apply an exact-CAS deterministic text patch.
4. Schedule the bounded local job.
5. Compile a declared `wasm-biotic:text-program@1` program.
6. Discover and run its test; the canonical fixture discovers one and passes it.
7. Obtain a deterministic `local-fixture` proposal.
8. Review the candidate through component policy.
9. Publish and verify a local content-addressed package.
10. Publish and resolve content-addressed evidence.
11. Execute all six workers and all seven service families through 12 ordered
    capability operations.
12. Persist inputs, state, outputs, receipts, activation pairs and audit bytes
    by digest through generic mechanisms.
13. Admit, activate, observe and roll back an exact successor through component
    decisions.
14. Reopen after restart and replay without changing mechanism state.
15. Run unchanged signed graph bytes on an independent substrate with exact
    output, provenance, principal and replay matches.
16. Ask the exchange component to issue one exactly constrained HTTPS request
    to the signed origin and pinned TLS peer, with component-owned request and
    response meaning.
17. Recover prepared, pending, terminal and indeterminate exchange outbox state
    without native retries or duplicate dispatch.
18. Supply a non-exportable credential by opaque handle while keeping its bytes
    outside component memory and durable/logged/returned evidence.

The boundary is equally important. R3 does **not**:

- read an ambient repository;
- run Cargo, a native compiler, a shell or another native workload;
- provide a general Rust/Cargo build service;
- provide a general live-provider client or ambient internet access;
- publish to a remote registry;
- perform a production deployment;
- satisfy the external North Star.

Its workspace is inline, its program language is bounded, its ordinary provider
is a local fixture and its package/evidence/deployment records are local
content-addressed documents. Its added HTTP authority is one reviewed,
content-bound exchange route, not a general provider capability. Those limits
are signed facts, not hidden native substitutions.

## 7. Execution and release evidence

### 7.1 Current R3 proof closure

The R3 aggregate retains one joined proof closure rather than treating isolated
test passes as a release claim:

| Evidence class | What it proves |
| --- | --- |
| Signed semantic admission | Both exact packages, pinned certifier trust, profile v3, HTTP constraint and native inventory agree and tampering fails closed. |
| Behavioural equivalence | Component-owned bounded factory and exchange semantics remain stable across the signed pair. |
| Adversarial isolation | Undeclared mechanisms, aliases, destinations, TLS peers, headers, sizes, timeouts, redirects, handles and targets fail closed. |
| Durability fault matrix | Local effects plus prepared, pending, terminal and indeterminate HTTP boundaries survive restart without duplicate dispatch. |
| Candidate graph shadow | The successor matches the incumbent on the frozen acceptance corpus without mutation authority. |
| Independent substrate reproduction | Unchanged signed bytes reproduce lifecycle, principal and transport constraints independently. |
| Principal isolation | Production and independent substrates preserve graph-qualified ownership and reject cross-principal access. |
| Transport confinement | Production, independent and joined reports cover destination/TLS, signed/operator intersection, durability, ownership, secret and non-retry cases. |
| Native build attestation | The optimized executable binds the exact native source, dependency lock, toolchain and compiled TCB inventory. |
| Package lifecycle | Incumbent, successor, rollback, restart and post-rollback execution remain component-decided. |

The public exact gate dispatches through the admitted exchange component to the
signed pinned TLS peer, observes one durable operation and one peer request,
then reopens the same mechanism state. The restarted process correctly has zero
new process-local authority-trace entries, and the peer receives no second
request. State, transcripts, receipts and response artifacts are scanned for
the credential sentinel. The production and independent case inventories are
joined only when their graph, principal, constraint and compiled-component
identities match.

The signed aggregate manifest records every report digest and is the final
identity authority. Post-signing negative controls copy and mutate the bundle,
reject each mutation and confirm that pristine public-key verification remains
unchanged.

### 7.2 Retained R2 four-phase lifecycle

The package harness executed:

1. an incumbent six-worker, 12-operation source-change cycle;
2. component-decided initial state binding and successor activation;
3. a successor cycle followed by an unhealthy observation and
   component-decided rollback;
4. restart and a post-rollback incumbent cycle with exact replay.

The lifecycle is
`sha256:a6d02c8fd7d0e2423d4bab13654488f1ed6a4dc22431133991eb9a99e301762c`.
Its four authority-trace phases contain 148, 168, 5 and 148 alias calls. The
principal inventories remain stable across activation, rollback and restart.

Both package copies retain identical lifecycle bytes. The successor received
the activation handle, used it for observation, and handed it back on rollback.

### 7.3 Retained R2 named proof reports

| Evidence | Result | SHA-256 |
| --- | --- | --- |
| Signed R2 semantic admission | Exact signed packages, pinned trust and tamper controls pass | `91e80bc413a82265e10cc399484d1ae8dc45a9ed274aac339ded8d358aef37d7` |
| Behavioural equivalence | Bounded useful semantics and lifecycle bindings pass | `dbc4c8be342d874697b2780192ec55ec62ec857bd17d56bce3f21adb0359d6b9` |
| Adversarial isolation | Mechanism and R2 authority escapes fail closed | `15cd84b4b4926f7b782de396035dc16483d3c3f5e82477a0b166955580ec9f0c` |
| Durability fault matrix | Crash, replay, graph/state and ownership evidence pass | `8a0183c25eafd1688384b829d9865bbb44034d5f246ddacda09e62bc545cadd5` |
| Candidate graph shadow | Incumbent/successor outputs match with zero conformance gaps | `bd47736ad8ae5b86d2f4642f3140bad84739a6171ce124a0d230a3a98c7b7a96` |
| Independent-substrate reproduction | Exact output, provenance, principals and replay match | `a32598fdab107ddce3de7335685075f1b7b210c281200a0204cdca76ec412f5f` |
| Independent principal isolation | 7/7 cross-principal controls pass | `258f088ca5e3acaa865376db03e19b3d1685eec0adb2868d895ce8bd40f6cf38` |
| Joined principal isolation | 26/26 production and independent cases pass | `0bd5e3f7540dbfe13624bb3147477fc2ace8e61c48c38d68c989440a1ce0ddc5` |
| Native build attestation | Fresh optimized arm64 binary binds exact source and compiled inventory | `007f01d62b23423a4a24449052612735b75dc52b5d7fd49683f051a41c019237` |
| Component lifecycle | Four live authority phases, handoff, handback and restart pass | `a6d02c8fd7d0e2423d4bab13654488f1ed6a4dc22431133991eb9a99e301762c` |
| Signed aggregate claim | C0–C7 pass; `component_complete_claim=true`; blockers empty | `c951ebfb7a2f66a3644c548d2a2581d6188929f63975b242f5f3b727f80d04d7` |
| Signed release root | Complete retained R2 closure verifies by public key | `0cb0ba1aad8676e38f535bdf1dfac030e43d2891704a0e629844bdb0a2bd4a52` |
| Post-signing release negatives | 13/13 mutations rejected; pristine closure accepted before and after | `500466a6e10c2c9c56db3fb5dcf9004baf195e910aa6c2ddd5251d25030a57f8` |

The standalone independent-principal report is bound into the joined principal
report; the joined report is retained by the aggregate.

The post-signing negative matrix is necessarily outside the already signed
closure. It verifies that closure rather than changing it. The pristine release
remained byte-identical:

- closure digest: `sha256:11b2747a352c428fb2968703437b63c463105004ebc6df6448851996092fcef1`;
- 227 files;
- 52 directories; and
- 65,025,039 file bytes.

### 7.4 Retained R2 test accounting

The definitive 12-command R2 gate passed **48/48**, comprising:

- 12 bounded service-policy cases;
- 5 kernel adversarial cases;
- 5 kernel durability cases;
- 5 activation/restart durability cases;
- 6 kernel R2 principal/linker/trace cases;
- 6 independent-substrate R2 cases;
- 3 package least-authority cases;
- 2 native-boundary cases; and
- one each for graph principal contract, active-target isolation, activation
  CAS isolation and compiled capability-router approval.

Additional retained R2 accounting:

- complete production-kernel all-target suite: **50/50**;
- joined production/independent principal campaign: **26/26**
  (19 production plus 7 independent);
- independent-substrate suite: **17/17**, with the exact R2 subset **6/6**;
- independent cross-principal campaign: **7/7**;
- Python release-tool regression suite: **29/29**;
- post-signing aggregate negative controls: **13/13**; and
- format, all-target check, strict Clippy and fresh optimized build: **pass**.

These counts are not substitutes for the signed artifacts. They identify the
executed checks whose outputs feed the named reports.

## 8. Conformance ledger

| Gate | Current state | Evidence |
| --- | --- | --- |
| C0 — Contract | **Pass** | Exact WIT, descriptor v2, profile v3, principal/alias rules and separate HTTP constraint are digest-bound. |
| C1 — Sealed graph | **Pass** | Two signed 22-node graphs retain exact lineage, raw/scoped/derived bytes and one matching exchange HTTP binding. |
| C2 — Native boundary | **Pass** | Eight generic mechanisms, alias-only linkers and forbidden-domain/provider/retry audits pass. |
| C3 — Behaviour | **Pass for bounded scope** | Six workers, seven service families and exchange policy execute as components; native HTTP returns opaque facts. |
| C4 — Durability | **Pass for enabled HTTP** | Local fault coverage plus prepared/pending/terminal/indeterminate dispatch and exact restart replay pass. |
| C5 — Isolation | **Pass** | Production and independent substrates reject principal, destination, TLS, bound, credential and idempotency escapes. |
| C6 — Lifecycle and reproduction | **Pass** | Incumbent, successor, rollback, restart, shadow, independent execution and the exact signed HTTP gate pass. |
| C7 — Aggregate and release | **Pass** | The signed manifest retains the exact closure and public-key verification plus post-signing negatives pass. |

`open_release_blockers` is empty.

The R3 claim is exact. Any new origin, TLS peer, provider, credential placement,
operator widening, platform, component or policy creates a different closure
and reopens the applicable transport, crash, credential, isolation and release
gates.

## 9. Current architectural decisions and limits

### 9.1 Per-consumer principals are the default

New component-complete releases use the R2/R3 principal/alias model. The R1
graph-union path remains explicitly versioned only for historical replay. It
cannot be selected by a v2/v3 descriptor or used as R2/R3 isolation evidence.

### 9.2 The native substrate enforces mechanics, not policy

Native code may verify signatures, digests, aliases, graph edges, ownership,
resource limits and atomicity. It may not infer that a principal is a worker,
that a payload is an approval, that a result is healthy or that a graph should
be promoted.

### 9.3 Build tools are not factory workloads

Host Cargo, `wasm-tools` and release utilities may build or inspect a release
outside the factory. They are not reachable from an admitted production graph.
Any compiler, test runner or generator invoked by the running factory must be
an admitted component selected by digest.

### 9.4 Transitional native implementations remain reference-only

The native control-plane and capability-service implementations remain useful
for frozen behavioural comparison and historical fixtures. They may not mutate
canonical component-factory state or substitute for a failed component.

### 9.5 Trust is independently pinned

The operator persists the raw Ed25519 public key independently from package
contents. Certificates bind the exact package closure and TCB inventory. The
private key is never stored in a package, native executable or mechanism state.

### 9.6 Scope expansion always creates a new claim

Changing the graph, WIT, profile, native source, native target, operator bounds
or enabled mechanisms requires a new signed release and reopened gates. The R3
root remains evidence for its exact cohort only; the historical R2 root remains
evidence for its disabled-HTTP cohort only.

## 10. Phase history and forward roadmap

| Phase | Status | Durable result |
| --- | --- | --- |
| R0 | Historical regression baseline | First bounded component-complete release and fail-closed release verification. |
| R1 | Historical useful baseline | One real bounded local source-change workflow, still using a static graph-union host principal. |
| R2 | **Complete — historical baseline** | Per-consumer alias authority, graph-qualified ownership and independently reproduced lifecycle. |
| R3 | **Complete — current baseline** | Tightly bounded external transport without native provider, retry, workflow or policy semantics. |
| R4 | **Next** | Reproducible multi-platform releases and key governance. |
| R5 | Not yet | Reassess the external operational North Star using real external evidence. |

### R0 — Establish the component-complete release baseline

**Status:** historical regression baseline

Release `sha256:4c7cb6d2df2822ef525e9cbb6626d738b489e8ac52aa2ba770febd5a5180cec7`
proved the bounded component architecture before useful service semantics. Its
reports and negative matrix remain retained for regression. They do not
describe current capabilities or authority.

### R1 — Add a useful bounded-local capability slice

**Status:** historical completed release

Release `sha256:a1bb67473e84a0251c8b5acded18e55e14d2a5568615263df6ea29a2f872ce5a`
completed the inline-workspace text change, declared text-program compilation,
test, review, local package and evidence workflow through all six workers and
seven services.

R1 used a graph-union principal for the statically composed root. Its evidence
remains valid for that exact release but does not prove per-consumer isolation.

### R2 — Restore per-consumer least authority

**Status:** **complete for the retained R2 cohort**

Release `sha256:0cb0ba1aad8676e38f535bdf1dfac030e43d2891704a0e629844bdb0a2bd4a52`
meets every R2 exit gate:

- every one of 22 consumers has an independently recomputed principal;
- 34 content-derived aliases expose only each consumer's declared mechanisms;
- one pure principal receives no substrate authority;
- no canonical R2 host import or graph-union fallback exists;
- callable authority cannot be chosen by guest identity or request metadata;
- caller-to-target invocation edges are exact and signed;
- wakes, runs, activations and idempotency are graph/principal qualified;
- activation ownership moves atomically to the exact successor principal and
  back to the last-known-good graph on rollback;
- wrong graph, wrong seed, missing import and stale-source access fail closed;
- topology, raw/scoped/executable provenance and authority remain
  content-addressed;
- production and independent substrates pass cross-principal attacks; and
- C0–C7, the full lifecycle, public-key aggregate verification and post-signing
  negative controls pass with no blockers.

R2 deliberately does not broaden the useful capability slice. Inline workspace,
`wasm-biotic:text-program@1`, `local-fixture`, local content-addressed stores and
disabled HTTP remain the signed limits.

### R3 — Enable bounded external transport

**Priority:** completed current baseline

**Status:** **complete for the exact signed R3 cohort**

R3 created a signed substrate profile v3 in which byte-oriented HTTPS is
enabled for one exact `exchange-service` alias. This does not authorize a
native provider service. The native substrate performs only the generic
transport operation under an immutable alias-bound grant.

R3 retains the component-complete invariant:

- provider selection remains component policy;
- prompt/request construction remains component behaviour;
- response parsing and validation remain component behaviour;
- accounting, retry, fallback and cancellation remain component policy;
- credentials remain non-exportable native handles;
- no shell, native provider SDK or domain-aware host adapter becomes reachable;
- every new running tool or protocol adapter is an admitted component; and
- R1 compatibility cannot bypass R2 principal isolation.

Completed R3 evidence:

1. Exact destination, DNS/IP, TLS, method, header, body, timeout, redirect and
   credential-handle confinement.
2. Denial of private, loopback, link-local and undeclared destinations unless
   an exact reviewed profile explicitly permits them.
3. Crash, dispatch, completion, retry, cancellation and idempotency coverage for
   the now-enabled irreversible effect.
4. Proof that secret bytes never enter component memory, logs or receipts.
5. Component-owned provider choice, request formation, response meaning,
   accounting, retry and fallback.
6. Cross-principal attacks against production and independent substrates.
7. A real signed incumbent/successor lifecycle through the enabled profile.
8. Candidate shadowing, independent reproduction, public-key aggregate
   verification and post-signing negative controls.
9. An explicit statement that enabling transport does not by itself satisfy the
   external North Star.

All nine conditions are satisfied for the exact R3 closure. The transport gate
uses one explicitly reviewed loopback TLS peer with exact DNS and SPKI pins, so
the result proves the confinement mechanism without pretending to be a
qualified live-provider milestone. C0–C7 pass, the blocker set is empty and R4
is now next.

Exact retained R3 reports:

| Evidence | Result | SHA-256 |
| --- | --- | --- |
| Signed semantic admission | Exact signed packages, public trust, final native attestation and negative controls pass | `1fe8505236908af56e20c10f7a2b4fde96fb7230580197ba6ab8b0d32048b750` |
| Component lifecycle | Incumbent, successor, graph-qualified handoff/handback, restart and replay pass | `5dff70d768861479ef967b54e4e7f0cf6dde464e209817f29eb43dd685b1d70d` |
| Transport confinement | Production and independent substrate evidence joins with no blockers | `769dd9cedaef040b166b07d48bba6540cf6f5d81e139bb0e8a14f3e082ebdb16` |
| Principal isolation | 26 production and independent ownership/authority cases pass | `e9dd426d9547265bdce371e9f37174b752ec167ac5cfe71c0f44ab5e99964333` |
| Behavioural equivalence | Bounded workflow and R3 adapter semantics pass | `dddccefcdacc4342570551554cbf867bc0c5c53762b063c2d6202d95a916680f` |
| Adversarial isolation | Production gate isolation and policy-neutrality cases pass | `242dca1a6558232ce10455e174ad707d71a522f978fbcbc5a9f72e4066029abd` |
| Durability fault matrix | Crash, replay, activation and transport durability cases pass | `09ed7cfa28140a2141551f4f493ff2822980523744ea55a75cb42559149e5ca2` |
| Candidate graph shadow | Incumbent/successor component behaviour matches without activation | `b29c9d1447ac3d702adeaaee23c58d385135d418fb55bedec9430ff000cd7d36` |
| Independent substrate reproduction | Exact package, component, principal, transport and replay evidence passes | `7e638f17f3b6f3fa92fb43ca193334bbb6cdf8f58e081fd692fb9d0d471a7ed2` |
| Native build attestation | Selected arm64 executable binds final source closure, inventory and gate | `968ccf4bbd3dbb28c16178009398f12f883f570d2db353f5e0b74a458a5b3993` |
| Post-signing negative matrix | 17/17 release mutations rejected; pristine release accepted before and after | `dfac56a36bcfa2c11e068857c5e472230a29bbabd8832b8db248c90848575be3` |

The definitive target-isolated R3 production gate passed **76/76** across 19
commands. The exact signed HTTP gate passed 1/1: one pinned TLS peer observed
one request, durable state retained one operation and replay emitted no second
transport request. The release negative matrix preserved a byte-identical
239-file closure.

The native attestation does not claim byte-for-byte reproducibility across
different Cargo target-directory paths: those paths and the resulting Mach-O
UUID differed between otherwise equivalent clean builds. R4 owns that explicit
reproducibility gap.

### R4 — Reproducible multi-platform release and key governance

**Status:** next

Required work:

- publish source, toolchain, target and binary attestations per platform;
- reproduce component and native artifacts on independent machines;
- define certifier rotation, revocation and threshold custody;
- publish a content-addressed archive and SBOM; and
- verify install, bootstrap, inactive admission, upgrade and rollback from
  public-key-only inputs.

### R5 — Reassess the external North Star

**Status:** **Not yet**

External closure still requires fresh source precommit, a real qualified
provider interaction, external custody, independent reviewer signature,
persisted dossier reopen/evaluation and explicit publication authority.

Only the `closure-evaluator` component may interpret that dossier. The native
substrate may verify signatures and store bytes but may not decide whether the
North Star is closed.

## 11. Canonical verification procedure

Verify the current R3 release by passing its content-addressed directory to
`tools/component-release-bundle.py verify` with the independently obtained raw
Ed25519 public key. The signed manifest inside that directory is authoritative:

```bash
python3 tools/component-release-bundle.py verify \
  artifacts/component-complete/releases/sha256-ed9eedf3633533cb877a0e0636f9b75a1a0050f426af623fc1ab5e934849e8c9 \
  --expected-public-key-hex \
  033212831d4f2022bce8bc70e8f4d7d970b41e1d32a35a207dd0d7731db9352a
```

The retained R2 release remains independently verifiable as historical
evidence:

```bash
python3 tools/component-release-bundle.py verify \
  artifacts/component-complete/releases/sha256-0cb0ba1aad8676e38f535bdf1dfac030e43d2891704a0e629844bdb0a2bd4a52 \
  --expected-public-key-hex \
  70bb289c70ee950e7dd85db57a873cd4771fa618c54720a48ee22da749521223
```

Re-run the retained R2 post-signing negative matrix against temporary bundle
copies:

```bash
python3 tools/release-negative-matrix.py \
  --bundle artifacts/component-complete/releases/sha256-0cb0ba1aad8676e38f535bdf1dfac030e43d2891704a0e629844bdb0a2bd4a52 \
  --public-key-hex \
  70bb289c70ee950e7dd85db57a873cd4771fa618c54720a48ee22da749521223 \
  --campaign-label r2 \
  --out artifacts/component-complete/2026-08-03-r2-release-negative-matrix.v1.json
```

Verify the standalone production kernel:

```bash
RUSTUP_HOME=/private/tmp/wasmbiotic-rustup \
CARGO_HOME=/tmp/wasmbiotic-cargo \
CARGO_TARGET_DIR=/tmp/wasmbiotic-kernel-target \
cargo test --locked --offline --manifest-path kernel/Cargo.toml --all-targets
```

Build and execute a new signed package cohort with an external certifier key:

```bash
RUSTUP_HOME=/private/tmp/wasmbiotic-rustup \
CARGO_HOME=/tmp/wasmbiotic-cargo \
WASM_TOOLS=/tmp/wasmbiotic-cargo/bin/wasm-tools \
/tmp/wasmbiotic-cargo/bin/cargo run --locked \
  --manifest-path tools/component-graph-package/Cargo.toml -- \
  --certifier-pkcs8 PATH_TO_EXTERNAL_PKCS8_KEY \
  --certifier-identity REVIEWED_CERTIFIER_IDENTITY \
  --r3-http-constraints PATH_TO_REVIEWED_HTTP_CONSTRAINTS \
  --out PATH_TO_NEW_PACKAGE_COHORT
```

The production launcher exposes only generic lifecycle commands:

```text
wasm-biotic-kernel init  MECHANISM_STATE TRUSTED_INITIAL_MANIFEST CERTIFIER_PUBLIC_KEY_HEX [OPERATOR_CONFIG]
wasm-biotic-kernel admit GRAPH_PACKAGE MECHANISM_STATE
wasm-biotic-kernel serve ACTIVE_GRAPH_PACKAGE MECHANISM_STATE
```

Route meaning and response policy remain in `factory-control`.

## 12. Evidence locations

The current signed R3 aggregate is
[`sha256:ed9eedf3633533cb877a0e0636f9b75a1a0050f426af623fc1ab5e934849e8c9`](../artifacts/component-complete/releases/sha256-ed9eedf3633533cb877a0e0636f9b75a1a0050f426af623fc1ab5e934849e8c9/).
The signed aggregate manifest remains authoritative; this roadmap mirrors that
published identity and is not part of its normative-contract tree.

Supporting locations:

- normative component-complete contract: `contracts/component-complete/`;
- current machine reports: `artifacts/component-complete/`;
- component sources: `components/`;
- canonical WIT package: `wit/wasm-biotic/`;
- standalone native substrate: `kernel/`; and
- build, verification and reproduction tools: `tools/`.

Historical R0, R1 and R2 aggregate roots remain beside R3 under
`artifacts/component-complete/releases/`. Historical M0–M7 native-oracle records
remain under `artifacts/baseline/` and historical documentation. They prove only
their named bytes and scopes.

## 13. Maintaining this roadmap

Every material status update must:

1. name exact graph, principal-inventory, TCB and profile digests;
2. distinguish component architecture, formal release and external North Star;
3. link retained machine-readable evidence;
4. report failures and rerun conditions, not only eventual passes;
5. treat any enabled mechanism or expanded service as a new qualification;
6. keep transitional native implementations labelled and unreachable;
7. preserve per-consumer graph-qualified authority unless a stronger signed
   model replaces it;
8. never move a missing component capability into native code for convenience;
   and
9. keep prior releases as history rather than silently rewriting their claims.

If prose and machine evidence disagree, the narrower machine-supported claim
wins until both are reconciled.
