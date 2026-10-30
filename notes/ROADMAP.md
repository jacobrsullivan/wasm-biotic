# Wasm-Biotic Roadmap

- **Status authority:** this file
- **Last reviewed:** 2026-08-04
- **Current completed phase:** R4 — reproducible multi-platform release and key governance
- **Next phase:** R5 — reassess the external operational North Star
- **Architecture invariant:** **Satisfied for the exact R4 release**
- **Formal aggregate `component_complete_claim`:** `true` for the exact signed
  R4 closure; the signed publication and final aggregate are the identity
  authorities
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

R4 is the current completed release baseline for that rule. It freezes and
publishes the same bounded incumbent and successor component graphs established
by R3, now as a reproducible two-platform delivery. Each graph has 22 admitted
Component Model nodes, 22 independently derived consumer principals and 34
unique content-derived host aliases. One pure principal has no host alias and
therefore no substrate authority.

Factory control, supervision, six workers, seven capability-service families,
exchange, migration, evolution, closure and API meaning execute in components.
The native kernel supplies eight generic mechanisms. It does not contain a
reachable native factory role, capability service, workflow or policy fallback.

R4 retains R3's bounded transport and R2's closure of R1's graph-union
authority limitation. Host authority is selected by the exact per-consumer
alias linked before guest
execution. Component payload fields and legacy request metadata cannot choose a
principal or widen callable authority.

The retained R3 profile enables one content-derived `http-transport` alias for
the `exchange-service` component. A separately signed constraint fixes the exact
origin, paths, DNS rule, TLS peer, methods, visible headers, byte/time/
concurrency limits, redirect denial and credential placement. The operator may
disable or narrow those limits; it cannot widen them. Native code transports
opaque bytes and preserves a durable single-dispatch fact. Components retain
provider choice, request construction, response meaning, accounting, retry,
fallback and workflow policy.

R4 changes how that bounded factory is built, governed, distributed and
recovered; it does not move factory meaning into native code or add a broader
workload. The exact source closure and vendor closure produce deterministic
source and component archives. The components reproduce on separate physical
Macs. The native substrate is closed for `aarch64-apple-darwin` and
`x86_64-unknown-linux-gnu`, with the arm64 executable reproduced on separate
physical Macs. A public install, SBOM, negative controls and public-key-only
lifecycle cover bootstrap, inactive successor admission, upgrade and rollback.

The governance policy requires 2 of 3 generation-1 signatures and supports a
separately pinned package-certifier leaf key. That is threshold-signature
mechanics, not evidence that three different people or organisations held the
keys. Likewise, the durable copy on Bobs Mini is operator custody, not
independent external or human custody, and the signed content-addressed
publication is an operator publication artifact, not a remote registry.

## 2. Three claims that must stay separate

| Claim | Current answer | Meaning |
| --- | --- | --- |
| Does the bounded execution path obey “only run Wasm-Biotic components”? | **Yes** | Factory semantics execute in admitted components; native code provides only the declared generic substrate. |
| Is the formal aggregate `component_complete_claim` released? | **Yes, for the exact R4 cohort** | The signed publication and post-publication aggregate close R4-C0 through R4-C7 for one exact source, graph, target and evidence cohort. |
| Is the broader external North Star operationally closed? | **No — Not yet** | A qualified live provider, custody controlled outside the operator, independent human review and genuine external publication authority remain separate work. |

The formal claim attaches only to the exact graphs, WIT package, principal
inventories, native TCB, substrate profile, two closed targets and evidence
below. It is not a claim about every repository checkout or future profile.

The external North Star is deliberately stricter and broader. Component
completeness cannot manufacture external facts that have not happened.

## 3. Current R4 release

R4 freezes the exact R3 incumbent/successor graph pair and adds a reproducible,
governed release envelope around it. The signed publication and
post-publication aggregate identities below are final. The Bobs custody tree
was moved into its absent digest-named path atomically, without overwriting the
mutable development worktree, and the complete public verification set passed
again from that final path.

| Item | Exact identity or result |
| --- | --- |
| Signed publication root | `sha256:659cdf6b1de2196a7f33fbd3cb55ed4dd7e7a8b514ce6970e1e392e6aabb8b12` |
| Publication root document / claim | `sha256:659cdf6b1de2196a7f33fbd3cb55ed4dd7e7a8b514ce6970e1e392e6aabb8b12` / `sha256:fbe0d53a4ea75aec14961ae730b3e8dc94ebc2e1767f1f16e8d78f2eea8fec98` |
| Final post-publication aggregate | `sha256:60a8cd54195e479f766c03cf5ecae4418e1f20b7ba895727273e46862fa975ae`; independently verified under Python 3.9 and 3.14; R4-C0 through R4-C7 pass; blockers empty; no private-key dependency |
| Durable Bobs operator-custody path | `/Users/bob/Developer/wasm-biotic-releases/sha256-659cdf6b1de2196a7f33fbd3cb55ed4dd7e7a8b514ce6970e1e392e6aabb8b12` |
| Source-snapshot manifest | `sha256:db64731d0e461bf3e146e30702c45fff9547f3ba9fb89f73385b8b15471e2716` |
| Source / vendored dependency closure | `sha256:ac60f6c97fa48db7243cdd96faf18b5c8feec42caf86b8191c408dc609e68833` / `sha256:5d8b016343d75fc42088cca3fa5ac7b26f9ee85b27e049dcaaf72ed3f7789bc9` |
| Deterministic source archive | `sha256:50b96f7d1c62825d0405c30557a8c813db34b6dac33e0b9c86ba1727278d40c7`; independently emitted by Python 3.9 and 3.14; 29,896 entries |
| Component release archive / reproduced component set | `sha256:b009fcd4f0fc098dc8cf43c0011f416a08a44ca9446b49831a5b1d85767791f0` / `sha256:deb8f0df03d85f286239d8c01d106b962dd0dd9787e0b518d1c7a52ba74c908d`; exact 22-node pair |
| Component witness reports | Jacob's MacBook Pro `sha256:051309111901f55fa583cf31574bbe5654215203cb7fe4f7c2a1cf0ffed6df28`; Bobs Mini `sha256:aaed26520c3c777b5f09a16418d82f62f2a92a676c4b0bed2c65d658d7efa333` |
| Deterministic install archive | `sha256:71dcac03c222bcf07dafc110d0754d41f6b74fe5d6b9fc0be84972faf6c110e7` |
| SPDX SBOM / exact coverage report | `sha256:9fa6f2f6d7b3f4f7c2ee3a08bdeee2d574ff003c4b4f86f37960ab9261b84ca1` / `sha256:efc4bff0573c5225ec8a96044e926ba3c5b7057c51f9fdd6fac5b67245ba47b4` |
| Incumbent / successor graph manifest | `sha256:ef9c8aac3b08848d3df56d069df0df405251786e4afb3dd95e1098dd08195eb4` / `sha256:f98f2f8b6be93e3d9342472a54c08ffa7e976d49a796e8f300a116650d6bbebd` |
| Component-complete contract / native TCB inventory | `sha256:6eff98aedd7d0047d6abe55b9d60d5bbabaa00b733e8df13d3a0fc3de9c96857` / `sha256:3b7cf13a9308e94d4847d3cfceb80e6a4304f00482f4a83507091f4c24fbebf0` |
| Linux kernel / public lifecycle runner | `sha256:acec1a22242a29cc29f4a1f15cc87075c069141ad556379068297ec9883e3b53` / `sha256:3b5d20e5758beef40e38e19673f23ac4ea5bffc3fcfd2f4a37151cb1c6442f5f`; `x86_64-unknown-linux-gnu` |
| Arm64 kernel / public lifecycle runner | `sha256:e89b932d8a39d6fceb2b2495e077172e233e8bdaaeeb1f118a47be2608e98ece` / `sha256:3e0cbb54d90b03dc44f93a8f2c87066dfc6e0a2b8323591661a0261ab8440cdd`; `aarch64-apple-darwin` |
| Native witness reports | Jacob's MacBook Pro `sha256:67c864101b6cde1b82cf8ff53b8bb747011e81bbe02cb23ae34af8b754547464`; Bobs Mini `sha256:4b620fcb56c0762620d87c4a9422b3519f3de9b6dbdf4179dd508a76d1635fd9`; `navillus` Linux `sha256:b0b37e5b964664e9cbf4db96882f8b5cc1b4bdcc68c47749a8d4cb03d631e0f2` |
| Package-certifier leaf key identity | `sha256:7bbbb6a94cb24edf5ccbaa34129598698deaf3aa5115130abb85602ab68f3014`; raw key `033212831d4f2022bce8bc70e8f4d7d970b41e1d32a35a207dd0d7731db9352a` |
| Operator-capacity document | `sha256:f6e5ff0abb5e32a4fdc39f63a6c443f0bfe73f63ed2dcf820a5c29fb4b0bf6b8` |
| Governance policy / ceremony manifest / report | `sha256:f14378e9ec55233a0fe1519e566605f65be586479c97758724460a267680ed3f` / `sha256:578239199e3006f1534811cc1042614532db909b94cf57fb167c4a7fcfb186d1` / `sha256:e19747f3100b9d8c64ddf558b946454af292c34d81d8bf125b7682d0b18cfd25`; generation 1 requires 2 of 3 valid release-domain signatures |
| Public install lifecycle | `sha256:273ad23971cd12fd9974698dd645eb63ddcfefb71b20149e21cf1c56d8f4cb4d`; bootstrap, inactive successor admission, activation and rollback pass under the exact operator capacity |
| Pre-publication negative controls | `sha256:b9ac7e3aae6232c535d85c7272252b5ce819ced4a0b5d01521f47852ba071b0b`; `pass`; blockers empty |
| Pre-publication reproduction matrix | `sha256:bddb4e8520d6d30b3757504337dace9f6cd43304142b1572de205c84f35649e8`; independently reproduced; bounded component-complete claim true; external North Star false |
| Publication negative controls | `sha256:1ef51f0a9234dcbc533b553c5d802d4d70803e01aa724b5db75ede68044b0a07`; 10/10 mutations rejected; pristine publication verifies before and after |
| Fresh Bobs post-publication recovery / lifecycle | `sha256:08b7c9957ce51886c793ed623b7312e90834180b3ffeb1fc92fcd5426659aa2e` / `sha256:8b42a8a221e6ffd30bd6c949ae21d343fca9e39b1e757fa4c58b81240904565e`; canonical, public-only and pass |
| Independent publication audit | Exact 15-role object closure and two distinct, valid, non-revoked signatures satisfy the 2-of-3 policy; no retired root, private-key path or R4 governance secret is present |
| Signing-material retirement | Temporary R4 governance private keys were destroyed only after final Bobs verification; with them absent, ceremony `sha256:578239199e3006f1534811cc1042614532db909b94cf57fb167c4a7fcfb186d1`, publication, aggregate and byte-identical publication negatives all reverified |
| Reproduction and recovery hosts | Components: Jacob's MacBook Pro and Bobs Mini; native arm64: both Macs; native Linux: `navillus`; fresh public recovery and durable custody: Bobs Mini |
| Regression suite | 196/196 under Python 3.9 and 3.14 in the working source and again from a fresh extraction of the deterministic source archive |

The R4 claim is bounded. The multi-host reports prove exact bytes and declared
targets, not organisational independence. The governance threshold proves
signature-policy enforcement, not multi-person key custody. Bobs holds a
durable, verified operator copy, not third-party custody. The publication can
be copied and verified without private material, but it was not uploaded to or
resolved from a remote registry. These are R5 facts, not wording upgrades to R4.

### Retained exact R3 release

The exact runtime package pair retained by R4 was first released by R3:

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

The retained R3 signed aggregate manifest is authoritative for that historical
release root, public key, complete package/native/source/contract trees and
every R3 report digest.
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

R4 retains the useful bounded-local capability slice completed in R1–R3. It
does not add a new factory role or service; it makes the exact existing factory
reproducible, installable and recoverable on the two closed native targets. The
factory itself can:

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

The boundary is equally important. R4 does **not**:

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

Outside the running factory, the R4 release toolchain can deterministically
snapshot and archive source, reproduce components and native executables,
produce an SBOM, verify a threshold-signed publication, safely install it and
exercise public-key-only recovery. Those host release tools are not admitted
factory workloads and do not expand what the component graph can do.

## 7. Execution and release evidence

### 7.1 Current R4 proof closure

The R4 aggregate joins release engineering and the retained R3 runtime closure
rather than treating isolated test passes as a release claim:

| Evidence class | What it proves |
| --- | --- |
| Frozen source and archives | The exact source snapshot, vendor closure, deterministic source archive, component release archive and install archive agree byte-for-byte with the publication matrix. |
| Component reproduction | Two physical Mac witnesses independently derive the exact 22-component incumbent/successor set from the frozen source. |
| Native reproduction | The arm64 kernel reproduces on two physical Macs; the Linux target is built and attested on `navillus`; each report binds toolchain, source, target, binary and runtime dependencies. |
| Governance | A generation-1 2-of-3 policy, release leaf-key lifecycle and negative controls bind the exact release and fail closed. This proves threshold mechanics, not multi-person custody. |
| SBOM and publication | The SPDX document and coverage report enumerate the exact source, component release, install and native artifacts plus closed runtime dependencies; the signed content-addressed publication retains the exact objects. |
| Public install and recovery | Public inputs alone reproduce install, bootstrap, inactive successor admission, activation, rollback and fresh post-publication recovery under an exact operator-capacity document. |
| Publication negatives | Wrong signatures, object mutations, archive substitutions, role swaps, policy changes and lifecycle mismatches are rejected while pristine verification remains stable. |
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

The signed publication records the pre-publication matrix. The final aggregate
is deliberately external to that signed root: it independently verifies the
publication, joins the matrix to publication-negative evidence and a fresh
post-publication lifecycle, and records R4-C0 through R4-C7 `pass` with no
private-key dependency. This self-reference boundary prevents a publication
from claiming that its own future recovery has already happened.

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
| R4-C0 — Contract and matrix | **Pass** | The frozen component/native boundary contract and canonical pre-publication matrix agree. |
| R4-C1 — Source and archives | **Pass** | The exact source snapshot and source, component-release and install archives are closed and reproducible. |
| R4-C2 — Components | **Pass** | The independent physical component witnesses report the same exact 22-node component set. |
| R4-C3 — Native targets | **Pass** | Arm64 reproduction and Linux target evidence bind exact binaries, build recipes, source closure and runtime dependencies. |
| R4-C4 — Governance | **Pass** | The threshold policy, public ceremony and pre-publication negative controls agree and fail closed. |
| R4-C5 — SBOM | **Pass** | SPDX and coverage documents exactly cover the five published artifact roles and closed runtime dependencies. |
| R4-C6 — Public lifecycle | **Pass** | Pre-publication install plus fresh post-publication recovery prove bootstrap, inactive admission, upgrade and rollback from public inputs. |
| R4-C7 — Publication and aggregate | **Pass** | The signed publication, publication negatives, recovery and external final aggregate join with no blockers. |

`open_release_blockers` is empty.

The R4 claim is exact. Any new origin, TLS peer, provider, credential placement,
operator widening, platform, component, source byte, toolchain or policy creates
a different closure and reopens the applicable transport, crash, credential,
isolation, reproduction, governance and release gates.

## 9. Current architectural decisions and limits

### 9.1 Per-consumer principals are the default

New component-complete releases use the R2–R4 principal/alias model. The R1
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

The operator independently pins both the generation-1 governance policy and
the raw Ed25519 package-certifier public key. Certificates bind the exact
package closure and TCB inventory. Private keys are never stored in a package,
native executable, mechanism state or custody release tree.

### 9.6 Scope expansion always creates a new claim

Changing the graph, WIT, profile, native source, native target, operator bounds
or enabled mechanisms requires a new signed release and reopened gates. The R4
publication remains evidence for its exact cohort only; the retained R3 root
remains evidence for its original arm64 cohort, and the historical R2 root
remains evidence for its disabled-HTTP cohort only.

## 10. Phase history and forward roadmap

| Phase | Status | Durable result |
| --- | --- | --- |
| R0 | Historical regression baseline | First bounded component-complete release and fail-closed release verification. |
| R1 | Historical useful baseline | One real bounded local source-change workflow, still using a static graph-union host principal. |
| R2 | **Complete — historical baseline** | Per-consumer alias authority, graph-qualified ownership and independently reproduced lifecycle. |
| R3 | **Complete — retained runtime baseline** | Tightly bounded external transport without native provider, retry, workflow or policy semantics. |
| R4 | **Complete — current release** | Frozen source, multi-host component/native reproduction, two closed targets, threshold governance, exact SBOM, signed publication, public-only recovery and durable operator custody. |
| R5 | **Next — Not yet** | Reassess the external operational North Star using genuinely external evidence. |

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
qualified live-provider milestone. C0–C7 pass and the blocker set is empty. R4
retains this runtime closure unchanged and adds release reproduction,
governance, publication and recovery evidence around it.

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

The retained R3 native attestation did not claim byte-for-byte reproducibility across
different Cargo target-directory paths: those paths and the resulting Mach-O
UUID differed between otherwise equivalent clean builds. R4 closes that gap
for its frozen source: independent physical arm64 builds produce the same exact
kernel bytes.

### R4 — Reproducible multi-platform release and key governance

**Priority:** completed current release

**Status:** **complete for the exact signed R4 cohort**

R4 closes the reproducibility gap without changing the factory's workload
model. The completion evidence establishes:

1. A canonical source snapshot with 325 project files and 25,441 vendored
   files, plus exact source and vendor closure digests.
2. A deterministic 29,896-entry source archive emitted byte-identically under
   Python 3.9 and 3.14 and safely reopened in a fresh extraction.
3. An exact content-addressed component release archive containing the retained
   R3 incumbent and successor; both physical Mac witnesses independently
   reproduce the same 22-component set.
4. Exact native reports for `aarch64-apple-darwin` and
   `x86_64-unknown-linux-gnu`; the arm64 executable reproduces byte-identically
   on Jacob's MacBook Pro and Bobs Mini, while `navillus` supplies the closed
   Linux witness and exact runtime dependency inventory.
5. A generation-1 governance policy requiring any 2 of 3 authorized release
   signatures, a separately pinned package-certifier leaf key, public
   rotation/revocation evidence and negative signature controls.
6. Deterministic public install and source archives, an exact SPDX SBOM plus
   coverage report, and a signed content-addressed operator publication.
7. Public-input-only install, bootstrap, inactive successor admission,
   activation, rollback and restart under the exact operator-capacity digest.
8. Pre-publication and post-signing negative campaigns that reject path,
   archive, role, target, policy, signature, object and lifecycle substitution.
9. Fresh post-publication recovery on Bobs Mini, followed by a final external
   aggregate that joins the publication, matrix, negatives and recovery with
   R4-C0 through R4-C7 `pass` and no private-key dependency.
10. Durable content-addressed operator custody on Bobs Mini, separate from its
    preserved mutable development worktree.

Those results close the R4 engineering milestone, but their governance and
custody scope must be stated literally. The 2-of-3 policy was exercised as
signature mechanics; it does not establish that separate people or
organisations controlled the keys. Bobs Mini is a second physical host and a
durable release location under the same operator, not independent external
custody. The signed publication is portable and independently verifiable, but
it is not evidence of a remote registry or outside publication authority.

The exact R4 publication and aggregate identities are listed in section 3 and
the compact retained release record linked in section 12.

### R5 — Reassess the external North Star

**Status:** **Not yet**

External closure still requires fresh source precommit, a real qualified
provider interaction, custody controlled outside the current operator,
independent reviewer signature, persisted dossier reopen/evaluation and
explicit external publication authority. A remote registry, if chosen, must be
exercised as a real distribution and resolution path rather than inferred from
a local signed directory.

Only the `closure-evaluator` component may interpret that dossier. The native
substrate may verify signatures and store bytes but may not decide whether the
North Star is closed.

## 11. Canonical verification procedure

For the ordinary networked Git checkout, run the pinned, sharded verification
driver:

```bash
./scripts/verify.sh
```

That verifies the immutable Git import of the signed 325-file project closure,
the compact R4 record, all release-tool and native-inventory tests, the
component/kernel/tool/oracle Rust suites, and the component build. See
[`R4-SOURCE-BASELINE.md`](R4-SOURCE-BASELINE.md) for the deliberate separation
between normal registry-backed development and the exact vendored offline
source archive.

Full release verification is a separate custody operation. It requires
OpenSSL 3 with Ed25519 `pkeyutl -rawin` support; Apple LibreSSL is insufficient.
The Operations custody runbook pins the exact executable and records the
successful Bob verification environment.

Verify the R4 publication from independently obtained generation-1 policy and
raw package-certifier leaf-key bytes. Do not trust policy or key copies merely
because they are inside the publication:

```bash
python3 tools/r4-publication.py verify \
  --publication PATH_TO_SHA256_PUBLICATION_ROOT \
  --policy PATH_TO_INDEPENDENT_GENESIS_POLICY \
  --release-public-key PATH_TO_INDEPENDENT_RAW_LEAF_KEY
```

Then follow [`tools/R4-PUBLIC-RECOVERY.md`](../tools/R4-PUBLIC-RECOVERY.md) from
an absent install and mechanism-state root. The procedure safely verifies and
extracts the source, component-release and install archives, selects one of the
two closed native targets, and performs bootstrap, inactive successor
admission, upgrade, rollback and restart without private material.

The final aggregate is external to the publication and must reproduce from the
exact pre-publication matrix, publication-negative report and fresh
post-publication reports:

```bash
python3 tools/r4-aggregate.py verify \
  --matrix PATH_TO_MATRIX \
  --publication PATH_TO_SHA256_PUBLICATION_ROOT \
  --policy PATH_TO_INDEPENDENT_GENESIS_POLICY \
  --release-public-key PATH_TO_INDEPENDENT_RAW_LEAF_KEY \
  --publication-negatives PATH_TO_PUBLICATION_NEGATIVES \
  --postpublication-recovery PATH_TO_RECOVERY_REPORT \
  --postpublication-lifecycle PATH_TO_LIFECYCLE_REPORT \
  --aggregate PATH_TO_FINAL_AGGREGATE
```

Every `PATH_TO_*` value must resolve to the exact object named by the final R4
release record. A placeholder is not evidence. Verification must report the
same publication root and aggregate digest listed in section 3.

The retained R3 release remains independently verifiable by passing its
content-addressed directory to `tools/component-release-bundle.py verify` with
the independently obtained raw Ed25519 key:

```bash
python3 tools/component-release-bundle.py verify \
  artifacts/component-complete/releases/sha256-ed9eedf3633533cb877a0e0636f9b75a1a0050f426af623fc1ab5e934849e8c9 \
  --expected-public-key-hex \
  033212831d4f2022bce8bc70e8f4d7d970b41e1d32a35a207dd0d7731db9352a
```

The retained R2 release likewise remains independently verifiable as historical
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

The compact current R4 release record is
[`sha256:659cdf6b1de2196a7f33fbd3cb55ed4dd7e7a8b514ce6970e1e392e6aabb8b12`](../artifacts/component-complete/r4-releases/sha256-659cdf6b1de2196a7f33fbd3cb55ed4dd7e7a8b514ce6970e1e392e6aabb8b12/).
The signed publication and
external post-publication aggregate remain authoritative; this roadmap mirrors
their identities and is not part of either closure.

The retained R3 aggregate is
[`sha256:ed9eedf3633533cb877a0e0636f9b75a1a0050f426af623fc1ab5e934849e8c9`](../artifacts/component-complete/releases/sha256-ed9eedf3633533cb877a0e0636f9b75a1a0050f426af623fc1ab5e934849e8c9/).

Supporting locations:

- normative component-complete contract: `contracts/component-complete/`;
- current machine reports: `artifacts/component-complete/`;
- component sources: `components/`;
- canonical WIT package: `wit/wasm-biotic/`;
- standalone native substrate: `kernel/`; and
- build, verification and reproduction tools: `tools/`.

Historical R0, R1 and R2 aggregate roots remain beside R3 under
`artifacts/component-complete/releases/`. R4 records live separately under
`artifacts/component-complete/r4-releases/` because the R4 publication and
external aggregate have a different self-reference boundary. Historical M0–M7
native-oracle records remain under `artifacts/baseline/` and historical
documentation. They prove only their named bytes and scopes.

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
