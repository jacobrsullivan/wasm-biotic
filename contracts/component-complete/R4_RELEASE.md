# R4 Reproducible Release and Certifier Governance Contract

## 1. Scope

This contract closes the bounded R4 release phase. It does not change the
component-complete factory contract and it does not claim the external North
Star.

The released factory remains a versioned, content-addressed graph of Wasm
components. Native code may instantiate, meter, persist, communicate, verify
bytes and signatures, and enforce declared capabilities. It may not implement
factory roles, services, workflows, health meaning, promotion decisions,
rollback policy, or North-Star policy.

R4 release builders, archive tools, SBOM tools, certifier-governance tools and
public recovery drivers are offline or operator-side tools. They are not linked
into a component world and are not reachable factory roles.

## 2. Closed platform set

The R4 platform claim is exactly:

| Target | Native format | Execution environment |
| --- | --- | --- |
| `aarch64-apple-darwin` | Mach-O 64-bit arm64 | arm64 macOS 26 |
| `x86_64-unknown-linux-gnu` | ELF 64-bit x86-64 | x86-64 Linux with the attested glibc/system dependency set |

No other target is implied. Component artifacts target `wasm32-wasip2` and are
identical across both native platforms.

R4 requires all 22 raw factory components to reproduce byte-for-byte on at
least two independent physical machines. Each native target must be built from
the same source snapshot and executed on its matching platform. The reference
`aarch64-apple-darwin` native executable must additionally reproduce
byte-for-byte on two independent physical machines. This proves the closed R4
set; it is not a claim about every architecture or operating system.

## 3. Reproducible inputs

One source snapshot is authoritative. It must contain:

1. `components/`, `wit/wasm-biotic/`, `kernel/` and
   `contracts/component-complete/`;
2. release and verification tooling under `tools/`;
3. the root `Cargo.toml`, `Cargo.lock` and `src/` library source required to
   compile the release tools, labelled as a transitional build dependency and
   never as the production factory;
4. the exact compile-time embedded inputs required by that transitional
   library: `README.md`, `reference-docs/introduction.md`, `notes/ROADMAP.md`,
   `artifacts/fixtures/m1-reference-component/template/component.wit` and
   `artifacts/fixtures/m1-reference-component/template/component.wat`;
5. every Cargo manifest and lockfile in those roots;
6. the complete versioned Cargo registry source closure under `vendor/`; and
7. an offline Cargo configuration selecting only that vendor directory.

The five embedded inputs are frozen, point-in-time build dependencies only.
They are not normative R4 factory inputs, factory roles, services, workflows,
policy or current status authority. In particular, the live
`notes/ROADMAP.md` may advance after publication without changing the already
content-addressed source snapshot. Every other path under `notes/`,
`reference-docs/` and `artifacts/` is excluded from the R4 source closure.

From a fresh extraction, the snapshot must build both public packaging
binaries using only the vendored dependency closure:

```sh
cargo build --locked --offline --release \
  --manifest-path tools/component-graph-package/Cargo.toml \
  --bin wasm-biotic-component-graph-package \
  --bin public-key-lifecycle
```

The source snapshot is an exact byte, size and normalized-mode closure. It must
contain no `.env`, operator or release private key, credential, generated
target directory, Git metadata, link or special file. Private-key-shaped files
outside `vendor/` are forbidden. Public, non-secret test vectors shipped inside
the checksum-authenticated upstream Cargo vendor closure are source fixtures,
not operator custody or release authority; retaining that exact upstream
closure is the only exception. A Git revision may be recorded as context but
is not authoritative for a dirty or uncommitted source set; the archive digest
and manifest are authoritative.

Per-platform native attestations bind the exact source closure, Cargo locks,
WIT closure, compiled `kernel/native-tcb.json`, target, Rust/Cargo/LLVM versions,
system dependencies, build recipe and final executable digest. They must not
record a physical checkout, Cargo home, Rustup home or target-directory path as
identity.

The macOS build must eliminate the R3 path-length-dependent Mach-O identity
gap. Two fresh target directories with materially different physical paths
must produce the same final executable, UUID, code-signature identity and
SHA-256 digest, and that executable must run successfully.

## 4. Component reproduction

An independent builder receives only the public source snapshot, an already
signed package and its raw public leaf key. It does not receive or accept a
release private key. Before compiling, it must verify the complete source
snapshot, verify the package's Ed25519 release certification, bind the signed
raw-artifact map to the composition evidence and verify the retained raw-file
closure.

The retained R3 component bytes have a frozen legacy build identity: changing
the compiler host or adding Rust path-remapping flags changes LTO function
order even when the resulting component is semantically identical. Therefore
an R4 witness for these already-signed bytes must use the recorded
`aarch64-apple-darwin` Rust/Cargo/LLVM toolchain, expose the authenticated
component and WIT inputs through the historical logical path
`/Users/jacobsullivan/Desktop/wasm-biotic`, expose the authenticated vendored
packages read-only through
`/tmp/wasmbiotic-cargo/registry/src/index.crates.io-1949cf8c6b5b557f`, and use
the frozen Cargo and Rustup homes `/tmp/wasmbiotic-cargo` and
`/tmp/wasmbiotic-rustup`. The witness must fail rather than replace or mutate
an occupied checkout, Cargo home or Rustup home. It runs with network and
writes to those projections denied, ambient Rust flags and compiler wrappers
cleared, locked dependencies, incremental compilation disabled, no path
remapping and a fresh external target directory.

The historical source path may be supplied by a narrow operator-side read-only
filesystem alias when the physical builder cannot create that absolute path.
That alias is not a factory role or component. Its complete public source,
compiler identity, build recipe, source and native-artifact digests, virtual and
physical roots, and exact sandbox profile must be bound into the witness report.
The sandbox must deny direct reads from any real checkout at the historical
path, deny writes to both roots and the frozen Cargo/Rustup homes, and deny
network access. This makes successful compilation evidence that the alias was
active and prevents silent fallback to an ambient checkout. An opaque
binary-only alias, a Rust compiler path-remapping flag, or an unreported mapping
is forbidden.

This frozen projection is a narrow reproduction rule for the retained R3
bytes, not a portable-build claim or an allowed identity for new releases.
Components first signed after R4 must eliminate this path- and host-sensitive
legacy identity.

The builder compiles the exact six workers, supervisor reducer and 15 other
factory components for `wasm32-wasip2`.
For every node it must compare the rebuilt file to both:

- the raw digest in `evidence/composition.json`; and
- the retained `components/sha256-<digest>.wasm` bytes.

The gate passes only when all 22 comparisons are byte-identical and the
component-set digest is the same for every witness.

## 5. Operator certifier governance

### 5.1 Boundary

The production kernel continues to pin one raw Ed25519 release-certifier key.
That leaf key verifies package certification and remains policy-neutral. It
does not select, rotate or revoke itself.

R4 adds operator-side governance above the leaf: a canonical 2-of-3 Ed25519
policy. The policy authorizes exact release and publication payloads through
domain-separated detached signatures. This quorum is release governance, not
factory policy, and cannot be driven by a component package.

### 5.2 Policy and transition rules

A policy contains exactly three sorted, distinct active public keys, threshold
two, a positive monotonic generation, the predecessor-policy digest and a
cumulative sorted revocation tombstone set.

Rotation or revocation creates a successor policy. It must:

1. increment the generation by exactly one;
2. name the exact predecessor policy digest;
3. retain every earlier revocation tombstone;
4. replace at least one active key while retaining the 2-of-3 shape;
5. carry a valid old-policy quorum over the exact transition; and
6. carry a successor-policy quorum, including proof of possession from every
   newly introduced key.

Revocation additionally tombstones every removed key. Tombstones cannot be
removed or reactivated. A verifier distinguishes historical validity at a
named policy from current acceptability at an independently pinned policy
head; an isolated release cannot prove that no newer revocation exists.

Duplicate, unknown, revoked, mixed-policy, cross-domain or malformed
signatures never count toward a quorum. Replay, downgrade and fork-shaped
transitions fail closed.

### 5.3 R3 re-root fact

The R3 leaf private key was destroyed before it signed a transition and R3 did
not have this governance policy. Cryptographic continuity from the R3 key
therefore cannot be manufactured after the fact. R4 is an explicit
operator-approved out-of-band genesis/re-root. Historical R3 verification
remains valid under the retained R3 public key. The R4 evidence must state this
fact and must not describe the change as an R3-signed rotation.

R5, not R4, owns proof of genuinely separate human custodians, external key
locations and an independently distributed live policy head.

## 6. Archives and SBOM

R4 publishes three distinct content-addressed archives:

1. a vendored source archive;
2. the complete signed component-release archive; and
3. a public install archive containing the selected platform binaries, signed
   packages, public keys/policy, configuration, attestations and recovery
   instructions needed for a clean install.

The install root contains one canonical, non-secret operator-capacity document
at the relative path named by the closed `INSTALL.json.operator_capacity`
field. It is projected from the exact signed incumbent constraints and grants
no authority beyond their intersection. Every production-kernel initialization
and the separate public lifecycle runner must consume those same installed
bytes. Their SHA-256 digest is retained by both the inner component lifecycle
report and its outer public install report.

Every archive uses a deterministic USTAR payload with byte-sorted paths, fixed
UID/GID/names/timestamps, normalized `0644`/`0755` modes, no links or special
files, and an exact canonical manifest. Verification binds path, kind, mode,
size and SHA-256 before extraction. Extraction rejects traversal, duplicate,
extra, missing, truncated, mutated and non-canonical entries.

The SPDX 2.3 JSON SBOM is deterministic at the release epoch. Its strict
coverage report binds:

- every included Cargo manifest and lockfile;
- every registry package in those lockfiles;
- every local production/build-tool package;
- source, WIT, raw/scoped/derived component and native executable bytes
  supplied to the release; and
- the declared runtime system dependencies for each native target.

An omitted, phantom or wrong-digest file or package fails the coverage gate.
A dated vulnerability database or VEX statement is separate, time-sensitive
evidence and is not fabricated as part of the deterministic SBOM.

## 7. Public-key-only install and lifecycle

The lifecycle gate has two non-circular stages. Before publication, a clean
install run starts from an absent mechanism-state directory and uses only the
prepared archive bytes, public keys/policy and the canonical non-secret
operator-capacity document selected by `INSTALL.json`.
Its complete lifecycle report is retained as a publication object. After the
publication root is signed, an external recovery driver first verifies that
final root, then starts from another absent state directory and repeats the
complete clean-install lifecycle from the published bytes. The external
postpublication wrapper and its fresh lifecycle report cannot be objects in
the root they verify; the R4 aggregate binds their exact digests to that root.

Neither stage accepts or reads a private key. Together they must execute and
retain evidence for this sequence:

1. in the postpublication stage, verify the final publication quorum, trust
   policy, independently supplied raw release leaf key and exact object
   closure before extracting or executing anything;
2. verify and safely extract the install and component-release archives;
3. verify the inner signed release with an independently supplied raw public
   leaf key;
4. select the attested binary for the exact host target and verify its digest;
5. initialize fresh mechanism state with the incumbent manifest, leaf key and
   installed operator-capacity document;
6. admit and bootstrap the incumbent;
7. admit and instantiate the successor while proving the active pointer did
   not change;
8. submit one useful incumbent component cycle;
9. let the incumbent components issue the exact successor migration and
   activation request;
10. reload and execute one useful successor component cycle;
11. present an explicit unhealthy observation to the component policy and let
    that component request rollback;
12. reopen the process, prove the incumbent graph/state pair survived and run
    an exact replay/post-rollback component cycle; and
13. reject a wrong key, tampered package and attempted automatic activation.

The prepublication lifecycle runner and postpublication recovery driver may
create fixtures and call public component entry points. They may not interpret
health, choose promotion, issue a substrate activation directly, implement a
worker/service, or substitute native success. Upgrade and rollback decisions
and receipts must come from admitted Wasm components.

## 8. Publication closure

The R4 publication claim contains exact content-addressed objects for:

- the source, component-release and install archives;
- the SPDX SBOM and coverage report;
- the independently usable raw release leaf public key;
- the trust policy and complete public governance-ceremony evidence, including
  transition signatures, successor proofs of possession, revocation evidence
  and the governance test report;
- the R4 contract;
- one native executable and one native attestation for each closed target;
- the component/native independent reproduction matrix; and
- the complete prepublication public-key-only lifecycle report.

The claim sets `component_complete_claim` to true and
`external_north_star_claim` to false. A detached 2-of-3 release-domain quorum
signs that exact claim. The content-addressed publication root binds the claim,
policy, sorted signatures and every object. Complete install-archive
publication metadata may be signed in the separate publication domain to avoid
self-reference.

The postpublication recovery wrapper, its fresh lifecycle report and the final
aggregate report are external verification evidence. They name and bind the
exact signed publication root but are not members of that root.

Private keys, signing requests containing secret bytes, temporary
credential/TLS material and mutable build caches are not publication objects
and must be destroyed or returned to their external custodian after signing.

## 9. Mandatory R4 gate

R4 is complete only when one aggregate report proves all of the following for
the exact publication root:

| Gate | Requirement |
| --- | --- |
| R4-C0 | Frozen contract, closed two-target set and factory/native boundary |
| R4-C1 | Exact vendored source snapshot and repeatable deterministic archives |
| R4-C2 | 22/22 raw components reproduced on independent physical machines |
| R4-C3 | Per-target native build, execution and attestations; reference macOS binary reproduced independently and across unequal build paths |
| R4-C4 | 2-of-3 release/publication quorum and rotation/revocation negative matrix |
| R4-C5 | SPDX SBOM and strict complete coverage report |
| R4-C6 | Embedded prepublication and fresh postpublication public-key-only install, bootstrap, inactive admission, upgrade, rollback, restart and replay |
| R4-C7 | Signed content-addressed publication closure, verified-before-use recovery and post-signing negative controls |

Every gate is bound to exact digests. A missing object, unexecuted target,
private-key dependency, unresolved blocker or failed negative control leaves R4
open.
