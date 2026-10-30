# Wasm-Biotic R4 compact release record

This directory is the small repository-side index for the exact R4 operator
publication:

`sha256:659cdf6b1de2196a7f33fbd3cb55ed4dd7e7a8b514ce6970e1e392e6aabb8b12`

It is not the signed publication, the complete install, or the durable custody
tree. Those bytes were atomically installed, verified from their final Bobs
Mini custody path and retained under the exact path listed below. Within that
tree, the publication remains at
`publication/sha256-659cdf6b1de2196a7f33fbd3cb55ed4dd7e7a8b514ce6970e1e392e6aabb8b12/`;
its digest basename must not be flattened away. The publication root, not this
README or its Git commit, identifies the signed release.

## Exact closure

| Item | SHA-256 or result |
| --- | --- |
| Publication root / `publication-root.json` | `sha256:659cdf6b1de2196a7f33fbd3cb55ed4dd7e7a8b514ce6970e1e392e6aabb8b12` |
| Publication claim | `sha256:fbe0d53a4ea75aec14961ae730b3e8dc94ebc2e1767f1f16e8d78f2eea8fec98` |
| Reproduction matrix | `sha256:bddb4e8520d6d30b3757504337dace9f6cd43304142b1572de205c84f35649e8` |
| Pre-publication negative controls | `sha256:b9ac7e3aae6232c535d85c7272252b5ce819ced4a0b5d01521f47852ba071b0b` |
| Publication negative controls | `sha256:1ef51f0a9234dcbc533b553c5d802d4d70803e01aa724b5db75ede68044b0a07` |
| Post-publication recovery / lifecycle | `sha256:08b7c9957ce51886c793ed623b7312e90834180b3ffeb1fc92fcd5426659aa2e` / `sha256:8b42a8a221e6ffd30bd6c949ae21d343fca9e39b1e757fa4c58b81240904565e` |
| Final post-publication aggregate | `sha256:60a8cd54195e479f766c03cf5ecae4418e1f20b7ba895727273e46862fa975ae`; independently verified under Python 3.9 and 3.14 |
| Durable Bobs operator-custody path | `/Users/bob/Developer/wasm-biotic-releases/sha256-659cdf6b1de2196a7f33fbd3cb55ed4dd7e7a8b514ce6970e1e392e6aabb8b12` |
| Source-snapshot manifest | `sha256:db64731d0e461bf3e146e30702c45fff9547f3ba9fb89f73385b8b15471e2716` |
| Deterministic source archive | `sha256:50b96f7d1c62825d0405c30557a8c813db34b6dac33e0b9c86ba1727278d40c7` |
| Component release archive | `sha256:b009fcd4f0fc098dc8cf43c0011f416a08a44ca9446b49831a5b1d85767791f0` |
| Deterministic install archive | `sha256:71dcac03c222bcf07dafc110d0754d41f6b74fe5d6b9fc0be84972faf6c110e7` |
| Incumbent / successor graph | `sha256:ef9c8aac3b08848d3df56d069df0df405251786e4afb3dd95e1098dd08195eb4` / `sha256:f98f2f8b6be93e3d9342472a54c08ffa7e976d49a796e8f300a116650d6bbebd` |
| Apple arm64 kernel | `sha256:e89b932d8a39d6fceb2b2495e077172e233e8bdaaeeb1f118a47be2608e98ece` |
| Linux x86_64 kernel | `sha256:acec1a22242a29cc29f4a1f15cc87075c069141ad556379068297ec9883e3b53` |
| Governance policy / report | `sha256:f14378e9ec55233a0fe1519e566605f65be586479c97758724460a267680ed3f` / `sha256:e19747f3100b9d8c64ddf558b946454af292c34d81d8bf125b7682d0b18cfd25` |
| SPDX SBOM / coverage | `sha256:9fa6f2f6d7b3f4f7c2ee3a08bdeee2d574ff003c4b4f86f37960ab9261b84ca1` / `sha256:efc4bff0573c5225ec8a96044e926ba3c5b7057c51f9fdd6fac5b67245ba47b4` |
| Public install lifecycle | `sha256:273ad23971cd12fd9974698dd645eb63ddcfefb71b20149e21cf1c56d8f4cb4d` |

## Retained small evidence

The completed record retains byte-for-byte copies of these small public
objects, without duplicating the large archives, component trees or native
executables:

| Path | Role |
| --- | --- |
| `aggregate.json` | External final aggregate joining R4-C0 through R4-C7 |
| `reproduction-matrix.json` | Canonical pre-publication matrix |
| `prepublication-negatives.json` | Archive, component, target, policy and lifecycle negative controls |
| `publication-negatives.json` | Post-signing publication mutation controls |
| `public-lifecycle.json` | Public-install lifecycle before publication |
| `postpublication-recovery.json` | Fresh public recovery wrapper, external to the signed publication |
| `postpublication-lifecycle.json` | Fresh lifecycle produced by post-publication recovery |
| `trust-policy.json` | Public generation-1 governance policy |
| `governance-report.json` | Public rotation, revocation and signing-ceremony report |
| `r3-certifier-public-key.raw` | Raw package-certifier leaf public key; never private material |
| `SOURCE-SNAPSHOT.json` | Exact source-snapshot manifest |

Every retained file must hash to the identity recorded by the final aggregate
or matrix. Missing files or digest disagreements leave this compact record
incomplete; the full publication and custody verifiers remain authoritative.

From the repository root, verify the compact file set and its internal joins
with `./scripts/verify.sh record`. This does not verify omitted signatures or
large byte closures. Full custody verification requires OpenSSL 3 with Ed25519
`pkeyutl -rawin` support; Apple LibreSSL is not sufficient.

Temporary R4 governance private keys were destroyed only after final Bobs
verification. With them absent, the public ceremony, publication, aggregate
and byte-identical publication-negative report all reverified. This record
contains no R4 governance-signing key or R4 operational credential material.
Because no authorized R4 private signer was retained, the release remains
verifiable but its signing lineage cannot be extended or rotated. A later
release must explicitly establish a new live trust root or re-rooting ceremony.

## Claim boundary

R4 proves that this exact bounded component factory can be reproduced,
threshold-signed, installed and recovered from public inputs on the two closed
native targets. It does not expand the component graph's useful workload.

Bobs Mini is durable custody by the existing operator, not custody controlled
by an independent person or organisation. The generation-1 2-of-3 rule proves
threshold-signature mechanics, not multi-person key custody. The signed
content-addressed publication is portable operator publication, not a remote
registry. The external operational North Star remains **Not yet**; R5 owns
qualified live-provider, independent custody/review and external-publication
evidence.

The status authority is
[`notes/ROADMAP.md`](../../../../notes/ROADMAP.md). The operator installation and
reverification procedure is maintained in the Operations repository's
`guides/wasm-biotic-release-custody.md`.
