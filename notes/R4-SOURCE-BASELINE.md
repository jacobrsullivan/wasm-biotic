# R4 source-control baseline

This Git branch makes the completed R4 implementation reviewable and usable as
a normal development checkout without changing the identity of the signed R4
release.

## Two distinct closures

The signed release source is identified by `SOURCE-SNAPSHOT.json`:

- manifest: `sha256:db64731d0e461bf3e146e30702c45fff9547f3ba9fb89f73385b8b15471e2716`;
- project source: 325 files, closure
  `sha256:ac60f6c97fa48db7243cdd96faf18b5c8feec42caf86b8191c408dc609e68833`;
- Cargo registry vendor tree: 25,441 files, closure
  `sha256:5d8b016343d75fc42088cca3fa5ac7b26f9ee85b27e049dcaaf72ed3f7789bc9`;
- deterministic full source archive:
  `sha256:50b96f7d1c62825d0405c30557a8c813db34b6dac33e0b9c86ba1727278d40c7`.

Commit `f19bed964e562c8c24d081ab01611b6422477e11` imports the signed 325-file
project closure byte-for-byte. The
large vendor tree is deliberately not stored as 25,441 Git objects. It remains
inside the content-addressed source archive in release custody. Extracting that
archive recreates the exact offline snapshot, including its generated
`.cargo/config.toml`.

The branch tip is a development closure layered on that immutable import. It
adds CI, a pinned toolchain, compact evidence, current documentation and a
normal registry-backed Cargo checkout. It also restores the small, textual
`artifacts/fixtures/component-factory/` test inputs that the R4 snapshot did
not select even though the Rust source references them at compile time, the
rest of the hand-authored M1 fixture, and a narrow historical evidence fixture
used by kernel tests. Consequently, the branch tip is not a new signed R4
cohort and must not be described as one. Any successor source-snapshot format
must inventory every Git-owned test input; the frozen R4 selector remains
unchanged so its signed 325-file identity stays reproducible.

## Developer verification

Rust is pinned by `rust-toolchain.toml`; the component build additionally
requires `wasm-tools 1.255.0`. Python cryptographic verification requires
OpenSSL 3. If it is not the host default, set `WASM_BIOTIC_OPENSSL` to its
absolute executable path; on Bob's Mini that is
`/opt/homebrew/bin/openssl`. Run all checks from the repository root:

```sh
./scripts/verify.sh
```

Individual scopes are `preflight`, `record`, `python`, `components`, `kernel`,
`rust-tools`, `oracle`, `format` and `component-build`. Cargo uses the
checked-in lock files and the registry for a normal clean clone. The exact
release archive uses its authenticated vendor closure and remains fully
offline.

The repository-side compact record verifies with the hash-only `record` scope
and does not require OpenSSL. Full detached
signature, archive, native-byte and recovery verification still requires the
complete custody tree and independently obtained trust policy; the compact
record never substitutes for them.

## Authority boundary

- Signed R4 authority: publication root
  `sha256:659cdf6b1de2196a7f33fbd3cb55ed4dd7e7a8b514ce6970e1e392e6aabb8b12`.
- Final external aggregate:
  `sha256:60a8cd54195e479f766c03cf5ecae4418e1f20b7ba895727273e46862fa975ae`.
- Git import authority for the selected project bytes: commit
  `f19bed964e562c8c24d081ab01611b6422477e11` plus
  the signed source-snapshot manifest.
- Current mutable checkout: development material only until a later release
  closes and signs a new cohort.
