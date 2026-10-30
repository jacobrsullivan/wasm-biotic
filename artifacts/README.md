# Artifacts

This directory separates small Git-resident evidence and fixtures from large,
content-addressed release custody.

## Current release authority

R4 is the current bounded release. Its signed publication root is:

`sha256:659cdf6b1de2196a7f33fbd3cb55ed4dd7e7a8b514ce6970e1e392e6aabb8b12`

The final external aggregate is:

`sha256:60a8cd54195e479f766c03cf5ecae4418e1f20b7ba895727273e46862fa975ae`

The small repository-side index is retained at
[`component-complete/r4-releases/sha256-659cdf…`](component-complete/r4-releases/sha256-659cdf6b1de2196a7f33fbd3cb55ed4dd7e7a8b514ce6970e1e392e6aabb8b12/).
It contains the final aggregate, reproduction matrix, public governance and
negative-control reports, recovery reports, source-snapshot manifest and raw
public leaf key. Verify those exact retained bytes with:

```sh
./scripts/verify.sh record
```

The compact record is not the signed publication, source archive, component
archive, install archive, native executables or complete custody tree. Full
verification starts from independently held trust material and the complete
content-addressed custody directory. On Bob's Mini it also requires Homebrew
OpenSSL 3; Apple LibreSSL cannot verify the Ed25519 signatures used by R4.

R4 records `component_complete_claim: true` only for its exact bounded cohort,
and `external_north_star_claim: false`. Bob's copy is same-operator custody,
the 2-of-3 exercise proves signature mechanics rather than separate-human key
control, and the publication directory is not a remote registry.

## Source and dependency bytes

The authenticated source snapshot is described by the checked-in
`SOURCE-SNAPSHOT.json` and [source-baseline note](../notes/R4-SOURCE-BASELINE.md).
Git retains the exact 325 project files through the immutable import commit.
The 25,441 vendored Cargo files remain in the deterministic content-addressed
source archive instead of becoming Git objects.

## Fixtures and historical evidence

`fixtures/` contains narrow checked-in inputs used by tests and release tools.
The two WAT/WIT template files under
`fixtures/m1-reference-component/template/` are part of the signed R4 project
source selection. The textual inputs under `fixtures/component-factory/` are
development test fixtures restored after the immutable source import; they are
not members of the signed 325-file R4 source closure. The remaining M1 README,
task and candidate WAT inputs are also Git-owned development fixtures restored
after that import. The narrow inputs under
`fixtures/component-complete-history/` let source-only tests verify a
historical R1 evidence binding without pretending to retain the full release
package.

Historical R0–R3 package and evidence trees remain lineage for their exact
named cohorts. They do not override the R4 publication or imply that mutable
test output is release authority. New build trees, generated Wasm binaries,
runtime stores, local exports and complete publication bytes belong in ignored
workspace paths or content-addressed custody, not ordinary Git commits.

No R4 governance-signing key or R4 operational credential material belongs in
this directory. That statement is intentionally scoped: dependency test
fixtures in the external vendor closure may contain public sample-key material.
