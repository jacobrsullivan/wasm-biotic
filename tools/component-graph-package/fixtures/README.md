# Component graph package regression fixtures

These canonical JSON documents are the smallest retained inputs needed by the
source-only regression tests:

- `r2/substrate-profile.json` preserves the exact signed R2 profile bytes;
- the two content-digest directories under `r3/` preserve only each graph
  manifest, derivation descriptor and substrate profile.

The fixture directories deliberately omit component binaries, certificates,
evidence and signer material. Complete R2 and R3 packages remain in external,
content-addressed release custody.
