# Executable component-factory fixtures

This directory is a deliberately small executable proof of a component-complete
factory graph. Every stage exposes the typed operation
`invoke(candidate: s32, minimum: s32) -> s32`.

- The supervisor components decide how a successful worker result is composed.
- The worker components transform the candidate before asking the service and
  decide how a successful service result is composed.
- The service components decide whether the candidate meets the threshold.
- `supervisor-spin.wat` is an intentionally non-terminating policy component
  used to prove that the same host fuel limit applies at every stage.

The host does not contain any of those rules. It instantiates each component,
meters it, and forwards the two typed values unchanged through a single generic
`downstream` callback. Swapping only one WAT fixture changes only that stage's
behavior in the focused Rust tests.

These fixtures demonstrate the architecture boundary; they are not claimed as
the production Wasm-Biotic factory implementation.
