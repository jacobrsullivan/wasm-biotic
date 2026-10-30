# M1 Reference Component

This fixture is the fixed-interface reference task used by the active
implementation roadmap.

The immutable interface is defined in `template/component.wit`:

```wit
transform: func(input: s32) -> s32
```

The incumbent implementation in `template/component.wat` returns its input
unchanged. `candidates/increment.wat` is the known-valid challenger and returns
`input + 1`. `candidates/broken.wat` is the negative control and must not build.

The M1 lifecycle may copy `template/` into a disposable workspace and replace
only `component.wat`. It must not modify `component.wit`, follow symlinks, or
write outside the configured candidate-workspace root.

Reproduce the M0 fixture check from a clean checkout with:

```bash
CARGO_TARGET_DIR=/tmp/aiaf-v1-target cargo test --manifest-path Cargo.toml \
  supervisor_m0_reference_task_reproduces_from_tracked_fixture
```

This checked-in fixture proves only that the reference task is reproducible.
It does not by itself prove the effectful M1 candidate lifecycle.
