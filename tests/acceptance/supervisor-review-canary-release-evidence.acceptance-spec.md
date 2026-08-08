# Acceptance Spec: supervisor-review-canary-release-evidence

Status: Implemented  
Applies to: `v1.4.2` through `v1.4.6`

## Purpose

Prove that the fixed-interface `v1.4` line keeps review, canary, release, and rejection evidence explicit, durable, and operator-visible.

## Scenario Summary

```text
completed runtime state is captured
  -> review support is attached
  -> canary, release, and rejection evidence is written
  -> runtime state is persisted and reloaded
  -> operator-grade release evidence remains reconstructable
```

## Primary Assertions

1. review bundles carry the expected canary, release, and rejection refs
2. operator review evidence remains linked through reload
3. release evidence is durable rather than ambient

## Trace

- [storage.rs](../../src/execution/storage.rs)
- [governance.rs](../../src/execution/governance.rs)
- [supervisor_review_canary_release_evidence.rs](./supervisor_review_canary_release_evidence.rs)
