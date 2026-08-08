# Acceptance Spec: supervisor-native-supervisor-challenger-evaluation

Status: Implemented  
Applies to: `v1.2.5` through `v1.2.6`

## Purpose

Prove that a native supervisor challenger can be compared against an incumbent under all six `v1.2` dimensions and promoted to a governed readiness decision without public interface change.

## Scenario Summary

```text
incumbent and challenger are evaluated under the same inputs
  -> six-dimension comparison is recorded
  -> sufficiency evidence is recorded
  -> promotion readiness is decided
  -> shadow evaluation bundle persists and reloads
```

## Primary Assertions

1. all six supervisor comparison dimensions are represented
2. the native-sufficiency gate succeeds with explicit evidence
3. promotion readiness reaches `Promotable`
4. the persisted shadow bundle reloads without losing challenger evidence

## Trace

- [replacement.rs](../../src/execution/replacement.rs)
- [governance.rs](../../src/execution/governance.rs)
- [storage.rs](../../src/execution/storage.rs)
- [supervisor_native_supervisor_challenger_evaluation.rs](./supervisor_native_supervisor_challenger_evaluation.rs)
