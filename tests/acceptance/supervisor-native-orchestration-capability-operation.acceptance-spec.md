# Acceptance Spec: supervisor-native-orchestration-capability-operation

Status: Implemented  
Applies to: `v1.2.4` through `v1.2.6`

## Purpose

Prove that bounded routing, capability-envelope operation, and synthesis closure can be handled as explicit native orchestration behavior under the unchanged public contract.

## Scenario Summary

```text
supervisor dispatches bounded worker work
  -> capability operation is admitted under the envelope
  -> worker result is accepted
  -> synthesis handoff closes the agenda item
  -> capability audit remains reconstructable
```

## Primary Assertions

1. bounded worker dispatch proceeds through the native routing path
2. synthesis closure completes the agenda item without interface drift
3. the admitted capability operation remains queryable as an audit-backed artifact

## Trace

- [transition.rs](../../src/execution/transition.rs)
- [orchestration.rs](../../src/execution/orchestration.rs)
- [supervisor_native_orchestration_capability_operation.rs](./supervisor_native_orchestration_capability_operation.rs)
