# Acceptance Spec: supervisor-integrated-multicycle-stability

Status: Implemented  
Applies to: `v1.1.6`

## Purpose

Prove that the hardened `v1.1` slice works as one integrated bounded supervisory loop without changing public interfaces.

## Scenario Summary

```text
cycle 1 approval lineage is persisted
  -> cycle 2 worker dispatch and synthesis run
  -> memory evidence is updated and retained
  -> rollback evidence remains available across cycles
  -> rollback restores cycle 1 without interface drift
```

## Primary Assertions

1. capability, background, checkpoint, and rollback evidence coexist in one durable state
2. worker orchestration and memory hardening remain compatible
3. multi-cycle persistence does not lose lineage-critical refs
4. rollback can restore the prior cycle from durable evidence

## Trace

- [memory.rs](../../src/execution/memory.rs)
- [orchestration.rs](../../src/execution/orchestration.rs)
- [governance.rs](../../src/execution/governance.rs)
- [storage.rs](../../src/execution/storage.rs)
- [supervisor_integrated_multicycle_stability.rs](./supervisor_integrated_multicycle_stability.rs)
