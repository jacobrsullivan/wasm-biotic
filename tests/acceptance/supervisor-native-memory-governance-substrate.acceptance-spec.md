# Acceptance Spec: supervisor-native-memory-governance-substrate

Status: Implemented  
Applies to: `v1.2.3` through `v1.2.6`

## Purpose

Prove that approval lineage, governed review bundles, quarantine blocking, and rollback continuity behave as native substrate responsibilities rather than ambient internals.

## Scenario Summary

```text
approval lineage is persisted
  -> governed review bundle is accepted
  -> quarantine blocks background resume
  -> resolved quarantine allows resume
  -> rollback restores the checkpoint with evidence intact
```

## Primary Assertions

1. approval lineage remains reconstructable from memory artifacts
2. governed review bundles preserve checkpoint evidence
3. quarantine blocks resume until resolved
4. rollback executes only with durable checkpoint and governance evidence

## Trace

- [governance.rs](../../src/execution/governance.rs)
- [memory.rs](../../src/execution/memory.rs)
- [storage.rs](../../src/execution/storage.rs)
- [supervisor_native_memory_governance_substrate.rs](./supervisor_native_memory_governance_substrate.rs)
