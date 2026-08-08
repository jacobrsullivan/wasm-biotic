# Acceptance Spec: supervisor-native-memory-governance-service-continuity

Status: Implemented  
Applies to: `v1.3.2` through `v1.3.6`

## Purpose

Prove that memory, approval, quarantine, rollback, and operator review continuity remain durable and reconstructable across governed pause, resume, and rollback flows.

## Scenario Summary

```text
approval-blocked runtime state is captured
  -> approval request and decision are persisted
  -> operator review bundle and rollback evidence are attached
  -> open quarantine blocks background resume
  -> resolved quarantine allows governed resume
  -> rollback restores the safe checkpoint with evidence intact
```

## Primary Assertions

1. approval transport lineage remains reconstructable
2. quarantine blocks resume until governance resolves it
3. rollback restores the checkpoint and preserved review evidence

## Trace

- [governance.rs](../../src/execution/governance.rs)
- [memory.rs](../../src/execution/memory.rs)
- [storage.rs](../../src/execution/storage.rs)
- [supervisor_native_memory_governance_service_continuity.rs](./supervisor_native_memory_governance_service_continuity.rs)
