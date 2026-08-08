# Acceptance Spec: supervisor-background-quarantine-rollback-control-loop

Status: Implemented  
Applies to: `v1.1.5` through `v1.1.6`

## Purpose

Prove that background approval resumption, quarantine blocking, and rollback execution remain durable and operator-legible.

## Scenario Summary

```text
approval-blocked background state is persisted
  -> granted approval resumes cleanly
  -> quarantine blocks the affected task
  -> quarantine resolves
  -> rollback evidence is validated
  -> rollback restores the safe checkpoint
```

## Primary Assertions

1. background resume requires matching granted approval lineage
2. open quarantine blocks the affected ref
3. resolved quarantine unblocks the governed path
4. rollback requires reconstructable checkpoint and governance evidence
5. governed background and rollback refs remain queryable from durable artifacts

## Trace

- [governance.rs](../../src/execution/governance.rs)
- [storage.rs](../../src/execution/storage.rs)
- [supervisor_background_quarantine_rollback_control_loop.rs](./supervisor_background_quarantine_rollback_control_loop.rs)
