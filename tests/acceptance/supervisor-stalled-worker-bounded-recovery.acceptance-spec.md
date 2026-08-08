# Acceptance Spec: supervisor-stalled-worker-bounded-recovery

Status: Implemented  
Applies to: `v1.1.4` through `v1.1.6`

## Purpose

Prove that stalled worker recovery remains bounded, replayable, and explicit.

## Scenario Summary

```text
worker dispatch stalls after checkpoint
  -> runtime state is reloaded
  -> orphaned dispatch is requeued
  -> partial synthesis state preserves outputs
  -> supervisor-visible repair remains deterministic
```

## Primary Assertions

1. stalled dispatched work is requeued after reload
2. awaiting-synthesis work preserves partial outputs
3. checkpoint lineage survives the recovery edge
4. recovery does not depend on hidden worker state

## Trace

- [orchestration.rs](../../src/execution/orchestration.rs)
- [storage.rs](../../src/execution/storage.rs)
- [supervisor_stalled_worker_bounded_recovery.rs](./supervisor_stalled_worker_bounded_recovery.rs)
