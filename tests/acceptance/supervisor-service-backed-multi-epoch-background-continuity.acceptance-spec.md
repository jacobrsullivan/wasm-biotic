# Acceptance Spec: supervisor-service-backed-multi-epoch-background-continuity

Status: Implemented  
Applies to: `v1.3.4` through `v1.3.6`

## Purpose

Prove that service-backed background operation remains governed and replayable across an epoch handoff and a follow-up background tick.

## Scenario Summary

```text
challenger is evaluated and marked promotable
  -> epoch handoff activates the successor session
  -> epoch-transition resume is validated
  -> a follow-up background checkpoint is captured in the new epoch
  -> scheduled-timer resume is validated again
  -> checkpoint lineage remains reconstructable after reload
```

## Primary Assertions

1. epoch-transition and scheduled-timer resume both remain valid under the same governed background campaign
2. epoch-handoff and follow-up checkpoints both remain audit-backed
3. the reloaded successor runtime stays in the new epoch with replayable checkpoint lineage

## Trace

- [governance.rs](../../src/execution/governance.rs)
- [transition.rs](../../src/execution/transition.rs)
- [storage.rs](../../src/execution/storage.rs)
- [supervisor_service_backed_multi_epoch_background_continuity.rs](./supervisor_service_backed_multi_epoch_background_continuity.rs)
