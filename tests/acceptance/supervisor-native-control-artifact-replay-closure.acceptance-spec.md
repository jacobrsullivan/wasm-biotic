# Acceptance Spec: supervisor-native-control-artifact-replay-closure

Status: Implemented  
Applies to: `v1.2.2` through `v1.2.6`

## Purpose

Prove that native control records for challenger comparison, sufficiency evidence, and checkpoint lineage remain durable and replay-safe through shadow bundle persistence.

## Scenario Summary

```text
bounded shadow evaluation completes
  -> comparison record is written
  -> sufficiency evidence is written
  -> challenger checkpoint lineage is preserved
  -> shadow bundle is persisted and reloaded
  -> control records remain reconstructable
```

## Primary Assertions

1. comparison and sufficiency control records exist as audit-backed artifacts
2. challenger checkpoint lineage contains both checkpoint and audit artifacts
3. the persisted shadow bundle reloads without losing control-record closure

## Trace

- [replacement.rs](../../src/execution/replacement.rs)
- [storage.rs](../../src/execution/storage.rs)
- [supervisor_native_control_artifact_replay_closure.rs](./supervisor_native_control_artifact_replay_closure.rs)
