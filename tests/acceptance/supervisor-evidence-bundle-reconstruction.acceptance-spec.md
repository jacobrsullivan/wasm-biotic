# Acceptance Spec: supervisor-evidence-bundle-reconstruction

Status: Implemented  
Applies to: `v1.1.3` through `v1.1.6`

## Purpose

Prove that checkpoint, approval, contradiction, transcript, quarantine, and rollback evidence survive governed memory updates and consolidation.

## Scenario Summary

```text
checkpoint and approval lineage are persisted
  -> contradiction and transcript evidence are attached
  -> governed memory update is accepted
  -> consolidation runs
  -> lineage-critical refs remain preserved
  -> evidence bundle can still be reconstructed after reload
```

## Primary Assertions

1. checkpoint lineage remains intact after consolidation
2. approval lineage remains queryable by request id
3. contradiction, transcript, and rollback refs survive evidence-preserving compaction
4. reloaded runtime state can still reconstruct the same evidence bundle

## Trace

- [memory.rs](../../src/execution/memory.rs)
- [storage.rs](../../src/execution/storage.rs)
- [supervisor_evidence_bundle_reconstruction.rs](./supervisor_evidence_bundle_reconstruction.rs)
