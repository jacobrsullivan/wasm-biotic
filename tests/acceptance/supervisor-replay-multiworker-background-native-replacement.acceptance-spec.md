# Supervisor Replay Multiworker Background Native Replacement

## Purpose

This is the carried `RC-02` integrated acceptance scenario inside standalone `aiaf-v1`.

It proves that the bounded AIAF supervisor can run a replayable governed campaign that is stronger than the `RC-01` slice without breaking the `RC-01` regression path.

## Scenario

1. Seed skeptical memory with a pointer index, legacy bundle, and transcript slices.
2. Dispatch an observe worker and persist a checkpoint snapshot.
3. Accept the observe result, synthesize it, persist runtime state, and reload it from durable storage.
4. Validate a scheduled-timer background resume against the replayed state.
5. Dispatch an evaluate worker, persist a second checkpoint, accept the result, resolve a contradiction, and unlock a merge task.
6. Dispatch a merge worker, persist a third checkpoint, accept the result, and synthesize the campaign summary.
7. Verify memory update acceptance and run a consolidation job.
8. Compare imported durable transcript retrieval with native in-memory transcript retrieval.
9. Assert that a rollback handle restores the earlier immutable checkpoint snapshot instead of the later mutated runtime state.

## Success Conditions

Standalone `aiaf-v1` passes this scenario only when all of the following are true:

- runtime replay survives process-style reload from durable artifacts
- checkpoint snapshots remain immutable after later runtime updates
- multiple workers are coordinated through the task graph without losing agenda state
- bounded background continuation is policy-validated
- skeptical memory handles contradiction resolution and consolidation
- native transcript retrieval matches imported durable retrieval under a sufficiency gate
- rollback restores the earlier checkpoint view of the campaign

## Implementation Reference

- [supervisor_replay_multiworker_background_native_replacement.rs](supervisor_replay_multiworker_background_native_replacement.rs)
