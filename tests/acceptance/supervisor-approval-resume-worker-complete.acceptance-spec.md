# Acceptance Spec: supervisor-approval-resume-worker-complete

Status: Implemented  
Applies to: `RC-01.1` through `RC-01.6`  
Primary references:
- [RC-01-bootstrap-plan.md](../../project-archive/AIAF-v01-archive/RC-01-AIAF/RC-01-bootstrap-plan.md)
- [RC-01-contract-freeze.md](../../contracts/RC-01-contract-freeze.md)
- [RC-01.1-execution-kernel-task-breakdown.md](../../project-archive/AIAF-v01-archive/RC-01-AIAF/RC-01.1-execution-kernel-task-breakdown.md)

## 1. Purpose

This is the first bounded acceptance scenario carried into standalone `aiaf-v1`.

It is designed to survive across multiple roadmap iterations, so the same scenario can be used to validate progressively deeper implementation slices instead of creating disconnected one-off tests for each workstream.

## 2. Scenario Objective

Prove that the first AIAF slice can:

- initialize a bounded `supervisor` session
- open a governed `task artifact`
- block correctly on a human approval requirement
- resume from a `run checkpoint`
- dispatch a bounded `worker` path under an explicit `capability envelope`
- and complete the task with traceable checkpoint, event, and audit outputs

## 3. Canonical Scenario Summary

```text
user task arrives
  -> supervisor session initializes
  -> pointer index loads
  -> task artifact opens
  -> supervisor proposes an approval-sensitive action
  -> approval request is created
  -> session checkpoints and enters awaiting-approval
  -> approval decision is granted
  -> session resumes from checkpoint
  -> supervisor dispatches one bounded worker
  -> worker returns bounded result
  -> supervisor synthesizes the outcome
  -> task artifact completes
  -> checkpoint, event trail, and audit refs are present
```

## 4. Scenario Preconditions

The scenario assumes:

- one valid `campaign_id`
- one valid `epoch_id`
- one valid `supervisor` identity
- one valid `capability envelope` bound to the supervisor
- one initial `pointer index` artifact ref
- one `task artifact` created for the incoming request
- one action path that is classified as `human-required`
- one bounded `worker` capability route available once approval is granted

## 5. Primary Assertions

The scenario is considered successful only if all of the following are true:

1. the session starts in a legal initialized state and enters `ready`
2. the session executes at least one turn and opens a `task artifact`
3. an approval-sensitive proposal does not execute immediately
4. an `approval request` is created before forward execution continues
5. a `run checkpoint` exists before the session enters `awaiting-approval`
6. resume uses the checkpointed continuation path rather than raw transcript replay
7. at least one bounded `worker` path is dispatched only after approval is granted
8. a `supervisor` synthesis decision closes the task path
9. event and audit references are present for the major control transitions

## 6. Progressive Iteration Gates

This one scenario evolved with the roadmap and now serves as the implemented `RC-01.6` acceptance path.

### 6.1 RC-01.1 gate

`RC-01.1` passes this scenario when:

- session lifecycle is legal
- task lifecycle is legal
- approval-sensitive execution blocks correctly
- a checkpoint is captured before blocking
- resume from approval works
- execution events exist for session, task, approval, and checkpoint transitions

The worker path may still be represented as a bounded placeholder in this phase.

### 6.2 RC-01.2 gate

`RC-01.2` adds:

- explicit `capability envelope` binding
- dispatch decisions that distinguish `auto-allowed` from `human-required`
- evidence that the approval-sensitive action was gated by envelope and approval semantics

### 6.3 RC-01.3 gate

`RC-01.3` adds:

- initial `pointer index` load
- bounded transcript or memory reference use
- verified memory-write discipline for any durable update caused by the scenario

### 6.4 RC-01.4 gate

`RC-01.4` adds:

- actual `supervisor` to `worker` dispatch
- a structured worker result
- synthesis handoff back to the supervisor

### 6.5 RC-01.5 gate

`RC-01.5` adds:

- approval decision artifact handling
- audit record expectations
- quarantine or rollback behavior if an invalid post-approval path is detected

### 6.6 RC-01.6 gate

`RC-01.6` passes the full scenario only when the complete end-to-end path works:

- explicit capability mediation
- skeptical-memory continuity
- bounded worker coordination
- approval-blocked resume
- governed task completion
- checkpoint, event, and audit traceability

## 7. Expected Artifact Set

The scenario should eventually produce or reference:

- one `task artifact`
- one `execution session`
- one or more `turn record` entries
- one `approval request`
- one `approval decision`
- at least one `run checkpoint`
- execution events across the required event families
- one `pointer index` reference
- one bounded worker result artifact or equivalent structured result

## 8. Expected Event Families

The minimum expected event families for the mature scenario are:

- `SessionLifecycleEvent`
- `TurnLifecycleEvent`
- `TaskLifecycleEvent`
- `ActionProposalEvent`
- `ApprovalStateEvent`
- `CheckpointEvent`
- `WorkerDispatchEvent`
- `GovernanceDecisionEvent`

`MemoryInteractionEvent` becomes mandatory once the `RC-01.3` memory baseline lands.

## 9. Failure Conditions

The scenario fails if any of the following occur:

- the approval-sensitive action executes before approval is granted
- the session resumes without a valid checkpoint
- the task completes directly from worker output without supervisor synthesis
- event emission is missing for committed blocked/resume transitions
- the worker path bypasses the declared capability mediation rules
- the pointer index is treated as raw transcript storage instead of bounded durable pointers

## 10. Suggested Fixture Shape

The first implementation of this scenario should use small deterministic fixtures:

- fixed `campaign_id`, `epoch_id`, `session_id`, and `task_id`
- one approval-sensitive action request
- one granted approval decision
- one worker result with a bounded structured payload
- one pointer-index reference

Avoid dynamic clocks, random ids, or live host interactions in the first acceptance version.

## 11. Trace To Source Skeleton

The implemented code path for this scenario primarily exercises:

- [lib.rs](../../src/lib.rs)
- [execution/mod.rs](../../src/execution/mod.rs)
- [session.rs](../../src/execution/session.rs)
- [task.rs](../../src/execution/task.rs)
- [proposals.rs](../../src/execution/proposals.rs)
- [checkpoint.rs](../../src/execution/checkpoint.rs)
- [events.rs](../../src/execution/events.rs)
- [failure_budget.rs](../../src/execution/failure_budget.rs)
- [governance.rs](../../src/execution/governance.rs)
- [memory.rs](../../src/execution/memory.rs)
- [orchestration.rs](../../src/execution/orchestration.rs)
- [transition.rs](../../src/execution/transition.rs)
