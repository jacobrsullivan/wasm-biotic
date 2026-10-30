# RC-01 Contract Freeze

Status: Proposed  
Applies to: `RC-01.0` and `RC-01.1`  
Primary references:
- `v01/Workstream-A-technical-design.md` (historical RC-01 design lineage)
- `v01/Workstream-B-technical-design.md` (historical RC-01 design lineage)
- `v01/Workstream-C-technical-design.md` (historical RC-01 design lineage)
- `v01/Workstream-E-technical-design.md` (historical RC-01 design lineage)

## 1. Purpose

This document freezes the minimum conceptual contracts that downstream `RC-01` implementation depends on.

It intentionally freezes only the surfaces needed to start building the execution kernel and the first bounded acceptance path. Everything broader remains open unless explicitly named here.

## 2. Freeze Policy

The contracts below are frozen for `RC-01.1` through `RC-01.3` unless a contradiction or major implementation blocker forces revision.

The point of this freeze is:

- to let code start
- to keep downstream work from reinterpreting core semantics
- and to prevent orchestration or governance from drifting ahead of the execution model

## 3. Frozen Contract Set

The first freeze set contains four contract families:

1. execution session and task lifecycle semantics
2. capability envelope, authority, and approval semantics
3. pointer index and memory write-discipline semantics
4. approval-blocked and resume semantics

## 4. Execution Session Contract

### 4.1 Frozen definition

An `execution session` is the canonical runtime container for one `supervisor` or one `worker`.

Every session must bind:

- `actor_kind`
- `actor_id`
- `campaign_id`
- `epoch_id`
- `capability_envelope_ref`
- `parent_session_id`, if present

### 4.2 Frozen session states

The session state names are frozen as:

- `initialized`
- `ready`
- `executing-turn`
- `awaiting-capability-result`
- `awaiting-worker-result`
- `awaiting-approval`
- `paused`
- `blocked`
- `completed`
- `failed`
- `terminated`

### 4.3 Frozen state rules

- a session may move from `initialized` to `ready` only after capability and context binding
- a session may move from `ready` only to `executing-turn`
- any `awaiting-*` state is resumable only through a committed `run checkpoint`
- `terminated` is reserved for operator stop, policy hard stop, or unrecoverable systemic failure

## 5. Task Lifecycle Contract

### 5.1 Frozen task states

The task lifecycle state names are frozen as:

- `created`
- `ready`
- `running`
- `blocked-on-capability`
- `blocked-on-worker`
- `blocked-on-approval`
- `paused`
- `completed`
- `failed`
- `canceled`

### 5.2 Frozen task rules

- only one active session may own a `running` task unless a read-only fan-out mode is explicitly added later
- blocked tasks must carry a structured blocked reason
- a worker result does not complete a task directly
- only a `supervisor` synthesis decision may complete the task path

## 6. Proposal Normalization Contract

The model does not emit executable authority. It emits proposal families that the harness normalizes and validates.

The frozen proposal families for the first slice are:

- `task-complete`
- `task-update`
- `capability-call-request`
- `worker-spawn-request`
- `memory-fetch-request`
- `memory-write-request`
- `approval-request`
- `synthesis-summary`
- `halt-or-escalate`

No proposal family outside this set should be implemented in `RC-01.1`.

## 7. Capability Contract

### 7.1 Capability envelope

A `capability envelope` is the explicit authority contract bound to a session or actor.

The envelope shape is frozen to include:

- allowed `capability worlds`
- allowed operations inside each world
- bound resource scope
- `authority class` ceiling
- `approval class` requirements
- `isolation profile`
- usage quotas or rate ceilings
- expiry or campaign/epoch scope

### 7.2 Authority classes

The first frozen `authority class` taxonomy is:

- `observe`
- `local-mutate`
- `campaign-control`
- `external-interact`
- `sensitive-access`
- `promotion-control`
- `automation-control`

### 7.3 Approval classes

The first frozen `approval class` taxonomy is:

- `auto-allowed`
- `supervisor-allowed`
- `human-required`
- `quarantine-on-expand`
- `forbidden`

### 7.4 Isolation profiles

The first frozen `isolation profile` taxonomy is:

- `read-only-inspect`
- `disposable-worktree`
- `artifact-sandbox`
- `isolated-service-namespace`
- `supervisor-exclusive`

### 7.5 Dispatch decision rule

Every dispatched action must be evaluated in this order:

```text
requested action
  -> world present?
  -> operation allowed?
  -> resource scope valid?
  -> isolation profile sufficient?
  -> authority class within envelope?
  -> approval class satisfied?
  -> execute / gate / quarantine / deny
```

## 8. Memory Contract

### 8.1 Pointer index

The `pointer index` is frozen as the always-available small durable memory surface injected into working context.

Its frozen limits are:

- target size approximately 200 lines or 25 KB maximum
- stores pointers and summaries, not raw transcript bodies
- includes active campaigns, current epoch refs, critical open task refs, high-value topic bundle refs, unresolved contradiction refs, and durable operator/governance constraints

### 8.2 Topic bundle role

`topic bundles` remain on-demand durable containers. They are not automatically injected into the live context.

### 8.3 Transcript retrieval

The canonical retrieval unit is a `transcript slice`, selected by campaign, epoch, session, task, artifact, time window, or search term.

### 8.4 Write discipline

The write discipline is frozen as:

- observations may be recorded as provisional `memory-update-proposal` artifacts
- durable memory updates require verification
- the `pointer index` may only reference verified or governance-approved durable facts
- success claims must be backed by capability results, checkpoints, or review artifacts

## 9. Approval-Blocked Semantics

### 9.1 Approval lifecycle

The frozen approval lifecycle is:

- `requested`
- `pending`
- `granted`
- `denied`
- `expired`
- `superseded`
- `consumed`

### 9.2 Approval-bound block rule

If a requested action has `approval class = human-required`, the harness must:

1. create an `approval request`
2. write a `run checkpoint`
3. transition the session to `awaiting-approval`
4. transition the task to `blocked-on-approval`
5. stop forward execution until an approval decision is present

### 9.3 Resume rule

Resume from `awaiting-approval` is legal only when:

- a valid approval decision exists for the named action and scope
- the capability envelope is still valid
- no unresolved quarantine blocks the path
- the latest checkpoint is intact

Resume must start from the checkpoint, not from inferred chat state.

## 10. Checkpoint Contract

The frozen `run checkpoint` payload must include:

- session header
- current session state
- active task refs
- outstanding proposals
- blocked reason, if any
- outstanding worker refs
- pending approval refs
- memory artifact refs loaded during the turn
- failure budget counters
- idempotency markers for already-dispatched actions

Checkpoints are mandatory:

- at the end of every committed turn
- before any blocked state
- before any human approval wait
- before pause or handoff

## 11. Event Family Contract

The frozen execution event family categories are:

- `SessionLifecycleEvent`
- `TurnLifecycleEvent`
- `TaskLifecycleEvent`
- `ActionProposalEvent`
- `CapabilityDispatchEvent`
- `WorkerDispatchEvent`
- `ApprovalStateEvent`
- `MemoryInteractionEvent`
- `GovernanceDecisionEvent`
- `CheckpointEvent`

Each event family must carry stable refs for:

- `campaign_id`
- `epoch_id`
- `session_id`
- `turn_id`, when applicable
- `task_id`, when applicable

## 12. Failure Budget Contract

The frozen retry classes are:

- `transient-model`
- `transient-capability`
- `transient-worker`
- `approval-timeout-retryable`
- `structural-non-retryable`
- `policy-non-retryable`

The frozen stop conditions are:

- explicit task completion
- operator halt
- governance hard-stop
- unrecoverable structural validation failure
- failure budget exhaustion
- no-progress ceiling reached

The default policy is:

- retryable classes use bounded exponential backoff
- structural and policy failures do not auto-retry
- budgets are tracked per `task artifact` and per `execution session`

## 13. What Is Not Frozen Yet

The following are intentionally not frozen in this document:

- final storage schema for checkpoints
- final Rust or WIT type syntax
- full worker registration surface
- broad background-campaign scheduling
- promotion and native replacement milestones

## 14. Use Of This Freeze

This document should be used as the minimum contract source for:

- `RC-01.1` execution-kernel implementation
- `RC-01.2` capability-envelope baseline
- `RC-01.3` skeptical-memory baseline

Any downstream work that needs semantics beyond this document should point back to the owning workstream design instead of silently inventing new rules.
