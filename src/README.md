# Source

This folder contains the transitional native `aiaf-v1` reference oracle and
its local operator/runtime surface. The canonical production factory lives in
[`../components`](../components), uses the versioned interfaces in
[`../wit/wasm-biotic`](../wit/wasm-biotic), and runs through the standalone
policy-neutral [`../kernel`](../kernel). Native code in this folder is not a
production fallback for any Wasm factory role or service.

The public `aiaf_v1::execution` interface carries the fixed-interface contract
from the archived `RC-05-AIAF` line. Later `v1.x`, `v2.x`, `v3.x`, Phase, and
NorthStar labels identify accumulated modules, record families, tests, and
historical review lines. They are not operational maturity claims.

Current status is governed by:

- [ROADMAP.md](../notes/ROADMAP.md) — implementation order and milestone gates
- [component-complete implementation status](../contracts/component-complete/IMPLEMENTATION-STATUS.md)
  — exact production-component evidence and open conformance gates
- [capability-baseline.json](../notes/capability-baseline.json) — the
  machine-readable transitional-oracle baseline cross-checked against native
  operator and scenario views

## Entry Points

- [lib.rs](lib.rs)
- [execution/mod.rs](execution/mod.rs)
- [local_runtime.rs](local_runtime.rs)
- [bin/aiaf-v1-runner.rs](bin/aiaf-v1-runner.rs)

## Honest Implementation Boundary

The source currently contains real local effects for:

- durable JSON-backed runtime and evidence state;
- CLI, localhost HTTP, console, and SSE operator surfaces;
- approval, checkpoint, quarantine, and runtime-state restoration transitions;
- configured inference HTTP transport;
- WIT/WAT parsing, component compilation, Wasmtime instantiation, and narrow
  component execution;
- typed tool authorization and schema checks;
- a contained M1 workspace, replacement, build, package, proving, comparison,
  approval-bound activation, observation, and byte-restoring rollback path;
- a single-writer M2 executor that durably schedules that closed path,
  wakes future work, resolves delayed approvals, reconciles restart and
  duplicate delivery, and exposes real job status;
- nine least-authority M3 registrations that execute real Build, Validation,
  Review, Packaging, Continuity, Scheduling, and Operations effects for the
  bounded reference workflow, with durable receipts, attestations, explicit
  unavailability, and immutable aggregate evidence;
- an authorized Wasmtime import bridge that invokes an actual M3 effect owner
  and rejects mismatched or forged evidence;
- six fixed M4 roles with admitted Wasm packages, durable dispatch, leases,
  exact M3 effects, content-addressed results, synthesis, recovery,
  cancellation, single-writer ownership, and bounded fleet fairness; and
- one bounded deterministic M5 runtime whose exact successor serves work,
  materially drives a second generation, and survives rejection, executable
  migration, post-adoption regression rollback, and restart through the same
  receipted M1–M4 boundaries;
- one bounded directional M6 runtime whose separately rooted sender and
  receiver exchange exact signed M5 artifacts through a neutral local spool,
  with raw quarantine, receiver proving and approval, ACK correlation, replay
  rejection, revocation, adoption or rollback, restart reconstruction, and
  sender isolation; and
- an M7 source-derivation, content-addressed dossier, detached-attestation,
  restart, and fail-closed evaluation mechanism. Repository fixtures verify
  that mechanism; they are not external custody or independent review.

The source also contains broad modeled and rehearsed surfaces for:

- worker roles, cards, dispatch, leases, synthesis, and ecology health beyond
  the fixed M4 role vocabulary and local choreography;
- legacy scheduler records, approval inboxes, and recurring factory programs
  beyond the bounded M2 reference executor;
- legacy service manifests and attestations outside the bounded M3 reference
  registrations;
- candidate workspaces, patchsets, packages, proving, observations, and
  comparisons;
- factory genomes, candidates, activation references, rollback references,
  reproduction, lineage, and closure review beyond the bounded M5 runtime; and
- exchange, compatibility, route, federation, and ecosystem-health behavior
  beyond the single bounded directional M6 route.

Those represented families do not uniformly perform the advertised effects.
The bounded M1–M6 paths perform real local effects within their fixed scopes. A
historical M5–M7 snapshot passed combined detached-clean whole-tree validation
with 900 tests and no failures; that run does not validate the current
post-baseline hardening. The immutable local-only R8 record at
`artifacts/baseline/2026-07-31/m5-m7-hardened-detached-clean-evidence.json`
binds synthetic commit `3204a1a60c289be98b2b77ac78c6451fbccc2159`, tree
`28de5fa7fece9d2ecf18ae242da84bedbec32ce0`, and 967 passed with 0 failed.
It retains `NotYet`, supplies no external or release authority, and validates
only that exact historical tree; it predates the current accounting,
catalog-integrity, migration, transport, and enclosing wire-schema repairs.
The current hardened candidate has local validation
only when the reserved
`artifacts/baseline/2026-08-01/m5-m7-accounting-hardened-detached-clean-evidence.json`
exists and validates; absence or invalidity means pending. M5 still requires a
current live-provider qualification. M6's historical public two-root, detached
bundle-tamper, and detached-clean gates are green, but current-candidate local
validation remains conditional and M6 remains Active behind M5. M7 still
requires one precommitted same-run external source-custodian, live-provider,
and independent-review proof. The broad legacy v1 rehearsal handlers retain
their documented limits.

## Module Guide

Effectful foundations:

- [artifact.rs](execution/artifact.rs)
- [capability.rs](execution/capability.rs)
- [checkpoint.rs](execution/checkpoint.rs)
- [component.rs](execution/component.rs)
- [governance.rs](execution/governance.rs)
- [inference.rs](execution/inference.rs)
- [memory.rs](execution/memory.rs)
- [session.rs](execution/session.rs)
- [storage.rs](execution/storage.rs)
- [tool_membrane.rs](execution/tool_membrane.rs)
- [validation.rs](execution/validation.rs)
- [candidate.rs](candidate.rs)
- [deployment.rs](deployment.rs)
- [m1_reference.rs](m1_reference.rs)
- [m1_tool_catalog.rs](m1_tool_catalog.rs)
- [m1_validation.rs](m1_validation.rs)
- [supervisor.rs](supervisor.rs)
- [m2_runtime.rs](m2_runtime.rs)
- [capability_services.rs](capability_services.rs)
- [m3_runtime.rs](m3_runtime.rs)
- [m3_component_bridge.rs](m3_component_bridge.rs)
- [m4_runtime.rs](m4_runtime.rs)
- [worker_runtime.rs](worker_runtime.rs)
- [m5_runtime.rs](m5_runtime.rs)
- [m5_export.rs](m5_export.rs)
- [m6_sender_runtime.rs](m6_sender_runtime.rs)
- [m6_receiver_runtime.rs](m6_receiver_runtime.rs)
- [m6_completion.rs](m6_completion.rs)
- [m7_closure.rs](m7_closure.rs)
- [m7_runtime.rs](m7_runtime.rs)

Primarily modeled or rehearsed higher-level families:

- [ecosystem.rs](execution/ecosystem.rs)
- [factory.rs](execution/factory.rs)
- [factory_exchange.rs](execution/factory_exchange.rs)
- [factory_program.rs](execution/factory_program.rs)
- [factory_replication.rs](execution/factory_replication.rs)
- [factory_runtime.rs](execution/factory_runtime.rs)
- [native_services.rs](execution/native_services.rs)
- [operations.rs](execution/operations.rs)
- [orchestration.rs](execution/orchestration.rs)
- [self_production.rs](execution/self_production.rs)
- [worker.rs](execution/worker.rs)
- [worker_ecology.rs](execution/worker_ecology.rs)

Some modules contain a mixture of effectful primitives and rehearsed
higher-level conclusions. Maturity attaches to the named capability and
evidence, not to an entire file.

## Rollback Vocabulary

The active baseline distinguishes:

- **state-reference rollback** — change a stored active pointer or reference;
- **runtime-state rollback** — restore actual local runtime state or executable
  behavior;
- **external compensation** — perform and verify a compensating action for an
  already-committed external effect.

Existing generic rollback records must not be interpreted as runtime failback
or external compensation without evidence of that exact effect.

## Local Runtime

`local_runtime.rs` supplies:

- the curated scenario catalog and explicit scenario maturity;
- `.aiaf-local/` workspace and durable run storage;
- run-bundle exports;
- localhost HTTP and SSE;
- operator, rehearsal, review, and historical closure views;
- inference, tool-membrane, and recursive-factory integration surfaces;
- the bounded M2 supervisor lifecycle and `/api/m2/` status, job,
  cancellation, and approval-resolution surfaces;
- the bounded M3 capability-service lifecycle and `/api/m3/` inventory,
  health, invocation, attestation, schedule, operations, and evidence surfaces;
- the bounded M4 worker lifecycle and `/api/m4/` worker, job, execution,
  result, reconciliation, cancellation, and event surfaces; and
- active operator-truth projections that report `NotYet`, bind the exact root
  README and roadmap bytes, and label Phase 04 closure as historical
  record-completeness lineage rather than current operational proof.

Historical endpoints remain available for lineage compatibility. The current
system overview separately reports the operational North Star decision as
`NotYet` and points to `notes/ROADMAP.md`.
