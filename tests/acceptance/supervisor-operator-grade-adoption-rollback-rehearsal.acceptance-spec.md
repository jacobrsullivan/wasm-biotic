# Acceptance Spec: supervisor-operator-grade-adoption-rollback-rehearsal

Status: Implemented  
Applies to: `v1.4.5` through `v1.4.6`

## Purpose

Prove that the fixed-interface `v1.4` line treats operator steering, rollback rehearsal, and adoption safety as durable evidence rather than informal process.

## Scenario Summary

```text
completed runtime state is captured
  -> review and rollback support are attached
  -> steering, rollback rehearsal, and adoption safety evidence is written
  -> runtime state is persisted
  -> rollback is executed
  -> operator-grade adoption control remains reconstructable
```

## Primary Assertions

1. rollback execution restores the expected checkpoint
2. steering and adoption-safety bundles survive rollback
3. rollback rehearsal evidence remains durable and operator-visible

## Trace

- [governance.rs](../../src/execution/governance.rs)
- [storage.rs](../../src/execution/storage.rs)
- [supervisor_operator_grade_adoption_rollback_rehearsal.rs](./supervisor_operator_grade_adoption_rollback_rehearsal.rs)
