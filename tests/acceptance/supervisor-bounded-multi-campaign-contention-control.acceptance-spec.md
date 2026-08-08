# Acceptance Spec: supervisor-bounded-multi-campaign-contention-control

Status: Implemented  
Applies to: `v1.4.4` through `v1.4.6`

## Purpose

Prove that the fixed-interface `v1.4` line makes contention control explicit: conflicting mutable ownership is rejected, while bounded same-owner coordination remains durable and audit-backed.

## Scenario Summary

```text
shared mutable ownership is evaluated
  -> same-owner contention is allowed
  -> conflicting-owner contention is rejected
  -> bounded contention and fairness evidence is written
  -> runtime state is persisted and reloaded
  -> bounded coordination remains reconstructable
```

## Primary Assertions

1. the ownership validator rejects conflicting mutable access on the same scope
2. bounded same-owner coordination can persist without hidden arbitration
3. contention and fairness evidence remains durable across reload

## Trace

- [orchestration.rs](../../src/execution/orchestration.rs)
- [storage.rs](../../src/execution/storage.rs)
- [supervisor_bounded_multi_campaign_contention_control.rs](./supervisor_bounded_multi_campaign_contention_control.rs)
