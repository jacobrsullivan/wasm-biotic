# Acceptance Spec: supervisor-failed-worker-bounded-recovery

Status: Implemented  
Applies to: `v1.1.4` through `v1.1.6`

## Purpose

Prove that transient, policy, and structural worker failures stay inside an explicit bounded-recovery model.

## Scenario Summary

```text
transient worker failure occurs
  -> retry budget is consumed deterministically
  -> repeated failure exhausts the budget
  -> policy and structural failures hard-stop immediately
  -> failure checkpoint remains reconstructable after reload
```

## Primary Assertions

1. transient worker failure remains retryable only while budget allows
2. repeated transient failure reaches `FailureBudgetExhausted`
3. policy failures stop through `GovernanceHardStop`
4. structural failures stop through `StructuralValidationFailure`
5. failed agenda state remains explicit and durable

## Trace

- [failure_budget.rs](../../src/execution/failure_budget.rs)
- [orchestration.rs](../../src/execution/orchestration.rs)
- [supervisor_failed_worker_bounded_recovery.rs](./supervisor_failed_worker_bounded_recovery.rs)
