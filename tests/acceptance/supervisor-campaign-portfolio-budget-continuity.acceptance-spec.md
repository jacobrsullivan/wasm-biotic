# Acceptance Spec: supervisor-campaign-portfolio-budget-continuity

Status: Implemented  
Applies to: `v1.4.1` through `v1.4.6`

## Purpose

Prove that the fixed-interface `v1.4` line makes campaign portfolio, budget, and intervention evidence explicit and durable across persistence.

## Scenario Summary

```text
completed runtime state is captured
  -> operator review support is attached
  -> portfolio, budget, and intervention evidence is written
  -> runtime state is persisted and reloaded
  -> campaign program law remains reconstructable
```

## Primary Assertions

1. portfolio, budget, and intervention evidence persists with deterministic refs
2. review-backed program continuity survives reload
3. campaign budget evidence remains reconstructable without interface changes

## Trace

- [storage.rs](../../src/execution/storage.rs)
- [memory.rs](../../src/execution/memory.rs)
- [supervisor_campaign_portfolio_budget_continuity.rs](./supervisor_campaign_portfolio_budget_continuity.rs)
