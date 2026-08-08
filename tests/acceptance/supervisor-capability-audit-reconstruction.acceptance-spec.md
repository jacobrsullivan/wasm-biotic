# Acceptance Spec: supervisor-capability-audit-reconstruction

Status: Implemented  
Applies to: `v1.1.2` through `v1.1.6`

## Purpose

Prove that capability use, denial, approval, and quarantine-driven revocation remain reconstructable from durable audit artifacts without changing the public interface.

## Scenario Summary

```text
dispatch capability is requested
  -> approval bundle is persisted
  -> denied decision fails closed
  -> granted decision is recorded
  -> quarantine revokes the affected path
  -> capability and envelope audit refs remain reconstructable
```

## Primary Assertions

1. capability audit artifacts exist under deterministic `related_ref` keys
2. denied approval does not allow background resume
3. quarantine blocks the affected task until resolved
4. granted lineage can resume only after the quarantine is resolved
5. envelope-scoped capability evidence remains queryable for later review

## Trace

- [governance.rs](../../src/execution/governance.rs)
- [memory.rs](../../src/execution/memory.rs)
- [supervisor_capability_audit_reconstruction.rs](./supervisor_capability_audit_reconstruction.rs)
