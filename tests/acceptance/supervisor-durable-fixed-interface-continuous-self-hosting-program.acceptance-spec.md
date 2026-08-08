# Acceptance Spec: supervisor-durable-fixed-interface-continuous-self-hosting-program

Status: Implemented  
Applies to: `v1.4.6`

## Purpose

Prove the first durable fixed-interface continuous self-hosting program: repeated governed promotion remains budgeted, review-backed, reversible, and memory-continuous without changing the public contract.

## Scenario Summary

```text
continuous challenger completes governed shadow evaluation
  -> promotion activation is prepared with v1.4 program evidence
  -> successor-loop and second-cycle evidence are written
  -> v1 completion gate is satisfied under the same public interface
  -> completion bundle is persisted and reloaded
  -> continuous-program evidence remains reconstructable
```

## Primary Assertions

1. promotion and v1 completion remain valid with portfolio, review, background-memory, and steering evidence attached
2. second-cycle evidence remains promotable under the same fixed-interface contract
3. the reloaded completion bundle preserves the continuous governed self-hosting claim

## Trace

- [governance.rs](../../src/execution/governance.rs)
- [replacement.rs](../../src/execution/replacement.rs)
- [storage.rs](../../src/execution/storage.rs)
- [supervisor_durable_fixed_interface_continuous_self_hosting_program.rs](./supervisor_durable_fixed_interface_continuous_self_hosting_program.rs)
