# Acceptance Spec: supervisor-durable-fixed-interface-self-hosting-loop

Status: Implemented  
Applies to: `v1.3.6`

## Purpose

Prove the first durable fixed-interface self-hosting loop: promotion, successor-loop evidence, and second-cycle completion all remain service-backed and replayable without changing the public contract.

## Scenario Summary

```text
durable challenger completes bounded shadow evaluation
  -> promotion activation is prepared with service-backed evidence
  -> successor loop comparison and evidence are written
  -> second-cycle comparison, review, and evidence are written
  -> v1 completion gate is satisfied
  -> durable self-hosting completion bundle is persisted and reloaded
```

## Primary Assertions

1. promotion activation remains valid with service-backed control, review, and inventory evidence
2. second-cycle evidence remains promotable under the same public interface
3. the reloaded completion bundle preserves the fixed-interface self-hosting claim

## Trace

- [governance.rs](../../src/execution/governance.rs)
- [replacement.rs](../../src/execution/replacement.rs)
- [storage.rs](../../src/execution/storage.rs)
- [supervisor_durable_fixed_interface_self_hosting_loop.rs](./supervisor_durable_fixed_interface_self_hosting_loop.rs)
