# Acceptance Spec: supervisor-native-service-inventory-closure

Status: Implemented  
Applies to: `v1.3.1` through `v1.3.6`

## Purpose

Prove that the fixed-interface `v1.3` service inventory is explicit, audit-backed, and durable enough to distinguish native services from explicit carried services.

## Scenario Summary

```text
completed runtime state is captured
  -> full service inventory is attached
  -> every inventory entry gets explicit audit coverage
  -> carried services remain explicit rather than hidden
  -> runtime state is persisted and reloaded
  -> service inventory closure remains reconstructable
```

## Primary Assertions

1. the full service inventory is complete and has no hidden imports
2. carried services remain explicitly identified
3. every inventory audit ref reloads as a persisted audit-backed service record

## Trace

- [replacement.rs](../../src/execution/replacement.rs)
- [storage.rs](../../src/execution/storage.rs)
- [supervisor_native_service_inventory_closure.rs](./supervisor_native_service_inventory_closure.rs)
