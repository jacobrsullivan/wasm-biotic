# Acceptance Spec: supervisor-carried-import-inventory-native-sufficiency

Status: Implemented  
Applies to: `v1.2.1` through `v1.2.6`

## Purpose

Prove that the fixed-interface `v1.2` line has an explicit full capability inventory and can still satisfy native-sufficiency gates while governed carried imports remain explicit.

## Scenario Summary

```text
full closure inventory is constructed
  -> explicit carried imports remain visible
  -> native challenger comparison is evaluated
  -> sufficiency evidence is checked against the gate
  -> inventory closure and sufficiency both pass
```

## Primary Assertions

1. the closure inventory covers every capability target exactly once
2. carried imports remain explicit rather than ambient
3. native-sufficiency evaluation succeeds under the unchanged interface

## Trace

- [replacement.rs](../../src/execution/replacement.rs)
- [supervisor_carried_import_inventory_native_sufficiency.rs](./supervisor_carried_import_inventory_native_sufficiency.rs)
