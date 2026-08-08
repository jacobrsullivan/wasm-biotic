# Acceptance Spec: supervisor-native-capability-organelle-approval-transport

Status: Implemented  
Applies to: `v1.3.3` through `v1.3.6`

## Purpose

Prove that governed capability use passes through explicit approval transport and leaves deterministic capability audit records that can be reconstructed after persistence.

## Scenario Summary

```text
worker dispatch requests a human-required capability
  -> dispatch checkpoints into approval wait
  -> approval request bundle is persisted
  -> granted decision moves through native approval transport
  -> capability and approval audits are written
  -> runtime state is reloaded with full lineage intact
```

## Primary Assertions

1. approval transport writes deterministic audit refs
2. capability dispatch writes deterministic capability audit refs
3. approval lineage survives persistence and reload

## Trace

- [governance.rs](../../src/execution/governance.rs)
- [transition.rs](../../src/execution/transition.rs)
- [supervisor_native_capability_organelle_approval_transport.rs](./supervisor_native_capability_organelle_approval_transport.rs)
