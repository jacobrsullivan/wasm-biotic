# Acceptance Spec: supervisor-native-factory-service-challenger-evaluation

Status: Implemented  
Applies to: `v1.3.5` through `v1.3.6`

## Purpose

Prove that a factory-service challenger can be evaluated through the governed shadow pipeline while carrying explicit native-service inventory evidence under the unchanged `v1` public contract.

## Scenario Summary

```text
incumbent and challenger factory-service sessions complete
  -> challenger carries explicit service inventory audits
  -> shadow comparison and sufficiency evidence are written
  -> promotion-readiness review stays bounded
  -> shadow bundle is persisted and reloaded
  -> factory-service challenger remains promotable
```

## Primary Assertions

1. the challenger keeps explicit service inventory coverage during shadow evaluation
2. the promotion-readiness decision remains promotable under the same fixed interface
3. the persisted shadow bundle reloads without losing factory-service evidence

## Trace

- [replacement.rs](../../src/execution/replacement.rs)
- [storage.rs](../../src/execution/storage.rs)
- [supervisor_native_factory_service_challenger_evaluation.rs](./supervisor_native_factory_service_challenger_evaluation.rs)
