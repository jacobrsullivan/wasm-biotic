# Acceptance Spec: supervisor-first-bounded-self-hosting-demonstration

Status: Implemented  
Applies to: `v1.2.6`

## Purpose

Prove the first stronger bounded self-hosting demonstration under the unchanged public interface.

## Scenario Summary

```text
native challenger is promoted
  -> bounded successor loop is compared
  -> successor genome and phenotype retain the same stable interface
  -> second cycle closes successfully
  -> v1 completion bundle persists under the same public contract
```

## Primary Assertions

1. promotion, adoption, reversal, and successor-loop control records remain explicit
2. successor genome and phenotype keep the stable `package:aiaf/supervisor@v1` interface
3. the second cycle reaches a promotable closure decision
4. the bounded self-hosting bundle persists with a satisfied completion gate

## Trace

- [replacement.rs](../../src/execution/replacement.rs)
- [governance.rs](../../src/execution/governance.rs)
- [storage.rs](../../src/execution/storage.rs)
- [supervisor_first_bounded_self_hosting_demonstration.rs](./supervisor_first_bounded_self_hosting_demonstration.rs)
