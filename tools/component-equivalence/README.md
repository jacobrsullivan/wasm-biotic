# Component/native differential harness

This is conformance tooling, not a production factory dependency. It links the
feature-disabled `aiaf-v1` library solely as the transitional behavioural
oracle and executes the component-owned pure policies from the same frozen
abstract event corpus.

The reducer/worker portion is deliberately a **synthetic policy trace**. It
feeds arbitrary frozen corpus bytes into the policy and returns deterministic
fake blob references from its service delegate. It verifies the exact six-role,
twelve-call routing/order/authority shape, but it does not execute capability
service implementations, produce useful software, or claim useful R1
semantics. Useful R1 execution is proven by the component-package lifecycle and
its dedicated strict semantic verifier, not by this differential oracle.

The report distinguishes:

- identical externally observable results;
- intentional, enumerated differences authorized by a versioned contract
  decision; and
- missing comparisons, which remain blockers.

It never makes native behaviour reachable from the standalone kernel or the
component graph.

Run it offline:

```sh
CARGO_TARGET_DIR=/tmp/wasm-biotic-equivalence-target \
  cargo run --locked --offline \
  --manifest-path tools/component-equivalence/Cargo.toml -- \
  --corpus tools/component-equivalence/fixtures/bounded-cycle.v1.json \
  --lifecycle-report /path/to/component-package/evidence/component-lifecycle.json \
  --out /tmp/wasm-biotic-behavioural-equivalence.v2.json
```

The process exits unsuccessfully if the corpus, expected operation vocabulary,
declared decision binding, approval artifact, compiled approval component, or
focused adversarial outcome changes unexpectedly. The frozen corpus now also:

- requires the exact expanded policy trace: planner
  `workspace-open → workspace-snapshot → workspace-patch → schedule-job`, then
  builder `candidate-build`, validator
  `factory-provider-proposal → validation-prove`, reviewer `review-candidate`,
  packager `package-publish → package-verify`, and continuity
  `evidence-publish → evidence-resolve`;
- binds five signed approval authenticity/replay cases executed by the compiled
  capability-router adapter and compares durable replay/conflict behavior with
  the native oracle;
- executes exchange first-use, exact-replay and conflicting-replay decisions in
  the component-owned policy and transitional durable transaction oracle;
- submits eight malformed or extended documents to seven owning component
  policies;
- executes initialization, successor activation, regression observation,
  rollback and restart against the component lifecycle artifact and the
  transitional native deployment oracle;
- invokes the exact content-addressed closure-evaluator Wasm component from the
  supplied package for complete and incomplete dossiers, compares its bytes
  with the component-owned policy function, and compares the common closure
  class with the native closure-inventory oracle; and
- consumes all twelve labelled synthetic policy-call receipts, all three
  activation/rollback receipts, and all eighteen six-role lifecycle mechanism
  receipts; removes only declared clock fields; and verifies digest, graph and
  executor bindings.

The approval source defaults to
`artifacts/component-complete/2026-08-02-adversarial-isolation.v1.json` and can
be selected explicitly with `--adversarial-report PATH`.

`--lifecycle-report` is required because lifecycle evidence is emitted by an
exact component package run. The report binds its package-relative logical
path and SHA-256 digest; it deliberately does not retain the caller's staging
directory. It validates lifecycle transition and mechanism-receipt evidence,
but deliberately leaves useful R1 work-state verification to the package's
strict verifier. It sets `report_complete=true` only after every bounded v1
category has executed;
the resulting intentional state-model, authority, lifecycle and receipt-count
differences are each bound to
`CD-0001-component-factory-contract-v1`. A missing, malformed, incomplete or
misbound lifecycle artifact makes the harness exit unsuccessfully.
