# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## Project Overview

The canonical production target is the Wasm-Biotic component graph under
`components/`, its versioned interfaces under `wit/wasm-biotic/`, and the
policy-neutral substrate under `kernel/`. The release builder and strict
offline validator live under `tools/component-graph-package/`.

The root `aiaf-v1` package under `src/` and `tests/` is a transitional native
reference oracle. Its native operator runner is feature-gated; the library and
offline graph validator still compile for reference tests and release tooling.
None of that code is the production factory or an acceptable fallback when a
component fails.

The active implementation order and capability maturity are defined in
`notes/ROADMAP.md`. Archived roadmap documents preserve design lineage but are not
current status authorities.

## Core Concepts

The active production implementation is a content-addressed graph whose
factory control, reducer, routers, six workers, seven capability services,
exchange, evolution, migration and closure policy execute as Wasm components.
The standalone kernel supplies only the eight mechanisms listed below.

## Component-Complete Architecture

The canonical production target is a **component-complete factory** as defined
under `contracts/component-complete/` and `wit/wasm-biotic/`:

- Every supervisor, worker, capability service, router, workflow, migration,
  exchange protocol, evaluation, and policy implementation must execute as a
  versioned WebAssembly Component Model component selected by content digest.
- Native Rust control-plane and capability-service implementations are
  transitional reference oracles only. They must not be reachable from the
  conforming production factory launch path.
- The native substrate may only instantiate and meter components, persist
  opaque bytes and atomic references, communicate, hold keys, switch an exact
  graph digest, and enforce declared capability/resource bounds. It must not
  interpret factory-domain payloads or branch on factory roles, services,
  workflows, milestones, or policy.
- Production `command-execute` means invoking an admitted tool component by
  digest. Do not add a native shell or process-execution escape hatch.
- Do not claim component completeness until every mandatory gate in
  `contracts/component-complete/CONFORMANCE.md` passes for the exact production
  graph and native-substrate digests.

## Technology References

- Rust stable (edition 2024)
- `serde`
- `serde_json`

## Repository Policy

- **All repos must be private.** Do not create public repositories for this project.

## Working With This Project

When extending the implementation or refining the specification:
- Preserve the fixed-interface v1 contract model.
- Do not casually change capability worlds, approval semantics, or governance-state meanings.
- Keep the carried acceptance scenarios deterministic and fixture-backed.
- Treat the externally custodied `project-archive/` collection as historical reference unless the task explicitly targets archive maintenance.

When working in code:
- Treat `components/`, `wit/wasm-biotic/`, `kernel/`, and
  `tools/component-graph-package/` as the canonical production surfaces.
- Treat the root `Cargo.toml`, `src/`, and `tests/` as the transitional native
  oracle and its regression suite.
- Verify the standalone kernel with
  `CARGO_TARGET_DIR=/tmp/wasmbiotic-kernel-target cargo test --locked --offline --manifest-path kernel/Cargo.toml`.
- Use `CARGO_TARGET_DIR=/tmp/aiaf-v1-target cargo test --manifest-path Cargo.toml`
  only when deliberately verifying the transitional oracle.
- Prefer deterministic fixture-backed execution over live network or host-side effects.
- Use local docs under `src/`, `tests/`, `artifacts/`, `contracts/`, and `scenarios/` before reaching into the archive.
