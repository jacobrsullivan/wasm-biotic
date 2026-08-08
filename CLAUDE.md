# CLAUDE.md

This file provides guidance to Claude Code (`claude.ai/code`) when working with code in this repository.

## Project Overview

The canonical live implementation target in this repository is the standalone root Rust package `aiaf-v1`.

It provides a bounded supervisory kernel plus a local operator/readout surface with:

- explicit capability envelopes and approval classes
- skeptical memory artifacts, pointer indexes, and transcript retrieval
- bounded worker orchestration and replayable checkpoints
- challenger evaluation, promotion governance, rollback, and bounded `v1 completion`
- a local runner, durable bundles, and a localhost-only observer console

Archived design material remains in the repository as historical and planning reference. The separate legacy Wasm-Biotic MVP and release-candidate `project-archive/` collection is held in external NAS custody and is not part of a normal clone. Neither is the primary live implementation surface.

## Repository Structure

- `Cargo.toml` — root manifest for the live `aiaf-v1` package
- `src/` — canonical implementation surface
- `tests/` — canonical regression and acceptance suite
- `contracts/` — fixed-interface contract anchors
- `artifacts/` — carried fixtures and sample artifacts
- `scenarios/` — curated runner scenario index
- `design-and-planning/` — roadmap and architectural design corpus
- `reference-docs/` — broader Wasm-Biotic reference material
- `project-archive/` — legacy MVP and RC material in external NAS custody; not tracked in this repository
- `notes/roadmap.md` — short-term focus and trajectory (Active Development entry)
- `scripts/` — showcase shell scripts (acceptance-flow demos, not part of `cargo test`)

## Key Files

- `src/lib.rs` — crate root for `aiaf_v1`
- `src/bin/aiaf-v1-runner.rs` — `aiaf-v1-runner` CLI (`list-scenarios`, `run`, `serve`)
- `src/local_runtime.rs` — local runner / HTTP operator surface (localhost-only)
- `src/execution/` — kernel modules (capability, governance, memory, orchestration, factory, component packaging, …)
- `tests/acceptance/` — 218 statically identified Rust test attributes; only eleven scenarios are exposed through the runner

## Core Concepts

The active implementation is a bounded AIAF kernel with:

- explicit session, task, checkpoint, and transition state
- governed approvals, denials, quarantine, and rollback
- replayable memory and evidence continuity
- bounded challenger evaluation and promotion flow
- second-cycle successor handling and `v1 completion` gating

The live root package is a Rust-local kernel and observer system. Wasmtime-backed component packaging and execution (`src/execution/component.rs`) are part of the live toolchain. Broader Wasm-Biotic substrate framing — full WIT world families, content-addressed lineage, federation — remains historical and northstar reference, not active surface.

## Technology References

- Rust stable (edition `2024`)
- `serde`
- `serde_json`
- `axum`
- `tokio`
- `tokio-stream`, `tower` (HTTP operator surface)
- `reqwest` (rustls; outbound calls from the runner)
- `wasmtime` 43, `wasmparser`, `wit-parser`, `wat` (live component packaging and execution in `src/execution/component.rs`)

## Repository Policy

- **All repos must be private.** Do not create public repositories for this project.

## Working With This Project

When extending the implementation or refining the specification:

- preserve the fixed-interface `v1` contract model
- do not casually change capability worlds, approval semantics, or governance-state meanings
- keep carried acceptance scenarios deterministic and fixture-backed
- prefer local docs under `src/`, `tests/`, `artifacts/`, `contracts/`, and `scenarios/` before reaching into archive material
- treat the externally custodied `project-archive/` collection as historical reference unless the task explicitly targets archive maintenance

When working in code:

- treat the repo root `Cargo.toml` as the main package manifest
- treat root `src/` as the canonical implementation surface
- treat root `tests/` as the canonical regression and acceptance suite
- use deterministic fixture-backed execution over live network or host-side effects

## Building and Testing

Use the root package and a clean target directory:

- `CARGO_TARGET_DIR=/tmp/aiaf-v1-target cargo test --manifest-path Cargo.toml`
- `CARGO_TARGET_DIR=/tmp/aiaf-v1-target cargo test --manifest-path Cargo.toml --test <acceptance_file_stem>` for a single acceptance file
- `CARGO_TARGET_DIR=/tmp/aiaf-v1-target cargo check --manifest-path Cargo.toml` for a fast type-check pass
- `env CARGO_TARGET_DIR=/tmp/aiaf-v1-target cargo run --bin aiaf-v1-runner -- list-scenarios`
- `env CARGO_TARGET_DIR=/tmp/aiaf-v1-target cargo run --bin aiaf-v1-runner -- serve`
- `env CARGO_TARGET_DIR=/tmp/aiaf-v1-target cargo run --bin aiaf-v1-runner -- run <scenario-id>`

Notes:

- Always set `CARGO_TARGET_DIR=/tmp/aiaf-v1-target` — the in-repo `target/` is shared with archive crates and grows quickly otherwise.
- `list-scenarios` returns only the eleven curated runner scenarios. The broader acceptance tree (`tests/acceptance/`) covers many more paths and is reachable via `cargo test`, not the runner.
- `serve` binds localhost-only; do not expose externally.
