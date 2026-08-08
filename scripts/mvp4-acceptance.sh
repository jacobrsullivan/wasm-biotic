#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
MANIFEST="$ROOT/project-archive/mvp-03-EvoEngine/Cargo.toml"

cargo test --manifest-path "$MANIFEST" \
  -p primordial-runtime --test fixtures \
  -p primordial-evolution --test promotion --test assembly --test capability_review \
  --test mitochondria --test assimilation --test derivatives --test mvp4_acceptance

cargo test --manifest-path "$MANIFEST" \
  -p primordial-store --test boundary_schema --test mitochondria_schema \
  --test assimilation_schema --test derivative_schema

cargo test --manifest-path "$MANIFEST" -p primordial-cli --no-run
