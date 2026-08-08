#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
MANIFEST="$ROOT/project-archive/mvp-03-EvoEngine/Cargo.toml"
TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/wasm-biotic-identity-v1-showcase}"

echo "exporting identity-resolution-v1 golden artifacts"
echo "  repo:   $ROOT"
echo "  target: $TARGET_DIR"

CARGO_TARGET_DIR="$TARGET_DIR" cargo test \
  --manifest-path "$MANIFEST" \
  -p primordial-evolution \
  --test identity_resolution_v1 \
  export_identity_resolution_v1_showcase_artifacts \
  -- --ignored --exact --nocapture

echo "artifacts written under:"
echo "  $ROOT/project-archive/mvp-03-EvoEngine/docs/walkthroughs/identity-resolution-v1-artifacts"
