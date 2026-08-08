#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
MANIFEST="$ROOT/project-archive/mvp-03-EvoEngine/Cargo.toml"
TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/wasm-biotic-event-v1-showcase}"

echo "exporting event-digestion-v1 golden artifacts"
echo "  repo:   $ROOT"
echo "  target: $TARGET_DIR"

CARGO_TARGET_DIR="$TARGET_DIR" cargo test \
  --manifest-path "$MANIFEST" \
  -p primordial-evolution \
  --test event_digestion_v1 \
  export_event_digestion_v1_showcase_artifacts \
  -- --ignored --exact --nocapture

echo "artifacts written under:"
echo "  $ROOT/project-archive/mvp-03-EvoEngine/docs/walkthroughs/event-digestion-v1-artifacts"
