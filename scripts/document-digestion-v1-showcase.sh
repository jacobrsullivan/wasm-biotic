#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
MANIFEST="$ROOT/project-archive/mvp-03-EvoEngine/Cargo.toml"
TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/wasm-biotic-document-digestion-v1-showcase}"

echo "exporting document-digestion-v1 golden artifacts"
echo "  repo:   $ROOT"
echo "  target: $TARGET_DIR"

CARGO_TARGET_DIR="$TARGET_DIR" cargo test \
  --manifest-path "$MANIFEST" \
  -p primordial-evolution \
  --test document_digestion_v1 \
  export_document_digestion_v1_showcase_artifacts \
  -- --ignored --exact --nocapture

echo "artifacts written under:"
echo "  $ROOT/project-archive/mvp-03-EvoEngine/docs/walkthroughs/document-digestion-v1-artifacts"
