#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
MANIFEST="$ROOT/project-archive/mvp-03-EvoEngine/Cargo.toml"
TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/wasm-biotic-knowledge-retrieval-v1-showcase}"

echo "exporting knowledge-retrieval-v1 golden artifacts"
echo "  repo:   $ROOT"
echo "  target: $TARGET_DIR"

CARGO_TARGET_DIR="$TARGET_DIR" cargo test \
  --manifest-path "$MANIFEST" \
  -p primordial-evolution \
  --test knowledge_retrieval_v1 \
  export_knowledge_retrieval_v1_showcase_artifacts \
  -- --ignored --exact --nocapture

echo "artifacts written under:"
echo "  $ROOT/project-archive/mvp-03-EvoEngine/docs/walkthroughs/knowledge-retrieval-v1-artifacts"
