#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
MANIFEST="$ROOT/project-archive/mvp-03-EvoEngine/Cargo.toml"
TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/wasm-biotic-contact-v2-showcase}"

echo "exporting schema-digestion-contact-v2 golden artifacts"
echo "  repo:   $ROOT"
echo "  target: $TARGET_DIR"

CARGO_TARGET_DIR="$TARGET_DIR" cargo test \
  --manifest-path "$MANIFEST" \
  -p primordial-evolution \
  --test schema_digestion_contact_v2 \
  export_schema_digestion_contact_v2_showcase_artifacts \
  -- --ignored --exact --nocapture

echo "artifacts written under:"
echo "  $ROOT/project-archive/mvp-03-EvoEngine/docs/walkthroughs/schema-digestion-contact-v2-artifacts"
