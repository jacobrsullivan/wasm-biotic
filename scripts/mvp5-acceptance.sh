#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
MANIFEST="$ROOT/project-archive/mvp-03-EvoEngine/Cargo.toml"

cargo test --manifest-path "$MANIFEST" \
  -p primordial-evolution campaign::tests

cargo test --manifest-path "$MANIFEST" \
  -p primordial-evolution --test mvp5_acceptance

cargo test --manifest-path "$MANIFEST" \
  -p primordial-evolution --test schema_digestion_contact_v2

cargo test --manifest-path "$MANIFEST" \
  -p primordial-evolution --test event_digestion_v1

cargo test --manifest-path "$MANIFEST" \
  -p primordial-evolution --test identity_resolution_v1

cargo test --manifest-path "$MANIFEST" \
  -p primordial-evolution --test policy_routing_v1

cargo test --manifest-path "$MANIFEST" \
  -p primordial-evolution --test case_assembly_v1

cargo test --manifest-path "$MANIFEST" \
  -p primordial-evolution --test document_digestion_v1

cargo test --manifest-path "$MANIFEST" \
  -p primordial-evolution --test knowledge_retrieval_v1

cargo test --manifest-path "$MANIFEST" \
  -p primordial-evolution --test response_orchestration_v1

cargo test --manifest-path "$MANIFEST" -p primordial-cli --no-run
