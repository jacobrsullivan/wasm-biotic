#!/usr/bin/env bash
set -euo pipefail

repository="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
scope="${1:-all}"
temporary_root="${TMPDIR:-/tmp}"
target_root="${CARGO_TARGET_DIR:-${temporary_root%/}/wasm-biotic-verify-target/$scope}"
export CARGO_TARGET_DIR="$target_root"
cd "$repository"

run_preflight() {
  python3 "$repository/scripts/verify-preflight.py"
  python3 "$repository/scripts/verify-source-baseline.py"
}

run_record() {
  python3 "$repository/scripts/verify-r4-record.py"
}

run_python() {
  require_openssl3
  python3 -m unittest discover -s "$repository/tools" -p 'test_*.py'
  python3 -m unittest "$repository/kernel/tools/test_native_tcb_inventory.py"
  build_kernel_fixtures
  python3 "$repository/kernel/tools/native_tcb_inventory.py" --check
}

require_openssl3() {
  local openssl_bin openssl_version
  openssl_bin="${WASM_BIOTIC_OPENSSL:-}"
  if [[ -z "$openssl_bin" ]]; then
    openssl_bin="$(command -v openssl || true)"
  fi
  if [[ -z "$openssl_bin" || "$openssl_bin" != /* || ! -x "$openssl_bin" ]]; then
    echo "OpenSSL 3 is required; set WASM_BIOTIC_OPENSSL to its absolute executable path" >&2
    return 1
  fi
  openssl_version="$("$openssl_bin" version 2>&1 || true)"
  if [[ "$openssl_version" != OpenSSL\ 3.* ]]; then
    echo "OpenSSL 3 is required; found ${openssl_version:-an unusable executable} at $openssl_bin" >&2
    echo "set WASM_BIOTIC_OPENSSL to an absolute OpenSSL 3 executable path" >&2
    return 1
  fi
  export WASM_BIOTIC_OPENSSL="$openssl_bin"
  export PATH="${openssl_bin%/*}:$PATH"
}

build_kernel_fixtures() {
  fixture_target="$target_root/kernel-fixtures"
  fixture_output="$fixture_target/wasm32-wasip2/release"
  for manifest in \
    "$repository/kernel/fixtures/adversarial-task-component/Cargo.toml" \
    "$repository/kernel/fixtures/mechanism-task-component/Cargo.toml" \
    "$repository/kernel/fixtures/root-component/Cargo.toml" \
    "$repository/kernel/fixtures/task-component/Cargo.toml"
  do
    CARGO_TARGET_DIR="$fixture_target" cargo build --locked --release \
      --target wasm32-wasip2 --manifest-path "$manifest"
  done
  mkdir -p "$repository/kernel/fixtures/artifacts"
  install -m 0644 "$fixture_output/wasm_biotic_kernel_adversarial_task_fixture.wasm" \
    "$repository/kernel/fixtures/artifacts/adversarial-task.wasm"
  install -m 0644 "$fixture_output/wasm_biotic_kernel_mechanism_task_fixture.wasm" \
    "$repository/kernel/fixtures/artifacts/mechanism-task.wasm"
  install -m 0644 "$fixture_output/wasm_biotic_kernel_root_fixture.wasm" \
    "$repository/kernel/fixtures/artifacts/root.wasm"
  install -m 0644 "$fixture_output/wasm_biotic_kernel_task_fixture.wasm" \
    "$repository/kernel/fixtures/artifacts/task.wasm"
}

run_components() {
  build_component_test_fixtures
  CARGO_TARGET_DIR="$target_root/components" cargo test --locked \
    --manifest-path "$repository/components/Cargo.toml" --workspace --all-targets
  CARGO_TARGET_DIR="$target_root/supervisor" cargo test --locked \
    --manifest-path "$repository/components/supervisor-reducer/Cargo.toml" --all-targets
  CARGO_TARGET_DIR="$target_root/workers" cargo test --locked \
    --manifest-path "$repository/components/workers/Cargo.toml" --all-targets
}

build_component_test_fixtures() {
  component_target="$target_root/component-test-fixtures"
  CARGO_TARGET_DIR="$component_target" cargo build --locked --release \
    --target wasm32-wasip2 --manifest-path "$repository/components/Cargo.toml" \
    -p wasm-biotic-capability-router -p wasm-biotic-exchange-service
  mkdir -p \
    "$repository/components/capability-router/tests/artifacts" \
    "$repository/components/exchange-service/tests/artifacts"
  install -m 0644 \
    "$component_target/wasm32-wasip2/release/wasm_biotic_capability_router.wasm" \
    "$repository/components/capability-router/tests/artifacts/capability-router-component.wasm"
  install -m 0644 \
    "$component_target/wasm32-wasip2/release/wasm_biotic_exchange_service.wasm" \
    "$repository/components/exchange-service/tests/artifacts/exchange-service-component.wasm"
}

run_kernel() {
  # The kernel tests compile these bytes with include_bytes!, so each scope
  # must materialize them independently in a fresh checkout.
  build_kernel_fixtures
  CARGO_TARGET_DIR="$target_root/kernel" cargo test --locked \
    --manifest-path "$repository/kernel/Cargo.toml" --all-targets
}

run_rust_tools() {
  CARGO_TARGET_DIR="$target_root/component-equivalence" cargo test --locked \
    --manifest-path "$repository/tools/component-equivalence/Cargo.toml" --all-targets
  rm -rf "$target_root/component-equivalence"
  CARGO_TARGET_DIR="$target_root/component-graph-package" cargo test --locked \
    --manifest-path "$repository/tools/component-graph-package/Cargo.toml" --all-targets
  rm -rf "$target_root/component-graph-package"
  CARGO_TARGET_DIR="$target_root/independent-substrate" cargo test --locked \
    --manifest-path "$repository/tools/independent-substrate/Cargo.toml" --all-targets
  rm -rf "$target_root/independent-substrate"
}

run_oracle() {
  CARGO_TARGET_DIR="$target_root/oracle" cargo test --locked \
    --manifest-path "$repository/Cargo.toml" --lib
}

run_format() {
  cargo fmt --manifest-path "$repository/Cargo.toml" -- --check
  cargo fmt --manifest-path "$repository/components/Cargo.toml" --all -- --check
  cargo fmt --manifest-path "$repository/components/supervisor-reducer/Cargo.toml" -- --check
  cargo fmt --manifest-path "$repository/components/workers/Cargo.toml" --all -- --check
  cargo fmt --manifest-path "$repository/kernel/Cargo.toml" -- --check
  for manifest in \
    "$repository/kernel/fixtures/adversarial-task-component/Cargo.toml" \
    "$repository/kernel/fixtures/mechanism-task-component/Cargo.toml" \
    "$repository/kernel/fixtures/root-component/Cargo.toml" \
    "$repository/kernel/fixtures/task-component/Cargo.toml" \
    "$repository/tools/component-equivalence/Cargo.toml" \
    "$repository/tools/component-graph-package/Cargo.toml" \
    "$repository/tools/independent-substrate/Cargo.toml"
  do
    cargo fmt --manifest-path "$manifest" -- --check
  done
}

run_component_build() {
  python3 "$repository/scripts/verify-preflight.py" --require-wasm-tools
  component_target="$target_root/component-build/components"
  workers_target="$target_root/component-build/workers"
  supervisor_target="$target_root/component-build/supervisor"

  CARGO_TARGET_DIR="$component_target" cargo build --locked --release \
    --target wasm32-wasip2 --manifest-path "$repository/components/Cargo.toml" \
    --workspace --exclude wasm-biotic-worker-router
  CARGO_TARGET_DIR="$component_target" cargo build --locked --release \
    --target wasm32-wasip2 --manifest-path "$repository/components/Cargo.toml" \
    -p wasm-biotic-worker-router
  CARGO_TARGET_DIR="$workers_target" cargo build --locked --release \
    --target wasm32-wasip2 --manifest-path "$repository/components/workers/Cargo.toml" \
    -p wasm-biotic-planner-worker \
    -p wasm-biotic-builder-worker \
    -p wasm-biotic-validator-worker \
    -p wasm-biotic-reviewer-worker \
    -p wasm-biotic-packager-worker \
    -p wasm-biotic-continuity-worker
  CARGO_TARGET_DIR="$supervisor_target" cargo build --locked --release \
    --target wasm32-wasip2 \
    --manifest-path "$repository/components/supervisor-reducer/Cargo.toml"

  for component in \
    wasm_biotic_admitted_tool_probe \
    wasm_biotic_build_service \
    wasm_biotic_capability_router \
    wasm_biotic_closure_evaluator \
    wasm_biotic_continuity_service \
    wasm_biotic_exchange_service \
    wasm_biotic_factory_control \
    wasm_biotic_factory_evolution \
    wasm_biotic_operations_service \
    wasm_biotic_packaging_service \
    wasm_biotic_review_service \
    wasm_biotic_scheduling_service \
    wasm_biotic_state_migration \
    wasm_biotic_validation_service \
    wasm_biotic_worker_router
  do
    validate_component "$component_target/wasm32-wasip2/release/$component.wasm"
  done
  for component in \
    wasm_biotic_planner_worker \
    wasm_biotic_builder_worker \
    wasm_biotic_validator_worker \
    wasm_biotic_reviewer_worker \
    wasm_biotic_packager_worker \
    wasm_biotic_continuity_worker
  do
    validate_component "$workers_target/wasm32-wasip2/release/$component.wasm"
  done
  validate_component \
    "$supervisor_target/wasm32-wasip2/release/wasm_biotic_supervisor_reducer.wasm"
}

validate_component() {
  local component="$1"
  if [[ ! -f "$component" ]]; then
    echo "expected component is absent: $component" >&2
    return 1
  fi
  wasm-tools validate --features component-model "$component"
}

case "$scope" in
  preflight) run_preflight ;;
  record) run_record ;;
  python) run_python ;;
  components) run_components ;;
  kernel) run_kernel ;;
  rust-tools) run_rust_tools ;;
  oracle) run_oracle ;;
  format) run_format ;;
  component-build) run_component_build ;;
  all)
    run_preflight
    run_record
    run_python
    run_components
    run_kernel
    run_rust_tools
    run_oracle
    run_format
    run_component_build
    ;;
  *)
    echo "usage: $0 [preflight|record|python|components|kernel|rust-tools|oracle|format|component-build|all]" >&2
    exit 2
    ;;
esac
