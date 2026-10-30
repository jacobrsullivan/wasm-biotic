#!/usr/bin/env python3
"""Regenerate the mechanically derived bindings in native-tcb.json.

The inventory remains a reviewed declaration: this tool deliberately preserves
all prose and policy claims.  It only replaces fields that can be derived from
the retained kernel, contract, configuration, and fixture bytes.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from typing import Any, Iterable

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.9/3.10 verifier fallback.
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools" / "_vendor"))
    import tomli as tomllib


INVENTORY_SCHEMA = "wasm-biotic.native-tcb-inventory.v1"
SOURCE_REVISION_STATUS = "content-addressed-source-closure"
SOURCE_REVISION_ALGORITHM = (
    "SHA-256 of '<file-sha256><two spaces><repository-relative-path><LF>' "
    "in bytewise path order"
)
SOURCE_REVISION_SCOPE = (
    "kernel/Cargo.toml, kernel/Cargo.lock, kernel/src/**/*.rs and "
    "wit/wasm-biotic/*.wit; this self-referential inventory is excluded"
)
WIT_PACKAGE = "wasm-biotic:factory@0.1.0"
WIT_PACKAGE_SCHEMA = "wasm-biotic.wit-package.v1"


class InventoryError(RuntimeError):
    """The inventory or one of its retained inputs is malformed."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InventoryError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_json_bytes(data: bytes, description: str) -> dict[str, Any]:
    try:
        decoded = data.decode("utf-8")
        value = json.loads(decoded, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise InventoryError(f"{description} is not valid UTF-8 JSON: {error}") from error
    if not isinstance(value, dict):
        raise InventoryError(f"{description} must contain a JSON object")
    return value


def _read_bytes(path: Path, description: str) -> bytes:
    if path.is_symlink():
        raise InventoryError(f"{description} must not be a symbolic link: {path}")
    try:
        if not path.is_file():
            raise InventoryError(f"{description} is not a regular file: {path}")
        return path.read_bytes()
    except OSError as error:
        raise InventoryError(f"cannot read {description} {path}: {error}") from error


def _sha256(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _repo_relative(path: Path, repo_root: Path) -> str:
    try:
        return path.relative_to(repo_root).as_posix()
    except ValueError as error:
        raise InventoryError(f"path escapes repository root: {path}") from error


def _bytewise_paths(paths: Iterable[Path], repo_root: Path) -> list[Path]:
    unique: dict[str, Path] = {}
    for path in paths:
        relative = _repo_relative(path, repo_root)
        if relative in unique:
            raise InventoryError(f"duplicate retained path: {relative}")
        unique[relative] = path
    return [unique[key] for key in sorted(unique, key=lambda value: value.encode("utf-8"))]


def _object(parent: dict[str, Any], key: str, context: str) -> dict[str, Any]:
    value = parent.get(key)
    if not isinstance(value, dict):
        raise InventoryError(f"{context}.{key} must be an object")
    return value


def _exact(value: Any, expected: Any, context: str) -> None:
    if value != expected:
        raise InventoryError(f"{context} must be {expected!r}, found {value!r}")


def _validate_template(inventory: dict[str, Any]) -> None:
    _exact(inventory.get("schema"), INVENTORY_SCHEMA, "schema")

    crate = _object(inventory, "crate", "inventory")
    source_revision = _object(crate, "source_revision", "crate")
    _exact(
        source_revision.get("status"),
        SOURCE_REVISION_STATUS,
        "crate.source_revision.status",
    )
    _exact(
        source_revision.get("algorithm"),
        SOURCE_REVISION_ALGORITHM,
        "crate.source_revision.algorithm",
    )
    _exact(
        source_revision.get("scope"),
        SOURCE_REVISION_SCOPE,
        "crate.source_revision.scope",
    )

    compiled_wit = _object(inventory, "compiled_wit_package", "inventory")
    _exact(compiled_wit.get("package"), WIT_PACKAGE, "compiled_wit_package.package")
    _exact(
        compiled_wit.get("artifact_schema"),
        WIT_PACKAGE_SCHEMA,
        "compiled_wit_package.artifact_schema",
    )

    dependency_lock = _object(inventory, "dependency_lock", "inventory")
    _exact(dependency_lock.get("path"), "Cargo.lock", "dependency_lock.path")
    operator_example = _object(inventory, "operator_capacity_example", "inventory")
    _exact(
        operator_example.get("path"),
        "operator-config.example.json",
        "operator_capacity_example.path",
    )
    http_operator_example = _object(
        inventory, "http_operator_capacity_example", "inventory"
    )
    _exact(
        http_operator_example.get("path"),
        "operator-config.http.example.json",
        "http_operator_capacity_example.path",
    )

    if not isinstance(inventory.get("fixture_artifacts"), list):
        raise InventoryError("fixture_artifacts must be an array")
    if not isinstance(inventory.get("reachable_native_modules"), list):
        raise InventoryError("reachable_native_modules must be an array")


def _load_manifest(kernel_root: Path) -> dict[str, Any]:
    manifest_path = kernel_root / "Cargo.toml"
    manifest_bytes = _read_bytes(manifest_path, "kernel Cargo manifest")
    try:
        manifest = tomllib.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise InventoryError(f"kernel Cargo manifest is invalid: {error}") from error
    if not isinstance(manifest, dict):
        raise InventoryError("kernel Cargo manifest must be a TOML table")
    return manifest


def _source_closure_paths(repo_root: Path) -> list[Path]:
    kernel_root = repo_root / "kernel"
    wit_root = repo_root / "wit" / "wasm-biotic"
    fixed = [kernel_root / "Cargo.toml", kernel_root / "Cargo.lock"]
    rust_sources = list((kernel_root / "src").rglob("*.rs"))
    wit_sources = list(wit_root.glob("*.wit"))
    paths = _bytewise_paths([*fixed, *rust_sources, *wit_sources], repo_root)
    for path in paths:
        _read_bytes(path, "source-closure input")
    return paths


def _source_revision(repo_root: Path) -> str:
    rows = bytearray()
    for path in _source_closure_paths(repo_root):
        relative = _repo_relative(path, repo_root)
        digest = _sha256(_read_bytes(path, "source-closure input"))[len("sha256:") :]
        rows.extend(f"{digest}  {relative}\n".encode("utf-8"))
    return _sha256(bytes(rows))


def _compiled_wit_digest(repo_root: Path) -> str:
    wit_root = repo_root / "wit" / "wasm-biotic"
    wit_paths = _bytewise_paths(wit_root.glob("*.wit"), repo_root)
    if not wit_paths:
        raise InventoryError(f"normative WIT package contains no .wit files: {wit_root}")

    files: list[dict[str, Any]] = []
    for path in wit_paths:
        content_bytes = _read_bytes(path, "normative WIT source")
        try:
            content = content_bytes.decode("utf-8")
        except UnicodeDecodeError as error:
            raise InventoryError(f"normative WIT source is not UTF-8: {path}") from error
        files.append(
            {
                "content": content,
                "content_digest": _sha256(content_bytes),
                "path": _repo_relative(path, repo_root),
            }
        )

    artifact = {
        "files": files,
        "package": WIT_PACKAGE,
        "schema": WIT_PACKAGE_SCHEMA,
    }
    artifact_bytes = json.dumps(
        artifact,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return _sha256(artifact_bytes)


def _wasmtime_dependency(manifest: dict[str, Any]) -> tuple[str, bool, list[str]]:
    dependencies = manifest.get("dependencies")
    if not isinstance(dependencies, dict):
        raise InventoryError("Cargo.toml dependencies must be a table")
    wasmtime = dependencies.get("wasmtime")
    if not isinstance(wasmtime, dict):
        raise InventoryError("Cargo.toml must declare wasmtime as a dependency table")
    raw_version = wasmtime.get("version")
    if not isinstance(raw_version, str) or not raw_version.startswith("="):
        raise InventoryError("wasmtime must use an exact '=version' requirement")
    default_features = wasmtime.get("default-features")
    if not isinstance(default_features, bool):
        raise InventoryError("wasmtime default-features must be an explicit boolean")
    features = wasmtime.get("features")
    if not isinstance(features, list) or not all(isinstance(item, str) for item in features):
        raise InventoryError("wasmtime features must be an array of strings")
    if len(features) != len(set(features)):
        raise InventoryError("wasmtime features must not contain duplicates")
    return raw_version.removeprefix("="), default_features, sorted(features)


def derive_inventory(inventory: dict[str, Any], repo_root: Path) -> dict[str, Any]:
    """Return the reviewed inventory with all byte-derived bindings replaced."""

    _validate_template(inventory)
    kernel_root = repo_root / "kernel"
    manifest = _load_manifest(kernel_root)

    package = manifest.get("package")
    if not isinstance(package, dict):
        raise InventoryError("Cargo.toml package must be a table")
    package_name = package.get("name")
    package_version = package.get("version")
    if not isinstance(package_name, str) or not isinstance(package_version, str):
        raise InventoryError("Cargo.toml package name and version must be strings")

    crate = _object(inventory, "crate", "inventory")
    crate["name"] = package_name
    crate["version"] = package_version
    source_revision = _object(crate, "source_revision", "crate")
    source_revision["value"] = _source_revision(repo_root)

    engine = _object(inventory, "engine", "inventory")
    wasmtime_version, default_features, cargo_features = _wasmtime_dependency(manifest)
    engine["name"] = "wasmtime"
    engine["version"] = wasmtime_version
    engine["cargo_default_features"] = default_features
    engine["cargo_features"] = cargo_features

    compiled_wit = _object(inventory, "compiled_wit_package", "inventory")
    compiled_wit["sha256"] = _compiled_wit_digest(repo_root)

    dependency_lock = _object(inventory, "dependency_lock", "inventory")
    dependency_lock["sha256"] = _sha256(
        _read_bytes(kernel_root / "Cargo.lock", "kernel dependency lock")
    )

    operator_example = _object(inventory, "operator_capacity_example", "inventory")
    operator_example["sha256"] = _sha256(
        _read_bytes(
            kernel_root / "operator-config.example.json",
            "operator capacity example",
        )
    )
    http_operator_example = _object(
        inventory, "http_operator_capacity_example", "inventory"
    )
    http_operator_example["sha256"] = _sha256(
        _read_bytes(
            kernel_root / "operator-config.http.example.json",
            "HTTP operator capacity example",
        )
    )

    fixture_root = kernel_root / "fixtures" / "artifacts"
    fixture_paths = _bytewise_paths(fixture_root.glob("*.wasm"), repo_root)
    if not fixture_paths:
        raise InventoryError(f"fixture artifact directory contains no .wasm files: {fixture_root}")
    inventory["fixture_artifacts"] = [
        {
            "path": path.relative_to(kernel_root).as_posix(),
            "sha256": _sha256(_read_bytes(path, "fixture artifact")),
        }
        for path in fixture_paths
    ]

    source_root = kernel_root / "src"
    # `reachable_native_modules` describes the production crate surface, not
    # cfg(test)-only nested modules such as local/durability_tests.rs.  The
    # latter remain bound by source_revision through its recursive scope.
    module_paths = _bytewise_paths(
        [*source_root.glob("*.rs"), *(source_root / "bin").glob("*.rs")],
        repo_root,
    )
    if not module_paths:
        raise InventoryError(f"kernel source directory contains no Rust modules: {source_root}")
    inventory["reachable_native_modules"] = [
        {
            "path": path.relative_to(kernel_root).as_posix(),
            "sha256": _sha256(_read_bytes(path, "reachable native module")),
        }
        for path in module_paths
    ]
    return inventory


def render_inventory(inventory: dict[str, Any]) -> bytes:
    return (json.dumps(inventory, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def expected_inventory_bytes(inventory_path: Path, repo_root: Path) -> tuple[bytes, bytes]:
    current = _read_bytes(inventory_path, "native TCB inventory")
    inventory = _load_json_bytes(current, "native TCB inventory")
    expected = render_inventory(derive_inventory(inventory, repo_root))

    # A generated inventory must be a fixed point.  This catches accidental
    # dependencies on stale derived values in the reviewed template.
    fixed_point = render_inventory(
        derive_inventory(_load_json_bytes(expected, "generated inventory"), repo_root)
    )
    if expected != fixed_point:
        raise InventoryError("generated native TCB inventory is not deterministic")
    return current, expected


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
        directory_descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except BaseException:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass
        raise


def _diff(current: bytes, expected: bytes, inventory_path: Path) -> str:
    current_lines = current.decode("utf-8", errors="replace").splitlines(keepends=True)
    expected_lines = expected.decode("utf-8", errors="replace").splitlines(keepends=True)
    return "".join(
        difflib.unified_diff(
            current_lines,
            expected_lines,
            fromfile=str(inventory_path),
            tofile=f"{inventory_path} (regenerated)",
        )
    )


def _parse_arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--check",
        action="store_true",
        help="verify the checked-in inventory without modifying it (default)",
    )
    mode.add_argument(
        "--write",
        action="store_true",
        help="atomically replace the inventory with regenerated bytes",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        help="repository root (defaults to the checkout containing this script)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    arguments = _parse_arguments(sys.argv[1:] if argv is None else argv)
    repo_root = (
        arguments.repo_root.resolve()
        if arguments.repo_root is not None
        else Path(__file__).resolve().parents[2]
    )
    inventory_path = repo_root / "kernel" / "native-tcb.json"

    try:
        current, expected = expected_inventory_bytes(inventory_path, repo_root)
        if current == expected:
            print(f"native TCB inventory is current: {inventory_path}")
            return 0
        if arguments.write:
            _atomic_write(inventory_path, expected)
            print(f"regenerated native TCB inventory: {inventory_path}")
            return 0
        print(
            "native TCB inventory is stale; run "
            "`python3 kernel/tools/native_tcb_inventory.py --write`",
            file=sys.stderr,
        )
        print(_diff(current, expected, inventory_path), file=sys.stderr, end="")
        return 1
    except (InventoryError, OSError) as error:
        print(f"native TCB inventory generation failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
