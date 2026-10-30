#!/usr/bin/env python3
"""Prepare and verify a self-contained, vendored R4 source snapshot.

The snapshot copies only the canonical component factory, substrate, contracts,
interfaces, release tools, and the transitional library source required to
compile those tools.  Cargo registry dependencies are vendored from every lock
universe, so independent builders need no repository or registry access.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any, Iterable


SCHEMA = "wasm-biotic.r4-source-snapshot.v1"
ROOT_FILES = (
    ".env.example",
    ".gitignore",
    "AGENTS.md",
    "Cargo.lock",
    "Cargo.toml",
    "README.md",
)
REQUIRED_ROOT_FILES = (
    "Cargo.lock",
    "Cargo.toml",
    "README.md",
)
SOURCE_ROOTS = (
    "components",
    "contracts/component-complete",
    "kernel",
    "src",
    "tools",
    "wit",
)
FROZEN_EMBEDDED_BUILD_INPUTS = (
    "artifacts/fixtures/m1-reference-component/template/component.wat",
    "artifacts/fixtures/m1-reference-component/template/component.wit",
    "notes/ROADMAP.md",
    "reference-docs/introduction.md",
)
FORBIDDEN_SEGMENTS = frozenset(
    {
        ".DS_Store",
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "__pycache__",
        "artifacts",
        "target",
        "vendor",
    }
)
FORBIDDEN_OPERATOR_KEY_SUFFIXES = frozenset(
    {".der", ".key", ".p8", ".pem", ".pk8", ".pkcs8"}
)
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
CONFIG_BYTES = b'''# Generated for the content-addressed R4 source snapshot.\n[source.crates-io]\nreplace-with = "vendored-sources"\n\n[source.vendored-sources]\ndirectory = "vendor"\n\n[net]\noffline = true\n'''


class SnapshotError(RuntimeError):
    """A snapshot was incomplete, unsafe, or did not reproduce."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SnapshotError(message)


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def digest_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def validate_relative(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    require(value and not path.is_absolute() and path.as_posix() == value, f"invalid snapshot path {value!r}")
    require(all(part not in ("", ".", "..") for part in path.parts), f"unsafe snapshot path {value!r}")
    if any(part in FORBIDDEN_SEGMENTS for part in path.parts):
        require(
            value in FROZEN_EMBEDDED_BUILD_INPUTS,
            f"generated path is forbidden: {value!r}",
        )
    require(path.name != ".env", "secret-bearing .env is forbidden from the source snapshot")
    return path


def validate_source_relative(value: str) -> PurePosixPath:
    path = validate_relative(value)
    require(
        path.suffix.lower() not in FORBIDDEN_OPERATOR_KEY_SUFFIXES,
        f"operator private-key-shaped source file is forbidden: {value!r}",
    )
    return path


def is_selected_source_path(value: str) -> bool:
    return (
        value in ROOT_FILES
        or value in FROZEN_EMBEDDED_BUILD_INPUTS
        or any(value.startswith(f"{root}/") for root in SOURCE_ROOTS)
    )


def required_embedded_input(repository: Path, value: str) -> Path:
    relative = validate_relative(value)
    path = repository.joinpath(*relative.parts)
    require(path.is_file(), f"required embedded build input is absent: {value}")
    cursor = repository
    for part in relative.parts:
        cursor = cursor / part
        require(not cursor.is_symlink(), f"embedded build input traverses a link: {value}")
    return path


def selected_source_files(repository: Path) -> list[Path]:
    files: list[Path] = []
    for name in ROOT_FILES:
        path = repository / name
        if name in REQUIRED_ROOT_FILES:
            require(path.is_file(), f"required root build input is absent: {name}")
        if path.exists() or path.is_symlink():
            require(path.is_file() and not path.is_symlink(), f"root source must be a regular file: {name}")
            files.append(path)
    for name in FROZEN_EMBEDDED_BUILD_INPUTS:
        files.append(required_embedded_input(repository, name))
    for name in SOURCE_ROOTS:
        root = repository / name
        require(root.is_dir() and not root.is_symlink(), f"required source root is absent: {name}")
        for directory, directory_names, file_names in os.walk(root, topdown=True, followlinks=False):
            directory_names[:] = sorted(item for item in directory_names if item not in FORBIDDEN_SEGMENTS)
            base = Path(directory)
            for file_name in sorted(file_names):
                source = base / file_name
                require(not source.is_symlink(), f"source links are forbidden: {source}")
                relative = source.relative_to(repository).as_posix()
                validate_source_relative(relative)
                files.append(source)
    output = sorted(set(files), key=lambda path: path.relative_to(repository).as_posix().encode("utf-8"))
    require(output, "source selection is empty")
    return output


def normalized_mode(path: Path) -> int:
    return 0o755 if path.lstat().st_mode & stat.S_IXUSR else 0o644


def copy_source(repository: Path, output: Path) -> list[dict[str, Any]]:
    inventory: list[dict[str, Any]] = []
    for source in selected_source_files(repository):
        relative = source.relative_to(repository).as_posix()
        destination = output.joinpath(*PurePosixPath(relative).parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination, follow_symlinks=False)
        mode = normalized_mode(source)
        os.chmod(destination, mode)
        inventory.append(
            {
                "mode": f"{mode:04o}",
                "path": relative,
                "sha256": digest_file(destination),
                "size_bytes": destination.stat().st_size,
            }
        )
    return inventory


def closure_digest(inventory: Iterable[dict[str, Any]]) -> str:
    rows = bytearray()
    for item in inventory:
        rows.extend(
            f"{item['sha256'][7:]}  {item['mode']}  {item['size_bytes']}  {item['path']}\n".encode(
                "utf-8"
            )
        )
    return digest_bytes(bytes(rows))


def lock_roots(repository: Path) -> list[Path]:
    roots: list[Path] = []
    for directory, directory_names, file_names in os.walk(repository, topdown=True, followlinks=False):
        directory_names[:] = sorted(item for item in directory_names if item not in FORBIDDEN_SEGMENTS)
        if "Cargo.lock" in file_names:
            manifest = Path(directory) / "Cargo.toml"
            if manifest.is_file():
                roots.append(manifest)
    roots = sorted(set(roots), key=lambda path: path.relative_to(repository).as_posix().encode("utf-8"))
    primary = repository / "Cargo.toml"
    require(primary in roots, "root Cargo.lock/Cargo.toml universe is absent")
    roots.remove(primary)
    return [primary, *roots]


def command_output(arguments: list[str], label: str, directory: Path) -> str:
    try:
        result = subprocess.run(
            arguments,
            cwd=directory,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise SnapshotError(f"cannot inspect {label}: {error}") from error
    return result.stdout.strip()


def toolchain(cargo: Path, repository: Path, wasm_tools: Path | None) -> dict[str, Any]:
    cargo_version = command_output([str(cargo), "-Vv"], "Cargo", repository)
    rustc = shutil.which("rustc")
    require(rustc is not None, "rustc is not available")
    rustc_version = command_output([rustc, "-vV"], "rustc", repository)
    value: dict[str, Any] = {
        "cargo": cargo_version.splitlines(),
        "rustc": rustc_version.splitlines(),
        "wasm_target": "wasm32-wasip2",
    }
    if wasm_tools is not None:
        value["wasm_tools"] = command_output([str(wasm_tools), "--version"], "wasm-tools", repository)
    return value


def vendor_dependencies(repository: Path, output: Path, cargo: Path) -> list[dict[str, Any]]:
    manifests = lock_roots(repository)
    vendor = output / "vendor"
    arguments = [
        str(cargo),
        "vendor",
        "--versioned-dirs",
        "--locked",
        "--offline",
        "--manifest-path",
        str(manifests[0]),
    ]
    for manifest in manifests[1:]:
        arguments.extend(("--sync", str(manifest)))
    arguments.append(str(vendor))
    try:
        result = subprocess.run(
            arguments,
            cwd=repository,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except (OSError, subprocess.SubprocessError) as error:
        detail = getattr(error, "stderr", "")
        raise SnapshotError(f"Cargo dependency vendoring failed: {error}: {detail}") from error
    config = output / ".cargo" / "config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_bytes(CONFIG_BYTES)
    inventory: list[dict[str, Any]] = []
    for path in sorted(vendor.rglob("*"), key=lambda item: item.relative_to(output).as_posix().encode("utf-8")):
        require(not path.is_symlink(), f"vendored dependency contains a link: {path}")
        if not path.is_file():
            continue
        mode = normalized_mode(path)
        os.chmod(path, mode)
        inventory.append(
            {
                "mode": f"{mode:04o}",
                "path": path.relative_to(output).as_posix(),
                "sha256": digest_file(path),
                "size_bytes": path.stat().st_size,
            }
        )
    require(inventory, "Cargo produced an empty vendor tree")
    return inventory


def snapshot_manifest(
    source: list[dict[str, Any]],
    vendor: list[dict[str, Any]],
    tools: dict[str, Any],
) -> dict[str, Any]:
    locks = [item for item in source if item["path"].endswith("Cargo.lock")]
    manifests = [item for item in source if item["path"].endswith("Cargo.toml")]
    return {
        "cargo_lock_count": len(locks),
        "cargo_locks": locks,
        "cargo_manifest_count": len(manifests),
        "cargo_manifests": manifests,
        "dependency_delivery": "complete Cargo registry source vendoring; no registry access required",
        "schema": SCHEMA,
        "selection": {
            "native_substrate": "kernel",
            "component_factory": "components",
            "frozen_embedded_build_inputs": list(FROZEN_EMBEDDED_BUILD_INPUTS),
            "interfaces": "wit/wasm-biotic",
            "normative_contract": "contracts/component-complete",
            "release_tools": "tools",
            "required_root_build_inputs": list(REQUIRED_ROOT_FILES),
            "transitional_build_dependency_only": (
                "src and root Cargo files plus the enumerated compile-time embedded inputs; "
                "not production factory authority"
            ),
        },
        "source_closure_sha256": closure_digest(source),
        "source_file_count": len(source),
        "toolchain": tools,
        "vendor_closure_sha256": closure_digest(vendor),
        "vendor_file_count": len(vendor),
    }


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in output, f"JSON contains duplicate key {key!r}")
        output[key] = value
    return output


def read_manifest(path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        data = path.read_bytes()
        value = json.loads(data, object_pairs_hook=reject_duplicate_keys)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SnapshotError(f"cannot read snapshot manifest {path}: {error}") from error
    require(isinstance(value, dict), "snapshot manifest must be an object")
    require(canonical_json(value) == data, "snapshot manifest is not canonical JSON")
    require(value.get("schema") == SCHEMA, "unsupported snapshot manifest schema")
    return value, data


def actual_inventory(root: Path, prefix: str) -> list[dict[str, Any]]:
    base = root / prefix
    require(base.is_dir(), f"snapshot directory is absent: {prefix}")
    items: list[dict[str, Any]] = []
    for path in sorted(base.rglob("*"), key=lambda item: item.relative_to(root).as_posix().encode("utf-8")):
        require(not path.is_symlink(), f"snapshot contains a link: {path}")
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        mode = normalized_mode(path)
        require(path.stat().st_mode & 0o777 == mode, f"snapshot file has non-normalized mode: {relative}")
        items.append(
            {
                "mode": f"{mode:04o}",
                "path": relative,
                "sha256": digest_file(path),
                "size_bytes": path.stat().st_size,
            }
        )
    return items


def verify_snapshot(root: Path) -> tuple[str, dict[str, Any]]:
    root = root.resolve(strict=True)
    require(root.is_dir() and not root.is_symlink(), "snapshot root is not a regular directory")
    manifest, manifest_bytes = read_manifest(root / "SOURCE-SNAPSHOT.json")
    expected_selection = snapshot_manifest([], [], manifest.get("toolchain", {}))["selection"]
    require(manifest.get("selection") == expected_selection, "source selection declaration differs")
    vendor = actual_inventory(root, "vendor")
    require(closure_digest(vendor) == manifest.get("vendor_closure_sha256"), "vendor closure digest differs")
    require(len(vendor) == manifest.get("vendor_file_count"), "vendor file count differs")
    source_items: list[dict[str, Any]] = []
    for item in manifest.get("cargo_locks", []) + manifest.get("cargo_manifests", []):
        require(isinstance(item, dict), "Cargo inventory item is not an object")
        path = root.joinpath(*validate_relative(item["path"]).parts)
        require(path.is_file() and digest_file(path) == item["sha256"], f"Cargo input differs: {item['path']}")
    # Reconstruct every non-generated source file rather than trusting the two
    # Cargo lists.  The source closure deliberately excludes its own manifest,
    # the generated Cargo config, and the vendored dependency tree.
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix().encode("utf-8")):
        relative = path.relative_to(root).as_posix()
        if relative == "SOURCE-SNAPSHOT.json" or relative == ".cargo/config.toml" or relative.startswith("vendor/"):
            continue
        require(not path.is_symlink(), f"snapshot contains a source link: {relative}")
        if path.is_file():
            validate_source_relative(relative)
            require(is_selected_source_path(relative), f"unselected source path is forbidden: {relative}")
            mode = normalized_mode(path)
            require(
                path.stat().st_mode & 0o777 == mode,
                f"snapshot source file has non-normalized mode: {relative}",
            )
            source_items.append(
                {
                    "mode": f"{mode:04o}",
                    "path": relative,
                    "sha256": digest_file(path),
                    "size_bytes": path.stat().st_size,
                }
            )
    require(closure_digest(source_items) == manifest.get("source_closure_sha256"), "source closure digest differs")
    require(len(source_items) == manifest.get("source_file_count"), "source file count differs")
    actual_locks = [item for item in source_items if item["path"].endswith("Cargo.lock")]
    actual_manifests = [item for item in source_items if item["path"].endswith("Cargo.toml")]
    require(manifest.get("cargo_locks") == actual_locks, "Cargo lock inventory differs from the source closure")
    require(manifest.get("cargo_lock_count") == len(actual_locks), "Cargo lock count differs")
    require(manifest.get("cargo_manifests") == actual_manifests, "Cargo manifest inventory differs from the source closure")
    require(manifest.get("cargo_manifest_count") == len(actual_manifests), "Cargo manifest count differs")
    for value in FROZEN_EMBEDDED_BUILD_INPUTS:
        require(
            any(item["path"] == value for item in source_items),
            f"required embedded build input is absent: {value}",
        )
    for value in REQUIRED_ROOT_FILES:
        require(
            any(item["path"] == value for item in source_items),
            f"required root build input is absent: {value}",
        )
    require((root / ".cargo/config.toml").read_bytes() == CONFIG_BYTES, "offline Cargo configuration differs")
    return digest_bytes(manifest_bytes), manifest


def prepare(options: argparse.Namespace) -> None:
    repository = options.repository.resolve(strict=True)
    require(repository.is_dir() and not repository.is_symlink(), "repository must be a regular directory")
    require(not options.out.exists(), f"snapshot destination already exists: {options.out}")
    # Preserve Cargo's argv[0] basename. Rustup installations expose Cargo as
    # a multicall symlink; resolving that symlink to `rustup` changes dispatch
    # and makes `cargo vendor` fail even though the supplied executable exists.
    cargo = (
        Path(os.path.abspath(os.fspath(options.cargo)))
        if options.cargo.is_absolute()
        else Path(shutil.which(str(options.cargo)) or "")
    )
    require(cargo.is_file(), f"Cargo executable is absent: {options.cargo}")
    wasm_tools = None
    if options.wasm_tools is not None:
        wasm_tools = options.wasm_tools.resolve(strict=True) if options.wasm_tools.is_absolute() else Path(shutil.which(str(options.wasm_tools)) or "")
        require(wasm_tools.is_file(), f"wasm-tools executable is absent: {options.wasm_tools}")
    options.out.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="wasm-biotic-source-", dir=options.out.parent) as temporary:
        candidate = Path(temporary) / "snapshot"
        candidate.mkdir()
        source = copy_source(repository, candidate)
        vendor = vendor_dependencies(repository, candidate, cargo)
        manifest = snapshot_manifest(source, vendor, toolchain(cargo, repository, wasm_tools))
        (candidate / "SOURCE-SNAPSHOT.json").write_bytes(canonical_json(manifest))
        verify_snapshot(candidate)
        os.replace(candidate, options.out)
    digest, manifest = verify_snapshot(options.out)
    print(f"prepared {digest} source-files={manifest['source_file_count']} vendor-files={manifest['vendor_file_count']} {options.out}")


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(description=__doc__)
    subcommands = command.add_subparsers(dest="command", required=True)
    prepare_parser = subcommands.add_parser("prepare", help="copy sources and vendor every lock universe")
    prepare_parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[1])
    prepare_parser.add_argument("--out", required=True, type=Path)
    prepare_parser.add_argument("--cargo", type=Path, default=Path(os.environ.get("CARGO", "cargo")))
    prepare_parser.add_argument("--wasm-tools", type=Path)
    verify_parser = subcommands.add_parser("verify", help="verify a prepared source snapshot")
    verify_parser.add_argument("snapshot", type=Path)
    return command


def main(arguments: list[str] | None = None) -> int:
    options = parser().parse_args(arguments)
    try:
        if options.command == "prepare":
            prepare(options)
        else:
            digest, manifest = verify_snapshot(options.snapshot)
            print(f"verified {digest} source-files={manifest['source_file_count']} vendor-files={manifest['vendor_file_count']} {options.snapshot}")
        return 0
    except SnapshotError as error:
        print(f"r4-source-snapshot: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
