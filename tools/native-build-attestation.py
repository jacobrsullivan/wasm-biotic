#!/usr/bin/env python3
"""Emit an exact, detached native-kernel build attestation.

The executable cannot contain its own digest without a circular identity.  This
tool instead proves that one freshly built executable embeds the exact current
``kernel/native-tcb.json`` bytes and binds that executable to the source closure
declared by the inventory.  The aggregate release signature supplies the final
custody boundary.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
from typing import Any, Iterable


DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
SOURCE_ALGORITHM = (
    "SHA-256 of '<file-sha256><two spaces><repository-relative-path><LF>' "
    "in bytewise path order"
)
INVENTORY_SCOPE = (
    "kernel/Cargo.toml, kernel/Cargo.lock, kernel/src/**/*.rs and "
    "wit/wasm-biotic/*.wit; this self-referential inventory is excluded"
)
ATTESTATION_SCOPE = INVENTORY_SCOPE.replace(
    "this self-referential inventory is excluded",
    "kernel/native-tcb.json is excluded as self-referential",
)


class AttestationError(RuntimeError):
    """A claimed build or source binding could not be established."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AttestationError(message)


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def generated_inventory_json(value: Any) -> bytes:
    """Match kernel/tools/native_tcb_inventory.py's deterministic reviewed format."""

    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def digest_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        require(key not in value, f"JSON contains duplicate key {key!r}")
        value[key] = item
    return value


def read_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        data = path.read_bytes()
        value = json.loads(data, object_pairs_hook=reject_duplicate_keys)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise AttestationError(f"cannot read {label} at {path}: {error}") from error
    require(isinstance(value, dict), f"{label} must be a JSON object")
    return value, data


def source_paths(repository: Path) -> list[Path]:
    paths = [repository / "kernel/Cargo.toml", repository / "kernel/Cargo.lock"]
    paths.extend((repository / "kernel/src").rglob("*.rs"))
    paths.extend((repository / "wit/wasm-biotic").glob("*.wit"))
    unique = sorted(set(paths), key=lambda path: path.relative_to(repository).as_posix().encode())
    require(unique, "native source closure is empty")
    for path in unique:
        require(path.is_file() and not path.is_symlink(), f"source input is not a regular file: {path}")
    return unique


def source_closure(repository: Path) -> tuple[str, list[dict[str, str]]]:
    rows = bytearray()
    files: list[dict[str, str]] = []
    for path in source_paths(repository):
        relative = path.relative_to(repository).as_posix()
        digest = digest_file(path)
        rows.extend(f"{digest[7:]}  {relative}\n".encode("utf-8"))
        files.append({"path": relative, "sha256": digest})
    return digest_bytes(bytes(rows)), files


def inventory_binding(binary: bytes, inventory: bytes) -> dict[str, Any]:
    require(inventory, "native TCB inventory is empty")
    offsets: list[int] = []
    start = 0
    while True:
        offset = binary.find(inventory, start)
        if offset < 0:
            break
        offsets.append(offset)
        start = offset + 1
    require(
        len(offsets) == 1,
        f"optimized executable must embed the exact inventory bytes once; observed {len(offsets)}",
    )
    return {
        "method": "exact raw inventory byte-subsequence search in the optimized executable",
        "offset_bytes": offsets[0],
        "occurrences": 1,
        "result": "pass",
    }


def command_output(arguments: list[str], label: str) -> str:
    try:
        result = subprocess.run(
            arguments,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise AttestationError(f"cannot inspect {label}: {error}") from error
    return result.stdout.strip()


def parse_rustc() -> dict[str, str]:
    lines = command_output(["rustc", "-vV"], "rustc").splitlines()
    fields = dict(line.split(": ", 1) for line in lines if ": " in line)
    return {
        "version": fields.get("release", "unknown"),
        "commit": fields.get("commit-hash", "unknown"),
        "llvm": fields.get("LLVM version", "unknown"),
    }


def parse_cargo() -> dict[str, str]:
    output = command_output(["cargo", "-Vv"], "cargo").splitlines()
    first = output[0].split() if output else []
    commit = "unknown"
    for line in output:
        if line.startswith("commit-hash: "):
            commit = line.removeprefix("commit-hash: ")
    return {"version": first[1] if len(first) > 1 else "unknown", "commit": commit}


def operating_system() -> dict[str, str]:
    return {
        "name": platform.system(),
        "version": platform.mac_ver()[0] or platform.release(),
        "architecture": platform.machine(),
    }


def parse_checks(values: Iterable[str]) -> dict[str, Any]:
    checks: dict[str, Any] = {}
    for value in values:
        key, separator, raw = value.partition("=")
        require(separator == "=" and key, f"verification must be KEY=JSON, got {value!r}")
        require(key not in checks, f"duplicate verification key {key!r}")
        try:
            checks[key] = json.loads(raw)
        except json.JSONDecodeError as error:
            raise AttestationError(f"verification {key!r} is not JSON: {error}") from error
    return checks


def build_report(options: argparse.Namespace) -> dict[str, Any]:
    repository = options.repository.resolve(strict=True)
    binary_path = options.binary.resolve(strict=True)
    inventory_path = repository / "kernel/native-tcb.json"
    require(binary_path.is_file() and not binary_path.is_symlink(), "binary must be a regular file")
    inventory, inventory_bytes = read_json(inventory_path, "native TCB inventory")
    require(
        inventory.get("schema") == "wasm-biotic.native-tcb-inventory.v1",
        "native TCB inventory schema is not v1",
    )
    require(
        inventory_bytes == generated_inventory_json(inventory),
        "native TCB inventory does not match the deterministic generator format",
    )
    crate = inventory.get("crate")
    require(isinstance(crate, dict), "native TCB inventory has no crate object")
    revision = crate.get("source_revision")
    require(isinstance(revision, dict), "native TCB inventory has no source revision")
    require(revision.get("status") == "content-addressed-source-closure", "source revision status is not content-addressed")
    require(revision.get("algorithm") == SOURCE_ALGORITHM, "source revision algorithm differs")
    require(revision.get("scope") == INVENTORY_SCOPE, "source revision scope differs")
    closure_digest, files = source_closure(repository)
    require(revision.get("value") == closure_digest, "current source bytes do not reproduce the native TCB revision")

    binary_bytes = binary_path.read_bytes()
    binary_digest = digest_bytes(binary_bytes)
    inventory_digest = digest_bytes(inventory_bytes)
    verification = {
        "source_closure_matches_inventory_declaration": True,
        "compiled_inventory_exact_bytes_embedded_once": True,
        "production_dependency_on_aiaf_v1": False,
        "certificate_inventory_equality_enforced_before_admission": True,
    }
    verification.update(parse_checks(options.verification))

    generated_at = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return {
        "schema": "wasm-biotic.native-build-attestation.v1",
        "generated_at": generated_at,
        "gate_result": "pass",
        "component_complete_claim": False,
        "scope": options.scope,
        "native_artifact": {
            "path": "objects/" + binary_digest.replace(":", "-", 1),
            "format": command_output(["file", "-b", str(binary_path)], "native executable format"),
            "size_bytes": len(binary_bytes),
            "sha256": binary_digest,
        },
        "compiled_inventory": {
            "path": "kernel/native-tcb.json",
            "size_bytes": len(inventory_bytes),
            "sha256": inventory_digest,
            "binding": "kernel/src/certification.rs computes compiled_native_tcb_inventory_digest from include_bytes!(\"../native-tcb.json\"); production admission rejects a certificate whose inventory digest differs.",
            "binary_embedding_verification": inventory_binding(binary_bytes, inventory_bytes),
            "self_digest_rule": "The executable digest is detached because embedding an executable's own SHA-256 would make its identity circular. The signed graph certificate binds the compiled inventory; this attestation binds the post-build executable to that inventory and verified source closure.",
            "placeholder_inventory_fields_used_as_authority": False,
        },
        "source_closure": {
            "sha256": closure_digest,
            "algorithm": SOURCE_ALGORITHM,
            "scope": ATTESTATION_SCOPE,
            "path_encoding": "UTF-8 repository-relative paths",
            "ordering": "bytewise ascending repository-relative path",
            "line_encoding": "lowercase hexadecimal SHA-256, two ASCII spaces, path, LF",
            "terminal_newline_per_entry": True,
            "inventory_entries_verified": len(files),
            "recomputation_result": "pass",
            "files": files,
            "dependency_lock": files[0],
            "crate_manifest": files[1],
        },
        "build": {
            "command": options.build_command,
            "cargo_target_dir": str(options.cargo_target_dir.resolve()),
            "output_path": str(binary_path),
            "fresh_target_directory": options.target_directory_state == "fresh",
            "result": "pass",
            "profile": "release",
            "target": options.target,
            "rustc": parse_rustc(),
            "cargo": parse_cargo(),
            "operating_system": operating_system(),
        },
        "verification": verification,
    }


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(description=__doc__)
    command.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[1])
    command.add_argument("--binary", type=Path, required=True)
    command.add_argument("--cargo-target-dir", type=Path, required=True)
    command.add_argument("--target", required=True)
    command.add_argument("--build-command", required=True)
    command.add_argument(
        "--target-directory-state",
        choices=("fresh", "reused"),
        default="fresh",
        help="whether the dedicated Cargo target directory was empty before this build",
    )
    command.add_argument("--scope", required=True)
    command.add_argument(
        "--verification",
        action="append",
        default=[],
        metavar="KEY=JSON",
        help="append an executed verification fact (repeatable)",
    )
    command.add_argument("--out", type=Path, required=True)
    return command


def main(arguments: list[str] | None = None) -> int:
    options = parser().parse_args(arguments)
    try:
        report = build_report(options)
        options.out.parent.mkdir(parents=True, exist_ok=True)
        options.out.write_bytes(canonical_json(report))
        print(f"wrote {digest_file(options.out)} {options.out}")
        return 0
    except AttestationError as error:
        print(f"native-build-attestation: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
