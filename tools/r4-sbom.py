#!/usr/bin/env python3
"""Generate and strictly verify a deterministic SPDX 2.3 R4 SBOM.

The document covers the exact Rust manifest/lock closure, canonical production
source files, release artifacts supplied by role, and declared target-system
packages.  Verification rebuilds the document from those public inputs; an
omitted, phantom, or modified file therefore fails closed.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Any, Iterable

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.9/3.10 public verifier fallback.
    sys.path.insert(0, str(Path(__file__).resolve().parent / "_vendor"))
    import tomli as tomllib


SPDX_VERSION = "SPDX-2.3"
COVERAGE_SCHEMA = "wasm-biotic.sbom-coverage.v1"
TOOL_NAME = "Wasm-Biotic r4-sbom"
SOURCE_ROOTS = (
    "components",
    "contracts/component-complete",
    "kernel",
    "src",
    "tools",
    "vendor",
    "wit",
)
ROOT_SOURCE_FILES = (
    ".env.example",
    ".gitignore",
    "AGENTS.md",
    "Cargo.lock",
    "Cargo.toml",
    "README.md",
)
REQUIRED_ROOT_SOURCE_FILES = (
    "Cargo.lock",
    "Cargo.toml",
    "README.md",
)
FROZEN_EMBEDDED_BUILD_INPUTS = (
    "artifacts/fixtures/m1-reference-component/template/component.wat",
    "artifacts/fixtures/m1-reference-component/template/component.wit",
    "notes/ROADMAP.md",
    "reference-docs/introduction.md",
)
FORBIDDEN_SEGMENTS = frozenset({".git", "artifacts", "target", "__pycache__"})
FORBIDDEN_OPERATOR_KEY_SUFFIXES = frozenset(
    {".der", ".key", ".p8", ".pem", ".pk8", ".pkcs8"}
)
RELEASE_TARGETS = frozenset({"aarch64-apple-darwin", "x86_64-unknown-linux-gnu"})
ROLE_RE = re.compile(r"[a-z0-9]+(?:[-_][a-z0-9]+)*\Z")
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")


class SbomError(RuntimeError):
    """An SBOM input or assertion was incomplete or non-canonical."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SbomError(message)


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in output, f"JSON contains duplicate key {key!r}")
        output[key] = value
    return output


def reject_floats(value: Any, where: str = "document") -> None:
    require(not isinstance(value, float), f"{where} contains a floating-point number")
    if isinstance(value, dict):
        for key, item in value.items():
            reject_floats(item, f"{where}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            reject_floats(item, f"{where}[{index}]")


def read_canonical_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        data = path.read_bytes()
        value = json.loads(data, object_pairs_hook=reject_duplicate_keys)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SbomError(f"cannot read {label} at {path}: {error}") from error
    require(isinstance(value, dict), f"{label} must be a JSON object")
    reject_floats(value, label)
    require(canonical_json(value) == data, f"{label} is not canonical JSON")
    return value, data


def stable_id(prefix: str, identity: str) -> str:
    suffix = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]
    return f"SPDXRef-{prefix}-{suffix}"


def source_paths(repository: Path) -> list[Path]:
    candidates: list[Path] = []
    for name in ROOT_SOURCE_FILES:
        path = repository / name
        if name in REQUIRED_ROOT_SOURCE_FILES:
            require(path.is_file(), f"required root build input is absent: {name}")
        if path.is_file():
            require(not path.is_symlink(), f"source link is forbidden: {path}")
            candidates.append(path)
    for name in FROZEN_EMBEDDED_BUILD_INPUTS:
        path = repository.joinpath(*PurePosixPath(name).parts)
        require(path.is_file(), f"required embedded build input is absent: {name}")
        require(not path.is_symlink(), f"source link is forbidden: {path}")
        candidates.append(path)
    for root_name in SOURCE_ROOTS:
        root = repository / root_name
        if not root.is_dir():
            continue
        for directory, names, file_names in os.walk(root, topdown=True, followlinks=False):
            names[:] = sorted(name for name in names if name not in FORBIDDEN_SEGMENTS)
            base = Path(directory)
            for name in sorted(file_names):
                path = base / name
                if path.is_symlink():
                    continue
                require(name != ".env", f"secret-bearing source file is forbidden: {path}")
                if root_name != "vendor":
                    require(
                        path.suffix.lower() not in FORBIDDEN_OPERATOR_KEY_SUFFIXES,
                        f"operator private-key-shaped source file is forbidden: {path}",
                    )
                candidates.append(path)
    result = sorted(set(candidates), key=lambda path: path.relative_to(repository).as_posix().encode("utf-8"))
    require(result, "SBOM source closure is empty")
    vendor = repository / "vendor"
    require(vendor.is_dir() and not vendor.is_symlink(), "vendored Cargo source tree is absent")
    require(any(path.is_relative_to(vendor) for path in result), "vendored Cargo source tree is empty")
    return result


def cargo_paths(repository: Path, name: str) -> list[Path]:
    return [path for path in source_paths(repository) if path.name == name]


def parse_toml(path: Path, label: str) -> dict[str, Any]:
    try:
        value = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise SbomError(f"cannot parse {label} {path}: {error}") from error
    require(isinstance(value, dict), f"{label} {path} is not a table")
    return value


def package_common(spdx_id: str, name: str, version: str, download: str) -> dict[str, Any]:
    return {
        "SPDXID": spdx_id,
        "copyrightText": "NOASSERTION",
        "downloadLocation": download,
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "name": name,
        "versionInfo": version,
    }


def cargo_packages(repository: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    packages: dict[str, dict[str, Any]] = {}
    lock_inventory: list[dict[str, Any]] = []
    for lock_path in cargo_paths(repository, "Cargo.lock"):
        relative = lock_path.relative_to(repository).as_posix()
        lock_inventory.append({"path": relative, "sha256": digest_file(lock_path)})
        value = parse_toml(lock_path, "Cargo lockfile")
        entries = value.get("package", [])
        require(isinstance(entries, list), f"Cargo lockfile has no package array: {relative}")
        for entry in entries:
            require(isinstance(entry, dict), f"Cargo package entry is not a table: {relative}")
            name = entry.get("name")
            version = entry.get("version")
            source = entry.get("source", "local")
            checksum = entry.get("checksum")
            require(isinstance(name, str) and isinstance(version, str), f"Cargo package has no name/version: {relative}")
            identity = f"cargo|{name}|{version}|{source}|{checksum or ''}"
            if identity in packages:
                continue
            item = package_common(
                stable_id("CargoPackage", identity),
                name,
                version,
                source if isinstance(source, str) and source != "local" else "NOASSERTION",
            )
            if isinstance(checksum, str):
                require(re.fullmatch(r"[0-9a-f]{64}", checksum) is not None, f"invalid Cargo checksum for {name}")
                item["checksums"] = [{"algorithm": "SHA256", "checksumValue": checksum}]
            if isinstance(source, str) and source.startswith("registry+"):
                item["externalRefs"] = [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceLocator": f"pkg:cargo/{name}@{version}",
                        "referenceType": "purl",
                    }
                ]
            packages[identity] = item
    return sorted(packages.values(), key=lambda item: item["SPDXID"]), lock_inventory


def local_packages(repository: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    packages: list[dict[str, Any]] = []
    manifest_inventory: list[dict[str, Any]] = []
    for manifest in cargo_paths(repository, "Cargo.toml"):
        relative = manifest.relative_to(repository).as_posix()
        manifest_inventory.append({"path": relative, "sha256": digest_file(manifest)})
        value = parse_toml(manifest, "Cargo manifest")
        package = value.get("package")
        if not isinstance(package, dict):
            continue
        name = package.get("name")
        version = package.get("version")
        if not isinstance(name, str):
            continue
        if not isinstance(version, str):
            workspace = package.get("version", {})
            version = "workspace" if isinstance(workspace, dict) else "unknown"
        identity = f"local|{relative}|{name}|{version}"
        item = package_common(stable_id("LocalPackage", identity), name, version, "NOASSERTION")
        item["comment"] = f"Wasm-Biotic source manifest: {relative}"
        packages.append(item)
    return sorted(packages, key=lambda item: item["SPDXID"]), manifest_inventory


def parse_artifacts(values: Iterable[str]) -> list[tuple[str, Path]]:
    result: list[tuple[str, Path]] = []
    roles: set[str] = set()
    for value in values:
        role, separator, raw_path = value.partition("=")
        require(separator == "=" and ROLE_RE.fullmatch(role) is not None, f"artifact must be ROLE=PATH, got {value!r}")
        require(role not in roles, f"duplicate artifact role {role!r}")
        path = Path(raw_path).resolve(strict=True)
        require(not path.is_symlink() and (path.is_file() or path.is_dir()), f"artifact is not a regular file/directory: {path}")
        roles.add(role)
        result.append((role, path))
    return sorted(result, key=lambda item: item[0])


def artifact_files(role: str, path: Path) -> list[tuple[str, Path]]:
    if path.is_file():
        return [(f"artifacts/{role}/{path.name}", path)]
    files: list[tuple[str, Path]] = []
    for candidate in path.rglob("*"):
        if candidate.is_symlink():
            raise SbomError(f"artifact tree contains a link: {candidate}")
        if candidate.is_file():
            relative = candidate.relative_to(path).as_posix()
            require(".." not in PurePosixPath(relative).parts, f"unsafe artifact path: {relative}")
            files.append((f"artifacts/{role}/{relative}", candidate))
    return sorted(files, key=lambda item: item[0].encode("utf-8"))


def parse_system_packages(values: Iterable[str]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for value in values:
        fields = value.split("|", 2)
        require(len(fields) == 3 and all(fields), f"system package must be TARGET|NAME|VERSION, got {value!r}")
        target, name, version = fields
        identity = f"system|{target}|{name}|{version}"
        require((target, name) not in seen, f"duplicate system package {target}|{name}")
        seen.add((target, name))
        item = package_common(stable_id("SystemPackage", identity), name, version, "NOASSERTION")
        item["comment"] = f"Runtime system dependency for {target}"
        output.append(item)
    return sorted(output, key=lambda item: item["SPDXID"])


def spdx_file(name: str, path: Path, file_type: str) -> dict[str, Any]:
    digest = digest_file(path)
    return {
        "SPDXID": stable_id("File", name),
        "checksums": [{"algorithm": "SHA256", "checksumValue": digest[7:]}],
        "copyrightText": "NOASSERTION",
        "fileName": "./" + name,
        "fileTypes": [file_type],
        "licenseConcluded": "NOASSERTION",
    }


def classify_file(path: Path) -> str:
    if path.suffix == ".wasm":
        return "BINARY"
    if path.suffix in (".md", ".json"):
        return "TEXT"
    if path.suffix in (".rs", ".py", ".wit", ".toml") or path.name == "Cargo.lock":
        return "SOURCE"
    return "BINARY"


def iso_time(epoch: int) -> str:
    require(epoch >= 0, "source date epoch must be non-negative")
    try:
        return dt.datetime.fromtimestamp(epoch, dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError) as error:
        raise SbomError(f"source date epoch is out of range: {epoch}") from error


def build_documents(
    repository: Path,
    artifacts: list[tuple[str, Path]],
    system_values: Iterable[str],
    epoch: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    repository = repository.resolve(strict=True)
    require(repository.is_dir() and not repository.is_symlink(), "source root must be a regular directory")
    dependency_packages, locks = cargo_packages(repository)
    project_packages, manifests = local_packages(repository)
    system_packages = parse_system_packages(system_values)
    system_targets = {
        item["comment"].removeprefix("Runtime system dependency for ")
        for item in system_packages
    }
    require(system_targets == RELEASE_TARGETS, "system package targets must equal the closed R4 target set")
    require(artifacts, "SBOM artifact role inventory is empty")
    packages = sorted(
        [*dependency_packages, *project_packages, *system_packages],
        key=lambda item: item["SPDXID"],
    )
    require(packages, "SBOM package inventory is empty")

    files: list[dict[str, Any]] = []
    inventory_rows = bytearray()
    for path in source_paths(repository):
        relative = "source/" + path.relative_to(repository).as_posix()
        item = spdx_file(relative, path, classify_file(path))
        files.append(item)
        inventory_rows.extend(f"{item['checksums'][0]['checksumValue']}  {relative}\n".encode("utf-8"))
    artifact_inventory: list[dict[str, Any]] = []
    for role, path in artifacts:
        role_files = artifact_files(role, path)
        require(role_files, f"artifact role {role!r} contains no files")
        role_rows: list[dict[str, Any]] = []
        for relative, candidate in role_files:
            item = spdx_file(relative, candidate, classify_file(candidate))
            files.append(item)
            digest = "sha256:" + item["checksums"][0]["checksumValue"]
            role_rows.append({"path": relative.removeprefix(f"artifacts/{role}/"), "sha256": digest, "size_bytes": candidate.stat().st_size})
            inventory_rows.extend(f"{digest[7:]}  {relative}\n".encode("utf-8"))
        artifact_inventory.append({"file_count": len(role_rows), "files": role_rows, "role": role})
    files.sort(key=lambda item: item["fileName"].encode("utf-8"))
    require(len({item["fileName"] for item in files}) == len(files), "SBOM contains duplicate file names")
    source_closure = digest_bytes(bytes(inventory_rows))
    namespace = f"https://wasm-biotic.invalid/spdx/{source_closure.replace(':', '-')}"
    relationships = [
        {
            "relatedSpdxElement": "SPDXRef-Package-WasmBioticFactory",
            "relationshipType": "DESCRIBES",
            "spdxElementId": "SPDXRef-DOCUMENT",
        },
        *[
        {
            "relatedSpdxElement": package["SPDXID"],
            "relationshipType": "DESCRIBES",
            "spdxElementId": "SPDXRef-DOCUMENT",
        }
        for package in packages
        ],
    ]
    relationships.extend(
        {
            "relatedSpdxElement": item["SPDXID"],
            "relationshipType": "CONTAINS",
            "spdxElementId": "SPDXRef-Package-WasmBioticFactory",
        }
        for item in files
    )
    root_package = package_common(
        "SPDXRef-Package-WasmBioticFactory",
        "wasm-biotic-component-complete-factory",
        "r4",
        "NOASSERTION",
    )
    root_package["comment"] = "Versioned content-addressed Wasm components plus policy-neutral native substrate"
    packages = [root_package, *packages]
    document = {
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {"created": iso_time(epoch), "creators": [f"Tool: {TOOL_NAME}"]},
        "dataLicense": "CC0-1.0",
        "documentNamespace": namespace,
        "files": files,
        "name": "Wasm-Biotic component-complete R4 release",
        "packages": packages,
        "relationships": relationships,
        "spdxVersion": SPDX_VERSION,
    }
    sbom_bytes = canonical_json(document)
    coverage = {
        "artifact_roles": artifact_inventory,
        "cargo_lock_count": len(locks),
        "cargo_locks": locks,
        "cargo_manifest_count": len(manifests),
        "cargo_manifests": manifests,
        "file_count": len(files),
        "package_count": len(packages),
        "result": "pass",
        "sbom_sha256": digest_bytes(sbom_bytes),
        "schema": COVERAGE_SCHEMA,
        "source_and_artifact_closure_sha256": source_closure,
        "system_package_count": len(system_packages),
        "system_packages": [
            {"name": item["name"], "target": item["comment"].removeprefix("Runtime system dependency for "), "version": item["versionInfo"]}
            for item in system_packages
        ],
    }
    return document, coverage


def write_documents(options: argparse.Namespace) -> None:
    artifacts = parse_artifacts(options.artifact)
    document, coverage = build_documents(
        options.source_root,
        artifacts,
        options.system_package,
        options.epoch,
    )
    options.out.parent.mkdir(parents=True, exist_ok=True)
    options.out.write_bytes(canonical_json(document))
    options.coverage_out.parent.mkdir(parents=True, exist_ok=True)
    options.coverage_out.write_bytes(canonical_json(coverage))
    print(f"wrote {coverage['sbom_sha256']} {options.out}")
    print(f"coverage {digest_file(options.coverage_out)} {options.coverage_out}")


def verify_documents(options: argparse.Namespace) -> None:
    actual, actual_bytes = read_canonical_json(options.sbom, "SPDX SBOM")
    coverage, coverage_bytes = read_canonical_json(options.coverage, "SBOM coverage report")
    created = actual.get("creationInfo", {}).get("created")
    require(isinstance(created, str) and created.endswith("Z"), "SBOM has no canonical creation timestamp")
    try:
        epoch = int(dt.datetime.fromisoformat(created.replace("Z", "+00:00")).timestamp())
    except (ValueError, OverflowError) as error:
        raise SbomError(f"SBOM creation timestamp is invalid: {created!r}") from error
    expected, expected_coverage = build_documents(
        options.source_root,
        parse_artifacts(options.artifact),
        options.system_package,
        epoch,
    )
    require(actual_bytes == canonical_json(expected), "SBOM does not reproduce from the declared public inputs")
    require(coverage_bytes == canonical_json(expected_coverage), "SBOM coverage report does not reproduce")
    require(coverage.get("result") == "pass" and coverage.get("sbom_sha256") == digest_bytes(actual_bytes), "SBOM coverage binding is invalid")
    print(f"verified {coverage['sbom_sha256']} files={coverage['file_count']} packages={coverage['package_count']}")


def add_inputs(command: argparse.ArgumentParser) -> None:
    command.add_argument("--source-root", required=True, type=Path)
    command.add_argument("--artifact", action="append", default=[], metavar="ROLE=PATH")
    command.add_argument(
        "--system-package",
        action="append",
        default=[],
        metavar="TARGET|NAME|VERSION",
    )


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(description=__doc__)
    subcommands = command.add_subparsers(dest="command", required=True)
    build = subcommands.add_parser("build", help="emit deterministic SPDX and coverage JSON")
    add_inputs(build)
    build.add_argument("--out", required=True, type=Path)
    build.add_argument("--coverage-out", required=True, type=Path)
    build.add_argument("--epoch", type=int, default=int(os.environ.get("SOURCE_DATE_EPOCH", "0")))
    verify = subcommands.add_parser("verify", help="strictly reproduce and compare SPDX and coverage JSON")
    add_inputs(verify)
    verify.add_argument("--sbom", required=True, type=Path)
    verify.add_argument("--coverage", required=True, type=Path)
    return command


def main(arguments: list[str] | None = None) -> int:
    options = parser().parse_args(arguments)
    try:
        if options.command == "build":
            write_documents(options)
        else:
            verify_documents(options)
        return 0
    except SbomError as error:
        print(f"r4-sbom: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
