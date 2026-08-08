#!/usr/bin/env python3
"""Rebuild all 22 factory components and compare exact published bytes.

This independent-builder tool consumes a public source snapshot and an already
signed package.  It never accepts a certifier private key.  The package's
composition evidence supplies the authoritative node-to-digest map; every
freshly compiled Wasm Component must match that map and the retained bytes.
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
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.9/3.10 on otherwise supported macOS hosts.
    sys.path.insert(0, str(Path(__file__).resolve().parent / "_vendor"))
    import tomli as tomllib


SCHEMA = "wasm-biotic.r4-component-reproduction.v1"
CERTIFICATE_SCHEMA = "wasm-biotic.release-certification.v1"
CERTIFICATE_STATEMENT_SCHEMA = "wasm-biotic.release-certification-statement.v1"
PACKAGE_SCHEMA = "wasm-biotic.component-graph-package.v1"
PACKAGE_SIGNING_PAYLOAD_SCHEMA = "wasm-biotic.release-certification-signing-payload.v1"
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
PUBLIC_KEY_RE = re.compile(r"[0-9a-f]{64}\Z")
SIGNATURE_RE = re.compile(r"[0-9a-f]{128}\Z")
WITNESS_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
EXPECTED_NODES = frozenset(
    {
        "admitted-tool-probe",
        "build-service",
        "builder-worker",
        "capability-router",
        "closure-evaluator",
        "continuity-service",
        "continuity-worker",
        "exchange-service",
        "factory-control",
        "factory-evolution",
        "operations-service",
        "packager-worker",
        "packaging-service",
        "planner-worker",
        "review-service",
        "reviewer-worker",
        "scheduling-service",
        "state-migration",
        "supervisor-reducer",
        "validation-service",
        "validator-worker",
        "worker-router",
    }
)
EXPECTED_NODE_COUNT = len(EXPECTED_NODES)
FROZEN_SOURCE_ROOT = "/Users/jacobsullivan/Desktop/wasm-biotic"
FROZEN_CARGO_HOME = "/tmp/wasmbiotic-cargo"
FROZEN_RUSTUP_HOME = "/tmp/wasmbiotic-rustup"
R3_VENDOR_LOGICAL_PREFIX = "/tmp/wasmbiotic-cargo/registry/src/index.crates.io-1949cf8c6b5b557f"
PATH_ALIAS_SCHEMA = "wasm-biotic.r4-read-only-path-alias.v1"
PATH_ALIAS_SOURCE_NAME = "r4-path-alias.c"
PATH_ALIAS_LAUNCHER_SOURCE_NAME = "r4-path-alias-launch.c"
SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
REGISTRY_METADATA_FILES = frozenset(
    {
        ".cargo-checksum.json",
        ".cargo-ok",
        ".cargo_vcs_info.json",
        ".gitattributes",
        ".gitignore",
    }
)
WORKER_NODES = frozenset(
    {
        "builder-worker",
        "continuity-worker",
        "packager-worker",
        "planner-worker",
        "reviewer-worker",
        "validator-worker",
    }
)


class ReproductionError(RuntimeError):
    """The public source build did not reproduce the signed component bytes."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReproductionError(message)


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


def read_json(
    path: Path,
    label: str,
    *,
    canonical: bool = False,
) -> tuple[dict[str, Any], bytes]:
    try:
        information = path.lstat()
        require(stat.S_ISREG(information.st_mode) and not stat.S_ISLNK(information.st_mode), f"{label} is not a regular file")
        data = path.read_bytes()
        value = json.loads(data, object_pairs_hook=reject_duplicate_keys)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReproductionError(f"cannot read {label} at {path}: {error}") from error
    require(isinstance(value, dict), f"{label} must be a JSON object")
    if canonical:
        require(canonical_json(value) == data, f"{label} is not canonical JSON")
    return value, data


def command_output(
    arguments: list[str],
    label: str,
    directory: Path | None = None,
    environment: dict[str, str] | None = None,
) -> str:
    try:
        result = subprocess.run(
            arguments,
            cwd=directory,
            env=environment,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ReproductionError(f"cannot inspect {label}: {error}") from error
    return result.stdout.strip()


def verify_ed25519(public_key: bytes, payload: bytes, signature: bytes) -> None:
    executable = shutil.which("openssl")
    require(executable is not None, "openssl is required for package authentication")
    with tempfile.TemporaryDirectory(prefix="wasm-biotic-r4-package-signature-") as temporary:
        root = Path(temporary)
        public_path = root / "public.der"
        payload_path = root / "payload.bin"
        signature_path = root / "signature.bin"
        public_path.write_bytes(SPKI_PREFIX + public_key)
        payload_path.write_bytes(payload)
        signature_path.write_bytes(signature)
        try:
            result = subprocess.run(
                [
                    executable,
                    "pkeyutl",
                    "-verify",
                    "-pubin",
                    "-inkey",
                    str(public_path),
                    "-keyform",
                    "DER",
                    "-rawin",
                    "-in",
                    str(payload_path),
                    "-sigfile",
                    str(signature_path),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=60,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise ReproductionError(f"cannot verify package signature: {error}") from error
    require(result.returncode == 0, "release certification signature verification failed")


def authenticate_package(package: Path, public_key_hex: str) -> tuple[dict[str, Any], dict[str, Any]]:
    require(PUBLIC_KEY_RE.fullmatch(public_key_hex) is not None, "public key must be raw lowercase Ed25519 hex")
    public_key = bytes.fromhex(public_key_hex)
    key_id = digest_bytes(public_key)
    certificate, certificate_bytes = read_json(
        package / "certification/release-certification.json",
        "release certification",
        canonical=True,
    )
    require(set(certificate) == {"certifier_key_id", "schema", "signature", "statement"}, "release certification fields are not closed")
    require(certificate["schema"] == CERTIFICATE_SCHEMA, "unsupported release certification schema")
    require(certificate["certifier_key_id"] == key_id, "release certification was not made by the supplied public key")
    signature = certificate["signature"]
    require(isinstance(signature, dict) and set(signature) == {"algorithm", "signature_hex"}, "release certification signature fields are not closed")
    require(signature["algorithm"] == "ed25519", "unsupported package signature algorithm")
    signature_hex = signature["signature_hex"]
    require(isinstance(signature_hex, str) and SIGNATURE_RE.fullmatch(signature_hex) is not None, "release certification signature is malformed")
    statement = certificate["statement"]
    require(isinstance(statement, dict), "release certification statement is not an object")
    require(statement.get("schema") == CERTIFICATE_STATEMENT_SCHEMA, "unsupported release certification statement schema")
    payload = canonical_json(
        {
            "certifier_key_id": key_id,
            "schema": PACKAGE_SIGNING_PAYLOAD_SCHEMA,
            "statement": statement,
        }
    )
    verify_ed25519(public_key, payload, bytes.fromhex(signature_hex))
    package_index, _ = read_json(package / "package.json", "package index", canonical=True)
    require(package_index.get("package_schema") == PACKAGE_SCHEMA, "unsupported package index schema")
    require(package_index.get("certification_digest") == digest_bytes(certificate_bytes), "package index does not bind its release certification")
    return statement, {
        "certification_sha256": digest_bytes(certificate_bytes),
        "certifier_key_id": key_id,
        "signature_verified": True,
    }


def expected_components(package: Path, public_key_hex: str) -> tuple[dict[str, str], str, dict[str, Any]]:
    statement, authentication = authenticate_package(package, public_key_hex)
    composition, _ = read_json(package / "evidence/composition.json", "composition evidence")
    require(composition.get("package_schema") == PACKAGE_SCHEMA, "unsupported composition package schema")
    require(composition.get("validated") is True, "package composition was not validated")
    raw = composition.get("raw_nodes")
    require(isinstance(raw, dict) and len(raw) == EXPECTED_NODE_COUNT, "composition evidence must name exactly 22 raw nodes")
    require(set(raw) == EXPECTED_NODES, "composition evidence raw nodes differ from the frozen R4 node set")
    components = package / "components"
    try:
        components_information = components.lstat()
        retained_entries = list(components.iterdir())
    except OSError as error:
        raise ReproductionError(f"cannot inspect published component closure: {error}") from error
    require(
        stat.S_ISDIR(components_information.st_mode) and not stat.S_ISLNK(components_information.st_mode),
        "published component closure is not a regular directory",
    )
    for entry in retained_entries:
        information = entry.lstat()
        require(
            stat.S_ISREG(information.st_mode) and not stat.S_ISLNK(information.st_mode),
            f"published component closure contains a non-regular entry: {entry.name}",
        )
    expected: dict[str, str] = {}
    for node, digest in raw.items():
        require(isinstance(node, str) and node and node == node.lower(), f"invalid component node {node!r}")
        require(isinstance(digest, str) and DIGEST_RE.fullmatch(digest) is not None, f"invalid digest for component {node}")
        retained = components / f"sha256-{digest[7:]}.wasm"
        require(retained.is_file() and not retained.is_symlink(), f"published bytes are absent for {node}")
        require(digest_file(retained) == digest, f"published component bytes have the wrong digest for {node}")
        expected[node] = digest
    graph = composition.get("graph_manifest_digest")
    require(isinstance(graph, str) and DIGEST_RE.fullmatch(graph) is not None, "composition evidence has no graph digest")
    require(digest_file(package / "manifest.json") == graph, "package manifest differs from composition evidence")
    require(statement.get("graph_manifest_digest") == graph, "signed statement does not bind the graph manifest")
    require(statement.get("raw_artifacts") == expected, "signed statement raw artifacts differ from composition evidence")
    package_index, _ = read_json(package / "package.json", "package index", canonical=True)
    require(package_index.get("graph_manifest_digest") == graph, "package index does not bind the graph manifest")
    retained_names = {path.name for path in retained_entries}
    expected_names = {f"sha256-{digest[7:]}.wasm" for digest in expected.values()}
    require(retained_names == expected_names, "published raw component file closure differs from the signed node set")
    return dict(sorted(expected.items())), graph, authentication


def artifact_name(node: str) -> str:
    return "wasm_biotic_" + node.replace("-", "_") + ".wasm"


def build_group(node: str) -> str:
    if node in WORKER_NODES:
        return "workers"
    if node == "supervisor-reducer":
        return "supervisor"
    return "components"


def verify_source_snapshot(repository: Path) -> tuple[str, dict[str, Any], Any]:
    verifier_path = Path(__file__).with_name("r4-source-snapshot.py")
    require(verifier_path.is_file() and not verifier_path.is_symlink(), "trusted source snapshot verifier is absent")
    import importlib.util

    spec = importlib.util.spec_from_file_location("wasm_biotic_r4_source_snapshot", verifier_path)
    require(spec is not None and spec.loader is not None, "cannot load the source snapshot verifier")
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    try:
        identity, manifest = verifier.verify_snapshot(repository)
    except Exception as error:
        raise ReproductionError(f"source snapshot verification failed: {error}") from error
    require(identity == digest_file(repository / "SOURCE-SNAPSHOT.json"), "source verifier returned a different snapshot identity")
    return identity, manifest, verifier


def identity_fields(lines: list[str]) -> dict[str, str]:
    output: dict[str, str] = {}
    if lines:
        output["version_line"] = lines[0]
    for line in lines[1:]:
        key, separator, value = line.partition(": ")
        if separator:
            output[key] = value
    return output


def frozen_environment() -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if key
        not in {
            "CARGO_ENCODED_RUSTFLAGS",
            "DYLD_INSERT_LIBRARIES",
            "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER",
            "RUSTFLAGS",
            "WASM_BIOTIC_R4_ALIAS_LIBRARY",
            "WASM_BIOTIC_R4_ALIAS_TRACE",
            "WASM_BIOTIC_R4_PHYSICAL_ROOT",
        }
    }
    environment["CARGO_HOME"] = FROZEN_CARGO_HOME
    environment["RUSTUP_HOME"] = FROZEN_RUSTUP_HOME
    environment["CARGO_INCREMENTAL"] = "0"
    environment["CARGO_NET_OFFLINE"] = "true"
    return environment


def inspect_builder(source_manifest: dict[str, Any], directory: Path) -> dict[str, Any]:
    require(platform.system() == "Darwin" and platform.machine() == "arm64", "signed R3 component bytes require the frozen aarch64-apple-darwin builder host")
    cargo = Path(FROZEN_CARGO_HOME) / "bin/cargo"
    rustc = Path(FROZEN_CARGO_HOME) / "bin/rustc"
    require(cargo.is_file(), f"frozen Cargo executable is absent: {cargo}")
    require(rustc.is_file(), f"frozen rustc executable is absent: {rustc}")
    environment = frozen_environment()
    rustc_lines = command_output([str(rustc), "-vV"], "frozen rustc", directory, environment).splitlines()
    cargo_lines = command_output([str(cargo), "-Vv"], "frozen Cargo", directory, environment).splitlines()
    expected_toolchain = source_manifest.get("toolchain")
    require(isinstance(expected_toolchain, dict), "source snapshot has no toolchain identity")
    expected_rustc = identity_fields(expected_toolchain.get("rustc", []))
    observed_rustc = identity_fields(rustc_lines)
    for field in ("version_line", "commit-hash", "release", "LLVM version"):
        require(observed_rustc.get(field) == expected_rustc.get(field), f"builder rustc {field} differs from the source snapshot")
    expected_cargo = identity_fields(expected_toolchain.get("cargo", []))
    observed_cargo = identity_fields(cargo_lines)
    for field in ("version_line", "commit-hash", "release"):
        require(observed_cargo.get(field) == expected_cargo.get(field), f"builder Cargo {field} differs from the source snapshot")
    target_libdir = command_output(
        [str(rustc), "--print", "target-libdir", "--target", "wasm32-wasip2"],
        "frozen Wasm target",
        directory,
        environment,
    )
    require(Path(target_libdir).is_dir(), "frozen wasm32-wasip2 standard library is absent")
    return {
        "cargo": cargo_lines,
        "cargo_executable": str(cargo),
        "host": "aarch64-apple-darwin",
        "rustc": rustc_lines,
        "rustc_executable": str(rustc),
        "wasm_target_libdir": target_libdir,
    }


def projection_inventory(root: Path, verifier: Any) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for path in verifier.selected_source_files(root):
        relative = path.relative_to(root).as_posix()
        if not (relative.startswith("components/") or relative.startswith("wit/")):
            continue
        output.append(
            {
                "mode": f"{verifier.normalized_mode(path):04o}",
                "path": relative,
                "sha256": digest_file(path),
                "size_bytes": path.stat().st_size,
            }
        )
    return output


def file_tree_inventory(root: Path) -> dict[str, str]:
    output: dict[str, str] = {}
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix().encode("utf-8")):
        information = path.lstat()
        require(not stat.S_ISLNK(information.st_mode), f"registry projection contains a link: {path}")
        require(
            stat.S_ISDIR(information.st_mode) or stat.S_ISREG(information.st_mode),
            f"registry projection contains a special entry: {path}",
        )
        if stat.S_ISDIR(information.st_mode):
            continue
        relative = path.relative_to(root).as_posix()
        if path.name in REGISTRY_METADATA_FILES:
            continue
        output[relative] = digest_file(path)
    return output


def registry_packages(snapshot: Path) -> list[str]:
    names: set[str] = set()
    for relative in (
        "components/Cargo.lock",
        "components/workers/Cargo.lock",
        "components/supervisor-reducer/Cargo.lock",
    ):
        try:
            value = tomllib.loads((snapshot / relative).read_text(encoding="utf-8"))
        except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
            raise ReproductionError(f"cannot parse frozen component lockfile {relative}: {error}") from error
        packages = value.get("package", [])
        require(isinstance(packages, list), f"component lockfile {relative} has no package array")
        for item in packages:
            require(isinstance(item, dict), f"component lockfile {relative} has a malformed package")
            if not str(item.get("source", "")).startswith("registry+"):
                continue
            name = item.get("name")
            version = item.get("version")
            require(isinstance(name, str) and isinstance(version, str), f"component lockfile {relative} package has no name/version")
            require("/" not in name and "\\" not in name and "/" not in version and "\\" not in version, "unsafe registry package identity")
            names.add(f"{name}-{version}")
    return sorted(names, key=lambda value: value.encode("utf-8"))


def verify_frozen_projection(snapshot: Path, verifier: Any) -> dict[str, Any]:
    expected_source = projection_inventory(snapshot, verifier)
    registry = Path(R3_VENDOR_LOGICAL_PREFIX)
    require(registry.is_dir() and not registry.is_symlink(), "frozen Cargo registry projection is absent")
    packages = registry_packages(snapshot)
    rows = bytearray()
    for package in packages:
        expected = snapshot / "vendor" / package
        observed = registry / package
        require(expected.is_dir() and not expected.is_symlink(), f"snapshot vendor package is absent: {package}")
        require(observed.is_dir() and not observed.is_symlink(), f"frozen registry package is absent: {package}")
        expected_inventory = file_tree_inventory(expected)
        observed_inventory = file_tree_inventory(observed)
        require(observed_inventory == expected_inventory, f"frozen registry package differs from the snapshot vendor tree: {package}")
        rows.extend(canonical_json({"files": expected_inventory, "package": package}) + b"\n")
    return {
        "cargo_registry_package_count": len(packages),
        "cargo_registry_projection_sha256": digest_bytes(bytes(rows)),
        "source_file_count": len(expected_source),
        "source_projection_sha256": digest_bytes(canonical_json(expected_source)),
    }


def sandbox_literal(path: Path | str) -> str:
    value = os.fspath(path)
    require("\x00" not in value and "\n" not in value and "\r" not in value, "sandbox path contains forbidden characters")
    return json.dumps(value, ensure_ascii=False)


def sandbox_profile(physical_source: Path | None = None) -> str:
    physical = physical_source or Path(FROZEN_SOURCE_ROOT)
    return (
        '(version 1)(allow default)'
        '(deny network*)'
        f'(deny file-read* (subpath {sandbox_literal(FROZEN_SOURCE_ROOT)}))'
        f'(deny file-write* (subpath {sandbox_literal(physical)}))'
        f'(deny file-write* (subpath {sandbox_literal(FROZEN_SOURCE_ROOT)}))'
        f'(deny file-write* (subpath {sandbox_literal(FROZEN_CARGO_HOME)}))'
        f'(deny file-write* (subpath {sandbox_literal(FROZEN_RUSTUP_HOME)}))'
    )


def compile_operator_alias(
    output: Path,
    physical_source: Path,
    profile: str,
) -> tuple[Path, Path, dict[str, Any]]:
    source_root = Path(__file__).resolve(strict=True).parent
    alias_source = source_root / PATH_ALIAS_SOURCE_NAME
    launcher_source = source_root / PATH_ALIAS_LAUNCHER_SOURCE_NAME
    for path, label in ((alias_source, "path-alias source"), (launcher_source, "path-alias launcher source")):
        try:
            information = path.lstat()
        except OSError as error:
            raise ReproductionError(f"cannot inspect {label}: {error}") from error
        require(
            stat.S_ISREG(information.st_mode) and not stat.S_ISLNK(information.st_mode),
            f"{label} is not a regular file",
        )
    xcrun = shutil.which("xcrun")
    require(xcrun is not None, "xcrun is required to compile the public R4 path alias")
    clang_text = command_output([xcrun, "--find", "clang"], "Apple clang", output.parent)
    clang = Path(clang_text)
    require(clang.is_absolute() and clang.is_file(), "xcrun returned no usable clang executable")
    output.mkdir(parents=True)
    dylib = output / "r4-path-alias.dylib"
    launcher = output / "r4-path-alias-launch"
    common = ["-Wall", "-Wextra", "-Werror", "-O2"]
    commands = [
        [xcrun, "clang", *common, "-dynamiclib", "-o", str(dylib), str(alias_source)],
        [xcrun, "clang", *common, "-o", str(launcher), str(launcher_source)],
    ]
    environment = frozen_environment()
    for name in ("CPATH", "C_INCLUDE_PATH", "LIBRARY_PATH", "MACOSX_DEPLOYMENT_TARGET", "SDKROOT"):
        environment.pop(name, None)
    environment["LC_ALL"] = "C"
    for index, arguments in enumerate(commands, 1):
        try:
            subprocess.run(
                arguments,
                cwd=output,
                env=environment,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=120,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise ReproductionError(f"cannot compile R4 path-alias artifact {index}: {error}") from error
    for path, label in ((dylib, "path-alias dylib"), (launcher, "path-alias launcher")):
        information = path.lstat()
        require(stat.S_ISREG(information.st_mode) and not stat.S_ISLNK(information.st_mode), f"{label} is not a regular file")
        require(path.read_bytes()[:4] == bytes.fromhex("cffaedfe"), f"{label} is not a 64-bit Mach-O file")
    require(launcher.stat().st_mode & stat.S_IXUSR != 0, "path-alias launcher is not executable")
    recipe = {
        "dylib": ["xcrun", "clang", *common, "-dynamiclib", "-o", "r4-path-alias.dylib", f"tools/{PATH_ALIAS_SOURCE_NAME}"],
        "launcher": ["xcrun", "clang", *common, "-o", "r4-path-alias-launch", f"tools/{PATH_ALIAS_LAUNCHER_SOURCE_NAME}"],
    }
    information = {
        "artifacts": {
            "dylib": {
                "sha256": digest_file(dylib),
                "size_bytes": dylib.stat().st_size,
            },
            "launcher": {
                "sha256": digest_file(launcher),
                "size_bytes": launcher.stat().st_size,
            },
        },
        "build_recipe": recipe,
        "compiler": command_output([xcrun, "clang", "--version"], "path-alias compiler", output, environment).splitlines(),
        "compiler_executable": str(clang),
        "dyld_injected_after_sandbox_activation": True,
        "physical_source_root": str(physical_source),
        "read_fallback_to_historical_checkout_denied": True,
        "read_only_mapping": True,
        "sandbox_profile": profile,
        "sandbox_profile_sha256": digest_bytes(profile.encode("utf-8")),
        "schema": PATH_ALIAS_SCHEMA,
        "sources": {
            f"tools/{PATH_ALIAS_SOURCE_NAME}": digest_file(alias_source),
            f"tools/{PATH_ALIAS_LAUNCHER_SOURCE_NAME}": digest_file(launcher_source),
        },
        "virtual_source_root": FROZEN_SOURCE_ROOT,
    }
    return dylib, launcher, information


def run_builds(
    repository: Path,
    target_root: Path,
    dylib: Path,
    launcher: Path,
    profile: str,
) -> None:
    require(target_root.is_dir(), f"fresh target root is absent: {target_root}")
    for group in ("components", "workers", "supervisor"):
        require(not (target_root / group).exists(), f"fresh build group already exists: {group}")
    sandbox = shutil.which("sandbox-exec")
    require(sandbox is not None, "sandbox-exec is required to protect the frozen source and toolchain projections")
    cargo = str(Path(FROZEN_CARGO_HOME) / "bin/cargo")
    environment = frozen_environment()
    environment["WASM_BIOTIC_R4_ALIAS_LIBRARY"] = str(dylib)
    environment["WASM_BIOTIC_R4_PHYSICAL_ROOT"] = str(repository)
    common = ["--locked", "--offline", "--release", "--target", "wasm32-wasip2"]
    commands = [
        [
            cargo,
            "build",
            "--manifest-path",
            f"{FROZEN_SOURCE_ROOT}/components/Cargo.toml",
            "--workspace",
            "--exclude",
            "wasm-biotic-worker-router",
            *common,
            "--target-dir",
            str(target_root / "components"),
        ],
        [
            cargo,
            "build",
            "--manifest-path",
            f"{FROZEN_SOURCE_ROOT}/components/Cargo.toml",
            "-p",
            "wasm-biotic-worker-router",
            *common,
            "--target-dir",
            str(target_root / "components"),
        ],
        [
            cargo,
            "build",
            "--manifest-path",
            f"{FROZEN_SOURCE_ROOT}/components/workers/Cargo.toml",
            *sum((["-p", f"wasm-biotic-{node}"] for node in sorted(WORKER_NODES)), []),
            *common,
            "--target-dir",
            str(target_root / "workers"),
        ],
        [
            cargo,
            "build",
            "--manifest-path",
            f"{FROZEN_SOURCE_ROOT}/components/supervisor-reducer/Cargo.toml",
            *common,
            "--target-dir",
            str(target_root / "supervisor"),
        ],
    ]
    for index, arguments in enumerate(commands, 1):
        try:
            subprocess.run(
                [sandbox, "-p", profile, str(launcher), *arguments],
                cwd=launcher.parent,
                env=environment,
                check=True,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise ReproductionError(f"component build command {index} failed: {error}") from error


def compiled_path(target_root: Path, node: str) -> Path:
    return target_root / build_group(node) / "wasm32-wasip2" / "release" / artifact_name(node)


def compare_components(expected: dict[str, str], target_root: Path) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for node, digest in expected.items():
        path = compiled_path(target_root, node)
        require(path.is_file() and not path.is_symlink(), f"compiled component is absent for {node}: {path}")
        actual = digest_file(path)
        require(actual == digest, f"compiled component differs for {node}: expected {digest}, observed {actual}")
        results.append(
            {
                "node": node,
                "published_sha256": digest,
                "rebuilt_sha256": actual,
                "size_bytes": path.stat().st_size,
            }
        )
    return results


def component_set_digest(results: list[dict[str, Any]]) -> str:
    rows = "".join(f"{item['node']}  {item['rebuilt_sha256']}\n" for item in results)
    return digest_bytes(rows.encode("utf-8"))


def build_report(options: argparse.Namespace) -> dict[str, Any]:
    repository_argument = Path(os.path.abspath(os.fspath(options.repository)))
    package_argument = Path(os.path.abspath(os.fspath(options.package)))
    for path, label in ((repository_argument, "source snapshot"), (package_argument, "signed package")):
        try:
            information = path.lstat()
        except OSError as error:
            raise ReproductionError(f"cannot inspect {label}: {error}") from error
        require(
            stat.S_ISDIR(information.st_mode) and not stat.S_ISLNK(information.st_mode),
            f"{label} must be a regular directory",
        )
    repository = repository_argument.resolve(strict=True)
    package = package_argument.resolve(strict=True)
    require(WITNESS_RE.fullmatch(options.witness_id) is not None, "invalid physical witness identifier")
    source_identity, source_manifest, source_verifier = verify_source_snapshot(repository)
    expected, graph, package_authentication = expected_components(
        package,
        options.public_key_hex,
    )
    projection = verify_frozen_projection(repository, source_verifier)
    target_root = Path(os.path.abspath(os.fspath(options.target_root)))
    frozen_source = Path(FROZEN_SOURCE_ROOT)
    require(
        not repository.is_relative_to(frozen_source) and not frozen_source.is_relative_to(repository),
        "authenticated snapshot must be physically separate from the historical source path",
    )
    require(not target_root.is_relative_to(repository), "target root must be outside the authenticated source snapshot")
    require(not target_root.is_relative_to(package), "target root must be outside the signed package")
    require(not target_root.is_relative_to(frozen_source), "target root must be outside the frozen source projection")
    require(not target_root.is_relative_to(Path(FROZEN_CARGO_HOME)), "target root must be outside the frozen Cargo projection")
    require(not target_root.is_relative_to(Path(FROZEN_RUSTUP_HOME)), "target root must be outside the frozen Rustup projection")
    require(not target_root.exists(), f"fresh target root already exists: {target_root}")
    target_root.mkdir(parents=True)
    builder = inspect_builder(source_manifest, repository)
    profile = sandbox_profile(repository)
    dylib, launcher, path_alias = compile_operator_alias(target_root / "operator", repository, profile)
    run_builds(repository, target_root, dylib, launcher, profile)
    results = compare_components(expected, target_root)
    return {
        "build": {
            "builder": builder,
            "cargo": builder["cargo"],
            "frozen_read_only_path_projection": True,
            "fresh_target_directory": True,
            "incremental": False,
            "offline": True,
            "network_disabled": True,
            "operator_path_alias": path_alias,
            "registry_projection": R3_VENDOR_LOGICAL_PREFIX,
            "rustc": builder["rustc"],
            "source_projection": FROZEN_SOURCE_ROOT,
            "target": "wasm32-wasip2",
            "target_scoped_path_remapping": False,
            "verified_projection": projection,
        },
        "component_count": len(results),
        "component_set_sha256": component_set_digest(results),
        "components": results,
        "generated_at": dt.datetime.fromtimestamp(options.epoch, dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "graph_manifest_digest": graph,
        "host": {
            "architecture": platform.machine(),
            "operating_system": platform.system(),
            "physical_machine": True,
            "release": platform.release(),
            "witness_id": options.witness_id,
        },
        "package_authentication": package_authentication,
        "private_key_accepted_or_read": False,
        "published_raw_components_reproduced_byte_for_byte": True,
        "result": "pass",
        "schema": SCHEMA,
        "source_snapshot_manifest_sha256": source_identity,
    }


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(description=__doc__)
    command.add_argument("--repository", type=Path, required=True)
    command.add_argument("--package", type=Path, required=True)
    command.add_argument("--public-key-hex", required=True)
    command.add_argument("--target-root", type=Path, required=True)
    command.add_argument("--witness-id", required=True)
    command.add_argument("--epoch", type=int, default=0)
    command.add_argument("--out", type=Path, required=True)
    return command


def main(arguments: list[str] | None = None) -> int:
    options = parser().parse_args(arguments)
    try:
        report = build_report(options)
        options.out.parent.mkdir(parents=True, exist_ok=True)
        options.out.write_bytes(canonical_json(report))
        print(f"reproduced {report['component_set_sha256']} {options.out}")
        return 0
    except (ReproductionError, OSError, ValueError) as error:
        print(f"r4-component-reproduction: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
