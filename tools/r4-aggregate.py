#!/usr/bin/env python3
"""Build and verify the two-stage R4 reproduction matrix and aggregate.

The reproduction matrix is deliberately pre-publication evidence and can be a
content-addressed publication object without referring to its own future root.
The aggregate is deliberately post-publication evidence: it independently
verifies the signed publication, joins the retained matrix to its exact object
closure, applies post-signing negative controls, and only then closes R4-C0
through R4-C7.  This operator-side tool never accepts or reads a private key.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from typing import Any, NoReturn


MATRIX_INPUT_SCHEMA = "wasm-biotic.r4-reproduction-matrix-input.v1"
MATRIX_SCHEMA = "wasm-biotic.r4-reproduction-matrix.v1"
AGGREGATE_SCHEMA = "wasm-biotic.r4-release-aggregate.v1"
GOVERNANCE_REPORT_SCHEMA = "wasm-biotic.r4-governance-report.v1"
PREPUBLICATION_NEGATIVE_SCHEMA = "wasm-biotic.r4-prepublication-negative-controls.v1"
PUBLICATION_NEGATIVE_SCHEMA = "wasm-biotic.r4-publication-negative-controls.v1"
SOURCE_SNAPSHOT_SCHEMA = "wasm-biotic.r4-source-snapshot.v1"
COMPONENT_REPRODUCTION_SCHEMA = "wasm-biotic.r4-component-reproduction.v1"
NATIVE_REPRODUCTION_SCHEMA = "wasm-biotic.r4-native-build-reproducibility.v1"
SBOM_COVERAGE_SCHEMA = "wasm-biotic.sbom-coverage.v1"
PUBLIC_LIFECYCLE_SCHEMA = "wasm-biotic.r4-public-install-lifecycle.v1"
POSTPUBLICATION_RECOVERY_SCHEMA = "wasm-biotic.r4-postpublication-recovery.v1"

FROZEN_CONTRACT_DIGEST = (
    "sha256:6eff98aedd7d0047d6abe55b9d60d5bbabaa00b733e8df13d3a0fc3de9c96857"
)
CLOSED_TARGETS = ("aarch64-apple-darwin", "x86_64-unknown-linux-gnu")
MACOS_TARGET = "aarch64-apple-darwin"
LINUX_TARGET = "x86_64-unknown-linux-gnu"
EXPECTED_COMPONENT_COUNT = 22

DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
WITNESS_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
MAX_JSON_BYTES = 64 * 1024 * 1024

ARCHIVE_ROLES = (
    "component-release-archive",
    "install-archive",
    "source-archive",
)
GOVERNANCE_NEGATIVES = frozenset(
    {
        "cross_domain_rejected",
        "downgrade_rejected",
        "duplicate_signer_rejected",
        "fork_shape_rejected",
        "mixed_policy_rejected",
        "one_of_three_rejected",
        "replay_rejected",
        "revoked_signer_rejected",
        "successor_possession_required",
        "unknown_signer_rejected",
    }
)
ARCHIVE_NEGATIVES = frozenset(
    {
        "duplicate_rejected",
        "extra_rejected",
        "missing_rejected",
        "mutated_rejected",
        "noncanonical_rejected",
        "traversal_rejected",
        "truncated_rejected",
    }
)
SBOM_NEGATIVES = frozenset(
    {
        "omitted_file_rejected",
        "omitted_package_rejected",
        "phantom_file_rejected",
        "phantom_package_rejected",
        "wrong_digest_rejected",
    }
)
LIFECYCLE_NEGATIVES = frozenset(
    {
        "automatic_activation_rejected",
        "private_key_argument_absent",
        "tampered_package_rejected",
        "wrong_key_rejected",
    }
)
PUBLICATION_NEGATIVES = frozenset(
    {
        "claim_substitution_rejected",
        "extra_object_rejected",
        "missing_object_rejected",
        "mode_drift_rejected",
        "object_substitution_rejected",
        "platform_mismatch_rejected",
        "policy_substitution_rejected",
        "root_rename_rejected",
        "signature_tamper_rejected",
        "valid_signature_inventory_substitution_changed_root",
    }
)
LIFECYCLE_COMMANDS = frozenset(
    {
        "admit-inactive-successor",
        "admit-incumbent",
        "bootstrap-incumbent",
        "component-owned-upgrade-rollback-restart",
        "incumbent-remains-selected",
        "initialize-fresh-state",
        "initialize-tamper-state",
        "initialize-wrong-key-state",
        "reject-tampered-package",
        "reject-unselected-successor-serve",
        "reject-wrong-public-key",
    }
)


class AggregateError(RuntimeError):
    """R4 evidence is incomplete, inconsistent, circular, or failed."""


def fail(message: str) -> NoReturn:
    raise AggregateError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def _load_tool(filename: str, module_name: str) -> Any:
    path = Path(__file__).with_name(filename)
    specification = importlib.util.spec_from_file_location(module_name, path)
    if specification is None or specification.loader is None:
        fail(f"cannot load required R4 tool at {path}")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


ARCHIVE = _load_tool("r4-install-archive.py", "wasm_biotic_r4_archive")
PUBLICATION = _load_tool("r4-publication.py", "wasm_biotic_r4_publication")
CEREMONY = _load_tool("r4-governance-ceremony.py", "wasm_biotic_r4_ceremony")
SOURCE_SNAPSHOT = _load_tool("r4-source-snapshot.py", "wasm_biotic_r4_source_snapshot")
SBOM_TOOL = _load_tool("r4-sbom.py", "wasm_biotic_r4_sbom")
PUBLIC_INSTALL = _load_tool("r4-public-install.py", "wasm_biotic_r4_public_install")
PREPUBLICATION_NEGATIVES = _load_tool(
    "r4-prepublication-negatives.py",
    "wasm_biotic_r4_prepublication_negatives",
)


def canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        fail(f"value cannot be represented as canonical JSON: {error}")


def digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def require_digest(value: Any, where: str) -> str:
    if not isinstance(value, str) or DIGEST_RE.fullmatch(value) is None:
        fail(f"{where} must be a lowercase sha256: digest")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            fail(f"JSON contains duplicate key {key!r}")
        output[key] = value
    return output


def _reject_numeric_constant(value: str) -> NoReturn:
    fail(f"JSON contains forbidden numeric constant {value}")


def _reject_floats(value: Any, where: str) -> None:
    if isinstance(value, float):
        fail(f"{where} contains a floating-point value")
    if isinstance(value, dict):
        for key, item in value.items():
            _reject_floats(item, f"{where}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_floats(item, f"{where}[{index}]")


def parse_canonical_object(data: bytes, where: str) -> dict[str, Any]:
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_numeric_constant,
        )
    except AggregateError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{where} is not valid UTF-8 JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{where} must be a JSON object")
    _reject_floats(value, where)
    if canonical_json(value) != data:
        fail(f"{where} is not canonical JSON")
    return value


def read_regular(path: Path, where: str, *, maximum: int | None = None) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        fail(f"cannot open {where} as a regular file at {path}: {error}")
    try:
        information = os.fstat(descriptor)
        if not stat.S_ISREG(information.st_mode):
            fail(f"{where} must be a regular file and not a link: {path}")
        if maximum is not None and information.st_size > maximum:
            fail(f"{where} exceeds the {maximum}-byte limit")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            return stream.read()
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def read_canonical(path: Path, where: str) -> tuple[dict[str, Any], bytes]:
    data = read_regular(path, where, maximum=MAX_JSON_BYTES)
    return parse_canonical_object(data, where), data


def require_fields(value: Any, fields: set[str], where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{where} must be an object")
    actual = set(value)
    if actual != fields:
        fail(
            f"{where} has missing fields {sorted(fields - actual)} and "
            f"unknown fields {sorted(actual - fields)}"
        )
    return value


def require_nonempty_string(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value:
        fail(f"{where} must be a non-empty string")
    return value


def require_witness(value: Any, where: str) -> str:
    value = require_nonempty_string(value, where)
    if WITNESS_RE.fullmatch(value) is None:
        fail(f"{where} is not a canonical physical witness identifier")
    return value


def require_positive_integer(value: Any, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        fail(f"{where} must be a positive integer")
    return value


def require_empty_blockers(value: Any, where: str) -> None:
    if not isinstance(value, list) or value:
        fail(f"{where} must be an empty blocker array")


def require_true_controls(
    value: Any, keys: frozenset[str], where: str
) -> dict[str, bool]:
    controls = require_fields(value, set(keys), where)
    failed = sorted(key for key in keys if controls[key] is not True)
    if failed:
        fail(f"{where} has failed or unexecuted controls {failed}")
    return controls


def validate_runtime_dependencies(value: Any, where: str) -> list[dict[str, str]]:
    """Validate the portable, path-free runtime dependency inventory."""

    require(isinstance(value, list) and value, f"{where} must be a non-empty array")
    dependencies: list[dict[str, str]] = []
    for index, raw in enumerate(value):
        item = require_fields(raw, {"name", "version"}, f"{where}[{index}]")
        dependencies.append(
            {
                "name": require_nonempty_string(item["name"], f"{where}[{index}].name"),
                "version": require_nonempty_string(
                    item["version"], f"{where}[{index}].version"
                ),
            }
        )
    expected = sorted(dependencies, key=lambda item: (item["name"], item["version"]))
    require(dependencies == expected, f"{where} is not sorted by name and version")
    names = [item["name"] for item in dependencies]
    require(
        len(names) == len(set(names)), f"{where} contains duplicate dependency names"
    )
    return dependencies


def validate_system_packages(value: Any, where: str) -> list[dict[str, str]]:
    """Validate and normalize SBOM target/name/version system-package rows."""

    require(isinstance(value, list) and value, f"{where} must be a non-empty array")
    packages: list[dict[str, str]] = []
    for index, raw in enumerate(value):
        item = require_fields(raw, {"name", "target", "version"}, f"{where}[{index}]")
        target = require_nonempty_string(item["target"], f"{where}[{index}].target")
        require(target in CLOSED_TARGETS, f"{where}[{index}] target is outside R4")
        packages.append(
            {
                "name": require_nonempty_string(item["name"], f"{where}[{index}].name"),
                "target": target,
                "version": require_nonempty_string(
                    item["version"], f"{where}[{index}].version"
                ),
            }
        )
    identities = [(item["target"], item["name"]) for item in packages]
    require(
        len(identities) == len(set(identities)),
        f"{where} contains duplicate target/name identities",
    )
    return sorted(
        packages, key=lambda item: (item["target"], item["name"], item["version"])
    )


def _path(raw: Any, base: Path, where: str) -> Path:
    value = require_nonempty_string(raw, where)
    path = Path(value)
    if not path.is_absolute():
        path = base / path
    try:
        information = path.lstat()
    except OSError as error:
        fail(f"cannot inspect {where} at {path}: {error}")
    if stat.S_ISLNK(information.st_mode) or not stat.S_ISREG(information.st_mode):
        fail(f"{where} must be a regular file and not a link: {path}")
    return path


def _directory(raw: Any, base: Path, where: str) -> Path:
    value = require_nonempty_string(raw, where)
    path = Path(value)
    if not path.is_absolute():
        path = base / path
    try:
        information = path.lstat()
    except OSError as error:
        fail(f"cannot inspect {where} at {path}: {error}")
    if stat.S_ISLNK(information.st_mode) or not stat.S_ISDIR(information.st_mode):
        fail(f"{where} must be a directory and not a link: {path}")
    return path


def _validate_source_snapshot(path: Path) -> dict[str, Any]:
    report, data = read_canonical(path, "source snapshot manifest")
    require_fields(
        report,
        {
            "cargo_lock_count",
            "cargo_locks",
            "cargo_manifest_count",
            "cargo_manifests",
            "dependency_delivery",
            "schema",
            "selection",
            "source_closure_sha256",
            "source_file_count",
            "toolchain",
            "vendor_closure_sha256",
            "vendor_file_count",
        },
        "source snapshot manifest",
    )
    require(
        report["schema"] == SOURCE_SNAPSHOT_SCHEMA, "source snapshot schema differs"
    )
    require(
        report["dependency_delivery"]
        == "complete Cargo registry source vendoring; no registry access required",
        "source snapshot does not require complete offline vendoring",
    )
    for name in (
        "cargo_lock_count",
        "cargo_manifest_count",
        "source_file_count",
        "vendor_file_count",
    ):
        require_positive_integer(report[name], f"source snapshot.{name}")
    for count_name, inventory_name in (
        ("cargo_lock_count", "cargo_locks"),
        ("cargo_manifest_count", "cargo_manifests"),
    ):
        inventory = report[inventory_name]
        require(
            isinstance(inventory, list) and len(inventory) == report[count_name],
            f"source snapshot {inventory_name} count differs",
        )
    source_closure = require_digest(
        report["source_closure_sha256"], "source snapshot source closure"
    )
    vendor_closure = require_digest(
        report["vendor_closure_sha256"], "source snapshot vendor closure"
    )
    selection = report["selection"]
    require(
        isinstance(selection, dict)
        and selection.get("native_substrate") == "kernel"
        and selection.get("component_factory") == "components"
        and selection.get("interfaces") == "wit/wasm-biotic"
        and selection.get("normative_contract") == "contracts/component-complete",
        "source snapshot selection does not preserve the component/native boundary",
    )
    toolchain = require_fields(
        report["toolchain"],
        {"cargo", "rustc", "wasm_target", "wasm_tools"},
        "source snapshot toolchain",
    )
    require(
        isinstance(toolchain["cargo"], list)
        and bool(toolchain["cargo"])
        and all(isinstance(item, str) and item for item in toolchain["cargo"])
        and isinstance(toolchain["rustc"], list)
        and bool(toolchain["rustc"])
        and all(isinstance(item, str) and item for item in toolchain["rustc"])
        and toolchain["wasm_target"] == "wasm32-wasip2"
        and isinstance(toolchain["wasm_tools"], str)
        and bool(toolchain["wasm_tools"]),
        "source snapshot toolchain identity differs",
    )
    return {
        "manifest_sha256": digest_bytes(data),
        "source_closure_sha256": source_closure,
        "source_file_count": report["source_file_count"],
        "toolchain": toolchain,
        "vendor_closure_sha256": vendor_closure,
        "vendor_file_count": report["vendor_file_count"],
    }


def _verify_archive(path: Path, role: str) -> dict[str, Any]:
    try:
        digest, manifest, manifest_bytes = ARCHIVE.verify_archive(path)
    except Exception as error:
        fail(f"{role} did not pass deterministic archive verification: {error}")
    return {
        "entry_count": manifest["entry_count"],
        "manifest_sha256": digest_bytes(manifest_bytes),
        "sha256": require_digest(digest, f"{role} digest"),
        "total_file_size_bytes": manifest["total_file_size_bytes"],
    }


def _publicly_verify_source_archive(path: Path, expected_manifest_sha256: str) -> None:
    with tempfile.TemporaryDirectory(prefix="r4-source-verify-") as temporary:
        extracted = Path(temporary) / "source"
        try:
            ARCHIVE.extract_archive(path, extracted)
            manifest_sha256, _ = SOURCE_SNAPSHOT.verify_snapshot(extracted)
        except Exception as error:
            fail(f"source archive did not publicly reproduce its closure: {error}")
        require(
            manifest_sha256 == expected_manifest_sha256,
            "public source verifier returned a different snapshot manifest",
        )


def _component_set_digest(components: list[dict[str, Any]]) -> str:
    rows = "".join(f"{item['node']}  {item['rebuilt_sha256']}\n" for item in components)
    return digest_bytes(rows.encode("utf-8"))


def _canonical_tmp_path(path: Path) -> Path:
    """Resolve a retained POSIX path while normalizing macOS' /tmp alias."""

    resolved = path.resolve(strict=False)
    value = resolved.as_posix()
    if value == "/private/tmp" or value.startswith("/private/tmp/"):
        value = "/tmp" + value[len("/private/tmp") :]
    return Path(value)


def _validate_component_report(
    path: Path, source_toolchain: dict[str, Any], source_root: Path
) -> dict[str, Any]:
    report, data = read_canonical(path, "component reproduction report")
    require(
        report.get("schema") == COMPONENT_REPRODUCTION_SCHEMA,
        "component reproduction schema differs",
    )
    require(report.get("result") == "pass", "component reproduction did not pass")
    require(
        report.get("private_key_accepted_or_read") is False,
        "component reproduction depended on a private key",
    )
    require(
        report.get("published_raw_components_reproduced_byte_for_byte") is True,
        "component bytes did not reproduce",
    )
    require(
        report.get("component_count") == EXPECTED_COMPONENT_COUNT,
        "component reproduction count is not 22",
    )
    components = report.get("components")
    require(
        isinstance(components, list) and len(components) == EXPECTED_COMPONENT_COUNT,
        "component comparison inventory is not 22/22",
    )
    nodes: list[str] = []
    for index, item in enumerate(components):
        require(
            isinstance(item, dict), f"component comparison {index} is not an object"
        )
        node = require_nonempty_string(
            item.get("node"), f"component comparison {index}.node"
        )
        published = require_digest(
            item.get("published_sha256"), f"component {node} published digest"
        )
        rebuilt = require_digest(
            item.get("rebuilt_sha256"), f"component {node} rebuilt digest"
        )
        require(published == rebuilt, f"component {node} was not byte-identical")
        require_positive_integer(item.get("size_bytes"), f"component {node} size")
        nodes.append(node)
    require(nodes == sorted(nodes), "component comparisons are not sorted by node")
    require(len(nodes) == len(set(nodes)), "component comparison nodes are duplicated")
    expected_set = _component_set_digest(components)
    require(
        report.get("component_set_sha256") == expected_set,
        "component-set digest does not match its 22 comparisons",
    )
    build = require_fields(
        report.get("build"),
        {
            "builder",
            "cargo",
            "frozen_read_only_path_projection",
            "fresh_target_directory",
            "incremental",
            "network_disabled",
            "offline",
            "operator_path_alias",
            "registry_projection",
            "rustc",
            "source_projection",
            "target",
            "target_scoped_path_remapping",
            "verified_projection",
        },
        "component reproduction build",
    )
    require(
        build["target"] == "wasm32-wasip2"
        and build.get("fresh_target_directory") is True
        and build.get("incremental") is False
        and build.get("offline") is True
        and build.get("network_disabled") is True
        and build.get("frozen_read_only_path_projection") is True
        and build.get("target_scoped_path_remapping") is False
        and build.get("source_projection")
        == PUBLICATION.COMPONENT_REPRODUCTION.FROZEN_SOURCE_ROOT
        and build.get("registry_projection")
        == PUBLICATION.COMPONENT_REPRODUCTION.R3_VENDOR_LOGICAL_PREFIX,
        "component reproduction did not use the frozen offline read-only projection",
    )
    builder = require_fields(
        build["builder"],
        {
            "cargo",
            "cargo_executable",
            "host",
            "rustc",
            "rustc_executable",
            "wasm_target_libdir",
        },
        "component reproduction builder",
    )
    wasm_target_libdir = builder["wasm_target_libdir"]
    wasm_target_path = (
        _canonical_tmp_path(Path(wasm_target_libdir))
        if isinstance(wasm_target_libdir, str)
        and bool(wasm_target_libdir)
        and Path(wasm_target_libdir).is_absolute()
        else None
    )
    frozen_rustup_root = _canonical_tmp_path(
        Path(PUBLICATION.COMPONENT_REPRODUCTION.FROZEN_RUSTUP_HOME)
    )
    require(
        builder["host"] == "aarch64-apple-darwin"
        and builder["cargo_executable"]
        == PUBLICATION.COMPONENT_REPRODUCTION.FROZEN_CARGO_HOME + "/bin/cargo"
        and builder["rustc_executable"]
        == PUBLICATION.COMPONENT_REPRODUCTION.FROZEN_CARGO_HOME + "/bin/rustc"
        and wasm_target_path is not None
        and wasm_target_path.is_relative_to(frozen_rustup_root)
        and wasm_target_path.parts[-2:] == ("wasm32-wasip2", "lib")
        and build["cargo"] == builder["cargo"] == source_toolchain.get("cargo")
        and build["rustc"] == builder["rustc"] == source_toolchain.get("rustc")
        and source_toolchain.get("wasm_target") == "wasm32-wasip2",
        "component reproduction builder/toolchain differs from the frozen source snapshot",
    )
    projection = require_fields(
        build["verified_projection"],
        {
            "cargo_registry_package_count",
            "cargo_registry_projection_sha256",
            "source_file_count",
            "source_projection_sha256",
        },
        "component verified projection",
    )
    require_positive_integer(
        projection["cargo_registry_package_count"],
        "component Cargo registry package count",
    )
    require_positive_integer(
        projection["source_file_count"], "component projection source file count"
    )
    require_digest(
        projection["cargo_registry_projection_sha256"],
        "component Cargo registry projection",
    )
    require_digest(
        projection["source_projection_sha256"], "component source projection"
    )
    alias = require_fields(
        build["operator_path_alias"],
        {
            "artifacts",
            "build_recipe",
            "compiler",
            "compiler_executable",
            "dyld_injected_after_sandbox_activation",
            "physical_source_root",
            "read_fallback_to_historical_checkout_denied",
            "read_only_mapping",
            "sandbox_profile",
            "sandbox_profile_sha256",
            "schema",
            "sources",
            "virtual_source_root",
        },
        "component operator path alias",
    )
    require(
        alias["schema"] == PUBLICATION.COMPONENT_REPRODUCTION.PATH_ALIAS_SCHEMA,
        "component operator path-alias schema differs",
    )
    physical_source_root = require_nonempty_string(
        alias["physical_source_root"], "component path-alias physical source root"
    )
    resolved_source_root = source_root.resolve()
    physical_path = Path(physical_source_root)
    require(
        physical_path.is_absolute()
        and physical_path == resolved_source_root
        and alias["virtual_source_root"]
        == PUBLICATION.COMPONENT_REPRODUCTION.FROZEN_SOURCE_ROOT
        and physical_source_root
        != PUBLICATION.COMPONENT_REPRODUCTION.FROZEN_SOURCE_ROOT,
        "component operator path-alias physical/virtual roots differ from the authenticated projection",
    )
    expected_profile = PUBLICATION.COMPONENT_REPRODUCTION.sandbox_profile(
        resolved_source_root
    )
    require(
        alias["sandbox_profile"] == expected_profile
        and alias["sandbox_profile_sha256"]
        == digest_bytes(expected_profile.encode("utf-8"))
        and alias["dyld_injected_after_sandbox_activation"] is True
        and alias["read_fallback_to_historical_checkout_denied"] is True
        and alias["read_only_mapping"] is True,
        "component operator path-alias sandbox/fallback evidence differs",
    )
    recipe = require_fields(
        alias["build_recipe"], {"dylib", "launcher"},
        "component path-alias build recipe",
    )
    expected_recipe = {
        "dylib": [
            "xcrun",
            "clang",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-O2",
            "-dynamiclib",
            "-o",
            "r4-path-alias.dylib",
            "tools/r4-path-alias.c",
        ],
        "launcher": [
            "xcrun",
            "clang",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-O2",
            "-o",
            "r4-path-alias-launch",
            "tools/r4-path-alias-launch.c",
        ],
    }
    require(
        recipe == expected_recipe,
        "component operator path-alias build recipe differs",
    )
    compiler = alias["compiler"]
    compiler_executable = alias["compiler_executable"]
    require(
        isinstance(compiler, list)
        and bool(compiler)
        and all(isinstance(item, str) and item for item in compiler)
        and any("Apple clang version" in item for item in compiler)
        and isinstance(compiler_executable, str)
        and Path(compiler_executable).is_absolute()
        and Path(compiler_executable).name == "clang",
        "component operator path-alias compiler identity differs",
    )
    artifacts = require_fields(
        alias["artifacts"], {"dylib", "launcher"},
        "component path-alias artifacts",
    )
    artifact_digests: set[str] = set()
    for name in ("dylib", "launcher"):
        artifact = require_fields(
            artifacts[name], {"sha256", "size_bytes"},
            f"component path-alias artifact {name}",
        )
        artifact_digests.add(
            require_digest(
                artifact["sha256"], f"component path-alias artifact {name}"
            )
        )
        require_positive_integer(
            artifact["size_bytes"], f"component path-alias artifact {name} size"
        )
    require(
        len(artifact_digests) == 2,
        "component path-alias dylib and launcher artifact digests are identical",
    )
    sources = require_fields(
        alias["sources"],
        {"tools/r4-path-alias.c", "tools/r4-path-alias-launch.c"},
        "component path-alias sources",
    )
    for relative, digest in sources.items():
        source_path = resolved_source_root / relative
        require(
            source_path.is_file()
            and not source_path.is_symlink()
            and digest_bytes(read_regular(source_path, f"path-alias source {relative}"))
            == require_digest(digest, f"component path-alias source {relative}"),
            f"component path-alias source digest differs for {relative}",
        )
    authentication = require_fields(
        report.get("package_authentication"),
        {"certification_sha256", "certifier_key_id", "signature_verified"},
        "component package authentication",
    )
    require_digest(
        authentication["certification_sha256"], "component release certification"
    )
    require_digest(authentication["certifier_key_id"], "component certifier key")
    require(
        authentication["signature_verified"] is True,
        "component release signature did not verify",
    )
    host = report.get("host")
    require(isinstance(host, dict), "component reproduction host is absent")
    require(
        host.get("physical_machine") is True,
        "component reproduction is not attested by a physical machine",
    )
    require(
        (host.get("architecture"), host.get("operating_system"))
        == ("arm64", "Darwin"),
        "component reproduction host is not the frozen aarch64-apple builder",
    )
    witness = require_witness(host.get("witness_id"), "component witness_id")
    return {
        "component_set_sha256": expected_set,
        "graph_manifest_digest": require_digest(
            report.get("graph_manifest_digest"), "component graph manifest"
        ),
        "host": {
            "architecture": require_nonempty_string(
                host.get("architecture"), "component host architecture"
            ),
            "operating_system": require_nonempty_string(
                host.get("operating_system"), "component host operating system"
            ),
            "physical_machine": True,
        },
        "report_sha256": digest_bytes(data),
        "release_certification_sha256": authentication["certification_sha256"],
        "release_certifier_key_id": authentication["certifier_key_id"],
        "source_snapshot_manifest_sha256": require_digest(
            report.get("source_snapshot_manifest_sha256"), "component source snapshot"
        ),
        "witness_id": witness,
    }


def _validate_native_report(path: Path, target: str, witness: str) -> dict[str, Any]:
    report, data = read_canonical(path, f"native reproduction report for {target}")
    require(
        report.get("schema") == NATIVE_REPRODUCTION_SCHEMA,
        f"native report schema differs for {target}",
    )
    require(
        report.get("gate_result") == "pass",
        f"native reproduction did not pass for {target}",
    )
    require(
        report.get("component_complete_claim") is False,
        f"native report improperly claims component completeness for {target}",
    )
    report_witness = require_fields(
        report.get("witness"),
        {"id", "physical_machine"},
        f"native witness for {target}",
    )
    require(
        report_witness["id"] == witness and report_witness["physical_machine"] is True,
        f"native witness for {target} is not the named physical machine",
    )
    platform = report.get("platform")
    require(
        isinstance(platform, dict) and platform.get("target") == target,
        f"native report target mismatch for {target}",
    )
    expected_platform = {
        MACOS_TARGET: ("macos", "aarch64", "Mach-O"),
        LINUX_TARGET: ("linux", "x86_64", "ELF"),
    }[target]
    require(
        (
            platform.get("os"),
            platform.get("architecture"),
            platform.get("binary_format"),
        )
        == expected_platform,
        f"native platform identity differs for {target}",
    )
    artifact = report.get("native_artifact")
    require(isinstance(artifact, dict), f"native artifact is absent for {target}")
    binary_digest = require_digest(
        artifact.get("sha256"), f"native executable for {target}"
    )
    require_positive_integer(
        artifact.get("size_bytes"), f"native executable size for {target}"
    )
    runtime_dependencies = validate_runtime_dependencies(
        artifact.get("runtime_dependencies"),
        f"native runtime dependencies for {target}",
    )
    source = report.get("source")
    closure = source.get("closure") if isinstance(source, dict) else None
    require(isinstance(closure, dict), f"native source closure is absent for {target}")
    source_digest = require_digest(
        closure.get("sha256"), f"native source closure for {target}"
    )
    snapshot = require_fields(
        source.get("snapshot_manifest") if isinstance(source, dict) else None,
        {"schema", "sha256"},
        f"native source snapshot for {target}",
    )
    require(
        snapshot["schema"] == SOURCE_SNAPSHOT_SCHEMA,
        f"native source snapshot schema differs for {target}",
    )
    snapshot_digest = require_digest(
        snapshot["sha256"], f"native source snapshot for {target}"
    )
    compiled = report.get("compiled_inventory")
    require(
        isinstance(compiled, dict)
        and compiled.get("schema") == "wasm-biotic.native-tcb-inventory.v1"
        and compiled.get("source_revision") == source_digest,
        f"native TCB inventory does not bind source for {target}",
    )
    embedding = compiled.get("binary_embedding")
    require(
        isinstance(embedding, dict)
        and embedding.get("result") == "pass"
        and embedding.get("occurrences") == 1,
        f"native TCB inventory is not embedded exactly once for {target}",
    )
    reproduction = report.get("reproduction")
    require(
        isinstance(reproduction, dict),
        f"native reproduction proof is absent for {target}",
    )
    require(
        reproduction.get("result") == "pass"
        and reproduction.get("clean_builds") == 2
        and reproduction.get("target_directory_shapes") == ["short", "materially-long"]
        and reproduction.get("exact_complete_binary_match") is True
        and reproduction.get("binary_sha256") == binary_digest
        and reproduction.get("physical_build_paths_embedded") is False,
        f"native unequal-path byte reproduction did not pass for {target}",
    )
    execution = reproduction.get("execution_verification")
    require(
        isinstance(execution, dict)
        and execution.get("invoked") is True
        and execution.get("process_loaded") is True
        and execution.get("expected_usage_error") is True
        and execution.get("result") == "pass",
        f"native executable was not run successfully for {target}",
    )
    if target == MACOS_TARGET:
        canonicalization = reproduction.get("platform_identity_canonicalization")
        require(
            isinstance(canonicalization, dict)
            and canonicalization.get("result") == "pass"
            and canonicalization.get("linked_artifacts_equal_outside_allowed_regions")
            is True,
            "macOS deterministic UUID/signature canonicalization did not pass",
        )
    reference = report.get("reference_digest_verification")
    require(
        isinstance(reference, dict) and reference.get("match") is True,
        f"native reference digest differs for {target}",
    )
    recipe = report.get("build_recipe")
    require(isinstance(recipe, dict), f"native build recipe is absent for {target}")
    recipe_digest = require_digest(
        recipe.get("sha256"), f"native build recipe for {target}"
    )
    return {
        "binary_sha256": binary_digest,
        "build_recipe_sha256": recipe_digest,
        "compiled_inventory_sha256": require_digest(
            compiled.get("sha256"), f"compiled inventory for {target}"
        ),
        "report_sha256": digest_bytes(data),
        "runtime_dependencies": runtime_dependencies,
        "source_closure_sha256": source_digest,
        "source_snapshot_manifest_sha256": snapshot_digest,
        "witness_id": witness,
    }


def _validate_governance(path: Path) -> dict[str, Any]:
    report, data = read_canonical(path, "governance report")
    require_fields(
        report,
        {
            "active_key_count",
            "blockers",
            "ceremony_manifest_sha256",
            "generation",
            "policy_digest",
            "private_key_dependency",
            "publication_quorum_verified",
            "r3_re_root",
            "release_quorum_verified",
            "result",
            "revocation_verified",
            "rotation_verified",
            "schema",
            "successor_proof_of_possession_verified",
            "threshold",
        },
        "governance report",
    )
    require(
        report["schema"] == GOVERNANCE_REPORT_SCHEMA, "governance report schema differs"
    )
    require(report["result"] == "pass", "governance report did not pass")
    require(
        report["generation"] == 1, "R4 governance report is not genesis generation 1"
    )
    require(
        report["threshold"] == 2 and report["active_key_count"] == 3,
        "governance custody is not 2-of-3",
    )
    for field in (
        "publication_quorum_verified",
        "release_quorum_verified",
        "revocation_verified",
        "rotation_verified",
        "successor_proof_of_possession_verified",
    ):
        require(report[field] is True, f"governance report did not verify {field}")
    require(
        report["private_key_dependency"] is False,
        "governance report has a private-key dependency",
    )
    require_empty_blockers(report["blockers"], "governance report.blockers")
    reroot = require_fields(
        report["r3_re_root"],
        {"kind", "r3_private_key_available", "r3_signed_rotation"},
        "governance report.r3_re_root",
    )
    require(
        reroot["kind"] == "out-of-band-genesis"
        and reroot["r3_private_key_available"] is False
        and reroot["r3_signed_rotation"] is False,
        "governance report misstates the R3 out-of-band re-root",
    )
    return {
        "ceremony_manifest_sha256": require_digest(
            report["ceremony_manifest_sha256"], "governance ceremony manifest"
        ),
        "policy_digest": require_digest(report["policy_digest"], "governance policy"),
        "report_sha256": digest_bytes(data),
    }


def _validate_governance_ceremony(
    ceremony_path: Path,
    governance_report_path: Path,
    install_archive_path: Path,
) -> dict[str, Any]:
    try:
        result = CEREMONY.verify_ceremony(ceremony_path)
    except Exception as error:
        fail(f"governance ceremony did not publicly re-verify: {error}")
    report_bytes = read_regular(governance_report_path, "governance report")
    ceremony_report_bytes = read_regular(
        ceremony_path / CEREMONY.REPORT_NAME, "ceremony governance report"
    )
    require(
        ceremony_report_bytes == report_bytes,
        "supplied governance report differs from the public ceremony report",
    )
    try:
        _, install_manifest, _ = ARCHIVE.verify_archive(install_archive_path)
    except Exception as error:
        fail(f"cannot inspect install archive governance closure: {error}")
    ceremony_files: dict[str, tuple[str, int]] = {}
    for path in ceremony_path.rglob("*"):
        relative = path.relative_to(ceremony_path).as_posix()
        information = path.lstat()
        require(
            not stat.S_ISLNK(information.st_mode),
            f"governance ceremony contains a link: {relative}",
        )
        if stat.S_ISREG(information.st_mode):
            data = read_regular(path, f"governance ceremony file {relative}")
            ceremony_files[f"governance/{relative}"] = (digest_bytes(data), len(data))
        else:
            require(
                stat.S_ISDIR(information.st_mode),
                f"governance ceremony contains a special file: {relative}",
            )
    archived_files = {
        item["path"]: (item.get("sha256"), item.get("size_bytes"))
        for item in install_manifest["entries"]
        if item.get("kind") == "file" and item.get("path", "").startswith("governance/")
    }
    require(
        archived_files == ceremony_files,
        "install archive governance files differ from the exact public ceremony closure",
    )
    return {
        "ceremony_manifest_sha256": require_digest(
            result.get("ceremony_sha256"), "verified governance ceremony"
        ),
        "policy_digest": require_digest(
            result.get("policy_digest"), "verified ceremony policy"
        ),
        "report_sha256": require_digest(
            result.get("report_sha256"), "verified ceremony report"
        ),
    }


def _validate_sbom(
    sbom_path: Path,
    coverage_path: Path,
    source_archive_path: Path,
    artifact_paths: dict[str, Path],
    native: dict[str, Any],
) -> dict[str, Any]:
    sbom, sbom_bytes = read_canonical(sbom_path, "SPDX SBOM")
    coverage, coverage_bytes = read_canonical(coverage_path, "SBOM coverage report")
    require(sbom.get("spdxVersion") == "SPDX-2.3", "SBOM is not SPDX 2.3")
    require(sbom.get("dataLicense") == "CC0-1.0", "SBOM data license differs")
    require(
        isinstance(sbom.get("files"), list) and sbom["files"],
        "SBOM file inventory is empty",
    )
    require(
        isinstance(sbom.get("packages"), list) and sbom["packages"],
        "SBOM package inventory is empty",
    )
    require(
        coverage.get("schema") == SBOM_COVERAGE_SCHEMA, "SBOM coverage schema differs"
    )
    require(coverage.get("result") == "pass", "SBOM coverage did not pass")
    require(
        coverage.get("sbom_sha256") == digest_bytes(sbom_bytes),
        "SBOM coverage does not bind the SPDX bytes",
    )
    for count in (
        "cargo_lock_count",
        "cargo_manifest_count",
        "file_count",
        "package_count",
    ):
        require_positive_integer(coverage.get(count), f"SBOM coverage.{count}")
    system_packages = validate_system_packages(
        coverage.get("system_packages"), "SBOM system package inventory"
    )
    require(
        coverage.get("system_package_count") == len(system_packages),
        "SBOM system package count differs from its inventory",
    )
    system_targets = {item["target"] for item in system_packages}
    require(
        system_targets == set(CLOSED_TARGETS),
        "SBOM system dependency targets do not equal the closed platform set",
    )
    roles = coverage.get("artifact_roles")
    require(isinstance(roles, list), "SBOM artifact-role inventory is absent")
    role_names = {item.get("role") for item in roles if isinstance(item, dict)}
    require(
        set(ARCHIVE_ROLES).issubset(role_names),
        "SBOM does not cover all three archives",
    )
    for target in CLOSED_TARGETS:
        require(
            any(isinstance(role, str) and target in role for role in role_names),
            f"SBOM does not cover the native executable for {target}",
        )
    expected_roles = {
        *ARCHIVE_ROLES,
        *(f"native-executable-{target}" for target in CLOSED_TARGETS),
    }
    require(
        set(artifact_paths) == expected_roles,
        "SBOM reproduction artifact role set differs from R4",
    )
    native_by_target = {item["target"]: item for item in native["targets"]}
    for target in CLOSED_TARGETS:
        path = artifact_paths[f"native-executable-{target}"]
        require(
            digest_bytes(read_regular(path, f"SBOM native artifact {target}"))
            == native_by_target[target]["binary_sha256"],
            f"SBOM native artifact differs from attestation for {target}",
        )
    created = sbom.get("creationInfo", {}).get("created")
    require(
        isinstance(created, str) and created.endswith("Z"),
        "SBOM has no canonical creation timestamp",
    )
    try:
        epoch = int(
            dt.datetime.fromisoformat(created.replace("Z", "+00:00")).timestamp()
        )
    except (ValueError, OverflowError) as error:
        fail(f"SBOM creation timestamp is invalid: {error}")
    system_values = [
        f"{item['target']}|{item['name']}|{item['version']}" for item in system_packages
    ]
    with tempfile.TemporaryDirectory(prefix="r4-sbom-source-") as temporary:
        extracted = Path(temporary) / "source"
        try:
            ARCHIVE.extract_archive(source_archive_path, extracted)
            expected_sbom, expected_coverage = SBOM_TOOL.build_documents(
                extracted,
                sorted(artifact_paths.items()),
                system_values,
                epoch,
            )
        except Exception as error:
            fail(f"SBOM did not reproduce from exact public inputs: {error}")
    require(
        sbom_bytes == canonical_json(expected_sbom),
        "SPDX SBOM does not reproduce from exact source/artifact/system inputs",
    )
    require(
        coverage_bytes == canonical_json(expected_coverage),
        "SBOM coverage does not reproduce from exact source/artifact/system inputs",
    )
    return {
        "coverage_sha256": digest_bytes(coverage_bytes),
        "source_and_artifact_closure_sha256": require_digest(
            coverage.get("source_and_artifact_closure_sha256"),
            "SBOM source/artifact closure",
        ),
        "spdx_sha256": digest_bytes(sbom_bytes),
        "system_packages": system_packages,
    }


def _validate_lifecycle(
    path: Path,
    archives: dict[str, Any],
    native: dict[str, Any],
    release_public_key: bytes,
) -> dict[str, Any]:
    report, data = read_canonical(path, "public lifecycle report")
    require(
        report.get("schema") == PUBLIC_LIFECYCLE_SCHEMA,
        "public lifecycle schema differs",
    )
    require(report.get("outcome") == "pass", "public lifecycle did not pass")
    require(
        report.get("private_key_argument_supported") is False,
        "public lifecycle exposes a private-key argument",
    )
    require(
        report.get("private_key_required_or_read") is False,
        "public lifecycle depended on a private key",
    )
    archive = report.get("archive")
    require(
        isinstance(archive, dict)
        and archive.get("install_archive_sha256")
        == archives["install-archive"]["sha256"]
        and archive.get("safe_archive_verifier_passed") is True
        and archive.get("extracted_tree_exactly_matches_manifest") is True,
        "public lifecycle does not bind the verified install archive",
    )
    host = report.get("host")
    require(isinstance(host, dict), "public lifecycle host is absent")
    require(
        host.get("physical_machine") is True,
        "public lifecycle is not attested by a physical machine",
    )
    target = host.get("target")
    require(
        target in CLOSED_TARGETS,
        "public lifecycle target is outside the closed platform set",
    )
    witness = require_witness(host.get("witness_id"), "public lifecycle witness_id")
    kernel = report.get("kernel")
    expected_binary = next(
        item for item in native["targets"] if item["target"] == target
    )["binary_sha256"]
    require(
        isinstance(kernel, dict)
        and kernel.get("expected_sha256") == expected_binary
        and kernel.get("observed_sha256") == expected_binary,
        "public lifecycle did not execute the attested target binary",
    )
    operator_capacity = require_fields(
        report.get("operator_capacity"),
        {"observed_sha256", "within_verified_install"},
        "public lifecycle operator capacity",
    )
    operator_capacity_sha256 = require_digest(
        operator_capacity["observed_sha256"],
        "public lifecycle operator capacity",
    )
    require(
        operator_capacity["within_verified_install"] is True,
        "public lifecycle operator capacity is outside the verified install",
    )
    negative = report.get("negative_controls")
    require(
        isinstance(negative, dict)
        and negative.get("automatic_successor_activation_rejected") is True
        and negative.get("tampered_package_rejected") is True
        and negative.get("wrong_public_key_rejected") is True,
        "public lifecycle negative controls did not pass",
    )
    inactive = report.get("inactive_admission")
    require(
        isinstance(inactive, dict)
        and inactive.get("incumbent_remained_bootable") is True
        and inactive.get("successor_serve_rejected_before_component_activation")
        is True,
        "public lifecycle did not prove inactive successor admission",
    )
    commands = report.get("commands")
    require(isinstance(commands, list), "public lifecycle command evidence is absent")
    labels = {item.get("label") for item in commands if isinstance(item, dict)}
    require(
        labels == LIFECYCLE_COMMANDS,
        "public lifecycle command sequence is incomplete or expanded",
    )
    component_lifecycle = report.get("component_lifecycle_report")
    require(
        isinstance(component_lifecycle, dict),
        "public lifecycle did not retain its component lifecycle report",
    )
    component_lifecycle_digest = digest_bytes(canonical_json(component_lifecycle))
    require(
        report.get("component_lifecycle_report_sha256")
        == component_lifecycle_digest,
        "public lifecycle component report digest differs from retained bytes",
    )
    incumbent_digest = require_digest(
        report.get("incumbent_graph_manifest_digest"),
        "public lifecycle incumbent graph",
    )
    successor_digest = require_digest(
        report.get("successor_graph_manifest_digest"),
        "public lifecycle successor graph",
    )
    try:
        PUBLIC_INSTALL.validate_component_lifecycle(
            component_lifecycle,
            incumbent_digest=incumbent_digest,
            successor_digest=successor_digest,
            public_key_hex=release_public_key.hex(),
            operator_capacity_sha256=operator_capacity_sha256,
        )
    except Exception as error:
        fail(f"retained component lifecycle evidence did not verify: {error}")
    return {
        "component_lifecycle_report_sha256": component_lifecycle_digest,
        "incumbent_graph_manifest_digest": incumbent_digest,
        "operator_capacity_sha256": operator_capacity_sha256,
        "report_sha256": digest_bytes(data),
        "successor_graph_manifest_digest": successor_digest,
        "target": target,
        "witness_id": witness,
    }


def require_executed_controls(
    value: Any, keys: frozenset[str], where: str
) -> dict[str, dict[str, str]]:
    controls = require_fields(value, set(keys), where)
    output: dict[str, dict[str, str]] = {}
    for name in sorted(keys):
        item = require_fields(
            controls[name],
            {"attack_sha256", "rejection_sha256", "result"},
            f"{where}.{name}",
        )
        require(item["result"] == "pass", f"{where}.{name} did not pass")
        output[name] = {
            "attack_sha256": require_digest(
                item["attack_sha256"], f"{where}.{name} attack"
            ),
            "rejection_sha256": require_digest(
                item["rejection_sha256"], f"{where}.{name} rejection"
            ),
            "result": "pass",
        }
    return output


def _validate_prepublication_negatives(
    path: Path, input_spec_path: Path
) -> dict[str, Any]:
    report, data = read_canonical(path, "pre-publication negative controls")
    require_fields(
        report,
        {
            "archives",
            "blockers",
            "evidence_closure_sha256",
            "governance",
            "inputs",
            "private_key_dependency",
            "public_lifecycle",
            "result",
            "sbom",
            "schema",
            "tool_sources",
        },
        "pre-publication negative controls",
    )
    require(
        report["schema"] == PREPUBLICATION_NEGATIVE_SCHEMA,
        "pre-publication negative schema differs",
    )
    require(
        report["result"] == "pass", "pre-publication negative controls did not pass"
    )
    require(
        report["private_key_dependency"] is False,
        "pre-publication controls have a private-key dependency",
    )
    require_empty_blockers(
        report["blockers"], "pre-publication negative controls.blockers"
    )
    try:
        reproduced = PREPUBLICATION_NEGATIVES.verify_report(input_spec_path, path)
    except Exception as error:
        fail(
            "pre-publication negative controls did not re-execute from exact "
            f"public inputs: {error}"
        )
    require(
        canonical_json(reproduced) == data,
        "pre-publication negative controls changed during public reproduction",
    )
    controls = {
        "archives": report["archives"],
        "governance": report["governance"],
        "public_lifecycle": report["public_lifecycle"],
        "sbom": report["sbom"],
    }
    closure = require_digest(
        report["evidence_closure_sha256"],
        "pre-publication negative evidence closure",
    )
    require(
        closure
        == digest_bytes(
            canonical_json(
                {
                    "controls": controls,
                    "inputs": report["inputs"],
                    "tool_sources": report["tool_sources"],
                }
            )
        ),
        "pre-publication negative evidence closure digest differs",
    )
    return {
        "archives": require_executed_controls(
            report["archives"], ARCHIVE_NEGATIVES, "archive negative controls"
        ),
        "evidence_closure_sha256": closure,
        "governance": require_executed_controls(
            report["governance"], GOVERNANCE_NEGATIVES, "governance negative controls"
        ),
        "inputs": report["inputs"],
        "public_lifecycle": require_executed_controls(
            report["public_lifecycle"],
            LIFECYCLE_NEGATIVES,
            "public lifecycle negative controls",
        ),
        "report_sha256": digest_bytes(data),
        "sbom": require_executed_controls(
            report["sbom"], SBOM_NEGATIVES, "SBOM negative controls"
        ),
        "tool_sources": report["tool_sources"],
    }


def _load_matrix_spec(path: Path) -> dict[str, Any]:
    spec, _ = read_canonical(path, "reproduction matrix input")
    require_fields(
        spec,
        {
            "archives",
            "blockers",
            "component_witnesses",
            "contract",
            "governance_ceremony",
            "governance_report",
            "native_witnesses",
            "negative_controls",
            "negative_controls_spec",
            "public_lifecycle_report",
            "release_public_key",
            "sbom",
            "sbom_artifacts",
            "sbom_coverage",
            "schema",
            "source_snapshot",
        },
        "reproduction matrix input",
    )
    require(spec["schema"] == MATRIX_INPUT_SCHEMA, "matrix input schema differs")
    require_empty_blockers(spec["blockers"], "matrix input.blockers")
    return spec


def build_matrix(spec_path: Path) -> dict[str, Any]:
    spec = _load_matrix_spec(spec_path)
    base = spec_path.parent
    contract_path = _path(spec["contract"], base, "R4 contract")
    contract_digest = digest_bytes(read_regular(contract_path, "R4 contract"))
    require(
        contract_digest == FROZEN_CONTRACT_DIGEST,
        "R4 contract digest is not the frozen contract",
    )
    release_public_key = read_regular(
        _path(spec["release_public_key"], base, "independent release public key"),
        "independent release public key",
    )
    require(
        len(release_public_key) == 32,
        "independent release public key must be exactly 32 raw Ed25519 bytes",
    )
    release_certifier_key_id = digest_bytes(release_public_key)

    source_path = _path(spec["source_snapshot"], base, "source snapshot")
    source = _validate_source_snapshot(source_path)
    raw_archives = require_fields(
        spec["archives"], set(ARCHIVE_ROLES), "matrix input.archives"
    )
    archives = {
        role: _verify_archive(_path(raw_archives[role], base, role), role)
        for role in ARCHIVE_ROLES
    }
    require(
        len({item["sha256"] for item in archives.values()}) == 3,
        "the three release archives are not distinct",
    )
    source_archive_path = _path(raw_archives["source-archive"], base, "source archive")
    try:
        _, source_manifest, _ = ARCHIVE.verify_archive(source_archive_path)
    except Exception as error:
        fail(f"cannot inspect source archive binding: {error}")
    snapshot_entries = [
        item
        for item in source_manifest["entries"]
        if item.get("kind") == "file" and item.get("path") == "SOURCE-SNAPSHOT.json"
    ]
    require(
        len(snapshot_entries) == 1
        and snapshot_entries[0].get("sha256") == source["manifest_sha256"],
        "source archive does not contain the exact source snapshot manifest",
    )
    _publicly_verify_source_archive(source_archive_path, source["manifest_sha256"])

    raw_component_paths = spec["component_witnesses"]
    require(
        isinstance(raw_component_paths, list) and len(raw_component_paths) >= 2,
        "at least two component witnesses are required",
    )
    component_witnesses = [
        _validate_component_report(
            _path(raw, base, f"component witness {index}"),
            source["toolchain"],
            source_path.parent,
        )
        for index, raw in enumerate(raw_component_paths)
    ]
    component_witnesses.sort(key=lambda item: item["witness_id"])
    witness_ids = [item["witness_id"] for item in component_witnesses]
    require(
        len(witness_ids) == len(set(witness_ids)),
        "component witness identities are not independent",
    )
    component_sets = {item["component_set_sha256"] for item in component_witnesses}
    graphs = {item["graph_manifest_digest"] for item in component_witnesses}
    sources = {item["source_snapshot_manifest_sha256"] for item in component_witnesses}
    certifications = {
        item["release_certification_sha256"] for item in component_witnesses
    }
    certifier_keys = {item["release_certifier_key_id"] for item in component_witnesses}
    require(
        len(component_sets) == 1,
        "component witnesses produced different component-set digests",
    )
    require(len(graphs) == 1, "component witnesses used different graph manifests")
    require(
        sources == {source["manifest_sha256"]},
        "component witnesses used a different source snapshot",
    )
    require(
        len(certifications) == 1 and len(certifier_keys) == 1,
        "component witnesses authenticated different signed packages",
    )
    require(
        certifier_keys == {release_certifier_key_id},
        "component witnesses used a different release public key",
    )
    components = {
        "component_count": EXPECTED_COMPONENT_COUNT,
        "component_set_sha256": next(iter(component_sets)),
        "graph_manifest_digest": next(iter(graphs)),
        "independence_basis": "distinct operator-assigned physical witness_id values",
        "release_certification_sha256": next(iter(certifications)),
        "release_certifier_key_id": next(iter(certifier_keys)),
        "witness_count": len(component_witnesses),
        "witnesses": component_witnesses,
    }

    raw_native = spec["native_witnesses"]
    require(
        isinstance(raw_native, list), "matrix input.native_witnesses must be an array"
    )
    native_by_target: dict[str, list[dict[str, Any]]] = {
        target: [] for target in CLOSED_TARGETS
    }
    for index, raw in enumerate(raw_native):
        item = require_fields(
            raw, {"path", "target", "witness_id"}, f"native witness {index}"
        )
        target = item["target"]
        require(
            target in CLOSED_TARGETS,
            f"native witness {index} target is outside the closed set",
        )
        witness = require_witness(
            item["witness_id"], f"native witness {index}.witness_id"
        )
        report_path = _path(item["path"], base, f"native witness {index}.path")
        native_by_target[target].append(
            _validate_native_report(report_path, target, witness)
        )
    require(
        len(native_by_target[MACOS_TARGET]) >= 2,
        "macOS native binary requires at least two physical witnesses",
    )
    require(
        len(native_by_target[LINUX_TARGET]) >= 1,
        "Linux native target was not built and executed",
    )
    native_targets: list[dict[str, Any]] = []
    all_native_sources: set[str] = set()
    all_native_snapshots: set[str] = set()
    for target in CLOSED_TARGETS:
        witnesses = sorted(
            native_by_target[target], key=lambda item: item["witness_id"]
        )
        ids = [item["witness_id"] for item in witnesses]
        require(
            len(ids) == len(set(ids)),
            f"native witness identities are duplicated for {target}",
        )
        binaries = {item["binary_sha256"] for item in witnesses}
        require(
            len(binaries) == 1,
            f"native witnesses produced different binaries for {target}",
        )
        recipes = {item["build_recipe_sha256"] for item in witnesses}
        require(
            len(recipes) == 1,
            f"native witnesses used different build recipes for {target}",
        )
        dependency_inventories = {
            canonical_json(item["runtime_dependencies"]) for item in witnesses
        }
        require(
            len(dependency_inventories) == 1,
            f"native witnesses declared different runtime dependencies for {target}",
        )
        all_native_sources.update(item["source_closure_sha256"] for item in witnesses)
        all_native_snapshots.update(
            item["source_snapshot_manifest_sha256"] for item in witnesses
        )
        native_targets.append(
            {
                "binary_sha256": next(iter(binaries)),
                "build_recipe_sha256": next(iter(recipes)),
                "runtime_dependencies": witnesses[0]["runtime_dependencies"],
                "target": target,
                "witness_count": len(witnesses),
                "witnesses": witnesses,
            }
        )
    require(
        len(all_native_sources) == 1,
        "native targets were not built from one exact source closure",
    )
    require(
        all_native_snapshots == {source["manifest_sha256"]},
        "native targets were not built from the authoritative source snapshot",
    )
    native = {
        "closed_targets": list(CLOSED_TARGETS),
        "source_closure_sha256": next(iter(all_native_sources)),
        "source_snapshot_manifest_sha256": source["manifest_sha256"],
        "targets": native_targets,
    }

    governance_report_path = _path(spec["governance_report"], base, "governance report")
    governance = _validate_governance(governance_report_path)
    ceremony = _validate_governance_ceremony(
        _directory(spec["governance_ceremony"], base, "governance ceremony"),
        governance_report_path,
        _path(raw_archives["install-archive"], base, "install archive"),
    )
    require(
        ceremony == governance,
        "governance report bindings differ from the publicly verified ceremony",
    )
    sbom_artifact_roles = {
        *ARCHIVE_ROLES,
        *(f"native-executable-{target}" for target in CLOSED_TARGETS),
    }
    raw_sbom_artifacts = require_fields(
        spec["sbom_artifacts"],
        sbom_artifact_roles,
        "matrix input.sbom_artifacts",
    )
    sbom_artifact_paths = {
        role: _path(raw, base, f"SBOM artifact {role}")
        for role, raw in raw_sbom_artifacts.items()
    }
    for role in ARCHIVE_ROLES:
        require(
            digest_bytes(
                read_regular(sbom_artifact_paths[role], f"SBOM artifact {role}")
            )
            == archives[role]["sha256"],
            f"SBOM artifact {role} differs from the matrix archive",
        )
    sbom = _validate_sbom(
        _path(spec["sbom"], base, "SPDX SBOM"),
        _path(spec["sbom_coverage"], base, "SBOM coverage"),
        source_archive_path,
        sbom_artifact_paths,
        native,
    )
    attested_system_packages = sorted(
        (
            {
                "name": dependency["name"],
                "target": target["target"],
                "version": dependency["version"],
            }
            for target in native_targets
            for dependency in target["runtime_dependencies"]
        ),
        key=lambda item: (item["target"], item["name"], item["version"]),
    )
    require(
        attested_system_packages == sbom["system_packages"],
        "SBOM system packages do not exactly match native runtime dependencies",
    )
    lifecycle = _validate_lifecycle(
        _path(spec["public_lifecycle_report"], base, "public lifecycle report"),
        archives,
        native,
        release_public_key,
    )
    negatives = _validate_prepublication_negatives(
        _path(spec["negative_controls"], base, "pre-publication negative controls"),
        _path(
            spec["negative_controls_spec"],
            base,
            "pre-publication negative-control input spec",
        ),
    )
    negative_inputs = negatives["inputs"]
    require(isinstance(negative_inputs, dict), "negative-control inputs are absent")
    negative_archives = negative_inputs.get("archives")
    require(
        isinstance(negative_archives, dict),
        "negative-control archive inputs are absent",
    )
    for role in ARCHIVE_ROLES:
        require(
            isinstance(negative_archives.get(role), dict)
            and negative_archives[role].get("sha256") == archives[role]["sha256"],
            f"negative controls used a different {role}",
        )
    negative_governance = negative_inputs.get("governance")
    require(
        isinstance(negative_governance, dict)
        and negative_governance.get("ceremony_manifest_sha256")
        == governance["ceremony_manifest_sha256"]
        and negative_governance.get("governance_report_sha256")
        == governance["report_sha256"]
        and negative_governance.get("policy_digest")
        == governance["policy_digest"],
        "negative controls used different governance evidence",
    )
    negative_sbom = negative_inputs.get("sbom")
    require(
        isinstance(negative_sbom, dict)
        and negative_sbom.get("spdx_sha256") == sbom["spdx_sha256"]
        and negative_sbom.get("coverage_sha256") == sbom["coverage_sha256"],
        "negative controls used a different SBOM or coverage report",
    )
    negative_lifecycle = negative_inputs.get("public_lifecycle")
    lifecycle_target = lifecycle["target"]
    lifecycle_binary = next(
        item for item in native["targets"] if item["target"] == lifecycle_target
    )["binary_sha256"]
    require(
        isinstance(negative_lifecycle, dict)
        and negative_lifecycle.get("install_archive_sha256")
        == archives["install-archive"]["sha256"]
        and negative_lifecycle.get("kernel_sha256") == lifecycle_binary
        and negative_lifecycle.get("operator_capacity_sha256")
        == lifecycle["operator_capacity_sha256"]
        and negative_lifecycle.get("incumbent_manifest_sha256")
        == lifecycle["incumbent_graph_manifest_digest"]
        and negative_lifecycle.get("successor_manifest_sha256")
        == lifecycle["successor_graph_manifest_digest"]
        and negative_lifecycle.get("release_certifier_key_id")
        == release_certifier_key_id
        and negative_lifecycle.get("target") == lifecycle_target,
        "negative controls used different public lifecycle inputs",
    )
    return {
        "archives": archives,
        "blockers": [],
        "component_complete_claim": True,
        "components": components,
        "contract": {
            "factory_native_boundary": "component roles/services/workflows/policy; native instantiate/meter/persist/communicate/enforce only",
            "sha256": contract_digest,
        },
        "external_north_star_claim": False,
        "governance": governance,
        "native": native,
        "negative_controls": negatives,
        "phase": "pre-publication",
        "private_key_dependency": False,
        "public_lifecycle": lifecycle,
        "result": "pass",
        "sbom": sbom,
        "schema": MATRIX_SCHEMA,
        "source_snapshot": source,
        "targets": list(CLOSED_TARGETS),
    }


def validate_matrix(matrix: Any) -> dict[str, Any]:
    value = require_fields(
        matrix,
        {
            "archives",
            "blockers",
            "component_complete_claim",
            "components",
            "contract",
            "external_north_star_claim",
            "governance",
            "native",
            "negative_controls",
            "phase",
            "private_key_dependency",
            "public_lifecycle",
            "result",
            "sbom",
            "schema",
            "source_snapshot",
            "targets",
        },
        "reproduction matrix",
    )
    require(value["schema"] == MATRIX_SCHEMA, "reproduction matrix schema differs")
    require(
        value["phase"] == "pre-publication",
        "reproduction matrix is not explicitly pre-publication",
    )
    require(value["result"] == "pass", "reproduction matrix did not pass")
    require(
        value["component_complete_claim"] is True,
        "matrix does not assert bounded component completeness",
    )
    require(
        value["external_north_star_claim"] is False,
        "matrix improperly asserts the external North Star",
    )
    require(
        value["private_key_dependency"] is False, "matrix has a private-key dependency"
    )
    require_empty_blockers(value["blockers"], "reproduction matrix.blockers")
    require(value["targets"] == list(CLOSED_TARGETS), "matrix target set differs")
    require(
        value["contract"].get("sha256") == FROZEN_CONTRACT_DIGEST,
        "matrix contract digest differs",
    )
    source_snapshot = require_fields(
        value["source_snapshot"],
        {
            "manifest_sha256",
            "source_closure_sha256",
            "source_file_count",
            "toolchain",
            "vendor_closure_sha256",
            "vendor_file_count",
        },
        "matrix source snapshot",
    )
    for field in (
        "manifest_sha256",
        "source_closure_sha256",
        "vendor_closure_sha256",
    ):
        require_digest(source_snapshot[field], f"matrix source snapshot.{field}")
    require_positive_integer(
        source_snapshot["source_file_count"], "matrix source snapshot.source_file_count"
    )
    require_positive_integer(
        source_snapshot["vendor_file_count"], "matrix source snapshot.vendor_file_count"
    )
    toolchain = require_fields(
        source_snapshot["toolchain"],
        {"cargo", "rustc", "wasm_target", "wasm_tools"},
        "matrix source snapshot toolchain",
    )
    require(
        isinstance(toolchain["cargo"], list)
        and bool(toolchain["cargo"])
        and all(isinstance(item, str) and item for item in toolchain["cargo"])
        and isinstance(toolchain["rustc"], list)
        and bool(toolchain["rustc"])
        and all(isinstance(item, str) and item for item in toolchain["rustc"])
        and toolchain["wasm_target"] == "wasm32-wasip2"
        and isinstance(toolchain["wasm_tools"], str)
        and bool(toolchain["wasm_tools"]),
        "matrix source snapshot toolchain identity differs",
    )
    components = require_fields(
        value["components"],
        {
            "component_count",
            "component_set_sha256",
            "graph_manifest_digest",
            "independence_basis",
            "release_certification_sha256",
            "release_certifier_key_id",
            "witness_count",
            "witnesses",
        },
        "matrix components",
    )
    require(
        components.get("component_count") == 22
        and components.get("witness_count", 0) >= 2,
        "matrix does not prove 22 components on two witnesses",
    )
    component_set = require_digest(
        components["component_set_sha256"], "matrix component-set"
    )
    component_graph = require_digest(
        components["graph_manifest_digest"], "matrix component graph"
    )
    component_certification = require_digest(
        components["release_certification_sha256"],
        "matrix component release certification",
    )
    component_certifier = require_digest(
        components["release_certifier_key_id"], "matrix component release certifier"
    )
    require(
        components["independence_basis"]
        == "distinct operator-assigned physical witness_id values",
        "matrix component witness independence basis differs",
    )
    component_witnesses = components["witnesses"]
    require(
        isinstance(component_witnesses, list)
        and len(component_witnesses) == components["witness_count"],
        "matrix component witness inventory differs from its count",
    )
    component_ids: list[str] = []
    for index, raw in enumerate(component_witnesses):
        witness = require_fields(
            raw,
            {
                "component_set_sha256",
                "graph_manifest_digest",
                "host",
                "report_sha256",
                "release_certification_sha256",
                "release_certifier_key_id",
                "source_snapshot_manifest_sha256",
                "witness_id",
            },
            f"matrix component witness {index}",
        )
        witness_id = require_witness(
            witness["witness_id"], f"matrix component witness {index}.witness_id"
        )
        component_ids.append(witness_id)
        host = require_fields(
            witness["host"],
            {"architecture", "operating_system", "physical_machine"},
            f"matrix component witness {index}.host",
        )
        require_nonempty_string(
            host["architecture"], f"matrix component witness {index}.architecture"
        )
        require_nonempty_string(
            host["operating_system"],
            f"matrix component witness {index}.operating_system",
        )
        require(
            host["physical_machine"] is True
            and host["architecture"] == "arm64"
            and host["operating_system"] == "Darwin",
            f"matrix component witness {index} is not a physical frozen Mac builder",
        )
        require_digest(
            witness["report_sha256"], f"matrix component witness {index}.report"
        )
        require(
            witness["component_set_sha256"] == component_set
            and witness["graph_manifest_digest"] == component_graph
            and witness["release_certification_sha256"] == component_certification
            and witness["release_certifier_key_id"] == component_certifier
            and witness["source_snapshot_manifest_sha256"]
            == source_snapshot["manifest_sha256"],
            f"matrix component witness {index} differs from the shared closure",
        )
    require(
        component_ids == sorted(component_ids)
        and len(component_ids) == len(set(component_ids)),
        "matrix component witness identities are not sorted and independent",
    )
    native = require_fields(
        value["native"],
        {
            "closed_targets",
            "source_closure_sha256",
            "source_snapshot_manifest_sha256",
            "targets",
        },
        "matrix native evidence",
    )
    require(
        native["closed_targets"] == list(CLOSED_TARGETS),
        "matrix native closed target set differs",
    )
    native_source_closure = require_digest(
        native["source_closure_sha256"], "matrix native source closure"
    )
    native_targets = native["targets"]
    require(
        [item.get("target") for item in native_targets] == list(CLOSED_TARGETS),
        "matrix native target set differs",
    )
    mac = native_targets[0]
    require(
        mac.get("witness_count", 0) >= 2,
        "matrix does not prove macOS binary reproduction on two witnesses",
    )
    require(
        native_targets[1].get("witness_count", 0) >= 1,
        "matrix does not prove Linux native execution",
    )
    source_snapshot_digest = require_digest(
        value["source_snapshot"].get("manifest_sha256"),
        "matrix source snapshot manifest",
    )
    require(
        native["source_snapshot_manifest_sha256"] == source_snapshot_digest,
        "matrix native evidence does not bind its source snapshot",
    )
    attested_system_packages: list[dict[str, str]] = []
    for target in native_targets:
        target = require_fields(
            target,
            {
                "binary_sha256",
                "build_recipe_sha256",
                "runtime_dependencies",
                "target",
                "witness_count",
                "witnesses",
            },
            "matrix native target",
        )
        target_name = target["target"]
        binary_digest = require_digest(
            target["binary_sha256"], f"matrix native executable for {target_name}"
        )
        recipe_digest = require_digest(
            target["build_recipe_sha256"],
            f"matrix native build recipe for {target_name}",
        )
        dependencies = validate_runtime_dependencies(
            target.get("runtime_dependencies"),
            f"matrix native runtime dependencies for {target_name}",
        )
        witnesses = target.get("witnesses")
        require(
            isinstance(witnesses, list)
            and len(witnesses) == target.get("witness_count"),
            f"matrix native witness inventory differs for {target_name}",
        )
        witness_ids: list[str] = []
        for index, raw_witness in enumerate(witnesses):
            witness = require_fields(
                raw_witness,
                {
                    "binary_sha256",
                    "build_recipe_sha256",
                    "compiled_inventory_sha256",
                    "report_sha256",
                    "runtime_dependencies",
                    "source_closure_sha256",
                    "source_snapshot_manifest_sha256",
                    "witness_id",
                },
                f"matrix native witness {target_name}[{index}]",
            )
            witness_ids.append(
                require_witness(
                    witness["witness_id"],
                    f"matrix native witness {target_name}[{index}].witness_id",
                )
            )
            require_digest(
                witness["compiled_inventory_sha256"],
                f"matrix native witness {target_name}[{index}].TCB inventory",
            )
            require_digest(
                witness["report_sha256"],
                f"matrix native witness {target_name}[{index}].report",
            )
            require(
                witness["binary_sha256"] == binary_digest
                and witness["build_recipe_sha256"] == recipe_digest
                and witness["source_closure_sha256"] == native_source_closure
                and witness.get("source_snapshot_manifest_sha256")
                == source_snapshot_digest
                and witness.get("runtime_dependencies") == dependencies,
                f"matrix native witness does not bind source/dependencies for {target_name}",
            )
        require(
            witness_ids == sorted(witness_ids)
            and len(witness_ids) == len(set(witness_ids)),
            f"matrix native witness identities are not sorted and independent for {target_name}",
        )
        attested_system_packages.extend(
            {
                "name": dependency["name"],
                "target": target_name,
                "version": dependency["version"],
            }
            for dependency in dependencies
        )
    matrix_system_packages = validate_system_packages(
        value["sbom"].get("system_packages"), "matrix SBOM system packages"
    )
    require(
        sorted(
            attested_system_packages,
            key=lambda item: (item["target"], item["name"], item["version"]),
        )
        == matrix_system_packages,
        "matrix SBOM does not exactly cover native runtime dependencies",
    )
    require_digest(value["sbom"].get("spdx_sha256"), "matrix SPDX SBOM")
    require_digest(value["sbom"].get("coverage_sha256"), "matrix SBOM coverage")
    require_digest(
        value["sbom"].get("source_and_artifact_closure_sha256"),
        "matrix SBOM source/artifact closure",
    )
    require_digest(value["governance"].get("policy_digest"), "matrix governance policy")
    require_digest(value["governance"].get("report_sha256"), "matrix governance report")
    public_lifecycle = require_fields(
        value["public_lifecycle"],
        {
            "component_lifecycle_report_sha256",
            "incumbent_graph_manifest_digest",
            "operator_capacity_sha256",
            "report_sha256",
            "successor_graph_manifest_digest",
            "target",
            "witness_id",
        },
        "matrix public lifecycle",
    )
    for field in (
        "component_lifecycle_report_sha256",
        "incumbent_graph_manifest_digest",
        "operator_capacity_sha256",
        "report_sha256",
        "successor_graph_manifest_digest",
    ):
        require_digest(
            public_lifecycle[field], f"matrix public lifecycle.{field}"
        )
    require(
        public_lifecycle["target"] in CLOSED_TARGETS,
        "matrix public lifecycle target differs",
    )
    require_witness(
        public_lifecycle["witness_id"], "matrix public lifecycle witness_id"
    )
    negative_controls = require_fields(
        value["negative_controls"],
        {
            "archives",
            "evidence_closure_sha256",
            "governance",
            "inputs",
            "public_lifecycle",
            "report_sha256",
            "sbom",
            "tool_sources",
        },
        "matrix pre-publication negative controls",
    )
    require_digest(
        negative_controls["evidence_closure_sha256"],
        "matrix pre-publication negative evidence closure",
    )
    require_digest(
        negative_controls["report_sha256"],
        "matrix pre-publication negative report",
    )
    require_executed_controls(
        negative_controls["archives"],
        ARCHIVE_NEGATIVES,
        "matrix archive negative controls",
    )
    require_executed_controls(
        negative_controls["governance"],
        GOVERNANCE_NEGATIVES,
        "matrix governance negative controls",
    )
    require_executed_controls(
        negative_controls["public_lifecycle"],
        LIFECYCLE_NEGATIVES,
        "matrix public lifecycle negative controls",
    )
    require_executed_controls(
        negative_controls["sbom"],
        SBOM_NEGATIVES,
        "matrix SBOM negative controls",
    )
    for role in ARCHIVE_ROLES:
        require_digest(
            value["archives"].get(role, {}).get("sha256"), f"matrix archive {role}"
        )
    return value


def _claim_entry(
    claim: dict[str, Any], role: str, target: str | None = None
) -> dict[str, Any]:
    matches = [
        item
        for item in claim["objects"]
        if item["role"] == role and item.get("target") == target
    ]
    require(
        len(matches) == 1, f"publication claim lacks exact {role} object for {target}"
    )
    return matches[0]


def _validate_publication_negatives(
    path: Path, publication_root: str
) -> dict[str, Any]:
    report, data = read_canonical(path, "publication negative controls")
    require_fields(
        report,
        {
            "blockers",
            "controls",
            "private_key_dependency",
            "pristine_verified_after_mutations",
            "pristine_verified_before_mutations",
            "publication_root",
            "result",
            "schema",
        },
        "publication negative controls",
    )
    require(
        report["schema"] == PUBLICATION_NEGATIVE_SCHEMA,
        "publication negative schema differs",
    )
    require(
        report["publication_root"] == publication_root,
        "publication negative controls name a different root",
    )
    require(report["result"] == "pass", "publication negative controls did not pass")
    require(
        report["pristine_verified_before_mutations"] is True
        and report["pristine_verified_after_mutations"] is True,
        "pristine publication was not verified around mutations",
    )
    require(
        report["private_key_dependency"] is False,
        "publication controls have a private-key dependency",
    )
    require_empty_blockers(report["blockers"], "publication negative controls.blockers")
    controls = require_true_controls(
        report["controls"],
        PUBLICATION_NEGATIVES,
        "publication negative controls.controls",
    )
    return {"controls": controls, "report_sha256": digest_bytes(data)}


def _validate_postpublication_recovery(
    wrapper_path: Path,
    lifecycle_path: Path,
    *,
    publication_root: str,
    policy_digest: str,
    matrix: dict[str, Any],
    release_public_key: bytes,
) -> dict[str, Any]:
    report, data = read_canonical(
        wrapper_path, "post-publication recovery report"
    )
    require_fields(
        report,
        {
            "blockers",
            "independent_policy_sha256",
            "lifecycle",
            "phase",
            "private_key_dependency",
            "publication",
            "result",
            "schema",
            "targets",
        },
        "post-publication recovery report",
    )
    require(
        report["schema"] == POSTPUBLICATION_RECOVERY_SCHEMA
        and report["phase"] == "post-publication"
        and report["result"] == "pass",
        "post-publication recovery schema/phase/result differs",
    )
    require(
        report["private_key_dependency"] is False,
        "post-publication recovery has a private-key dependency",
    )
    require_empty_blockers(report["blockers"], "post-publication recovery.blockers")
    require(
        report["targets"] == list(CLOSED_TARGETS),
        "post-publication recovery target set differs",
    )
    require(
        report["independent_policy_sha256"] == policy_digest,
        "post-publication recovery used a different independent policy",
    )
    publication = require_fields(
        report["publication"],
        {"publication_root", "verified_before_recovery"},
        "post-publication recovery publication",
    )
    require(
        publication["publication_root"] == publication_root
        and publication["verified_before_recovery"] is True,
        "post-publication recovery did not first verify the exact final root",
    )
    lifecycle_binding = require_fields(
        report["lifecycle"],
        {
            "fresh_mechanism_state",
            "operator_capacity_sha256",
            "outcome",
            "private_key_argument_supported",
            "private_key_required_or_read",
            "report_sha256",
        },
        "post-publication recovery lifecycle binding",
    )
    require(
        lifecycle_binding["fresh_mechanism_state"] is True
        and lifecycle_binding["outcome"] == "pass"
        and lifecycle_binding["private_key_argument_supported"] is False
        and lifecycle_binding["private_key_required_or_read"] is False,
        "post-publication lifecycle was not rerun from fresh state without private keys",
    )
    require_digest(
        lifecycle_binding["operator_capacity_sha256"],
        "post-publication recovery operator capacity",
    )
    external_lifecycle = _validate_lifecycle(
        lifecycle_path,
        matrix["archives"],
        matrix["native"],
        release_public_key,
    )
    require(
        lifecycle_binding["report_sha256"]
        == external_lifecycle["report_sha256"],
        "post-publication wrapper does not bind the exact external lifecycle report",
    )
    embedded = matrix["public_lifecycle"]
    require(
        external_lifecycle["incumbent_graph_manifest_digest"]
        == embedded["incumbent_graph_manifest_digest"]
        and external_lifecycle["successor_graph_manifest_digest"]
        == embedded["successor_graph_manifest_digest"],
        "post-publication lifecycle used a different signed package pair",
    )
    require(
        lifecycle_binding["operator_capacity_sha256"]
        == external_lifecycle["operator_capacity_sha256"]
        == embedded["operator_capacity_sha256"],
        "post-publication lifecycle used a different operator capacity",
    )
    return {
        "lifecycle_report_sha256": external_lifecycle["report_sha256"],
        "report_sha256": digest_bytes(data),
        "target": external_lifecycle["target"],
        "witness_id": external_lifecycle["witness_id"],
    }


def build_aggregate(
    matrix_path: Path,
    publication_path: Path,
    policy_path: Path,
    release_public_key_path: Path,
    publication_negatives_path: Path,
    postpublication_recovery_path: Path,
    postpublication_lifecycle_path: Path,
) -> dict[str, Any]:
    matrix, matrix_bytes = read_canonical(matrix_path, "reproduction matrix")
    validate_matrix(matrix)
    release_public_key = read_regular(
        release_public_key_path, "independent release public key"
    )
    require(
        len(release_public_key) == 32,
        "independent release public key must be exactly 32 raw Ed25519 bytes",
    )
    release_public_key_digest = digest_bytes(release_public_key)
    require(
        release_public_key_digest
        == matrix["components"]["release_certifier_key_id"],
        "independent release public key differs from the matrix certifier",
    )
    try:
        publication_report = PUBLICATION.verify(
            publication_path, policy_path, release_public_key_path
        )
    except Exception as error:
        fail(f"signed publication verification failed: {error}")
    publication_root = publication_report["publication_root"]
    claim, _ = PUBLICATION.read_canonical_file(
        publication_path / PUBLICATION.CLAIM_NAME, "publication claim"
    )
    require(
        claim.get("component_complete_claim") is True,
        "publication claim does not assert component completeness",
    )
    require(
        claim.get("external_north_star_claim") is False,
        "publication claim improperly asserts the external North Star",
    )
    require(
        claim.get("targets") == list(CLOSED_TARGETS),
        "publication target set differs from R4",
    )

    bindings = {
        "component-release-archive": matrix["archives"]["component-release-archive"][
            "sha256"
        ],
        "governance-report": matrix["governance"]["report_sha256"],
        "install-archive": matrix["archives"]["install-archive"]["sha256"],
        "public-lifecycle-report": matrix["public_lifecycle"]["report_sha256"],
        "release-public-key": release_public_key_digest,
        "r4-contract": matrix["contract"]["sha256"],
        "reproduction-matrix": digest_bytes(matrix_bytes),
        "sbom-coverage": matrix["sbom"]["coverage_sha256"],
        "source-archive": matrix["archives"]["source-archive"]["sha256"],
        "spdx-sbom": matrix["sbom"]["spdx_sha256"],
    }
    for role, expected in bindings.items():
        require(
            _claim_entry(claim, role)["digest"] == expected,
            f"publication {role} does not match the reproduction matrix",
        )

    policy_bytes = read_regular(
        policy_path, "independent genesis policy", maximum=MAX_JSON_BYTES
    )
    require(
        digest_bytes(policy_bytes) == matrix["governance"]["policy_digest"],
        "independent policy differs from matrix governance policy",
    )
    independent_policy_digest = digest_bytes(policy_bytes)
    for target in CLOSED_TARGETS:
        target_matrix = next(
            item for item in matrix["native"]["targets"] if item["target"] == target
        )
        require(
            _claim_entry(claim, "native-executable", target)["digest"]
            == target_matrix["binary_sha256"],
            f"published executable differs from matrix for {target}",
        )
        witness_reports = {item["report_sha256"] for item in target_matrix["witnesses"]}
        require(
            _claim_entry(claim, "native-attestation", target)["digest"]
            in witness_reports,
            f"published native attestation was not a matrix witness for {target}",
        )

    publication_negatives = _validate_publication_negatives(
        publication_negatives_path, publication_root
    )
    publication_root_path = publication_path.resolve()
    for path, where in (
        (postpublication_recovery_path, "post-publication recovery report"),
        (postpublication_lifecycle_path, "post-publication lifecycle report"),
    ):
        try:
            external_path = path.resolve(strict=True)
        except OSError as error:
            fail(f"cannot resolve {where}: {error}")
        require(
            not external_path.is_relative_to(publication_root_path),
            f"{where} must remain external to the signed publication root",
        )
    recovery = _validate_postpublication_recovery(
        postpublication_recovery_path,
        postpublication_lifecycle_path,
        publication_root=publication_root,
        policy_digest=independent_policy_digest,
        matrix=matrix,
        release_public_key=release_public_key,
    )
    matrix_digest = digest_bytes(matrix_bytes)
    gates = [
        {
            "evidence": sorted({matrix["contract"]["sha256"], matrix_digest}),
            "gate": "R4-C0",
            "result": "pass",
        },
        {
            "evidence": sorted(
                {
                    matrix["source_snapshot"]["manifest_sha256"],
                    *(item["sha256"] for item in matrix["archives"].values()),
                }
            ),
            "gate": "R4-C1",
            "result": "pass",
        },
        {
            "evidence": sorted(
                item["report_sha256"] for item in matrix["components"]["witnesses"]
            ),
            "gate": "R4-C2",
            "result": "pass",
        },
        {
            "evidence": sorted(
                {
                    item["report_sha256"]
                    for target in matrix["native"]["targets"]
                    for item in target["witnesses"]
                }
                | {item["binary_sha256"] for item in matrix["native"]["targets"]}
            ),
            "gate": "R4-C3",
            "result": "pass",
        },
        {
            "evidence": sorted(
                {
                    matrix["governance"]["policy_digest"],
                    matrix["governance"]["report_sha256"],
                    matrix["negative_controls"]["report_sha256"],
                }
            ),
            "gate": "R4-C4",
            "result": "pass",
        },
        {
            "evidence": sorted(
                {matrix["sbom"]["spdx_sha256"], matrix["sbom"]["coverage_sha256"]}
            ),
            "gate": "R4-C5",
            "result": "pass",
        },
        {
            "evidence": sorted(
                {
                    matrix["public_lifecycle"]["report_sha256"],
                    recovery["lifecycle_report_sha256"],
                    recovery["report_sha256"],
                }
            ),
            "gate": "R4-C6",
            "result": "pass",
        },
        {
            "evidence": sorted(
                {
                    publication_root,
                    publication_negatives["report_sha256"],
                    recovery["lifecycle_report_sha256"],
                    recovery["report_sha256"],
                }
            ),
            "gate": "R4-C7",
            "result": "pass",
        },
    ]
    return {
        "blockers": [],
        "component_complete_claim": True,
        "external_north_star_claim": False,
        "gates": gates,
        "matrix_sha256": matrix_digest,
        "phase": "post-publication",
        "postpublication_lifecycle_sha256": recovery["lifecycle_report_sha256"],
        "postpublication_recovery_sha256": recovery["report_sha256"],
        "private_key_dependency": False,
        "publication_negative_controls_sha256": publication_negatives["report_sha256"],
        "publication_root": publication_root,
        "release_public_key_sha256": release_public_key_digest,
        "result": "pass",
        "schema": AGGREGATE_SCHEMA,
        "self_reference_boundary": {
            "aggregate": "external post-publication report binds the independently verified final root, fresh recovery wrapper and lifecycle and is not an object inside that root",
            "matrix": "pre-publication object binds functional C0-C6 evidence and intentionally contains no future publication root",
        },
        "targets": list(CLOSED_TARGETS),
    }


def write_atomic(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.tmp-", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical_json(value))
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(description=__doc__)
    subcommands = command.add_subparsers(dest="command", required=True)
    matrix = subcommands.add_parser(
        "matrix", help="build the pre-publication reproduction matrix"
    )
    matrix.add_argument("--spec", required=True, type=Path)
    matrix.add_argument("--out", required=True, type=Path)
    verify_matrix = subcommands.add_parser(
        "verify-matrix", help="rebuild and compare a matrix"
    )
    verify_matrix.add_argument("--spec", required=True, type=Path)
    verify_matrix.add_argument("--matrix", required=True, type=Path)
    for name in ("aggregate", "verify"):
        item = subcommands.add_parser(name)
        item.add_argument("--matrix", required=True, type=Path)
        item.add_argument("--publication", required=True, type=Path)
        item.add_argument("--policy", required=True, type=Path)
        item.add_argument("--release-public-key", required=True, type=Path)
        item.add_argument("--publication-negatives", required=True, type=Path)
        item.add_argument("--postpublication-recovery", required=True, type=Path)
        item.add_argument("--postpublication-lifecycle", required=True, type=Path)
        if name == "aggregate":
            item.add_argument("--out", required=True, type=Path)
        else:
            item.add_argument("--aggregate", required=True, type=Path)
    return command


def main(arguments: list[str] | None = None) -> int:
    options = parser().parse_args(arguments)
    try:
        if options.command == "matrix":
            value = build_matrix(options.spec)
            write_atomic(options.out, value)
            print(f"matrix {digest_bytes(canonical_json(value))} {options.out}")
        elif options.command == "verify-matrix":
            expected = build_matrix(options.spec)
            actual, actual_bytes = read_canonical(options.matrix, "reproduction matrix")
            validate_matrix(actual)
            require(
                actual_bytes == canonical_json(expected),
                "reproduction matrix does not reproduce from its exact evidence spec",
            )
            print(f"verified matrix {digest_bytes(actual_bytes)}")
        elif options.command == "aggregate":
            value = build_aggregate(
                options.matrix,
                options.publication,
                options.policy,
                options.release_public_key,
                options.publication_negatives,
                options.postpublication_recovery,
                options.postpublication_lifecycle,
            )
            write_atomic(options.out, value)
            print(f"aggregate {digest_bytes(canonical_json(value))} {options.out}")
        else:
            expected = build_aggregate(
                options.matrix,
                options.publication,
                options.policy,
                options.release_public_key,
                options.publication_negatives,
                options.postpublication_recovery,
                options.postpublication_lifecycle,
            )
            actual, actual_bytes = read_canonical(options.aggregate, "R4 aggregate")
            require(
                actual_bytes == canonical_json(expected),
                "R4 aggregate does not reproduce from the exact publication and evidence",
            )
            print(
                f"verified aggregate {digest_bytes(actual_bytes)} root={expected['publication_root']}"
            )
        return 0
    except (AggregateError, OSError) as error:
        print(f"r4-aggregate: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
