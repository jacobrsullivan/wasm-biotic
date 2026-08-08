#!/usr/bin/env python3
"""Prepare, assemble, and independently verify a detached R4 publication.

The publication tool never accepts or opens private keys.  Operators prepare a
content-addressed claim, sign its canonical release payload with the separate
R4 certifier-governance tool, and only then assemble an atomic publication.
Verification starts from an independently obtained genesis trust policy.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tarfile
import tempfile
from typing import Any, BinaryIO, NoReturn


SPEC_SCHEMA = "wasm-biotic.r4-publication-spec.v1"
CLAIM_SCHEMA = "wasm-biotic.r4-publication-claim.v1"
SIGNING_PAYLOAD_SCHEMA = "wasm-biotic.r4-publication-signing-payload.v1"
PUBLICATION_ROOT_SCHEMA = "wasm-biotic.r4-publication-root.v1"
NATIVE_ATTESTATION_SCHEMA = "wasm-biotic.r4-native-build-reproducibility.v1"
SOURCE_SNAPSHOT_SCHEMA = "wasm-biotic.r4-source-snapshot.v1"
GOVERNANCE_REPORT_SCHEMA = "wasm-biotic.r4-governance-report.v1"
REPRODUCTION_MATRIX_SCHEMA = "wasm-biotic.r4-reproduction-matrix.v1"
SBOM_COVERAGE_SCHEMA = "wasm-biotic.sbom-coverage.v1"
PUBLIC_LIFECYCLE_SCHEMA = "wasm-biotic.r4-public-install-lifecycle.v1"
COMPONENT_CLAIM_SIGNING_PAYLOAD_SCHEMA = (
    "wasm-biotic.component-complete-claim-signing-payload.v1"
)
FROZEN_CONTRACT_DIGEST = (
    "sha256:6eff98aedd7d0047d6abe55b9d60d5bbabaa00b733e8df13d3a0fc3de9c96857"
)
CLOSED_TARGETS = ("aarch64-apple-darwin", "x86_64-unknown-linux-gnu")

CLAIM_NAME = "claim.json"
SIGNING_PAYLOAD_NAME = "signing-payload.json"
PUBLICATION_ROOT_NAME = "publication-root.json"
OBJECT_DIRECTORY = "objects"
OBJECT_ALGORITHM_DIRECTORY = "objects/sha256"
SIGNATURE_DIRECTORY = "signatures"

GLOBAL_ROLES = frozenset(
    {
        "component-release-archive",
        "governance-report",
        "install-archive",
        "public-lifecycle-report",
        "release-public-key",
        "r4-contract",
        "reproduction-matrix",
        "sbom-coverage",
        "source-archive",
        "spdx-sbom",
        "trust-policy",
    }
)
NATIVE_ROLES = frozenset({"native-attestation", "native-executable"})
ALL_ROLES = GLOBAL_ROLES | NATIVE_ROLES

DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
TARGET_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}\Z")
WITNESS_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
SIGNATURE_FILE_RE = re.compile(r"([0-9a-f]{64})\.json\Z")
MAX_JSON_BYTES = 16 * 1024 * 1024
READ_CHUNK = 1024 * 1024


class PublicationError(RuntimeError):
    """The proposed publication is incomplete, ambiguous, or untrusted."""


def fail(message: str) -> NoReturn:
    raise PublicationError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def _load_governance() -> Any:
    path = Path(__file__).with_name("r4-certifier-governance.py")
    specification = importlib.util.spec_from_file_location(
        "wasm_biotic_r4_certifier_governance", path
    )
    if specification is None or specification.loader is None:
        fail(f"cannot load certifier governance module at {path}")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


GOVERNANCE = _load_governance()


def _load_archive_tool() -> Any:
    path = Path(__file__).with_name("r4-install-archive.py")
    specification = importlib.util.spec_from_file_location(
        "wasm_biotic_r4_install_archive_for_publication", path
    )
    if specification is None or specification.loader is None:
        fail(f"cannot load deterministic archive verifier at {path}")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


ARCHIVE = _load_archive_tool()


def _load_ceremony_tool() -> Any:
    path = Path(__file__).with_name("r4-governance-ceremony.py")
    specification = importlib.util.spec_from_file_location(
        "wasm_biotic_r4_ceremony_for_publication", path
    )
    if specification is None or specification.loader is None:
        fail(f"cannot load governance ceremony verifier at {path}")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


CEREMONY = _load_ceremony_tool()


def _load_local_tool(filename: str, module_name: str) -> Any:
    path = Path(__file__).with_name(filename)
    specification = importlib.util.spec_from_file_location(module_name, path)
    if specification is None or specification.loader is None:
        fail(f"cannot load required R4 verifier at {path}")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


COMPONENT_REPRODUCTION = _load_local_tool(
    "r4-component-reproduction.py",
    "wasm_biotic_r4_component_reproduction_for_publication",
)
COMPONENT_RELEASE = _load_local_tool(
    "component-release-bundle.py",
    "wasm_biotic_component_release_bundle_for_publication",
)
PUBLIC_INSTALL = _load_local_tool(
    "r4-public-install.py", "wasm_biotic_r4_public_install_for_publication"
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
    except PublicationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{where} is not valid UTF-8 JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{where} must be a JSON object")
    _reject_floats(value, where)
    if canonical_json(value) != data:
        fail(f"{where} is not canonical JSON")
    return value


def _open_regular(path: Path, where: str) -> tuple[BinaryIO, os.stat_result]:
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
            fail(f"{where} must be a regular file: {path}")
        return os.fdopen(descriptor, "rb"), information
    except BaseException:
        os.close(descriptor)
        raise


def read_regular(path: Path, where: str, *, maximum: int | None = None) -> bytes:
    stream, information = _open_regular(path, where)
    with stream:
        if maximum is not None and information.st_size > maximum:
            fail(f"{where} exceeds the {maximum}-byte limit")
        return stream.read()


def read_canonical_file(path: Path, where: str) -> tuple[dict[str, Any], bytes]:
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


def require_target(value: Any, where: str) -> str:
    if not isinstance(value, str) or TARGET_RE.fullmatch(value) is None:
        fail(f"{where} is not a closed target identifier")
    return value


def require_nonnegative_integer(value: Any, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        fail(f"{where} must be a non-negative integer")
    return value


def require_nonempty_string(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value:
        fail(f"{where} must be a non-empty string")
    return value


def validate_runtime_dependencies(value: Any, where: str) -> list[dict[str, str]]:
    if not isinstance(value, list) or not value:
        fail(f"{where} must be a non-empty array")
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
    if dependencies != expected:
        fail(f"{where} is not sorted by name and version")
    names = [item["name"] for item in dependencies]
    if len(names) != len(set(names)):
        fail(f"{where} contains duplicate dependency names")
    return dependencies


def validate_system_packages(value: Any, where: str) -> list[dict[str, str]]:
    if not isinstance(value, list) or not value:
        fail(f"{where} must be a non-empty array")
    packages: list[dict[str, str]] = []
    for index, raw in enumerate(value):
        item = require_fields(raw, {"name", "target", "version"}, f"{where}[{index}]")
        target = require_target(item["target"], f"{where}[{index}].target")
        if target not in CLOSED_TARGETS:
            fail(f"{where}[{index}] target is outside R4")
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
    if len(identities) != len(set(identities)):
        fail(f"{where} contains duplicate target/name identities")
    return sorted(
        packages, key=lambda item: (item["target"], item["name"], item["version"])
    )


def object_identity(value: dict[str, Any]) -> tuple[int, bytes, bytes]:
    target = value.get("target")
    return (
        1 if target is not None else 0,
        (target or "").encode("utf-8"),
        str(value.get("role", "")).encode("utf-8"),
    )


def validate_targets(value: Any, where: str) -> list[str]:
    if not isinstance(value, list) or not value:
        fail(f"{where} must be a non-empty array")
    targets = [
        require_target(item, f"{where}[{index}]") for index, item in enumerate(value)
    ]
    if targets != sorted(targets, key=lambda item: item.encode("utf-8")):
        fail(f"{where} must be byte-sorted")
    if len(targets) != len(set(targets)):
        fail(f"{where} must not contain duplicates")
    if targets != list(CLOSED_TARGETS):
        fail(
            f"{where} must equal the exact closed R4 target set {list(CLOSED_TARGETS)}"
        )
    return targets


def _source_path(raw: Any, base: Path, where: str) -> Path:
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        fail(f"{where} must be a non-empty path string")
    path = Path(raw)
    if not path.is_absolute():
        path = base / path
    try:
        information = path.lstat()
    except OSError as error:
        fail(f"cannot inspect {where} at {path}: {error}")
    if stat.S_ISLNK(information.st_mode) or not stat.S_ISREG(information.st_mode):
        fail(f"{where} must be a regular file and not a link: {path}")
    return path


def validate_spec(
    value: Any, *, base: Path
) -> tuple[dict[str, Any], list[tuple[str, str | None, Path]]]:
    spec = require_fields(value, {"schema", "targets", "objects"}, "publication spec")
    if spec["schema"] != SPEC_SCHEMA:
        fail(f"publication spec schema must be {SPEC_SCHEMA!r}")
    targets = validate_targets(spec["targets"], "publication spec.targets")
    raw_objects = spec["objects"]
    if not isinstance(raw_objects, list) or not raw_objects:
        fail("publication spec.objects must be a non-empty array")

    records: list[tuple[str, str | None, Path]] = []
    identities: list[tuple[int, bytes, bytes]] = []
    global_roles: set[str] = set()
    target_roles: dict[str, set[str]] = {target: set() for target in targets}
    for index, raw in enumerate(raw_objects):
        where = f"publication spec.objects[{index}]"
        if not isinstance(raw, dict):
            fail(f"{where} must be an object")
        role = raw.get("role")
        if not isinstance(role, str) or role not in ALL_ROLES:
            fail(f"{where}.role is not a permitted publication role")
        if role in GLOBAL_ROLES:
            item = require_fields(raw, {"path", "role"}, where)
            target = None
            if role in global_roles:
                fail(f"duplicate global publication role {role!r}")
            global_roles.add(role)
        else:
            item = require_fields(raw, {"path", "role", "target"}, where)
            target = require_target(item["target"], f"{where}.target")
            if target not in target_roles:
                fail(f"{where}.target is outside the closed target list")
            if role in target_roles[target]:
                fail(f"duplicate {role!r} for target {target!r}")
            target_roles[target].add(role)
        identities.append(object_identity(item))
        records.append(
            (role, target, _source_path(item["path"], base, f"{where}.path"))
        )

    if identities != sorted(identities):
        fail("publication spec.objects must be ordered by target and role")
    if global_roles != GLOBAL_ROLES:
        fail(
            "publication spec global roles differ; missing "
            f"{sorted(GLOBAL_ROLES - global_roles)}, unknown {sorted(global_roles - GLOBAL_ROLES)}"
        )
    for target in targets:
        if target_roles[target] != NATIVE_ROLES:
            fail(
                f"target {target!r} must have exactly one native executable and "
                "one native attestation"
            )
    return spec, records


def load_spec(path: Path) -> tuple[dict[str, Any], list[tuple[str, str | None, Path]]]:
    value, _ = read_canonical_file(path, "publication spec")
    return validate_spec(value, base=path.parent)


def object_path(digest: str) -> str:
    require_digest(digest, "object digest")
    return f"{OBJECT_ALGORITHM_DIRECTORY}/{digest[7:]}"


def expected_mode(role: str) -> str:
    return "0755" if role == "native-executable" else "0644"


def _copy_and_digest(source: Path, destination: Path, role: str) -> tuple[str, int]:
    stream, information = _open_regular(source, f"{role} source object")
    if role == "native-executable" and not information.st_mode & stat.S_IXUSR:
        stream.close()
        fail(f"native executable source is not executable: {source}")
    digest = hashlib.sha256()
    size = 0
    try:
        with stream, destination.open("xb") as output:
            while chunk := stream.read(READ_CHUNK):
                digest.update(chunk)
                size += len(chunk)
                output.write(chunk)
    except BaseException:
        if destination.exists():
            destination.unlink()
        raise
    return "sha256:" + digest.hexdigest(), size


def write_canonical(path: Path, value: Any, mode: int = 0o644) -> None:
    path.write_bytes(canonical_json(value))
    os.chmod(path, mode)


def validate_claim(value: Any) -> dict[str, Any]:
    claim = require_fields(
        value,
        {
            "component_complete_claim",
            "external_north_star_claim",
            "objects",
            "schema",
            "targets",
        },
        "publication claim",
    )
    if claim["schema"] != CLAIM_SCHEMA:
        fail(f"publication claim schema must be {CLAIM_SCHEMA!r}")
    if claim["component_complete_claim"] is not True:
        fail("publication claim must assert the bounded component-complete release")
    if claim["external_north_star_claim"] is not False:
        fail("publication claim must not assert the external North Star")
    targets = validate_targets(claim["targets"], "publication claim.targets")
    raw_objects = claim["objects"]
    if not isinstance(raw_objects, list) or not raw_objects:
        fail("publication claim.objects must be a non-empty array")

    identities: list[tuple[int, bytes, bytes]] = []
    global_roles: set[str] = set()
    target_roles: dict[str, set[str]] = {target: set() for target in targets}
    paths: dict[str, tuple[str, int]] = {}
    for index, raw in enumerate(raw_objects):
        where = f"publication claim.objects[{index}]"
        if not isinstance(raw, dict):
            fail(f"{where} must be an object")
        role = raw.get("role")
        if not isinstance(role, str) or role not in ALL_ROLES:
            fail(f"{where}.role is not a permitted publication role")
        fields = {"digest", "mode", "path", "role", "size_bytes"}
        target: str | None = None
        if role in NATIVE_ROLES:
            fields.add("target")
        item = require_fields(raw, fields, where)
        if role in GLOBAL_ROLES:
            if role in global_roles:
                fail(f"duplicate global publication role {role!r}")
            global_roles.add(role)
        else:
            target = require_target(item["target"], f"{where}.target")
            if target not in target_roles:
                fail(f"{where}.target is outside the closed target list")
            if role in target_roles[target]:
                fail(f"duplicate {role!r} for target {target!r}")
            target_roles[target].add(role)
        digest = require_digest(item["digest"], f"{where}.digest")
        if item["path"] != object_path(digest):
            fail(f"{where}.path is not the path derived from its digest")
        mode = expected_mode(role)
        if item["mode"] != mode:
            fail(f"{where}.mode must be {mode}")
        size = require_nonnegative_integer(item["size_bytes"], f"{where}.size_bytes")
        prior = paths.get(item["path"])
        if prior is not None and prior != (mode, size):
            fail(f"content-addressed object {item['path']} has conflicting metadata")
        paths[item["path"]] = (mode, size)
        identities.append(object_identity(item))

    if identities != sorted(identities):
        fail("publication claim.objects must be ordered by target and role")
    if len(identities) != len(set(identities)):
        fail("publication claim contains duplicate object identities")
    if global_roles != GLOBAL_ROLES:
        fail(
            f"publication claim is missing roles {sorted(GLOBAL_ROLES - global_roles)}"
        )
    for target in targets:
        if target_roles[target] != NATIVE_ROLES:
            fail(f"target {target!r} does not have exactly one native pair")
    return claim


def signing_payload(claim_bytes: bytes) -> dict[str, str]:
    return {
        "claim_digest": digest_bytes(claim_bytes),
        "publication_root_derivation": PUBLICATION_ROOT_SCHEMA,
        "schema": SIGNING_PAYLOAD_SCHEMA,
    }


def validate_signing_payload(value: Any, claim_bytes: bytes) -> dict[str, Any]:
    payload = require_fields(
        value,
        {"claim_digest", "publication_root_derivation", "schema"},
        "publication signing payload",
    )
    expected = signing_payload(claim_bytes)
    if canonical_json(payload) != canonical_json(expected):
        fail("publication signing payload does not exactly bind the canonical claim")
    return payload


def publication_root_descriptor(
    claim: dict[str, Any],
    claim_bytes: bytes,
    payload: dict[str, Any],
    policy_bytes: bytes,
    signatures: list[dict[str, Any]],
) -> dict[str, Any]:
    ordered = sorted(signatures, key=lambda item: item["key_id"])
    return {
        "claim_digest": digest_bytes(claim_bytes),
        "object_closure_digest": digest_bytes(canonical_json(claim["objects"])),
        "policy_digest": digest_bytes(policy_bytes),
        "schema": PUBLICATION_ROOT_SCHEMA,
        "signature_inventory": [
            {
                "key_id": signature["key_id"],
                "sha256": digest_bytes(canonical_json(signature)),
            }
            for signature in ordered
        ],
        "signing_payload_digest": digest_bytes(canonical_json(payload)),
    }


def validate_publication_root_descriptor(
    value: Any,
    claim: dict[str, Any],
    claim_bytes: bytes,
    payload: dict[str, Any],
    policy_bytes: bytes,
    signatures: list[dict[str, Any]],
) -> dict[str, Any]:
    descriptor = require_fields(
        value,
        {
            "claim_digest",
            "object_closure_digest",
            "policy_digest",
            "schema",
            "signature_inventory",
            "signing_payload_digest",
        },
        "publication root descriptor",
    )
    expected = publication_root_descriptor(
        claim, claim_bytes, payload, policy_bytes, signatures
    )
    if canonical_json(descriptor) != canonical_json(expected):
        fail(
            "publication root descriptor does not bind the exact claim, policy, "
            "signatures, and object closure"
        )
    return descriptor


def _walk_tree(root: Path) -> tuple[set[str], set[str]]:
    try:
        root_information = root.lstat()
    except OSError as error:
        fail(f"cannot inspect publication directory {root}: {error}")
    if stat.S_ISLNK(root_information.st_mode) or not stat.S_ISDIR(
        root_information.st_mode
    ):
        fail(f"publication path must be a directory and not a link: {root}")
    directories: set[str] = set()
    files: set[str] = set()

    def visit(directory: Path, prefix: str) -> None:
        try:
            children = sorted(
                directory.iterdir(), key=lambda path: path.name.encode("utf-8")
            )
        except OSError as error:
            fail(f"cannot enumerate publication directory {directory}: {error}")
        for child in children:
            relative = f"{prefix}/{child.name}" if prefix else child.name
            information = child.lstat()
            if stat.S_ISLNK(information.st_mode):
                fail(f"publication contains a symbolic link: {relative}")
            if stat.S_ISDIR(information.st_mode):
                directories.add(relative)
                visit(child, relative)
            elif stat.S_ISREG(information.st_mode):
                files.add(relative)
            else:
                fail(f"publication contains a special file: {relative}")

    visit(root, "")
    return directories, files


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


def _digest_file(path: Path, where: str) -> tuple[str, int]:
    stream, information = _open_regular(path, where)
    digest = hashlib.sha256()
    with stream:
        while chunk := stream.read(READ_CHUNK):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest(), information.st_size


def _governance_policy(value: dict[str, Any], where: str) -> dict[str, Any]:
    try:
        return GOVERNANCE.validate_policy(value, require_genesis=True, where=where)
    except GOVERNANCE.GovernanceError as error:
        fail(f"{where} is not a canonical genesis policy: {error}")


def _entry_by_role(
    claim: dict[str, Any], role: str, target: str | None = None
) -> dict[str, Any]:
    matches = [
        item
        for item in claim["objects"]
        if item["role"] == role and item.get("target") == target
    ]
    if len(matches) != 1:
        fail(
            f"claim does not contain exactly one {role!r} object for target {target!r}"
        )
    return matches[0]


def _validate_embedded_policy(root: Path, claim: dict[str, Any]) -> dict[str, Any]:
    entry = _entry_by_role(claim, "trust-policy")
    value, _ = read_canonical_file(root / entry["path"], "claimed trust policy")
    return _governance_policy(value, "claimed trust policy")


def _claimed_bytes(root: Path, claim: dict[str, Any], role: str) -> bytes:
    entry = _entry_by_role(claim, role)
    return read_regular(root / entry["path"], f"claimed {role}")


def _validate_release_public_key_bytes(data: bytes, where: str) -> bytes:
    if len(data) != 32:
        fail(f"{where} must be exactly 32 raw Ed25519 public-key bytes")
    return data


def _claimed_release_public_key(root: Path, claim: dict[str, Any]) -> bytes:
    data = _claimed_bytes(root, claim, "release-public-key")
    _validate_release_public_key_bytes(data, "claimed release public key")
    if _entry_by_role(claim, "release-public-key")["digest"] != digest_bytes(data):
        fail("claimed release public key digest differs from its raw bytes")
    return data


def _load_release_public_key(path: Path) -> bytes:
    data = read_regular(path, "independent release public key", maximum=32)
    return _validate_release_public_key_bytes(data, "independent release public key")


def _require_release_public_key_match(
    root: Path, claim: dict[str, Any], independent: bytes
) -> None:
    if _claimed_release_public_key(root, claim) != independent:
        fail("claimed release public key differs from the independently supplied key")


def _verify_archive_object(
    root: Path, claim: dict[str, Any], role: str
) -> tuple[dict[str, Any], Path]:
    entry = _entry_by_role(claim, role)
    path = root / entry["path"]
    try:
        digest, manifest, _ = ARCHIVE.verify_archive(path)
    except Exception as error:
        fail(f"claimed {role} is not a valid deterministic R4 archive: {error}")
    if digest != entry["digest"]:
        fail(f"claimed {role} archive verifier returned a different digest")
    return manifest, path


def _archive_member_bytes(path: Path, relative: str, where: str) -> bytes:
    name = f"payload/{relative}"
    try:
        with tarfile.open(path, mode="r:") as archive:
            members = [member for member in archive.getmembers() if member.name == name]
            if len(members) != 1 or not members[0].isfile():
                fail(f"{where} does not contain exactly one regular {relative}")
            stream = archive.extractfile(members[0])
            if stream is None:
                fail(f"{where} member {relative} has no body")
            return stream.read()
    except (OSError, tarfile.TarError) as error:
        fail(f"cannot inspect {where} member {relative}: {error}")


def _validate_source_archive(root: Path, claim: dict[str, Any]) -> str:
    manifest, path = _verify_archive_object(root, claim, "source-archive")
    entries = [
        item
        for item in manifest["entries"]
        if item.get("kind") == "file" and item.get("path") == "SOURCE-SNAPSHOT.json"
    ]
    if len(entries) != 1:
        fail("source archive does not contain exactly one SOURCE-SNAPSHOT.json")
    data = _archive_member_bytes(path, "SOURCE-SNAPSHOT.json", "source archive")
    snapshot = parse_canonical_object(data, "source archive SOURCE-SNAPSHOT.json")
    if snapshot.get("schema") != SOURCE_SNAPSHOT_SCHEMA:
        fail("source archive snapshot manifest schema differs")
    if snapshot.get("dependency_delivery") != (
        "complete Cargo registry source vendoring; no registry access required"
    ):
        fail("source archive does not declare the complete offline vendor closure")
    for field in ("source_closure_sha256", "vendor_closure_sha256"):
        require_digest(snapshot.get(field), f"source archive snapshot.{field}")
    if entries[0].get("sha256") != digest_bytes(data):
        fail("source archive manifest does not bind SOURCE-SNAPSHOT.json")
    return digest_bytes(data)


def _validate_component_release_archive(
    root: Path, claim: dict[str, Any], release_public_key: bytes
) -> dict[str, dict[str, str]]:
    manifest, path = _verify_archive_object(root, claim, "component-release-archive")
    file_paths = {
        item["path"] for item in manifest["entries"] if item.get("kind") == "file"
    }
    if "release.json" not in file_paths:
        fail("component-release archive has no release.json root")
    release_bytes = _archive_member_bytes(
        path, "release.json", "component-release archive"
    )
    release = parse_canonical_object(
        release_bytes, "component-release archive release.json"
    )
    if release.get("schema") != "wasm-biotic.component-complete-release-root.v1":
        fail("component-release archive release root schema differs")
    referenced: dict[str, bytes] = {}
    for field in ("claim_manifest", "claim_signature"):
        reference = release.get(field)
        reference = require_fields(
            reference, {"path", "sha256", "size_bytes"},
            f"component-release root {field}",
        )
        relative = reference.get("path")
        if not isinstance(relative, str) or relative not in file_paths:
            fail(f"component-release root {field} path is absent")
        body = _archive_member_bytes(path, relative, "component-release archive")
        if reference.get("sha256") != digest_bytes(body) or reference.get(
            "size_bytes"
        ) != len(body):
            fail(f"component-release root does not bind exact {field} bytes")
        referenced[field] = body
    claim_manifest = parse_canonical_object(
        referenced["claim_manifest"], "component-release claim manifest"
    )
    expected_key_id = digest_bytes(release_public_key)
    certifier = claim_manifest.get("certifier")
    if not isinstance(certifier, dict) or (
        certifier.get("algorithm"), certifier.get("key_id")
    ) != ("ed25519", expected_key_id):
        fail("component-release claim does not name the independent release key")
    signature = parse_canonical_object(
        referenced["claim_signature"],
        "component-release claim signature",
    )
    if (
        signature.get("schema") != "wasm-biotic.component-complete-claim-signature.v1"
        or signature.get("algorithm") != "ed25519"
        or signature.get("claim_manifest_digest") != release["claim_manifest"]["sha256"]
    ):
        fail("component-release claim signature does not bind the claim manifest")
    if signature.get("certifier_key_id") != expected_key_id:
        fail("component-release claim signature used a different release key")
    if (
        not isinstance(signature.get("signature_hex"), str)
        or re.fullmatch(r"[0-9a-f]{128}", signature["signature_hex"]) is None
    ):
        fail("component-release claim signature is malformed")
    claim_payload = canonical_json(
        {
            "claim_manifest_digest": release["claim_manifest"]["sha256"],
            "schema": COMPONENT_CLAIM_SIGNING_PAYLOAD_SCHEMA,
        }
    )
    try:
        GOVERNANCE._verify_bytes(
            release_public_key,
            claim_payload,
            bytes.fromhex(signature["signature_hex"]),
        )
    except Exception as error:
        fail(f"component-release claim signature did not verify: {error}")
    packages: dict[str, dict[str, str]] = {}
    with tempfile.TemporaryDirectory(prefix="r4-component-release-") as temporary:
        extracted = Path(temporary) / "release"
        try:
            ARCHIVE.extract_archive(path, extracted)
            verified_release_root = COMPONENT_RELEASE.verify_bundle(
                extracted,
                release_public_key.hex(),
                require_root_name=False,
            )
            if verified_release_root != digest_bytes(release_bytes):
                fail("component-release verifier returned a different release root")
            raw_trees = claim_manifest.get("trees")
            if not isinstance(raw_trees, list):
                fail("component-release claim has no content-addressed tree inventory")
            trees = [
                COMPONENT_RELEASE.parse_tree_ref(
                    item, f"component-release claim trees[{index}]"
                )
                for index, item in enumerate(raw_trees)
            ]
            COMPONENT_RELEASE.validate_sorted_unique_roles(
                trees, "component-release claim trees"
            )
            package_trees = {
                item["role"]: item
                for item in trees
                if item["role"].endswith("-package")
            }
            if set(package_trees) != {
                "incumbent-package",
                "successor-package",
            }:
                fail(
                    "component-release archive must retain exactly incumbent and successor package trees"
                )
            for kind, role in (
                ("incumbent", "incumbent-package"),
                ("successor", "successor-package"),
            ):
                expected, graph, authentication = (
                    COMPONENT_REPRODUCTION.expected_components(
                        extracted / package_trees[role]["path"] / "files",
                        release_public_key.hex(),
                    )
                )
                if len(expected) != 22:
                    fail(f"component-release {kind} package is not a 22-node closure")
                packages[kind] = {
                    "certification_sha256": authentication["certification_sha256"],
                    "graph_manifest_digest": graph,
                }
        except PublicationError:
            raise
        except Exception as error:
            fail(f"component-release signed package verification failed: {error}")
    identities = claim_manifest.get("identities")
    if not isinstance(identities, dict):
        fail("component-release claim has no release identity inventory")
    for kind in ("incumbent", "successor"):
        if packages[kind]["graph_manifest_digest"] != identities.get(
            f"{kind}_graph_manifest_digest"
        ):
            fail(f"component-release {kind} package tree is bound to the wrong role")
    if packages["incumbent"]["graph_manifest_digest"] == packages["successor"][
        "graph_manifest_digest"
    ]:
        fail("component-release incumbent and successor graph manifests are identical")
    return packages


def _validate_governance_report(
    root: Path, claim: dict[str, Any], policy: dict[str, Any]
) -> dict[str, Any]:
    data = _claimed_bytes(root, claim, "governance-report")
    report = parse_canonical_object(data, "governance report")
    if (
        report.get("schema") != GOVERNANCE_REPORT_SCHEMA
        or report.get("result") != "pass"
    ):
        fail("governance report schema/result differs")
    if report.get("policy_digest") != GOVERNANCE.policy_digest(policy):
        fail("governance report does not bind the claimed genesis policy")
    if (
        report.get("generation") != 1
        or report.get("threshold") != 2
        or report.get("active_key_count") != 3
    ):
        fail("governance report does not prove generation-1 2-of-3 custody")
    for field in (
        "release_quorum_verified",
        "publication_quorum_verified",
        "rotation_verified",
        "revocation_verified",
        "successor_proof_of_possession_verified",
    ):
        if report.get(field) is not True:
            fail(f"governance report did not verify {field}")
    if (
        report.get("private_key_dependency") is not False
        or report.get("blockers") != []
    ):
        fail("governance report has a private-key dependency or blockers")
    reroot = report.get("r3_re_root")
    if not isinstance(reroot, dict) or (
        reroot.get("kind"),
        reroot.get("r3_private_key_available"),
        reroot.get("r3_signed_rotation"),
    ) != ("out-of-band-genesis", False, False):
        fail("governance report misstates the R3 out-of-band genesis")
    require_digest(
        report.get("ceremony_manifest_sha256"), "governance ceremony manifest"
    )
    return report


def _validate_install_governance_ceremony(
    install_archive: Path,
    governance: dict[str, Any],
    policy: dict[str, Any],
) -> None:
    with tempfile.TemporaryDirectory(prefix="r4-publication-install-") as temporary:
        extracted = Path(temporary) / "install"
        try:
            ARCHIVE.extract_archive(install_archive, extracted)
            result = CEREMONY.verify_ceremony(extracted / "governance")
        except Exception as error:
            fail(
                f"install archive governance ceremony did not publicly verify: {error}"
            )
        ceremony_report = read_regular(
            extracted / "governance" / CEREMONY.REPORT_NAME,
            "install archive ceremony governance report",
        )
    if ceremony_report != canonical_json(governance):
        fail("install archive ceremony report differs from claimed governance report")
    if (
        result.get("ceremony_sha256") != governance["ceremony_manifest_sha256"]
        or result.get("report_sha256") != digest_bytes(canonical_json(governance))
        or result.get("policy_digest") != GOVERNANCE.policy_digest(policy)
    ):
        fail("install archive ceremony bindings differ from governance evidence")


def _validate_install_release_public_key(
    install_manifest: dict[str, Any], install_archive: Path, release_public_key: bytes
) -> None:
    relative = "public/r3-certifier-public-key.raw"
    entries = [
        item
        for item in install_manifest["entries"]
        if item.get("kind") == "file" and item.get("path") == relative
    ]
    if len(entries) != 1:
        fail("install archive does not retain exactly one raw R3 release public key")
    data = _archive_member_bytes(install_archive, relative, "install archive")
    if data != release_public_key or entries[0].get("sha256") != digest_bytes(data):
        fail("install archive release public key differs from the claimed raw key")


def _validate_sbom_pair(root: Path, claim: dict[str, Any]) -> list[dict[str, str]]:
    sbom_bytes = _claimed_bytes(root, claim, "spdx-sbom")
    coverage_bytes = _claimed_bytes(root, claim, "sbom-coverage")
    sbom = parse_canonical_object(sbom_bytes, "SPDX SBOM")
    coverage = parse_canonical_object(coverage_bytes, "SBOM coverage")
    if (
        sbom.get("spdxVersion") != "SPDX-2.3"
        or sbom.get("dataLicense") != "CC0-1.0"
        or not isinstance(sbom.get("files"), list)
        or not sbom["files"]
        or not isinstance(sbom.get("packages"), list)
        or not sbom["packages"]
    ):
        fail("SPDX SBOM is not a non-empty SPDX 2.3 document")
    if (
        coverage.get("schema") != SBOM_COVERAGE_SCHEMA
        or coverage.get("result") != "pass"
        or coverage.get("sbom_sha256") != digest_bytes(sbom_bytes)
    ):
        fail("SBOM coverage does not pass and bind the exact SPDX document")
    system_packages = validate_system_packages(
        coverage.get("system_packages"), "SBOM system package inventory"
    )
    if coverage.get("system_package_count") != len(system_packages):
        fail("SBOM system package count differs from its inventory")
    if {item["target"] for item in system_packages} != set(CLOSED_TARGETS):
        fail("SBOM system dependency target set differs from closed R4 targets")
    roles = coverage.get("artifact_roles")
    role_names = (
        {item.get("role") for item in roles if isinstance(item, dict)}
        if isinstance(roles, list)
        else set()
    )
    if not {"component-release-archive", "install-archive", "source-archive"}.issubset(
        role_names
    ):
        fail("SBOM coverage omits one or more required archives")
    for target in CLOSED_TARGETS:
        if not any(isinstance(role, str) and target in role for role in role_names):
            fail(f"SBOM coverage omits native executable {target}")
    return system_packages


def _validate_reproduction_matrix(root: Path, claim: dict[str, Any]) -> dict[str, Any]:
    data = _claimed_bytes(root, claim, "reproduction-matrix")
    matrix = parse_canonical_object(data, "reproduction matrix")
    if (
        matrix.get("schema") != REPRODUCTION_MATRIX_SCHEMA
        or matrix.get("phase") != "pre-publication"
        or matrix.get("result") != "pass"
        or matrix.get("component_complete_claim") is not True
        or matrix.get("external_north_star_claim") is not False
        or matrix.get("private_key_dependency") is not False
        or matrix.get("blockers") != []
        or matrix.get("targets") != list(CLOSED_TARGETS)
    ):
        fail(
            "reproduction matrix does not make the exact bounded pre-publication claim"
        )
    components = matrix.get("components")
    if (
        not isinstance(components, dict)
        or components.get("component_count") != 22
        or components.get("witness_count", 0) < 2
    ):
        fail("reproduction matrix does not prove 22/22 components on two witnesses")
    native = matrix.get("native")
    targets = native.get("targets") if isinstance(native, dict) else None
    if not isinstance(targets, list) or [
        item.get("target") for item in targets
    ] != list(CLOSED_TARGETS):
        fail("reproduction matrix native target set differs")
    if targets[0].get("witness_count", 0) < 2 or targets[1].get("witness_count", 0) < 1:
        fail("reproduction matrix native physical witness coverage is incomplete")
    return matrix


def _validate_public_lifecycle(
    root: Path,
    claim: dict[str, Any],
    matrix: dict[str, Any],
    release_public_key: bytes,
    packages: dict[str, dict[str, str]],
) -> None:
    data = _claimed_bytes(root, claim, "public-lifecycle-report")
    report = parse_canonical_object(data, "public install lifecycle report")
    if (
        report.get("schema") != PUBLIC_LIFECYCLE_SCHEMA
        or report.get("outcome") != "pass"
        or report.get("private_key_argument_supported") is not False
        or report.get("private_key_required_or_read") is not False
    ):
        fail("public lifecycle report did not pass without private keys")
    archive = report.get("archive")
    if not isinstance(archive, dict) or (
        archive.get("install_archive_sha256")
        != _entry_by_role(claim, "install-archive")["digest"]
        or archive.get("safe_archive_verifier_passed") is not True
        or archive.get("extracted_tree_exactly_matches_manifest") is not True
    ):
        fail("public lifecycle report does not bind the verified install archive")
    host = report.get("host")
    if not isinstance(host, dict):
        fail("public lifecycle report has no physical host evidence")
    target = host.get("target")
    witness_id = host.get("witness_id")
    if (
        target not in CLOSED_TARGETS
        or host.get("physical_machine") is not True
        or not isinstance(witness_id, str)
        or WITNESS_RE.fullmatch(witness_id) is None
    ):
        fail("public lifecycle report is not bound to a named physical witness")
    kernel = report.get("kernel")
    native = next(
        item for item in matrix["native"]["targets"] if item["target"] == target
    )
    if not isinstance(kernel, dict) or (
        kernel.get("expected_sha256"),
        kernel.get("observed_sha256"),
    ) != (native.get("binary_sha256"), native.get("binary_sha256")):
        fail("public lifecycle report does not execute the matrix native binary")
    operator_capacity = report.get("operator_capacity")
    if not isinstance(operator_capacity, dict) or (
        set(operator_capacity),
        operator_capacity.get("within_verified_install"),
    ) != ({"observed_sha256", "within_verified_install"}, True):
        fail("public lifecycle report does not bind installed operator capacity")
    require_digest(
        operator_capacity.get("observed_sha256"),
        "public lifecycle operator capacity",
    )
    if (
        matrix.get("public_lifecycle", {}).get("operator_capacity_sha256")
        != operator_capacity["observed_sha256"]
    ):
        fail("reproduction matrix does not bind public lifecycle operator capacity")
    negative = report.get("negative_controls")
    if not isinstance(negative, dict) or any(
        negative.get(field) is not True
        for field in (
            "automatic_successor_activation_rejected",
            "tampered_package_rejected",
            "wrong_public_key_rejected",
        )
    ):
        fail("public lifecycle negative controls did not pass")
    component_lifecycle = report.get("component_lifecycle_report")
    if not isinstance(component_lifecycle, dict):
        fail("public lifecycle did not retain its component lifecycle report")
    component_lifecycle_digest = digest_bytes(canonical_json(component_lifecycle))
    if report.get("component_lifecycle_report_sha256") != component_lifecycle_digest:
        fail("public lifecycle retained component report digest differs")
    incumbent_digest = report.get("incumbent_graph_manifest_digest")
    successor_digest = report.get("successor_graph_manifest_digest")
    if (
        incumbent_digest != packages["incumbent"]["graph_manifest_digest"]
        or successor_digest != packages["successor"]["graph_manifest_digest"]
    ):
        fail("public lifecycle graph pair differs from the signed archived packages")
    try:
        PUBLIC_INSTALL.validate_component_lifecycle(
            component_lifecycle,
            incumbent_digest=incumbent_digest,
            successor_digest=successor_digest,
            public_key_hex=release_public_key.hex(),
            operator_capacity_sha256=operator_capacity["observed_sha256"],
        )
    except Exception as error:
        fail(f"retained component lifecycle evidence did not verify: {error}")
    matrix_lifecycle = matrix.get("public_lifecycle", {})
    if (
        matrix_lifecycle.get("component_lifecycle_report_sha256")
        != component_lifecycle_digest
        or matrix_lifecycle.get("incumbent_graph_manifest_digest")
        != incumbent_digest
        or matrix_lifecycle.get("successor_graph_manifest_digest")
        != successor_digest
    ):
        fail("reproduction matrix does not bind the retained component lifecycle")


def _validate_matrix_bindings(
    root: Path,
    claim: dict[str, Any],
    matrix: dict[str, Any],
    source_snapshot_digest: str,
    native_evidence: dict[str, dict[str, Any]],
    system_packages: list[dict[str, str]],
) -> None:
    bindings = {
        "component-release-archive": matrix.get("archives", {})
        .get("component-release-archive", {})
        .get("sha256"),
        "governance-report": matrix.get("governance", {}).get("report_sha256"),
        "install-archive": matrix.get("archives", {})
        .get("install-archive", {})
        .get("sha256"),
        "public-lifecycle-report": matrix.get("public_lifecycle", {}).get(
            "report_sha256"
        ),
        "r4-contract": matrix.get("contract", {}).get("sha256"),
        "sbom-coverage": matrix.get("sbom", {}).get("coverage_sha256"),
        "source-archive": matrix.get("archives", {})
        .get("source-archive", {})
        .get("sha256"),
        "spdx-sbom": matrix.get("sbom", {}).get("spdx_sha256"),
    }
    for role, digest in bindings.items():
        require_digest(digest, f"reproduction matrix binding for {role}")
        if _entry_by_role(claim, role)["digest"] != digest:
            fail(f"reproduction matrix does not bind the claimed {role}")
    if (
        matrix.get("source_snapshot", {}).get("manifest_sha256")
        != source_snapshot_digest
        or matrix.get("native", {}).get("source_snapshot_manifest_sha256")
        != source_snapshot_digest
    ):
        fail("reproduction matrix does not bind the authoritative source snapshot")
    matrix_system_packages = validate_system_packages(
        matrix.get("sbom", {}).get("system_packages"),
        "reproduction matrix SBOM system packages",
    )
    if matrix_system_packages != system_packages:
        fail("reproduction matrix SBOM system packages differ from coverage")
    for target in CLOSED_TARGETS:
        evidence = next(
            item for item in matrix["native"]["targets"] if item["target"] == target
        )
        if (
            native_evidence[target]["source_snapshot_manifest_sha256"]
            != source_snapshot_digest
        ):
            fail(f"native attestation source snapshot differs for {target}")
        if _entry_by_role(claim, "native-executable", target)["digest"] != evidence.get(
            "binary_sha256"
        ):
            fail(f"reproduction matrix does not bind native executable {target}")
        reports = {
            item.get("report_sha256")
            for item in evidence.get("witnesses", [])
            if isinstance(item, dict)
        }
        if _entry_by_role(claim, "native-attestation", target)["digest"] not in reports:
            fail(
                f"claimed native attestation is not a reproduction witness for {target}"
            )
        dependencies = validate_runtime_dependencies(
            evidence.get("runtime_dependencies"),
            f"reproduction matrix runtime dependencies for {target}",
        )
        if dependencies != native_evidence[target]["runtime_dependencies"]:
            fail(f"reproduction matrix runtime dependencies differ for {target}")
        matching_witnesses = [
            item
            for item in evidence.get("witnesses", [])
            if isinstance(item, dict)
            and item.get("report_sha256")
            == _entry_by_role(claim, "native-attestation", target)["digest"]
        ]
        if len(matching_witnesses) != 1:
            fail(f"matrix does not identify one published native witness for {target}")
        witness = matching_witnesses[0]
        if (
            witness.get("witness_id") != native_evidence[target]["witness_id"]
            or witness.get("source_snapshot_manifest_sha256") != source_snapshot_digest
            or witness.get("runtime_dependencies") != dependencies
        ):
            fail(f"matrix published witness binding differs for {target}")
    attested_packages = sorted(
        (
            {"name": item["name"], "target": target, "version": item["version"]}
            for target, evidence in native_evidence.items()
            for item in evidence["runtime_dependencies"]
        ),
        key=lambda item: (item["target"], item["name"], item["version"]),
    )
    if attested_packages != system_packages:
        fail("native runtime dependencies do not exactly match SBOM system packages")


def _validate_evidence_semantics(
    root: Path,
    claim: dict[str, Any],
    native_evidence: dict[str, dict[str, Any]],
) -> None:
    install_manifest, install_archive = _verify_archive_object(
        root, claim, "install-archive"
    )
    release_public_key = _claimed_release_public_key(root, claim)
    _validate_install_release_public_key(
        install_manifest, install_archive, release_public_key
    )
    source_snapshot_digest = _validate_source_archive(root, claim)
    packages = _validate_component_release_archive(root, claim, release_public_key)
    contract = _claimed_bytes(root, claim, "r4-contract")
    if digest_bytes(contract) != FROZEN_CONTRACT_DIGEST:
        fail("claimed R4 contract is not the exact frozen contract")
    policy = _validate_embedded_policy(root, claim)
    governance = _validate_governance_report(root, claim, policy)
    _validate_install_governance_ceremony(install_archive, governance, policy)
    system_packages = _validate_sbom_pair(root, claim)
    matrix = _validate_reproduction_matrix(root, claim)
    matrix_components = matrix.get("components", {})
    archived_authentication = {
        (
            package["graph_manifest_digest"],
            package["certification_sha256"],
        )
        for package in packages.values()
    }
    if (
        matrix_components.get("release_certifier_key_id")
        != digest_bytes(release_public_key)
        or (
            matrix_components.get("graph_manifest_digest"),
            matrix_components.get("release_certification_sha256"),
        )
        not in archived_authentication
    ):
        fail("reproduction matrix component witnesses do not bind a signed archived package")
    if matrix.get("governance", {}).get("policy_digest") != GOVERNANCE.policy_digest(
        policy
    ) or matrix.get("governance", {}).get("report_sha256") != digest_bytes(
        canonical_json(governance)
    ):
        fail("reproduction matrix governance evidence differs")
    if (
        matrix.get("governance", {}).get("ceremony_manifest_sha256")
        != governance["ceremony_manifest_sha256"]
    ):
        fail("reproduction matrix governance ceremony binding differs")
    _validate_matrix_bindings(
        root,
        claim,
        matrix,
        source_snapshot_digest,
        native_evidence,
        system_packages,
    )
    _validate_public_lifecycle(
        root, claim, matrix, release_public_key, packages
    )


def _validate_native_pairs(
    root: Path, claim: dict[str, Any]
) -> dict[str, dict[str, Any]]:
    validated: dict[str, dict[str, Any]] = {}
    for target in claim["targets"]:
        executable = _entry_by_role(claim, "native-executable", target)
        attestation = _entry_by_role(claim, "native-attestation", target)
        value, _ = read_canonical_file(
            root / attestation["path"], f"native attestation for {target}"
        )
        if value.get("schema") != NATIVE_ATTESTATION_SCHEMA:
            fail(f"native attestation for {target} has an unsupported schema")
        if value.get("gate_result") != "pass":
            fail(f"native attestation for {target} did not pass")
        if value.get("component_complete_claim") is not False:
            fail(
                f"native attestation for {target} must not claim component completeness"
            )
        witness = require_fields(
            value.get("witness"),
            {"id", "physical_machine"},
            f"native witness for {target}",
        )
        witness_id = witness.get("id")
        if (
            not isinstance(witness_id, str)
            or WITNESS_RE.fullmatch(witness_id) is None
            or witness.get("physical_machine") is not True
        ):
            fail(f"native attestation for {target} is not a named physical witness")
        platform = value.get("platform")
        if not isinstance(platform, dict) or platform.get("target") != target:
            fail(f"native attestation platform does not match target {target!r}")
        expected_platform = {
            "aarch64-apple-darwin": ("macos", "aarch64", "Mach-O"),
            "x86_64-unknown-linux-gnu": ("linux", "x86_64", "ELF"),
        }[target]
        if (
            platform.get("os"),
            platform.get("architecture"),
            platform.get("binary_format"),
        ) != expected_platform:
            fail(
                f"native attestation has the wrong OS/architecture/format for {target}"
            )
        artifact = value.get("native_artifact")
        if not isinstance(artifact, dict):
            fail(f"native attestation for {target} has no native_artifact")
        if artifact.get("sha256") != executable["digest"]:
            fail(f"native attestation for {target} does not bind its executable digest")
        if artifact.get("size_bytes") != executable["size_bytes"]:
            fail(f"native attestation for {target} does not bind its executable size")
        runtime_dependencies = validate_runtime_dependencies(
            artifact.get("runtime_dependencies"),
            f"native runtime dependencies for {target}",
        )
        expected_upstream_path = "objects/" + executable["digest"].replace(":", "-", 1)
        if artifact.get("path") != expected_upstream_path:
            fail(f"native attestation for {target} has a substituted artifact path")
        executable_bytes = read_regular(
            root / executable["path"], f"native executable for {target}"
        )
        if target == "aarch64-apple-darwin":
            if not executable_bytes.startswith(bytes.fromhex("cffaedfe")):
                fail("aarch64 macOS native executable is not a 64-bit Mach-O file")
            metadata = artifact.get("platform_metadata")
            if not isinstance(metadata, dict) or metadata.get("format") != "Mach-O":
                fail("macOS native attestation lacks Mach-O platform metadata")
        else:
            if not executable_bytes.startswith(b"\x7fELF"):
                fail("x86-64 Linux native executable is not an ELF file")
            metadata = artifact.get("platform_metadata")
            if not isinstance(metadata, dict) or metadata.get("format") != "ELF":
                fail("Linux native attestation lacks ELF platform metadata")
        source = value.get("source")
        closure = source.get("closure") if isinstance(source, dict) else None
        if not isinstance(closure, dict):
            fail(f"native attestation for {target} has no source closure")
        source_closure_digest = require_digest(
            closure.get("sha256"), f"native source closure for {target}"
        )
        snapshot = require_fields(
            source.get("snapshot_manifest"),
            {"schema", "sha256"},
            f"native source snapshot for {target}",
        )
        if snapshot["schema"] != SOURCE_SNAPSHOT_SCHEMA:
            fail(f"native source snapshot schema differs for {target}")
        source_snapshot_digest = require_digest(
            snapshot["sha256"], f"native source snapshot for {target}"
        )
        compiled = value.get("compiled_inventory")
        embedding = (
            compiled.get("binary_embedding") if isinstance(compiled, dict) else None
        )
        if (
            not isinstance(compiled, dict)
            or compiled.get("schema") != "wasm-biotic.native-tcb-inventory.v1"
            or compiled.get("source_revision") != source_closure_digest
            or not isinstance(embedding, dict)
            or embedding.get("result") != "pass"
            or embedding.get("occurrences") != 1
        ):
            fail(f"native attestation TCB inventory does not bind source for {target}")
        require_digest(compiled.get("sha256"), f"native TCB inventory for {target}")
        recipe = value.get("build_recipe")
        if not isinstance(recipe, dict):
            fail(f"native attestation for {target} has no build recipe")
        require_digest(recipe.get("sha256"), f"native build recipe for {target}")
        reproduction = value.get("reproduction")
        if not isinstance(reproduction, dict):
            fail(f"native attestation for {target} has no reproduction proof")
        if (
            reproduction.get("result") != "pass"
            or reproduction.get("clean_builds") != 2
            or reproduction.get("target_directory_shapes")
            != ["short", "materially-long"]
            or reproduction.get("exact_complete_binary_match") is not True
            or reproduction.get("binary_sha256") != executable["digest"]
            or reproduction.get("physical_build_paths_embedded") is not False
        ):
            fail(f"native attestation for {target} does not prove exact reproduction")
        execution = reproduction.get("execution_verification")
        if (
            not isinstance(execution, dict)
            or execution.get("invoked") is not True
            or execution.get("process_loaded") is not True
            or execution.get("expected_usage_error") is not True
            or execution.get("result") != "pass"
        ):
            fail(f"native attestation for {target} does not prove execution")
        if target == CLOSED_TARGETS[0]:
            canonicalization = reproduction.get("platform_identity_canonicalization")
            if (
                not isinstance(canonicalization, dict)
                or canonicalization.get("result") != "pass"
                or canonicalization.get(
                    "linked_artifacts_equal_outside_allowed_regions"
                )
                is not True
            ):
                fail(
                    "macOS native attestation does not prove identity canonicalization"
                )
        reference = value.get("reference_digest_verification")
        if not isinstance(reference, dict) or reference.get("match") is not True:
            fail(f"native reference digest differs for {target}")
        validated[target] = {
            "runtime_dependencies": runtime_dependencies,
            "source_snapshot_manifest_sha256": source_snapshot_digest,
            "witness_id": witness_id,
        }
    return validated


def _base_documents(root: Path) -> tuple[dict[str, Any], bytes, dict[str, Any]]:
    claim, claim_bytes = read_canonical_file(root / CLAIM_NAME, "publication claim")
    validate_claim(claim)
    payload, _ = read_canonical_file(
        root / SIGNING_PAYLOAD_NAME, "publication signing payload"
    )
    validate_signing_payload(payload, claim_bytes)
    return claim, claim_bytes, payload


def _validate_tree(
    root: Path,
    claim: dict[str, Any],
    *,
    signature_paths: set[str] | None,
) -> None:
    directories, files = _walk_tree(root)
    expected_directories = {OBJECT_DIRECTORY, OBJECT_ALGORITHM_DIRECTORY}
    if signature_paths is not None:
        expected_directories.add(SIGNATURE_DIRECTORY)
    expected_files = {CLAIM_NAME, SIGNING_PAYLOAD_NAME}
    expected_files.update(item["path"] for item in claim["objects"])
    if signature_paths is not None:
        expected_files.add(PUBLICATION_ROOT_NAME)
        expected_files.update(signature_paths)
    if directories != expected_directories:
        fail(
            f"publication directory closure differs: expected {sorted(expected_directories)}, "
            f"found {sorted(directories)}"
        )
    if files != expected_files:
        fail(
            f"publication file closure differs: missing {sorted(expected_files - files)}, "
            f"extra {sorted(files - expected_files)}"
        )
    for relative in ("", *sorted(expected_directories)):
        path = root if not relative else root / relative
        if _mode(path) != 0o755:
            fail(f"publication directory has non-canonical mode: {relative or '.'}")
    metadata_files = [CLAIM_NAME, SIGNING_PAYLOAD_NAME]
    if signature_paths is not None:
        metadata_files.append(PUBLICATION_ROOT_NAME)
    for relative in metadata_files:
        if _mode(root / relative) != 0o644:
            fail(f"publication metadata has non-canonical mode: {relative}")
    for entry in claim["objects"]:
        path = root / entry["path"]
        wanted_mode = int(entry["mode"], 8)
        if _mode(path) != wanted_mode:
            fail(f"publication object has non-canonical mode: {entry['path']}")
        digest, size = _digest_file(path, f"publication object {entry['path']}")
        if digest != entry["digest"] or size != entry["size_bytes"]:
            fail(f"publication object content differs from claim: {entry['path']}")
    if signature_paths is not None:
        for relative in signature_paths:
            if _mode(root / relative) != 0o644:
                fail(f"publication signature has non-canonical mode: {relative}")


def validate_staging(root: Path) -> tuple[dict[str, Any], bytes, dict[str, Any]]:
    claim, claim_bytes, payload = _base_documents(root)
    _validate_tree(root, claim, signature_paths=None)
    native_evidence = _validate_native_pairs(root, claim)
    _validate_evidence_semantics(root, claim, native_evidence)
    return claim, claim_bytes, payload


def _remove_temporary(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)


def prepare(spec_path: Path, staging: Path) -> tuple[str, Path]:
    spec, records = load_spec(spec_path)
    if staging.exists() or staging.is_symlink():
        fail(f"staging path already exists: {staging}")
    staging.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{staging.name}.tmp-", dir=staging.parent)
    )
    os.chmod(temporary, 0o755)
    try:
        object_root = temporary / OBJECT_ALGORITHM_DIRECTORY
        object_root.mkdir(parents=True)
        os.chmod(temporary / OBJECT_DIRECTORY, 0o755)
        os.chmod(object_root, 0o755)
        entries: list[dict[str, Any]] = []
        stored_modes: dict[str, str] = {}
        for index, (role, target, source) in enumerate(records):
            incoming = object_root / f".incoming-{index}"
            digest, size = _copy_and_digest(source, incoming, role)
            relative = object_path(digest)
            destination = temporary / relative
            mode = expected_mode(role)
            prior_mode = stored_modes.get(relative)
            if destination.exists():
                incoming.unlink()
                if prior_mode != mode:
                    fail(
                        f"object {digest} is requested with conflicting normalized modes"
                    )
            else:
                os.replace(incoming, destination)
                os.chmod(destination, int(mode, 8))
                stored_modes[relative] = mode
            entry: dict[str, Any] = {
                "digest": digest,
                "mode": mode,
                "path": relative,
                "role": role,
                "size_bytes": size,
            }
            if target is not None:
                entry["target"] = target
            entries.append(entry)
        entries.sort(key=object_identity)
        claim = {
            "component_complete_claim": True,
            "external_north_star_claim": False,
            "objects": entries,
            "schema": CLAIM_SCHEMA,
            "targets": spec["targets"],
        }
        validate_claim(claim)
        claim_bytes = canonical_json(claim)
        write_canonical(temporary / CLAIM_NAME, claim)
        write_canonical(temporary / SIGNING_PAYLOAD_NAME, signing_payload(claim_bytes))
        validate_staging(temporary)
        root = digest_bytes(claim_bytes)
        os.replace(temporary, staging)
        return root, staging
    except BaseException:
        _remove_temporary(temporary)
        raise


def _load_external_policy(path: Path) -> tuple[dict[str, Any], bytes]:
    value, data = read_canonical_file(path, "independent genesis policy")
    return _governance_policy(value, "independent genesis policy"), data


def _require_policy_match(
    root: Path, claim: dict[str, Any], policy_bytes: bytes
) -> None:
    entry = _entry_by_role(claim, "trust-policy")
    claimed = read_regular(root / entry["path"], "claimed trust policy")
    if claimed != policy_bytes:
        fail("claimed trust-policy object differs from the independent genesis policy")


def _load_signatures(paths: list[Path]) -> list[dict[str, Any]]:
    signatures: list[dict[str, Any]] = []
    for index, path in enumerate(paths):
        try:
            signature = GOVERNANCE.load_detached_signature(path)
        except GOVERNANCE.GovernanceError as error:
            fail(f"detached release signature {index} is invalid: {error}")
        signatures.append(signature)
    return sorted(signatures, key=lambda item: item["key_id"])


def _verify_quorum(
    policy: dict[str, Any], payload: dict[str, Any], signatures: list[dict[str, Any]]
) -> list[str]:
    try:
        return GOVERNANCE.verify_release_quorum(policy, payload, signatures)
    except GOVERNANCE.GovernanceError as error:
        fail(f"detached release quorum is invalid: {error}")


def _copy_file(source: Path, destination: Path, mode: int) -> None:
    stream, _ = _open_regular(source, f"publication source {source}")
    with stream, destination.open("xb") as output:
        shutil.copyfileobj(stream, output, length=READ_CHUNK)
    os.chmod(destination, mode)


def assemble(
    staging: Path,
    policy_path: Path,
    release_public_key_path: Path,
    signature_paths: list[Path],
    publish_root: Path,
) -> Path:
    claim, claim_bytes, payload = validate_staging(staging)
    policy, policy_bytes = _load_external_policy(policy_path)
    _require_policy_match(staging, claim, policy_bytes)
    release_public_key = _load_release_public_key(release_public_key_path)
    _require_release_public_key_match(staging, claim, release_public_key)
    signatures = _load_signatures(signature_paths)
    _verify_quorum(policy, payload, signatures)

    root_value = publication_root_descriptor(
        claim, claim_bytes, payload, policy_bytes, signatures
    )
    publication_root = digest_bytes(canonical_json(root_value))
    final = publish_root / publication_root.replace(":", "-", 1)
    if publish_root.exists():
        information = publish_root.lstat()
        if stat.S_ISLNK(information.st_mode) or not stat.S_ISDIR(information.st_mode):
            fail(f"publish root is not a directory or is a link: {publish_root}")
    else:
        publish_root.mkdir(parents=True)
        os.chmod(publish_root, 0o755)
    if final.exists() or final.is_symlink():
        fail(f"publication already exists: {final}")

    temporary = Path(tempfile.mkdtemp(prefix=f".{final.name}.tmp-", dir=publish_root))
    os.chmod(temporary, 0o755)
    try:
        (temporary / OBJECT_ALGORITHM_DIRECTORY).mkdir(parents=True)
        (temporary / SIGNATURE_DIRECTORY).mkdir()
        os.chmod(temporary / OBJECT_DIRECTORY, 0o755)
        os.chmod(temporary / OBJECT_ALGORITHM_DIRECTORY, 0o755)
        os.chmod(temporary / SIGNATURE_DIRECTORY, 0o755)
        _copy_file(staging / CLAIM_NAME, temporary / CLAIM_NAME, 0o644)
        _copy_file(
            staging / SIGNING_PAYLOAD_NAME,
            temporary / SIGNING_PAYLOAD_NAME,
            0o644,
        )
        copied: set[str] = set()
        for entry in claim["objects"]:
            if entry["path"] in copied:
                continue
            copied.add(entry["path"])
            _copy_file(
                staging / entry["path"],
                temporary / entry["path"],
                int(entry["mode"], 8),
            )
        for signature in signatures:
            name = f"{signature['key_id'][7:]}.json"
            write_canonical(temporary / SIGNATURE_DIRECTORY / name, signature)
        write_canonical(temporary / PUBLICATION_ROOT_NAME, root_value)
        _verify_publication(
            temporary,
            policy,
            policy_bytes,
            release_public_key,
            check_name=False,
        )
        os.replace(temporary, final)
        return final
    except BaseException:
        _remove_temporary(temporary)
        raise


def _publication_signature_paths(root: Path) -> set[str]:
    directory = root / SIGNATURE_DIRECTORY
    try:
        entries = sorted(
            directory.iterdir(), key=lambda path: path.name.encode("utf-8")
        )
    except OSError as error:
        fail(f"cannot enumerate detached signatures: {error}")
    paths: set[str] = set()
    for path in entries:
        if SIGNATURE_FILE_RE.fullmatch(path.name) is None:
            fail(f"publication has a non-canonical signature name: {path.name}")
        paths.add(f"{SIGNATURE_DIRECTORY}/{path.name}")
    return paths


def _verify_publication(
    root: Path,
    policy: dict[str, Any],
    policy_bytes: bytes,
    release_public_key: bytes,
    *,
    check_name: bool,
) -> dict[str, Any]:
    claim, claim_bytes, payload = _base_documents(root)
    signature_paths = _publication_signature_paths(root)
    _validate_tree(root, claim, signature_paths=signature_paths)
    _require_policy_match(root, claim, policy_bytes)
    _require_release_public_key_match(root, claim, release_public_key)
    native_evidence = _validate_native_pairs(root, claim)
    _validate_evidence_semantics(root, claim, native_evidence)

    signatures: list[dict[str, Any]] = []
    for relative in sorted(signature_paths):
        value, _ = read_canonical_file(
            root / relative, f"detached signature {relative}"
        )
        try:
            signature = GOVERNANCE.validate_detached_signature(value, relative)
        except GOVERNANCE.GovernanceError as error:
            fail(f"detached signature {relative} is invalid: {error}")
        if relative != f"{SIGNATURE_DIRECTORY}/{signature['key_id'][7:]}.json":
            fail(f"detached signature filename does not match signer key: {relative}")
        signatures.append(signature)
    signers = _verify_quorum(
        policy, payload, sorted(signatures, key=lambda item: item["key_id"])
    )
    root_value, root_bytes = read_canonical_file(
        root / PUBLICATION_ROOT_NAME, "publication root descriptor"
    )
    validate_publication_root_descriptor(
        root_value,
        claim,
        claim_bytes,
        payload,
        policy_bytes,
        signatures,
    )
    publication_root = digest_bytes(root_bytes)
    if check_name and root.name != publication_root.replace(":", "-", 1):
        fail("publication directory name does not match the canonical publication root")
    return {
        "claim_digest": digest_bytes(claim_bytes),
        "object_count": len(claim["objects"]),
        "publication_root": publication_root,
        "schema": CLAIM_SCHEMA,
        "signer_count": len(signers),
        "targets": claim["targets"],
    }


def verify(
    publication: Path, policy_path: Path, release_public_key_path: Path
) -> dict[str, Any]:
    policy, policy_bytes = _load_external_policy(policy_path)
    release_public_key = _load_release_public_key(release_public_key_path)
    return _verify_publication(
        publication,
        policy,
        policy_bytes,
        release_public_key,
        check_name=True,
    )


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(description=__doc__)
    subcommands = command.add_subparsers(dest="command", required=True)

    prepare_command = subcommands.add_parser(
        "prepare", help="copy a closed publication spec into object staging"
    )
    prepare_command.add_argument("--spec", required=True, type=Path)
    prepare_command.add_argument("--staging", required=True, type=Path)

    assemble_command = subcommands.add_parser(
        "assemble", help="verify detached release signatures and publish atomically"
    )
    assemble_command.add_argument("--staging", required=True, type=Path)
    assemble_command.add_argument("--policy", required=True, type=Path)
    assemble_command.add_argument("--release-public-key", required=True, type=Path)
    assemble_command.add_argument(
        "--signature", required=True, action="append", type=Path
    )
    assemble_command.add_argument("--publish-root", required=True, type=Path)

    verify_command = subcommands.add_parser(
        "verify", help="verify a publication from an independently obtained policy"
    )
    verify_command.add_argument("--publication", required=True, type=Path)
    verify_command.add_argument("--policy", required=True, type=Path)
    verify_command.add_argument("--release-public-key", required=True, type=Path)
    return command


def main(arguments: list[str] | None = None) -> int:
    options = parser().parse_args(arguments)
    try:
        if options.command == "prepare":
            root, staging = prepare(options.spec, options.staging)
            print(f"prepared {root} {staging}")
        elif options.command == "assemble":
            publication = assemble(
                options.staging,
                options.policy,
                options.release_public_key,
                options.signature,
                options.publish_root,
            )
            print(f"published {publication.name} {publication}")
        else:
            report = verify(
                options.publication, options.policy, options.release_public_key
            )
            print(
                f"verified {report['publication_root']} "
                f"objects={report['object_count']} signers={report['signer_count']}"
            )
        return 0
    except (PublicationError, OSError) as error:
        print(f"r4-publication: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
