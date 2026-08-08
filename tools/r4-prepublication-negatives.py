#!/usr/bin/env python3
"""Execute and reproduce every R4 pre-publication negative control.

The input spec names only public release inputs.  ``run`` verifies the pristine
inputs, performs real isolated mutations/commands, and emits canonical evidence.
``verify`` repeats those operations and requires byte-identical evidence.  The
runner never accepts a private key and does not retain physical input paths.
"""

from __future__ import annotations

import argparse
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import Any, Callable, NoReturn


INPUT_SCHEMA = "wasm-biotic.r4-prepublication-negative-input.v1"
REPORT_SCHEMA = "wasm-biotic.r4-prepublication-negative-controls.v1"
ARCHIVE_ROLES = (
    "component-release-archive",
    "install-archive",
    "source-archive",
)
ARCHIVE_CONTROLS = (
    "duplicate_rejected",
    "extra_rejected",
    "missing_rejected",
    "mutated_rejected",
    "noncanonical_rejected",
    "traversal_rejected",
    "truncated_rejected",
)
GOVERNANCE_CONTROLS = (
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
)
SBOM_CONTROLS = (
    "omitted_file_rejected",
    "omitted_package_rejected",
    "phantom_file_rejected",
    "phantom_package_rejected",
    "wrong_digest_rejected",
)
LIFECYCLE_CONTROLS = (
    "automatic_activation_rejected",
    "private_key_argument_absent",
    "tampered_package_rejected",
    "wrong_key_rejected",
)
PUBLIC_KEY_HEX_LENGTH = 64
MAX_JSON_BYTES = 64 * 1024 * 1024


class NegativeControlError(RuntimeError):
    """A pristine input failed or an attack was accepted."""


def fail(message: str) -> NoReturn:
    raise NegativeControlError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def load_tool(filename: str, module_name: str) -> Any:
    path = Path(__file__).with_name(filename)
    specification = importlib.util.spec_from_file_location(module_name, path)
    require(
        specification is not None and specification.loader is not None,
        f"cannot load required negative-control tool at {path}",
    )
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


ARCHIVE = load_tool("r4-install-archive.py", "wasm_biotic_r4_negative_archive")
GOVERNANCE = load_tool(
    "r4-certifier-governance.py", "wasm_biotic_r4_negative_governance"
)
CEREMONY = load_tool(
    "r4-governance-ceremony.py", "wasm_biotic_r4_negative_ceremony"
)
SBOM = load_tool("r4-sbom.py", "wasm_biotic_r4_negative_sbom")
PUBLIC_INSTALL = load_tool(
    "r4-public-install.py", "wasm_biotic_r4_negative_public_install"
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
        raise NegativeControlError(
            f"value cannot be represented as canonical JSON: {error}"
        ) from error


def digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"JSON contains duplicate key {key!r}")
        result[key] = value
    return result


def read_regular(path: Path, where: str, *, maximum: int = MAX_JSON_BYTES) -> bytes:
    try:
        information = path.lstat()
    except OSError as error:
        raise NegativeControlError(f"cannot inspect {where} at {path}: {error}") from error
    require(
        stat.S_ISREG(information.st_mode) and not stat.S_ISLNK(information.st_mode),
        f"{where} must be a regular file and not a link",
    )
    require(information.st_size <= maximum, f"{where} exceeds its size ceiling")
    return path.read_bytes()


def read_canonical(path: Path, where: str) -> tuple[dict[str, Any], bytes]:
    data = read_regular(path, where)
    try:
        value = json.loads(data, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise NegativeControlError(f"cannot parse {where}: {error}") from error
    require(isinstance(value, dict), f"{where} must be a JSON object")
    require(canonical_json(value) == data, f"{where} is not canonical JSON")
    return value, data


def require_fields(value: Any, fields: set[str], where: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{where} must be an object")
    actual = set(value)
    require(
        actual == fields,
        f"{where} has missing fields {sorted(fields - actual)} and unknown fields {sorted(actual - fields)}",
    )
    return value


def resolve_file(value: Any, base: Path, where: str) -> Path:
    require(isinstance(value, str) and value, f"{where} must be a path string")
    path = Path(value)
    path = path if path.is_absolute() else base / path
    try:
        information = path.lstat()
    except OSError as error:
        raise NegativeControlError(f"cannot inspect {where} at {path}: {error}") from error
    require(
        stat.S_ISREG(information.st_mode) and not stat.S_ISLNK(information.st_mode),
        f"{where} must be a regular file and not a link",
    )
    require(
        information.st_size <= ARCHIVE.MAX_TOTAL_SIZE + 256 * 1024 * 1024,
        f"{where} exceeds its size ceiling",
    )
    return path


def resolve_directory(value: Any, base: Path, where: str) -> Path:
    require(isinstance(value, str) and value, f"{where} must be a path string")
    path = Path(value)
    path = path if path.is_absolute() else base / path
    try:
        information = path.lstat()
    except OSError as error:
        raise NegativeControlError(f"cannot inspect {where} at {path}: {error}") from error
    require(
        stat.S_ISDIR(information.st_mode) and not stat.S_ISLNK(information.st_mode),
        f"{where} must be a directory and not a link",
    )
    return path


def public_key_hex(value: Any, where: str) -> str:
    require(
        isinstance(value, str)
        and len(value) == PUBLIC_KEY_HEX_LENGTH
        and all(character in "0123456789abcdef" for character in value),
        f"{where} must be 32 raw Ed25519 bytes as lowercase hex",
    )
    return value


def closure_digest(path: Path) -> tuple[str, int]:
    if path.is_file():
        return digest_file(path), 1
    rows = bytearray()
    count = 0
    for candidate in sorted(
        path.rglob("*"),
        key=lambda item: item.relative_to(path).as_posix().encode("utf-8"),
    ):
        relative = candidate.relative_to(path).as_posix()
        information = candidate.lstat()
        require(not stat.S_ISLNK(information.st_mode), f"artifact contains a link: {relative}")
        if stat.S_ISDIR(information.st_mode):
            continue
        require(stat.S_ISREG(information.st_mode), f"artifact contains a special file: {relative}")
        digest = digest_file(candidate)
        rows.extend(f"{digest[7:]}  {information.st_size}  {relative}\n".encode("utf-8"))
        count += 1
    require(count > 0, f"artifact directory is empty: {path}")
    return digest_bytes(bytes(rows)), count


def tool_sources() -> list[dict[str, str]]:
    names = (
        "r4-certifier-governance.py",
        "r4-governance-ceremony.py",
        "r4-install-archive.py",
        "r4-prepublication-negatives.py",
        "r4-public-install.py",
        "r4-sbom.py",
    )
    return [
        {"path": f"tools/{name}", "sha256": digest_file(Path(__file__).with_name(name))}
        for name in names
    ]


def rejection_record(
    name: str,
    attack: Any,
    operation: Callable[[], Any],
    exceptions: tuple[type[BaseException], ...],
) -> dict[str, str]:
    try:
        operation()
    except exceptions as error:
        message = str(error)
        require(message, f"{name} rejection had no diagnostic")
        return {
            "attack_sha256": digest_bytes(canonical_json(attack)),
            "rejection_sha256": digest_bytes(
                canonical_json(
                    {"exception": type(error).__name__, "message": message}
                )
            ),
            "result": "pass",
        }
    except Exception as error:  # pragma: no cover - defensive classification
        raise NegativeControlError(
            f"{name} raised an unexpected {type(error).__name__}: {error}"
        ) from error
    fail(f"{name} attack was accepted")


def clone_member(member: tarfile.TarInfo) -> tarfile.TarInfo:
    cloned = copy.copy(member)
    cloned.pax_headers = {}
    return cloned


class MutatingReader:
    """Flip the first payload byte while streaming the remainder unchanged."""

    def __init__(self, stream: Any) -> None:
        self.stream = stream
        self.changed = False

    def read(self, size: int = -1) -> bytes:
        data = self.stream.read(size)
        if data and not self.changed:
            data = bytes((data[0] ^ 1,)) + data[1:]
            self.changed = True
        return data


def rewrite_archive(source: Path, output: Path, attack: str) -> None:
    with tarfile.open(source, mode="r:") as incoming:
        members = incoming.getmembers()
        require(len(members) >= 2, "archive fixture has too few members")
        mutable_index = next(
            (
                index
                for index, member in enumerate(members)
                if index > 0 and member.isfile() and member.size > 0
            ),
            None,
        )
        with tarfile.open(output, mode="w", format=tarfile.USTAR_FORMAT) as outgoing:
            for index, member in enumerate(members):
                if attack == "missing" and index == len(members) - 1:
                    continue
                cloned = clone_member(member)
                if attack == "noncanonical" and index == 1:
                    cloned.uid = 1
                stream = incoming.extractfile(member) if member.isfile() else None
                if attack == "mutated" and index == mutable_index:
                    require(stream is not None, "mutable archive member has no body")
                    outgoing.addfile(cloned, MutatingReader(stream))
                else:
                    outgoing.addfile(cloned, stream)
            if attack == "duplicate":
                outgoing.addfile(clone_member(members[1]))
            elif attack == "extra":
                data = b"negative-control-extra\n"
                item = ARCHIVE.tar_info(
                    f"{ARCHIVE.ROOT_NAME}/zz-negative-control-extra",
                    0o644,
                    len(data),
                    int(members[0].mtime),
                    tarfile.REGTYPE,
                )
                outgoing.addfile(item, io.BytesIO(data))


def traversal_archive(source: Path, output: Path) -> None:
    with tarfile.open(source, mode="r:") as incoming:
        manifest_stream = incoming.extractfile(incoming.getmembers()[0])
        require(manifest_stream is not None, "archive manifest has no body")
        manifest = ARCHIVE.read_canonical_json(manifest_stream.read())
    manifest = copy.deepcopy(manifest)
    manifest["entries"][0]["path"] = "../negative-control-escape"
    data = ARCHIVE.canonical_json(manifest)
    epoch = manifest["source_date_epoch"]
    with tarfile.open(output, mode="w", format=tarfile.USTAR_FORMAT) as outgoing:
        outgoing.addfile(
            ARCHIVE.tar_info(
                ARCHIVE.MANIFEST_NAME,
                0o644,
                len(data),
                epoch,
                tarfile.REGTYPE,
            ),
            io.BytesIO(data),
        )
        outgoing.addfile(
            ARCHIVE.tar_info(
                ARCHIVE.ROOT_NAME, 0o755, 0, epoch, tarfile.DIRTYPE
            )
        )


def archive_controls(
    archives: dict[str, Path], work: Path
) -> tuple[dict[str, dict[str, str]], dict[str, Any]]:
    work.mkdir(parents=True, exist_ok=False)
    inventory: dict[str, Any] = {}
    for role in ARCHIVE_ROLES:
        try:
            digest, manifest, manifest_bytes = ARCHIVE.verify_archive(archives[role])
        except Exception as error:
            raise NegativeControlError(f"pristine {role} did not verify: {error}") from error
        inventory[role] = {
            "entry_count": manifest["entry_count"],
            "manifest_sha256": digest_bytes(manifest_bytes),
            "sha256": digest,
            "size_bytes": archives[role].stat().st_size,
        }
    subject_role = min(ARCHIVE_ROLES, key=lambda role: archives[role].stat().st_size)
    subject = archives[subject_role]
    controls: dict[str, dict[str, str]] = {}
    attacks = {
        "duplicate_rejected": "duplicate",
        "extra_rejected": "extra",
        "missing_rejected": "missing",
        "mutated_rejected": "mutated",
        "noncanonical_rejected": "noncanonical",
    }
    for name, attack in attacks.items():
        path = work / f"archive-{attack}.tar"
        rewrite_archive(subject, path, attack)
        controls[name] = rejection_record(
            name,
            {
                "attack": attack,
                "mutated_sha256": digest_file(path),
                "subject_role": subject_role,
                "subject_sha256": inventory[subject_role]["sha256"],
            },
            lambda selected=path: ARCHIVE.verify_archive(selected),
            (ARCHIVE.ArchiveError,),
        )

    traversal = work / "archive-traversal.tar"
    traversal_archive(subject, traversal)
    controls["traversal_rejected"] = rejection_record(
        "traversal_rejected",
        {
            "attack": "manifest-path-traversal",
            "mutated_sha256": digest_file(traversal),
            "subject_role": subject_role,
            "subject_sha256": inventory[subject_role]["sha256"],
        },
        lambda: ARCHIVE.verify_archive(traversal),
        (ARCHIVE.ArchiveError,),
    )

    truncated = work / "archive-truncated.tar"
    size = subject.stat().st_size
    require(size > tarfile.BLOCKSIZE, "archive is too small for truncation control")
    with subject.open("rb") as incoming, truncated.open("xb") as outgoing:
        remaining = size - tarfile.BLOCKSIZE
        while remaining:
            chunk = incoming.read(min(1024 * 1024, remaining))
            require(chunk, "archive ended before truncation boundary")
            outgoing.write(chunk)
            remaining -= len(chunk)
    controls["truncated_rejected"] = rejection_record(
        "truncated_rejected",
        {
            "attack": "remove-final-ustar-block",
            "mutated_sha256": digest_file(truncated),
            "subject_role": subject_role,
            "subject_sha256": inventory[subject_role]["sha256"],
        },
        lambda: ARCHIVE.verify_archive(truncated),
        (ARCHIVE.ArchiveError,),
    )
    for role in ARCHIVE_ROLES:
        ARCHIVE.verify_archive(archives[role])
    require(set(controls) == set(ARCHIVE_CONTROLS), "archive control inventory differs")
    inventory["mutation_subject_role"] = subject_role
    return {name: controls[name] for name in sorted(controls)}, inventory


def governance_controls(
    ceremony_root: Path,
) -> tuple[dict[str, dict[str, str]], dict[str, str]]:
    try:
        verified = CEREMONY.verify_ceremony(ceremony_root)
    except Exception as error:
        raise NegativeControlError(f"pristine governance ceremony did not verify: {error}") from error
    genesis = GOVERNANCE.load_policy(
        ceremony_root / CEREMONY.POLICY_NAME, require_genesis=True
    )
    release_payload = GOVERNANCE.load_payload(ceremony_root / "release-payload.json")
    release_signatures = [
        GOVERNANCE.load_detached_signature(
            ceremony_root / f"release-signature-{index}.json"
        )
        for index in (1, 2)
    ]
    rotation = GOVERNANCE.load_policy(ceremony_root / "rotation-policy.json")
    rotation_transition = GOVERNANCE.load_transition(
        ceremony_root / "rotation-transition.json"
    )
    revocation = GOVERNANCE.load_policy(ceremony_root / "revocation-policy.json")
    GOVERNANCE.verify_release_quorum(genesis, release_payload, release_signatures)
    GOVERNANCE.verify_transition(genesis, rotation, rotation_transition)
    GOVERNANCE.verify_transition(
        rotation,
        revocation,
        GOVERNANCE.load_transition(ceremony_root / "revocation-transition.json"),
    )

    controls: dict[str, dict[str, str]] = {}

    def record(name: str, attack: Any, operation: Callable[[], Any]) -> None:
        controls[name] = rejection_record(
            name, attack, operation, (GOVERNANCE.GovernanceError,)
        )

    record(
        "one_of_three_rejected",
        {"signature_count": 1, "threshold": genesis["threshold"]},
        lambda: GOVERNANCE.verify_release_quorum(
            genesis, release_payload, [release_signatures[0]]
        ),
    )
    record(
        "duplicate_signer_rejected",
        {"duplicate_key_id": release_signatures[0]["key_id"]},
        lambda: GOVERNANCE.verify_release_quorum(
            genesis,
            release_payload,
            [release_signatures[0], copy.deepcopy(release_signatures[0])],
        ),
    )
    record(
        "cross_domain_rejected",
        {
            "actual_domain": GOVERNANCE.RELEASE_DOMAIN,
            "verification_domain": GOVERNANCE.PUBLICATION_DOMAIN,
        },
        lambda: GOVERNANCE.verify_publication_quorum(
            genesis, release_payload, release_signatures
        ),
    )

    mixed = copy.deepcopy(release_signatures)
    mixed[1]["policy_digest"] = GOVERNANCE.policy_digest(rotation)
    mixed.sort(key=lambda item: item["key_id"])
    record(
        "mixed_policy_rejected",
        {"signature_inventory_sha256": digest_bytes(canonical_json(mixed))},
        lambda: GOVERNANCE.verify_release_quorum(genesis, release_payload, mixed),
    )

    genesis_ids = {item["key_id"] for item in genesis["keys"]}
    unknown_id = next(
        item["key_id"] for item in rotation["keys"] if item["key_id"] not in genesis_ids
    )
    unknown = copy.deepcopy(release_signatures)
    unknown[1]["key_id"] = unknown_id
    unknown.sort(key=lambda item: item["key_id"])
    record(
        "unknown_signer_rejected",
        {"signature_inventory_sha256": digest_bytes(canonical_json(unknown))},
        lambda: GOVERNANCE.verify_release_quorum(genesis, release_payload, unknown),
    )

    revoked_id = revocation["revoked_key_ids"][0]
    require(revoked_id != "sha256:" + "f" * 64, "cannot construct revoked-key control")
    revoked = copy.deepcopy(release_signatures)
    revoked_policy_digest = GOVERNANCE.policy_digest(revocation)
    payload_digest = digest_bytes(canonical_json(release_payload))
    revoked[0].update(
        {
            "domain": GOVERNANCE.RELEASE_DOMAIN,
            "key_id": revoked_id,
            "payload_digest": payload_digest,
            "policy_digest": revoked_policy_digest,
        }
    )
    revoked[1].update(
        {
            "domain": GOVERNANCE.RELEASE_DOMAIN,
            "key_id": "sha256:" + "f" * 64,
            "payload_digest": payload_digest,
            "policy_digest": revoked_policy_digest,
        }
    )
    revoked.sort(key=lambda item: item["key_id"])
    record(
        "revoked_signer_rejected",
        {"signature_inventory_sha256": digest_bytes(canonical_json(revoked))},
        lambda: GOVERNANCE.verify_release_quorum(revocation, release_payload, revoked),
    )

    record(
        "downgrade_rejected",
        {
            "from_generation": rotation["generation"],
            "to_generation": genesis["generation"],
        },
        lambda: GOVERNANCE.transition_statement(rotation, genesis, "rotate"),
    )
    fork = copy.deepcopy(revocation)
    fork["predecessor_policy_digest"] = GOVERNANCE.policy_digest(genesis)
    record(
        "fork_shape_rejected",
        {"fork_policy_sha256": digest_bytes(canonical_json(fork))},
        lambda: GOVERNANCE.transition_statement(rotation, fork, "revoke"),
    )
    next_rotation = copy.deepcopy(revocation)
    next_rotation["revoked_key_ids"] = list(rotation["revoked_key_ids"])
    record(
        "replay_rejected",
        {
            "replayed_transition_sha256": digest_bytes(
                canonical_json(rotation_transition)
            ),
            "successor_policy_sha256": digest_bytes(canonical_json(next_rotation)),
        },
        lambda: GOVERNANCE.verify_transition(
            rotation, next_rotation, rotation_transition
        ),
    )

    introduced = {
        item["key_id"] for item in rotation["keys"]
    } - genesis_ids
    no_possession = copy.deepcopy(rotation_transition)
    no_possession["successor_policy_signatures"] = [
        signature
        for signature in no_possession["successor_policy_signatures"]
        if signature["key_id"] not in introduced
    ]
    record(
        "successor_possession_required",
        {"transition_sha256": digest_bytes(canonical_json(no_possession))},
        lambda: GOVERNANCE.verify_transition(genesis, rotation, no_possession),
    )

    CEREMONY.verify_ceremony(ceremony_root)
    require(
        set(controls) == set(GOVERNANCE_CONTROLS),
        "governance control inventory differs",
    )
    return {name: controls[name] for name in sorted(controls)}, {
        "ceremony_manifest_sha256": verified["ceremony_sha256"],
        "governance_report_sha256": verified["report_sha256"],
        "policy_digest": verified["policy_digest"],
    }


def update_sbom_binding(sbom: dict[str, Any], coverage: dict[str, Any]) -> None:
    coverage["sbom_sha256"] = digest_bytes(canonical_json(sbom))


def remove_relationships(document: dict[str, Any], identity: str) -> None:
    document["relationships"] = [
        item
        for item in document["relationships"]
        if item.get("relatedSpdxElement") != identity
        and item.get("spdxElementId") != identity
    ]


def run_sbom_verifier(
    source_root: Path,
    artifacts: list[tuple[str, Path]],
    system_packages: list[str],
    sbom_path: Path,
    coverage_path: Path,
) -> None:
    options = argparse.Namespace(
        source_root=source_root,
        artifact=[f"{role}={path}" for role, path in artifacts],
        system_package=system_packages,
        sbom=sbom_path,
        coverage=coverage_path,
    )
    with contextlib.redirect_stdout(io.StringIO()):
        SBOM.verify_documents(options)


def sbom_controls(
    *,
    source_root: Path,
    artifacts: list[tuple[str, Path]],
    system_packages: list[str],
    sbom_path: Path,
    coverage_path: Path,
    work: Path,
) -> tuple[dict[str, dict[str, str]], dict[str, Any]]:
    run_sbom_verifier(
        source_root, artifacts, system_packages, sbom_path, coverage_path
    )
    pristine_sbom, pristine_sbom_bytes = read_canonical(sbom_path, "SPDX SBOM")
    pristine_coverage, pristine_coverage_bytes = read_canonical(
        coverage_path, "SBOM coverage"
    )
    controls: dict[str, dict[str, str]] = {}

    def execute(name: str, mutate: Callable[[dict[str, Any], dict[str, Any]], None]) -> None:
        document = copy.deepcopy(pristine_sbom)
        coverage = copy.deepcopy(pristine_coverage)
        mutate(document, coverage)
        update_sbom_binding(document, coverage)
        mutated_sbom = work / f"{name}.spdx.json"
        mutated_coverage = work / f"{name}.coverage.json"
        mutated_sbom.write_bytes(canonical_json(document))
        mutated_coverage.write_bytes(canonical_json(coverage))
        attack = {
            "coverage_sha256": digest_file(mutated_coverage),
            "spdx_sha256": digest_file(mutated_sbom),
        }
        controls[name] = rejection_record(
            name,
            attack,
            lambda: run_sbom_verifier(
                source_root,
                artifacts,
                system_packages,
                mutated_sbom,
                mutated_coverage,
            ),
            (SBOM.SbomError,),
        )

    def omitted_file(document: dict[str, Any], coverage: dict[str, Any]) -> None:
        item = document["files"].pop(0)
        remove_relationships(document, item["SPDXID"])
        coverage["file_count"] -= 1

    def phantom_file(document: dict[str, Any], coverage: dict[str, Any]) -> None:
        identity = "SPDXRef-File-r4-negative-phantom"
        document["files"].append(
            {
                "SPDXID": identity,
                "checksums": [{"algorithm": "SHA256", "checksumValue": "0" * 64}],
                "copyrightText": "NOASSERTION",
                "fileName": "./phantom/r4-negative",
                "fileTypes": ["BINARY"],
                "licenseConcluded": "NOASSERTION",
            }
        )
        document["files"].sort(key=lambda item: item["fileName"].encode("utf-8"))
        document["relationships"].append(
            {
                "relatedSpdxElement": identity,
                "relationshipType": "CONTAINS",
                "spdxElementId": "SPDXRef-Package-WasmBioticFactory",
            }
        )
        coverage["file_count"] += 1

    def omitted_package(document: dict[str, Any], coverage: dict[str, Any]) -> None:
        index = next(
            index
            for index, item in enumerate(document["packages"])
            if item["SPDXID"] != "SPDXRef-Package-WasmBioticFactory"
        )
        item = document["packages"].pop(index)
        remove_relationships(document, item["SPDXID"])
        coverage["package_count"] -= 1

    def phantom_package(document: dict[str, Any], coverage: dict[str, Any]) -> None:
        identity = "SPDXRef-Package-r4-negative-phantom"
        document["packages"].append(
            {
                "SPDXID": identity,
                "copyrightText": "NOASSERTION",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "name": "r4-negative-phantom",
                "versionInfo": "0",
            }
        )
        document["relationships"].append(
            {
                "relatedSpdxElement": identity,
                "relationshipType": "DESCRIBES",
                "spdxElementId": "SPDXRef-DOCUMENT",
            }
        )
        coverage["package_count"] += 1

    def wrong_digest(document: dict[str, Any], _coverage: dict[str, Any]) -> None:
        checksum = document["files"][0]["checksums"][0]
        checksum["checksumValue"] = (
            "0" * 64 if checksum["checksumValue"] != "0" * 64 else "1" * 64
        )

    execute("omitted_file_rejected", omitted_file)
    execute("omitted_package_rejected", omitted_package)
    execute("phantom_file_rejected", phantom_file)
    execute("phantom_package_rejected", phantom_package)
    execute("wrong_digest_rejected", wrong_digest)
    run_sbom_verifier(
        source_root, artifacts, system_packages, sbom_path, coverage_path
    )
    require(set(controls) == set(SBOM_CONTROLS), "SBOM control inventory differs")
    artifact_inventory: list[dict[str, Any]] = []
    for role, path in artifacts:
        digest, count = closure_digest(path)
        artifact_inventory.append(
            {"file_count": count, "role": role, "sha256": digest}
        )
    return {name: controls[name] for name in sorted(controls)}, {
        "artifact_inventory": artifact_inventory,
        "coverage_sha256": digest_bytes(pristine_coverage_bytes),
        "spdx_sha256": digest_bytes(pristine_sbom_bytes),
        "system_packages": list(system_packages),
    }


def command_result(arguments: list[str], *, expected_success: bool) -> dict[str, Any]:
    try:
        result = subprocess.run(
            arguments,
            input=b"",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=600,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise NegativeControlError(f"cannot execute lifecycle control: {error}") from error
    require(result.returncode >= 0, "lifecycle control terminated by a signal")
    if expected_success:
        require(result.returncode == 0, f"lifecycle setup returned {result.returncode}")
    else:
        require(
            1 <= result.returncode <= 125,
            f"lifecycle rejection returned non-semantic code {result.returncode}",
        )
    return {
        "exit_code": result.returncode,
        "expected": "success" if expected_success else "rejection",
    }


def manifest_digest(package: Path, where: str) -> str:
    path = package / "manifest.json"
    digest = digest_file(path)
    require(
        package.name == digest.replace(":", "-", 1),
        f"{where} package directory is not manifest-addressed",
    )
    return digest


def lifecycle_controls(
    *,
    install_archive: Path,
    extracted_root: Path,
    kernel: Path,
    operator_capacity: Path,
    incumbent: Path,
    successor: Path,
    expected_kernel_sha256: str,
    trusted_key: str,
    wrong_key: str,
    target: str,
    work: Path,
) -> tuple[dict[str, dict[str, str]], dict[str, Any]]:
    archive_digest, archive_manifest, _ = ARCHIVE.verify_archive(install_archive)
    require(
        ARCHIVE.source_entries(extracted_root) == archive_manifest["entries"],
        "lifecycle extracted install tree differs from the exact archive",
    )
    extracted = extracted_root.resolve()
    for label, path in (
        ("kernel", kernel),
        ("operator capacity", operator_capacity),
        ("incumbent", incumbent),
        ("successor", successor),
    ):
        require(path.resolve().is_relative_to(extracted), f"{label} is outside install tree")
    require(kernel.is_file() and kernel.stat().st_mode & 0o111, "kernel is not executable")
    require(
        operator_capacity.is_file() and not operator_capacity.is_symlink(),
        "operator capacity is not a regular file",
    )
    observed_kernel = digest_file(kernel)
    require(observed_kernel == expected_kernel_sha256, "kernel digest differs")
    incumbent_digest = manifest_digest(incumbent, "incumbent")
    successor_digest = manifest_digest(successor, "successor")
    require(trusted_key != wrong_key, "wrong public key equals trusted key")

    controls: dict[str, dict[str, str]] = {}
    kernel_command = str(kernel)

    automatic_state = work / "automatic-state"
    setup = [
        command_result(
            [
                kernel_command,
                "init",
                str(automatic_state),
                incumbent_digest,
                trusted_key,
                str(operator_capacity),
            ],
            expected_success=True,
        ),
        command_result(
            [kernel_command, "admit", str(incumbent), str(automatic_state)],
            expected_success=True,
        ),
        command_result(
            [kernel_command, "serve", str(incumbent), str(automatic_state)],
            expected_success=True,
        ),
    ]
    mechanisms = automatic_state / "mechanisms.json"
    require(mechanisms.is_file(), "kernel did not persist mechanisms.json")
    before = digest_file(mechanisms)
    setup.append(
        command_result(
            [kernel_command, "admit", str(successor), str(automatic_state)],
            expected_success=True,
        )
    )
    after = digest_file(mechanisms)
    rejected = command_result(
        [kernel_command, "serve", str(successor), str(automatic_state)],
        expected_success=False,
    )
    incumbent_still_served = command_result(
        [kernel_command, "serve", str(incumbent), str(automatic_state)],
        expected_success=True,
    )
    controls["automatic_activation_rejected"] = {
        "attack_sha256": digest_bytes(
            canonical_json(
                {
                    "mechanism_state_after": after,
                    "mechanism_state_before": before,
                    "incumbent_still_served": incumbent_still_served,
                    "rejection": rejected,
                    "setup": setup,
                }
            )
        ),
        "rejection_sha256": digest_bytes(canonical_json(rejected)),
        "result": "pass",
    }

    parser = PUBLIC_INSTALL.parser()
    option_strings = sorted(
        option
        for action in parser._actions
        for option in action.option_strings
    )
    private_options = [option for option in option_strings if "private" in option]
    require(not private_options, "public install parser exposes a private-key option")
    inventory_digest = digest_bytes(canonical_json(option_strings))
    controls["private_key_argument_absent"] = {
        "attack_sha256": digest_bytes(
            canonical_json({"forbidden_option_fragment": "private"})
        ),
        "rejection_sha256": inventory_digest,
        "result": "pass",
    }

    tampered_root = work / "tampered-package"
    tampered = PUBLIC_INSTALL.tampered_package(incumbent, tampered_root)
    tampered_state = work / "tampered-state"
    command_result(
        [
            kernel_command,
            "init",
            str(tampered_state),
            incumbent_digest,
            trusted_key,
            str(operator_capacity),
        ],
        expected_success=True,
    )
    tampered_rejected = command_result(
        [kernel_command, "admit", str(tampered), str(tampered_state)],
        expected_success=False,
    )
    controls["tampered_package_rejected"] = {
        "attack_sha256": closure_digest(tampered)[0],
        "rejection_sha256": digest_bytes(canonical_json(tampered_rejected)),
        "result": "pass",
    }

    wrong_state = work / "wrong-key-state"
    command_result(
        [
            kernel_command,
            "init",
            str(wrong_state),
            incumbent_digest,
            wrong_key,
            str(operator_capacity),
        ],
        expected_success=True,
    )
    wrong_rejected = command_result(
        [kernel_command, "admit", str(incumbent), str(wrong_state)],
        expected_success=False,
    )
    controls["wrong_key_rejected"] = {
        "attack_sha256": digest_bytes(bytes.fromhex(wrong_key)),
        "rejection_sha256": digest_bytes(canonical_json(wrong_rejected)),
        "result": "pass",
    }

    ARCHIVE.verify_archive(install_archive)
    require(
        set(controls) == set(LIFECYCLE_CONTROLS),
        "lifecycle control inventory differs",
    )
    return {name: controls[name] for name in sorted(controls)}, {
        "incumbent_manifest_sha256": incumbent_digest,
        "install_archive_sha256": archive_digest,
        "kernel_sha256": observed_kernel,
        "operator_capacity_sha256": digest_file(operator_capacity),
        "parser_option_inventory_sha256": inventory_digest,
        "release_certifier_key_id": digest_bytes(bytes.fromhex(trusted_key)),
        "successor_manifest_sha256": successor_digest,
        "target": target,
    }


def load_spec(path: Path) -> dict[str, Any]:
    spec, _ = read_canonical(path, "pre-publication negative input spec")
    require_fields(
        spec,
        {"archives", "governance_ceremony", "lifecycle", "sbom", "schema"},
        "pre-publication negative input spec",
    )
    require(spec["schema"] == INPUT_SCHEMA, "negative input schema differs")
    require_fields(spec["archives"], set(ARCHIVE_ROLES), "negative input archives")
    require_fields(
        spec["sbom"],
        {"artifacts", "coverage", "spdx", "system_packages"},
        "negative input SBOM",
    )
    require_fields(
        spec["lifecycle"],
        {
            "expected_kernel_sha256",
            "extracted_root",
            "incumbent",
            "kernel",
            "operator_capacity",
            "public_key_hex",
            "successor",
            "target",
            "wrong_public_key_hex",
        },
        "negative input lifecycle",
    )
    return spec


def build_report(spec_path: Path) -> dict[str, Any]:
    spec = load_spec(spec_path)
    base = spec_path.parent
    archives = {
        role: resolve_file(spec["archives"][role], base, f"{role} input")
        for role in ARCHIVE_ROLES
    }
    ceremony = resolve_directory(
        spec["governance_ceremony"], base, "governance ceremony"
    )
    raw_artifacts = spec["sbom"]["artifacts"]
    require(isinstance(raw_artifacts, dict) and raw_artifacts, "SBOM artifacts are empty")
    artifacts: list[tuple[str, Path]] = []
    for role, raw in sorted(raw_artifacts.items()):
        require(
            isinstance(role, str) and SBOM.ROLE_RE.fullmatch(role) is not None,
            f"invalid SBOM artifact role {role!r}",
        )
        raw_path = Path(raw) if isinstance(raw, str) else Path("")
        require(isinstance(raw, str) and raw, f"SBOM artifact {role} path is invalid")
        path = raw_path if raw_path.is_absolute() else base / raw_path
        require(
            path.exists()
            and not path.is_symlink()
            and (path.is_file() or path.is_dir()),
            f"SBOM artifact {role} is not a regular file/directory",
        )
        artifacts.append((role, path))
    system_packages = spec["sbom"]["system_packages"]
    require(
        isinstance(system_packages, list)
        and system_packages
        and all(isinstance(item, str) and item for item in system_packages),
        "SBOM system packages must be a non-empty string array",
    )
    require(system_packages == sorted(system_packages), "SBOM system packages are not sorted")
    sbom_path = resolve_file(spec["sbom"]["spdx"], base, "SPDX SBOM")
    coverage_path = resolve_file(
        spec["sbom"]["coverage"], base, "SBOM coverage"
    )

    lifecycle = spec["lifecycle"]
    extracted_root = resolve_directory(
        lifecycle["extracted_root"], base, "lifecycle extracted install root"
    )
    kernel = resolve_file(lifecycle["kernel"], base, "lifecycle kernel")
    operator_capacity = resolve_file(
        lifecycle["operator_capacity"], base, "lifecycle operator capacity"
    )
    incumbent = resolve_directory(lifecycle["incumbent"], base, "incumbent package")
    successor = resolve_directory(lifecycle["successor"], base, "successor package")
    trusted_key = public_key_hex(lifecycle["public_key_hex"], "trusted public key")
    wrong_key = public_key_hex(
        lifecycle["wrong_public_key_hex"], "wrong public key"
    )
    expected_kernel_sha256 = lifecycle["expected_kernel_sha256"]
    require(
        isinstance(expected_kernel_sha256, str)
        and expected_kernel_sha256.startswith("sha256:")
        and len(expected_kernel_sha256) == 71,
        "expected kernel digest is invalid",
    )
    target = lifecycle["target"]
    require(isinstance(target, str) and target, "lifecycle target is invalid")

    with tempfile.TemporaryDirectory(prefix="r4-prepublication-negatives-") as temporary:
        work = Path(temporary)
        archive_evidence, archive_inputs = archive_controls(
            archives, work / "archives"
        )
        governance_evidence, governance_inputs = governance_controls(ceremony)
        source_root = work / "source"
        try:
            ARCHIVE.extract_archive(archives["source-archive"], source_root)
        except Exception as error:
            raise NegativeControlError(
                f"cannot extract source archive for SBOM controls: {error}"
            ) from error
        sbom_work = work / "sbom"
        sbom_work.mkdir()
        sbom_evidence, sbom_inputs = sbom_controls(
            source_root=source_root,
            artifacts=artifacts,
            system_packages=system_packages,
            sbom_path=sbom_path,
            coverage_path=coverage_path,
            work=sbom_work,
        )
        lifecycle_work = work / "lifecycle"
        lifecycle_work.mkdir()
        lifecycle_evidence, lifecycle_inputs = lifecycle_controls(
            install_archive=archives["install-archive"],
            extracted_root=extracted_root,
            kernel=kernel,
            operator_capacity=operator_capacity,
            incumbent=incumbent,
            successor=successor,
            expected_kernel_sha256=expected_kernel_sha256,
            trusted_key=trusted_key,
            wrong_key=wrong_key,
            target=target,
            work=lifecycle_work,
        )

    controls = {
        "archives": archive_evidence,
        "governance": governance_evidence,
        "public_lifecycle": lifecycle_evidence,
        "sbom": sbom_evidence,
    }
    inputs = {
        "archives": archive_inputs,
        "governance": governance_inputs,
        "public_lifecycle": lifecycle_inputs,
        "sbom": sbom_inputs,
    }
    sources = tool_sources()
    evidence_closure = digest_bytes(
        canonical_json({"controls": controls, "inputs": inputs, "tool_sources": sources})
    )
    return {
        "archives": archive_evidence,
        "blockers": [],
        "evidence_closure_sha256": evidence_closure,
        "governance": governance_evidence,
        "inputs": inputs,
        "private_key_dependency": False,
        "public_lifecycle": lifecycle_evidence,
        "result": "pass",
        "sbom": sbom_evidence,
        "schema": REPORT_SCHEMA,
        "tool_sources": sources,
    }


def write_atomic(path: Path, value: Any) -> None:
    require(not path.exists(), f"negative-control output already exists: {path}")
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


def verify_report(spec_path: Path, report_path: Path) -> dict[str, Any]:
    actual, actual_bytes = read_canonical(report_path, "pre-publication negative report")
    expected = build_report(spec_path)
    require(
        actual_bytes == canonical_json(expected),
        "pre-publication negative report does not reproduce from exact public inputs",
    )
    return actual


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(description=__doc__)
    subcommands = command.add_subparsers(dest="command", required=True)
    run = subcommands.add_parser("run", help="execute controls and write canonical evidence")
    run.add_argument("--spec", required=True, type=Path)
    run.add_argument("--out", required=True, type=Path)
    verify = subcommands.add_parser(
        "verify", help="re-execute controls and compare canonical evidence"
    )
    verify.add_argument("--spec", required=True, type=Path)
    verify.add_argument("--report", required=True, type=Path)
    return command


def main(arguments: list[str] | None = None) -> int:
    options = parser().parse_args(arguments)
    try:
        if options.command == "run":
            report = build_report(options.spec)
            write_atomic(options.out, report)
            print(
                f"prepublication-negatives {digest_file(options.out)} {options.out}"
            )
        else:
            report = verify_report(options.spec, options.report)
            print(
                "verified prepublication-negatives "
                f"{digest_file(options.report)} closure={report['evidence_closure_sha256']}"
            )
        return 0
    except (
        NegativeControlError,
        ARCHIVE.ArchiveError,
        CEREMONY.CeremonyError,
        GOVERNANCE.GovernanceError,
        PUBLIC_INSTALL.InstallError,
        SBOM.SbomError,
        OSError,
        ValueError,
    ) as error:
        print(f"r4-prepublication-negatives: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
