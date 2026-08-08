#!/usr/bin/env python3
"""Run and publicly re-verify the complete R4 governance ceremony.

The ``run`` command receives five operator private keys: three generation-1
custodian keys and two disposable successor keys used to exercise rotation and
revocation.  It emits only public policies, payloads, detached signatures,
transitions, a closed evidence manifest, and the exact R4 governance report.

The ``verify`` command accepts only that public directory.  This keeps the
published report's ``private_key_dependency: false`` claim concrete: every
reported result is reproducible after the signing keys have been destroyed.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
from typing import Any, NoReturn


SCHEMA = "wasm-biotic.r4-governance-ceremony.v1"
REPORT_SCHEMA = "wasm-biotic.r4-governance-report.v1"
MANIFEST_NAME = "CEREMONY.json"
REPORT_NAME = "governance-report.json"
POLICY_NAME = "trust-policy.json"


class CeremonyError(RuntimeError):
    """The governance ceremony is incomplete, unsafe, or not reproducible."""


def fail(message: str) -> NoReturn:
    raise CeremonyError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def load_governance() -> Any:
    path = Path(__file__).with_name("r4-certifier-governance.py")
    specification = importlib.util.spec_from_file_location(
        "wasm_biotic_r4_certifier_governance", path
    )
    require(
        specification is not None and specification.loader is not None,
        f"cannot load governance implementation at {path}",
    )
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


GOV = load_governance()


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def read_regular(path: Path, where: str) -> bytes:
    try:
        information = path.lstat()
    except FileNotFoundError:
        fail(f"{where} is missing: {path}")
    require(
        stat.S_ISREG(information.st_mode) and not stat.S_ISLNK(information.st_mode),
        f"{where} must be a regular file",
    )
    require(information.st_size <= 16 * 1024 * 1024, f"{where} is too large")
    return path.read_bytes()


def read_object(path: Path, where: str) -> dict[str, Any]:
    data = read_regular(path, where)
    try:
        value = GOV.parse_canonical_json(data, where)
    except GOV.GovernanceError as error:
        raise CeremonyError(str(error)) from error
    require(isinstance(value, dict), f"{where} must be a JSON object")
    return value


def key_entry(private_key: Path) -> dict[str, str]:
    public_key = GOV.public_key_from_private(private_key)
    return {
        "algorithm": GOV.ALGORITHM,
        "key_id": GOV.digest_bytes(public_key),
        "public_key_hex": public_key.hex(),
    }


def policy(
    entries: list[dict[str, str]],
    *,
    generation: int,
    predecessor: str | None,
    revoked: list[str],
) -> dict[str, Any]:
    value = {
        "generation": generation,
        "keys": sorted(entries, key=lambda item: item["key_id"]),
        "predecessor_policy_digest": predecessor,
        "revoked_key_ids": sorted(revoked),
        "schema": GOV.POLICY_SCHEMA,
        "threshold": GOV.THRESHOLD,
    }
    GOV.validate_policy(value)
    return value


def sorted_signatures(
    selected_policy: dict[str, Any],
    domain: str,
    payload: dict[str, Any],
    private_keys: list[Path],
) -> list[dict[str, Any]]:
    return sorted(
        (
            GOV.sign_detached(selected_policy, domain, payload, private_key)
            for private_key in private_keys
        ),
        key=lambda item: item["key_id"],
    )


def write_value(root: Path, name: str, value: Any) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json(value))
    os.chmod(path, 0o644)


def public_file_inventory(root: Path) -> list[dict[str, Any]]:
    files: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix().encode()):
        relative = path.relative_to(root).as_posix()
        require(not path.is_symlink(), f"ceremony contains a link: {relative}")
        require(path.is_file(), f"ceremony contains a non-file entry: {relative}")
        if relative in {MANIFEST_NAME, REPORT_NAME}:
            continue
        files.append(
            {
                "path": relative,
                "sha256": digest_file(path),
                "size_bytes": path.stat().st_size,
            }
        )
    return files


def build_report(
    genesis: dict[str, Any], ceremony_manifest_sha256: str
) -> dict[str, Any]:
    return {
        "active_key_count": GOV.KEY_COUNT,
        "blockers": [],
        "ceremony_manifest_sha256": ceremony_manifest_sha256,
        "generation": 1,
        "policy_digest": GOV.policy_digest(genesis),
        "private_key_dependency": False,
        "publication_quorum_verified": True,
        "r3_re_root": {
            "kind": "out-of-band-genesis",
            "r3_private_key_available": False,
            "r3_signed_rotation": False,
        },
        "release_quorum_verified": True,
        "result": "pass",
        "revocation_verified": True,
        "rotation_verified": True,
        "schema": REPORT_SCHEMA,
        "successor_proof_of_possession_verified": True,
        "threshold": GOV.THRESHOLD,
    }


def run_ceremony(
    genesis_private_keys: list[Path],
    successor_private_keys: list[Path],
    release_payload: dict[str, Any],
    publication_payload: dict[str, Any],
    output: Path,
) -> dict[str, Any]:
    require(len(genesis_private_keys) == 3, "ceremony requires exactly three genesis keys")
    require(len(successor_private_keys) == 2, "ceremony requires exactly two successor keys")
    require(not output.exists(), f"ceremony output already exists: {output}")
    all_private_keys = [*genesis_private_keys, *successor_private_keys]
    for index, path in enumerate(all_private_keys):
        read_regular(path, f"private key {index}")
    entries = [key_entry(path) for path in all_private_keys]
    require(
        len({item["key_id"] for item in entries}) == 5,
        "all five ceremony public keys must be distinct",
    )
    genesis_entries = entries[:3]
    first_successor, second_successor = entries[3:]
    genesis = policy(
        genesis_entries, generation=1, predecessor=None, revoked=[]
    )

    release_signatures = sorted_signatures(
        genesis,
        GOV.RELEASE_DOMAIN,
        release_payload,
        genesis_private_keys[:2],
    )
    GOV.verify_release_quorum(genesis, release_payload, release_signatures)
    publication_signatures = sorted_signatures(
        genesis,
        GOV.PUBLICATION_DOMAIN,
        publication_payload,
        genesis_private_keys[1:],
    )
    GOV.verify_publication_quorum(
        genesis, publication_payload, publication_signatures
    )

    rotation = policy(
        [genesis_entries[1], genesis_entries[2], first_successor],
        generation=2,
        predecessor=GOV.policy_digest(genesis),
        revoked=[],
    )
    rotation_statement = GOV.transition_statement(genesis, rotation, "rotate")
    rotation_transition = GOV.assemble_transition(
        genesis,
        rotation,
        "rotate",
        sorted_signatures(
            genesis,
            GOV.TRANSITION_OLD_DOMAIN,
            rotation_statement,
            genesis_private_keys[:2],
        ),
        sorted_signatures(
            rotation,
            GOV.TRANSITION_SUCCESSOR_DOMAIN,
            rotation_statement,
            [genesis_private_keys[1], successor_private_keys[0]],
        ),
    )

    revoked_key = genesis_entries[1]["key_id"]
    revocation = policy(
        [genesis_entries[2], first_successor, second_successor],
        generation=3,
        predecessor=GOV.policy_digest(rotation),
        revoked=[revoked_key],
    )
    revocation_statement = GOV.transition_statement(rotation, revocation, "revoke")
    revocation_transition = GOV.assemble_transition(
        rotation,
        revocation,
        "revoke",
        sorted_signatures(
            rotation,
            GOV.TRANSITION_OLD_DOMAIN,
            revocation_statement,
            [genesis_private_keys[1], genesis_private_keys[2]],
        ),
        sorted_signatures(
            revocation,
            GOV.TRANSITION_SUCCESSOR_DOMAIN,
            revocation_statement,
            [genesis_private_keys[2], successor_private_keys[1]],
        ),
    )

    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(
        tempfile.mkdtemp(prefix=f".{output.name}.tmp-", dir=output.parent)
    )
    try:
        values = {
            POLICY_NAME: genesis,
            "release-payload.json": release_payload,
            "release-signature-1.json": release_signatures[0],
            "release-signature-2.json": release_signatures[1],
            "publication-payload.json": publication_payload,
            "publication-signature-1.json": publication_signatures[0],
            "publication-signature-2.json": publication_signatures[1],
            "rotation-policy.json": rotation,
            "rotation-transition.json": rotation_transition,
            "revocation-policy.json": revocation,
            "revocation-transition.json": revocation_transition,
        }
        for name, value in values.items():
            write_value(temporary, name, value)
        provisional_manifest = {
            "files": public_file_inventory(temporary),
            "policy_digest": GOV.policy_digest(genesis),
            "private_key_dependency": False,
            "result": "pass",
            "schema": SCHEMA,
        }
        ceremony_manifest_sha256 = digest_bytes(canonical_json(provisional_manifest))
        write_value(
            temporary,
            REPORT_NAME,
            build_report(genesis, ceremony_manifest_sha256),
        )
        manifest = {
            "files": public_file_inventory(temporary),
            "policy_digest": GOV.policy_digest(genesis),
            "private_key_dependency": False,
            "result": "pass",
            "schema": SCHEMA,
        }
        write_value(temporary, MANIFEST_NAME, manifest)
        os.rename(temporary, output)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
    return verify_ceremony(output)


def verify_ceremony(root: Path) -> dict[str, Any]:
    require(root.is_dir() and not root.is_symlink(), "ceremony root is not a regular directory")
    manifest = read_object(root / MANIFEST_NAME, "ceremony manifest")
    require(
        set(manifest)
        == {"files", "policy_digest", "private_key_dependency", "result", "schema"},
        "ceremony manifest fields are not closed",
    )
    require(manifest["schema"] == SCHEMA and manifest["result"] == "pass", "ceremony manifest did not pass")
    require(manifest["private_key_dependency"] is False, "ceremony verification has a private-key dependency")
    entries = manifest["files"]
    require(isinstance(entries, list) and entries, "ceremony file inventory is empty")
    expected_names = [item.get("path") for item in entries if isinstance(item, dict)]
    require(expected_names == sorted(expected_names, key=lambda item: item.encode()), "ceremony files are not sorted")
    require(len(expected_names) == len(set(expected_names)), "ceremony files are duplicated")
    actual_names = sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name != MANIFEST_NAME
    )
    require(
        actual_names == sorted([*expected_names, REPORT_NAME]),
        "ceremony public file closure differs",
    )
    for item in entries:
        require(
            isinstance(item, dict) and set(item) == {"path", "sha256", "size_bytes"},
            "ceremony file entry fields are not closed",
        )
        path = root / item["path"]
        data = read_regular(path, f"ceremony file {item['path']}")
        require(item["sha256"] == digest_bytes(data), f"ceremony file digest differs: {item['path']}")
        require(item["size_bytes"] == len(data), f"ceremony file size differs: {item['path']}")

    genesis = GOV.load_policy(root / POLICY_NAME, require_genesis=True)
    require(manifest["policy_digest"] == GOV.policy_digest(genesis), "ceremony policy digest differs")
    release_payload = GOV.load_payload(root / "release-payload.json")
    release_signatures = [
        GOV.load_detached_signature(root / f"release-signature-{index}.json")
        for index in (1, 2)
    ]
    GOV.verify_release_quorum(
        genesis,
        release_payload,
        sorted(release_signatures, key=lambda item: item["key_id"]),
    )
    publication_payload = GOV.load_payload(root / "publication-payload.json")
    publication_signatures = [
        GOV.load_detached_signature(root / f"publication-signature-{index}.json")
        for index in (1, 2)
    ]
    GOV.verify_publication_quorum(
        genesis,
        publication_payload,
        sorted(publication_signatures, key=lambda item: item["key_id"]),
    )
    rotation = GOV.load_policy(root / "rotation-policy.json")
    GOV.verify_transition(
        genesis, rotation, GOV.load_transition(root / "rotation-transition.json")
    )
    revocation = GOV.load_policy(root / "revocation-policy.json")
    GOV.verify_transition(
        rotation,
        revocation,
        GOV.load_transition(root / "revocation-transition.json"),
    )
    report = read_object(root / REPORT_NAME, "governance report")
    expected_manifest_digest = digest_bytes(canonical_json(manifest))
    require(
        report == build_report(genesis, expected_manifest_digest),
        "governance report does not reproduce from public evidence",
    )
    return {
        "ceremony_sha256": digest_bytes(canonical_json(manifest)),
        "policy_digest": GOV.policy_digest(genesis),
        "report_sha256": digest_file(root / REPORT_NAME),
        "result": "pass",
    }


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(description=__doc__)
    subcommands = command.add_subparsers(dest="command", required=True)
    run = subcommands.add_parser("run")
    run.add_argument("--genesis-key", type=Path, action="append", required=True)
    run.add_argument("--successor-key", type=Path, action="append", required=True)
    run.add_argument("--release-payload", type=Path, required=True)
    run.add_argument("--publication-payload", type=Path, required=True)
    run.add_argument("--out", type=Path, required=True)
    verify = subcommands.add_parser("verify")
    verify.add_argument("--ceremony", type=Path, required=True)
    return command


def main(arguments: list[str] | None = None) -> int:
    options = parser().parse_args(arguments)
    try:
        if options.command == "run":
            release_payload = GOV.load_payload(options.release_payload)
            publication_payload = GOV.load_payload(options.publication_payload)
            result = run_ceremony(
                options.genesis_key,
                options.successor_key,
                release_payload,
                publication_payload,
                options.out,
            )
        else:
            result = verify_ceremony(options.ceremony)
        print(
            f"verified governance ceremony {result['ceremony_sha256']} "
            f"policy={result['policy_digest']}"
        )
        return 0
    except (CeremonyError, GOV.GovernanceError, OSError) as error:
        print(f"r4-governance-ceremony: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
