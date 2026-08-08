#!/usr/bin/env python3
"""Execute the R4 post-publication negative controls on isolated clones.

The runner starts and ends by independently verifying the pristine signed
publication.  It never accepts a private key.  The valid-inventory control may
consume additional *detached signatures* made by an external custodian so it
can construct another valid quorum and prove that its signature inventory has
a different content-addressed publication root.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import itertools
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
from typing import Any, Callable, NoReturn


SCHEMA = "wasm-biotic.r4-publication-negative-controls.v1"
CONTROL_NAMES = (
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
)
MAX_JSON_BYTES = 16 * 1024 * 1024


class NegativeControlError(RuntimeError):
    """The pristine root failed or a required mutation was not rejected."""


def fail(message: str) -> NoReturn:
    raise NegativeControlError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def _load_publication() -> Any:
    path = Path(__file__).with_name("r4-publication.py")
    specification = importlib.util.spec_from_file_location(
        "wasm_biotic_r4_publication_negatives", path
    )
    if specification is None or specification.loader is None:
        fail(f"cannot load publication verifier at {path}")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


PUBLICATION = _load_publication()
GOVERNANCE = PUBLICATION.GOVERNANCE


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


def _regular_directory(path: Path, where: str) -> Path:
    try:
        information = path.lstat()
    except OSError as error:
        fail(f"cannot inspect {where} at {path}: {error}")
    if stat.S_ISLNK(information.st_mode) or not stat.S_ISDIR(information.st_mode):
        fail(f"{where} must be a directory and not a link: {path}")
    return path


def _clone(publication: Path, root: Path, label: str) -> Path:
    destination = root / label / publication.name
    destination.parent.mkdir(mode=0o755)
    shutil.copytree(publication, destination, copy_function=shutil.copy2)
    return destination


def _must_reject(label: str, operation: Callable[[], Any]) -> bool:
    try:
        operation()
    except PUBLICATION.PublicationError:
        return True
    fail(f"{label} mutation was accepted")


def _claimed_object(clone: Path, *, role: str, target: str | None = None) -> Path:
    claim, _ = PUBLICATION.read_canonical_file(
        clone / PUBLICATION.CLAIM_NAME, "publication claim"
    )
    entry = PUBLICATION._entry_by_role(claim, role, target)
    return clone / entry["path"]


def _substitute_policy(policy: dict[str, Any]) -> dict[str, Any]:
    substituted = copy.deepcopy(policy)
    entry = substituted["keys"][0]
    public_key = bytearray.fromhex(entry["public_key_hex"])
    public_key[0] ^= 1
    entry["public_key_hex"] = bytes(public_key).hex()
    entry["key_id"] = GOVERNANCE.digest_bytes(bytes(public_key))
    substituted["keys"].sort(key=lambda item: item["key_id"])
    try:
        return GOVERNANCE.validate_policy(
            substituted, require_genesis=True, where="substituted policy"
        )
    except GOVERNANCE.GovernanceError as error:
        fail(f"cannot construct a distinct valid policy control: {error}")


def _load_signature(path: Path, where: str) -> dict[str, Any]:
    try:
        return GOVERNANCE.load_detached_signature(path)
    except (OSError, GOVERNANCE.GovernanceError) as error:
        fail(f"cannot load {where} at {path}: {error}")


def _published_signatures(publication: Path) -> list[dict[str, Any]]:
    paths = PUBLICATION._publication_signature_paths(publication)
    return [
        _load_signature(publication / relative, f"published signature {relative}")
        for relative in sorted(paths)
    ]


def _alternate_quorum(
    policy: dict[str, Any],
    payload: dict[str, Any],
    published: list[dict[str, Any]],
    supplied_paths: list[Path],
) -> list[dict[str, Any]]:
    candidates = {item["key_id"]: item for item in published}
    for index, path in enumerate(supplied_paths):
        item = _load_signature(path, f"alternate signature {index}")
        prior = candidates.get(item["key_id"])
        if prior is not None and canonical_json(prior) != canonical_json(item):
            fail(f"alternate signature {index} conflicts for {item['key_id']}")
        candidates[item["key_id"]] = item
    original_inventory = tuple(sorted(item["key_id"] for item in published))
    threshold = policy["threshold"]
    ordered = sorted(candidates.values(), key=lambda item: item["key_id"])
    for size in range(threshold, len(ordered) + 1):
        for raw in itertools.combinations(ordered, size):
            inventory = tuple(item["key_id"] for item in raw)
            if inventory == original_inventory:
                continue
            try:
                GOVERNANCE.verify_release_quorum(policy, payload, list(raw))
            except GOVERNANCE.GovernanceError:
                continue
            return list(raw)
    fail(
        "no alternate valid signature inventory is available; supply a detached "
        "signature from another active policy key"
    )


def _valid_inventory_control(
    publication: Path,
    policy_path: Path,
    release_public_key_path: Path,
    alternate_signature_paths: list[Path],
    root: Path,
    original_root: str,
) -> bool:
    policy, policy_bytes = PUBLICATION._load_external_policy(policy_path)
    claim, claim_bytes, payload = PUBLICATION._base_documents(publication)
    published = _published_signatures(publication)
    alternate = _alternate_quorum(policy, payload, published, alternate_signature_paths)
    descriptor = PUBLICATION.publication_root_descriptor(
        claim, claim_bytes, payload, policy_bytes, alternate
    )
    alternate_root = digest_bytes(canonical_json(descriptor))
    require(
        alternate_root != original_root,
        "alternate valid signature inventory did not change the publication root",
    )
    clone = _clone(publication, root, "valid-inventory")
    signature_directory = clone / PUBLICATION.SIGNATURE_DIRECTORY
    for child in signature_directory.iterdir():
        child.unlink()
    for signature in alternate:
        path = signature_directory / f"{signature['key_id'][7:]}.json"
        path.write_bytes(canonical_json(signature))
        path.chmod(0o644)
    descriptor_path = clone / PUBLICATION.PUBLICATION_ROOT_NAME
    descriptor_path.write_bytes(canonical_json(descriptor))
    descriptor_path.chmod(0o644)
    rejected_under_old_name = _must_reject(
        "valid signature inventory under old root name",
        lambda: PUBLICATION.verify(clone, policy_path, release_public_key_path),
    )
    correctly_named = clone.with_name(alternate_root.replace(":", "-", 1))
    os.replace(clone, correctly_named)
    verified = PUBLICATION.verify(
        correctly_named, policy_path, release_public_key_path
    )
    require(
        verified["publication_root"] == alternate_root,
        "alternate valid signature inventory did not verify under its derived root",
    )
    return rejected_under_old_name


def run_controls(
    publication: Path,
    policy_path: Path,
    release_public_key_path: Path,
    alternate_signature_paths: list[Path],
) -> dict[str, Any]:
    publication = _regular_directory(publication, "signed publication")
    pristine_before = PUBLICATION.verify(
        publication, policy_path, release_public_key_path
    )
    publication_root = pristine_before["publication_root"]
    controls: dict[str, bool] = {}
    with tempfile.TemporaryDirectory(prefix="r4-publication-negatives-") as temporary:
        root = Path(temporary)

        clone = _clone(publication, root, "claim-substitution")
        claim_path = clone / PUBLICATION.CLAIM_NAME
        claim, _ = PUBLICATION.read_canonical_file(claim_path, "publication claim")
        claim["external_north_star_claim"] = True
        claim_path.write_bytes(canonical_json(claim))
        controls["claim_substitution_rejected"] = _must_reject(
            "claim substitution",
            lambda: PUBLICATION.verify(clone, policy_path, release_public_key_path),
        )

        clone = _clone(publication, root, "extra-object")
        extra = clone / PUBLICATION.OBJECT_ALGORITHM_DIRECTORY / ("0" * 64)
        extra.write_bytes(b"extra\n")
        extra.chmod(0o644)
        controls["extra_object_rejected"] = _must_reject(
            "extra object",
            lambda: PUBLICATION.verify(clone, policy_path, release_public_key_path),
        )

        clone = _clone(publication, root, "missing-object")
        _claimed_object(clone, role="component-release-archive").unlink()
        controls["missing_object_rejected"] = _must_reject(
            "missing object",
            lambda: PUBLICATION.verify(clone, policy_path, release_public_key_path),
        )

        clone = _clone(publication, root, "mode-drift")
        (clone / PUBLICATION.CLAIM_NAME).chmod(0o600)
        controls["mode_drift_rejected"] = _must_reject(
            "mode drift",
            lambda: PUBLICATION.verify(clone, policy_path, release_public_key_path),
        )

        clone = _clone(publication, root, "object-substitution")
        _claimed_object(clone, role="component-release-archive").write_bytes(
            b"substituted\n"
        )
        controls["object_substitution_rejected"] = _must_reject(
            "object substitution",
            lambda: PUBLICATION.verify(clone, policy_path, release_public_key_path),
        )

        clone = _clone(publication, root, "platform-mismatch")
        native_path = _claimed_object(
            clone,
            role="native-attestation",
            target=PUBLICATION.CLOSED_TARGETS[0],
        )
        native, _ = PUBLICATION.read_canonical_file(native_path, "native attestation")
        native["platform"]["target"] = PUBLICATION.CLOSED_TARGETS[1]
        native_path.write_bytes(canonical_json(native))
        controls["platform_mismatch_rejected"] = _must_reject(
            "platform mismatch",
            lambda: PUBLICATION.verify(clone, policy_path, release_public_key_path),
        )

        policy, _ = PUBLICATION._load_external_policy(policy_path)
        substituted_policy = root / "substituted-policy.json"
        substituted_policy.write_bytes(canonical_json(_substitute_policy(policy)))
        substituted_policy.chmod(0o644)
        controls["policy_substitution_rejected"] = _must_reject(
            "policy substitution",
            lambda: PUBLICATION.verify(
                publication, substituted_policy, release_public_key_path
            ),
        )

        renamed = root / "renamed-publication" / ("sha256-" + "0" * 64)
        renamed.parent.mkdir(mode=0o755)
        shutil.copytree(publication, renamed, copy_function=shutil.copy2)
        controls["root_rename_rejected"] = _must_reject(
            "root rename",
            lambda: PUBLICATION.verify(
                renamed, policy_path, release_public_key_path
            ),
        )

        clone = _clone(publication, root, "signature-tamper")
        signature_path = sorted(
            (clone / PUBLICATION.SIGNATURE_DIRECTORY).iterdir(),
            key=lambda item: item.name,
        )[0]
        signature, _ = PUBLICATION.read_canonical_file(
            signature_path, "detached signature"
        )
        first = signature["signature_hex"][0]
        signature["signature_hex"] = ("0" if first != "0" else "1") + signature[
            "signature_hex"
        ][1:]
        signature_path.write_bytes(canonical_json(signature))
        controls["signature_tamper_rejected"] = _must_reject(
            "signature tamper",
            lambda: PUBLICATION.verify(clone, policy_path, release_public_key_path),
        )

        controls["valid_signature_inventory_substitution_changed_root"] = (
            _valid_inventory_control(
                publication,
                policy_path,
                release_public_key_path,
                alternate_signature_paths,
                root,
                publication_root,
            )
        )

    pristine_after = PUBLICATION.verify(
        publication, policy_path, release_public_key_path
    )
    require(
        pristine_after == pristine_before,
        "pristine publication verification changed after negative controls",
    )
    require(
        set(controls) == set(CONTROL_NAMES) and all(controls.values()),
        "publication negative-control inventory is incomplete",
    )
    return {
        "blockers": [],
        "controls": {name: controls[name] for name in sorted(controls)},
        "pristine_verified_after_mutations": True,
        "pristine_verified_before_mutations": True,
        "private_key_dependency": False,
        "publication_root": publication_root,
        "result": "pass",
        "schema": SCHEMA,
    }


def write_atomic(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.tmp-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical_json(value))
        temporary.chmod(0o644)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(description=__doc__)
    command.add_argument("--publication", required=True, type=Path)
    command.add_argument("--policy", required=True, type=Path)
    command.add_argument("--release-public-key", required=True, type=Path)
    command.add_argument(
        "--alternate-signature",
        action="append",
        default=[],
        type=Path,
        help="additional detached signature; may repeat; never a private key",
    )
    command.add_argument("--out", required=True, type=Path)
    return command


def main(arguments: list[str] | None = None) -> int:
    options = parser().parse_args(arguments)
    try:
        report = run_controls(
            options.publication,
            options.policy,
            options.release_public_key,
            options.alternate_signature,
        )
        write_atomic(options.out, report)
        print(
            f"publication-negatives {digest_bytes(canonical_json(report))} {options.out}"
        )
        return 0
    except (NegativeControlError, PUBLICATION.PublicationError, OSError) as error:
        print(f"r4-publication-negatives: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
