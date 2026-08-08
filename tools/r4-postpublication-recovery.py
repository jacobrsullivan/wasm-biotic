#!/usr/bin/env python3
"""Verify an R4 publication, then rerun clean public-only recovery.

This post-publication gate resolves the unavoidable evidence ordering: the
signed root contains the pre-publication lifecycle proof, while this external
report first verifies that final root and independently pinned policy and only
then performs the same lifecycle from a fresh mechanism-state directory.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
from typing import Any, NoReturn


SCHEMA = "wasm-biotic.r4-postpublication-recovery.v1"
LAYOUT_SCHEMA = "wasm-biotic.r4-public-install-layout.v1"
LIFECYCLE_SCHEMA = "wasm-biotic.r4-public-install-lifecycle.v1"
CLOSED_TARGETS = ("aarch64-apple-darwin", "x86_64-unknown-linux-gnu")
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
PUBLIC_KEY_RE = re.compile(r"[0-9a-f]{64}\Z")
WITNESS_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")


class RecoveryError(RuntimeError):
    """The final publication or fresh public recovery did not verify."""


def fail(message: str) -> NoReturn:
    raise RecoveryError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def load_tool(filename: str, module_name: str) -> Any:
    path = Path(__file__).with_name(filename)
    specification = importlib.util.spec_from_file_location(module_name, path)
    require(
        specification is not None and specification.loader is not None,
        f"cannot load required recovery tool at {path}",
    )
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


PUBLICATION = load_tool("r4-publication.py", "wasm_biotic_r4_recovery_publication")
ARCHIVE = load_tool("r4-install-archive.py", "wasm_biotic_r4_recovery_archive")


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
    return path.read_bytes()


def read_canonical(path: Path, where: str) -> tuple[dict[str, Any], bytes]:
    data = read_regular(path, where)
    try:
        value = json.loads(data)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise RecoveryError(f"cannot parse {where}: {error}") from error
    require(isinstance(value, dict), f"{where} must be a JSON object")
    require(canonical_json(value) == data, f"{where} is not canonical JSON")
    return value, data


def role_entry(
    claim: dict[str, Any], role: str, target: str | None = None
) -> dict[str, Any]:
    matches = [
        item
        for item in claim.get("objects", [])
        if isinstance(item, dict)
        and item.get("role") == role
        and item.get("target") == target
    ]
    require(len(matches) == 1, f"publication lacks exact {role} object for {target}")
    return matches[0]


def relative_path(value: Any, where: str) -> PurePosixPath:
    require(isinstance(value, str) and value, f"{where} must be a relative path")
    path = PurePosixPath(value)
    require(
        not path.is_absolute()
        and path.as_posix() == value
        and all(part not in ("", ".", "..") for part in path.parts),
        f"{where} is unsafe",
    )
    return path


def validate_layout(value: Any) -> dict[str, Any]:
    require(isinstance(value, dict), "install layout must be an object")
    require(
        set(value)
        == {
            "archive_tool",
            "incumbent",
            "leaf_public_key",
            "operator_capacity",
            "public_install_tool",
            "schema",
            "successor",
            "targets",
            "trust_policy",
        },
        "install layout fields are not closed",
    )
    require(value["schema"] == LAYOUT_SCHEMA, "install layout schema differs")
    for field in (
        "archive_tool",
        "incumbent",
        "leaf_public_key",
        "operator_capacity",
        "public_install_tool",
        "successor",
        "trust_policy",
    ):
        relative_path(value[field], f"install layout.{field}")
    targets = value["targets"]
    require(
        isinstance(targets, dict) and tuple(targets) == CLOSED_TARGETS,
        "install layout target set/order differs",
    )
    for target in CLOSED_TARGETS:
        item = targets[target]
        require(
            isinstance(item, dict) and set(item) == {"kernel", "lifecycle_runner"},
            f"install layout target {target} fields differ",
        )
        relative_path(item["kernel"], f"install layout target {target}.kernel")
        relative_path(
            item["lifecycle_runner"],
            f"install layout target {target}.lifecycle_runner",
        )
    return value


def installed_path(root: Path, value: Any, where: str) -> Path:
    relative = relative_path(value, where)
    path = root.joinpath(*relative.parts)
    require(path.resolve(strict=False).is_relative_to(root.resolve()), f"{where} escaped install root")
    return path


def wrong_public_key(value: str) -> str:
    require(PUBLIC_KEY_RE.fullmatch(value) is not None, "installed leaf public key is malformed")
    replacement = "0" if value[0] != "0" else "1"
    wrong = replacement + value[1:]
    require(wrong != value, "cannot derive distinct wrong-key control")
    return wrong


def build_wrapper(
    *,
    publication_root: str,
    policy_digest: str,
    lifecycle: dict[str, Any],
    lifecycle_bytes: bytes,
    targets: list[str],
) -> dict[str, Any]:
    require(DIGEST_RE.fullmatch(publication_root) is not None, "publication root is invalid")
    require(DIGEST_RE.fullmatch(policy_digest) is not None, "policy digest is invalid")
    require(targets == list(CLOSED_TARGETS), "post-publication target set differs")
    host = lifecycle.get("host")
    require(
        lifecycle.get("schema") == LIFECYCLE_SCHEMA
        and lifecycle.get("outcome") == "pass"
        and lifecycle.get("private_key_argument_supported") is False
        and lifecycle.get("private_key_required_or_read") is False,
        "fresh post-publication lifecycle did not pass public-only checks",
    )
    operator_capacity = lifecycle.get("operator_capacity")
    require(
        isinstance(operator_capacity, dict)
        and set(operator_capacity)
        == {"observed_sha256", "within_verified_install"}
        and DIGEST_RE.fullmatch(operator_capacity.get("observed_sha256", ""))
        is not None
        and operator_capacity.get("within_verified_install") is True,
        "fresh lifecycle did not bind installed operator capacity",
    )
    require(
        isinstance(host, dict)
        and host.get("physical_machine") is True
        and host.get("target") in CLOSED_TARGETS
        and isinstance(host.get("witness_id"), str)
        and WITNESS_RE.fullmatch(host["witness_id"]) is not None,
        "fresh lifecycle is not bound to a named physical witness",
    )
    return {
        "blockers": [],
        "independent_policy_sha256": policy_digest,
        "lifecycle": {
            "fresh_mechanism_state": True,
            "operator_capacity_sha256": operator_capacity["observed_sha256"],
            "outcome": "pass",
            "private_key_argument_supported": False,
            "private_key_required_or_read": False,
            "report_sha256": digest_bytes(lifecycle_bytes),
        },
        "phase": "post-publication",
        "private_key_dependency": False,
        "publication": {
            "publication_root": publication_root,
            "verified_before_recovery": True,
        },
        "result": "pass",
        "schema": SCHEMA,
        "targets": targets,
    }


def run(options: argparse.Namespace) -> dict[str, Any]:
    require(not options.extracted_root.exists(), "fresh extraction root already exists")
    require(not options.work_root.exists(), "fresh recovery work root already exists")
    require(not options.lifecycle_out.exists(), "lifecycle output already exists")
    require(not options.out.exists(), "post-publication report already exists")
    try:
        publication_report = PUBLICATION.verify(
            options.publication, options.policy, options.release_public_key
        )
        claim, _ = PUBLICATION.read_canonical_file(
            options.publication / PUBLICATION.CLAIM_NAME, "publication claim"
        )
    except Exception as error:
        raise RecoveryError(f"final signed publication did not verify: {error}") from error
    targets = claim.get("targets")
    require(targets == list(CLOSED_TARGETS), "publication target set differs")
    require(options.target in CLOSED_TARGETS, "recovery target is outside the closed set")
    install_entry = role_entry(claim, "install-archive")
    install_archive = options.publication / install_entry["path"]
    require(digest_file(install_archive) == install_entry["digest"], "install archive object digest differs")
    try:
        archive_digest, _ = ARCHIVE.extract_archive(
            install_archive, options.extracted_root
        )
    except Exception as error:
        raise RecoveryError(f"cannot safely extract install archive: {error}") from error
    require(archive_digest == install_entry["digest"], "extracted install archive digest differs")
    layout, _ = read_canonical(options.extracted_root / "INSTALL.json", "install layout")
    validate_layout(layout)
    installed_policy = installed_path(
        options.extracted_root, layout["trust_policy"], "install layout.trust_policy"
    )
    policy_digest = digest_file(options.policy)
    require(digest_file(installed_policy) == policy_digest, "installed policy differs from independent policy")
    target_layout = layout["targets"][options.target]
    kernel = installed_path(options.extracted_root, target_layout["kernel"], "installed kernel")
    lifecycle_runner = installed_path(
        options.extracted_root,
        target_layout["lifecycle_runner"],
        "installed lifecycle runner",
    )
    expected_kernel = role_entry(claim, "native-executable", options.target)["digest"]
    require(digest_file(kernel) == expected_kernel, "installed kernel differs from published native executable")
    incumbent = installed_path(options.extracted_root, layout["incumbent"], "installed incumbent")
    successor = installed_path(options.extracted_root, layout["successor"], "installed successor")
    leaf_path = installed_path(
        options.extracted_root, layout["leaf_public_key"], "installed leaf public key"
    )
    leaf_bytes = read_regular(leaf_path, "installed leaf public key")
    require(len(leaf_bytes) == 32, "installed leaf public key is not raw Ed25519 bytes")
    require(
        leaf_bytes
        == read_regular(options.release_public_key, "independent release public key"),
        "installed leaf public key differs from the independent release key",
    )
    leaf_key = leaf_bytes.hex()
    archive_tool = installed_path(
        options.extracted_root, layout["archive_tool"], "installed archive tool"
    )
    public_install_tool = installed_path(
        options.extracted_root,
        layout["public_install_tool"],
        "installed public install tool",
    )
    operator_capacity = installed_path(
        options.extracted_root,
        layout["operator_capacity"],
        "installed operator capacity",
    )
    arguments = [
        sys.executable,
        str(public_install_tool),
        "--kernel",
        str(kernel),
        "--expected-kernel-sha256",
        expected_kernel,
        "--incumbent",
        str(incumbent),
        "--successor",
        str(successor),
        "--public-key-hex",
        leaf_key,
        "--wrong-public-key-hex",
        wrong_public_key(leaf_key),
        "--lifecycle-runner",
        str(lifecycle_runner),
        "--operator-capacity",
        str(operator_capacity),
        "--install-archive",
        str(install_archive),
        "--install-archive-sha256",
        archive_digest,
        "--archive-tool",
        str(archive_tool),
        "--extracted-root",
        str(options.extracted_root),
        "--work-root",
        str(options.work_root),
        "--target",
        options.target,
        "--witness-id",
        options.witness_id,
        "--epoch",
        str(options.epoch),
        "--out",
        str(options.lifecycle_out),
    ]
    result = subprocess.run(
        arguments,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=1800,
    )
    require(result.returncode >= 0, "public install lifecycle terminated by a signal")
    require(result.returncode == 0, "public install lifecycle rejected the final publication")
    lifecycle, lifecycle_bytes = read_canonical(
        options.lifecycle_out, "post-publication lifecycle report"
    )
    wrapper = build_wrapper(
        publication_root=publication_report["publication_root"],
        policy_digest=policy_digest,
        lifecycle=lifecycle,
        lifecycle_bytes=lifecycle_bytes,
        targets=targets,
    )
    options.out.parent.mkdir(parents=True, exist_ok=True)
    options.out.write_bytes(canonical_json(wrapper))
    return wrapper


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(description=__doc__)
    command.add_argument("--publication", required=True, type=Path)
    command.add_argument("--policy", required=True, type=Path)
    command.add_argument("--release-public-key", required=True, type=Path)
    command.add_argument("--target", required=True)
    command.add_argument("--witness-id", required=True)
    command.add_argument("--extracted-root", required=True, type=Path)
    command.add_argument("--work-root", required=True, type=Path)
    command.add_argument("--lifecycle-out", required=True, type=Path)
    command.add_argument("--out", required=True, type=Path)
    command.add_argument("--epoch", type=int, default=int(os.environ.get("SOURCE_DATE_EPOCH", "0")))
    return command


def main(arguments: list[str] | None = None) -> int:
    options = parser().parse_args(arguments)
    try:
        report = run(options)
        print(
            f"verified post-publication recovery {digest_file(options.out)} "
            f"root={report['publication']['publication_root']}"
        )
        return 0
    except (RecoveryError, OSError, UnicodeError, ValueError) as error:
        print(f"r4-postpublication-recovery: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
