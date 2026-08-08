#!/usr/bin/env python3
"""Exercise fail-closed controls against a real R0 release bundle.

The pristine bundle is read only. Every negative control operates on a fresh
temporary copy, invokes the production release verifier as a subprocess, and
requires rejection. A physical closure snapshot before and after the campaign
proves that the supplied bundle was not changed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any, Callable


SCHEMA = "wasm-biotic.r0-release-negative-matrix.v1"
HEX_64 = frozenset("0123456789abcdef")


class MatrixError(RuntimeError):
    """The negative-control campaign could not be completed safely."""


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
            size += len(block)
    return "sha256:" + digest.hexdigest(), size


def closure_snapshot(root: Path) -> dict[str, Any]:
    """Return a deterministic digest of every physical path and file byte."""

    if not root.is_dir() or root.is_symlink():
        raise MatrixError("bundle must be a real directory, not a symlink")
    directories: list[str] = []
    files: list[dict[str, Any]] = []
    for current, directory_names, file_names in os.walk(root, followlinks=False):
        directory_names.sort()
        file_names.sort()
        current_path = Path(current)
        for name in directory_names:
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
                raise MatrixError(f"bundle closure has a non-directory entry: {relative}")
            directories.append(relative)
        for name in file_names:
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
                raise MatrixError(f"bundle closure has a non-regular entry: {relative}")
            digest, size = sha256_file(path)
            files.append({"path": relative, "sha256": digest, "size_bytes": size})
    closure = {"directories": sorted(directories), "files": files}
    return {
        "closure_digest": sha256_bytes(canonical_json(closure)),
        "directory_count": len(directories),
        "file_count": len(files),
        "files_size_bytes": sum(item["size_bytes"] for item in files),
    }


def run_verifier(
    verifier: Path, bundle: Path, public_key_hex: str
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            sys.executable,
            str(verifier),
            "verify",
            str(bundle),
            "--expected-public-key-hex",
            public_key_hex,
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def load_claim(bundle: Path) -> dict[str, Any]:
    try:
        value = json.loads((bundle / "claim" / "manifest.json").read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MatrixError(f"cannot read claim manifest: {error}") from error
    if not isinstance(value, dict):
        raise MatrixError("claim manifest is not an object")
    return value


def write_claim(bundle: Path, claim: dict[str, Any]) -> None:
    (bundle / "claim" / "manifest.json").write_bytes(canonical_json(claim))


def mutate_schema_byte(path: Path, schema: bytes) -> None:
    """Change exactly one byte while preserving valid, canonical JSON."""

    raw = path.read_bytes()
    needle = schema + b".v1"
    replacement = schema + b".v0"
    if raw.count(needle) != 1 or len(needle) != len(replacement):
        raise MatrixError(f"cannot locate a unique schema marker in {path.name}")
    mutated = raw.replace(needle, replacement, 1)
    differences = sum(left != right for left, right in zip(raw, mutated))
    if len(raw) != len(mutated) or differences != 1:
        raise MatrixError(f"mutation of {path.name} did not change exactly one byte")
    path.write_bytes(mutated)


def ref_for_role(claim: dict[str, Any], field: str, role: str) -> dict[str, Any]:
    values = claim.get(field)
    if not isinstance(values, list):
        raise MatrixError(f"claim field {field!r} is not an array")
    matches = [item for item in values if isinstance(item, dict) and item.get("role") == role]
    if len(matches) != 1:
        raise MatrixError(f"claim does not contain exactly one {role!r} {field} entry")
    return matches[0]


def mutate_release_byte(bundle: Path) -> None:
    mutate_schema_byte(
        bundle / "release.json",
        b"wasm-biotic.component-complete-release-root",
    )


def mutate_claim_byte(bundle: Path) -> None:
    mutate_schema_byte(
        bundle / "claim" / "manifest.json",
        b"wasm-biotic.component-complete-claim-manifest",
    )


def mutate_signature_byte(bundle: Path) -> None:
    mutate_schema_byte(
        bundle / "claim" / "signature.json",
        b"wasm-biotic.component-complete-claim-signature",
    )


def remove_object(bundle: Path) -> None:
    reference = ref_for_role(load_claim(bundle), "objects", "native-executable")
    path = bundle / reference["path"]
    if not path.is_file() or path.is_symlink():
        raise MatrixError("native-executable object is not a regular file")
    path.unlink()


def remove_package_file(bundle: Path) -> None:
    reference = ref_for_role(load_claim(bundle), "trees", "incumbent-package")
    path = bundle / reference["path"] / "files" / "manifest.json"
    if not path.is_file() or path.is_symlink():
        raise MatrixError("retained incumbent manifest is not a regular file")
    path.unlink()


def add_unlisted_file(bundle: Path) -> None:
    path = bundle / "objects" / "unlisted-negative-control"
    if path.exists() or path.is_symlink():
        raise MatrixError("unlisted negative-control path unexpectedly exists")
    path.write_bytes(b"must be rejected\n")


def flip_component_complete_claim(bundle: Path) -> None:
    claim = load_claim(bundle)
    if claim.get("component_complete_claim") is not True:
        raise MatrixError("pristine component_complete_claim is not true")
    claim["component_complete_claim"] = False
    write_claim(bundle, claim)


def flip_c7_gate(bundle: Path) -> None:
    claim = load_claim(bundle)
    gates = claim.get("gates")
    if not isinstance(gates, dict) or gates.get("C7") != "pass":
        raise MatrixError("pristine C7 gate is not pass")
    gates["C7"] = "fail"
    write_claim(bundle, claim)


def insert_blocker(bundle: Path) -> None:
    claim = load_claim(bundle)
    blockers = claim.get("open_release_blockers")
    if not isinstance(blockers, list) or blockers:
        raise MatrixError("pristine open_release_blockers is not an empty array")
    blockers.append("unsigned-negative-control")
    write_claim(bundle, claim)


Mutation = Callable[[Path], None]


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(
        description="Run R0 release fail-closed controls against temporary bundle copies."
    )
    command.add_argument("--bundle", required=True, type=Path)
    command.add_argument("--public-key-hex", required=True)
    command.add_argument(
        "--verifier",
        type=Path,
        default=Path(__file__).with_name("component-release-bundle.py"),
    )
    command.add_argument("--out", type=Path)
    return command


def main(arguments: list[str] | None = None) -> int:
    options = parser().parse_args(arguments)
    bundle = options.bundle.resolve()
    verifier = options.verifier.resolve()
    public_key_hex = options.public_key_hex
    try:
        if (
            len(public_key_hex) != 64
            or any(character not in HEX_64 for character in public_key_hex)
        ):
            raise MatrixError("public key must be exactly 64 lowercase hexadecimal characters")
        if not verifier.is_file() or verifier.is_symlink():
            raise MatrixError("verifier must be a regular file")
        if options.out is not None:
            output = options.out.resolve()
            try:
                output.relative_to(bundle)
            except ValueError:
                pass
            else:
                raise MatrixError("output must not be written inside the pristine bundle")

        before = closure_snapshot(bundle)
        release_digest, _ = sha256_file(bundle / "release.json")
        expected_name = release_digest.replace("sha256:", "sha256-")
        if bundle.name != expected_name:
            raise MatrixError("bundle directory name does not match release.json digest")
        pristine_before = run_verifier(verifier, bundle, public_key_hex)
        if pristine_before.returncode != 0:
            raise MatrixError("production verifier rejected the pristine bundle before campaign")

        wrong_key = ("0" if public_key_hex[0] != "0" else "1") + public_key_hex[1:]
        controls: list[tuple[str, Mutation, str]] = [
            ("wrong-independently-pinned-key", lambda _bundle: None, wrong_key),
            ("wrong-content-addressed-directory-name", lambda _bundle: None, public_key_hex),
            ("release-json-byte-mutation", mutate_release_byte, public_key_hex),
            ("claim-manifest-byte-mutation", mutate_claim_byte, public_key_hex),
            ("claim-signature-byte-mutation", mutate_signature_byte, public_key_hex),
            ("missing-object", remove_object, public_key_hex),
            ("missing-retained-package-file", remove_package_file, public_key_hex),
            ("unlisted-extra-file", add_unlisted_file, public_key_hex),
            ("unsigned-component-complete-claim-flip", flip_component_complete_claim, public_key_hex),
            ("unsigned-c7-gate-flip", flip_c7_gate, public_key_hex),
            ("unsigned-blocker-insertion", insert_blocker, public_key_hex),
        ]
        outcomes: list[dict[str, Any]] = []
        with tempfile.TemporaryDirectory(prefix="wasm-biotic-r0-negative-") as temporary_text:
            temporary = Path(temporary_text)
            for index, (control, mutation, pinned_key) in enumerate(controls):
                copy_name = bundle.name
                if control == "wrong-content-addressed-directory-name":
                    copy_name = "sha256-" + ("0" * 64)
                    if copy_name == bundle.name:
                        copy_name = "sha256-" + ("1" * 64)
                copied_bundle = temporary / f"case-{index}" / copy_name
                copied_bundle.parent.mkdir()
                shutil.copytree(bundle, copied_bundle, symlinks=False)
                mutation(copied_bundle)
                result = run_verifier(verifier, copied_bundle, pinned_key)
                rejected = result.returncode != 0
                outcomes.append(
                    {
                        "control": control,
                        "expected": "reject",
                        "observed": "reject" if rejected else "accept",
                        "result": "pass" if rejected else "fail",
                        "verifier_exit_code": result.returncode,
                    }
                )
                shutil.rmtree(copied_bundle.parent)

        after = closure_snapshot(bundle)
        pristine_after = run_verifier(verifier, bundle, public_key_hex)
        unchanged = before == after
        pristine_accepted_after = pristine_after.returncode == 0
        passed = sum(item["result"] == "pass" for item in outcomes)
        gate_passed = passed == len(outcomes) and unchanged and pristine_accepted_after
        report = {
            "schema": SCHEMA,
            "bundle_root_digest": release_digest,
            "certifier_key_id": sha256_bytes(bytes.fromhex(public_key_hex)),
            "pristine": {
                "before": {**before, "verifier_result": "accept"},
                "after": {
                    **after,
                    "verifier_result": "accept" if pristine_accepted_after else "reject",
                },
                "unchanged": unchanged,
            },
            "negative_controls": outcomes,
            "summary": {
                "controls": len(outcomes),
                "failed": len(outcomes) - passed,
                "gate_result": "pass" if gate_passed else "fail",
                "passed": passed,
            },
            "verifier": verifier.name,
        }
        encoded = canonical_json(report)
        if options.out is None:
            sys.stdout.buffer.write(encoded + b"\n")
        else:
            options.out.write_bytes(encoded)
        return 0 if gate_passed else 1
    except (MatrixError, OSError, shutil.Error) as error:
        print(f"r0-release-negative-matrix: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
