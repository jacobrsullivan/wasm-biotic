#!/usr/bin/env python3
"""Operator-side certifier governance for R4 release and publication approval.

This tool deliberately does not alter the kernel's single leaf certifier.  It
defines and verifies a closed 2-of-3 operator policy above that leaf, produces
domain-separated detached Ed25519 signatures, and validates monotonic policy
rotation or revocation transitions.  Private keys are read only by the
explicit ``sign`` command and are never placed in a policy or transition.

Only Python's standard library and the ``openssl`` executable are required.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any, NoReturn


POLICY_SCHEMA = "wasm-biotic.certifier-trust-policy.v1"
TRANSITION_STATEMENT_SCHEMA = "wasm-biotic.certifier-trust-transition-statement.v1"
TRANSITION_SCHEMA = "wasm-biotic.certifier-trust-transition.v1"
SIGNING_PAYLOAD_SCHEMA = "wasm-biotic.certifier-governance-signing-payload.v1"
DETACHED_SIGNATURE_SCHEMA = "wasm-biotic.certifier-detached-signature.v1"

RELEASE_DOMAIN = "wasm-biotic.certifier-governance.release.v1"
PUBLICATION_DOMAIN = "wasm-biotic.certifier-governance.publication.v1"
TRANSITION_OLD_DOMAIN = "wasm-biotic.certifier-governance.transition-old.v1"
TRANSITION_SUCCESSOR_DOMAIN = (
    "wasm-biotic.certifier-governance.transition-successor.v1"
)
DOMAINS = frozenset(
    {
        RELEASE_DOMAIN,
        PUBLICATION_DOMAIN,
        TRANSITION_OLD_DOMAIN,
        TRANSITION_SUCCESSOR_DOMAIN,
    }
)
DOMAIN_ALIASES = {
    "release": RELEASE_DOMAIN,
    "publication": PUBLICATION_DOMAIN,
    "transition-old": TRANSITION_OLD_DOMAIN,
    "transition-successor": TRANSITION_SUCCESSOR_DOMAIN,
}

ALGORITHM = "ed25519"
KEY_COUNT = 3
THRESHOLD = 2
PUBLIC_KEY_BYTES = 32
SIGNATURE_BYTES = 64
MAX_JSON_BYTES = 16 * 1024 * 1024
SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")

DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
PUBLIC_KEY_RE = re.compile(r"[0-9a-f]{64}\Z")
SIGNATURE_RE = re.compile(r"[0-9a-f]{128}\Z")


class GovernanceError(RuntimeError):
    """A closed governance or cryptographic precondition failed."""


def fail(message: str) -> NoReturn:
    raise GovernanceError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        fail(f"value cannot be represented as canonical JSON: {error}")


def digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            fail(f"JSON contains duplicate key {key!r}")
        value[key] = item
    return value


def _reject_numeric_constant(value: str) -> NoReturn:
    fail(f"JSON contains forbidden numeric constant {value}")


def parse_canonical_json(data: bytes, where: str) -> Any:
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_numeric_constant,
        )
    except GovernanceError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{where} is not valid UTF-8 JSON: {error}")
    if canonical_json(value) != data:
        fail(f"{where} is not canonical JSON")
    return value


def read_regular(path: Path, where: str, *, maximum: int = MAX_JSON_BYTES) -> bytes:
    try:
        information = path.lstat()
    except FileNotFoundError:
        fail(f"{where} is missing: {path}")
    if stat.S_ISLNK(information.st_mode) or not stat.S_ISREG(information.st_mode):
        fail(f"{where} must be a regular file, not a link or special entry")
    if information.st_size > maximum:
        fail(f"{where} exceeds the {maximum}-byte limit")
    return path.read_bytes()


def load_canonical_object(path: Path, where: str) -> dict[str, Any]:
    value = parse_canonical_json(read_regular(path, where), where)
    if not isinstance(value, dict):
        fail(f"{where} must be a JSON object")
    return value


def require_fields(value: Any, fields: tuple[str, ...], where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{where} must be an object")
    expected = set(fields)
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        fail(f"{where} has missing fields {missing} and unknown fields {extra}")
    return value


def require_string(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value:
        fail(f"{where} must be a non-empty string")
    return value


def require_digest(value: Any, where: str) -> str:
    value = require_string(value, where)
    if DIGEST_RE.fullmatch(value) is None:
        fail(f"{where} must be sha256: followed by 64 lowercase hexadecimal digits")
    return value


def require_positive_integer(value: Any, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        fail(f"{where} must be a positive integer")
    return value


def _require_sorted_unique(values: list[str], where: str) -> None:
    if values != sorted(values):
        fail(f"{where} must be sorted bytewise")
    if len(values) != len(set(values)):
        fail(f"{where} must not contain duplicates")


def validate_policy(
    value: Any, *, require_genesis: bool = False, where: str = "policy"
) -> dict[str, Any]:
    """Validate the exact canonical policy value and return it unchanged."""

    policy = require_fields(
        value,
        (
            "schema",
            "generation",
            "threshold",
            "keys",
            "revoked_key_ids",
            "predecessor_policy_digest",
        ),
        where,
    )
    if policy["schema"] != POLICY_SCHEMA:
        fail(f"{where}.schema must be {POLICY_SCHEMA!r}")
    generation = require_positive_integer(policy["generation"], f"{where}.generation")
    if policy["threshold"] != THRESHOLD or isinstance(policy["threshold"], bool):
        fail(f"{where}.threshold must be exactly {THRESHOLD}")

    raw_keys = policy["keys"]
    if not isinstance(raw_keys, list) or len(raw_keys) != KEY_COUNT:
        fail(f"{where}.keys must contain exactly {KEY_COUNT} active keys")
    key_ids: list[str] = []
    public_keys: set[str] = set()
    for index, raw_key in enumerate(raw_keys):
        key_where = f"{where}.keys[{index}]"
        key = require_fields(
            raw_key, ("algorithm", "key_id", "public_key_hex"), key_where
        )
        if key["algorithm"] != ALGORITHM:
            fail(f"{key_where}.algorithm must be {ALGORITHM!r}")
        key_id = require_digest(key["key_id"], f"{key_where}.key_id")
        public_key_hex = require_string(
            key["public_key_hex"], f"{key_where}.public_key_hex"
        )
        if PUBLIC_KEY_RE.fullmatch(public_key_hex) is None:
            fail(f"{key_where}.public_key_hex must be 64 lowercase hexadecimal digits")
        expected_key_id = digest_bytes(bytes.fromhex(public_key_hex))
        if key_id != expected_key_id:
            fail(f"{key_where}.key_id does not match its public key bytes")
        if public_key_hex in public_keys:
            fail(f"{where}.keys contains duplicate public key bytes")
        public_keys.add(public_key_hex)
        key_ids.append(key_id)
    _require_sorted_unique(key_ids, f"{where}.keys by key_id")

    raw_revocations = policy["revoked_key_ids"]
    if not isinstance(raw_revocations, list):
        fail(f"{where}.revoked_key_ids must be an array")
    revocations = [
        require_digest(item, f"{where}.revoked_key_ids[{index}]")
        for index, item in enumerate(raw_revocations)
    ]
    _require_sorted_unique(revocations, f"{where}.revoked_key_ids")
    overlap = sorted(set(key_ids) & set(revocations))
    if overlap:
        fail(f"{where} lists active keys as revoked: {overlap}")

    predecessor = policy["predecessor_policy_digest"]
    if generation == 1:
        if predecessor is not None:
            fail(f"{where} generation 1 must have a null predecessor")
        if revocations:
            fail(f"{where} genesis must have no revocations")
    else:
        require_digest(predecessor, f"{where}.predecessor_policy_digest")
    if require_genesis and generation != 1:
        fail(f"{where} is not a generation-1 genesis policy")
    return policy


def load_policy(path: Path, *, require_genesis: bool = False) -> dict[str, Any]:
    return validate_policy(
        load_canonical_object(path, "policy"), require_genesis=require_genesis
    )


def policy_digest(policy: dict[str, Any]) -> str:
    validate_policy(policy)
    return digest_bytes(canonical_json(policy))


def _active_keys(policy: dict[str, Any]) -> dict[str, str]:
    validate_policy(policy)
    return {item["key_id"]: item["public_key_hex"] for item in policy["keys"]}


def validate_payload(value: Any, where: str = "payload") -> dict[str, Any]:
    if not isinstance(value, dict) or not value:
        fail(f"{where} must be a non-empty JSON object")
    schema = require_string(value.get("schema"), f"{where}.schema")
    if not schema.isascii() or any(ord(character) < 33 for character in schema):
        fail(f"{where}.schema must be printable non-whitespace ASCII")
    canonical_json(value)
    return value


def _require_domain(domain: str) -> str:
    if domain not in DOMAINS:
        fail(f"unsupported signing domain {domain!r}")
    return domain


def signing_payload(
    policy: dict[str, Any], domain: str, payload: dict[str, Any]
) -> bytes:
    validate_policy(policy)
    _require_domain(domain)
    validate_payload(payload)
    return canonical_json(
        {
            "domain": domain,
            "payload": payload,
            "policy_digest": policy_digest(policy),
            "schema": SIGNING_PAYLOAD_SCHEMA,
        }
    )


def _openssl(arguments: list[str], where: str) -> subprocess.CompletedProcess[bytes]:
    executable = shutil.which("openssl")
    if executable is None:
        fail("openssl is required but was not found on PATH")
    result = subprocess.run(
        [executable, *arguments],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        fail(f"openssl failed while {where}: {detail}")
    return result


def _normalize_private_key(private_key: Path, output: Path) -> bytes:
    read_regular(private_key, "private key", maximum=64 * 1024)
    attempts = (
        [
            "pkey",
            "-in",
            str(private_key),
            "-inform",
            "DER",
            "-outform",
            "DER",
            "-out",
            str(output),
        ],
        ["pkey", "-in", str(private_key), "-outform", "DER", "-out", str(output)],
    )
    errors: list[str] = []
    executable = shutil.which("openssl")
    if executable is None:
        fail("openssl is required but was not found on PATH")
    for arguments in attempts:
        result = subprocess.run(
            [executable, *arguments],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if result.returncode == 0:
            os.chmod(output, 0o600)
            break
        errors.append(result.stderr.decode("utf-8", "replace").strip())
    else:
        fail("private key is not readable DER or PEM: " + " | ".join(errors))

    public_der = _openssl(
        [
            "pkey",
            "-in",
            str(output),
            "-inform",
            "DER",
            "-pubout",
            "-outform",
            "DER",
        ],
        "deriving the Ed25519 public key",
    ).stdout
    if len(public_der) != len(SPKI_PREFIX) + PUBLIC_KEY_BYTES or not public_der.startswith(
        SPKI_PREFIX
    ):
        fail("private key is not Ed25519")
    return public_der[len(SPKI_PREFIX) :]


def public_key_from_private(private_key: Path) -> bytes:
    with tempfile.TemporaryDirectory(prefix="wasm-biotic-r4-key-") as temporary:
        normalized = Path(temporary) / "private.pk8"
        return _normalize_private_key(private_key, normalized)


def _sign_bytes(private_key: Path, data: bytes) -> tuple[bytes, bytes]:
    with tempfile.TemporaryDirectory(prefix="wasm-biotic-r4-sign-") as temporary:
        root = Path(temporary)
        normalized = root / "private.pk8"
        public_key = _normalize_private_key(private_key, normalized)
        payload_path = root / "payload.json"
        signature_path = root / "signature.bin"
        payload_path.write_bytes(data)
        _openssl(
            [
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(normalized),
                "-keyform",
                "DER",
                "-in",
                str(payload_path),
                "-out",
                str(signature_path),
            ],
            "creating a detached Ed25519 signature",
        )
        signature = signature_path.read_bytes()
        if len(signature) != SIGNATURE_BYTES:
            fail("openssl produced a non-Ed25519 signature length")
        return public_key, signature


def _verify_bytes(public_key: bytes, data: bytes, signature: bytes) -> None:
    with tempfile.TemporaryDirectory(prefix="wasm-biotic-r4-verify-") as temporary:
        root = Path(temporary)
        public_path = root / "public.der"
        payload_path = root / "payload.json"
        signature_path = root / "signature.bin"
        public_path.write_bytes(SPKI_PREFIX + public_key)
        payload_path.write_bytes(data)
        signature_path.write_bytes(signature)
        _openssl(
            [
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
            "verifying a detached Ed25519 signature",
        )


def _detached_signature_for_context(
    policy: dict[str, Any],
    domain: str,
    payload: dict[str, Any],
    private_key: Path,
) -> dict[str, Any]:
    """Sign a context without membership checks; tests use this for attacks."""

    preimage = signing_payload(policy, domain, payload)
    public_key, signature = _sign_bytes(private_key, preimage)
    return {
        "schema": DETACHED_SIGNATURE_SCHEMA,
        "algorithm": ALGORITHM,
        "domain": domain,
        "policy_digest": policy_digest(policy),
        "payload_digest": digest_bytes(canonical_json(payload)),
        "key_id": digest_bytes(public_key),
        "signature_hex": signature.hex(),
    }


def sign_detached(
    policy: dict[str, Any],
    domain: str,
    payload: dict[str, Any],
    private_key: Path,
) -> dict[str, Any]:
    """Create one detached signature from an active policy member."""

    signature = _detached_signature_for_context(policy, domain, payload, private_key)
    key_id = signature["key_id"]
    if key_id in set(policy["revoked_key_ids"]):
        fail("private key is revoked by the selected policy")
    if key_id not in _active_keys(policy):
        fail("private key is not an active member of the selected policy")
    return signature


def validate_detached_signature(value: Any, where: str) -> dict[str, Any]:
    signature = require_fields(
        value,
        (
            "schema",
            "algorithm",
            "domain",
            "policy_digest",
            "payload_digest",
            "key_id",
            "signature_hex",
        ),
        where,
    )
    if signature["schema"] != DETACHED_SIGNATURE_SCHEMA:
        fail(f"{where}.schema must be {DETACHED_SIGNATURE_SCHEMA!r}")
    if signature["algorithm"] != ALGORITHM:
        fail(f"{where}.algorithm must be {ALGORITHM!r}")
    _require_domain(require_string(signature["domain"], f"{where}.domain"))
    require_digest(signature["policy_digest"], f"{where}.policy_digest")
    require_digest(signature["payload_digest"], f"{where}.payload_digest")
    require_digest(signature["key_id"], f"{where}.key_id")
    encoded = require_string(signature["signature_hex"], f"{where}.signature_hex")
    if SIGNATURE_RE.fullmatch(encoded) is None:
        fail(f"{where}.signature_hex must be 128 lowercase hexadecimal digits")
    return signature


def load_detached_signature(path: Path) -> dict[str, Any]:
    return validate_detached_signature(
        load_canonical_object(path, "detached signature"), "detached signature"
    )


def verify_quorum(
    policy: dict[str, Any],
    domain: str,
    payload: dict[str, Any],
    signatures: list[dict[str, Any]],
) -> list[str]:
    """Verify a sorted, unique threshold signature set for one exact context."""

    validate_policy(policy)
    _require_domain(domain)
    validate_payload(payload)
    if not isinstance(signatures, list):
        fail("signatures must be an array")
    if len(signatures) < THRESHOLD:
        fail(f"signature quorum requires at least {THRESHOLD} signatures")
    if len(signatures) > KEY_COUNT:
        fail(f"signature set exceeds the {KEY_COUNT}-member policy")

    validated = [
        validate_detached_signature(value, f"signatures[{index}]")
        for index, value in enumerate(signatures)
    ]
    signer_ids = [value["key_id"] for value in validated]
    _require_sorted_unique(signer_ids, "signatures by key_id")

    expected_policy = policy_digest(policy)
    expected_payload = digest_bytes(canonical_json(payload))
    active = _active_keys(policy)
    revoked = set(policy["revoked_key_ids"])
    preimage = signing_payload(policy, domain, payload)
    for index, signature in enumerate(validated):
        where = f"signatures[{index}]"
        if signature["domain"] != domain:
            fail(f"{where} was produced for a different domain")
        if signature["policy_digest"] != expected_policy:
            fail(f"{where} was produced for a different policy")
        if signature["payload_digest"] != expected_payload:
            fail(f"{where} was produced for a different payload")
        key_id = signature["key_id"]
        if key_id in revoked:
            fail(f"{where} was produced by a revoked key")
        public_key_hex = active.get(key_id)
        if public_key_hex is None:
            fail(f"{where} was produced by an unknown policy key")
        _verify_bytes(
            bytes.fromhex(public_key_hex),
            preimage,
            bytes.fromhex(signature["signature_hex"]),
        )
    return signer_ids


def verify_release_quorum(
    policy: dict[str, Any], payload: dict[str, Any], signatures: list[dict[str, Any]]
) -> list[str]:
    return verify_quorum(policy, RELEASE_DOMAIN, payload, signatures)


def verify_publication_quorum(
    policy: dict[str, Any], payload: dict[str, Any], signatures: list[dict[str, Any]]
) -> list[str]:
    return verify_quorum(policy, PUBLICATION_DOMAIN, payload, signatures)


def transition_statement(
    old_policy: dict[str, Any], new_policy: dict[str, Any], kind: str
) -> dict[str, Any]:
    """Validate a monotonic policy relationship and return its signed statement."""

    validate_policy(old_policy, where="old policy")
    validate_policy(new_policy, where="new policy")
    if kind not in {"rotate", "revoke"}:
        fail("transition kind must be 'rotate' or 'revoke'")
    old_digest = policy_digest(old_policy)
    new_digest = policy_digest(new_policy)
    old_generation = old_policy["generation"]
    new_generation = new_policy["generation"]
    if new_generation != old_generation + 1:
        fail("successor generation must be exactly one greater than current generation")
    if new_policy["predecessor_policy_digest"] != old_digest:
        fail("successor policy predecessor does not match the current policy")
    if new_digest == old_digest:
        fail("successor policy has the same identity as the current policy")

    old_keys = set(_active_keys(old_policy))
    new_keys = set(_active_keys(new_policy))
    removed = old_keys - new_keys
    added = new_keys - old_keys
    if not removed or len(removed) != len(added):
        fail("transition must replace at least one active key while retaining 2-of-3 shape")
    old_revoked = set(old_policy["revoked_key_ids"])
    new_revoked = set(new_policy["revoked_key_ids"])
    if not old_revoked.issubset(new_revoked):
        fail("successor policy removed a cumulative revocation tombstone")
    if kind == "rotate":
        if new_revoked != old_revoked:
            fail("rotation must not change cumulative revocations")
    else:
        added_revocations = new_revoked - old_revoked
        if added_revocations != removed:
            fail("revocation must tombstone exactly every removed active key")

    return {
        "schema": TRANSITION_STATEMENT_SCHEMA,
        "kind": kind,
        "old_policy_digest": old_digest,
        "new_policy_digest": new_digest,
        "old_generation": old_generation,
        "new_generation": new_generation,
    }


def assemble_transition(
    old_policy: dict[str, Any],
    new_policy: dict[str, Any],
    kind: str,
    old_signatures: list[dict[str, Any]],
    successor_signatures: list[dict[str, Any]],
) -> dict[str, Any]:
    if not isinstance(old_signatures, list) or not isinstance(
        successor_signatures, list
    ):
        fail("transition signature inventories must be arrays")
    old_signatures = sorted(
        (
            validate_detached_signature(value, f"old signatures[{index}]")
            for index, value in enumerate(old_signatures)
        ),
        key=lambda item: item["key_id"],
    )
    successor_signatures = sorted(
        (
            validate_detached_signature(value, f"successor signatures[{index}]")
            for index, value in enumerate(successor_signatures)
        ),
        key=lambda item: item["key_id"],
    )
    transition = {
        "schema": TRANSITION_SCHEMA,
        "statement": transition_statement(old_policy, new_policy, kind),
        "old_policy_signatures": old_signatures,
        "successor_policy_signatures": successor_signatures,
    }
    verify_transition(old_policy, new_policy, transition)
    return transition


def verify_transition(
    old_policy: dict[str, Any],
    new_policy: dict[str, Any],
    value: Any,
) -> dict[str, Any]:
    transition = require_fields(
        value,
        (
            "schema",
            "statement",
            "old_policy_signatures",
            "successor_policy_signatures",
        ),
        "transition",
    )
    if transition["schema"] != TRANSITION_SCHEMA:
        fail(f"transition.schema must be {TRANSITION_SCHEMA!r}")
    raw_statement = require_fields(
        transition["statement"],
        (
            "schema",
            "kind",
            "old_policy_digest",
            "new_policy_digest",
            "old_generation",
            "new_generation",
        ),
        "transition.statement",
    )
    expected = transition_statement(
        old_policy,
        new_policy,
        require_string(raw_statement["kind"], "transition.statement.kind"),
    )
    if canonical_json(raw_statement) != canonical_json(expected):
        fail("transition statement does not exactly describe the supplied policies")
    old_signatures = transition["old_policy_signatures"]
    successor_signatures = transition["successor_policy_signatures"]
    if not isinstance(old_signatures, list) or not isinstance(successor_signatures, list):
        fail("transition signature inventories must be arrays")
    verify_quorum(old_policy, TRANSITION_OLD_DOMAIN, expected, old_signatures)
    successor_signers = verify_quorum(
        new_policy,
        TRANSITION_SUCCESSOR_DOMAIN,
        expected,
        successor_signatures,
    )
    introduced = set(_active_keys(new_policy)) - set(_active_keys(old_policy))
    missing_possession = sorted(introduced - set(successor_signers))
    if missing_possession:
        fail(
            "successor proof-of-possession is missing newly introduced keys: "
            f"{missing_possession}"
        )
    return transition


def load_payload(path: Path) -> dict[str, Any]:
    return validate_payload(load_canonical_object(path, "payload"))


def load_transition(path: Path) -> dict[str, Any]:
    return load_canonical_object(path, "transition")


def write_canonical(path: Path, value: Any) -> None:
    encoded = canonical_json(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.is_symlink():
        fail(f"output path must not be a symlink: {path}")
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        temporary.write_bytes(encoded)
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _signature_inputs(paths: list[Path]) -> list[dict[str, Any]]:
    return sorted(
        (load_detached_signature(path) for path in paths),
        key=lambda item: item["key_id"],
    )


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(
        description="Validate R4 operator certifier governance and detached quorums."
    )
    subcommands = command.add_subparsers(dest="command", required=True)

    validate = subcommands.add_parser("validate-policy")
    validate.add_argument("policy", type=Path)
    validate.add_argument("--genesis", action="store_true")

    digest = subcommands.add_parser("policy-digest")
    digest.add_argument("policy", type=Path)

    statement = subcommands.add_parser("transition-statement")
    statement.add_argument("--old-policy", required=True, type=Path)
    statement.add_argument("--new-policy", required=True, type=Path)
    statement.add_argument("--kind", choices=("rotate", "revoke"), required=True)
    statement.add_argument("--out", required=True, type=Path)

    sign = subcommands.add_parser("sign")
    sign.add_argument("--policy", required=True, type=Path)
    sign.add_argument("--domain", choices=tuple(DOMAIN_ALIASES), required=True)
    sign.add_argument("--payload", required=True, type=Path)
    sign.add_argument("--private-key", required=True, type=Path)
    sign.add_argument("--out", required=True, type=Path)

    for name in ("verify-release", "verify-publication"):
        verify = subcommands.add_parser(name)
        verify.add_argument("--policy", required=True, type=Path)
        verify.add_argument("--payload", required=True, type=Path)
        verify.add_argument("--signature", required=True, action="append", type=Path)

    assemble = subcommands.add_parser("assemble-transition")
    assemble.add_argument("--old-policy", required=True, type=Path)
    assemble.add_argument("--new-policy", required=True, type=Path)
    assemble.add_argument("--kind", choices=("rotate", "revoke"), required=True)
    assemble.add_argument("--old-signature", required=True, action="append", type=Path)
    assemble.add_argument(
        "--successor-signature", required=True, action="append", type=Path
    )
    assemble.add_argument("--out", required=True, type=Path)

    verify_transition_command = subcommands.add_parser("verify-transition")
    verify_transition_command.add_argument("--old-policy", required=True, type=Path)
    verify_transition_command.add_argument("--new-policy", required=True, type=Path)
    verify_transition_command.add_argument("--transition", required=True, type=Path)
    return command


def main(arguments: list[str] | None = None) -> int:
    options = parser().parse_args(arguments)
    try:
        if options.command == "validate-policy":
            policy = load_policy(options.policy, require_genesis=options.genesis)
            print(f"valid {policy_digest(policy)} generation={policy['generation']}")
        elif options.command == "policy-digest":
            print(policy_digest(load_policy(options.policy)))
        elif options.command == "transition-statement":
            value = transition_statement(
                load_policy(options.old_policy),
                load_policy(options.new_policy),
                options.kind,
            )
            write_canonical(options.out, value)
            print(digest_bytes(canonical_json(value)))
        elif options.command == "sign":
            value = sign_detached(
                load_policy(options.policy),
                DOMAIN_ALIASES[options.domain],
                load_payload(options.payload),
                options.private_key,
            )
            write_canonical(options.out, value)
            print(value["key_id"])
        elif options.command in {"verify-release", "verify-publication"}:
            policy = load_policy(options.policy)
            payload = load_payload(options.payload)
            signatures = _signature_inputs(options.signature)
            if options.command == "verify-release":
                signers = verify_release_quorum(policy, payload, signatures)
            else:
                signers = verify_publication_quorum(policy, payload, signatures)
            print(f"verified {len(signers)}-of-{KEY_COUNT} quorum")
        elif options.command == "assemble-transition":
            value = assemble_transition(
                load_policy(options.old_policy),
                load_policy(options.new_policy),
                options.kind,
                _signature_inputs(options.old_signature),
                _signature_inputs(options.successor_signature),
            )
            write_canonical(options.out, value)
            print(digest_bytes(canonical_json(value)))
        else:
            old_policy = load_policy(options.old_policy)
            new_policy = load_policy(options.new_policy)
            value = load_transition(options.transition)
            verify_transition(old_policy, new_policy, value)
            print(
                f"verified transition generation={old_policy['generation']}"
                f"->{new_policy['generation']}"
            )
        return 0
    except (GovernanceError, OSError) as error:
        print(f"r4-certifier-governance: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
