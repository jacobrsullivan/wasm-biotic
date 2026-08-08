#!/usr/bin/env python3
"""Generate one canonical, exact R3 HTTP transport constraint.

The peer certificate/private key and credential bytes remain operator material.
This tool consumes only the peer's public SPKI DER bytes and emits the signed,
non-secret capability document used by component-graph-package.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sys
from typing import NoReturn


SCHEMA = "wasm-biotic.http-transport-constraints.v1"
ID_RE = re.compile(r"[a-z][a-z0-9-]{0,126}\Z")
HANDLE_RE = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")


class ConstraintError(RuntimeError):
    pass


def fail(message: str) -> NoReturn:
    raise ConstraintError(message)


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_host(value: str) -> str:
    if not value or not value.isascii() or value != value.lower() or value.endswith("."):
        fail("host must be lower-case ASCII without a trailing dot")
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        if not re.fullmatch(r"[a-z0-9.-]+", value):
            fail("host is not canonical DNS or IP syntax")
        if any(not label or len(label) > 63 for label in value.split(".")):
            fail("host contains an empty or oversized DNS label")
        return value
    if str(parsed) != value:
        fail("IP host is not in canonical spelling")
    return value


def canonical_path(value: str) -> str:
    if (
        not value.startswith("/")
        or not value.isascii()
        or not all(0x21 <= ord(character) <= 0x7E for character in value)
        or any(marker in value for marker in ("%", "\\", "?", "#", "//"))
        or any(segment in (".", "..") for segment in value.split("/"))
    ):
        fail("path prefix must be a visible-ASCII canonical absolute path")
    return value


def canonical_cidrs(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError as error:
            fail(f"exact CIDR {value!r} is not canonical: {error}")
        if network.prefixlen == 0 or str(network) != value:
            fail(f"exact CIDR {value!r} is broad or noncanonical")
        result.append(value)
    if result != sorted(set(result)):
        fail("exact CIDRs must be sorted and unique")
    return result


def build(args: argparse.Namespace) -> dict[str, object]:
    if not ID_RE.fullmatch(args.origin_id):
        fail("origin id must be lower-case hyphenated syntax")
    if not 1 <= args.port <= 65535:
        fail("port must be between 1 and 65535")
    host = canonical_host(args.host)
    path = canonical_path(args.path_prefix)
    spki = args.peer_spki_der.read_bytes()
    if not spki:
        fail("peer SPKI DER file is empty")
    pin = "sha256:" + hashlib.sha256(spki).hexdigest()
    if args.public_only:
        if args.exact_cidr:
            fail("public-only and exact CIDRs are mutually exclusive")
        dns: dict[str, object] = {"policy": "public-only", "cidrs": []}
    else:
        cidrs = canonical_cidrs(args.exact_cidr)
        if not cidrs:
            fail("at least one exact CIDR is required unless --public-only is selected")
        dns = {"policy": "exact-cidrs", "cidrs": cidrs}

    credential_bindings: list[dict[str, object]] = []
    request_names = ["content-type"]
    if args.credential_handle is not None:
        if not HANDLE_RE.fullmatch(args.credential_handle):
            fail("credential handle must be a safe opaque identifier")
        request_names = ["authorization", "content-type"]
        credential_bindings.append(
            {
                "handle": args.credential_handle,
                "origin_id": args.origin_id,
                "header_name": "authorization",
                "value_prefix": "Bearer ",
                "placement": "append-to-header-value",
            }
        )

    for name, value in (
        ("max-url-bytes", args.max_url_bytes),
        ("max-body-bytes", args.max_body_bytes),
        ("max-timeout-ms", args.max_timeout_ms),
        ("max-concurrency", args.max_concurrency),
    ):
        if value <= 0:
            fail(f"{name} must be positive")

    return {
        "schema": SCHEMA,
        "origins": [
            {
                "id": args.origin_id,
                "scheme": "https",
                "host": host,
                "port": args.port,
                "path_prefixes": [path],
                "dns": dns,
                "tls": {
                    "minimum_version": "tls-1.3",
                    "server_name": host,
                    "peer_spki_sha256": [pin],
                },
            }
        ],
        "methods": ["post"],
        "request_headers": {
            "allowed_names": request_names,
            "max_count": 8,
            "max_total_bytes": 8192,
        },
        "response_headers": {
            "exposed_names": ["content-type"],
            "max_count": 16,
            "max_total_bytes": 16384,
        },
        "max_url_bytes": args.max_url_bytes,
        "max_request_body_bytes": args.max_body_bytes,
        "max_response_body_bytes": args.max_body_bytes,
        "max_timeout_ms": args.max_timeout_ms,
        "max_concurrency": args.max_concurrency,
        "redirects": "deny",
        "credential_bindings": credential_bindings,
    }


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--host", required=True)
    value.add_argument("--port", required=True, type=int)
    value.add_argument("--origin-id", default="exchange-origin")
    value.add_argument("--path-prefix", default="/exchange")
    value.add_argument("--peer-spki-der", required=True, type=Path)
    policy = value.add_mutually_exclusive_group(required=True)
    policy.add_argument("--public-only", action="store_true")
    policy.add_argument("--exact-cidr", action="append", default=[])
    value.add_argument("--credential-handle", default="exchange-api")
    value.add_argument(
        "--without-credential", action="store_const", const=None, dest="credential_handle"
    )
    value.add_argument("--max-url-bytes", type=int, default=2048)
    value.add_argument("--max-body-bytes", type=int, default=1_048_576)
    value.add_argument("--max-timeout-ms", type=int, default=10_000)
    value.add_argument("--max-concurrency", type=int, default=2)
    value.add_argument("--out", required=True, type=Path)
    return value


def main() -> int:
    try:
        args = parser().parse_args()
        payload = canonical_json(build(args))
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_bytes(payload)
        print(f"http_transport_constraint_digest=sha256:{hashlib.sha256(payload).hexdigest()}")
        print(f"http_transport_constraint_path={args.out}")
        return 0
    except (ConstraintError, OSError) as error:
        print(f"r3-http-constraints: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
