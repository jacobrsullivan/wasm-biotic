"""Closed validation of the signed profile-v3 HTTP authority projection.

This module is intentionally standard-library-only so release evidence tools
can independently reconstruct the identity that the Rust package validator
admits.  It validates authority and content identity; it never consumes
operator credential material or network configuration.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from pathlib import Path
import re
from typing import Any, Callable


PROFILE_SCHEMA_V3 = "wasm-biotic.factory-substrate-profile.v3"
HTTP_CONSTRAINT_SCHEMA = "wasm-biotic.http-transport-constraints.v1"
HTTP_IMPORT = "wasm-biotic:factory/http-transport@0.1.0"
HTTP_MODE = "bounded-external"
HTTP_CONSUMER = "exchange-service"
HTTP_CAPABILITY = "http-transport"
HTTP_SCOPE = "request"
ALIAS_MATERIAL_SCHEMA = "wasm-biotic.host-import-alias-material.v1"
IMPORT_ALIAS_SCHEME = "wasm-biotic.per-consumer-host-import.v1"
PRINCIPAL_ID_SCHEME = "wasm-biotic.graph-node-principal.v1"
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
CONTRACT_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,126}$")
HEADER_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9a-z-]{1,256}$")
FORBIDDEN_REQUEST_HEADERS = {
    "connection",
    "content-length",
    "host",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "via",
}
METHODS = {"delete", "get", "head", "patch", "post", "put"}


class R3AuthorityError(RuntimeError):
    """The retained package does not contain one exact closed R3 authority."""


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def digest_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"JSON contains duplicate key {key!r}")
        result[key] = value
    return result


def require(condition: bool, message: str) -> None:
    if not condition:
        raise R3AuthorityError(message)


def require_fields(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} is not an object")
    require(set(value) == fields, f"{label} does not have the exact closed field set")
    return value


def require_digest(value: Any, label: str) -> str:
    require(
        isinstance(value, str) and DIGEST_RE.fullmatch(value) is not None,
        f"{label} is not a canonical SHA-256 digest",
    )
    return value


def require_positive_integer(value: Any, maximum: int, label: str) -> int:
    require(
        type(value) is int and 0 < value <= maximum,
        f"{label} is not a bounded positive integer",
    )
    return value


def require_sorted_unique(
    values: Any,
    label: str,
    *,
    nonempty: bool = False,
    key: Callable[[Any], Any] | None = None,
) -> list[Any]:
    require(isinstance(values, list), f"{label} is not an array")
    require(not nonempty or bool(values), f"{label} is empty")
    selected = [key(item) if key is not None else item for item in values]
    try:
        sorted_values = sorted(selected)
        unique_count = len(set(selected))
    except TypeError as error:
        raise R3AuthorityError(f"{label} contains an invalid identity") from error
    require(selected == sorted_values, f"{label} is not sorted")
    require(len(selected) == unique_count, f"{label} is not unique")
    return values


def canonical_host(value: Any) -> bool:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 253
        or not value.isascii()
        or value != value.lower()
    ):
        return False
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return all(
            bool(label)
            and len(label) <= 63
            and not label.startswith("-")
            and not label.endswith("-")
            and all(character.isdigit() or "a" <= character <= "z" or character == "-" for character in label)
            for label in value.split(".")
        )
    return str(address) == value


def canonical_path(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= 4096
        and value.startswith("/")
        and value.isascii()
        and all(0x21 <= ord(character) <= 0x7E for character in value)
        and not any(marker in value for marker in ("%", "\\", "?", "#", "//"))
        and not any(segment in {".", ".."} for segment in value.split("/"))
    )


def canonical_cidr(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError:
        return False
    prefix = value.rsplit("/", 1)[-1]
    return (
        network.prefixlen != 0
        and str(network) == value
        and (len(prefix) == 1 or not prefix.startswith("0"))
    )


def validate_header_policy(
    value: Any, *, request: bool, label: str
) -> tuple[list[str], int, int]:
    names_field = "allowed_names" if request else "exposed_names"
    policy = require_fields(
        value,
        {names_field, "max_count", "max_total_bytes"},
        label,
    )
    names = require_sorted_unique(policy[names_field], f"{label} names")
    require(
        all(isinstance(name, str) and HEADER_RE.fullmatch(name) for name in names),
        f"{label} contains a noncanonical header name",
    )
    if request:
        require(
            not (set(names) & FORBIDDEN_REQUEST_HEADERS),
            f"{label} includes a transport-owned request header",
        )
    return (
        names,
        require_positive_integer(policy["max_count"], 2**32 - 1, f"{label} count"),
        require_positive_integer(
            policy["max_total_bytes"], 2**64 - 1, f"{label} byte limit"
        ),
    )


def validate_http_constraint(
    value: Any, ceilings: Any, label: str = "R3 HTTP constraint"
) -> None:
    constraint = require_fields(
        value,
        {
            "schema",
            "origins",
            "methods",
            "request_headers",
            "response_headers",
            "max_url_bytes",
            "max_request_body_bytes",
            "max_response_body_bytes",
            "max_timeout_ms",
            "max_concurrency",
            "redirects",
            "credential_bindings",
        },
        label,
    )
    require(
        constraint["schema"] == HTTP_CONSTRAINT_SCHEMA,
        f"{label} has the wrong schema",
    )
    require(isinstance(ceilings, dict), f"{label} has no shared ceilings")
    max_blob = require_positive_integer(
        ceilings.get("max_blob_bytes"), 2**64 - 1, f"{label} shared blob ceiling"
    )
    max_http_timeout = require_positive_integer(
        ceilings.get("max_http_timeout_ms"),
        2**64 - 1,
        f"{label} shared timeout ceiling",
    )

    origins = require_sorted_unique(
        constraint["origins"],
        f"{label} origins",
        nonempty=True,
        key=lambda origin: origin.get("id") if isinstance(origin, dict) else None,
    )
    origin_ids: set[str] = set()
    authorities: set[tuple[str, str, int]] = set()
    for index, raw_origin in enumerate(origins):
        origin_label = f"{label} origin {index}"
        origin = require_fields(
            raw_origin,
            {"id", "scheme", "host", "port", "path_prefixes", "dns", "tls"},
            origin_label,
        )
        origin_id = origin["id"]
        require(
            isinstance(origin_id, str) and CONTRACT_ID_RE.fullmatch(origin_id),
            f"{origin_label} id is not canonical",
        )
        origin_ids.add(origin_id)
        require(origin["scheme"] == "https", f"{origin_label} is not HTTPS")
        host = origin["host"]
        require(canonical_host(host), f"{origin_label} host is not canonical")
        port = require_positive_integer(origin["port"], 65535, f"{origin_label} port")
        require(
            ("https", host, port) not in authorities,
            f"{label} repeats an origin authority",
        )
        authorities.add(("https", host, port))
        paths = require_sorted_unique(
            origin["path_prefixes"], f"{origin_label} paths", nonempty=True
        )
        require(all(canonical_path(path) for path in paths), f"{origin_label} path is not canonical")

        dns = require_fields(origin["dns"], {"policy", "cidrs"}, f"{origin_label} DNS")
        cidrs = require_sorted_unique(dns["cidrs"], f"{origin_label} CIDRs")
        if dns["policy"] == "public-only":
            require(not cidrs, f"{origin_label} public-only DNS contains CIDRs")
        elif dns["policy"] == "exact-cidrs":
            require(bool(cidrs), f"{origin_label} exact DNS has no CIDRs")
            require(
                all(canonical_cidr(cidr) for cidr in cidrs),
                f"{origin_label} CIDR is not canonical",
            )
        else:
            raise R3AuthorityError(f"{origin_label} has an unsupported DNS policy")

        tls = require_fields(
            origin["tls"],
            {"minimum_version", "server_name", "peer_spki_sha256"},
            f"{origin_label} TLS",
        )
        require(
            tls["minimum_version"] == "tls-1.3" and tls["server_name"] == host,
            f"{origin_label} TLS authority is not exact TLS 1.3",
        )
        pins = require_sorted_unique(
            tls["peer_spki_sha256"], f"{origin_label} SPKI pins", nonempty=True
        )
        for pin in pins:
            require_digest(pin, f"{origin_label} SPKI pin")

    methods = require_sorted_unique(
        constraint["methods"], f"{label} methods", nonempty=True
    )
    require(set(methods) <= METHODS, f"{label} contains an unsupported method")
    request_names, request_count, request_bytes = validate_header_policy(
        constraint["request_headers"], request=True, label=f"{label} request headers"
    )
    _, response_count, response_bytes = validate_header_policy(
        constraint["response_headers"], request=False, label=f"{label} response headers"
    )
    max_url = require_positive_integer(
        constraint["max_url_bytes"], 2**64 - 1, f"{label} URL limit"
    )
    max_request_body = require_positive_integer(
        constraint["max_request_body_bytes"], 2**64 - 1, f"{label} request-body limit"
    )
    max_response_body = require_positive_integer(
        constraint["max_response_body_bytes"], 2**64 - 1, f"{label} response-body limit"
    )
    max_timeout = require_positive_integer(
        constraint["max_timeout_ms"], 2**64 - 1, f"{label} timeout"
    )
    require_positive_integer(
        constraint["max_concurrency"], 2**32 - 1, f"{label} concurrency"
    )
    require(
        max(max_url, max_request_body, max_response_body, request_bytes, response_bytes)
        <= max_blob,
        f"{label} exceeds the shared blob ceiling",
    )
    require(max_timeout <= max_http_timeout, f"{label} exceeds the shared HTTP timeout")
    require(request_count > 0 and response_count > 0, f"{label} has a zero header count")
    require(constraint["redirects"] == "deny", f"{label} permits redirects")

    credentials = require_sorted_unique(
        constraint["credential_bindings"],
        f"{label} credential bindings",
        key=lambda binding: (
            binding.get("handle"),
            binding.get("origin_id"),
            binding.get("header_name"),
        )
        if isinstance(binding, dict)
        else (None, None, None),
    )
    handles: set[str] = set()
    for index, raw_binding in enumerate(credentials):
        binding_label = f"{label} credential binding {index}"
        binding = require_fields(
            raw_binding,
            {"handle", "origin_id", "header_name", "value_prefix", "placement"},
            binding_label,
        )
        handle = binding["handle"]
        prefix = binding["value_prefix"]
        require(
            isinstance(handle, str)
            and 0 < len(handle) <= 256
            and all(0x21 <= ord(character) <= 0x7E for character in handle),
            f"{binding_label} handle is unsafe",
        )
        require(handle not in handles, f"{label} repeats a credential handle")
        handles.add(handle)
        require(binding["origin_id"] in origin_ids, f"{binding_label} origin is unknown")
        require(
            binding["header_name"] in request_names,
            f"{binding_label} header is not request-allowlisted",
        )
        require(
            isinstance(binding["header_name"], str)
            and HEADER_RE.fullmatch(binding["header_name"]) is not None
            and binding["header_name"] not in FORBIDDEN_REQUEST_HEADERS,
            f"{binding_label} header is not canonical",
        )
        require(
            isinstance(prefix, str)
            and 0 < len(prefix) <= 1024
            and all(0x20 <= ord(character) <= 0x7E for character in prefix),
            f"{binding_label} prefix is unsafe",
        )
        require(
            binding["placement"] == "append-to-header-value",
            f"{binding_label} placement is unsupported",
        )


def load_closed_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw, object_pairs_hook=reject_duplicate_keys)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise R3AuthorityError(f"cannot read {label}: {error}") from error
    require(isinstance(value, dict), f"{label} is not a JSON object")
    require(raw == canonical_json(value), f"{label} is not canonical JSON")
    return value, raw


def inspect_r3_http_authority(
    directory: Path,
    profile: dict[str, Any],
    manifest: dict[str, Any],
    certification_statement: dict[str, Any],
    label: str,
) -> dict[str, str]:
    """Return the exact signed HTTP identity after closed cross-projection checks."""

    require(profile.get("schema") == PROFILE_SCHEMA_V3, f"{label} is not profile v3")
    require(
        profile.get("static_grant_model") == "per-consumer-import-alias"
        and profile.get("import_alias_scheme") == IMPORT_ALIAS_SCHEME
        and profile.get("principal_id_scheme") == PRINCIPAL_ID_SCHEME,
        f"{label} does not retain the exact scoped authority model",
    )
    transport = require_fields(
        profile.get("http_transport"), {"mode", "bindings"}, f"{label} HTTP profile"
    )
    require(transport["mode"] == HTTP_MODE, f"{label} HTTP mode is not bounded-external")
    bindings = transport["bindings"]
    require(isinstance(bindings, list) and len(bindings) == 1, f"{label} must have one HTTP binding")
    binding = require_fields(
        bindings[0], {"consumer", "alias", "constraints"}, f"{label} HTTP binding"
    )
    require(binding["consumer"] == HTTP_CONSUMER, f"{label} HTTP consumer is not exchange-service")
    constraint_digest = require_digest(binding["constraints"], f"{label} HTTP constraint")
    alias = binding["alias"]
    require(isinstance(alias, str) and bool(alias), f"{label} HTTP alias is empty")

    principals = profile.get("principals")
    require(isinstance(principals, list), f"{label} principals are malformed")
    projected: list[dict[str, Any]] = []
    http_authority_digest: str | None = None
    for principal in principals:
        require(isinstance(principal, dict), f"{label} principal is malformed")
        imports = principal.get("host_imports")
        require(isinstance(imports, list), f"{label} host imports are malformed")
        for host_import in imports:
            require(isinstance(host_import, dict), f"{label} host import is malformed")
            if host_import.get("capability") == HTTP_CAPABILITY:
                require_fields(
                    host_import,
                    {"alias", "source_import", "capability", "scope", "constraints"},
                    f"{label} HTTP host import",
                )
                require(
                    principal.get("consumer") == HTTP_CONSUMER
                    and host_import.get("source_import") == HTTP_IMPORT
                    and host_import.get("scope") == HTTP_SCOPE,
                    f"{label} HTTP host import is not the exact exchange-service request import",
                )
                authority_digest = require_digest(
                    principal.get("authority_component_digest"),
                    f"{label} exchange-service authority",
                )
                http_authority_digest = authority_digest
                expected_alias = "wasm-biotic:factory/host-{}@0.1.0".format(
                    digest_bytes(
                        canonical_json(
                            {
                                "authority_component_digest": authority_digest,
                                "capability": HTTP_CAPABILITY,
                                "consumer": HTTP_CONSUMER,
                                "schema": ALIAS_MATERIAL_SCHEMA,
                                "source_import": HTTP_IMPORT,
                            }
                        )
                    )[7:]
                )
                require(
                    host_import.get("alias") == expected_alias,
                    f"{label} HTTP alias is not content-derived exactly",
                )
                projected.append(
                    {
                        "consumer": principal.get("consumer"),
                        "alias": host_import.get("alias"),
                        "constraints": host_import.get("constraints"),
                    }
                )
    require(projected == [binding], f"{label} HTTP profile is not the exact principal projection")

    nodes = manifest.get("nodes")
    require(isinstance(nodes, list), f"{label} manifest nodes are malformed")
    http_grants: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for node in nodes:
        require(isinstance(node, dict), f"{label} manifest node is malformed")
        grants = node.get("grants")
        require(isinstance(grants, list), f"{label} manifest grants are malformed")
        for grant in grants:
            require(isinstance(grant, dict), f"{label} manifest grant is malformed")
            if grant.get("capability") == HTTP_CAPABILITY:
                http_grants.append((node, grant))
    require(len(http_grants) == 1, f"{label} does not have exactly one manifest HTTP grant")
    node, grant = http_grants[0]
    require(
        node.get("id") == HTTP_CONSUMER
        and node.get("kind") == HTTP_CONSUMER
        and node.get("component_digest") == http_authority_digest
        and grant
        == {
            "capability": HTTP_CAPABILITY,
            "scope": HTTP_SCOPE,
            "constraints": constraint_digest,
        },
        f"{label} manifest HTTP grant does not match the signed profile binding",
    )

    manifest_bindings = manifest.get("bindings")
    require(isinstance(manifest_bindings, list), f"{label} manifest bindings are malformed")
    http_manifest_bindings = [
        item
        for item in manifest_bindings
        if isinstance(item, dict)
        and (
            item.get("import") == HTTP_IMPORT
            or (
                isinstance(item.get("provider"), dict)
                and item["provider"].get("capability") == HTTP_CAPABILITY
            )
        )
    ]
    require(
        http_manifest_bindings
        == [
            {
                "consumer": HTTP_CONSUMER,
                "import": HTTP_IMPORT,
                "provider": {"kind": "host", "capability": HTTP_CAPABILITY},
            }
        ],
        f"{label} manifest HTTP binding is not exact",
    )

    ceilings = profile.get("ceilings")
    require(isinstance(ceilings, dict), f"{label} shared ceilings are missing")
    shared_bytes = canonical_json(ceilings)
    shared_digest = digest_bytes(shared_bytes)
    require(shared_digest != constraint_digest, f"{label} HTTP authority reuses shared ceilings")
    constraint_digests = certification_statement.get("constraint_digests")
    require(
        constraint_digests == sorted([shared_digest, constraint_digest]),
        f"{label} certificate does not bind exactly the shared and HTTP constraints",
    )
    constraints_directory = directory / "constraints"
    expected_names = {
        shared_digest.replace(":", "-", 1) + ".json",
        constraint_digest.replace(":", "-", 1) + ".json",
    }
    try:
        entries = list(constraints_directory.iterdir())
    except OSError as error:
        raise R3AuthorityError(f"cannot enumerate {label} constraints: {error}") from error
    require(
        all(path.is_file() and not path.is_symlink() for path in entries),
        f"{label} constraint directory contains a non-regular entry",
    )
    observed_names = {path.name for path in entries}
    require(observed_names == expected_names, f"{label} constraint file set is not exact")
    shared_path = constraints_directory / (shared_digest.replace(":", "-", 1) + ".json")
    try:
        retained_shared = shared_path.read_bytes()
    except OSError as error:
        raise R3AuthorityError(f"cannot read {label} shared constraint: {error}") from error
    require(retained_shared == shared_bytes, f"{label} shared constraint differs from profile ceilings")

    constraint_path = constraints_directory / (
        constraint_digest.replace(":", "-", 1) + ".json"
    )
    constraint, constraint_bytes = load_closed_json(constraint_path, f"{label} HTTP constraint")
    require(
        digest_bytes(constraint_bytes) == constraint_digest,
        f"{label} HTTP constraint digest does not match its binding",
    )
    validate_http_constraint(constraint, ceilings, f"{label} HTTP constraint")
    return {
        "binding_alias": alias,
        "constraint_digest": constraint_digest,
        "constraint_schema": HTTP_CONSTRAINT_SCHEMA,
        "consumer": HTTP_CONSUMER,
        "profile_schema": PROFILE_SCHEMA_V3,
    }
