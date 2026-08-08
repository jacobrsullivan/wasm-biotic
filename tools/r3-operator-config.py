#!/usr/bin/env python3
"""Project an exact R3 signed package into a reviewable operator capacity.

The output is a candidate operator configuration, not new authority: the
kernel still intersects it with the independently signed package constraint.
Public-only DNS grants require explicit ``--allowed-cidr`` values because an
operator network ceiling must not be invented from a DNS lookup here.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import sys
from typing import Any


class ConfigError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ConfigError(message)


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"JSON contains duplicate key {key!r}")
        result[key] = value
    return result


def read_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        data = path.read_bytes()
        value = json.loads(data, object_pairs_hook=reject_duplicates)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ConfigError(f"cannot read {label} at {path}: {error}") from error
    require(isinstance(value, dict), f"{label} must be a JSON object")
    return value, data


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def origin_authority(origin: dict[str, Any]) -> str:
    host = origin.get("host")
    port = origin.get("port")
    require(isinstance(host, str) and isinstance(port, int), "R3 origin host/port is malformed")
    if ":" in host:
        host = f"[{host}]"
    return f"https://{host}:{port}"


def canonical_cidrs(values: list[str]) -> list[str]:
    require(values == sorted(set(values)), "operator CIDRs must be sorted and unique")
    for value in values:
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError as error:
            raise ConfigError(f"operator CIDR {value!r} is invalid: {error}") from error
        require(str(network) == value and network.prefixlen > 0, f"operator CIDR {value!r} is not canonical")
    return values


def project(package: Path, extra_cidrs: list[str]) -> dict[str, Any]:
    profile, profile_bytes = read_json(package / "substrate-profile.json", "R3 profile")
    require(profile.get("schema") == "wasm-biotic.factory-substrate-profile.v3", "package is not profile v3")
    http = profile.get("http_transport")
    require(isinstance(http, dict) and http.get("mode") == "bounded-external", "R3 HTTP mode is not bounded-external")
    bindings = http.get("bindings")
    require(isinstance(bindings, list) and len(bindings) == 1, "R3 profile must have one HTTP binding")
    binding = bindings[0]
    require(isinstance(binding, dict) and binding.get("consumer") == "exchange-service", "R3 HTTP binding owner is not exchange-service")
    constraint_digest = binding.get("constraints")
    require(isinstance(constraint_digest, str) and constraint_digest.startswith("sha256:"), "R3 HTTP constraint digest is malformed")
    constraint_path = package / "constraints" / (constraint_digest.replace(":", "-", 1) + ".json")
    constraint, constraint_bytes = read_json(constraint_path, "R3 HTTP constraint")
    require(constraint_bytes == canonical_json(constraint), "R3 HTTP constraint is not canonical JSON")
    require(digest(constraint_bytes) == constraint_digest, "R3 HTTP constraint digest differs")
    require(constraint.get("schema") == "wasm-biotic.http-transport-constraints.v1", "HTTP constraint schema is not v1")
    origins = constraint.get("origins")
    require(isinstance(origins, list) and origins, "R3 HTTP origins are empty")

    signed_cidrs: list[str] = []
    has_public_only = False
    for origin in origins:
        require(isinstance(origin, dict), "R3 HTTP origin is malformed")
        dns = origin.get("dns")
        require(isinstance(dns, dict), "R3 HTTP DNS policy is malformed")
        if dns.get("policy") == "exact-cidrs":
            cidrs = dns.get("cidrs")
            require(isinstance(cidrs, list) and all(isinstance(item, str) for item in cidrs), "signed CIDRs are malformed")
            signed_cidrs.extend(cidrs)
        elif dns.get("policy") == "public-only":
            has_public_only = True
        else:
            raise ConfigError("R3 HTTP DNS policy is unknown")
    if has_public_only:
        require(extra_cidrs, "public-only signed DNS requires explicit operator --allowed-cidr")
        signed_cidrs.extend(extra_cidrs)
    elif extra_cidrs:
        signed_cidrs.extend(extra_cidrs)
    allowed_cidrs = canonical_cidrs(sorted(set(signed_cidrs)))

    ceilings = profile.get("ceilings")
    require(isinstance(ceilings, dict), "R3 shared ceilings are absent")
    credentials = constraint.get("credential_bindings")
    require(isinstance(credentials, list), "R3 credential bindings are malformed")
    handles = sorted(
        {
            binding.get("handle")
            for binding in credentials
            if isinstance(binding, dict) and isinstance(binding.get("handle"), str)
        }
    )
    request = constraint.get("request_headers")
    response = constraint.get("response_headers")
    require(isinstance(request, dict) and isinstance(response, dict), "R3 header ceilings are absent")
    methods = constraint.get("methods")
    require(isinstance(methods, list), "R3 methods are absent")
    namespaces = ceilings.get("transaction_namespaces")
    require(isinstance(namespaces, list), "R3 transaction namespaces are absent")

    mechanisms = {
        "allowed_namespaces": namespaces,
        "http_transport": {
            "allowed_cidrs": allowed_cidrs,
            "allowed_methods": methods,
            "allowed_origins": sorted(origin_authority(origin) for origin in origins),
            "allowed_request_headers": request.get("allowed_names"),
            "allowed_response_headers": response.get("exposed_names"),
            "credential_handles": handles,
            "enabled": True,
            "max_concurrency": constraint.get("max_concurrency"),
            "max_request_body_bytes": constraint.get("max_request_body_bytes"),
            "max_request_header_bytes": request.get("max_total_bytes"),
            "max_request_header_count": request.get("max_count"),
            "max_response_body_bytes": constraint.get("max_response_body_bytes"),
            "max_response_header_bytes": response.get("max_total_bytes"),
            "max_response_header_count": response.get("max_count"),
            "max_timeout_ms": constraint.get("max_timeout_ms"),
            "max_url_bytes": constraint.get("max_url_bytes"),
        },
    }
    for field in (
        "max_blob_bytes",
        "max_component_fuel",
        "max_component_memory_bytes",
        "max_component_output_bytes",
        "max_component_wall_time_ms",
        "max_http_timeout_ms",
        "max_random_bytes",
        "max_total_blob_bytes",
        "max_wake_delay_ms",
    ):
        require(isinstance(ceilings.get(field), int), f"R3 ceiling {field} is absent")
        mechanisms[field] = ceilings[field]
    require(profile_bytes == canonical_json(profile), "R3 profile is not canonical JSON")
    return {
        "mechanisms": mechanisms,
        "schema": "wasm-biotic.operator-mechanism-capacity.v2",
    }


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(description=__doc__)
    command.add_argument("--package", type=Path, required=True)
    command.add_argument("--allowed-cidr", action="append", default=[])
    command.add_argument("--out", type=Path, required=True)
    return command


def main(arguments: list[str] | None = None) -> int:
    options = parser().parse_args(arguments)
    try:
        config = project(options.package.resolve(strict=True), options.allowed_cidr)
        options.out.parent.mkdir(parents=True, exist_ok=True)
        options.out.write_bytes(canonical_json(config))
        print(f"operator_config_digest={digest(canonical_json(config))}")
        return 0
    except (ConfigError, OSError) as error:
        print(f"r3-operator-config: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
