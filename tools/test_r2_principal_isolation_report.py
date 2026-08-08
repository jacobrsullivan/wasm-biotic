"""Regression tests for exact R2/R3 principal-isolation package binding."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("r2-principal-isolation-report.py")
SPEC = importlib.util.spec_from_file_location("wasm_biotic_principal_report", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
REPORT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPORT)

AUTH_SCRIPT = Path(__file__).with_name("r3_release_authority.py")
AUTH_SPEC = importlib.util.spec_from_file_location(
    "wasm_biotic_r3_release_authority_test", AUTH_SCRIPT
)
assert AUTH_SPEC is not None and AUTH_SPEC.loader is not None
AUTHORITY = importlib.util.module_from_spec(AUTH_SPEC)
AUTH_SPEC.loader.exec_module(AUTHORITY)


def write_json(path: Path, value: object) -> bytes:
    data = REPORT.canonical_json(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return data


def digest(character: str) -> str:
    return f"sha256:{character * 64}"


def make_package(root: Path, profile_schema: str) -> dict[str, str | None]:
    ceilings = {
        "schema": "wasm-biotic.capability-constraints.v1",
        "max_blob_bytes": 4096,
        "max_total_blob_bytes": 8192,
        "max_random_bytes": 32,
        "max_wake_delay_ms": 1000,
        "max_http_timeout_ms": 1000,
        "max_component_fuel": 1000,
        "max_component_memory_bytes": 4096,
        "max_component_output_bytes": 4096,
        "max_component_wall_time_ms": 1000,
        "transaction_namespaces": ["exchange-v1"],
    }
    authority_digest = digest("b")
    alias = "wasm-biotic:factory/host-{}@0.1.0".format(
        AUTHORITY.digest_bytes(
            AUTHORITY.canonical_json(
                {
                    "authority_component_digest": authority_digest,
                    "capability": AUTHORITY.HTTP_CAPABILITY,
                    "consumer": AUTHORITY.HTTP_CONSUMER,
                    "schema": AUTHORITY.ALIAS_MATERIAL_SCHEMA,
                    "source_import": AUTHORITY.HTTP_IMPORT,
                }
            )
        )[7:]
    )
    constraint_digest: str | None = None
    http_imports: list[dict] = []
    http_grants: list[dict] = []
    http_bindings: list[dict] = []
    profile_http: dict = {}
    constraint_digests: list[str] = []
    if profile_schema == AUTHORITY.PROFILE_SCHEMA_V3:
        constraint = {
            "schema": AUTHORITY.HTTP_CONSTRAINT_SCHEMA,
            "origins": [
                {
                    "id": "exchange",
                    "scheme": "https",
                    "host": "api.example.com",
                    "port": 443,
                    "path_prefixes": ["/v1"],
                    "dns": {"policy": "public-only", "cidrs": []},
                    "tls": {
                        "minimum_version": "tls-1.3",
                        "server_name": "api.example.com",
                        "peer_spki_sha256": [digest("a")],
                    },
                }
            ],
            "methods": ["post"],
            "request_headers": {
                "allowed_names": ["authorization"],
                "max_count": 2,
                "max_total_bytes": 256,
            },
            "response_headers": {
                "exposed_names": [],
                "max_count": 4,
                "max_total_bytes": 512,
            },
            "max_url_bytes": 512,
            "max_request_body_bytes": 1024,
            "max_response_body_bytes": 1024,
            "max_timeout_ms": 500,
            "max_concurrency": 1,
            "redirects": "deny",
            "credential_bindings": [
                {
                    "handle": "exchange-api",
                    "origin_id": "exchange",
                    "header_name": "authorization",
                    "value_prefix": "Bearer ",
                    "placement": "append-to-header-value",
                }
            ],
        }
        constraint_bytes = REPORT.canonical_json(constraint)
        constraint_digest = REPORT.digest_bytes(constraint_bytes)
        http_imports = [
            {
                "alias": alias,
                "source_import": AUTHORITY.HTTP_IMPORT,
                "capability": AUTHORITY.HTTP_CAPABILITY,
                "scope": AUTHORITY.HTTP_SCOPE,
                "constraints": constraint_digest,
            }
        ]
        http_grants = [
            {
                "capability": AUTHORITY.HTTP_CAPABILITY,
                "scope": AUTHORITY.HTTP_SCOPE,
                "constraints": constraint_digest,
            }
        ]
        http_bindings = [
            {
                "consumer": AUTHORITY.HTTP_CONSUMER,
                "import": AUTHORITY.HTTP_IMPORT,
                "provider": {
                    "kind": "host",
                    "capability": AUTHORITY.HTTP_CAPABILITY,
                },
            }
        ]
        profile_http = {
            "http_transport": {
                "mode": AUTHORITY.HTTP_MODE,
                "bindings": [
                    {
                        "consumer": AUTHORITY.HTTP_CONSUMER,
                        "alias": alias,
                        "constraints": constraint_digest,
                    }
                ],
            }
        }
        constraint_path = root / "constraints" / (
            constraint_digest.replace(":", "-", 1) + ".json"
        )
        write_json(constraint_path, constraint)

    principals = [
        {
            "consumer": "exchange-service",
            "authority_component_digest": authority_digest,
            "host_imports": http_imports,
        },
        {"consumer": "worker-router", "host_imports": []},
    ]
    profile = {
        "schema": profile_schema,
        "static_grant_model": REPORT.PRINCIPAL_MODEL,
        "import_alias_scheme": "wasm-biotic.per-consumer-host-import.v1",
        "principal_id_scheme": "wasm-biotic.graph-node-principal.v1",
        "principals": principals,
        "ceilings": ceilings,
        **profile_http,
    }
    manifest = {
        "previous_graph": None,
        "nodes": [
            {
                "id": "exchange-service",
                "kind": "exchange-service",
                "component_digest": authority_digest,
                "grants": http_grants,
            },
            {"id": "worker-router", "kind": "worker-router", "grants": []},
        ],
        "bindings": http_bindings,
    }
    descriptor = {"schema": "wasm-biotic.component-derivation-descriptor.v2"}
    profile_bytes = write_json(root / "substrate-profile.json", profile)
    manifest_bytes = write_json(root / "manifest.json", manifest)
    descriptor_bytes = write_json(root / "derivation-descriptor.json", descriptor)
    graph_digest = REPORT.digest_bytes(manifest_bytes)
    profile_digest = REPORT.digest_bytes(profile_bytes)
    descriptor_digest = REPORT.digest_bytes(descriptor_bytes)
    shared_bytes = REPORT.canonical_json(ceilings)
    shared_digest = REPORT.digest_bytes(shared_bytes)
    if profile_schema == AUTHORITY.PROFILE_SCHEMA_V3:
        (root / "constraints").mkdir(exist_ok=True)
        (root / "constraints" / (shared_digest.replace(":", "-", 1) + ".json")).write_bytes(
            shared_bytes
        )
        assert constraint_digest is not None
        constraint_digests = sorted([shared_digest, constraint_digest])
    certification = {
        "statement": {
            "derivation_descriptor_digest": descriptor_digest,
            "substrate_profile_digest": profile_digest,
            "constraint_digests": constraint_digests,
        }
    }
    certification_bytes = write_json(
        root / "certification/release-certification.json", certification
    )
    certification_digest = REPORT.digest_bytes(certification_bytes)
    write_json(
        root / "package.json",
        {
            "graph_manifest_digest": graph_digest,
            "certification_digest": certification_digest,
        },
    )
    write_json(
        root / "metadata.json",
        {
            "derivation_descriptor_digest": descriptor_digest,
            "substrate_profile_digest": profile_digest,
        },
    )
    inventory = {
        "graph_manifest_digest": graph_digest,
        "import_alias_scheme": profile["import_alias_scheme"],
        "principal_id_scheme": profile["principal_id_scheme"],
        "principals": principals,
        "schema": REPORT.INVENTORY_SCHEMA,
    }
    inventory_bytes = write_json(root / "evidence/principal-inventory.json", inventory)
    write_json(
        root / "evidence/strict-validation.json",
        {
            "schema": REPORT.STRICT_SCHEMA,
            "outcome": "pass",
            "principal_inventory_digest": REPORT.digest_bytes(inventory_bytes),
            "principal_enforcement": {
                "graph_union_absent": True,
                "grants_exact": True,
                "aliases_unique": True,
                "result": "pass",
            },
        },
    )
    return {
        "constraint_digest": constraint_digest,
        "profile_digest": profile_digest,
    }


class PrincipalIsolationProfileTests(unittest.TestCase):
    def test_profile_v2_remains_accepted_without_http_projection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_package(root, REPORT.PROFILE_SCHEMA_V2)
            identity = REPORT.package_identity(root, "incumbent")
            self.assertEqual(identity["profile_schema"], REPORT.PROFILE_SCHEMA_V2)
            self.assertIsNone(identity["http_transport_constraint_digest"])

    def test_profile_v3_binds_exact_http_constraint_and_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            expected = make_package(root, AUTHORITY.PROFILE_SCHEMA_V3)
            identity = REPORT.package_identity(root, "incumbent")
            self.assertEqual(identity["profile_schema"], AUTHORITY.PROFILE_SCHEMA_V3)
            self.assertEqual(
                identity["http_transport_constraint_digest"],
                expected["constraint_digest"],
            )
            self.assertEqual(identity["substrate_profile_digest"], expected["profile_digest"])

    def test_profile_v2_with_r3_projection_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            make_package(root, REPORT.PROFILE_SCHEMA_V2)
            profile_path = root / "substrate-profile.json"
            profile = json.loads(profile_path.read_bytes())
            profile["http_transport"] = {"mode": "bounded-external", "bindings": []}
            profile_bytes = write_json(profile_path, profile)
            metadata = json.loads((root / "metadata.json").read_bytes())
            metadata["substrate_profile_digest"] = REPORT.digest_bytes(profile_bytes)
            write_json(root / "metadata.json", metadata)
            certification_path = root / "certification/release-certification.json"
            certification = json.loads(certification_path.read_bytes())
            certification["statement"]["substrate_profile_digest"] = REPORT.digest_bytes(
                profile_bytes
            )
            certification_bytes = write_json(certification_path, certification)
            package = json.loads((root / "package.json").read_bytes())
            package["certification_digest"] = REPORT.digest_bytes(certification_bytes)
            write_json(root / "package.json", package)
            with self.assertRaisesRegex(REPORT.ReportError, "unexpectedly contains"):
                REPORT.package_identity(root, "incumbent")


if __name__ == "__main__":
    unittest.main()
