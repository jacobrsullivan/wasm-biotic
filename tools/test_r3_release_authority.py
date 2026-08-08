"""Tests for the closed profile-v3 HTTP authority reconstruction."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("r3_release_authority.py")
SPEC = importlib.util.spec_from_file_location("wasm_biotic_r3_release_authority", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
AUTHORITY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUTHORITY)


def digest(character: str) -> str:
    return f"sha256:{character * 64}"


def fixture(root: Path) -> tuple[dict, dict, dict, str]:
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
            "allowed_names": ["authorization", "content-type"],
            "max_count": 4,
            "max_total_bytes": 512,
        },
        "response_headers": {
            "exposed_names": ["content-type"],
            "max_count": 8,
            "max_total_bytes": 1024,
        },
        "max_url_bytes": 512,
        "max_request_body_bytes": 1024,
        "max_response_body_bytes": 1024,
        "max_timeout_ms": 500,
        "max_concurrency": 2,
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
    shared_bytes = AUTHORITY.canonical_json(ceilings)
    constraint_bytes = AUTHORITY.canonical_json(constraint)
    shared_digest = AUTHORITY.digest_bytes(shared_bytes)
    constraint_digest = AUTHORITY.digest_bytes(constraint_bytes)
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
    profile = {
        "schema": AUTHORITY.PROFILE_SCHEMA_V3,
        "static_grant_model": "per-consumer-import-alias",
        "import_alias_scheme": AUTHORITY.IMPORT_ALIAS_SCHEME,
        "principal_id_scheme": AUTHORITY.PRINCIPAL_ID_SCHEME,
        "ceilings": ceilings,
        "principals": [
            {
                "consumer": AUTHORITY.HTTP_CONSUMER,
                "authority_component_digest": authority_digest,
                "host_imports": [
                    {
                        "alias": alias,
                        "source_import": AUTHORITY.HTTP_IMPORT,
                        "capability": AUTHORITY.HTTP_CAPABILITY,
                        "scope": AUTHORITY.HTTP_SCOPE,
                        "constraints": constraint_digest,
                    }
                ],
            }
        ],
        "http_transport": {
            "mode": AUTHORITY.HTTP_MODE,
            "bindings": [
                {
                    "consumer": AUTHORITY.HTTP_CONSUMER,
                    "alias": alias,
                    "constraints": constraint_digest,
                }
            ],
        },
    }
    manifest = {
        "nodes": [
            {
                "id": AUTHORITY.HTTP_CONSUMER,
                "kind": AUTHORITY.HTTP_CONSUMER,
                "component_digest": authority_digest,
                "grants": [
                    {
                        "capability": AUTHORITY.HTTP_CAPABILITY,
                        "scope": AUTHORITY.HTTP_SCOPE,
                        "constraints": constraint_digest,
                    }
                ],
            }
        ],
        "bindings": [
            {
                "consumer": AUTHORITY.HTTP_CONSUMER,
                "import": AUTHORITY.HTTP_IMPORT,
                "provider": {
                    "kind": "host",
                    "capability": AUTHORITY.HTTP_CAPABILITY,
                },
            }
        ],
    }
    statement = {"constraint_digests": sorted([shared_digest, constraint_digest])}
    constraints = root / "constraints"
    constraints.mkdir()
    (constraints / (shared_digest.replace(":", "-", 1) + ".json")).write_bytes(
        shared_bytes
    )
    (constraints / (constraint_digest.replace(":", "-", 1) + ".json")).write_bytes(
        constraint_bytes
    )
    return profile, manifest, statement, constraint_digest


class R3ReleaseAuthorityTests(unittest.TestCase):
    def test_exact_profile_manifest_certificate_and_constraint_projection_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile, manifest, statement, constraint_digest = fixture(root)
            authority = AUTHORITY.inspect_r3_http_authority(
                root, profile, manifest, statement, "fixture"
            )
            self.assertEqual(authority["constraint_digest"], constraint_digest)
            self.assertEqual(authority["consumer"], "exchange-service")

    def test_profile_or_manifest_projection_drift_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile, manifest, statement, _ = fixture(root)
            changed = copy.deepcopy(profile)
            changed["http_transport"]["bindings"][0]["alias"] = "forged"
            with self.assertRaisesRegex(AUTHORITY.R3AuthorityError, "projection"):
                AUTHORITY.inspect_r3_http_authority(
                    root, changed, manifest, statement, "fixture"
                )

            changed_manifest = copy.deepcopy(manifest)
            changed_manifest["nodes"][0]["grants"][0]["scope"] = "ambient"
            with self.assertRaisesRegex(AUTHORITY.R3AuthorityError, "grant"):
                AUTHORITY.inspect_r3_http_authority(
                    root, profile, changed_manifest, statement, "fixture"
                )

    def test_constraint_closure_and_exact_file_set_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile, manifest, statement, _ = fixture(root)
            (root / "constraints" / "unexpected.json").write_bytes(b"{}")
            with self.assertRaisesRegex(AUTHORITY.R3AuthorityError, "file set"):
                AUTHORITY.inspect_r3_http_authority(
                    root, profile, manifest, statement, "fixture"
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile, manifest, statement, constraint_digest = fixture(root)
            path = root / "constraints" / (
                constraint_digest.replace(":", "-", 1) + ".json"
            )
            constraint = json.loads(path.read_bytes())
            constraint["credential_bindings"][0]["value_prefix"] = ""
            path.write_bytes(AUTHORITY.canonical_json(constraint))
            with self.assertRaisesRegex(AUTHORITY.R3AuthorityError, "digest"):
                AUTHORITY.inspect_r3_http_authority(
                    root, profile, manifest, statement, "fixture"
                )

    def test_constraint_validator_rejects_unknown_fields_and_segment_unsafe_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            profile, _, _, constraint_digest = fixture(Path(temporary))
            constraint_path = Path(temporary) / "constraints" / (
                constraint_digest.replace(":", "-", 1) + ".json"
            )
            constraint = json.loads(constraint_path.read_bytes())
            constraint["retry_policy"] = "native"
            with self.assertRaisesRegex(AUTHORITY.R3AuthorityError, "field set"):
                AUTHORITY.validate_http_constraint(constraint, profile["ceilings"])
            del constraint["retry_policy"]
            constraint["origins"][0]["path_prefixes"] = ["/v1/../secret"]
            with self.assertRaisesRegex(AUTHORITY.R3AuthorityError, "path"):
                AUTHORITY.validate_http_constraint(constraint, profile["ceilings"])


if __name__ == "__main__":
    unittest.main()
