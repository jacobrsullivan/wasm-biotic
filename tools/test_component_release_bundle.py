#!/usr/bin/env python3
"""Focused end-to-end tests for component-release-bundle.py."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("component-release-bundle.py")
MODULE_SPEC = importlib.util.spec_from_file_location("component_release_bundle", SCRIPT)
assert MODULE_SPEC is not None and MODULE_SPEC.loader is not None
BUNDLE = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(BUNDLE)


def digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


def behavioural_report(schema: str, incumbent: str, successor: str) -> dict:
    report = {
        "schema": schema,
        "report_complete": True,
        "blockers": [],
        "lifecycle": {
            "incumbent_graph_manifest_digest": incumbent,
            "successor_graph_manifest_digest": successor,
        },
    }
    if schema == BUNDLE.BEHAVIOURAL_EQUIVALENCE_SCHEMA_V2:
        report.update(
            {
                "synthetic_policy_service_outputs": True,
                "synthetic_policy_trace_claims_useful_r1_semantics": False,
                "lifecycle_r1_semantics_verified_by_this_report": False,
                "component_trace": {
                    "expected_capability_request_count": len(
                        BUNDLE.R1_SYNTHETIC_POLICY_TRACE
                    ),
                    "capability_request_order_verified": True,
                    "service_output_mode": (
                        "deterministic-synthetic-blob; no useful R1 semantics executed"
                    ),
                    "capability_requests": [
                        {
                            "role": role,
                            "family": family,
                            "operation": operation,
                            "authority": authority,
                        }
                        for role, family, operation, authority in BUNDLE.R1_SYNTHETIC_POLICY_TRACE
                    ],
                },
                "receipt_normalization": {
                    "policy_component_receipt_count": len(
                        BUNDLE.R1_SYNTHETIC_POLICY_TRACE
                    )
                },
            }
        )
    return report


def r2_behavioural_report(
    identities: dict[str, str], component_lifecycle_digest: str
) -> dict:
    incumbent = identities["incumbent_graph_manifest_digest"]
    successor = identities["successor_graph_manifest_digest"]
    report = behavioural_report(
        BUNDLE.BEHAVIOURAL_EQUIVALENCE_SCHEMA_V2, incumbent, successor
    )
    graph_scopes = (
        [incumbent],
        sorted((incumbent, successor)),
        [successor],
        [incumbent],
    )
    report["lifecycle"].update(
        {
            "source_report_path": "package:evidence/component-lifecycle.json",
            "source_report_digest": component_lifecycle_digest,
            "source_schema": BUNDLE.COMPONENT_LIFECYCLE_SCHEMA_V2,
            "graph_qualified_activation_ownership_handoff_verified": True,
            "principal_mapping_stable_across_restart_activation_and_rollback": True,
            "principal_inventory_digests": {
                "incumbent": identities["incumbent_principal_inventory_digest"],
                "successor": identities["successor_principal_inventory_digest"],
            },
            "authority_trace_summaries": [
                {
                    "aliases": [f"wasm-biotic:test/{index:02d}@0.1.0"],
                    "call_count": index + 1,
                    "consumers": ["factory-control"],
                    "graph_manifest_digests": graphs,
                    "phase": phase,
                    "profile_mapping_verified": True,
                    "trace_digest": digest(f"authority-trace-{phase}"),
                }
                for index, (phase, graphs) in enumerate(
                    zip(BUNDLE.R2_AUTHORITY_TRACE_PHASES, graph_scopes)
                )
            ],
        }
    )
    return report


def principal_isolation_report() -> tuple[dict, dict[str, str]]:
    identities = {
        "capability_profile_digest": digest("principal-profile"),
        "incumbent_graph_manifest_digest": digest("principal-incumbent"),
        "successor_graph_manifest_digest": digest("principal-successor"),
        "incumbent_principal_inventory_digest": digest("principal-incumbent-inventory"),
        "successor_principal_inventory_digest": digest("principal-successor-inventory"),
        "incumbent_derivation_descriptor_digest": digest("principal-incumbent-descriptor"),
        "successor_derivation_descriptor_digest": digest("principal-successor-descriptor"),
    }
    release_identity = lambda kind: {
        "certification_digest": digest(f"principal-{kind}-certification"),
        "derivation_descriptor_digest": identities[
            f"{kind}_derivation_descriptor_digest"
        ],
        "graph_manifest_digest": identities[f"{kind}_graph_manifest_digest"],
        "import_alias_scheme": "wasm-biotic.per-consumer-host-import.v1",
        "principal_count": 22,
        "principal_id_scheme": "wasm-biotic.graph-node-principal.v1",
        "principal_inventory_digest": identities[
            f"{kind}_principal_inventory_digest"
        ],
        "substrate_profile_digest": identities["capability_profile_digest"],
    }
    cases = [
        {
            "assertion": f"assertion for {case_id}",
            "id": case_id,
            "result": "pass",
            "substrate": "production-kernel",
        }
        for case_id in BUNDLE.R2_PRODUCTION_PRINCIPAL_CASE_IDS
    ]
    cases.extend(
        {
            "id": case_id,
            "result": "pass",
            "substrate": "independent-substrate",
        }
        for case_id in BUNDLE.R2_INDEPENDENT_AGGREGATE_CASE_IDS
    )
    report = {
        "component_complete_claim": False,
        "cross_principal_cases": cases,
        "incumbent_graph_manifest_digest": identities[
            "incumbent_graph_manifest_digest"
        ],
        "successor_graph_manifest_digest": identities[
            "successor_graph_manifest_digest"
        ],
        "incumbent_principal_inventory_digest": identities[
            "incumbent_principal_inventory_digest"
        ],
        "successor_principal_inventory_digest": identities[
            "successor_principal_inventory_digest"
        ],
        "independent_substrate": {
            "activation_owner_handoff": {
                "atomic_commit_owner_handoff": True,
                "case_id": "graph-qualified-activation-owner-handoff",
                "restart_persistence_verified": True,
                "rollback_owner_handback": True,
            },
            "case_ids": list(BUNDLE.R2_INDEPENDENT_PRINCIPAL_CASE_IDS),
            "cases_passed": len(BUNDLE.R2_INDEPENDENT_PRINCIPAL_CASE_IDS),
            "graph_qualified_activation_owner_handoff_enforced": True,
            "principal_model": "per-consumer-import-alias",
            "release_pair": {
                "incumbent": release_identity("incumbent"),
                "successor": release_identity("successor"),
            },
            "report_digest": digest("independent-principal-report"),
            "result": "pass",
        },
        "principal_model": "per-consumer-import-alias",
        "production_kernel": {
            "cases_passed": len(BUNDLE.R2_PRODUCTION_PRINCIPAL_CASE_IDS),
            "principal_model": "per-consumer-import-alias",
            "result": "pass",
            "source_bindings": [],
            "test_identities": [],
            "transcripts": [],
        },
        "remaining_blockers": [],
        "report_complete": True,
        "result": "pass",
        "schema": BUNDLE.PRINCIPAL_ISOLATION_SCHEMA_V1,
    }
    return report, identities


def r3_identities() -> dict[str, str]:
    return {
        "incumbent_graph_manifest_digest": digest("r3-incumbent"),
        "successor_graph_manifest_digest": digest("r3-successor"),
        "native_tcb_inventory_digest": digest("r3-tcb"),
        "capability_profile_digest": digest("r3-profile"),
        "wit_contract_digest": digest("r3-wit"),
        "component_complete_contract_digest": digest("r3-contract"),
        "incumbent_principal_inventory_digest": digest("r3-incumbent-principals"),
        "successor_principal_inventory_digest": digest("r3-successor-principals"),
        "incumbent_derivation_descriptor_digest": digest("r3-incumbent-descriptor"),
        "successor_derivation_descriptor_digest": digest("r3-successor-descriptor"),
        "incumbent_http_transport_constraint_digest": digest("r3-incumbent-http"),
        "successor_http_transport_constraint_digest": digest("r3-successor-http"),
        "native_target": "aarch64-apple-darwin",
    }


def transport_confinement_report(
    identities: dict[str, str],
    incumbent_component: str,
    successor_component: str,
) -> dict:
    graphs = [
        identities["incumbent_graph_manifest_digest"],
        identities["successor_graph_manifest_digest"],
    ]
    constraints = [
        identities["incumbent_http_transport_constraint_digest"],
        identities["successor_http_transport_constraint_digest"],
    ]

    def substrate(implementation: str) -> dict:
        return {
            "implementation": implementation,
            "graph_manifest_digests": graphs,
            "http_transport_constraint_digests": constraints,
            "case_groups": {
                group: list(case_ids)
                for group, case_ids in BUNDLE.R3_TRANSPORT_CASE_GROUPS.items()
            },
            "report_digest": digest(f"{implementation}-r3-report"),
            "result": "pass",
        }

    return {
        "schema": BUNDLE.TRANSPORT_CONFINEMENT_SCHEMA_V1,
        "claim_profile": BUNDLE.R3_CLAIM_PROFILE,
        "incumbent_graph_manifest_digest": identities[
            "incumbent_graph_manifest_digest"
        ],
        "successor_graph_manifest_digest": identities[
            "successor_graph_manifest_digest"
        ],
        "capability_profile_digest": identities["capability_profile_digest"],
        "incumbent_http_transport_constraint_digest": identities[
            "incumbent_http_transport_constraint_digest"
        ],
        "successor_http_transport_constraint_digest": identities[
            "successor_http_transport_constraint_digest"
        ],
        "production_kernel": substrate("production-kernel"),
        "independent_substrate": substrate("independent-substrate"),
        "compiled_exchange_component": {
            "component_id": "exchange-service",
            "incumbent_component_digest": incumbent_component,
            "successor_component_digest": successor_component,
            "component_type_checked": True,
            "request_formation_component_owned": True,
            "response_interpretation_component_owned": True,
            "retry_cancel_fallback_component_owned": True,
            "native_provider_logic_absent": True,
            "credential_value_prefixes": ["Bearer "],
            "result": "pass",
        },
        "remaining_blockers": [],
        "report_complete": True,
        "result": "pass",
    }


def capability_ceilings() -> dict:
    return {
        "schema": "wasm-biotic.capability-constraints.v1",
        "max_blob_bytes": 16 * 1024 * 1024,
        "max_total_blob_bytes": 256 * 1024 * 1024,
        "max_random_bytes": 4096,
        "max_wake_delay_ms": 30 * 24 * 60 * 60 * 1000,
        "max_http_timeout_ms": 30000,
        "max_component_fuel": 50000000,
        "max_component_memory_bytes": 64 * 1024 * 1024,
        "max_component_output_bytes": 16 * 1024 * 1024,
        "max_component_wall_time_ms": 30000,
        "transaction_namespaces": [
            "exchange-v1",
            "wasm-biotic.approvals.v1",
            "wasm-biotic.factory-control.v1",
            "wasm-biotic.schedule.v1",
        ],
    }


class DigestStemTests(unittest.TestCase):
    def test_canonical_digest_stem_and_rejections(self) -> None:
        value = "sha256:" + "a" * 64
        self.assertEqual(BUNDLE.digest_stem(value), "sha256-" + "a" * 64)

        for malformed in ("sha256-" + "a" * 64, "sha256:" + "A" * 64, ""):
            with self.subTest(malformed=malformed):
                with self.assertRaises(BUNDLE.BundleError):
                    BUNDLE.digest_stem(malformed)


class R3ReleaseContractTests(unittest.TestCase):
    def test_closed_http_constraint_matches_checked_in_fixture(self) -> None:
        constraint = json.loads(
            (SCRIPT.parent / "component-graph-package/r3-http-constraints.example.json")
            .read_text(encoding="utf-8")
        )
        prefixes = BUNDLE.validate_http_transport_constraints(
            constraint, capability_ceilings(), "R3 HTTP constraint"
        )
        self.assertEqual(prefixes, ["Bearer "])
        self.assertEqual(
            BUNDLE.sha256_bytes(BUNDLE.canonical_json(constraint)),
            "sha256:bc54aaa9f58bc86e5a1fc5c941b6334a283a4074d53806832a675dd860b9a634",
        )

        mutations = []
        unknown = json.loads(json.dumps(constraint))
        unknown["provider"] = "forbidden-policy"
        mutations.append(("unknown-field", unknown, "unknown fields"))
        unbounded = json.loads(json.dumps(constraint))
        unbounded["max_timeout_ms"] = capability_ceilings()["max_http_timeout_ms"] + 1
        mutations.append(("ceiling", unbounded, "exceed"))
        forbidden = json.loads(json.dumps(constraint))
        forbidden["request_headers"]["allowed_names"].append("host")
        forbidden["request_headers"]["allowed_names"].sort()
        mutations.append(("forbidden-header", forbidden, "permanently forbidden"))
        empty_prefix = json.loads(json.dumps(constraint))
        empty_prefix["credential_bindings"][0]["value_prefix"] = ""
        mutations.append(("empty-prefix", empty_prefix, "non-empty"))
        for label, mutated, message in mutations:
            with self.subTest(label=label):
                with self.assertRaisesRegex(BUNDLE.BundleError, message):
                    BUNDLE.validate_http_transport_constraints(
                        mutated, capability_ceilings(), "R3 HTTP constraint"
                    )

    def test_transport_evidence_is_closed_and_package_bound(self) -> None:
        identities = r3_identities()
        incumbent_component = digest("r3-incumbent-exchange")
        successor_component = digest("r3-successor-exchange")
        report = transport_confinement_report(
            identities, incumbent_component, successor_component
        )
        validated = BUNDLE.validate_transport_confinement_report(
            BUNDLE.canonical_json(report), identities, "transport confinement"
        )
        facts = {
            "incumbent": {
                "exchange_component_digest": incumbent_component,
                "credential_value_prefixes": ["Bearer "],
            },
            "successor": {
                "exchange_component_digest": successor_component,
                "credential_value_prefixes": ["Bearer "],
            },
        }
        BUNDLE.validate_transport_confinement_package_bindings(
            validated, facts, "transport confinement"
        )

        mutations = []
        swapped = json.loads(json.dumps(report))
        swapped["production_kernel"]["http_transport_constraint_digests"].reverse()
        mutations.append(("constraint-swap", swapped, "exact ordered R3 constraints"))
        missing_case = json.loads(json.dumps(report))
        missing_case["independent_substrate"]["case_groups"]["non_retry"].pop()
        mutations.append(("missing-case", missing_case, "exact ordered R3 campaign"))
        extra_case = json.loads(json.dumps(report))
        extra_case["production_kernel"]["case_groups"]["owner"].append("extra")
        mutations.append(("extra-case", extra_case, "exact ordered R3 campaign"))
        extra_field = json.loads(json.dumps(report))
        extra_field["provider_policy"] = "native"
        mutations.append(("extra-field", extra_field, "unknown fields"))
        for label, mutated, message in mutations:
            with self.subTest(label=label):
                with self.assertRaisesRegex(BUNDLE.BundleError, message):
                    BUNDLE.validate_transport_confinement_report(
                        BUNDLE.canonical_json(mutated),
                        identities,
                        "transport confinement",
                    )

        substituted = transport_confinement_report(
            identities, digest("substituted-exchange"), successor_component
        )
        substituted = BUNDLE.validate_transport_confinement_report(
            BUNDLE.canonical_json(substituted), identities, "transport confinement"
        )
        with self.assertRaisesRegex(BUNDLE.BundleError, "incumbent_component_digest"):
            BUNDLE.validate_transport_confinement_package_bindings(
                substituted, facts, "transport confinement"
            )

    def test_v3_contract_retains_r2_and_adds_transport_role(self) -> None:
        spec_schema, roles, required = BUNDLE.release_contract(BUNDLE.CLAIM_SCHEMA_V3)
        self.assertEqual(spec_schema, BUNDLE.SPEC_SCHEMA_V3)
        self.assertEqual(roles[:-1], BUNDLE.SECTION_7_ROLES_V2)
        self.assertEqual(roles[-1], "transport-confinement")
        self.assertTrue(BUNDLE.REQUIRED_OBJECT_ROLES_V2.issubset(required))
        self.assertIn("transport-confinement", required)
        BUNDLE.validate_identities(
            r3_identities(), "R3 identities", r2=True, r3=True
        )

        missing = r3_identities()
        missing.pop("successor_http_transport_constraint_digest")
        with self.assertRaisesRegex(BUNDLE.BundleError, "successor_http"):
            BUNDLE.validate_identities(
                missing, "R3 identities", r2=True, r3=True
            )


class ReleaseBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        if shutil.which("openssl") is None:
            self.skipTest("openssl is not available")
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.private_key = self.root / "one-shot.pk8"
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "ED25519",
                "-outform",
                "DER",
                "-out",
                str(self.private_key),
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        normalized = self.root / "normalized-private.pk8"
        _, public_key = BUNDLE.normalize_private_key(self.private_key, normalized)
        key_id = BUNDLE.sha256_bytes(public_key)
        signing_temporary = self.root / "package-signing"
        signing_temporary.mkdir()

        tcb_bytes = BUNDLE.canonical_json(
            {
                "schema": "wasm-biotic.native-tcb-inventory.v1",
                "conformance": {"component_complete_claim": True},
            }
        )
        tcb_digest = BUNDLE.sha256_bytes(tcb_bytes)
        profile_bytes = BUNDLE.canonical_json(
            {"schema": "wasm-biotic.factory-substrate-profile.v1"}
        )
        profile_digest = BUNDLE.sha256_bytes(profile_bytes)
        wit_bytes = BUNDLE.canonical_json({"schema": "test-wit-package.v1"})
        wit_digest = BUNDLE.sha256_bytes(wit_bytes)
        contract_bytes = b"# Component-complete conformance\n"
        contract_digest = BUNDLE.sha256_bytes(contract_bytes)

        incumbent_manifest_bytes = BUNDLE.canonical_json(
            {"schema": "wasm-biotic.factory-graph.v1"}
        )
        incumbent = BUNDLE.sha256_bytes(incumbent_manifest_bytes)
        successor_manifest_bytes = BUNDLE.canonical_json(
            {
                "schema": "wasm-biotic.factory-graph.v1",
                "previous_graph": incumbent,
            }
        )
        successor = BUNDLE.sha256_bytes(successor_manifest_bytes)

        for kind, graph_digest, manifest_bytes in (
            ("incumbent", incumbent, incumbent_manifest_bytes),
            ("successor", successor, successor_manifest_bytes),
        ):
            package_root = self.root / f"{kind}-package"
            (package_root / "certification").mkdir(parents=True)
            (package_root / "certified-kernel-tcb").mkdir()
            (package_root / "wit").mkdir()
            (package_root / "manifest.json").write_bytes(manifest_bytes)
            (package_root / "substrate-profile.json").write_bytes(profile_bytes)
            (
                package_root / "certified-kernel-tcb" / f"sha256-{tcb_digest[7:]}.json"
            ).write_bytes(tcb_bytes)
            (
                package_root / "wit" / f"sha256-{wit_digest[7:]}-package.json"
            ).write_bytes(wit_bytes)
            statement = {
                "graph_manifest_digest": graph_digest,
                "native_tcb_inventory_digest": tcb_digest,
                "substrate_profile_digest": profile_digest,
                "wit_package_digest": wit_digest,
            }
            signing_payload = BUNDLE.canonical_json(
                {
                    "certifier_key_id": key_id,
                    "schema": BUNDLE.PACKAGE_SIGNING_PAYLOAD_SCHEMA,
                    "statement": statement,
                }
            )
            package_signature = BUNDLE.sign_payload(
                normalized, signing_payload, signing_temporary
            )
            certification = {
                "schema": "wasm-biotic.release-certification.v1",
                "certifier_key_id": key_id,
                "signature": {
                    "algorithm": "ed25519",
                    "signature_hex": package_signature.hex(),
                },
                "statement": statement,
            }
            certification_bytes = BUNDLE.canonical_json(certification)
            (package_root / "certification" / "release-certification.json").write_bytes(
                certification_bytes
            )
            package = {
                "package_schema": "wasm-biotic.component-graph-package.v1",
                "graph_manifest_digest": graph_digest,
                "certified_kernel_tcb_inventory_digest": tcb_digest,
                "certification_digest": BUNDLE.sha256_bytes(certification_bytes),
                "root_authority_digest": digest("root-authority"),
                "root_executable_digest": digest("root-executable"),
                "validation_report_digest": digest(f"{kind}-validation"),
            }
            (package_root / "package.json").write_bytes(BUNDLE.canonical_json(package))
        shutil.rmtree(signing_temporary)
        normalized.unlink()

        native_source = self.root / "native-source" / "kernel"
        native_source.mkdir(parents=True)
        (native_source / "native-tcb.json").write_bytes(tcb_bytes)
        contract_root = (
            self.root / "normative-contract" / "contracts" / "component-complete"
        )
        contract_root.mkdir(parents=True)
        (contract_root / "CONFORMANCE.md").write_bytes(contract_bytes)

        executable_bytes = b"test-native-executable\n"
        (self.root / "native-executable.bin").write_bytes(executable_bytes)
        executable_digest = BUNDLE.sha256_bytes(executable_bytes)
        for role in sorted(BUNDLE.REQUIRED_OBJECT_ROLES - {"native-executable"}):
            path = self.root / f"{role}.bin"
            if role == "behavioural-equivalence":
                path.write_bytes(
                    BUNDLE.canonical_json(
                        behavioural_report(
                            BUNDLE.BEHAVIOURAL_EQUIVALENCE_SCHEMA_V2,
                            incumbent,
                            successor,
                        )
                    )
                )
            else:
                path.write_bytes(f"{role}\n".encode("utf-8"))
        native_attestation = {
            "schema": "wasm-biotic.native-build-attestation.v1",
            "gate_result": "pass",
            "native_artifact": {
                "sha256": executable_digest,
                "size_bytes": len(executable_bytes),
            },
            "compiled_inventory": {"sha256": tcb_digest},
            "build": {"target": "aarch64-apple-darwin"},
        }
        (self.root / "native-build-attestation.bin").write_bytes(
            BUNDLE.canonical_json(native_attestation)
        )

        self.spec = {
            "schema": BUNDLE.SPEC_SCHEMA,
            "component_complete_claim": True,
            "external_north_star_claim": False,
            "identities": {
                "incumbent_graph_manifest_digest": incumbent,
                "successor_graph_manifest_digest": successor,
                "native_tcb_inventory_digest": tcb_digest,
                "capability_profile_digest": profile_digest,
                "wit_contract_digest": wit_digest,
                "component_complete_contract_digest": contract_digest,
                "native_target": "aarch64-apple-darwin",
            },
            "successor_lineage": {
                "incumbent_graph_manifest_digest": incumbent,
                "successor_graph_manifest_digest": successor,
                "successor_previous_graph_digest": incumbent,
            },
            "gates": {f"C{index}": "pass" for index in range(8)},
            "open_release_blockers": [],
            "trees": [
                {"role": role, "sources": [{"source": role, "prefix": ""}]}
                for role in sorted(BUNDLE.TREE_ROLES)
            ],
            "objects": [
                {"role": role, "source": f"{role}.bin"}
                for role in sorted(BUNDLE.REQUIRED_OBJECT_ROLES)
            ],
        }
        self.spec_path = self.root / "spec.json"
        self.spec_path.write_text(json.dumps(self.spec), encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def build(self) -> tuple[Path, str]:
        release = BUNDLE.build_bundle(
            self.spec_path, self.private_key, self.root / "releases"
        )
        claim = json.loads((release / "claim" / "manifest.json").read_text())
        public_ref = next(
            item for item in claim["objects"] if item["role"] == "certifier-public-key"
        )
        public_hex = (release / public_ref["path"]).read_bytes().hex()
        return release, public_hex

    def test_round_trip_and_unlisted_file_rejection(self) -> None:
        release, public_hex = self.build()
        root_digest = BUNDLE.verify_bundle(release, public_hex)
        self.assertEqual(release.name, root_digest.replace("sha256:", "sha256-"))
        (release / "objects" / "unlisted").write_bytes(b"tamper")
        with self.assertRaisesRegex(BUNDLE.BundleError, "unlisted files"):
            BUNDLE.verify_bundle(release, public_hex)

    def test_historical_behavioural_equivalence_v1_remains_accepted(self) -> None:
        path = self.root / "behavioural-equivalence.bin"
        path.write_bytes(
            BUNDLE.canonical_json(
                behavioural_report(
                    BUNDLE.BEHAVIOURAL_EQUIVALENCE_SCHEMA_V1,
                    self.spec["identities"]["incumbent_graph_manifest_digest"],
                    self.spec["identities"]["successor_graph_manifest_digest"],
                )
            )
        )
        release, public_hex = self.build()
        BUNDLE.verify_bundle(release, public_hex)

    def test_behavioural_equivalence_must_bind_release_cohort(self) -> None:
        path = self.root / "behavioural-equivalence.bin"
        report = json.loads(path.read_text(encoding="utf-8"))
        report["lifecycle"]["successor_graph_manifest_digest"] = digest(
            "stale-successor"
        )
        path.write_bytes(BUNDLE.canonical_json(report))
        with self.assertRaisesRegex(BUNDLE.BundleError, "release cohort"):
            BUNDLE.build_bundle(
                self.spec_path, self.private_key, self.root / "releases"
            )

    def test_behavioural_equivalence_v2_must_label_synthetic_boundary(self) -> None:
        path = self.root / "behavioural-equivalence.bin"
        report = json.loads(path.read_text(encoding="utf-8"))
        report["synthetic_policy_trace_claims_useful_r1_semantics"] = True
        path.write_bytes(BUNDLE.canonical_json(report))
        with self.assertRaisesRegex(
            BUNDLE.BundleError,
            "synthetic_policy_trace_claims_useful_r1_semantics must be false",
        ):
            BUNDLE.build_bundle(
                self.spec_path, self.private_key, self.root / "releases"
            )

    def test_r2_behavioural_equivalence_requires_exact_authority_handoff(self) -> None:
        identities = dict(self.spec["identities"])
        identities.update(
            {
                "incumbent_principal_inventory_digest": digest(
                    "r2-incumbent-principal-inventory"
                ),
                "successor_principal_inventory_digest": digest(
                    "r2-successor-principal-inventory"
                ),
            }
        )
        component_lifecycle_digest = digest("r2-component-lifecycle-object")
        report = r2_behavioural_report(identities, component_lifecycle_digest)
        BUNDLE.validate_behavioural_equivalence_report(
            BUNDLE.canonical_json(report),
            identities,
            "behavioural equivalence",
            r2_claim=True,
            component_lifecycle_digest=component_lifecycle_digest,
        )

        def changed(path: tuple[object, ...], value: object) -> dict:
            mutated = json.loads(json.dumps(report))
            target: object = mutated
            for part in path[:-1]:
                target = target[part]  # type: ignore[index]
            target[path[-1]] = value  # type: ignore[index]
            return mutated

        mutations = (
            (
                "lifecycle-object-substitution",
                changed(
                    ("lifecycle", "source_report_digest"),
                    digest("substituted-component-lifecycle-object"),
                ),
                "does not match the signed component-lifecycle object",
            ),
            (
                "noncanonical-lifecycle-path",
                changed(
                    ("lifecycle", "source_report_path"),
                    "../../evidence/component-lifecycle.json",
                ),
                "canonical package lifecycle path",
            ),
            (
                "source-schema",
                changed(("lifecycle", "source_schema"), "wasm-biotic.component-lifecycle-execution.v1"),
                "source_schema",
            ),
            (
                "handoff",
                changed(
                    (
                        "lifecycle",
                        "graph_qualified_activation_ownership_handoff_verified",
                    ),
                    False,
                ),
                "handoff_verified must be true",
            ),
            (
                "stable-principal-mapping",
                changed(
                    (
                        "lifecycle",
                        "principal_mapping_stable_across_restart_activation_and_rollback",
                    ),
                    False,
                ),
                "principal_mapping_stable.*must be true",
            ),
            (
                "inventory-substitution",
                changed(
                    ("lifecycle", "principal_inventory_digests", "successor"),
                    digest("substituted-successor-inventory"),
                ),
                "does not match the R2 release cohort",
            ),
            (
                "phase-order",
                changed(
                    ("lifecycle", "authority_trace_summaries", 0, "phase"),
                    "rollback",
                ),
                "phases must remain ordered",
            ),
            (
                "profile-mapping",
                changed(
                    (
                        "lifecycle",
                        "authority_trace_summaries",
                        1,
                        "profile_mapping_verified",
                    ),
                    False,
                ),
                "profile_mapping_verified must be true",
            ),
            (
                "phase-graph-scope",
                changed(
                    (
                        "lifecycle",
                        "authority_trace_summaries",
                        2,
                        "graph_manifest_digests",
                    ),
                    [identities["incumbent_graph_manifest_digest"]],
                ),
                "exact R2 phase graph scope",
            ),
            (
                "duplicate-trace-digest",
                changed(
                    (
                        "lifecycle",
                        "authority_trace_summaries",
                        3,
                        "trace_digest",
                    ),
                    report["lifecycle"]["authority_trace_summaries"][0][
                        "trace_digest"
                    ],
                ),
                "different trace digest",
            ),
        )
        for label, mutated, message in mutations:
            with self.subTest(label=label):
                with self.assertRaisesRegex(BUNDLE.BundleError, message):
                    BUNDLE.validate_behavioural_equivalence_report(
                        BUNDLE.canonical_json(mutated),
                        identities,
                        "behavioural equivalence",
                        r2_claim=True,
                        component_lifecycle_digest=component_lifecycle_digest,
                    )

        v1 = behavioural_report(
            BUNDLE.BEHAVIOURAL_EQUIVALENCE_SCHEMA_V1,
            identities["incumbent_graph_manifest_digest"],
            identities["successor_graph_manifest_digest"],
        )
        with self.assertRaisesRegex(BUNDLE.BundleError, "must use.*v2"):
            BUNDLE.validate_behavioural_equivalence_report(
                BUNDLE.canonical_json(v1),
                identities,
                "behavioural equivalence",
                r2_claim=True,
                component_lifecycle_digest=component_lifecycle_digest,
            )

    def test_independent_key_is_required(self) -> None:
        release, public_hex = self.build()
        wrong_hex = ("0" if public_hex[0] != "0" else "1") + public_hex[1:]
        with self.assertRaisesRegex(BUNDLE.BundleError, "independently supplied"):
            BUNDLE.verify_bundle(release, wrong_hex)

    def test_private_key_material_is_rejected_as_an_object(self) -> None:
        native = next(
            item for item in self.spec["objects"] if item["role"] == "native-executable"
        )
        native["source"] = self.private_key.name
        self.spec_path.write_text(json.dumps(self.spec), encoding="utf-8")
        with self.assertRaisesRegex(BUNDLE.BundleError, "private"):
            BUNDLE.build_bundle(
                self.spec_path, self.private_key, self.root / "releases"
            )

    def test_symlink_in_a_tree_is_rejected(self) -> None:
        source = self.root / "incumbent-package"
        try:
            (source / "escape").symlink_to(
                self.root / "successor-package" / "manifest.json"
            )
        except OSError as error:
            self.skipTest(f"symlinks are unavailable: {error}")
        with self.assertRaisesRegex(BUNDLE.BundleError, "symlink"):
            BUNDLE.build_bundle(
                self.spec_path, self.private_key, self.root / "releases"
            )

    def test_native_attestation_cross_substitution_is_rejected(self) -> None:
        path = self.root / "native-build-attestation.bin"
        attestation = json.loads(path.read_text(encoding="utf-8"))
        attestation["compiled_inventory"]["sha256"] = digest("wrong-tcb")
        path.write_bytes(BUNDLE.canonical_json(attestation))
        with self.assertRaisesRegex(BUNDLE.BundleError, "compiled inventory"):
            BUNDLE.build_bundle(
                self.spec_path, self.private_key, self.root / "releases"
            )

    def test_successor_package_identity_substitution_is_rejected(self) -> None:
        path = self.root / "successor-package" / "package.json"
        package = json.loads(path.read_text(encoding="utf-8"))
        package["graph_manifest_digest"] = self.spec["identities"][
            "incumbent_graph_manifest_digest"
        ]
        path.write_bytes(BUNDLE.canonical_json(package))
        with self.assertRaisesRegex(BUNDLE.BundleError, "successor package index"):
            BUNDLE.build_bundle(
                self.spec_path, self.private_key, self.root / "releases"
            )

    def test_r2_spec_requires_principal_identity_and_evidence(self) -> None:
        self.spec["schema"] = BUNDLE.SPEC_SCHEMA_V2
        self.spec["claim_profile"] = BUNDLE.R2_CLAIM_PROFILE
        self.spec["identities"].update(
            {
                "incumbent_principal_inventory_digest": digest(
                    "incumbent-principal-inventory"
                ),
                "successor_principal_inventory_digest": digest(
                    "successor-principal-inventory"
                ),
                "incumbent_derivation_descriptor_digest": digest(
                    "incumbent-r2-descriptor"
                ),
                "successor_derivation_descriptor_digest": digest(
                    "successor-r2-descriptor"
                ),
            }
        )
        principal_path = self.root / "principal-isolation.bin"
        principal_path.write_bytes(b"principal-isolation\n")
        self.spec["objects"].append(
            {"role": "principal-isolation", "source": principal_path.name}
        )
        self.spec_path.write_text(json.dumps(self.spec), encoding="utf-8")
        resolved = BUNDLE.resolve_spec(self.spec_path)
        self.assertEqual(resolved["schema"], BUNDLE.SPEC_SCHEMA_V2)

        self.spec["objects"] = [
            item
            for item in self.spec["objects"]
            if item["role"] != "principal-isolation"
        ]
        self.spec_path.write_text(json.dumps(self.spec), encoding="utf-8")
        with self.assertRaisesRegex(BUNDLE.BundleError, "principal-isolation"):
            BUNDLE.resolve_spec(self.spec_path)

    def test_r3_spec_retains_r2_and_requires_transport_identity_and_evidence(self) -> None:
        self.spec["schema"] = BUNDLE.SPEC_SCHEMA_V3
        self.spec["claim_profile"] = BUNDLE.R3_CLAIM_PROFILE
        self.spec["identities"].update(
            {
                field: value
                for field, value in r3_identities().items()
                if field
                in {
                    "incumbent_principal_inventory_digest",
                    "successor_principal_inventory_digest",
                    "incumbent_derivation_descriptor_digest",
                    "successor_derivation_descriptor_digest",
                    "incumbent_http_transport_constraint_digest",
                    "successor_http_transport_constraint_digest",
                }
            }
        )
        for role in ("principal-isolation", "transport-confinement"):
            path = self.root / f"{role}.bin"
            path.write_bytes(f"{role}\n".encode("utf-8"))
            self.spec["objects"].append(
                {"role": role, "source": path.name}
            )
        self.spec["objects"].sort(key=lambda item: item["role"])
        self.spec_path.write_text(json.dumps(self.spec), encoding="utf-8")
        resolved = BUNDLE.resolve_spec(self.spec_path)
        self.assertEqual(resolved["schema"], BUNDLE.SPEC_SCHEMA_V3)

        self.spec["objects"] = [
            item
            for item in self.spec["objects"]
            if item["role"] != "transport-confinement"
        ]
        self.spec_path.write_text(json.dumps(self.spec), encoding="utf-8")
        with self.assertRaisesRegex(BUNDLE.BundleError, "transport-confinement"):
            BUNDLE.resolve_spec(self.spec_path)

    def test_principal_isolation_verifier_requires_exact_handoff_facts(self) -> None:
        report, identities = principal_isolation_report()
        BUNDLE.validate_principal_isolation_report(
            BUNDLE.canonical_json(report), identities, "principal isolation"
        )

        for field in (
            "atomic_commit_owner_handoff",
            "restart_persistence_verified",
            "rollback_owner_handback",
        ):
            with self.subTest(field=field):
                mutated, identities = principal_isolation_report()
                mutated["independent_substrate"]["activation_owner_handoff"][field] = False
                with self.assertRaisesRegex(BUNDLE.BundleError, field):
                    BUNDLE.validate_principal_isolation_report(
                        BUNDLE.canonical_json(mutated),
                        identities,
                        "principal isolation",
                    )

        mutated, identities = principal_isolation_report()
        mutated["independent_substrate"][
            "graph_qualified_activation_owner_handoff_enforced"
        ] = False
        with self.assertRaisesRegex(BUNDLE.BundleError, "handoff_enforced"):
            BUNDLE.validate_principal_isolation_report(
                BUNDLE.canonical_json(mutated), identities, "principal isolation"
            )

        mutated, identities = principal_isolation_report()
        mutated["independent_substrate"]["release_pair"]["successor"][
            "graph_manifest_digest"
        ] = digest("substituted-successor")
        with self.assertRaisesRegex(BUNDLE.BundleError, "release_pair.successor"):
            BUNDLE.validate_principal_isolation_report(
                BUNDLE.canonical_json(mutated), identities, "principal isolation"
            )

    def test_principal_isolation_verifier_requires_exact_campaign(self) -> None:
        report, identities = principal_isolation_report()
        report["independent_substrate"]["cases_passed"] -= 1
        with self.assertRaisesRegex(BUNDLE.BundleError, "exact independent case count"):
            BUNDLE.validate_principal_isolation_report(
                BUNDLE.canonical_json(report), identities, "principal isolation"
            )

        report, identities = principal_isolation_report()
        report["cross_principal_cases"][-1] = dict(
            report["cross_principal_cases"][-2]
        )
        with self.assertRaisesRegex(BUNDLE.BundleError, "duplicates principal case"):
            BUNDLE.validate_principal_isolation_report(
                BUNDLE.canonical_json(report), identities, "principal isolation"
            )

    def test_r2_native_source_closure_is_recomputed_from_retained_bytes(self) -> None:
        bundle = self.root / "synthetic-r2-bundle"
        tree_path = "trees/sha256-native-source"
        files_root = bundle / tree_path / "files"
        sources = {
            "kernel/Cargo.lock": b"lock\n",
            "kernel/Cargo.toml": b"[package]\nname='kernel'\n",
            "kernel/src/lib.rs": b"pub fn mechanism() {}\n",
            "wit/wasm-biotic/foundation.wit": b"package test:factory;\n",
        }
        entries = []
        lines = bytearray()
        rows = []
        for relative in sorted(sources, key=lambda path: path.encode("utf-8")):
            path = files_root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(sources[relative])
            source_digest = BUNDLE.sha256_bytes(sources[relative])
            entries.append(
                {
                    "path": relative,
                    "sha256": source_digest,
                    "size_bytes": len(sources[relative]),
                }
            )
            lines.extend(
                f"{source_digest[7:]}  {relative}\n".encode("utf-8")
            )
            rows.append({"path": relative, "sha256": source_digest})
        (bundle / tree_path / "tree.json").write_bytes(
            BUNDLE.canonical_json(
                {
                    "schema": BUNDLE.TREE_SCHEMA,
                    "digest_algorithm": "sha256",
                    "entries": entries,
                }
            )
        )
        revision = BUNDLE.sha256_bytes(bytes(lines))
        inventory = {
            "crate": {
                "source_revision": {
                    "status": "content-addressed-source-closure",
                    "value": revision,
                    "algorithm": BUNDLE.R2_NATIVE_SOURCE_ALGORITHM,
                    "scope": BUNDLE.R2_NATIVE_SOURCE_SCOPE,
                }
            }
        }
        attestation = {
            "source_closure": {
                "sha256": revision,
                "algorithm": BUNDLE.R2_NATIVE_SOURCE_ALGORITHM,
                "scope": BUNDLE.R2_NATIVE_SOURCE_SCOPE.replace(
                    "this self-referential inventory is excluded",
                    "kernel/native-tcb.json is excluded as self-referential",
                ),
                "inventory_entries_verified": len(rows),
                "files": rows,
                "recomputation_result": "pass",
            }
        }
        tree_ref = {"path": tree_path}
        BUNDLE.verify_r2_native_source_closure(
            bundle, tree_ref, inventory, attestation
        )

        inventory_bytes = BUNDLE.canonical_json(inventory)
        inventory_path = files_root / "kernel/native-tcb.json"
        inventory_path.write_bytes(inventory_bytes)
        entries.append(
            {
                "path": "kernel/native-tcb.json",
                "sha256": BUNDLE.sha256_bytes(inventory_bytes),
                "size_bytes": len(inventory_bytes),
            }
        )
        entries.sort(key=lambda entry: entry["path"].encode("utf-8"))
        (bundle / tree_path / "tree.json").write_bytes(
            BUNDLE.canonical_json(
                {
                    "schema": BUNDLE.TREE_SCHEMA,
                    "digest_algorithm": "sha256",
                    "entries": entries,
                }
            )
        )

        contract_bytes = b"# R2 conformance\n"
        contract_tree_path = "trees/sha256-normative-contract"
        contract_path = (
            bundle
            / contract_tree_path
            / "files/contracts/component-complete/CONFORMANCE.md"
        )
        contract_path.parent.mkdir(parents=True, exist_ok=True)
        contract_path.write_bytes(contract_bytes)
        attestation.update(
            {
                "schema": "wasm-biotic.native-build-attestation.v1",
                "gate_result": "pass",
                "native_artifact": {
                    "sha256": digest("r2-native"),
                    "size_bytes": 42,
                },
                "compiled_inventory": {
                    "sha256": BUNDLE.sha256_bytes(inventory_bytes)
                },
                "build": {"target": "aarch64-apple-darwin"},
            }
        )
        attestation_path = bundle / "objects/attestation.json"
        attestation_path.parent.mkdir(parents=True, exist_ok=True)
        attestation_path.write_bytes(BUNDLE.canonical_json(attestation))
        BUNDLE.verify_native_cross_bindings(
            bundle,
            {
                "native-source": tree_ref,
                "normative-contract": {"path": contract_tree_path},
            },
            {
                "native-executable": {
                    "sha256": digest("r2-native"),
                    "size_bytes": 42,
                },
                "native-build-attestation": {
                    "path": "objects/attestation.json"
                },
            },
            {
                "native_tcb_inventory_digest": BUNDLE.sha256_bytes(
                    inventory_bytes
                ),
                "component_complete_contract_digest": BUNDLE.sha256_bytes(
                    contract_bytes
                ),
                "native_target": "aarch64-apple-darwin",
                "incumbent_principal_inventory_digest": digest(
                    "r2-principal-inventory"
                ),
            },
        )

        (files_root / "kernel/src/lib.rs").write_bytes(b"tampered\n")
        with self.assertRaisesRegex(BUNDLE.BundleError, "do not reproduce"):
            BUNDLE.verify_r2_native_source_closure(
                bundle, tree_ref, inventory, attestation
            )


if __name__ == "__main__":
    unittest.main()
