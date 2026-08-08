#!/usr/bin/env python3
"""Unit tests for versioned signed-admission report selection and R1 evidence."""

from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
import unittest


SCRIPT = Path(__file__).with_name("r0-signed-admission.py")
SPEC = importlib.util.spec_from_file_location("wasm_biotic_signed_admission", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
ADMISSION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ADMISSION)


def digest(character: str) -> str:
    return f"sha256:{character * 64}"


def independent_r1_reproduction() -> dict[str, object]:
    semantic_hex = {
        name: character * 64
        for name, character in [
            ("request_digest_hex", "1"),
            ("base_tree_digest_hex", "2"),
            ("patched_tree_digest_hex", "3"),
            ("artifact_digest_hex", "4"),
            ("validation_digest_hex", "5"),
            ("review_digest_hex", "6"),
            ("package_digest_hex", "7"),
            ("verification_digest_hex", "8"),
            ("evidence_digest_hex", "9"),
            ("resolved_digest_hex", "a"),
        ]
    }
    semantics: dict[str, object] = {
        **semantic_hex,
        "source_changed": True,
        "bytecode_size_bytes": 29,
        "provider_policy": "local-fixture",
        "tests_discovered": 1,
        "passed_tests": 1,
        "total_tests": 1,
        "review_approved": True,
        "package_verified": True,
        "evidence_resolved": True,
        "operation_history": list(ADMISSION.R1_OPERATION_HISTORY),
        "fixture_label": "kernel-probe",
        "input_digest": digest("1"),
        "input_media_type": ADMISSION.R1_CHANGE_REQUEST_MEDIA_TYPE,
        "output_digest": digest("a"),
        "output_media_type": ADMISSION.R1_WORK_STATE_MEDIA_TYPE,
    }
    return {
        "admitted_dynamic_authorities": 7,
        "boundary_probe_component_root": True,
        "boundary_probe_status": 200,
        "complete_six_worker_cycle": True,
        "dynamic_execution_provenance": {
            name: {}
            for name in [
                "planner",
                "builder",
                "validator",
                "reviewer",
                "packager",
                "continuity-worker",
                "admitted-tool-probe",
            ]
        },
        "evolution_shadow_matched": True,
        "exact_replay": {
            "inspect_blob_equal": True,
            "inspect_bytes_equal": True,
            "job_id_equal": True,
            "mechanism_snapshot_after_digest": digest("b"),
            "mechanism_snapshot_before_digest": digest("b"),
            "mechanism_snapshot_unchanged": True,
            "output_blob_equal": True,
            "output_bytes_equal": True,
            "provenance_unchanged": True,
            "resubmitted_exact_submit_blob": True,
        },
        "final_output_digest": digest("a"),
        "final_output_media_type": ADMISSION.R1_WORK_STATE_MEDIA_TYPE,
        "r1_semantics": semantics,
        "r1_semantics_verified": True,
        "reference_exact_replay_claim_complete": True,
        "reference_final_output_exact_match": True,
        "reference_provenance_exact_match": True,
        "reference_r1_semantics_exact_match": True,
        "reference_terminal_result_exact_match": True,
        "source_digest": digest("1"),
        "source_label": "kernel-probe",
        "source_media_type": ADMISSION.R1_CHANGE_REQUEST_MEDIA_TYPE,
        "terminal_result_digest": digest("c"),
        "terminal_status": "completed",
    }


def r2_package(
    character: str, profile_schema: str = ADMISSION.PROFILE_SCHEMA_V2
) -> dict[str, object]:
    callers = {
        role: digest("d" if role == "admitted-tool-probe" else "e")
        for role in ADMISSION.R2_DYNAMIC_TARGETS
    }
    consumers = {
        role: "factory-evolution" if role == "admitted-tool-probe" else "worker-router"
        for role in ADMISSION.R2_DYNAMIC_TARGETS
    }
    return {
        "certification_digest": digest(character),
        "manifest_digest": digest(character),
        "previous_graph": None,
        "root_authority_digest": digest("1"),
        "root_executable_digest": digest("2"),
        "strict_report_digest": digest("3"),
        "wit_package_digest": digest("4"),
        "derivation_descriptor_digest": digest("5"),
        "substrate_profile_digest": digest("6"),
        "principal_inventory_digest": digest("7"),
        "principal_alias_count": 34,
        "principal_count": 22,
        "pure_principal_count": 1,
        "import_alias_scheme": ADMISSION.R2_IMPORT_ALIAS_SCHEME,
        "principal_id_scheme": ADMISSION.R2_PRINCIPAL_ID_SCHEME,
        "profile_schema": profile_schema,
        "expected_dynamic_caller_principals": callers,
        "expected_dynamic_caller_consumers": consumers,
    }


def independent_r2(package: dict[str, object]) -> tuple[dict[str, object], dict[str, object]]:
    reproduction = independent_r1_reproduction()
    callers = package["expected_dynamic_caller_principals"]
    consumers = package["expected_dynamic_caller_consumers"]
    assert isinstance(callers, dict) and isinstance(consumers, dict)
    provenance = reproduction["dynamic_execution_provenance"]
    assert isinstance(provenance, dict)
    for role in ADMISSION.R2_DYNAMIC_TARGETS:
        provenance[role] = {
            "authority_component_digest": digest("8"),
            "caller_principal_seed": callers[role],
            "executable_component_digest": digest("9"),
            "graph_manifest_digest": package["manifest_digest"],
            "source_component_digests": [digest("a")],
        }
    reproduction["caller_principals_exact"] = True
    reproduction["observed_caller_principals"] = {
        consumer: callers[role] for role, consumer in consumers.items()
    }
    independent = {
        "independent_substrate": {
            "dependencies_on_forbidden_native_implementations": False,
            "mechanism_interfaces": [
                "blob-store",
                "transaction-store",
                "clock",
                "component-runner",
                "http-transport",
                "key-service",
                "activation",
                "audit-log",
            ],
        },
        "principal_enforcement": {
            "alias_count": package["principal_alias_count"],
            "caller_identity_source": "validated-linker-alias-bound-to-signed-principal-seed-v1",
            "caller_owned_operations_enforced": True,
            "caller_target_edges_enforced": True,
            "canonical_host_imports_absent": True,
            "descriptor_schema": "wasm-biotic.component-derivation-descriptor.v2",
            "fixed_linker_alias_contexts": True,
            "import_alias_scheme": package["import_alias_scheme"],
            "principal_count": package["principal_count"],
            "principal_id_scheme": package["principal_id_scheme"],
            "principal_inventory_digest": package["principal_inventory_digest"],
            "profile_schema": package["profile_schema"],
            "pure_principal_count": package["pure_principal_count"],
            "result": "pass",
        },
    }
    return independent, reproduction


class SignedAdmissionVersionTests(unittest.TestCase):
    def test_v1_candidate_retains_historical_r0_outer_schema(self) -> None:
        contract = ADMISSION.report_contract_for_candidate_schema(
            ADMISSION.CANDIDATE_REPORT_SCHEMA_V1
        )
        self.assertEqual(contract["schema"], ADMISSION.REPORT_SCHEMA_R0)
        self.assertEqual(contract["evidence_profile"], "r0-bounded-cycle")
        self.assertIn("Section 7", contract["claim_scope"])

    def test_v2_candidate_uses_truthful_r1_outer_schema_and_wording(self) -> None:
        contract = ADMISSION.report_contract_for_candidate_schema(
            ADMISSION.CANDIDATE_REPORT_SCHEMA_V2
        )
        self.assertEqual(contract["schema"], ADMISSION.REPORT_SCHEMA_R1)
        self.assertEqual(contract["evidence_profile"], "r1-bounded-local-source-change")
        self.assertIn("canonical R1 source-change", contract["claim_scope"])

    def test_v3_candidate_uses_truthful_r2_outer_schema_and_wording(self) -> None:
        contract = ADMISSION.report_contract_for_candidate_schema(
            ADMISSION.CANDIDATE_REPORT_SCHEMA_V3
        )
        self.assertEqual(contract["schema"], ADMISSION.REPORT_SCHEMA_R2)
        self.assertEqual(contract["evidence_profile"], "r2-per-consumer-least-authority")
        self.assertIn("per-consumer principal", contract["claim_scope"])

    def test_v3_candidate_and_profile_v3_use_distinct_r3_contract(self) -> None:
        contract = ADMISSION.report_contract_for_candidate_schema(
            ADMISSION.CANDIDATE_REPORT_SCHEMA_V3,
            ADMISSION.PROFILE_SCHEMA_V3,
        )
        self.assertEqual(contract["schema"], ADMISSION.REPORT_SCHEMA_R3)
        self.assertEqual(
            contract["evidence_profile"], "r3-bounded-http-component-authority"
        )
        self.assertIn("bounded-HTTP profile/constraint identity", contract["claim_scope"])

    def test_candidate_schema_and_profile_generation_mismatch_fails_closed(self) -> None:
        with self.assertRaisesRegex(ADMISSION.HarnessError, "profile generation"):
            ADMISSION.report_contract_for_candidate_schema(
                ADMISSION.CANDIDATE_REPORT_SCHEMA_V2,
                ADMISSION.PROFILE_SCHEMA_V3,
            )

    def test_unknown_candidate_schema_fails_closed(self) -> None:
        with self.assertRaises(ADMISSION.HarnessError):
            ADMISSION.report_contract_for_candidate_schema("candidate-shadow.v3")

    def test_complete_independent_r1_reproduction_is_accepted(self) -> None:
        ADMISSION.validate_independent_r1_reproduction(independent_r1_reproduction())

    def test_r1_path_rejects_legacy_media_or_short_history(self) -> None:
        legacy = independent_r1_reproduction()
        legacy["source_media_type"] = "application/octet-stream"
        with self.assertRaisesRegex(ADMISSION.HarnessError, "change-request media"):
            ADMISSION.validate_independent_r1_reproduction(legacy)

        short = independent_r1_reproduction()
        short_semantics = short["r1_semantics"]
        assert isinstance(short_semantics, dict)
        short_semantics["operation_history"] = ADMISSION.R1_OPERATION_HISTORY[:-1]
        with self.assertRaisesRegex(ADMISSION.HarnessError, "12-operation"):
            ADMISSION.validate_independent_r1_reproduction(short)

    def test_r1_path_rejects_unverified_semantics_or_changed_replay(self) -> None:
        unverified = independent_r1_reproduction()
        unverified["r1_semantics_verified"] = False
        with self.assertRaisesRegex(ADMISSION.HarnessError, "r1_semantics_verified"):
            ADMISSION.validate_independent_r1_reproduction(unverified)

        changed = copy.deepcopy(independent_r1_reproduction())
        replay = changed["exact_replay"]
        assert isinstance(replay, dict)
        replay["provenance_unchanged"] = False
        with self.assertRaisesRegex(ADMISSION.HarnessError, "provenance_unchanged"):
            ADMISSION.validate_independent_r1_reproduction(changed)

    def test_r2_independent_path_binds_exact_alias_principals(self) -> None:
        package = r2_package("b")
        independent, reproduction = independent_r2(package)
        ADMISSION.validate_independent_r2_reproduction(
            independent, reproduction, package
        )

        altered = copy.deepcopy(reproduction)
        observed = altered["observed_caller_principals"]
        assert isinstance(observed, dict)
        observed["worker-router"] = digest("f")
        with self.assertRaisesRegex(ADMISSION.HarnessError, "signed exact mapping"):
            ADMISSION.validate_independent_r2_reproduction(
                independent, altered, package
            )

    def test_r3_independent_path_requires_exact_profile_v3_identity(self) -> None:
        package = r2_package("c", ADMISSION.PROFILE_SCHEMA_V3)
        independent, reproduction = independent_r2(package)
        ADMISSION.validate_independent_r2_reproduction(
            independent, reproduction, package
        )

        altered = copy.deepcopy(independent)
        enforcement = altered["principal_enforcement"]
        assert isinstance(enforcement, dict)
        enforcement["profile_schema"] = ADMISSION.PROFILE_SCHEMA_V2
        with self.assertRaisesRegex(ADMISSION.HarnessError, "profile_schema"):
            ADMISSION.validate_independent_r2_reproduction(
                altered, reproduction, package
            )


if __name__ == "__main__":
    unittest.main()
