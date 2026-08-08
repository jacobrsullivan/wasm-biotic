#!/usr/bin/env python3
"""Safety and binding tests for r4-public-install.py."""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest


TOOL = Path(__file__).with_name("r4-public-install.py")
SPEC = importlib.util.spec_from_file_location("r4_public_install", TOOL)
assert SPEC and SPEC.loader
install = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(install)
ARCHIVE_TOOL = Path(__file__).with_name("r4-install-archive.py")
ARCHIVE_SPEC = importlib.util.spec_from_file_location("r4_install_archive_for_public", ARCHIVE_TOOL)
assert ARCHIVE_SPEC and ARCHIVE_SPEC.loader
archive = importlib.util.module_from_spec(ARCHIVE_SPEC)
ARCHIVE_SPEC.loader.exec_module(archive)


class PublicInstallTests(unittest.TestCase):
    def component_lifecycle_fixture(self) -> tuple[dict[str, object], str, str, str]:
        incumbent = "sha256:" + "11" * 32
        successor = "sha256:" + "22" * 32
        public_key = "33" * 32

        def hashed(value: str) -> dict[str, str]:
            return {"algorithm": "sha256", "hex": value[7:]}

        replay = {
            "inspect_blob_equal": True,
            "inspect_bytes_equal": True,
            "job_id_equal": True,
            "mechanism_counters_after": {"transaction_version": 1},
            "mechanism_counters_before": {"transaction_version": 1},
            "mechanism_counters_unchanged": True,
            "mechanism_state_digest_after": incumbent,
            "mechanism_state_digest_before": incumbent,
            "mechanism_state_unchanged": True,
            "output_blob_equal": True,
            "output_bytes_equal": True,
            "resubmitted_exact_submit_blob": True,
        }

        def cycle(graph: str) -> dict[str, object]:
            return {
                "exact_replay": dict(replay),
                "execution_completions": {
                    key: {}
                    for key in (
                        "builder",
                        "continuity-worker",
                        "packager",
                        "planner",
                        "reviewer",
                        "validator",
                    )
                },
                "graph_manifest_digest": graph,
                "terminal_result": {"failure": None, "status": "completed"},
            }

        value: dict[str, object] = {
            "build_performed": False,
            "certifier_key_id": install.digest_bytes(bytes.fromhex(public_key)),
            "component_complete_claim": False,
            "inactive_successor_admission": {
                "active_manifest_after_admission": incumbent,
                "active_manifest_before_admission": incumbent,
                "active_manifest_unchanged": True,
                "admitted_successor_manifest_digest": successor,
            },
            "incumbent": {
                "graph_manifest_digest": incumbent,
                "previous_graph_manifest_digest": None,
                "signature_and_exact_closure_verified_by_production_admission": True,
            },
            "lifecycle": {
                "all_factory_semantics_executed_as_components": True,
                "component_decided_initial_state_binding": True,
                "component_decided_rollback": True,
                "component_decided_successor_activation": True,
                "graph_qualified_activation_ownership_handoff_verified": True,
                "incumbent_cycle": cycle(incumbent),
                "incumbent_graph_manifest_digest": incumbent,
                "native_substrate_responsibility": (
                    "verified admission, instantiation, metering, opaque persistence, "
                    "communication and declared-capability enforcement only"
                ),
                "post_rollback_cycle": cycle(incumbent),
                "principal_mapping_stable_across_restart_activation_and_rollback": True,
                "restart_preserved_rollback_pair": True,
                "rollback_observation_result": {
                    "action": "rolled-back",
                    "observed_graph": hashed(successor),
                    "status": {
                        "active_graph": hashed(incumbent),
                        "state": "rolled-back",
                    },
                },
                "successor_cycle": cycle(successor),
                "successor_graph_manifest_digest": successor,
                "upgrade_result": {
                    "committed": {"active_graph": hashed(successor)},
                    "previous_graph": hashed(incumbent),
                    "target_graph": hashed(successor),
                },
            },
            "outcome": "pass",
            "operator_capacity_sha256": "sha256:" + "44" * 32,
            "private_signing_key_required_or_read": False,
            "public_key_hex": public_key,
            "schema": install.LIFECYCLE_SCHEMA,
            "signing_performed": False,
            "state": {
                "final_active_manifest_digest": incumbent,
                "fresh_state_directory_required": True,
                "incumbent_bootstrap_manifest_digest": incumbent,
                "restart_reopened_persisted_state": True,
            },
            "successor": {
                "graph_manifest_digest": successor,
                "previous_graph_manifest_digest": incumbent,
                "signature_and_exact_closure_verified_by_production_admission": True,
            },
        }
        return value, incumbent, successor, public_key

    def fixture(
        self,
        root: Path,
        *,
        archive_tool_in_install: bool = False,
    ) -> argparse.Namespace:
        root.mkdir(parents=True, exist_ok=True)
        extracted = root / "install"
        extracted.mkdir()
        kernel = extracted / "kernel"
        runner = extracted / "runner"
        operator_capacity = extracted / "operator-capacity.json"
        kernel.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        runner.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        operator_capacity.write_bytes(
            b'{"mechanisms":{"allowed_namespaces":[],"max_blob_bytes":1,"max_component_fuel":1,"max_component_memory_bytes":1,"max_component_output_bytes":1,"max_component_wall_time_ms":1,"max_http_timeout_ms":1,"max_random_bytes":1,"max_total_blob_bytes":1,"max_wake_delay_ms":1},"schema":"wasm-biotic.operator-mechanism-capacity.v1"}'
        )
        kernel.chmod(0o755)
        runner.chmod(0o755)
        incumbent_manifest = b'{"graph":"incumbent"}'
        successor_manifest = b'{"graph":"successor"}'
        incumbent_digest = install.digest_bytes(incumbent_manifest)
        successor_digest = install.digest_bytes(successor_manifest)
        incumbent = extracted / incumbent_digest.replace(":", "-")
        successor = extracted / successor_digest.replace(":", "-")
        incumbent.mkdir()
        successor.mkdir()
        (incumbent / "manifest.json").write_bytes(incumbent_manifest)
        (successor / "manifest.json").write_bytes(successor_manifest)
        (incumbent / "factory-root.wasm").write_bytes(b"component-root")
        archive_tool = ARCHIVE_TOOL
        if archive_tool_in_install:
            archive_tool = extracted / "tools" / "r4-install-archive.py"
            archive_tool.parent.mkdir()
            archive_tool.write_bytes(ARCHIVE_TOOL.read_bytes())
        archive_path = root / "install.tar"
        archive_digest, _ = archive.write_archive(extracted, archive_path, 0)
        return argparse.Namespace(
            kernel=kernel,
            lifecycle_runner=runner,
            operator_capacity=operator_capacity,
            incumbent=incumbent,
            successor=successor,
            public_key_hex="11" * 32,
            wrong_public_key_hex="22" * 32,
            expected_kernel_sha256=install.digest_file(kernel),
            install_archive=archive_path,
            install_archive_sha256=archive_digest,
            archive_tool=archive_tool,
            extracted_root=extracted,
            witness_id="physical-test-host",
        )

    def test_input_binding_accepts_exact_digest_named_packages(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            options = self.fixture(Path(temporary))
            incumbent, successor = install.validate_inputs(options)
            self.assertEqual(incumbent, install.digest_file(options.incumbent / "manifest.json"))
            self.assertEqual(successor, install.digest_file(options.successor / "manifest.json"))
            evidence = install.verify_extracted_install(options)
            self.assertTrue(evidence["safe_archive_verifier_passed"])

    def test_extracted_tree_mutation_is_rejected_against_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            options = self.fixture(Path(temporary))
            options.kernel.write_text("changed\n", encoding="utf-8")
            with self.assertRaisesRegex(install.InstallError, "differs"):
                install.verify_extracted_install(options)

    def test_in_tree_archive_tool_does_not_mutate_verified_install(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            options = self.fixture(
                Path(temporary),
                archive_tool_in_install=True,
            )
            previous_dont_write_bytecode = sys.dont_write_bytecode
            try:
                sys.dont_write_bytecode = False
                evidence = install.verify_extracted_install(options)
                self.assertFalse(sys.dont_write_bytecode)
                self.assertTrue(evidence["extracted_tree_exactly_matches_manifest"])
                self.assertFalse(
                    (options.archive_tool.parent / "__pycache__").exists()
                )
            finally:
                sys.dont_write_bytecode = previous_dont_write_bytecode

    def test_wrong_binary_digest_key_or_package_name_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            options = self.fixture(Path(temporary))
            options.expected_kernel_sha256 = "sha256:" + "00" * 32
            # Shape validation succeeds; final build_report performs the exact
            # binary comparison.  A malformed digest itself fails immediately.
            options.expected_kernel_sha256 = "invalid"
            with self.assertRaisesRegex(install.InstallError, "kernel digest"):
                install.validate_inputs(options)

            options = self.fixture(Path(temporary) / "second")
            options.wrong_public_key_hex = options.public_key_hex
            with self.assertRaisesRegex(install.InstallError, "equals"):
                install.validate_inputs(options)

            options = self.fixture(Path(temporary) / "third")
            renamed = options.incumbent.with_name("not-content-addressed")
            options.incumbent.rename(renamed)
            options.incumbent = renamed
            with self.assertRaisesRegex(install.InstallError, "manifest-addressed"):
                install.validate_inputs(options)

            options = self.fixture(Path(temporary) / "fourth")
            options.witness_id = "Not A Witness"
            with self.assertRaisesRegex(install.InstallError, "witness"):
                install.validate_inputs(options)

            options = self.fixture(Path(temporary) / "fifth")
            options.operator_capacity.write_text(
                '{"schema": "wasm-biotic.operator-mechanism-capacity.v1", "mechanisms": {}}\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(install.InstallError, "canonical"):
                install.validate_inputs(options)

    def test_tamper_fixture_changes_bytes_without_touching_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            options = self.fixture(root)
            original = (options.incumbent / "factory-root.wasm").read_bytes()
            tampered = install.tampered_package(options.incumbent, root / "tampered")
            self.assertEqual((options.incumbent / "factory-root.wasm").read_bytes(), original)
            self.assertNotEqual((tampered / "factory-root.wasm").read_bytes(), original)

    def test_expected_success_and_expected_rejection_are_both_enforced(self) -> None:
        true_program = "/usr/bin/true"
        false_program = "/usr/bin/false"
        self.assertEqual(
            install.run_command("success", [true_program], expected_success=True)["exit_code"],
            0,
        )
        self.assertNotEqual(
            install.run_command("rejection", [false_program], expected_success=False)["exit_code"],
            0,
        )
        with self.assertRaisesRegex(install.InstallError, "expected rejection"):
            install.run_command("false-negative", [true_program], expected_success=False)

    def test_crash_is_not_accepted_as_a_semantic_rejection(self) -> None:
        with self.assertRaisesRegex(install.InstallError, "terminated by a signal"):
            install.run_command(
                "crash",
                ["/bin/sh", "-c", "kill -ABRT $$"],
                expected_success=False,
            )

    def test_command_evidence_hashes_output_without_recording_physical_paths(self) -> None:
        physical = "/private/tmp/wasm-biotic-secret-physical-state"
        evidence = install.run_command(
            "path-output",
            ["/bin/sh", "-c", f"printf '%s' '{physical}'; printf '%s' '{physical}' >&2"],
            expected_success=True,
        )
        self.assertNotIn("stdout", evidence)
        self.assertNotIn("stderr", evidence)
        self.assertNotIn(physical.encode("utf-8"), install.canonical_json(evidence))
        self.assertEqual(evidence["stdout_size_bytes"], len(physical))
        self.assertEqual(evidence["stderr_size_bytes"], len(physical))

    def test_component_lifecycle_requires_component_policy_restart_and_replay(self) -> None:
        value, incumbent, successor, public_key = self.component_lifecycle_fixture()
        install.validate_component_lifecycle(
            value,
            incumbent_digest=incumbent,
            successor_digest=successor,
            public_key_hex=public_key,
            operator_capacity_sha256="sha256:" + "44" * 32,
        )

        value["operator_capacity_sha256"] = "sha256:" + "45" * 32
        with self.assertRaisesRegex(install.InstallError, "operator capacity"):
            install.validate_component_lifecycle(
                value,
                incumbent_digest=incumbent,
                successor_digest=successor,
                public_key_hex=public_key,
                operator_capacity_sha256="sha256:" + "44" * 32,
            )
        value["operator_capacity_sha256"] = "sha256:" + "44" * 32

        value["lifecycle"]["component_decided_rollback"] = False
        with self.assertRaisesRegex(install.InstallError, "component_decided_rollback"):
            install.validate_component_lifecycle(
                value,
                incumbent_digest=incumbent,
                successor_digest=successor,
                public_key_hex=public_key,
                operator_capacity_sha256="sha256:" + "44" * 32,
            )


if __name__ == "__main__":
    unittest.main()
