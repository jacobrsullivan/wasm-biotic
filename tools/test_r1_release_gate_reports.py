#!/usr/bin/env python3
"""Focused compatibility tests for the R1/R2/R3 gate-report command inventory."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("r1-release-gate-reports.py")
MODULE_SPEC = importlib.util.spec_from_file_location("r1_release_gate_reports", SCRIPT)
assert MODULE_SPEC is not None and MODULE_SPEC.loader is not None
GATES = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(GATES)


class GateReportCommandTests(unittest.TestCase):
    def test_r1_and_r2_command_inventories_remain_stable(self) -> None:
        self.assertEqual(len(GATES.command_specs("R1")), 8)
        self.assertEqual(len(GATES.command_specs("R2")), 12)
        self.assertEqual(
            [item[0] for item in GATES.command_specs("R2")[-4:]],
            [
                "component-graph-r2-principal-contract",
                "component-graph-package-r2-least-authority",
                "kernel-r2-principal-linking-and-trace",
                "independent-substrate-r2-principal-isolation",
            ],
        )

    def test_r3_retains_r2_and_adds_exact_http_commands(self) -> None:
        r2 = GATES.command_specs("R2")
        r3 = GATES.command_specs("R3")
        self.assertEqual(r3[: len(r2)], r2)
        expected = {
            "component-graph-r3-http-contract": 3,
            "component-graph-package-r3-http-contract": 2,
            "kernel-r3-http-production": 4,
            "independent-r3-http-confinement": 9,
            "independent-r3-http-wit-boundary": 2,
            "independent-r3-package-admission": 2,
            "compiled-exchange-r3-http-adapter": 6,
        }
        self.assertEqual({item[0]: item[2] for item in r3[len(r2) :]}, expected)
        self.assertTrue(
            all("--offline" in item[1] for item in r3[len(r2) :])
        )

    def test_each_cargo_workspace_has_a_deterministic_isolated_target(self) -> None:
        repository = Path("/tmp/repository")
        environment = {"CARGO_TARGET_DIR": "/tmp/caller-target"}
        expected = {
            None: "root",
            "Cargo.toml": "root",
            "components/Cargo.toml": "components",
            "kernel/Cargo.toml": "kernel",
            "tools/component-graph-package/Cargo.toml": "component-graph-package",
            "tools/independent-substrate/Cargo.toml": "independent-substrate",
        }
        for manifest, partition in expected.items():
            with self.subTest(manifest=manifest):
                command = ["cargo", "test"]
                if manifest is not None:
                    command.extend(["--manifest-path", manifest])
                self.assertEqual(
                    GATES.isolated_cargo_target_dir(
                        command, repository, environment
                    ),
                    Path("/tmp/caller-target").resolve() / partition,
                )

    def test_relative_target_base_is_resolved_from_repository(self) -> None:
        repository = Path("/tmp/repository")
        target = GATES.isolated_cargo_target_dir(
            ["cargo", "test", "--manifest-path=components/Cargo.toml"],
            repository,
            {"CARGO_TARGET_DIR": "build/gate"},
        )
        self.assertEqual(
            target, repository.resolve() / "build/gate/components"
        )

    def test_manifest_resolution_rejects_unsafe_or_ambiguous_commands(self) -> None:
        invalid_commands = [
            ["cargo", "test", "--manifest-path"],
            ["cargo", "test", "--manifest-path="],
            ["cargo", "test", "--manifest-path", "/tmp/Cargo.toml"],
            ["cargo", "test", "--manifest-path", "../Cargo.toml"],
            ["cargo", "test", "--manifest-path", "./components/Cargo.toml"],
            ["cargo", "test", "--manifest-path", "tools/unknown/Cargo.toml"],
            [
                "cargo",
                "test",
                "--manifest-path",
                "components/Cargo.toml",
                "--manifest-path=kernel/Cargo.toml",
            ],
            ["cargo", "test", "--target-dir", "/tmp/shared"],
            ["not-cargo", "test"],
        ]
        for command in invalid_commands:
            with self.subTest(command=command):
                with self.assertRaises(GATES.GateError):
                    GATES.cargo_workspace_partition(command)

    def test_unsafe_target_bases_are_rejected(self) -> None:
        repository = Path("/tmp/repository").resolve()
        for raw_base in ["", str(repository), str(Path(repository.anchor))]:
            with self.subTest(raw_base=raw_base):
                with self.assertRaises(GATES.GateError):
                    GATES.isolated_cargo_target_dir(
                        ["cargo", "test"],
                        repository,
                        {"CARGO_TARGET_DIR": raw_base},
                    )

    def test_run_test_passes_only_the_partitioned_target_to_subprocess(self) -> None:
        output = (
            b"test isolated_workspace ... ok\n"
            b"test result: ok. 1 passed; 0 failed; 0 ignored; "
            b"0 measured; 0 filtered out\n"
        )
        completed = mock.Mock(returncode=0, stdout=output, stderr=b"")
        base_environment = {"CARGO_TARGET_DIR": "/tmp/caller-target"}
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            transcript_dir = repository / "transcripts"
            transcript_dir.mkdir()
            with mock.patch.object(GATES.subprocess, "run", return_value=completed) as run:
                GATES.run_test(
                    "components-case",
                    Path("/toolchain/cargo"),
                    [
                        "cargo",
                        "test",
                        "--manifest-path",
                        "components/Cargo.toml",
                    ],
                    1,
                    "R3",
                    repository,
                    transcript_dir,
                    base_environment,
                )
            subprocess_environment = run.call_args.kwargs["env"]
            self.assertEqual(
                subprocess_environment["CARGO_TARGET_DIR"],
                str(Path("/tmp/caller-target").resolve() / "components"),
            )
            self.assertEqual(
                base_environment["CARGO_TARGET_DIR"], "/tmp/caller-target"
            )


if __name__ == "__main__":
    unittest.main()
