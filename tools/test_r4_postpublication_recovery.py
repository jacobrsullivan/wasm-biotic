#!/usr/bin/env python3
"""Closed-shape tests for external post-publication recovery evidence."""

from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
import unittest


TOOL = Path(__file__).with_name("r4-postpublication-recovery.py")
SPEC = importlib.util.spec_from_file_location("r4_postpublication_recovery", TOOL)
assert SPEC is not None and SPEC.loader is not None
RECOVERY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RECOVERY)


class R4PostPublicationRecoveryTests(unittest.TestCase):
    def lifecycle(self) -> dict[str, object]:
        return {
            "host": {
                "physical_machine": True,
                "target": "aarch64-apple-darwin",
                "witness_id": "physical-recovery-1",
            },
            "outcome": "pass",
            "operator_capacity": {
                "observed_sha256": "sha256:" + "33" * 32,
                "within_verified_install": True,
            },
            "private_key_argument_supported": False,
            "private_key_required_or_read": False,
            "schema": RECOVERY.LIFECYCLE_SCHEMA,
        }

    def test_wrapper_binds_final_root_policy_and_fresh_lifecycle(self) -> None:
        lifecycle = self.lifecycle()
        data = RECOVERY.canonical_json(lifecycle)
        report = RECOVERY.build_wrapper(
            publication_root="sha256:" + "11" * 32,
            policy_digest="sha256:" + "22" * 32,
            lifecycle=lifecycle,
            lifecycle_bytes=data,
            targets=list(RECOVERY.CLOSED_TARGETS),
        )
        self.assertEqual(report["schema"], RECOVERY.SCHEMA)
        self.assertTrue(report["publication"]["verified_before_recovery"])
        self.assertEqual(
            report["lifecycle"]["report_sha256"], RECOVERY.digest_bytes(data)
        )
        self.assertFalse(report["private_key_dependency"])

    def test_nonphysical_or_wrong_target_lifecycle_fails(self) -> None:
        lifecycle = self.lifecycle()
        lifecycle["host"]["physical_machine"] = False
        with self.assertRaisesRegex(RECOVERY.RecoveryError, "physical witness"):
            RECOVERY.build_wrapper(
                publication_root="sha256:" + "11" * 32,
                policy_digest="sha256:" + "22" * 32,
                lifecycle=lifecycle,
                lifecycle_bytes=RECOVERY.canonical_json(lifecycle),
                targets=list(RECOVERY.CLOSED_TARGETS),
            )

    def test_install_layout_is_closed_and_rejects_traversal(self) -> None:
        layout = {
            "archive_tool": "tools/r4-install-archive.py",
            "incumbent": "packages/incumbent",
            "leaf_public_key": "public/r3-certifier-public-key.raw",
            "operator_capacity": "config/operator-capacity.json",
            "public_install_tool": "tools/r4-public-install.py",
            "schema": RECOVERY.LAYOUT_SCHEMA,
            "successor": "packages/successor",
            "targets": {
                target: {
                    "kernel": f"targets/{target}/wasm-biotic-kernel",
                    "lifecycle_runner": f"targets/{target}/public-key-lifecycle",
                }
                for target in RECOVERY.CLOSED_TARGETS
            },
            "trust_policy": "governance/trust-policy.json",
        }
        self.assertIs(RECOVERY.validate_layout(layout), layout)
        missing = copy.deepcopy(layout)
        missing.pop("operator_capacity")
        with self.assertRaisesRegex(RECOVERY.RecoveryError, "fields"):
            RECOVERY.validate_layout(missing)
        extra = copy.deepcopy(layout)
        extra["unexpected"] = "extra"
        with self.assertRaisesRegex(RECOVERY.RecoveryError, "fields"):
            RECOVERY.validate_layout(extra)
        layout["operator_capacity"] = "../escape.json"
        with self.assertRaisesRegex(RECOVERY.RecoveryError, "unsafe"):
            RECOVERY.validate_layout(layout)

    def test_wrong_key_control_is_distinct_and_well_formed(self) -> None:
        correct = "03" * 32
        wrong = RECOVERY.wrong_public_key(correct)
        self.assertNotEqual(correct, wrong)
        self.assertRegex(wrong, r"[0-9a-f]{64}")


if __name__ == "__main__":
    unittest.main()
