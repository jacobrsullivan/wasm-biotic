#!/usr/bin/env python3
"""Public-verification tests for the production R4 governance ceremony."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


TOOL = Path(__file__).with_name("r4-governance-ceremony.py")
SPEC = importlib.util.spec_from_file_location("r4_governance_ceremony", TOOL)
assert SPEC is not None and SPEC.loader is not None
CEREMONY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CEREMONY)


class R4GovernanceCeremonyTests(unittest.TestCase):
    def setUp(self) -> None:
        if shutil.which("openssl") is None:
            self.skipTest("openssl is unavailable")
        self.temporary = tempfile.TemporaryDirectory(prefix="r4-governance-ceremony-test-")
        self.root = Path(self.temporary.name)
        self.keys: list[Path] = []
        for index in range(5):
            path = self.root / f"private-{index}.der"
            subprocess.run(
                [
                    "openssl",
                    "genpkey",
                    "-algorithm",
                    "ED25519",
                    "-outform",
                    "DER",
                    "-out",
                    str(path),
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.keys.append(path)
        self.release = {
            "closure_sha256": "sha256:" + "11" * 32,
            "schema": "wasm-biotic.r4-governance-release-test.v1",
        }
        self.publication = {
            "closure_sha256": "sha256:" + "22" * 32,
            "schema": "wasm-biotic.r4-governance-publication-test.v1",
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_ceremony_reverifies_without_private_keys(self) -> None:
        output = self.root / "public-ceremony"
        result = CEREMONY.run_ceremony(
            self.keys[:3], self.keys[3:], self.release, self.publication, output
        )
        for key in self.keys:
            key.unlink()
        self.assertEqual(CEREMONY.verify_ceremony(output), result)
        report = CEREMONY.read_object(
            output / CEREMONY.REPORT_NAME, "governance report"
        )
        self.assertFalse(report["private_key_dependency"])
        self.assertEqual(
            report["ceremony_manifest_sha256"],
            CEREMONY.digest_file(output / CEREMONY.MANIFEST_NAME),
        )
        self.assertTrue(report["rotation_verified"])
        self.assertTrue(report["revocation_verified"])
        self.assertTrue(report["successor_proof_of_possession_verified"])

    def test_mutated_public_transition_fails_closed(self) -> None:
        output = self.root / "public-ceremony"
        CEREMONY.run_ceremony(
            self.keys[:3], self.keys[3:], self.release, self.publication, output
        )
        transition = output / "rotation-transition.json"
        transition.write_bytes(transition.read_bytes() + b"\n")
        with self.assertRaisesRegex(CEREMONY.CeremonyError, "digest differs"):
            CEREMONY.verify_ceremony(output)


if __name__ == "__main__":
    unittest.main()
