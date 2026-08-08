#!/usr/bin/env python3
"""Focused tests for release-level and retained R0 negative campaigns."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("release-negative-matrix.py")
R0_SCRIPT = Path(__file__).with_name("r0-release-negative-matrix.py")
MODULE_SPEC = importlib.util.spec_from_file_location("release_negative_matrix", SCRIPT)
assert MODULE_SPEC is not None and MODULE_SPEC.loader is not None
MATRIX = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(MATRIX)


class ReleaseNegativeMatrixTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.public_key_hex = "ab" * 32
        staging = self.root / "staging-release"
        (staging / "claim").mkdir(parents=True)
        (staging / "objects").mkdir()
        (staging / "trees" / "incumbent" / "files").mkdir(parents=True)

        release_bytes = MATRIX.canonical_json(
            {
                "schema": "wasm-biotic.component-complete-release-root.v1",
                "claim": "claim/manifest.json",
            }
        )
        claim_bytes = MATRIX.canonical_json(
            {
                "schema": "wasm-biotic.component-complete-claim-manifest.v1",
                "component_complete_claim": True,
                "gates": {"C7": "pass"},
                "open_release_blockers": [],
                "objects": [
                    {"role": "native-executable", "path": "objects/native"}
                ],
                "trees": [
                    {
                        "role": "incumbent-package",
                        "path": "trees/incumbent",
                    }
                ],
            }
        )
        signature_bytes = MATRIX.canonical_json(
            {
                "schema": "wasm-biotic.component-complete-claim-signature.v1",
                "signature": "fixture",
            }
        )
        (staging / "release.json").write_bytes(release_bytes)
        (staging / "claim" / "manifest.json").write_bytes(claim_bytes)
        (staging / "claim" / "signature.json").write_bytes(signature_bytes)
        (staging / "objects" / "native").write_bytes(b"native\n")
        (staging / "trees" / "incumbent" / "files" / "manifest.json").write_bytes(
            b"retained package manifest\n"
        )

        release_digest = MATRIX.sha256_bytes(release_bytes)
        self.release = self.root / release_digest.replace("sha256:", "sha256-")
        staging.rename(self.release)
        self.before = MATRIX.closure_snapshot(self.release)
        self.verifier = self.root / "fixture-verifier.py"
        self._write_exact_fixture_verifier()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_exact_fixture_verifier(self) -> None:
        expected_files = {}
        for path in sorted(self.release.rglob("*")):
            if path.is_file() and not path.is_symlink():
                relative = path.relative_to(self.release).as_posix()
                expected_files[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
        source = f"""#!/usr/bin/env python3
import hashlib
from pathlib import Path
import sys

EXPECTED_KEY = {self.public_key_hex!r}
EXPECTED_NAME = {self.release.name!r}
EXPECTED_FILES = {expected_files!r}

def main():
    if len(sys.argv) != 5 or sys.argv[1] != "verify" or sys.argv[3] != "--expected-public-key-hex":
        return 2
    root = Path(sys.argv[2])
    if sys.argv[4] != EXPECTED_KEY or root.name != EXPECTED_NAME or not root.is_dir() or root.is_symlink():
        return 1
    actual = {{}}
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or (not path.is_file() and not path.is_dir()):
            return 1
        if path.is_file():
            actual[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return 0 if actual == EXPECTED_FILES else 1

raise SystemExit(main())
"""
        self.verifier.write_text(source, encoding="utf-8")

    def run_campaign(
        self, script: Path, *extra: str
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [
                sys.executable,
                str(script),
                "--bundle",
                str(self.release),
                "--public-key-hex",
                self.public_key_hex,
                "--verifier",
                str(self.verifier),
                *extra,
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_generic_campaign_rejects_all_eleven_and_preserves_original(self) -> None:
        result = self.run_campaign(
            SCRIPT, "--campaign-label", "r1-component-complete"
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
        report = json.loads(result.stdout)
        self.assertEqual(report["schema"], MATRIX.SCHEMA)
        self.assertEqual(
            report["campaign"],
            {"label": "r1-component-complete", "level": "release"},
        )
        self.assertEqual(report["summary"], {
            "controls": 11,
            "failed": 0,
            "gate_result": "pass",
            "passed": 11,
        })
        self.assertEqual(len(report["negative_controls"]), 11)
        self.assertTrue(
            all(item["result"] == "pass" for item in report["negative_controls"])
        )
        self.assertTrue(report["pristine"]["unchanged"])
        self.assertEqual(report["pristine"]["before"], report["pristine"]["after"])
        self.assertEqual(self.before, MATRIX.closure_snapshot(self.release))

    def test_historical_r0_command_remains_compatible(self) -> None:
        result = self.run_campaign(R0_SCRIPT)
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
        report = json.loads(result.stdout)
        self.assertEqual(report["schema"], "wasm-biotic.r0-release-negative-matrix.v1")
        self.assertNotIn("campaign", report)
        self.assertEqual(report["summary"]["controls"], 11)
        self.assertEqual(report["summary"]["passed"], 11)
        self.assertEqual(self.before, MATRIX.closure_snapshot(self.release))

    def test_output_inside_pristine_bundle_is_rejected_before_writing(self) -> None:
        result = self.run_campaign(
            SCRIPT,
            "--campaign-label",
            "safe-output",
            "--out",
            str(self.release / "forbidden-report.json"),
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"must not be written inside", result.stderr)
        self.assertFalse((self.release / "forbidden-report.json").exists())
        self.assertEqual(self.before, MATRIX.closure_snapshot(self.release))

    def test_invalid_campaign_label_fails_without_touching_release(self) -> None:
        result = self.run_campaign(SCRIPT, "--campaign-label", "bad label")
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"campaign label", result.stderr)
        self.assertEqual(self.before, MATRIX.closure_snapshot(self.release))

    def test_r2_campaign_adds_principal_specific_controls(self) -> None:
        controls = MATRIX.controls(
            self.public_key_hex,
            "wasm-biotic.component-complete-claim-manifest.v2",
        )
        names = [name for name, _mutation, _key in controls]
        self.assertEqual(len(names), 13)
        self.assertIn("missing-principal-isolation-object", names)
        self.assertIn("unsigned-principal-inventory-substitution", names)

    def test_r3_campaign_retains_r2_and_adds_transport_controls(self) -> None:
        controls = MATRIX.controls(
            self.public_key_hex,
            "wasm-biotic.component-complete-claim-manifest.v3",
        )
        names = [name for name, _mutation, _key in controls]
        self.assertEqual(len(names), MATRIX.CONTROL_COUNT_V3)
        self.assertIn("missing-principal-isolation-object", names)
        self.assertIn("missing-transport-confinement-object", names)
        self.assertIn("unsigned-http-constraint-substitution", names)
        self.assertIn("retained-http-constraint-byte-mutation", names)
        self.assertIn("transport-confinement-byte-mutation", names)

    def test_r3_campaign_executes_all_seventeen_controls(self) -> None:
        claim_path = self.release / "claim/manifest.json"
        claim = json.loads(claim_path.read_bytes())
        claim["schema"] = "wasm-biotic.component-complete-claim-manifest.v3"
        http_digest = MATRIX.sha256_bytes(b"r3-http-constraint")
        claim["identities"] = {
            "incumbent_principal_inventory_digest": MATRIX.sha256_bytes(
                b"r3-principals"
            ),
            "incumbent_http_transport_constraint_digest": http_digest,
        }
        claim["objects"].extend(
            [
                {
                    "role": "principal-isolation",
                    "path": "objects/principal-isolation",
                },
                {
                    "role": "transport-confinement",
                    "path": "objects/transport-confinement",
                },
            ]
        )
        claim_path.write_bytes(MATRIX.canonical_json(claim))
        (self.release / "objects/principal-isolation").write_bytes(b"principal\n")
        (self.release / "objects/transport-confinement").write_bytes(
            MATRIX.canonical_json(
                {"schema": "wasm-biotic.transport-confinement.v1"}
            )
        )
        constraint_path = (
            self.release
            / "trees/incumbent/files/constraints"
            / f"{http_digest.replace(':', '-')}.json"
        )
        constraint_path.parent.mkdir()
        constraint_path.write_bytes(
            MATRIX.canonical_json(
                {"schema": "wasm-biotic.http-transport-constraints.v1"}
            )
        )
        self._write_exact_fixture_verifier()

        result = self.run_campaign(
            SCRIPT, "--campaign-label", "r3-bounded-external-transport"
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8"))
        report = json.loads(result.stdout)
        self.assertEqual(report["summary"]["controls"], MATRIX.CONTROL_COUNT_V3)
        self.assertEqual(report["summary"]["passed"], MATRIX.CONTROL_COUNT_V3)
        self.assertEqual(report["summary"]["failed"], 0)

    def test_schema_mutation_handles_v2_without_length_change(self) -> None:
        path = self.root / "v2.json"
        original = MATRIX.canonical_json(
            {"schema": "wasm-biotic.component-complete-claim-manifest.v2"}
        )
        path.write_bytes(original)
        MATRIX.mutate_schema_byte(
            path, b"wasm-biotic.component-complete-claim-manifest"
        )
        mutated = path.read_bytes()
        self.assertEqual(len(mutated), len(original))
        self.assertEqual(
            sum(left != right for left, right in zip(original, mutated)), 1
        )


if __name__ == "__main__":
    unittest.main()
