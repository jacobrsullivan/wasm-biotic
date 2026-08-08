#!/usr/bin/env python3
"""Determinism and closed-coverage tests for r4-sbom.py."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


TOOL = Path(__file__).with_name("r4-sbom.py")
SPEC = importlib.util.spec_from_file_location("r4_sbom", TOOL)
assert SPEC and SPEC.loader
sbom_tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sbom_tool)

SYSTEM_PACKAGES = [
    "aarch64-apple-darwin|libSystem|macOS-26.5.2",
    "x86_64-unknown-linux-gnu|glibc|2.39",
]


class SbomTests(unittest.TestCase):
    def fixture(self, root: Path) -> tuple[Path, Path]:
        repository = root / "source"
        (repository / "kernel" / "src").mkdir(parents=True)
        (repository / "components" / "example" / "src").mkdir(parents=True)
        (repository / "wit" / "wasm-biotic").mkdir(parents=True)
        (repository / "tools").mkdir(parents=True)
        (repository / "contracts" / "component-complete").mkdir(parents=True)
        (repository / "vendor" / "serde-1.0.1" / "src").mkdir(parents=True)
        (repository / "Cargo.toml").write_text(
            '[package]\nname = "wasm-biotic-root"\nversion = "0.1.0"\n',
            encoding="utf-8",
        )
        (repository / "Cargo.lock").write_text(
            '''version = 4

[[package]]
name = "serde"
version = "1.0.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
''',
            encoding="utf-8",
        )
        (repository / "README.md").write_text("# Fixture\n", encoding="utf-8")
        for name in sbom_tool.FROZEN_EMBEDDED_BUILD_INPUTS:
            path = repository / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"fixture: {name}\n", encoding="utf-8")
        (repository / "kernel" / "Cargo.toml").write_text(
            '[package]\nname = "kernel"\nversion = "0.2.0"\n', encoding="utf-8"
        )
        (repository / "kernel" / "Cargo.lock").write_text("version = 4\n", encoding="utf-8")
        (repository / "kernel" / "src" / "lib.rs").write_text("pub fn run() {}\n", encoding="utf-8")
        (repository / "components" / "example" / "Cargo.toml").write_text(
            '[package]\nname = "component"\nversion = "0.3.0"\n', encoding="utf-8"
        )
        (repository / "components" / "example" / "src" / "lib.rs").write_text(
            "#[no_mangle] pub fn component() {}\n", encoding="utf-8"
        )
        (repository / "wit" / "wasm-biotic" / "worlds.wit").write_text(
            "package wasm-biotic:factory@0.1.0;\n", encoding="utf-8"
        )
        (repository / "tools" / "build.py").write_text("print('build')\n", encoding="utf-8")
        (repository / "contracts" / "component-complete" / "CONFORMANCE.md").write_text(
            "# Contract\n", encoding="utf-8"
        )
        (repository / "vendor" / "serde-1.0.1" / "src" / "lib.rs").write_text(
            "pub fn vendored_serde() {}\n", encoding="utf-8"
        )
        artifact = root / "factory-root.wasm"
        artifact.write_bytes(b"\x00asm-component")
        return repository, artifact

    def test_document_and_coverage_are_deterministic_and_exact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, artifact = self.fixture(Path(temporary))
            arguments = (
                repository,
                [("factory-root", artifact)],
                SYSTEM_PACKAGES,
                123,
            )
            first, first_coverage = sbom_tool.build_documents(*arguments)
            second, second_coverage = sbom_tool.build_documents(*arguments)
            self.assertEqual(sbom_tool.canonical_json(first), sbom_tool.canonical_json(second))
            self.assertEqual(first_coverage, second_coverage)
            self.assertEqual(first["spdxVersion"], "SPDX-2.3")
            self.assertEqual(first_coverage["cargo_lock_count"], 2)
            self.assertEqual(first_coverage["cargo_manifest_count"], 3)
            self.assertEqual(first_coverage["artifact_roles"][0]["file_count"], 1)
            self.assertEqual(
                {item["target"] for item in first_coverage["system_packages"]},
                sbom_tool.RELEASE_TARGETS,
            )
            self.assertEqual(
                first_coverage["sbom_sha256"],
                sbom_tool.digest_bytes(sbom_tool.canonical_json(first)),
            )
            file_names = {item["fileName"] for item in first["files"]}
            for name in sbom_tool.FROZEN_EMBEDDED_BUILD_INPUTS:
                self.assertIn(f"./source/{name}", file_names)

    def test_required_compile_time_inputs_cannot_be_omitted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, artifact = self.fixture(Path(temporary))
            (repository / "README.md").unlink()
            with self.assertRaisesRegex(sbom_tool.SbomError, "required root build input is absent"):
                sbom_tool.build_documents(repository, [("factory-root", artifact)], SYSTEM_PACKAGES, 0)

        with tempfile.TemporaryDirectory() as temporary:
            repository, artifact = self.fixture(Path(temporary))
            (repository / sbom_tool.FROZEN_EMBEDDED_BUILD_INPUTS[0]).unlink()
            with self.assertRaisesRegex(sbom_tool.SbomError, "required embedded build input is absent"):
                sbom_tool.build_documents(repository, [("factory-root", artifact)], SYSTEM_PACKAGES, 0)

    def test_operator_key_shaped_source_is_forbidden_outside_vendor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, artifact = self.fixture(Path(temporary))
            (repository / "tools" / "operator.pem").write_text(
                "not custody material\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(sbom_tool.SbomError, "private-key-shaped"):
                sbom_tool.build_documents(repository, [("factory-root", artifact)], SYSTEM_PACKAGES, 0)

    def test_system_python_imports_the_vendored_toml_fallback(self) -> None:
        system_python = Path("/usr/bin/python3")
        if not system_python.is_file():
            self.skipTest("system Python is unavailable")
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        result = subprocess.run(
            [str(system_python), str(TOOL), "--help"],
            check=True,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertIn("deterministic SPDX", result.stdout)

    def test_changed_source_or_artifact_changes_the_bound_document(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, artifact = self.fixture(Path(temporary))
            baseline, _ = sbom_tool.build_documents(repository, [("factory-root", artifact)], SYSTEM_PACKAGES, 0)
            (repository / "kernel" / "src" / "lib.rs").write_text("pub fn changed() {}\n", encoding="utf-8")
            source_changed, _ = sbom_tool.build_documents(repository, [("factory-root", artifact)], SYSTEM_PACKAGES, 0)
            self.assertNotEqual(sbom_tool.canonical_json(baseline), sbom_tool.canonical_json(source_changed))
            artifact.write_bytes(b"\x00asm-mutated")
            artifact_changed, _ = sbom_tool.build_documents(repository, [("factory-root", artifact)], SYSTEM_PACKAGES, 0)
            self.assertNotEqual(sbom_tool.canonical_json(source_changed), sbom_tool.canonical_json(artifact_changed))

    def test_vendored_source_mutation_changes_the_bound_document(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, artifact = self.fixture(Path(temporary))
            baseline, _ = sbom_tool.build_documents(repository, [("factory-root", artifact)], SYSTEM_PACKAGES, 0)
            (repository / "vendor" / "serde-1.0.1" / "src" / "lib.rs").write_text(
                "pub fn changed_vendor() {}\n", encoding="utf-8"
            )
            changed, _ = sbom_tool.build_documents(repository, [("factory-root", artifact)], SYSTEM_PACKAGES, 0)
            self.assertNotEqual(sbom_tool.canonical_json(baseline), sbom_tool.canonical_json(changed))

    def test_omitted_and_phantom_files_do_not_verify_as_the_same_sbom(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, artifact = self.fixture(Path(temporary))
            document, coverage = sbom_tool.build_documents(repository, [("factory-root", artifact)], SYSTEM_PACKAGES, 0)
            with self.assertRaisesRegex(sbom_tool.SbomError, "artifact role inventory"):
                sbom_tool.build_documents(repository, [], SYSTEM_PACKAGES, 0)

            phantom = json.loads(sbom_tool.canonical_json(document))
            phantom["files"].append(
                {
                    "SPDXID": "SPDXRef-File-phantom",
                    "checksums": [{"algorithm": "SHA256", "checksumValue": "0" * 64}],
                    "copyrightText": "NOASSERTION",
                    "fileName": "./phantom",
                    "fileTypes": ["BINARY"],
                    "licenseConcluded": "NOASSERTION",
                }
            )
            self.assertNotEqual(sbom_tool.canonical_json(document), sbom_tool.canonical_json(phantom))
            self.assertEqual(coverage["result"], "pass")

    def test_duplicate_roles_and_bad_system_package_shapes_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository, artifact = self.fixture(Path(temporary))
            parsed = sbom_tool.parse_artifacts(
                [f"native-executable-x86_64-unknown-linux-gnu={artifact}"]
            )
            self.assertEqual(
                parsed[0][0], "native-executable-x86_64-unknown-linux-gnu"
            )
            with self.assertRaisesRegex(sbom_tool.SbomError, "duplicate artifact role"):
                sbom_tool.parse_artifacts([f"root={artifact}", f"root={artifact}"])
            with self.assertRaisesRegex(sbom_tool.SbomError, "TARGET\\|NAME\\|VERSION"):
                sbom_tool.build_documents(repository, [("factory-root", artifact)], ["missing-fields"], 0)
            with self.assertRaisesRegex(sbom_tool.SbomError, "closed R4 target set"):
                sbom_tool.build_documents(
                    repository,
                    [("factory-root", artifact)],
                    ["aarch64-apple-darwin|libSystem|macOS-26.5.2"],
                    0,
                )


if __name__ == "__main__":
    unittest.main()
