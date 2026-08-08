#!/usr/bin/env python3
"""End-to-end tests for production R4 pre-publication negative evidence."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


TOOL = Path(__file__).with_name("r4-prepublication-negatives.py")
SPEC = importlib.util.spec_from_file_location("r4_prepublication_negatives", TOOL)
assert SPEC is not None and SPEC.loader is not None
NEGATIVES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NEGATIVES)


class R4PrepublicationNegativeTests(unittest.TestCase):
    """Real public inputs are mutated and the report must reproduce exactly."""

    @classmethod
    def setUpClass(cls) -> None:
        if shutil.which("openssl") is None:
            raise unittest.SkipTest("openssl is unavailable")
        cls.temporary = tempfile.TemporaryDirectory(
            prefix="r4-prepublication-negative-test-"
        )
        cls.root = Path(cls.temporary.name)
        cls.build_fixture()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    @classmethod
    def write(cls, relative: str, data: bytes, *, executable: bool = False) -> Path:
        path = cls.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(0o755 if executable else 0o644)
        return path

    @classmethod
    def build_package(cls, root: Path, label: str, wasm: bytes) -> Path:
        temporary = root / f"temporary-{label}"
        temporary.mkdir(parents=True)
        manifest = NEGATIVES.canonical_json({"graph": label, "schema": "fixture.v1"})
        (temporary / "manifest.json").write_bytes(manifest)
        (temporary / "factory-root.wasm").write_bytes(wasm)
        digest = NEGATIVES.digest_bytes(manifest)
        destination = root / digest.replace(":", "-", 1)
        temporary.rename(destination)
        return destination

    @classmethod
    def build_fixture(cls) -> None:
        source = cls.root / "source"
        cls.write(
            "source/Cargo.toml",
            b'[package]\nname="negative-fixture"\nversion="0.1.0"\n',
        )
        cls.write(
            "source/Cargo.lock",
            b'version = 4\n\n[[package]]\nname = "negative-fixture"\nversion = "0.1.0"\n',
        )
        cls.write("source/README.md", b"# Negative fixture\n")
        for relative in NEGATIVES.SBOM.FROZEN_EMBEDDED_BUILD_INPUTS:
            cls.write(f"source/{relative}", f"fixture: {relative}\n".encode("utf-8"))
        cls.write("source/components/lib.rs", b"pub fn component() {}\n")
        cls.write("source/kernel/lib.rs", b"pub fn kernel() {}\n")
        cls.write("source/tools/release.py", b"print('release')\n")
        cls.write("source/vendor/example-1.0.0/src/lib.rs", b"pub fn vendor() {}\n")
        cls.write(
            "source/wit/wasm-biotic/factory.wit",
            b"package wasm-biotic:factory;\n",
        )
        cls.source_archive = cls.root / "source.tar"
        NEGATIVES.ARCHIVE.write_archive(source, cls.source_archive, 0)

        component_tree = cls.root / "component-release"
        cls.write(
            "component-release/release.json",
            NEGATIVES.canonical_json(
                {"schema": "wasm-biotic.component-complete-release-root.v1"}
            ),
        )
        cls.component_archive = cls.root / "component-release.tar"
        NEGATIVES.ARCHIVE.write_archive(component_tree, cls.component_archive, 0)

        install = cls.root / "install"
        packages = install / "packages"
        cls.incumbent = cls.build_package(packages, "incumbent", b"\x00asm-incumbent")
        cls.successor = cls.build_package(packages, "successor", b"\x00asm-successor")
        cls.trusted_key = "33" * 32
        cls.wrong_key = "44" * 32
        incumbent_digest = NEGATIVES.digest_file(cls.incumbent / "manifest.json")
        successor_digest = NEGATIVES.digest_file(cls.successor / "manifest.json")
        kernel_source = f'''#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path
import sys

TRUSTED = {cls.trusted_key!r}
EXPECTED = {{
    {incumbent_digest!r}: {NEGATIVES.digest_file(cls.incumbent / "factory-root.wasm")!r},
    {successor_digest!r}: {NEGATIVES.digest_file(cls.successor / "factory-root.wasm")!r},
}}

def digest(path):
    return "sha256:" + hashlib.sha256(Path(path).read_bytes()).hexdigest()

command = sys.argv[1]
if command == "init":
    if len(sys.argv) != 6 or not Path(sys.argv[5]).is_file():
        raise SystemExit(2)
    capacity = json.loads(Path(sys.argv[5]).read_text())
    if capacity.get("schema") != "wasm-biotic.operator-mechanism-capacity.v1":
        raise SystemExit(2)
    state = Path(sys.argv[2])
    state.mkdir(parents=True)
    value = {{"active": sys.argv[3], "admitted": [], "key": sys.argv[4]}}
    (state / "mechanisms.json").write_text(json.dumps(value, separators=(",", ":"), sort_keys=True))
    raise SystemExit(0)
package = Path(sys.argv[2])
state = Path(sys.argv[3])
value = json.loads((state / "mechanisms.json").read_text())
manifest = digest(package / "manifest.json")
if command == "admit":
    if value["key"] != TRUSTED or manifest not in EXPECTED:
        raise SystemExit(1)
    if digest(package / "factory-root.wasm") != EXPECTED[manifest]:
        raise SystemExit(1)
    if manifest not in value["admitted"]:
        value["admitted"].append(manifest)
    (state / "mechanisms.json").write_text(json.dumps(value, separators=(",", ":"), sort_keys=True))
    raise SystemExit(0)
if command == "serve":
    raise SystemExit(0 if manifest == value["active"] else 1)
raise SystemExit(2)
'''.encode("utf-8")
        cls.kernel = cls.write("install/bin/kernel", kernel_source, executable=True)
        cls.operator_capacity = cls.write(
            "install/config/operator-capacity.json",
            NEGATIVES.canonical_json(
                {
                    "mechanisms": {
                        "allowed_namespaces": [],
                        "max_blob_bytes": 1,
                        "max_component_fuel": 1,
                        "max_component_memory_bytes": 1,
                        "max_component_output_bytes": 1,
                        "max_component_wall_time_ms": 1,
                        "max_http_timeout_ms": 1,
                        "max_random_bytes": 1,
                        "max_total_blob_bytes": 1,
                        "max_wake_delay_ms": 1,
                    },
                    "schema": "wasm-biotic.operator-mechanism-capacity.v1",
                }
            ),
        )
        cls.install_archive = cls.root / "install.tar"
        NEGATIVES.ARCHIVE.write_archive(install, cls.install_archive, 0)

        cls.keys = []
        for index in range(5):
            key = cls.root / f"private-{index}.der"
            subprocess.run(
                [
                    "openssl",
                    "genpkey",
                    "-algorithm",
                    "ED25519",
                    "-outform",
                    "DER",
                    "-out",
                    str(key),
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            cls.keys.append(key)
        cls.ceremony = cls.root / "governance"
        NEGATIVES.CEREMONY.run_ceremony(
            cls.keys[:3],
            cls.keys[3:],
            {
                "closure_sha256": "sha256:" + "11" * 32,
                "schema": "wasm-biotic.r4-governance-release-test.v1",
            },
            {
                "closure_sha256": "sha256:" + "22" * 32,
                "schema": "wasm-biotic.r4-governance-publication-test.v1",
            },
            cls.ceremony,
        )
        for key in cls.keys:
            key.unlink()

        cls.artifacts = {
            "component-release-archive": cls.component_archive,
            "install-archive": cls.install_archive,
            "native-executable-aarch64-apple-darwin": cls.kernel,
            "native-executable-x86_64-unknown-linux-gnu": cls.kernel,
            "source-archive": cls.source_archive,
        }
        cls.system_packages = [
            "aarch64-apple-darwin|libSystem|1",
            "x86_64-unknown-linux-gnu|glibc|2",
        ]
        sbom, coverage = NEGATIVES.SBOM.build_documents(
            source,
            sorted(cls.artifacts.items()),
            cls.system_packages,
            0,
        )
        cls.sbom = cls.write("spdx.json", NEGATIVES.canonical_json(sbom))
        cls.coverage = cls.write(
            "sbom-coverage.json", NEGATIVES.canonical_json(coverage)
        )
        cls.spec_value = {
            "archives": {
                "component-release-archive": str(cls.component_archive),
                "install-archive": str(cls.install_archive),
                "source-archive": str(cls.source_archive),
            },
            "governance_ceremony": str(cls.ceremony),
            "lifecycle": {
                "expected_kernel_sha256": NEGATIVES.digest_file(cls.kernel),
                "extracted_root": str(install),
                "incumbent": str(cls.incumbent),
                "kernel": str(cls.kernel),
                "operator_capacity": str(cls.operator_capacity),
                "public_key_hex": cls.trusted_key,
                "successor": str(cls.successor),
                "target": "aarch64-apple-darwin",
                "wrong_public_key_hex": cls.wrong_key,
            },
            "sbom": {
                "artifacts": {
                    role: str(path) for role, path in cls.artifacts.items()
                },
                "coverage": str(cls.coverage),
                "spdx": str(cls.sbom),
                "system_packages": cls.system_packages,
            },
            "schema": NEGATIVES.INPUT_SCHEMA,
        }
        cls.spec = cls.write(
            "negative-spec.json", NEGATIVES.canonical_json(cls.spec_value)
        )

    def test_all_controls_execute_and_public_verify_reproduces(self) -> None:
        report = NEGATIVES.build_report(self.spec)
        inventories = (
            ("archives", NEGATIVES.ARCHIVE_CONTROLS),
            ("governance", NEGATIVES.GOVERNANCE_CONTROLS),
            ("public_lifecycle", NEGATIVES.LIFECYCLE_CONTROLS),
            ("sbom", NEGATIVES.SBOM_CONTROLS),
        )
        for category, names in inventories:
            self.assertEqual(set(report[category]), set(names))
            self.assertTrue(
                all(item["result"] == "pass" for item in report[category].values())
            )
            self.assertTrue(
                all("attack_sha256" in item for item in report[category].values())
            )
        self.assertFalse(report["private_key_dependency"])
        self.assertEqual(report["blockers"], [])
        output = self.root / "prepublication-negatives.json"
        self.assertEqual(
            NEGATIVES.main(
                ["run", "--spec", str(self.spec), "--out", str(output)]
            ),
            0,
        )
        self.assertEqual(
            NEGATIVES.main(
                ["verify", "--spec", str(self.spec), "--report", str(output)]
            ),
            0,
        )
        self.assertEqual(output.read_bytes(), NEGATIVES.canonical_json(report))

    def test_hand_authored_true_maps_cannot_verify(self) -> None:
        forged = {
            "archives": {name: True for name in NEGATIVES.ARCHIVE_CONTROLS},
            "blockers": [],
            "governance": {name: True for name in NEGATIVES.GOVERNANCE_CONTROLS},
            "private_key_dependency": False,
            "public_lifecycle": {
                name: True for name in NEGATIVES.LIFECYCLE_CONTROLS
            },
            "result": "pass",
            "sbom": {name: True for name in NEGATIVES.SBOM_CONTROLS},
            "schema": NEGATIVES.REPORT_SCHEMA,
        }
        path = self.root / "forged-negative-report.json"
        path.write_bytes(NEGATIVES.canonical_json(forged))
        with self.assertRaisesRegex(
            NEGATIVES.NegativeControlError, "does not reproduce"
        ):
            NEGATIVES.verify_report(self.spec, path)

    def test_changed_public_input_invalidates_reproduction(self) -> None:
        changed = json.loads(json.dumps(self.spec_value))
        changed["lifecycle"]["expected_kernel_sha256"] = "sha256:" + "00" * 32
        path = self.root / "changed-negative-spec.json"
        path.write_bytes(NEGATIVES.canonical_json(changed))
        with self.assertRaisesRegex(NEGATIVES.NegativeControlError, "kernel digest"):
            NEGATIVES.build_report(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
