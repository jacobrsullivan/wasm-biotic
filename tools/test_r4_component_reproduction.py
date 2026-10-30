#!/usr/bin/env python3
"""Unit and adversarial tests for R4 component reproduction."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


TOOL = Path(__file__).with_name("r4-component-reproduction.py")
SPEC = importlib.util.spec_from_file_location("r4_component_reproduction", TOOL)
assert SPEC and SPEC.loader
repro = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(repro)

PRIVATE_SEED = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc4"
    "4449c5697b326919703bac031cae7f60"
)
PRIVATE_DER_PREFIX = bytes.fromhex("302e020100300506032b657004220420")
PUBLIC_KEY_HEX = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"


NODES = (
    "admitted-tool-probe",
    "build-service",
    "builder-worker",
    "capability-router",
    "closure-evaluator",
    "continuity-service",
    "continuity-worker",
    "exchange-service",
    "factory-control",
    "factory-evolution",
    "operations-service",
    "packager-worker",
    "packaging-service",
    "planner-worker",
    "review-service",
    "reviewer-worker",
    "scheduling-service",
    "state-migration",
    "supervisor-reducer",
    "validation-service",
    "validator-worker",
    "worker-router",
)


class ComponentReproductionTests(unittest.TestCase):
    def sign(self, payload: bytes, root: Path) -> bytes:
        private = root / "fixture-private.der"
        message = root / "fixture-payload.bin"
        signature = root / "fixture-signature.bin"
        private.write_bytes(PRIVATE_DER_PREFIX + PRIVATE_SEED)
        message.write_bytes(payload)
        subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-inkey",
                str(private),
                "-keyform",
                "DER",
                "-rawin",
                "-in",
                str(message),
                "-out",
                str(signature),
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return signature.read_bytes()

    def package_fixture(self, root: Path) -> tuple[Path, dict[str, str]]:
        manifest = b'{"fixture":"manifest"}'
        graph = repro.digest_bytes(manifest)
        package = root / graph.replace(":", "-")
        (package / "evidence").mkdir(parents=True)
        (package / "components").mkdir()
        (package / "certification").mkdir()
        expected: dict[str, str] = {}
        for node in NODES:
            data = f"component:{node}".encode("utf-8")
            digest = repro.digest_bytes(data)
            expected[node] = digest
            (package / "components" / f"sha256-{digest[7:]}.wasm").write_bytes(data)
        (package / "manifest.json").write_bytes(manifest)
        composition = {
            "graph_manifest_digest": graph,
            "package_schema": "wasm-biotic.component-graph-package.v1",
            "raw_nodes": expected,
            "validated": True,
        }
        (package / "evidence" / "composition.json").write_bytes(repro.canonical_json(composition))
        key_id = repro.digest_bytes(bytes.fromhex(PUBLIC_KEY_HEX))
        statement = {
            "graph_manifest_digest": graph,
            "raw_artifacts": expected,
            "schema": repro.CERTIFICATE_STATEMENT_SCHEMA,
        }
        payload = repro.canonical_json(
            {
                "certifier_key_id": key_id,
                "schema": repro.PACKAGE_SIGNING_PAYLOAD_SCHEMA,
                "statement": statement,
            }
        )
        certificate = {
            "certifier_key_id": key_id,
            "schema": repro.CERTIFICATE_SCHEMA,
            "signature": {
                "algorithm": "ed25519",
                "signature_hex": self.sign(payload, root).hex(),
            },
            "statement": statement,
        }
        certificate_bytes = repro.canonical_json(certificate)
        (package / "certification" / "release-certification.json").write_bytes(certificate_bytes)
        (package / "package.json").write_bytes(
            repro.canonical_json(
                {
                    "certification_digest": repro.digest_bytes(certificate_bytes),
                    "graph_manifest_digest": graph,
                    "package_schema": repro.PACKAGE_SCHEMA,
                }
            )
        )
        return package, expected

    def compiled_fixture(self, root: Path, expected: dict[str, str]) -> Path:
        target = root / "target"
        for node in NODES:
            path = repro.compiled_path(target, node)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(f"component:{node}".encode("utf-8"))
        return target

    def test_exact_22_component_set_matches(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package, expected = self.package_fixture(root)
            parsed, graph, authentication = repro.expected_components(package, PUBLIC_KEY_HEX)
            self.assertEqual(parsed, expected)
            self.assertEqual(graph, repro.digest_file(package / "manifest.json"))
            self.assertTrue(authentication["signature_verified"])
            results = repro.compare_components(expected, self.compiled_fixture(root, expected))
            self.assertEqual(len(results), 22)
            self.assertEqual(
                repro.component_set_digest(results),
                repro.component_set_digest(results.copy()),
            )

    def test_missing_extra_or_mutated_component_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package, expected = self.package_fixture(root)
            composition_path = package / "evidence" / "composition.json"
            composition, _ = repro.read_json(composition_path, "composition")
            composition["raw_nodes"].pop("worker-router")
            composition_path.write_bytes(repro.canonical_json(composition))
            with self.assertRaisesRegex(repro.ReproductionError, "exactly 22"):
                repro.expected_components(package, PUBLIC_KEY_HEX)

            package, expected = self.package_fixture(root / "second")
            target = self.compiled_fixture(root / "second", expected)
            repro.compiled_path(target, "factory-control").write_bytes(b"mutated")
            with self.assertRaisesRegex(repro.ReproductionError, "compiled component differs"):
                repro.compare_components(expected, target)

    def test_same_size_node_substitution_fails_the_frozen_set(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            package, _ = self.package_fixture(Path(temporary))
            composition_path = package / "evidence" / "composition.json"
            composition, _ = repro.read_json(composition_path, "composition")
            digest = composition["raw_nodes"].pop("worker-router")
            composition["raw_nodes"]["substitute-node"] = digest
            composition_path.write_bytes(repro.canonical_json(composition))
            with self.assertRaisesRegex(repro.ReproductionError, "frozen R4 node set"):
                repro.expected_components(package, PUBLIC_KEY_HEX)

    def test_component_directory_closure_rejects_directories_and_links(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package, _ = self.package_fixture(root / "directory-case")
            (package / "components" / "unsigned-extra").mkdir()
            with self.assertRaisesRegex(repro.ReproductionError, "non-regular entry"):
                repro.expected_components(package, PUBLIC_KEY_HEX)

            package, _ = self.package_fixture(root / "link-case")
            outside = root / "outside.wasm"
            outside.write_bytes(b"unsigned")
            (package / "components" / "unsigned-extra.wasm").symlink_to(outside)
            with self.assertRaisesRegex(repro.ReproductionError, "non-regular entry"):
                repro.expected_components(package, PUBLIC_KEY_HEX)

    def test_wrong_key_stale_signature_and_unsigned_composition_change_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package, _ = self.package_fixture(root)
            with self.assertRaisesRegex(repro.ReproductionError, "supplied public key"):
                repro.expected_components(package, "00" * 32)

            certificate_path = package / "certification" / "release-certification.json"
            certificate, _ = repro.read_json(certificate_path, "certificate")
            certificate["statement"]["validator_identity"] = "mutated-after-signing"
            certificate_path.write_bytes(repro.canonical_json(certificate))
            with self.assertRaisesRegex(repro.ReproductionError, "signature verification failed"):
                repro.expected_components(package, PUBLIC_KEY_HEX)

            package, _ = self.package_fixture(root / "second")
            composition_path = package / "evidence" / "composition.json"
            composition, _ = repro.read_json(composition_path, "composition")
            first = composition["raw_nodes"]["build-service"]
            composition["raw_nodes"]["build-service"] = composition["raw_nodes"]["review-service"]
            composition["raw_nodes"]["review-service"] = first
            composition_path.write_bytes(repro.canonical_json(composition))
            with self.assertRaisesRegex(repro.ReproductionError, "signed statement raw artifacts"):
                repro.expected_components(package, PUBLIC_KEY_HEX)

    def test_group_and_artifact_mapping_cover_frozen_nodes(self) -> None:
        self.assertEqual(repro.build_group("builder-worker"), "workers")
        self.assertEqual(repro.build_group("worker-router"), "components")
        self.assertEqual(repro.build_group("supervisor-reducer"), "supervisor")
        self.assertEqual(
            repro.artifact_name("factory-control"),
            "wasm_biotic_factory_control.wasm",
        )
        groups = {name: sum(repro.build_group(node) == name for node in NODES) for name in ("components", "workers", "supervisor")}
        self.assertEqual(groups, {"components": 15, "workers": 6, "supervisor": 1})

    def test_frozen_environment_and_sandbox_deny_ambient_mutation(self) -> None:
        environment = repro.frozen_environment()
        self.assertEqual(environment["CARGO_HOME"], repro.FROZEN_CARGO_HOME)
        self.assertEqual(environment["RUSTUP_HOME"], repro.FROZEN_RUSTUP_HOME)
        self.assertEqual(environment["CARGO_NET_OFFLINE"], "true")
        for name in (
            "RUSTFLAGS",
            "CARGO_ENCODED_RUSTFLAGS",
            "DYLD_INSERT_LIBRARIES",
            "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER",
            "WASM_BIOTIC_R4_ALIAS_LIBRARY",
            "WASM_BIOTIC_R4_ALIAS_TRACE",
            "WASM_BIOTIC_R4_PHYSICAL_ROOT",
        ):
            self.assertNotIn(name, environment)
        profile = repro.sandbox_profile(Path("/authenticated/snapshot"))
        self.assertIn("(deny network*)", profile)
        self.assertIn("(deny file-read*", profile)
        self.assertIn("/authenticated/snapshot", profile)
        self.assertIn(repro.FROZEN_SOURCE_ROOT, profile)
        self.assertIn(repro.FROZEN_CARGO_HOME, profile)
        self.assertIn(repro.FROZEN_RUSTUP_HOME, profile)
        self.assertNotIn("remap-path", profile)

    def test_public_operator_alias_compiles_and_is_fully_attested(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile = repro.sandbox_profile(root / "authenticated-source")
            if shutil.which("xcrun") is None:
                with self.assertRaisesRegex(repro.ReproductionError, "xcrun is required"):
                    repro.compile_operator_alias(
                        root / "operator",
                        root / "authenticated-source",
                        profile,
                    )
                return
            dylib, launcher, information = repro.compile_operator_alias(
                root / "operator",
                root / "authenticated-source",
                profile,
            )
            self.assertTrue(dylib.is_file())
            self.assertTrue(launcher.is_file())
            self.assertEqual(information["schema"], repro.PATH_ALIAS_SCHEMA)
            self.assertEqual(information["sandbox_profile"], profile)
            self.assertEqual(
                information["sandbox_profile_sha256"],
                repro.digest_bytes(profile.encode("utf-8")),
            )
            self.assertEqual(information["artifacts"]["dylib"]["sha256"], repro.digest_file(dylib))
            self.assertEqual(information["artifacts"]["launcher"]["sha256"], repro.digest_file(launcher))
            self.assertEqual(
                set(information["sources"]),
                {"tools/r4-path-alias.c", "tools/r4-path-alias-launch.c"},
            )

    def test_cli_has_public_key_and_no_private_key_or_source_identity_fallback(self) -> None:
        destinations = {action.dest for action in repro.parser()._actions}
        self.assertIn("public_key_hex", destinations)
        self.assertNotIn("private_key", destinations)
        self.assertNotIn("source_identity", destinations)
        self.assertNotIn("builder_image", destinations)

    def test_public_tool_imports_on_system_python_with_vendored_tomli_fallback(self) -> None:
        python = Path("/usr/bin/python3")
        if not python.is_file():
            self.skipTest("system Python is unavailable")
        program = """
import importlib.util
import pathlib
import sys
spec = importlib.util.spec_from_file_location("r4_component_reproduction", pathlib.Path(sys.argv[1]))
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
print(module.tomllib.__name__)
"""
        result = subprocess.run(
            [str(python), "-I", "-c", program, str(TOOL)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        name = result.stdout.strip()
        self.assertIn(name, {"tomli", "tomllib"})
        version = subprocess.run(
            [str(python), "--version"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ).stdout.strip()
        if version.startswith(("Python 3.9.", "Python 3.10.")):
            self.assertEqual(name, "tomli")

    def test_source_identity_cannot_fall_back_when_snapshot_is_absent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(repro.ReproductionError, "source snapshot verification failed"):
                repro.verify_source_snapshot(Path(temporary))

    def test_physical_witness_identifier_is_strict(self) -> None:
        self.assertIsNotNone(repro.WITNESS_RE.fullmatch("bobs-mini-r4-local-01"))
        for value in ("", "Bobs-mini", "../witness", "witness id", "-witness"):
            self.assertIsNone(repro.WITNESS_RE.fullmatch(value))


if __name__ == "__main__":
    unittest.main()
