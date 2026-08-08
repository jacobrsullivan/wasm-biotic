from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("native-build-attestation.py")
SPEC = importlib.util.spec_from_file_location("native_build_attestation", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class NativeBuildAttestationTests(unittest.TestCase):
    def test_inventory_must_be_embedded_exactly_once(self) -> None:
        inventory = b'{"schema":"test"}'
        binding = MODULE.inventory_binding(b"prefix" + inventory + b"suffix", inventory)
        self.assertEqual(binding["occurrences"], 1)
        self.assertEqual(binding["offset_bytes"], 6)
        with self.assertRaisesRegex(MODULE.AttestationError, "observed 0"):
            MODULE.inventory_binding(b"unrelated", inventory)
        with self.assertRaisesRegex(MODULE.AttestationError, "observed 2"):
            MODULE.inventory_binding(inventory + inventory, inventory)

    def test_generated_inventory_format_matches_the_kernel_generator(self) -> None:
        value = {"schema": "test", "nested": {"enabled": True}}
        self.assertEqual(
            MODULE.generated_inventory_json(value),
            b'{\n  "schema": "test",\n  "nested": {\n    "enabled": true\n  }\n}\n',
        )

    def test_source_closure_is_bytewise_and_input_sensitive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "kernel/src").mkdir(parents=True)
            (root / "wit/wasm-biotic").mkdir(parents=True)
            (root / "kernel/Cargo.toml").write_text("[package]\n", encoding="utf-8")
            (root / "kernel/Cargo.lock").write_text("# lock\n", encoding="utf-8")
            (root / "kernel/src/lib.rs").write_text("pub fn one() {}\n", encoding="utf-8")
            (root / "wit/wasm-biotic/worlds.wit").write_text("package test:x;\n", encoding="utf-8")
            first, files = MODULE.source_closure(root)
            self.assertEqual(
                [item["path"] for item in files],
                [
                    "kernel/Cargo.lock",
                    "kernel/Cargo.toml",
                    "kernel/src/lib.rs",
                    "wit/wasm-biotic/worlds.wit",
                ],
            )
            (root / "kernel/src/lib.rs").write_text("pub fn two() {}\n", encoding="utf-8")
            second, _ = MODULE.source_closure(root)
            self.assertNotEqual(first, second)

    def test_verification_values_are_json_and_unique(self) -> None:
        self.assertEqual(
            MODULE.parse_checks(["tests=\"51 passed\"", "clippy=true"]),
            {"tests": "51 passed", "clippy": True},
        )
        with self.assertRaisesRegex(MODULE.AttestationError, "duplicate"):
            MODULE.parse_checks(["tests=true", "tests=false"])

    def test_target_directory_state_is_explicit_and_defaults_to_fresh(self) -> None:
        parser = MODULE.parser()
        required = [
            "--binary",
            "/tmp/kernel",
            "--cargo-target-dir",
            "/tmp/target",
            "--target",
            "aarch64-apple-darwin",
            "--build-command",
            "cargo build",
            "--scope",
            "fixture",
            "--out",
            "/tmp/report.json",
        ]
        self.assertEqual(parser.parse_args(required).target_directory_state, "fresh")
        self.assertEqual(
            parser.parse_args([*required, "--target-directory-state", "reused"])
            .target_directory_state,
            "reused",
        )


if __name__ == "__main__":
    unittest.main()
