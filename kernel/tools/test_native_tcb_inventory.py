#!/usr/bin/env python3
"""Tests for the deterministic native TCB inventory generator."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


TOOLS_ROOT = Path(__file__).resolve().parent
KERNEL_ROOT = TOOLS_ROOT.parent
REPO_ROOT = KERNEL_ROOT.parent
GENERATOR = TOOLS_ROOT / "native_tcb_inventory.py"


class NativeTcbInventoryGeneratorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="wasm-biotic-tcb-test-")
        self.repo = Path(self.temporary.name)
        self._copy_file(KERNEL_ROOT / "native-tcb.json")
        self._copy_file(KERNEL_ROOT / "Cargo.toml")
        self._copy_file(KERNEL_ROOT / "Cargo.lock")
        self._copy_file(KERNEL_ROOT / "operator-config.example.json")
        self._copy_file(KERNEL_ROOT / "operator-config.http.example.json")
        for path in sorted((KERNEL_ROOT / "src").rglob("*.rs")):
            self._copy_file(path)
        for path in sorted((KERNEL_ROOT / "fixtures" / "artifacts").glob("*.wasm")):
            self._copy_file(path)
        for path in sorted((REPO_ROOT / "wit" / "wasm-biotic").glob("*.wit")):
            self._copy_file(path)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _copy_file(self, source: Path) -> None:
        relative = source.relative_to(REPO_ROOT)
        destination = self.repo / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)

    def _run(self, *arguments: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(GENERATOR),
                "--repo-root",
                str(self.repo),
                *arguments,
            ],
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
        )

    def test_write_is_deterministic_and_check_is_cwd_independent(self) -> None:
        first = self._run("--write", cwd=self.repo / "kernel")
        self.assertEqual(first.returncode, 0, first.stderr)
        inventory_path = self.repo / "kernel" / "native-tcb.json"
        generated_once = inventory_path.read_bytes()

        second = self._run("--write", cwd=self.repo / "wit" / "wasm-biotic")
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(inventory_path.read_bytes(), generated_once)

        checked = self._run("--check", cwd=Path(tempfile.gettempdir()))
        self.assertEqual(checked.returncode, 0, checked.stderr)
        inventory = json.loads(generated_once)
        module_paths = [row["path"] for row in inventory["reachable_native_modules"]]
        fixture_paths = [row["path"] for row in inventory["fixture_artifacts"]]
        self.assertEqual(module_paths, sorted(module_paths, key=lambda value: value.encode()))
        self.assertEqual(fixture_paths, sorted(fixture_paths, key=lambda value: value.encode()))

    def test_default_check_detects_stale_input_without_mutating_inventory(self) -> None:
        written = self._run("--write")
        self.assertEqual(written.returncode, 0, written.stderr)
        inventory_path = self.repo / "kernel" / "native-tcb.json"
        current_inventory = inventory_path.read_bytes()

        lock_path = self.repo / "kernel" / "Cargo.lock"
        lock_path.write_bytes(lock_path.read_bytes() + b"\n# stale-test\n")
        checked = self._run()
        self.assertEqual(checked.returncode, 1)
        self.assertIn("inventory is stale", checked.stderr)
        self.assertIn("dependency_lock", checked.stderr)
        self.assertEqual(inventory_path.read_bytes(), current_inventory)

    def test_duplicate_inventory_keys_fail_closed(self) -> None:
        inventory_path = self.repo / "kernel" / "native-tcb.json"
        inventory_path.write_text('{"schema":"one","schema":"two"}\n', encoding="utf-8")
        checked = self._run("--check")
        self.assertEqual(checked.returncode, 2)
        self.assertIn("duplicate JSON key: schema", checked.stderr)


if __name__ == "__main__":
    unittest.main()
