#!/usr/bin/env python3
"""Closed-source and vendoring tests for r4-source-snapshot.py."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import tempfile
import unittest


TOOL = Path(__file__).with_name("r4-source-snapshot.py")
SPEC = importlib.util.spec_from_file_location("r4_source_snapshot", TOOL)
assert SPEC and SPEC.loader
snapshot_tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(snapshot_tool)


class SourceSnapshotTests(unittest.TestCase):
    def source_inventory(self, snapshot: Path) -> list[dict]:
        items = []
        for path in sorted(
            snapshot.rglob("*"),
            key=lambda item: item.relative_to(snapshot).as_posix().encode("utf-8"),
        ):
            relative = path.relative_to(snapshot).as_posix()
            if (
                not path.is_file()
                or relative == "SOURCE-SNAPSHOT.json"
                or relative == ".cargo/config.toml"
                or relative.startswith("vendor/")
            ):
                continue
            mode = snapshot_tool.normalized_mode(path)
            items.append(
                {
                    "mode": f"{mode:04o}",
                    "path": relative,
                    "sha256": snapshot_tool.digest_file(path),
                    "size_bytes": path.stat().st_size,
                }
            )
        return items

    def repository_fixture(self, root: Path) -> Path:
        repository = root / "repository"
        for name in snapshot_tool.SOURCE_ROOTS:
            (repository / name).mkdir(parents=True)
        (repository / "Cargo.toml").write_text(
            '[package]\nname = "fixture"\nversion = "0.1.0"\n', encoding="utf-8"
        )
        (repository / "Cargo.lock").write_text("version = 4\n", encoding="utf-8")
        (repository / ".env.example").write_text("TOKEN=replace-me\n", encoding="utf-8")
        (repository / ".gitignore").write_text(".env\n", encoding="utf-8")
        (repository / "AGENTS.md").write_text("# Agents\n", encoding="utf-8")
        (repository / "README.md").write_text("# Source\n", encoding="utf-8")
        for name in snapshot_tool.FROZEN_EMBEDDED_BUILD_INPUTS:
            embedded = repository / name
            embedded.parent.mkdir(parents=True, exist_ok=True)
            embedded.write_text(f"fixture: {name}\n", encoding="utf-8")
        (repository / "kernel" / "src").mkdir()
        executable = repository / "kernel" / "src" / "kernel.rs"
        executable.write_text("pub fn kernel() {}\n", encoding="utf-8")
        executable.chmod(0o751)
        (repository / "components" / "factory.rs").write_text("pub fn factory() {}\n", encoding="utf-8")
        (repository / "wit" / "world.wit").write_text("package fixture:world;\n", encoding="utf-8")
        (repository / "tools" / "release.py").write_text("print('release')\n", encoding="utf-8")
        return repository

    def prepared_fixture(self, root: Path) -> tuple[Path, dict, list, list]:
        repository = self.repository_fixture(root)
        snapshot = root / "snapshot"
        snapshot.mkdir()
        source = snapshot_tool.copy_source(repository, snapshot)
        vendor_file = snapshot / "vendor" / "serde-1.0.0" / "src" / "lib.rs"
        vendor_file.parent.mkdir(parents=True)
        vendor_file.write_text("pub fn serde() {}\n", encoding="utf-8")
        vendor_file.chmod(0o644)
        config = snapshot / ".cargo" / "config.toml"
        config.parent.mkdir()
        config.write_bytes(snapshot_tool.CONFIG_BYTES)
        vendor = [
            {
                "mode": "0644",
                "path": vendor_file.relative_to(snapshot).as_posix(),
                "sha256": snapshot_tool.digest_file(vendor_file),
                "size_bytes": vendor_file.stat().st_size,
            }
        ]
        manifest = snapshot_tool.snapshot_manifest(
            source,
            vendor,
            {"cargo": ["cargo 1.97.1"], "rustc": ["rustc 1.97.1"], "wasm_target": "wasm32-wasip2"},
        )
        (snapshot / "SOURCE-SNAPSHOT.json").write_bytes(snapshot_tool.canonical_json(manifest))
        return snapshot, manifest, source, vendor

    def test_snapshot_verifies_exact_source_vendor_and_modes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            snapshot, manifest, _, _ = self.prepared_fixture(Path(temporary))
            digest, verified = snapshot_tool.verify_snapshot(snapshot)
            self.assertEqual(verified, manifest)
            self.assertEqual(digest, snapshot_tool.digest_file(snapshot / "SOURCE-SNAPSHOT.json"))
            self.assertEqual((snapshot / "kernel" / "src" / "kernel.rs").stat().st_mode & 0o777, 0o755)
            self.assertEqual(manifest["cargo_lock_count"], 1)
            self.assertEqual(manifest["cargo_manifest_count"], 1)

    def test_source_vendor_and_config_mutations_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            snapshot, _, _, _ = self.prepared_fixture(root)
            (snapshot / "components" / "factory.rs").write_text("changed\n", encoding="utf-8")
            with self.assertRaisesRegex(snapshot_tool.SnapshotError, "source closure"):
                snapshot_tool.verify_snapshot(snapshot)

            snapshot, _, _, _ = self.prepared_fixture(root / "second")
            (snapshot / "vendor" / "serde-1.0.0" / "src" / "lib.rs").write_text("changed\n", encoding="utf-8")
            with self.assertRaisesRegex(snapshot_tool.SnapshotError, "vendor closure"):
                snapshot_tool.verify_snapshot(snapshot)

            snapshot, _, _, _ = self.prepared_fixture(root / "third")
            (snapshot / ".cargo" / "config.toml").write_text("[net]\noffline=false\n", encoding="utf-8")
            with self.assertRaisesRegex(snapshot_tool.SnapshotError, "offline Cargo"):
                snapshot_tool.verify_snapshot(snapshot)

    def test_cargo_inventory_cannot_be_erased_from_an_unchanged_source_closure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            snapshot, manifest, _, _ = self.prepared_fixture(Path(temporary))
            manifest["cargo_locks"] = []
            manifest["cargo_lock_count"] = 0
            manifest["cargo_manifests"] = []
            manifest["cargo_manifest_count"] = 0
            (snapshot / "SOURCE-SNAPSHOT.json").write_bytes(snapshot_tool.canonical_json(manifest))
            with self.assertRaisesRegex(snapshot_tool.SnapshotError, "Cargo lock inventory"):
                snapshot_tool.verify_snapshot(snapshot)

    def test_secret_file_and_source_link_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository_fixture(Path(temporary))
            (repository / "kernel" / ".env").write_text("SECRET=value\n", encoding="utf-8")
            with self.assertRaisesRegex(snapshot_tool.SnapshotError, "secret-bearing"):
                snapshot_tool.selected_source_files(repository)
            (repository / "kernel" / ".env").unlink()
            (repository / "kernel" / "link").symlink_to("src/kernel.rs")
            with self.assertRaisesRegex(snapshot_tool.SnapshotError, "source links"):
                snapshot_tool.selected_source_files(repository)

    def test_operator_key_shaped_file_outside_vendor_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = self.repository_fixture(Path(temporary))
            (repository / "tools" / "release-private.pem").write_text(
                "public test text is still forbidden at this path\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(snapshot_tool.SnapshotError, "private-key-shaped"):
                snapshot_tool.selected_source_files(repository)

    def test_every_embedded_build_input_is_required(self) -> None:
        for missing in snapshot_tool.FROZEN_EMBEDDED_BUILD_INPUTS:
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as temporary:
                repository = self.repository_fixture(Path(temporary))
                (repository / missing).unlink()
                with self.assertRaisesRegex(snapshot_tool.SnapshotError, "required embedded build input is absent"):
                    snapshot_tool.selected_source_files(repository)

    def test_every_root_build_input_is_required_by_selection_and_verification(self) -> None:
        for missing in snapshot_tool.REQUIRED_ROOT_FILES:
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                repository = self.repository_fixture(root)
                (repository / missing).unlink()
                with self.assertRaisesRegex(snapshot_tool.SnapshotError, "required root build input is absent"):
                    snapshot_tool.selected_source_files(repository)

            with self.subTest(self_consistent_snapshot=missing), tempfile.TemporaryDirectory() as temporary:
                snapshot, manifest, _, _ = self.prepared_fixture(Path(temporary))
                (snapshot / missing).unlink()
                source_items = self.source_inventory(snapshot)
                locks = [item for item in source_items if item["path"].endswith("Cargo.lock")]
                manifests = [item for item in source_items if item["path"].endswith("Cargo.toml")]
                manifest["source_closure_sha256"] = snapshot_tool.closure_digest(source_items)
                manifest["source_file_count"] = len(source_items)
                manifest["cargo_locks"] = locks
                manifest["cargo_lock_count"] = len(locks)
                manifest["cargo_manifests"] = manifests
                manifest["cargo_manifest_count"] = len(manifests)
                (snapshot / "SOURCE-SNAPSHOT.json").write_bytes(snapshot_tool.canonical_json(manifest))
                with self.assertRaisesRegex(snapshot_tool.SnapshotError, "required root build input is absent"):
                    snapshot_tool.verify_snapshot(snapshot)

    def test_source_modes_must_be_physically_normalized(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            snapshot, _, _, _ = self.prepared_fixture(Path(temporary))
            (snapshot / "README.md").chmod(0o600)
            with self.assertRaisesRegex(snapshot_tool.SnapshotError, "non-normalized mode"):
                snapshot_tool.verify_snapshot(snapshot)

    def test_only_enumerated_artifacts_and_selected_roots_are_accepted(self) -> None:
        with self.assertRaisesRegex(snapshot_tool.SnapshotError, "generated path is forbidden"):
            snapshot_tool.validate_relative("artifacts/fixtures/unlisted/component.wit")
        self.assertFalse(snapshot_tool.is_selected_source_path("unlisted.txt"))

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            snapshot, manifest, _, _ = self.prepared_fixture(root)
            extra = snapshot / "unlisted.txt"
            extra.write_text("not selected\n", encoding="utf-8")
            source_items = self.source_inventory(snapshot)
            manifest["source_closure_sha256"] = snapshot_tool.closure_digest(source_items)
            manifest["source_file_count"] = len(source_items)
            (snapshot / "SOURCE-SNAPSHOT.json").write_bytes(snapshot_tool.canonical_json(manifest))
            with self.assertRaisesRegex(snapshot_tool.SnapshotError, "unselected source path is forbidden"):
                snapshot_tool.verify_snapshot(snapshot)


if __name__ == "__main__":
    unittest.main()
