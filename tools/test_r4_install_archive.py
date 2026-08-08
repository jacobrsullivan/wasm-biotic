#!/usr/bin/env python3
"""Regression and adversarial tests for r4-install-archive.py."""

from __future__ import annotations

import importlib.util
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest


TOOL = Path(__file__).with_name("r4-install-archive.py")
SPEC = importlib.util.spec_from_file_location("r4_install_archive", TOOL)
assert SPEC and SPEC.loader
archive_tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(archive_tool)


class InstallArchiveTests(unittest.TestCase):
    def fixture(self, root: Path) -> Path:
        payload = root / "input"
        (payload / "bin").mkdir(parents=True)
        (payload / "share" / "nested").mkdir(parents=True)
        executable = payload / "bin" / "wasm-biotic-kernel"
        executable.write_bytes(b"native-bytes\x00\x01")
        executable.chmod(0o751)
        (payload / "share" / "README.md").write_text("portable\n", encoding="utf-8")
        (payload / "share" / "nested" / ".env.example").write_text(
            "TOKEN=replace-me\n", encoding="utf-8"
        )
        return payload

    def test_repeat_build_is_byte_identical_and_extracts_normalized_modes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = self.fixture(root)
            first = root / "first.tar"
            second = root / "second.tar"
            first_digest, first_manifest = archive_tool.write_archive(payload, first, 17)
            second_digest, second_manifest = archive_tool.write_archive(payload, second, 17)
            self.assertEqual(first_digest, second_digest)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(first_manifest, second_manifest)

            verified_digest, manifest, manifest_bytes = archive_tool.verify_archive(first)
            self.assertEqual(verified_digest, first_digest)
            self.assertEqual(manifest_bytes, archive_tool.canonical_json(manifest))
            self.assertEqual(manifest["source_date_epoch"], 17)

            output = root / "output"
            archive_tool.extract_archive(first, output)
            self.assertEqual(
                (output / "bin" / "wasm-biotic-kernel").read_bytes(),
                b"native-bytes\x00\x01",
            )
            self.assertEqual((output / "bin" / "wasm-biotic-kernel").stat().st_mode & 0o777, 0o755)
            self.assertEqual((output / "share" / "README.md").stat().st_mode & 0o777, 0o644)

    def test_system_python_can_build_and_verify_the_archive(self) -> None:
        system_python = Path("/usr/bin/python3")
        if not system_python.is_file():
            self.skipTest("system Python is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = self.fixture(root)
            output = root / "archives"
            environment = os.environ.copy()
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            result = subprocess.run(
                [
                    str(system_python),
                    str(TOOL),
                    "build",
                    "--input",
                    str(payload),
                    "--out-root",
                    str(output),
                    "--epoch",
                    "0",
                ],
                check=True,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            archive = next(output.glob("sha256-*.tar"))
            verified = subprocess.run(
                [str(system_python), str(TOOL), "verify", str(archive)],
                check=True,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertIn("sha256:", result.stdout)
            self.assertIn("verified sha256:", verified.stdout)

    def test_links_generated_directories_and_dot_env_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = self.fixture(root)
            (payload / "link").symlink_to("share/README.md")
            with self.assertRaisesRegex(archive_tool.ArchiveError, "links and special"):
                archive_tool.build_manifest(payload, 0)
            (payload / "link").unlink()
            (payload / ".env").write_text("SECRET=value\n", encoding="utf-8")
            with self.assertRaisesRegex(archive_tool.ArchiveError, "secret-bearing"):
                archive_tool.build_manifest(payload, 0)
            (payload / ".env").unlink()
            (payload / "target").mkdir()
            with self.assertRaisesRegex(archive_tool.ArchiveError, "generated path"):
                archive_tool.build_manifest(payload, 0)

    def test_vendored_source_target_module_is_not_a_generated_build_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = self.fixture(root)
            module = payload / "vendor/cc-1.4.0/src/target"
            module.mkdir(parents=True)
            (module / "apple.rs").write_text("pub const TARGET: &str = \"apple\";\n", encoding="utf-8")
            archive_path = root / "source.tar"
            digest, manifest = archive_tool.write_archive(payload, archive_path, 0)
            verified_digest, verified_manifest, _ = archive_tool.verify_archive(archive_path)
            self.assertEqual(verified_digest, digest)
            self.assertEqual(verified_manifest, manifest)

            for relative in (
                "kernel/target/release/binary",
                "vendor/cc-1.4.0/target/cache",
                "vendor/cc-1.4.0/src/nested/target/cache",
            ):
                with self.assertRaisesRegex(archive_tool.ArchiveError, "generated path"):
                    archive_tool.validate_relative_path(relative)

    def test_truncation_and_payload_mutation_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = self.fixture(root)
            good = root / "good.tar"
            archive_tool.write_archive(payload, good, 0)

            truncated = root / "truncated.tar"
            truncated.write_bytes(good.read_bytes()[:1024])
            with self.assertRaises(archive_tool.ArchiveError):
                archive_tool.verify_archive(truncated)

            mutated = root / "mutated.tar"
            data = bytearray(good.read_bytes())
            offset = data.find(b"native-bytes")
            self.assertGreater(offset, 0)
            data[offset] ^= 0x01
            mutated.write_bytes(data)
            with self.assertRaisesRegex(archive_tool.ArchiveError, "digest differs"):
                archive_tool.verify_archive(mutated)

    def test_bytes_appended_after_the_ustar_end_markers_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = self.fixture(root)
            archive = root / "trailing.tar"
            archive_tool.write_archive(payload, archive, 0)
            with archive.open("ab") as stream:
                stream.write(b"UNMANIFESTED-TRAILER")
            with self.assertRaisesRegex(archive_tool.ArchiveError, "trailing bytes"):
                archive_tool.verify_archive(archive)

    def test_mode_change_is_detected_even_when_file_bytes_match(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = self.fixture(root)
            good = root / "good.tar"
            archive_tool.write_archive(payload, good, 0)
            changed = root / "changed-mode.tar"
            with tarfile.open(good, "r:") as source, tarfile.open(
                changed, "w", format=tarfile.USTAR_FORMAT
            ) as target:
                for member in source.getmembers():
                    body = source.extractfile(member) if member.isfile() else None
                    clone = tarfile.TarInfo(member.name)
                    clone.mode = member.mode
                    clone.uid = member.uid
                    clone.gid = member.gid
                    clone.uname = member.uname
                    clone.gname = member.gname
                    clone.mtime = member.mtime
                    clone.type = member.type
                    clone.size = member.size
                    if member.name.endswith("wasm-biotic-kernel"):
                        clone.mode = 0o644
                    target.addfile(clone, body)
            with self.assertRaisesRegex(archive_tool.ArchiveError, "mode differs"):
                archive_tool.verify_archive(changed)

    def test_path_traversal_manifest_is_rejected_before_extraction(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            malicious = root / "traversal.tar"
            manifest = {
                "archive_format": "ustar",
                "entries": [
                    {
                        "kind": "file",
                        "mode": "0644",
                        "path": "../escape",
                        "sha256": archive_tool.digest_bytes(b"x"),
                        "size_bytes": 1,
                    }
                ],
                "entry_count": 1,
                "payload_root": "payload",
                "schema": archive_tool.SCHEMA,
                "source_date_epoch": 0,
                "total_file_size_bytes": 1,
            }
            encoded = archive_tool.canonical_json(manifest)
            with tarfile.open(malicious, "w", format=tarfile.USTAR_FORMAT) as target:
                target.addfile(
                    archive_tool.tar_info("MANIFEST.json", 0o644, len(encoded), 0, tarfile.REGTYPE),
                    io.BytesIO(encoded),
                )
                target.addfile(archive_tool.tar_info("payload", 0o755, 0, 0, tarfile.DIRTYPE))
                target.addfile(
                    archive_tool.tar_info("payload/../escape", 0o644, 1, 0, tarfile.REGTYPE),
                    io.BytesIO(b"x"),
                )
            with self.assertRaisesRegex(archive_tool.ArchiveError, "unsafe archive path"):
                archive_tool.verify_archive(malicious)


if __name__ == "__main__":
    unittest.main()
