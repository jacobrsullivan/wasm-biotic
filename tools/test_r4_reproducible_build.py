from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("r4-reproducible-build.py")
SPEC = importlib.util.spec_from_file_location("r4_reproducible_build", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class R4ReproducibleBuildTests(unittest.TestCase):
    def test_digest_normalization_is_strict(self) -> None:
        raw = "a" * 64
        self.assertEqual(MODULE.normalize_digest(raw), f"sha256:{raw}")
        self.assertEqual(MODULE.normalize_digest(f"sha256:{raw}"), f"sha256:{raw}")
        with self.assertRaisesRegex(MODULE.ReproducibilityError, "lowercase"):
            MODULE.normalize_digest("A" * 64)

    def test_report_rejects_absolute_paths_at_any_depth(self) -> None:
        MODULE.require_no_absolute_report_paths(
            {"path": "kernel/Cargo.toml", "nested": ["wasm-biotic/source"]}
        )
        with self.assertRaisesRegex(MODULE.ReproducibilityError, "absolute path"):
            MODULE.require_no_absolute_report_paths({"nested": {"path": "/tmp/build"}})
        with self.assertRaisesRegex(MODULE.ReproducibilityError, "absolute path"):
            MODULE.require_no_absolute_report_paths({"text": "built from C:\\temp\\source"})

    def test_source_and_wit_closures_are_content_sensitive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            (repository / "kernel/src").mkdir(parents=True)
            (repository / "wit/wasm-biotic").mkdir(parents=True)
            (repository / "kernel/Cargo.toml").write_text("[package]\n", encoding="utf-8")
            (repository / "kernel/Cargo.lock").write_text("# lock\n", encoding="utf-8")
            (repository / "kernel/src/lib.rs").write_text("pub fn one() {}\n", encoding="utf-8")
            wit = repository / "wit/wasm-biotic/worlds.wit"
            wit.write_text("package test:factory;\n", encoding="utf-8")
            first, files = MODULE.closure(repository, MODULE.source_paths(repository))
            self.assertEqual(
                [item["path"] for item in files],
                [
                    "kernel/Cargo.lock",
                    "kernel/Cargo.toml",
                    "kernel/src/lib.rs",
                    "wit/wasm-biotic/worlds.wit",
                ],
            )
            wit.write_text("package test:changed;\n", encoding="utf-8")
            second, _ = MODULE.closure(repository, MODULE.source_paths(repository))
            self.assertNotEqual(first, second)

    def test_remaps_cover_lexical_and_resolved_roots_with_relative_destinations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "real"
            real.mkdir()
            alias = root / "alias"
            alias.symlink_to(real, target_is_directory=True)
            flags = MODULE.remap_flags(alias, root / "target", root / "cargo", root / "sysroot")
            self.assertTrue(any(str(alias) in flag for flag in flags))
            self.assertTrue(any(str(real) in flag for flag in flags))
            for destination in MODULE.LOGICAL_PREFIXES.values():
                self.assertFalse(destination.startswith("/"))
                self.assertTrue(any(flag.endswith(f"={destination}") for flag in flags))
            self.assertEqual(flags[-1], "--remap-path-scope=object")

    def test_environment_rejects_ambient_rust_flags_and_encodes_its_own(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("target", "repository", "cargo", "sysroot"):
                (root / name).mkdir()
            recipe = {"linker_flags": ["-Wl,--build-id=sha1"], "environment": {}}
            with mock.patch.dict(
                os.environ,
                {
                    "RUSTFLAGS": "-C opt-level=0",
                    "CARGO_PROFILE_RELEASE_LTO": "true",
                    "RUSTC_WRAPPER": "/tmp/wrapper",
                },
                clear=False,
            ):
                environment, flags = MODULE.build_environment(
                    target_directory=root / "target",
                    repository=root / "repository",
                    cargo_home=root / "cargo",
                    rust_sysroot=root / "sysroot",
                    rustc="rustc",
                    recipe=recipe,
                )
            self.assertNotIn("RUSTFLAGS", environment)
            self.assertNotIn("RUSTC_WRAPPER", environment)
            self.assertNotIn("CARGO_PROFILE_RELEASE_LTO", environment)
            self.assertEqual(environment["CARGO_ENCODED_RUSTFLAGS"], "\x1f".join(flags))
            self.assertIn("-C", flags)
            self.assertIn("link-arg=-Wl,--build-id=sha1", flags)

    def test_macho_identity_policy_requires_one_uuid_and_one_signature(self) -> None:
        signature = struct.pack("<4I", MODULE.LC_CODE_SIGNATURE, 16, 48, 32)
        header = struct.pack("<8I", MODULE.MACHO_MAGIC_64, 0, 0, 2, 1, len(signature), 0, 0)
        commands = MODULE.macho_load_commands(header + signature + bytes(32))
        with self.assertRaisesRegex(MODULE.ReproducibilityError, "LC_UUID"):
            MODULE.validate_macho_identity_commands(commands)

        uuid_command = struct.pack("<2I16s", MODULE.LC_UUID, 24, bytes(16))
        signature = struct.pack("<4I", MODULE.LC_CODE_SIGNATURE, 16, 80, 32)
        header_with_uuid = struct.pack(
            "<8I", MODULE.MACHO_MAGIC_64, 0, 0, 2, 2, len(signature) + len(uuid_command), 0, 0
        )
        commands_with_uuid = MODULE.macho_load_commands(
            header_with_uuid + uuid_command + signature + bytes(8) + bytes(32)
        )
        MODULE.validate_macho_identity_commands(commands_with_uuid)

    def test_macho_canonical_material_ignores_only_uuid_and_signature_bytes(self) -> None:
        first_uuid = bytes.fromhex("00112233445566778899aabbccddeeff")
        second_uuid = bytes.fromhex("ffeeddccbbaa99887766554433221100")
        uuid_one = struct.pack("<2I16s", MODULE.LC_UUID, 24, first_uuid)
        uuid_two = struct.pack("<2I16s", MODULE.LC_UUID, 24, second_uuid)
        signature = struct.pack("<4I", MODULE.LC_CODE_SIGNATURE, 16, 80, 32)
        header = struct.pack(
            "<8I", MODULE.MACHO_MAGIC_64, 0, 0, 2, 2, len(uuid_one) + len(signature), 0, 0
        )
        one = header + uuid_one + signature + b"PAYLOAD!" + bytes([1]) * 32
        two = header + uuid_two + signature + b"PAYLOAD!" + bytes([2]) * 32
        self.assertEqual(MODULE.canonical_macho_material(one), MODULE.canonical_macho_material(two))
        changed = header + uuid_two + signature + b"CHANGED!" + bytes([2]) * 32
        self.assertNotEqual(
            MODULE.canonical_macho_material(one), MODULE.canonical_macho_material(changed)
        )

        selected = MODULE.deterministic_macho_uuid(MODULE.digest_bytes(b"canonical"))
        self.assertEqual(selected[6] >> 4, 8)
        self.assertEqual(selected[8] >> 6, 2)

    def test_full_binary_comparison_does_not_normalize_differences(self) -> None:
        MODULE.require_identical(b"complete-binary", b"complete-binary")
        with self.assertRaisesRegex(MODULE.ReproducibilityError, "byte offset 9"):
            MODULE.require_identical(b"complete-a", b"complete-b")

    def test_physical_path_scan_checks_real_and_lexical_forms(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            MODULE.require_no_physical_paths(b"wasm-biotic/source/file.rs", [root])
            with self.assertRaisesRegex(MODULE.ReproducibilityError, "physical build path"):
                MODULE.require_no_physical_paths(b"prefix" + str(root).encode() + b"suffix", [root])

    def test_platform_recipes_bind_deterministic_identity_flags(self) -> None:
        with mock.patch.object(MODULE.platform, "system", return_value="Darwin"), mock.patch.object(
            MODULE,
            "command_text",
            side_effect=["@(#)PROGRAM:ld PROJECT:ld-1", "Apple clang version 1", "15.0"],
        ):
            macos = MODULE.platform_recipe("aarch64-apple-darwin", "11.0")
        self.assertEqual(macos["linker_flags"], ["-Wl,-reproducible"])
        self.assertIn("detached SHA-256", macos["identity_policy"])

        with mock.patch.object(MODULE.platform, "system", return_value="Linux"), mock.patch.object(
            MODULE,
            "command_text",
            side_effect=["GNU ld 2.42", "cc 14"],
        ):
            linux = MODULE.platform_recipe("x86_64-unknown-linux-gnu", "unused")
        self.assertEqual(linux["linker_flags"], ["-Wl,--build-id=sha1"])

    def test_source_snapshot_identity_is_canonical_and_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            snapshot = {
                "schema": MODULE.SOURCE_SNAPSHOT_SCHEMA,
                "source_closure_sha256": "sha256:" + "11" * 32,
                "source_file_count": 1,
                "vendor_closure_sha256": "sha256:" + "22" * 32,
                "vendor_file_count": 2,
            }
            data = MODULE.canonical_json(snapshot)
            (root / "SOURCE-SNAPSHOT.json").write_bytes(data)
            identity = MODULE.source_snapshot_identity(root)
            self.assertEqual(
                identity,
                {
                    "schema": MODULE.SOURCE_SNAPSHOT_SCHEMA,
                    "sha256": MODULE.digest_bytes(data),
                },
            )
            (root / "SOURCE-SNAPSHOT.json").write_bytes(data + b"\n")
            with self.assertRaisesRegex(MODULE.ReproducibilityError, "canonical"):
                MODULE.source_snapshot_identity(root)

    def test_runtime_dependencies_drop_physical_paths(self) -> None:
        with mock.patch.object(
            MODULE,
            "command_text",
            return_value=(
                "kernel:\n"
                "\t/usr/lib/libSystem.B.dylib "
                "(compatibility version 1.0.0, current version 1356.0.0)"
            ),
        ):
            result = MODULE.runtime_dependencies("macos", Path("kernel"))
        self.assertEqual(result, [{"name": "libSystem.B.dylib", "version": "1356.0.0"}])
        MODULE.require_no_absolute_report_paths(result)

    def test_linux_runtime_dependencies_bind_package_versions(self) -> None:
        with mock.patch.object(
            MODULE,
            "command_text",
            side_effect=[
                " 0x1 (NEEDED) Shared library: [libc.so.6]\n",
                "libc.so.6 => /lib/libc.so.6 (0x1234)\n",
            ],
        ), mock.patch.object(MODULE, "linux_package_version", return_value="2.41-12"):
            result = MODULE.runtime_dependencies("linux", Path("kernel"))
        self.assertEqual(result, [{"name": "libc.so.6", "version": "2.41-12"}])

    def test_linux_runtime_dependencies_accept_direct_dynamic_loader(self) -> None:
        versions = {
            "ld-linux-x86-64.so.2": "2.41-12",
            "libc.so.6": "2.41-12",
        }
        with mock.patch.object(
            MODULE,
            "command_text",
            side_effect=[
                (
                    " 0x1 (NEEDED) Shared library: [libc.so.6]\n"
                    " 0x1 (NEEDED) Shared library: [ld-linux-x86-64.so.2]\n"
                ),
                (
                    "libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x1234)\n"
                    "/lib64/ld-linux-x86-64.so.2 (0x5678)\n"
                ),
            ],
        ), mock.patch.object(
            MODULE,
            "linux_package_version",
            side_effect=lambda path, library: versions[library],
        ):
            result = MODULE.runtime_dependencies("linux", Path("kernel"))
        self.assertEqual(
            result,
            [
                {"name": "ld-linux-x86-64.so.2", "version": "2.41-12"},
                {"name": "libc.so.6", "version": "2.41-12"},
            ],
        )

    def test_linux_package_version_ignores_usr_merge_diversion_records(self) -> None:
        direct = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=(
                "diversion by libc6 from: /lib64/ld-linux-x86-64.so.2\n"
                "diversion by libc6 to: /lib64/ld-linux-x86-64.so.2.usr-is-merged\n"
            ),
            stderr="",
        )
        resolved = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="libc6:amd64: /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2\n",
            stderr="",
        )
        with mock.patch.object(
            MODULE.os.path,
            "realpath",
            return_value="/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
        ), mock.patch.object(
            MODULE.subprocess,
            "run",
            side_effect=[direct, resolved],
        ), mock.patch.object(
            MODULE,
            "command_text",
            return_value="2.41-12",
        ) as version:
            self.assertEqual(
                MODULE.linux_package_version(
                    "/lib64/ld-linux-x86-64.so.2",
                    "ld-linux-x86-64.so.2",
                ),
                "2.41-12",
            )
        version.assert_called_once_with(
            ["dpkg-query", "-W", "-f=${Version}", "libc6:amd64"],
            "inspect installed package version for ld-linux-x86-64.so.2",
        )

    def test_linux_package_version_rejects_no_or_multiple_real_owners(self) -> None:
        no_owner = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="diversion by libc6 from: /lib64/ld-linux-x86-64.so.2\n",
            stderr="",
        )
        with mock.patch.object(MODULE.os.path, "realpath", return_value="/same"), mock.patch.object(
            MODULE.subprocess,
            "run",
            return_value=no_owner,
        ):
            with self.assertRaisesRegex(MODULE.ReproducibilityError, "one installed package owner"):
                MODULE.linux_package_version("/same", "loader")

        ambiguous = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="libc6:amd64, libc6-extra:amd64: /usr/lib/loader\n",
            stderr="",
        )
        with mock.patch.object(MODULE.os.path, "realpath", return_value="/same"), mock.patch.object(
            MODULE.subprocess,
            "run",
            return_value=ambiguous,
        ):
            with self.assertRaisesRegex(MODULE.ReproducibilityError, "one installed package owner"):
                MODULE.linux_package_version("/same", "loader")

    def test_ldd_dependency_path_rejects_malformed_or_absent_loader(self) -> None:
        malformed = (
            "/lib64/ld-linux-x86-64.so.2 [0x1234]\n"
            "ld-linux-x86-64.so.2 => relative/ld-linux-x86-64.so.2 (0x5678)\n"
        )
        with self.assertRaisesRegex(MODULE.ReproducibilityError, "did not resolve"):
            MODULE.ldd_dependency_path(malformed, "ld-linux-x86-64.so.2")
        with self.assertRaisesRegex(MODULE.ReproducibilityError, "did not resolve"):
            MODULE.ldd_dependency_path(
                "/lib64/not-the-loader.so.2 (0x1234)\n",
                "ld-linux-x86-64.so.2",
            )

    def test_ldd_dependency_path_rejects_ambiguous_loader(self) -> None:
        ambiguous = (
            "ld-linux-x86-64.so.2 => /lib64/ld-linux-x86-64.so.2 (0x1234)\n"
            "/usr/lib64/ld-linux-x86-64.so.2 (0x5678)\n"
        )
        with self.assertRaisesRegex(MODULE.ReproducibilityError, "ambiguously"):
            MODULE.ldd_dependency_path(ambiguous, "ld-linux-x86-64.so.2")


if __name__ == "__main__":
    unittest.main()
