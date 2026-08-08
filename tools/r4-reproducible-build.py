#!/usr/bin/env python3
"""Build and attest a byte-reproducible native Wasm-Biotic kernel.

The gate performs two clean, offline Cargo builds in target directories whose
names have materially different lengths.  It compares the complete executable
bytes, including platform metadata and signatures, and emits a deterministic
per-platform report.  Physical build paths are deliberately absent from both
the object-path provenance and the report; stable logical prefixes retain the
meaning of embedded source locations.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from typing import Any, Iterable, Mapping, Sequence
import uuid


SCHEMA = "wasm-biotic.r4-native-build-reproducibility.v1"
SOURCE_SNAPSHOT_SCHEMA = "wasm-biotic.r4-source-snapshot.v1"
WITNESS_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
DIGEST_RE = re.compile(r"(?:sha256:)?([0-9a-f]{64})\Z")
DEBIAN_PACKAGE_RE = re.compile(r"[a-z0-9][a-z0-9+.-]*(?::[a-z0-9][a-z0-9-]*)?\Z")
ABSOLUTE_POSIX_RE = re.compile(r"(?:\A|[\s=:'\"(])/(?!/)")
ABSOLUTE_WINDOWS_RE = re.compile(r"(?:\A|[\s=:'\"(])[A-Za-z]:[\\/]")
SOURCE_ALGORITHM = (
    "SHA-256 of '<file-sha256><two spaces><repository-relative-path><LF>' "
    "in bytewise path order"
)
INVENTORY_SCOPE = (
    "kernel/Cargo.toml, kernel/Cargo.lock, kernel/src/**/*.rs and "
    "wit/wasm-biotic/*.wit; this self-referential inventory is excluded"
)
LOGICAL_PREFIXES = {
    "repository": "wasm-biotic/source",
    "target": "wasm-biotic/build/target",
    "cargo_home": "wasm-biotic/cargo-home",
    "rust_sysroot": "wasm-biotic/rust-sysroot",
}
AMBIENT_BUILD_VARIABLES = {
    "AR",
    "CC",
    "CFLAGS",
    "CPPFLAGS",
    "CXX",
    "CXXFLAGS",
    "LD",
    "LDFLAGS",
    "RANLIB",
    "CARGO_BUILD_RUSTFLAGS",
    "CARGO_BUILD_TARGET",
    "CARGO_ENCODED_RUSTFLAGS",
    "RUSTC",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "RUSTDOCFLAGS",
    "RUSTFLAGS",
}
MACHO_MAGIC_64 = 0xFEEDFACF
LC_UUID = 0x1B
LC_CODE_SIGNATURE = 0x1D


class ReproducibilityError(RuntimeError):
    """The build cannot support the claimed reproducibility statement."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReproducibilityError(message)


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def digest_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def generated_inventory_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        require(key not in value, f"JSON contains duplicate key {key!r}")
        value[key] = item
    return value


def normalize_digest(value: str) -> str:
    match = DIGEST_RE.fullmatch(value)
    require(match is not None, "reference digest must be 64 lowercase hexadecimal characters")
    return "sha256:" + match.group(1)


def command(
    arguments: Sequence[str],
    label: str,
    *,
    environment: Mapping[str, str] | None = None,
    cwd: Path | None = None,
    timeout: int = 1800,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            list(arguments),
            check=True,
            cwd=cwd,
            env=dict(environment) if environment is not None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as error:
        detail = ""
        if isinstance(error, subprocess.CalledProcessError):
            captured = (error.stderr or error.stdout or "").strip()
            if captured:
                detail = f": {captured[-4000:]}"
        raise ReproducibilityError(f"{label} failed{detail}") from error


def command_text(
    arguments: Sequence[str],
    label: str,
    *,
    environment: Mapping[str, str] | None = None,
) -> str:
    result = command(arguments, label, environment=environment, timeout=60)
    return result.stdout.strip() or result.stderr.strip()


def parse_colon_fields(text: str) -> dict[str, str]:
    return {
        key: value
        for line in text.splitlines()
        if ": " in line
        for key, value in [line.split(": ", 1)]
    }


def toolchain_identity(rustc: str, cargo: str, target: str) -> tuple[dict[str, Any], Path]:
    rustc_output = command_text([rustc, "-vV"], "inspect rustc")
    rustc_fields = parse_colon_fields(rustc_output)
    cargo_output = command_text([cargo, "-Vv"], "inspect cargo")
    cargo_lines = cargo_output.splitlines()
    cargo_fields = parse_colon_fields(cargo_output)
    cargo_words = cargo_lines[0].split() if cargo_lines else []
    sysroot_text = command_text([rustc, "--print", "sysroot"], "inspect Rust sysroot")
    sysroot = Path(sysroot_text).resolve(strict=True)
    target_libdir = Path(
        command_text(
            [rustc, "--print", "target-libdir", "--target", target],
            f"inspect Rust target {target}",
        )
    )
    require(target_libdir.is_dir(), f"Rust standard library for target {target!r} is not installed")
    identity = {
        "rustc": {
            "version": rustc_fields.get("release", "unknown"),
            "commit": rustc_fields.get("commit-hash", "unknown"),
            "commit_date": rustc_fields.get("commit-date", "unknown"),
            "host": rustc_fields.get("host", "unknown"),
            "llvm": rustc_fields.get("LLVM version", "unknown"),
        },
        "cargo": {
            "version": cargo_words[1] if len(cargo_words) > 1 else "unknown",
            "commit": cargo_fields.get("commit-hash", "unknown"),
            "commit_date": cargo_fields.get("commit-date", "unknown"),
            "host": cargo_fields.get("host", rustc_fields.get("host", "unknown")),
        },
    }
    return identity, sysroot


def host_target(rustc: str) -> str:
    fields = parse_colon_fields(command_text([rustc, "-vV"], "inspect rustc host"))
    target = fields.get("host")
    require(bool(target), "rustc did not report a host target")
    return target or ""


def platform_recipe(target: str, macos_deployment_target: str) -> dict[str, Any]:
    system = platform.system()
    if system == "Darwin":
        require(target.endswith("-apple-darwin"), "a macOS host requires an apple-darwin target")
        linker = command_text(["xcrun", "ld", "-v"], "inspect Apple linker")
        clang = command_text(["xcrun", "clang", "--version"], "inspect Apple clang").splitlines()[0]
        sdk = command_text(
            ["xcrun", "--sdk", "macosx", "--show-sdk-version"], "inspect macOS SDK"
        )
        return {
            "os": "macos",
            "binary_format": "Mach-O",
            "linker_flags": ["-Wl,-reproducible"],
            "identity_policy": (
                "LC_UUID is a deterministic RFC 9562 UUIDv8 derived from canonical Mach-O "
                "content; the detached SHA-256 artifact identity and signed release manifest "
                "remain authoritative"
            ),
            "environment": {"MACOSX_DEPLOYMENT_TARGET": macos_deployment_target},
            "linker": linker.splitlines()[0],
            "compiler_driver": clang,
            "sdk": sdk,
        }
    if system == "Linux":
        require("-linux-" in target, "a Linux host requires a Linux target")
        linker = command_text(["ld", "--version"], "inspect GNU-compatible linker").splitlines()[0]
        compiler = command_text(["cc", "--version"], "inspect C compiler driver").splitlines()[0]
        return {
            "os": "linux",
            "binary_format": "ELF",
            "linker_flags": ["-Wl,--build-id=sha1"],
            "identity_policy": "deterministic GNU SHA-1 build ID plus detached SHA-256 artifact identity",
            "environment": {},
            "linker": linker,
            "compiler_driver": compiler,
        }
    raise ReproducibilityError(f"unsupported build host {system!r}; only macOS and Linux are supported")


def path_variants(path: Path) -> list[str]:
    lexical = os.path.abspath(os.fspath(path))
    resolved = os.path.realpath(lexical)
    return list(dict.fromkeys((lexical, resolved)))


def remap_flags(
    repository: Path,
    target_directory: Path,
    cargo_home: Path,
    rust_sysroot: Path,
) -> list[str]:
    mappings = (
        (target_directory, LOGICAL_PREFIXES["target"]),
        (repository, LOGICAL_PREFIXES["repository"]),
        (cargo_home, LOGICAL_PREFIXES["cargo_home"]),
        (rust_sysroot, LOGICAL_PREFIXES["rust_sysroot"]),
    )
    flags: list[str] = []
    seen: set[tuple[str, str]] = set()
    for physical, logical in mappings:
        for variant in path_variants(physical):
            item = (variant, logical)
            if item not in seen:
                seen.add(item)
                flags.append(f"--remap-path-prefix={variant}={logical}")
    flags.append("--remap-path-scope=object")
    return flags


def source_paths(repository: Path) -> list[Path]:
    paths = [repository / "kernel/Cargo.toml", repository / "kernel/Cargo.lock"]
    paths.extend((repository / "kernel/src").rglob("*.rs"))
    paths.extend((repository / "wit/wasm-biotic").glob("*.wit"))
    unique = sorted(set(paths), key=lambda path: path.relative_to(repository).as_posix().encode())
    require(unique, "native source closure is empty")
    for path in unique:
        require(path.is_file() and not path.is_symlink(), f"source input is not a regular file: {path}")
    return unique


def closure(repository: Path, paths: Iterable[Path]) -> tuple[str, list[dict[str, str]]]:
    rows = bytearray()
    files: list[dict[str, str]] = []
    for path in sorted(
        set(paths), key=lambda item: item.relative_to(repository).as_posix().encode()
    ):
        relative = path.relative_to(repository).as_posix()
        digest = digest_file(path)
        rows.extend(f"{digest[7:]}  {relative}\n".encode())
        files.append({"path": relative, "sha256": digest})
    require(files, "source closure is empty")
    return digest_bytes(bytes(rows)), files


def read_inventory(repository: Path) -> tuple[dict[str, Any], bytes]:
    path = repository / "kernel/native-tcb.json"
    try:
        data = path.read_bytes()
        inventory = json.loads(data, object_pairs_hook=reject_duplicate_keys)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReproducibilityError(f"cannot read native TCB inventory: {error}") from error
    require(isinstance(inventory, dict), "native TCB inventory must be a JSON object")
    require(
        inventory.get("schema") == "wasm-biotic.native-tcb-inventory.v1",
        "native TCB inventory schema is not v1",
    )
    require(
        data == generated_inventory_json(inventory),
        "native TCB inventory does not match its deterministic generator format",
    )
    return inventory, data


def validate_inventory_source_binding(inventory: dict[str, Any], source_digest: str) -> None:
    crate = inventory.get("crate")
    require(isinstance(crate, dict), "native TCB inventory has no crate object")
    revision = crate.get("source_revision")
    require(isinstance(revision, dict), "native TCB inventory has no source revision")
    require(revision.get("algorithm") == SOURCE_ALGORITHM, "native TCB source algorithm differs")
    require(revision.get("scope") == INVENTORY_SCOPE, "native TCB source scope differs")
    require(revision.get("value") == source_digest, "native TCB source revision is stale")


def embedded_once(binary: bytes, value: bytes, label: str) -> int:
    require(value, f"{label} is empty")
    first = binary.find(value)
    require(first >= 0, f"optimized executable does not embed exact {label} bytes")
    require(binary.find(value, first + 1) < 0, f"optimized executable embeds {label} more than once")
    return first


def first_difference(left: bytes, right: bytes) -> int | None:
    for index, (one, two) in enumerate(zip(left, right)):
        if one != two:
            return index
    if len(left) != len(right):
        return min(len(left), len(right))
    return None


def require_identical(left: bytes, right: bytes) -> None:
    difference = first_difference(left, right)
    require(
        difference is None,
        f"clean build executables differ at byte offset {difference}; exact reproducibility failed",
    )


def macho_load_commands(binary: bytes) -> list[tuple[int, int, int]]:
    require(len(binary) >= 32, "Mach-O executable is truncated")
    magic, _, _, _, count, commands_size, _, _ = struct.unpack_from("<8I", binary, 0)
    require(magic == MACHO_MAGIC_64, "native artifact is not a thin 64-bit little-endian Mach-O")
    require(32 + commands_size <= len(binary), "Mach-O load-command region is truncated")
    commands: list[tuple[int, int, int]] = []
    offset = 32
    for _ in range(count):
        require(offset + 8 <= len(binary), "Mach-O load command is truncated")
        kind, size = struct.unpack_from("<2I", binary, offset)
        require(size >= 8 and offset + size <= len(binary), "Mach-O load command has invalid size")
        commands.append((kind, offset, size))
        offset += size
    require(offset == 32 + commands_size, "Mach-O load commands do not match declared size")
    return commands


def validate_macho_identity_commands(commands: Sequence[tuple[int, int, int]]) -> None:
    require(
        sum(kind == LC_UUID for kind, _, _ in commands) == 1,
        "Mach-O must contain exactly one LC_UUID command",
    )
    require(
        sum(kind == LC_CODE_SIGNATURE for kind, _, _ in commands) == 1,
        "Mach-O must contain exactly one code-signature command",
    )


def macho_identity_regions(binary: bytes) -> tuple[int, int, int]:
    commands = macho_load_commands(binary)
    validate_macho_identity_commands(commands)
    uuid_command = next(item for item in commands if item[0] == LC_UUID)
    signature_command = next(item for item in commands if item[0] == LC_CODE_SIGNATURE)
    require(uuid_command[2] >= 24, "Mach-O LC_UUID command is truncated")
    require(signature_command[2] >= 16, "Mach-O code-signature command is truncated")
    signature_offset, signature_size = struct.unpack_from("<2I", binary, signature_command[1] + 8)
    require(
        signature_offset + signature_size <= len(binary),
        "Mach-O embedded code signature is truncated",
    )
    return uuid_command[1] + 8, signature_offset, signature_size


def canonical_macho_material(binary: bytes) -> bytes:
    uuid_offset, signature_offset, signature_size = macho_identity_regions(binary)
    material = bytearray(binary)
    material[uuid_offset : uuid_offset + 16] = bytes(16)
    material[signature_offset : signature_offset + signature_size] = bytes(signature_size)
    return bytes(material)


def deterministic_macho_uuid(material_digest: str) -> bytes:
    raw = bytearray(bytes.fromhex(normalize_digest(material_digest)[7:])[:16])
    raw[6] = (raw[6] & 0x0F) | 0x80
    raw[8] = (raw[8] & 0x3F) | 0x80
    return bytes(raw)


def replace_macho_uuid(path: Path, value: bytes) -> None:
    require(len(value) == 16, "Mach-O UUID replacement must be exactly 16 bytes")
    binary = bytearray(path.read_bytes())
    uuid_offset, _, _ = macho_identity_regions(binary)
    binary[uuid_offset : uuid_offset + 16] = value
    path.write_bytes(binary)


def sign_macho(path: Path, identifier: str) -> None:
    command(
        [
            "codesign",
            "--force",
            "--sign",
            "-",
            "--timestamp=none",
            "--identifier",
            identifier,
            str(path),
        ],
        "create deterministic ad-hoc Mach-O signature",
        timeout=60,
    )


def canonicalize_macho_pair(paths: Sequence[Path]) -> dict[str, Any]:
    require(len(paths) == 2, "Mach-O reproduction requires exactly two clean builds")
    linked = [path.read_bytes() for path in paths]
    linked_material = [canonical_macho_material(binary) for binary in linked]
    require_identical(linked_material[0], linked_material[1])
    linked_digest = digest_bytes(linked_material[0])
    identifier = "wasm-biotic.kernel." + linked_digest[7:23]

    # First establish one canonical signature layout while LC_UUID is neutral.
    for path in paths:
        replace_macho_uuid(path, bytes(16))
        sign_macho(path, identifier)
    neutral_signed = [path.read_bytes() for path in paths]
    neutral_material = [canonical_macho_material(binary) for binary in neutral_signed]
    require_identical(neutral_material[0], neutral_material[1])
    material_digest = digest_bytes(neutral_material[0])
    selected_uuid = deterministic_macho_uuid(material_digest)

    # Re-sign after selecting the content-derived UUID. The UUID is meaningful
    # to dyld/debuggers, while the detached SHA-256 remains the artifact identity.
    for path in paths:
        replace_macho_uuid(path, selected_uuid)
        sign_macho(path, identifier)
    final = [path.read_bytes() for path in paths]
    require_identical(final[0], final[1])
    for binary in final:
        require(
            digest_bytes(canonical_macho_material(binary)) == material_digest,
            "Mach-O canonical content changed while assigning deterministic identity",
        )
    return {
        "method": (
            "zero LC_UUID and embedded signature bytes, require all remaining linked bytes "
            "equal, establish a canonical ad-hoc signature layout, derive UUIDv8 from its "
            "SHA-256, then re-sign"
        ),
        "linked_material_sha256": linked_digest,
        "raw_linker_outputs_equal": linked[0] == linked[1],
        "canonical_material_sha256": material_digest,
        "linked_artifacts_equal_outside_allowed_regions": True,
        "allowed_identity_regions": ["LC_UUID payload", "LC_CODE_SIGNATURE blob"],
        "uuid": str(uuid.UUID(bytes=selected_uuid)),
        "uuid_standard": "RFC 9562 version 8, RFC 4122 variant",
        "signature": "deterministic ad-hoc codesign without timestamp",
        "result": "pass",
    }


def macos_binary_metadata(binary_path: Path, binary: bytes) -> dict[str, Any]:
    commands = macho_load_commands(binary)
    validate_macho_identity_commands(commands)
    uuid_offset, _, _ = macho_identity_regions(binary)
    command(["codesign", "--verify", "--strict", str(binary_path)], "verify Mach-O signature", timeout=60)
    details_result = command(
        ["codesign", "-dvvv", str(binary_path)], "inspect Mach-O signature", timeout=60
    )
    details = "\n".join((details_result.stdout, details_result.stderr))
    fields = parse_colon_fields(details.replace("=", ": "))
    require("adhoc" in details.lower(), "Mach-O signature is not ad hoc")
    return {
        "format": "Mach-O",
        "lc_uuid_present": True,
        "lc_uuid": str(uuid.UUID(bytes=binary[uuid_offset : uuid_offset + 16])),
        "code_signature": {
            "kind": "ad-hoc",
            "identifier": fields.get("Identifier", "unknown"),
            "cdhash": fields.get("CDHash", fields.get("CandidateCDHash sha256", "unknown")),
            "verification": "pass",
        },
    }


def linux_binary_metadata(binary_path: Path, binary: bytes) -> dict[str, Any]:
    require(binary.startswith(b"\x7fELF"), "native artifact is not ELF")
    notes = command_text(["readelf", "-n", str(binary_path)], "inspect ELF notes")
    match = re.search(r"Build ID:\s*([0-9a-fA-F]+)", notes)
    require(match is not None, "ELF artifact has no build ID")
    return {
        "format": "ELF",
        "build_id": (match.group(1).lower() if match else "unknown"),
    }


def binary_metadata(system: str, binary_path: Path, binary: bytes) -> dict[str, Any]:
    if system == "macos":
        return macos_binary_metadata(binary_path, binary)
    if system == "linux":
        return linux_binary_metadata(binary_path, binary)
    raise ReproducibilityError(f"unsupported binary metadata platform {system!r}")


def linux_package_version(path: str, library: str) -> str:
    """Resolve an ELF dependency to its installed Debian package version."""

    candidates = list(dict.fromkeys((path, os.path.realpath(path))))
    owners: set[str] = set()
    for candidate in candidates:
        result = subprocess.run(
            ["dpkg-query", "-S", candidate],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                owner, separator, _ = line.rpartition(": ")
                if separator:
                    candidates = [item.strip() for item in owner.split(",") if item.strip()]
                    owners.update(
                        item
                        for item in candidates
                        if DEBIAN_PACKAGE_RE.fullmatch(item) is not None
                    )
    require(len(owners) == 1, f"cannot resolve one installed package owner for {library}")
    owner = next(iter(owners))
    version = command_text(
        ["dpkg-query", "-W", "-f=${Version}", owner],
        f"inspect installed package version for {library}",
    )
    require(bool(version), f"installed package for {library} has no version")
    return version


def ldd_dependency_path(output: str, library: str) -> str:
    """Resolve one NEEDED name from the two closed ldd line forms we permit."""

    address = r"0x[0-9a-fA-F]+"
    named = re.compile(
        rf"\s*{re.escape(library)}\s+=>\s+(/[^\s()]+)\s+\({address}\)\s*\Z"
    )
    direct = re.compile(rf"\s*(/[^\s()]+)\s+\({address}\)\s*\Z")
    matches: list[str] = []
    for line in output.splitlines():
        named_match = named.fullmatch(line)
        if named_match is not None:
            matches.append(named_match.group(1))
            continue
        direct_match = direct.fullmatch(line)
        if direct_match is not None and Path(direct_match.group(1)).name == library:
            matches.append(direct_match.group(1))
    require(matches, f"ldd did not resolve ELF dependency {library}")
    require(len(matches) == 1, f"ldd resolved ELF dependency {library} ambiguously")
    return matches[0]


def runtime_dependencies(system: str, binary_path: Path) -> list[dict[str, str]]:
    """Return sorted exact runtime names and versions without host paths."""

    if system == "macos":
        output = command_text(["otool", "-L", str(binary_path)], "inspect Mach-O dependencies")
        libraries: list[dict[str, str]] = []
        for line in output.splitlines()[1:]:
            value = line.strip()
            if not value:
                continue
            name, separator, detail = value.partition(" (")
            require(separator == " (" and detail.endswith(")"), "malformed otool dependency")
            fields = [item.strip() for item in detail[:-1].split(",")]
            require(len(fields) == 2, "malformed Mach-O dependency versions")
            compatibility = fields[0].removeprefix("compatibility version ")
            current = fields[1].removeprefix("current version ")
            require(
                fields[0] == f"compatibility version {compatibility}"
                and fields[1] == f"current version {current}",
                "malformed Mach-O dependency version labels",
            )
            libraries.append(
                {
                    "name": Path(name).name,
                    "version": current,
                }
            )
        require(libraries, "Mach-O executable declares no dynamic libraries")
        require(
            len({item["name"] for item in libraries}) == len(libraries),
            "Mach-O executable declares duplicate dynamic libraries",
        )
        return sorted(libraries, key=lambda item: (item["name"], item["version"]))
    if system == "linux":
        dynamic = command_text(["readelf", "-d", str(binary_path)], "inspect ELF dependencies")
        libraries = sorted(set(re.findall(r"Shared library: \[([^\]]+)\]", dynamic)))
        require(libraries, "ELF executable declares no dynamic libraries")
        linked = command_text(["ldd", str(binary_path)], "resolve ELF dependencies")
        result: list[dict[str, str]] = []
        for library in libraries:
            path = ldd_dependency_path(linked, library)
            result.append(
                {
                    "name": library,
                    "version": linux_package_version(path, library),
                }
            )
        return sorted(result, key=lambda item: (item["name"], item["version"]))
    raise ReproducibilityError(f"unsupported runtime dependency platform {system!r}")


def source_snapshot_identity(repository: Path) -> dict[str, Any]:
    path = repository / "SOURCE-SNAPSHOT.json"
    require(path.is_file() and not path.is_symlink(), "authoritative SOURCE-SNAPSHOT.json is absent")
    data = path.read_bytes()
    try:
        value = json.loads(data, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ReproducibilityError(f"cannot parse SOURCE-SNAPSHOT.json: {error}") from error
    require(isinstance(value, dict), "SOURCE-SNAPSHOT.json must be an object")
    require(canonical_json(value) == data, "SOURCE-SNAPSHOT.json is not canonical JSON")
    require(value.get("schema") == SOURCE_SNAPSHOT_SCHEMA, "unsupported source snapshot schema")
    for field in ("source_closure_sha256", "vendor_closure_sha256"):
        require(
            isinstance(value.get(field), str) and DIGEST_RE.fullmatch(value[field]) is not None,
            f"SOURCE-SNAPSHOT.json has invalid {field}",
        )
    return {"schema": SOURCE_SNAPSHOT_SCHEMA, "sha256": digest_bytes(data)}


def verify_executable_loads(binary_path: Path) -> dict[str, Any]:
    try:
        result = subprocess.run(
            [str(binary_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ReproducibilityError(f"cannot execute the reproduced kernel: {error}") from error
    combined = "\n".join((result.stdout, result.stderr))
    require(result.returncode >= 0, "reproduced kernel terminated by a signal")
    require("missing LC_UUID" not in combined, "dyld rejected the reproduced kernel identity")
    require("usage:" in combined, "reproduced kernel did not reach its argument parser")
    return {
        "invoked": True,
        "expected_usage_error": True,
        "process_loaded": True,
        "result": "pass",
    }


def physical_path_needles(*roots: Path) -> list[bytes]:
    needles: list[bytes] = []
    for root in roots:
        for variant in path_variants(root):
            encoded = variant.encode()
            if encoded not in needles:
                needles.append(encoded)
    return needles


def require_no_physical_paths(binary: bytes, roots: Sequence[Path]) -> None:
    leaked = [needle.decode(errors="replace") for needle in physical_path_needles(*roots) if needle in binary]
    if leaked:
        raise ReproducibilityError(
            f"optimized executable contains physical build path {leaked[0]!r}"
        )


def contains_absolute_path(value: str) -> bool:
    return bool(ABSOLUTE_POSIX_RE.search(value) or ABSOLUTE_WINDOWS_RE.search(value))


def require_no_absolute_report_paths(value: Any, location: str = "report") -> None:
    if isinstance(value, str):
        require(not contains_absolute_path(value), f"{location} contains an absolute path: {value!r}")
    elif isinstance(value, dict):
        for key, item in value.items():
            require_no_absolute_report_paths(item, f"{location}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            require_no_absolute_report_paths(item, f"{location}[{index}]")


def build_environment(
    *,
    target_directory: Path,
    repository: Path,
    cargo_home: Path,
    rust_sysroot: Path,
    rustc: str,
    recipe: dict[str, Any],
) -> tuple[dict[str, str], list[str]]:
    environment = dict(os.environ)
    for key in list(environment):
        if (
            key in AMBIENT_BUILD_VARIABLES
            or key.startswith("CARGO_PROFILE_RELEASE_")
            or key.startswith("CARGO_TARGET_")
            or key.startswith("CC_")
            or key.startswith("CFLAGS_")
            or key.startswith("CXX_")
            or key.startswith("CXXFLAGS_")
            or key.startswith("AR_")
            or key.startswith("RANLIB_")
        ):
            environment.pop(key, None)
    flags = remap_flags(repository, target_directory, cargo_home, rust_sysroot)
    for linker_flag in recipe["linker_flags"]:
        flags.extend(("-C", f"link-arg={linker_flag}"))
    temporary = target_directory / "build-tmp"
    temporary.mkdir(parents=True, exist_ok=True)
    environment.update(
        {
            "CARGO_HOME": str(cargo_home),
            "CARGO_INCREMENTAL": "0",
            "CARGO_TARGET_DIR": str(target_directory),
            "CARGO_ENCODED_RUSTFLAGS": "\x1f".join(flags),
            "LANG": "C",
            "LC_ALL": "C",
            "RUSTC": rustc,
            "SOURCE_DATE_EPOCH": "0",
            "TMPDIR": str(temporary),
            "TZ": "UTC",
            "ZERO_AR_DATE": "1",
        }
    )
    environment.update(recipe["environment"])
    return environment, flags


def build_once(
    *,
    cargo: str,
    rustc: str,
    repository: Path,
    target: str,
    target_directory: Path,
    cargo_home: Path,
    rust_sysroot: Path,
    recipe: dict[str, Any],
) -> tuple[Path, list[str]]:
    require(not target_directory.exists(), f"build target directory is not fresh: {target_directory}")
    target_directory.mkdir(parents=True)
    environment, flags = build_environment(
        target_directory=target_directory,
        repository=repository,
        cargo_home=cargo_home,
        rust_sysroot=rust_sysroot,
        rustc=rustc,
        recipe=recipe,
    )
    arguments = [
        cargo,
        "build",
        "--locked",
        "--offline",
        "--manifest-path",
        str(repository / "kernel/Cargo.toml"),
        "--release",
        "--bin",
        "wasm-biotic-kernel",
        "--target",
        target,
    ]
    command(arguments, "clean native kernel build", environment=environment, cwd=repository)
    suffix = ".exe" if target.endswith("windows-msvc") or target.endswith("windows-gnu") else ""
    binary_path = target_directory / target / "release" / f"wasm-biotic-kernel{suffix}"
    require(binary_path.is_file() and not binary_path.is_symlink(), "Cargo did not emit the native kernel")
    return binary_path, flags


def build_report(
    *,
    repository: Path,
    target: str,
    recipe: dict[str, Any],
    toolchain: dict[str, Any],
    binary_path: Path,
    binary: bytes,
    inventory: dict[str, Any],
    inventory_bytes: bytes,
    source_digest: str,
    source_files: list[dict[str, str]],
    wit_digest: str,
    wit_files: list[dict[str, str]],
    reference_digest: str | None,
    platform_canonicalization: dict[str, Any] | None,
    execution_verification: dict[str, Any],
    builder_digest: str,
    snapshot: dict[str, Any],
    witness_id: str,
) -> dict[str, Any]:
    binary_digest = digest_bytes(binary)
    tcb_offset = embedded_once(binary, inventory_bytes, "native TCB inventory")
    metadata = binary_metadata(recipe["os"], binary_path, binary)
    dependencies = runtime_dependencies(recipe["os"], binary_path)
    recipe_facts = {
        "profile": "release",
        "cargo_arguments": [
            "build",
            "--locked",
            "--offline",
            "--manifest-path",
            "kernel/Cargo.toml",
            "--release",
            "--bin",
            "wasm-biotic-kernel",
            "--target",
            target,
        ],
        "environment": {
            "CARGO_INCREMENTAL": "0",
            "SOURCE_DATE_EPOCH": "0",
            "ZERO_AR_DATE": "1",
            "LANG": "C",
            "LC_ALL": "C",
            "TZ": "UTC",
            **recipe["environment"],
        },
        "path_remapping": [
            {"physical_role": key, "logical_prefix": value}
            for key, value in sorted(LOGICAL_PREFIXES.items())
        ],
        "remap_scope": "object",
        "linker_flags": recipe["linker_flags"],
    }
    reference = {
        "requested": reference_digest is not None,
        "expected_sha256": reference_digest,
        "match": reference_digest is None or reference_digest == binary_digest,
    }
    report = {
        "schema": SCHEMA,
        "gate_result": "pass",
        "component_complete_claim": False,
        "witness": {"id": witness_id, "physical_machine": True},
        "platform": {
            "os": recipe["os"],
            "architecture": target.split("-", 1)[0],
            "target": target,
            "binary_format": recipe["binary_format"],
            "identity_policy": recipe["identity_policy"],
        },
        "source": {
            "snapshot_manifest": snapshot,
            "closure": {
                "sha256": source_digest,
                "algorithm": SOURCE_ALGORITHM,
                "scope": INVENTORY_SCOPE,
                "files": source_files,
            },
            "cargo_manifest": next(item for item in source_files if item["path"] == "kernel/Cargo.toml"),
            "dependency_lock": next(item for item in source_files if item["path"] == "kernel/Cargo.lock"),
            "wit_bindings": {
                "sha256": wit_digest,
                "algorithm": SOURCE_ALGORITHM,
                "scope": "wit/wasm-biotic/*.wit",
                "files": wit_files,
            },
            "builder": {
                "path": "tools/r4-reproducible-build.py",
                "sha256": builder_digest,
            },
        },
        "toolchain": {
            **toolchain,
            "linker": recipe["linker"],
            "compiler_driver": recipe["compiler_driver"],
            "host_os": {
                "system": platform.system(),
                "version": platform.mac_ver()[0] or platform.release(),
                "architecture": platform.machine(),
            },
            **({"sdk": recipe["sdk"]} if "sdk" in recipe else {}),
        },
        "build_recipe": {
            **recipe_facts,
            "sha256": digest_bytes(canonical_json(recipe_facts)),
        },
        "native_artifact": {
            "path": "objects/" + binary_digest.replace(":", "-", 1),
            "sha256": binary_digest,
            "size_bytes": len(binary),
            "platform_metadata": metadata,
            "runtime_dependencies": dependencies,
        },
        "compiled_inventory": {
            "path": "kernel/native-tcb.json",
            "sha256": digest_bytes(inventory_bytes),
            "schema": inventory.get("schema"),
            "source_revision": source_digest,
            "binary_embedding": {
                "method": "exact raw byte-subsequence search",
                "occurrences": 1,
                "offset_bytes": tcb_offset,
                "result": "pass",
            },
        },
        "reproduction": {
            "clean_builds": 2,
            "target_directory_shapes": ["short", "materially-long"],
            "exact_complete_binary_match": True,
            "binary_sha256": binary_digest,
            "physical_build_paths_embedded": False,
            "platform_identity_canonicalization": platform_canonicalization,
            "execution_verification": execution_verification,
            "result": "pass",
        },
        "reference_digest_verification": reference,
    }
    require(reference["match"], f"binary digest {binary_digest} does not match reference {reference_digest}")
    require_no_absolute_report_paths(report)
    return report


def resolve_executable(value: str, label: str) -> str:
    resolved = shutil.which(value)
    require(resolved is not None, f"cannot locate {label} executable {value!r}")
    return resolved or value


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[1])
    result.add_argument("--target", help="Rust target triple; defaults to rustc's host")
    result.add_argument("--cargo", default="cargo")
    result.add_argument("--rustc", default="rustc")
    result.add_argument("--cargo-home", type=Path)
    result.add_argument("--work-root", type=Path, help="parent for disposable clean build directories")
    result.add_argument("--keep-builds", action="store_true")
    result.add_argument("--macos-deployment-target", default="11.0")
    result.add_argument("--reference-digest")
    result.add_argument("--witness-id", required=True)
    result.add_argument("--binary-out", type=Path, required=True)
    result.add_argument("--out", type=Path, required=True, help="canonical JSON reproduction report")
    return result


def run(options: argparse.Namespace) -> tuple[dict[str, Any], bytes]:
    builder_path = Path(__file__)
    builder_digest = digest_file(builder_path)
    repository = options.repository.resolve(strict=True)
    require(WITNESS_RE.fullmatch(options.witness_id) is not None, "invalid physical witness identifier")
    require((repository / "kernel/Cargo.toml").is_file(), "repository has no kernel/Cargo.toml")
    cargo = resolve_executable(options.cargo, "cargo")
    rustc = resolve_executable(options.rustc, "rustc")
    target = options.target or host_target(rustc)
    toolchain, rust_sysroot = toolchain_identity(rustc, cargo, target)
    require(
        target == toolchain["rustc"]["host"],
        "this gate builds and executes the current host target; use one native runner per platform",
    )
    recipe = platform_recipe(target, options.macos_deployment_target)
    cargo_home = (
        options.cargo_home
        or (Path(os.environ["CARGO_HOME"]) if os.environ.get("CARGO_HOME") else Path.home() / ".cargo")
    ).resolve(strict=True)

    source_digest, source_files = closure(repository, source_paths(repository))
    snapshot = source_snapshot_identity(repository)
    wit_paths = list((repository / "wit/wasm-biotic").glob("*.wit"))
    wit_digest, wit_files = closure(repository, wit_paths)
    inventory, inventory_bytes = read_inventory(repository)
    validate_inventory_source_binding(inventory, source_digest)
    reference = normalize_digest(options.reference_digest) if options.reference_digest else None

    work_parent = options.work_root.resolve(strict=True) if options.work_root else None
    temporary = Path(tempfile.mkdtemp(prefix="wasm-biotic-r4-repro-", dir=work_parent))
    try:
        targets = [
            temporary / "target-a",
            temporary / "target-b-with-a-materially-different-directory-name",
        ]
        built: list[tuple[Path, list[str]]] = []
        for target_directory in targets:
            built.append(
                build_once(
                    cargo=cargo,
                    rustc=rustc,
                    repository=repository,
                    target=target,
                    target_directory=target_directory,
                    cargo_home=cargo_home,
                    rust_sysroot=rust_sysroot,
                    recipe=recipe,
                )
            )
        platform_canonicalization = None
        if recipe["os"] == "macos":
            platform_canonicalization = canonicalize_macho_pair([path for path, _ in built])
        binaries = [path.read_bytes() for path, _ in built]
        require_identical(binaries[0], binaries[1])
        for binary in binaries:
            require_no_physical_paths(
                binary,
                [repository, cargo_home, rust_sysroot, targets[0], targets[1], temporary],
            )
            embedded_once(binary, inventory_bytes, "native TCB inventory")
        final_source_digest, _ = closure(repository, source_paths(repository))
        require(final_source_digest == source_digest, "native source closure changed during the build")
        _, final_inventory_bytes = read_inventory(repository)
        require(final_inventory_bytes == inventory_bytes, "native TCB inventory changed during the build")
        require(digest_file(builder_path) == builder_digest, "reproducible-build tool changed during the build")
        execution_verification = verify_executable_loads(built[0][0])
        report = build_report(
            repository=repository,
            target=target,
            recipe=recipe,
            toolchain=toolchain,
            binary_path=built[0][0],
            binary=binaries[0],
            inventory=inventory,
            inventory_bytes=inventory_bytes,
            source_digest=source_digest,
            source_files=source_files,
            wit_digest=wit_digest,
            wit_files=wit_files,
            reference_digest=reference,
            platform_canonicalization=platform_canonicalization,
            execution_verification=execution_verification,
            builder_digest=builder_digest,
            snapshot=snapshot,
            witness_id=options.witness_id,
        )
        return report, binaries[0]
    finally:
        if not options.keep_builds:
            shutil.rmtree(temporary)
        else:
            print(f"retained disposable builds under {temporary}", file=sys.stderr)


def main(arguments: Sequence[str] | None = None) -> int:
    options = parser().parse_args(arguments)
    try:
        report, binary = run(options)
        options.binary_out.parent.mkdir(parents=True, exist_ok=True)
        options.out.parent.mkdir(parents=True, exist_ok=True)
        options.binary_out.write_bytes(binary)
        options.binary_out.chmod(0o755)
        report_bytes = canonical_json(report)
        options.out.write_bytes(report_bytes)
        print(
            f"reproduced {report['native_artifact']['sha256']} and wrote "
            f"{digest_bytes(report_bytes)} report"
        )
        return 0
    except ReproducibilityError as error:
        print(f"r4-reproducible-build: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
