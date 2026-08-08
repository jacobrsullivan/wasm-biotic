#!/usr/bin/env python3
"""Build, verify, and safely extract a deterministic Wasm-Biotic archive.

The archive is deliberately simple: one canonical ``MANIFEST.json`` followed
by a byte-sorted ``payload/`` tree.  The manifest binds every normalized mode,
size, and SHA-256 digest.  Tar metadata is fixed so the same input bytes produce
the same archive bytes on every supported host.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import tarfile
import tempfile
from typing import Any


SCHEMA = "wasm-biotic.install-archive-manifest.v1"
ROOT_NAME = "payload"
MANIFEST_NAME = "MANIFEST.json"
MAX_ENTRY_COUNT = 100_000
MAX_TOTAL_SIZE = 8 * 1024 * 1024 * 1024
FORBIDDEN_SEGMENTS = frozenset({".git", "__pycache__"})


class ArchiveError(RuntimeError):
    """The requested archive operation was not safe or reproducible."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ArchiveError(message)


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"JSON contains duplicate key {key!r}")
        result[key] = value
    return result


def reject_floats(value: Any, where: str = "document") -> None:
    require(not isinstance(value, float), f"{where} contains a floating-point value")
    if isinstance(value, dict):
        for key, item in value.items():
            reject_floats(item, f"{where}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            reject_floats(item, f"{where}[{index}]")


def read_canonical_json(data: bytes) -> dict[str, Any]:
    try:
        value = json.loads(data, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ArchiveError(f"manifest is not valid UTF-8 JSON: {error}") from error
    require(isinstance(value, dict), "manifest must be a JSON object")
    reject_floats(value)
    require(canonical_json(value) == data, "manifest is not canonical JSON")
    return value


def validate_relative_path(value: str) -> PurePosixPath:
    require(isinstance(value, str) and value, "archive entry path must be non-empty")
    require("\\" not in value and "\x00" not in value, f"unsafe archive path {value!r}")
    path = PurePosixPath(value)
    require(not path.is_absolute(), f"archive path is absolute: {value!r}")
    require(path.as_posix() == value, f"archive path is not canonical: {value!r}")
    require(all(part not in ("", ".", "..") for part in path.parts), f"unsafe archive path {value!r}")
    require(not any(part in FORBIDDEN_SEGMENTS for part in path.parts), f"generated path is forbidden: {value!r}")
    target_segments = [index for index, part in enumerate(path.parts) if part == "target"]
    require(
        not target_segments
        or (
            target_segments == [3]
            and len(path.parts) >= 4
            and path.parts[0] == "vendor"
            and path.parts[2] == "src"
        ),
        f"generated path is forbidden: {value!r}",
    )
    require(path.name != ".env", "a secret-bearing .env file cannot enter a release archive")
    require(len(value.encode("utf-8")) <= 240, f"archive path is too long: {value!r}")
    return path


def normalized_file_mode(path: Path) -> int:
    return 0o755 if path.lstat().st_mode & stat.S_IXUSR else 0o644


def source_entries(root: Path) -> list[dict[str, Any]]:
    require(root.is_dir() and not root.is_symlink(), f"input is not a regular directory: {root}")
    entries: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix().encode("utf-8")):
        relative = path.relative_to(root).as_posix()
        validate_relative_path(relative)
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            entries.append({"kind": "directory", "mode": "0755", "path": relative})
        elif stat.S_ISREG(info.st_mode):
            mode = normalized_file_mode(path)
            entries.append(
                {
                    "kind": "file",
                    "mode": f"{mode:04o}",
                    "path": relative,
                    "sha256": digest_file(path),
                    "size_bytes": info.st_size,
                }
            )
        else:
            raise ArchiveError(f"links and special files are forbidden: {path}")
    require(entries, "archive payload is empty")
    require(len(entries) <= MAX_ENTRY_COUNT, "archive has too many entries")
    total = sum(entry.get("size_bytes", 0) for entry in entries)
    require(total <= MAX_TOTAL_SIZE, "archive payload exceeds the size ceiling")
    return entries


def build_manifest(root: Path, epoch: int) -> tuple[dict[str, Any], bytes]:
    require(epoch >= 0, "source date epoch must be non-negative")
    entries = source_entries(root)
    manifest = {
        "archive_format": "ustar",
        "entry_count": len(entries),
        "payload_root": ROOT_NAME,
        "schema": SCHEMA,
        "source_date_epoch": epoch,
        "total_file_size_bytes": sum(entry.get("size_bytes", 0) for entry in entries),
        "entries": entries,
    }
    return manifest, canonical_json(manifest)


def tar_info(name: str, mode: int, size: int, epoch: int, kind: bytes) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.mode = mode
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    info.mtime = epoch
    info.size = size
    info.type = kind
    return info


def write_archive(root: Path, output: Path, epoch: int) -> tuple[str, dict[str, Any]]:
    manifest, manifest_bytes = build_manifest(root, epoch)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("xb") as stream, tarfile.open(
        fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT
    ) as archive:
        archive.addfile(
            tar_info(MANIFEST_NAME, 0o644, len(manifest_bytes), epoch, tarfile.REGTYPE),
            io.BytesIO(manifest_bytes),
        )
        archive.addfile(tar_info(ROOT_NAME, 0o755, 0, epoch, tarfile.DIRTYPE))
        for entry in manifest["entries"]:
            source = root / PurePosixPath(entry["path"])
            name = f"{ROOT_NAME}/{entry['path']}"
            mode = int(entry["mode"], 8)
            if entry["kind"] == "directory":
                archive.addfile(tar_info(name, mode, 0, epoch, tarfile.DIRTYPE))
            else:
                with source.open("rb") as file_stream:
                    archive.addfile(
                        tar_info(name, mode, entry["size_bytes"], epoch, tarfile.REGTYPE),
                        file_stream,
                    )
    return digest_file(output), manifest


def expected_members(manifest: dict[str, Any]) -> list[tuple[str, dict[str, Any] | None]]:
    return [(MANIFEST_NAME, None), (ROOT_NAME, None)] + [
        (f"{ROOT_NAME}/{entry['path']}", entry) for entry in manifest["entries"]
    ]


def validate_manifest_shape(manifest: dict[str, Any]) -> None:
    require(
        set(manifest)
        == {
            "archive_format",
            "entries",
            "entry_count",
            "payload_root",
            "schema",
            "source_date_epoch",
            "total_file_size_bytes",
        },
        "manifest fields are not closed",
    )
    require(manifest["schema"] == SCHEMA, "unsupported archive manifest schema")
    require(manifest["archive_format"] == "ustar", "unsupported archive format")
    require(manifest["payload_root"] == ROOT_NAME, "unexpected archive payload root")
    require(isinstance(manifest["source_date_epoch"], int) and manifest["source_date_epoch"] >= 0, "invalid source date epoch")
    entries = manifest["entries"]
    require(isinstance(entries, list) and entries, "manifest entries must be a non-empty list")
    require(len(entries) <= MAX_ENTRY_COUNT, "manifest has too many entries")
    paths: list[str] = []
    total = 0
    for entry in entries:
        require(isinstance(entry, dict), "manifest entry must be an object")
        kind = entry.get("kind")
        required = {"kind", "mode", "path"}
        if kind == "file":
            required |= {"sha256", "size_bytes"}
        require(set(entry) == required, f"manifest entry fields are not closed: {entry!r}")
        path = entry["path"]
        validate_relative_path(path)
        paths.append(path)
        if kind == "directory":
            require(entry["mode"] == "0755", f"directory has non-canonical mode: {path}")
        else:
            require(kind == "file", f"unsupported manifest entry kind {kind!r}")
            require(entry["mode"] in ("0644", "0755"), f"file has non-canonical mode: {path}")
            require(
                isinstance(entry["sha256"], str)
                and len(entry["sha256"]) == 71
                and entry["sha256"].startswith("sha256:")
                and all(character in "0123456789abcdef" for character in entry["sha256"][7:]),
                f"file has invalid digest: {path}",
            )
            require(isinstance(entry["size_bytes"], int) and entry["size_bytes"] >= 0, f"file has invalid size: {path}")
            total += entry["size_bytes"]
    require(paths == sorted(paths, key=lambda item: item.encode("utf-8")), "manifest paths are not byte-sorted")
    require(len(paths) == len(set(paths)), "manifest contains duplicate paths")
    require(manifest["entry_count"] == len(entries), "manifest entry count differs")
    require(manifest["total_file_size_bytes"] == total, "manifest total size differs")
    require(total <= MAX_TOTAL_SIZE, "manifest payload exceeds the size ceiling")


def verify_archive(path: Path) -> tuple[str, dict[str, Any], bytes]:
    require(path.is_file() and not path.is_symlink(), f"archive is not a regular file: {path}")
    require(path.stat().st_size <= MAX_TOTAL_SIZE + 1024 * 1024 * 128, "archive exceeds the size ceiling")
    try:
        with tarfile.open(path, mode="r:") as archive:
            members = archive.getmembers()
            require(members and members[0].name == MANIFEST_NAME, "manifest must be the first archive member")
            require(len(members) <= MAX_ENTRY_COUNT + 2, "archive has too many members")
            manifest_stream = archive.extractfile(members[0])
            require(manifest_stream is not None, "manifest has no file body")
            manifest_bytes = manifest_stream.read()
            manifest = read_canonical_json(manifest_bytes)
            validate_manifest_shape(manifest)
            expected = expected_members(manifest)
            require([member.name for member in members] == [name for name, _ in expected], "archive member closure or order differs from its manifest")
            epoch = manifest["source_date_epoch"]
            # ``strict=`` was added in Python 3.10.  The member-name equality
            # above already proves equal lengths, so plain zip preserves the
            # fail-closed semantics on the Python 3.9 shipped by Bobs-mini.
            for member, (_, entry) in zip(members, expected):
                require(member.uid == 0 and member.gid == 0, f"non-canonical owner metadata on {member.name}")
                require(member.uname == "root" and member.gname == "root", f"non-canonical owner names on {member.name}")
                require(member.mtime == epoch, f"non-canonical timestamp on {member.name}")
                require(not member.linkname, f"links are forbidden: {member.name}")
                if entry is None:
                    expected_mode = 0o644 if member.name == MANIFEST_NAME else 0o755
                    expected_type = member.isfile() if member.name == MANIFEST_NAME else member.isdir()
                    require(expected_type and member.mode == expected_mode, f"non-canonical root member {member.name}")
                    continue
                expected_mode = int(entry["mode"], 8)
                require(member.mode == expected_mode, f"mode differs for {member.name}")
                if entry["kind"] == "directory":
                    require(member.isdir() and member.size == 0, f"directory entry differs for {member.name}")
                else:
                    require(member.isfile() and member.size == entry["size_bytes"], f"file size differs for {member.name}")
                    stream = archive.extractfile(member)
                    require(stream is not None, f"file body is absent for {member.name}")
                    data = stream.read()
                    require(digest_bytes(data) == entry["sha256"], f"file digest differs for {member.name}")
            # tarfile stops at the first end marker and otherwise ignores any
            # bytes that follow it.  Bind the exact framing emitted by our
            # deterministic USTAR writer: two zero blocks followed only by
            # zero padding to one RECORDSIZE boundary.
            last = members[-1]
            payload_end = last.offset_data + ((last.size + tarfile.BLOCKSIZE - 1) // tarfile.BLOCKSIZE) * tarfile.BLOCKSIZE
            end_markers = payload_end + 2 * tarfile.BLOCKSIZE
            canonical_size = ((end_markers + tarfile.RECORDSIZE - 1) // tarfile.RECORDSIZE) * tarfile.RECORDSIZE
            require(path.stat().st_size == canonical_size, "archive has trailing bytes or non-canonical USTAR framing")
            with path.open("rb") as raw:
                raw.seek(payload_end)
                trailer = raw.read()
            require(trailer == b"\0" * len(trailer), "archive has non-zero bytes after its final member")
    except (OSError, tarfile.TarError) as error:
        raise ArchiveError(f"cannot read archive {path}: {error}") from error
    return digest_file(path), manifest, manifest_bytes


def extract_archive(path: Path, output: Path) -> tuple[str, dict[str, Any]]:
    archive_digest, manifest, _ = verify_archive(path)
    if output.exists():
        require(output.is_dir() and not any(output.iterdir()), f"extraction directory is not empty: {output}")
    else:
        output.mkdir(parents=True)
    with tarfile.open(path, mode="r:") as archive:
        members = {member.name: member for member in archive.getmembers()}
        for entry in manifest["entries"]:
            relative = validate_relative_path(entry["path"])
            destination = output.joinpath(*relative.parts)
            require(
                destination.resolve(strict=False).is_relative_to(output.resolve()),
                "extraction path escaped its root",
            )
            member = members[f"{ROOT_NAME}/{entry['path']}"]
            if entry["kind"] == "directory":
                destination.mkdir(parents=True, exist_ok=False)
            else:
                destination.parent.mkdir(parents=True, exist_ok=True)
                stream = archive.extractfile(member)
                require(stream is not None, f"file body is absent for {member.name}")
                with destination.open("xb") as target:
                    while chunk := stream.read(1024 * 1024):
                        target.write(chunk)
            os.chmod(destination, int(entry["mode"], 8), follow_symlinks=False)
    return archive_digest, manifest


def build_command(options: argparse.Namespace) -> None:
    root = options.input.resolve(strict=True)
    epoch = options.epoch
    options.out_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="wasm-biotic-archive-", dir=options.out_root) as temporary:
        candidate = Path(temporary) / "candidate.tar"
        digest, _ = write_archive(root, candidate, epoch)
        destination = options.out_root / f"sha256-{digest[7:]}.tar"
        if destination.exists():
            require(digest_file(destination) == digest, f"existing archive at {destination} has wrong bytes")
        else:
            os.replace(candidate, destination)
        verify_archive(destination)
    print(f"{digest} {destination}")


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(description=__doc__)
    subcommands = command.add_subparsers(dest="command", required=True)
    build = subcommands.add_parser("build", help="build a deterministic content-addressed tar")
    build.add_argument("--input", required=True, type=Path)
    build.add_argument("--out-root", required=True, type=Path)
    build.add_argument(
        "--epoch",
        type=int,
        default=int(os.environ.get("SOURCE_DATE_EPOCH", "0")),
        help="fixed non-negative archive timestamp (default SOURCE_DATE_EPOCH or zero)",
    )
    verify = subcommands.add_parser("verify", help="verify archive closure, bytes, modes and metadata")
    verify.add_argument("archive", type=Path)
    extract = subcommands.add_parser("extract", help="verify and safely extract an archive")
    extract.add_argument("archive", type=Path)
    extract.add_argument("--out", required=True, type=Path)
    return command


def main(arguments: list[str] | None = None) -> int:
    options = parser().parse_args(arguments)
    try:
        if options.command == "build":
            build_command(options)
        elif options.command == "verify":
            digest, manifest, _ = verify_archive(options.archive)
            print(f"verified {digest} entries={manifest['entry_count']} {options.archive}")
        else:
            digest, manifest = extract_archive(options.archive, options.out)
            print(f"extracted {digest} entries={manifest['entry_count']} {options.out}")
        return 0
    except ArchiveError as error:
        print(f"r4-install-archive: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
