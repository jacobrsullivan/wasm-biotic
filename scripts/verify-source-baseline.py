#!/usr/bin/env python3
"""Recompute the signed project-source closure from its immutable Git import."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
from typing import Any


class BaselineError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise BaselineError(message)


def load_snapshot_tool(repository: Path) -> Any:
    path = repository / "tools" / "r4-source-snapshot.py"
    spec = importlib.util.spec_from_file_location("wasm_biotic_r4_source_snapshot", path)
    require(spec is not None and spec.loader is not None, "cannot load source-snapshot verifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def safe_extract(archive: Path, output: Path) -> None:
    with tarfile.open(archive, "r:") as source:
        for member in source.getmembers():
            path = Path(member.name)
            require(not path.is_absolute() and ".." not in path.parts, "Git archive contains an unsafe path")
            require(member.isfile() or member.isdir(), "Git archive contains a non-regular member")
            destination = output / path
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            stream = source.extractfile(member)
            require(stream is not None, f"cannot read archived file {member.name}")
            destination.write_bytes(stream.read())
            destination.chmod(member.mode & 0o777)


def main() -> int:
    repository = Path(__file__).resolve().parents[1]
    try:
        lock = json.loads((repository / "tools" / "verification-lock.json").read_text())
        commit = lock["baseline_commit"]
        subprocess.run(
            ["git", "cat-file", "-e", f"{commit}^{{commit}}"],
            cwd=repository,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        with tempfile.TemporaryDirectory(prefix="wasm-biotic-source-baseline-") as temporary:
            base = Path(temporary)
            archive = base / "baseline.tar"
            checkout = base / "checkout"
            checkout.mkdir()
            subprocess.run(
                ["git", "archive", "--format=tar", f"--output={archive}", commit],
                cwd=repository,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            safe_extract(archive, checkout)
            # Recompute the signed closure with the selector that was itself
            # archived in the immutable baseline, never mutable branch-tip
            # code.
            tool = load_snapshot_tool(checkout)
            inventory = []
            for path in tool.selected_source_files(checkout):
                relative = path.relative_to(checkout).as_posix()
                inventory.append(
                    {
                        "mode": f"{tool.normalized_mode(path):04o}",
                        "path": relative,
                        "sha256": "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(),
                        "size_bytes": path.stat().st_size,
                    }
                )
            manifest_bytes = (checkout / "SOURCE-SNAPSHOT.json").read_bytes()
            manifest = json.loads(manifest_bytes)
            require(tool.canonical_json(manifest) == manifest_bytes, "archived source manifest is not canonical")
            require(len(inventory) == manifest["source_file_count"] == 325, "source file count differs")
            require(tool.closure_digest(inventory) == manifest["source_closure_sha256"], "source closure differs")
            require(
                "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()
                == "sha256:db64731d0e461bf3e146e30702c45fff9547f3ba9fb89f73385b8b15471e2716",
                "source snapshot identity differs",
            )
    except (BaselineError, KeyError, OSError, json.JSONDecodeError, subprocess.SubprocessError) as error:
        detail = getattr(error, "stderr", b"")
        if isinstance(detail, bytes):
            detail = detail.decode("utf-8", errors="replace")
        print(f"verify-source-baseline: {detail.strip() or error}", file=sys.stderr)
        return 1
    print(f"verified signed 325-file project closure from baseline commit {commit}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
