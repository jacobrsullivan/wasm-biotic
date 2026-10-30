#!/usr/bin/env python3
"""Verify the clean-checkout toolchain, lock topology and credential hygiene."""

from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys


class PreflightError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PreflightError(message)


def run(arguments: list[str], repository: Path) -> str:
    try:
        result = subprocess.run(
            arguments,
            cwd=repository,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.SubprocessError) as error:
        detail = getattr(error, "stderr", "") or str(error)
        raise PreflightError(f"{' '.join(arguments)} failed: {detail.strip()}") from error
    return result.stdout.strip()


def version_field(output: str, name: str) -> str:
    match = re.search(rf"^{re.escape(name)}: (.+)$", output, re.MULTILINE)
    require(match is not None, f"version output has no {name}")
    return match.group(1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-wasm-tools", action="store_true")
    options = parser.parse_args()
    repository = Path(__file__).resolve().parents[1]
    try:
        lock = json.loads((repository / "tools" / "verification-lock.json").read_text())
        rustc = run(["rustc", "-Vv"], repository)
        cargo = run(["cargo", "-Vv"], repository)
        require(version_field(rustc, "release") == lock["rustc_release"], "rustc release differs")
        require(version_field(rustc, "commit-hash") == lock["rustc_commit"], "rustc commit differs")
        require(version_field(cargo, "release") == lock["cargo_release"], "Cargo release differs")
        require(version_field(cargo, "commit-hash") == lock["cargo_commit"], "Cargo commit differs")

        actual_locks = sorted(
            path.relative_to(repository).as_posix()
            for path in repository.rglob("Cargo.lock")
            if not {".git", "target", "vendor", ".worktrees"}.intersection(path.parts)
        )
        require(actual_locks == lock["lockfiles"], "Cargo lockfile inventory differs")
        for manifest in lock["effective_cargo_manifests"]:
            path = repository / manifest
            require(path.is_file() and not path.is_symlink(), f"Cargo universe is absent or linked: {manifest}")
            run(
                [
                    "cargo",
                    "metadata",
                    "--locked",
                    "--no-deps",
                    "--format-version",
                    "1",
                    "--manifest-path",
                    str(path),
                ],
                repository,
            )

        tracked = run(["git", "ls-files"], repository).splitlines()
        tracked_env = sorted(path for path in tracked if PurePosixPath(path).name == ".env")
        require(not tracked_env, f"tracked .env files are forbidden: {tracked_env}")
        ignored = subprocess.run(
            ["git", "check-ignore", "-q", ".env"], cwd=repository, check=False
        )
        require(ignored.returncode == 0, ".env is not ignored")
        example = (repository / ".env.example").read_text()
        require("replace_with_" in example and "sk-" not in example, ".env.example is not placeholder-only")

        if options.require_wasm_tools:
            observed = run(["wasm-tools", "--version"], repository)
            require(observed == f"wasm-tools {lock['wasm_tools_release']}", "wasm-tools release differs")
    except (KeyError, OSError, json.JSONDecodeError, PreflightError) as error:
        print(f"verify-preflight: {error}", file=sys.stderr)
        return 1
    print("verified toolchain, Cargo universes, lockfiles and credential hygiene")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
