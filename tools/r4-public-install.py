#!/usr/bin/env python3
"""Verify a clean R4 install and lifecycle using public inputs only.

The selected production kernel performs init/admission/bootstrap and negative
checks.  The separately attested lifecycle runner then drives component-owned
upgrade and rollback policy against a fresh state directory.  This orchestrator
accepts no private-key argument and records no physical input paths.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
from typing import Any


SCHEMA = "wasm-biotic.r4-public-install-lifecycle.v1"
LIFECYCLE_SCHEMA = "wasm-biotic.public-key-only-component-lifecycle.v1"
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
PUBLIC_KEY_RE = re.compile(r"[0-9a-f]{64}\Z")
WITNESS_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")


class InstallError(RuntimeError):
    """A public-only installation or lifecycle assertion failed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise InstallError(message)


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
    output: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in output, f"JSON contains duplicate key {key!r}")
        output[key] = value
    return output


def read_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        data = path.read_bytes()
        value = json.loads(data, object_pairs_hook=reject_duplicate_keys)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise InstallError(f"cannot read {label} at {path}: {error}") from error
    require(isinstance(value, dict), f"{label} must be a JSON object")
    require(canonical_json(value) == data, f"{label} must be canonical JSON")
    return value, data


def run_command(
    label: str,
    arguments: list[str],
    *,
    expected_success: bool,
    input_bytes: bytes | None = None,
) -> dict[str, Any]:
    try:
        result = subprocess.run(
            arguments,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=600,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise InstallError(f"cannot execute {label}: {error}") from error
    require(result.returncode >= 0, f"{label} terminated by a signal instead of returning a semantic result")
    success = result.returncode == 0
    if not expected_success:
        require(result.returncode <= 125, f"{label} failed to execute cleanly instead of returning a semantic rejection")
    require(success == expected_success, f"{label} returned {result.returncode}, expected {'success' if expected_success else 'rejection'}")
    return {
        "exit_code": result.returncode,
        "expected": "success" if expected_success else "rejection",
        "label": label,
        "stderr_sha256": digest_bytes(result.stderr),
        "stderr_size_bytes": len(result.stderr),
        "stdout_sha256": digest_bytes(result.stdout),
        "stdout_size_bytes": len(result.stdout),
    }


def require_fresh_directory(path: Path) -> None:
    require(not path.exists(), f"fresh work root already exists: {path}")
    path.mkdir(parents=True)


def verify_extracted_install(options: argparse.Namespace) -> dict[str, Any]:
    require(
        options.install_archive.is_file() and not options.install_archive.is_symlink(),
        f"install archive is not a regular file: {options.install_archive}",
    )
    require(
        options.archive_tool.is_file() and not options.archive_tool.is_symlink(),
        f"archive verifier is not a regular file: {options.archive_tool}",
    )
    require(
        options.extracted_root.is_dir() and not options.extracted_root.is_symlink(),
        f"extracted install root is not a regular directory: {options.extracted_root}",
    )
    observed = digest_file(options.install_archive)
    require(observed == options.install_archive_sha256, "install archive has the wrong digest")
    spec = importlib.util.spec_from_file_location("wasm_biotic_r4_archive", options.archive_tool)
    require(spec is not None and spec.loader is not None, "cannot load the archive verifier")
    module = importlib.util.module_from_spec(spec)
    # The verifier can live inside the immutable extracted install.  A normal
    # dynamic source import writes ``tools/__pycache__`` there before the exact
    # manifest comparison.  Disable that write for precisely this import and
    # restore the caller's interpreter setting afterward.
    previous_dont_write_bytecode = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous_dont_write_bytecode
    try:
        verified, manifest, _ = module.verify_archive(options.install_archive)
        actual_entries = module.source_entries(options.extracted_root)
    except Exception as error:
        raise InstallError(f"install archive verification failed: {error}") from error
    require(verified == observed, "archive verifier returned a different digest")
    require(actual_entries == manifest["entries"], "extracted install tree differs from the verified archive manifest")
    extracted = options.extracted_root.resolve()
    for label, path in (
        ("kernel", options.kernel),
        ("lifecycle runner", options.lifecycle_runner),
        ("operator capacity", options.operator_capacity),
        ("incumbent package", options.incumbent),
        ("successor package", options.successor),
    ):
        require(path.resolve().is_relative_to(extracted), f"{label} is outside the verified install tree")
    return {
        "entry_count": manifest["entry_count"],
        "extracted_tree_exactly_matches_manifest": True,
        "install_archive_sha256": observed,
        "safe_archive_verifier_passed": True,
    }


def validate_inputs(options: argparse.Namespace) -> tuple[str, str]:
    for label, path in (
        ("kernel", options.kernel),
        ("lifecycle runner", options.lifecycle_runner),
    ):
        require(path.is_file() and not path.is_symlink(), f"{label} is not a regular file: {path}")
        require(path.stat().st_mode & 0o111 != 0, f"{label} is not executable: {path}")
    require(
        options.operator_capacity.is_file()
        and not options.operator_capacity.is_symlink(),
        f"operator capacity is not a regular file: {options.operator_capacity}",
    )
    read_json(options.operator_capacity, "operator capacity")
    for label, path in (("incumbent", options.incumbent), ("successor", options.successor)):
        require(path.is_dir() and not path.is_symlink(), f"{label} package is not a regular directory: {path}")
    require(PUBLIC_KEY_RE.fullmatch(options.public_key_hex) is not None, "public key must be raw lowercase Ed25519 hex")
    require(PUBLIC_KEY_RE.fullmatch(options.wrong_public_key_hex) is not None, "wrong-key fixture must be raw lowercase Ed25519 hex")
    require(options.public_key_hex != options.wrong_public_key_hex, "wrong-key fixture equals the trusted public key")
    require(DIGEST_RE.fullmatch(options.expected_kernel_sha256) is not None, "expected kernel digest is invalid")
    require(DIGEST_RE.fullmatch(options.install_archive_sha256) is not None, "install archive digest is invalid")
    require(
        isinstance(options.witness_id, str)
        and WITNESS_RE.fullmatch(options.witness_id) is not None,
        "physical witness identifier is invalid",
    )
    incumbent = digest_file(options.incumbent / "manifest.json")
    successor = digest_file(options.successor / "manifest.json")
    require(options.incumbent.name == incumbent.replace(":", "-"), "incumbent directory is not manifest-addressed")
    require(options.successor.name == successor.replace(":", "-"), "successor directory is not manifest-addressed")
    return incumbent, successor


def tampered_package(source: Path, destination_root: Path) -> Path:
    destination = destination_root / source.name
    shutil.copytree(source, destination, symlinks=True)
    for path in destination.rglob("*"):
        require(not path.is_symlink(), f"package copy contains a link: {path}")
    target = destination / "factory-root.wasm"
    data = bytearray(target.read_bytes())
    require(data, "factory-root.wasm is empty")
    data[-1] ^= 1
    target.write_bytes(data)
    return destination


def sha256_value(value: Any, label: str) -> str:
    require(
        isinstance(value, dict)
        and value.get("algorithm") == "sha256"
        and isinstance(value.get("hex"), str)
        and re.fullmatch(r"[0-9a-f]{64}", value["hex"]) is not None,
        f"{label} is not a SHA-256 value",
    )
    return "sha256:" + value["hex"]


def validate_exact_replay(value: Any, label: str) -> None:
    require(isinstance(value, dict), f"{label} is not an object")
    for field in (
        "inspect_blob_equal",
        "inspect_bytes_equal",
        "job_id_equal",
        "mechanism_counters_unchanged",
        "mechanism_state_unchanged",
        "output_blob_equal",
        "output_bytes_equal",
        "resubmitted_exact_submit_blob",
    ):
        require(value.get(field) is True, f"{label} did not prove {field}")
    require(
        value.get("mechanism_counters_before")
        == value.get("mechanism_counters_after"),
        f"{label} changed mechanism counters",
    )
    require(
        value.get("mechanism_state_digest_before")
        == value.get("mechanism_state_digest_after"),
        f"{label} changed mechanism state",
    )


def validate_cycle(value: Any, graph_digest: str, label: str) -> None:
    require(isinstance(value, dict), f"{label} is not an object")
    require(value.get("graph_manifest_digest") == graph_digest, f"{label} used the wrong graph")
    terminal = value.get("terminal_result")
    require(
        isinstance(terminal, dict)
        and terminal.get("status") == "completed"
        and terminal.get("failure") is None,
        f"{label} did not complete",
    )
    require(
        set(value.get("execution_completions", {}))
        == {
            "builder",
            "continuity-worker",
            "packager",
            "planner",
            "reviewer",
            "validator",
        },
        f"{label} did not execute the exact worker set",
    )
    validate_exact_replay(value.get("exact_replay"), f"{label} exact replay")


def validate_component_lifecycle(
    value: dict[str, Any],
    *,
    incumbent_digest: str,
    successor_digest: str,
    public_key_hex: str,
    operator_capacity_sha256: str,
) -> None:
    require(value.get("schema") == LIFECYCLE_SCHEMA, "component lifecycle report schema differs")
    require(value.get("outcome") == "pass", "component lifecycle did not pass")
    require(value.get("component_complete_claim") is False, "component lifecycle made an aggregate claim")
    require(value.get("build_performed") is False, "component lifecycle unexpectedly built artifacts")
    require(value.get("signing_performed") is False, "component lifecycle unexpectedly signed artifacts")
    require(value.get("private_signing_key_required_or_read") is False, "component lifecycle read a private key")
    require(value.get("public_key_hex") == public_key_hex, "component lifecycle used a different public key")
    require(
        value.get("operator_capacity_sha256") == operator_capacity_sha256,
        "component lifecycle used a different operator capacity",
    )
    require(
        value.get("certifier_key_id")
        == digest_bytes(bytes.fromhex(public_key_hex)),
        "component lifecycle certifier identity differs",
    )
    incumbent = value.get("incumbent")
    successor = value.get("successor")
    require(
        isinstance(incumbent, dict)
        and incumbent.get("graph_manifest_digest") == incumbent_digest
        and incumbent.get("previous_graph_manifest_digest") is None
        and incumbent.get("signature_and_exact_closure_verified_by_production_admission") is True,
        "component lifecycle incumbent binding differs",
    )
    require(
        isinstance(successor, dict)
        and successor.get("graph_manifest_digest") == successor_digest
        and successor.get("previous_graph_manifest_digest") == incumbent_digest
        and successor.get("signature_and_exact_closure_verified_by_production_admission") is True,
        "component lifecycle successor binding differs",
    )
    inactive = value.get("inactive_successor_admission")
    require(
        isinstance(inactive, dict)
        and inactive.get("active_manifest_before_admission") == incumbent_digest
        and inactive.get("active_manifest_after_admission") == incumbent_digest
        and inactive.get("admitted_successor_manifest_digest") == successor_digest
        and inactive.get("active_manifest_unchanged") is True,
        "component lifecycle did not prove inactive successor admission",
    )
    lifecycle = value.get("lifecycle")
    require(isinstance(lifecycle, dict), "component lifecycle semantics are absent")
    for field in (
        "all_factory_semantics_executed_as_components",
        "component_decided_initial_state_binding",
        "component_decided_rollback",
        "component_decided_successor_activation",
        "graph_qualified_activation_ownership_handoff_verified",
        "principal_mapping_stable_across_restart_activation_and_rollback",
        "restart_preserved_rollback_pair",
    ):
        require(lifecycle.get(field) is True, f"component lifecycle did not prove {field}")
    require(
        lifecycle.get("native_substrate_responsibility")
        == (
            "verified admission, instantiation, metering, opaque persistence, "
            "communication and declared-capability enforcement only"
        ),
        "component lifecycle assigns factory semantics to the native substrate",
    )
    require(
        lifecycle.get("incumbent_graph_manifest_digest") == incumbent_digest
        and lifecycle.get("successor_graph_manifest_digest") == successor_digest,
        "component lifecycle semantic graph binding differs",
    )
    validate_cycle(lifecycle.get("incumbent_cycle"), incumbent_digest, "incumbent cycle")
    validate_cycle(lifecycle.get("successor_cycle"), successor_digest, "successor cycle")
    validate_cycle(
        lifecycle.get("post_rollback_cycle"),
        incumbent_digest,
        "post-rollback cycle",
    )
    upgrade = lifecycle.get("upgrade_result")
    require(isinstance(upgrade, dict), "component lifecycle upgrade result is absent")
    require(
        sha256_value(upgrade.get("previous_graph"), "upgrade previous graph")
        == incumbent_digest
        and sha256_value(upgrade.get("target_graph"), "upgrade target graph")
        == successor_digest
        and sha256_value(
            upgrade.get("committed", {}).get("active_graph"),
            "upgrade committed graph",
        )
        == successor_digest,
        "component lifecycle upgrade graph transition differs",
    )
    rollback = lifecycle.get("rollback_observation_result")
    require(
        isinstance(rollback, dict)
        and rollback.get("action") == "rolled-back"
        and sha256_value(rollback.get("observed_graph"), "rollback observed graph")
        == successor_digest
        and sha256_value(
            rollback.get("status", {}).get("active_graph"),
            "rollback active graph",
        )
        == incumbent_digest
        and rollback.get("status", {}).get("state") == "rolled-back",
        "component lifecycle rollback transition differs",
    )
    state = value.get("state")
    require(
        isinstance(state, dict)
        and state.get("fresh_state_directory_required") is True
        and state.get("restart_reopened_persisted_state") is True
        and state.get("incumbent_bootstrap_manifest_digest") == incumbent_digest
        and state.get("final_active_manifest_digest") == incumbent_digest,
        "component lifecycle final restart state differs",
    )


def build_report(options: argparse.Namespace) -> dict[str, Any]:
    archive_evidence = verify_extracted_install(options)
    incumbent_digest, successor_digest = validate_inputs(options)
    observed_kernel = digest_file(options.kernel)
    require(observed_kernel == options.expected_kernel_sha256, "selected platform kernel has the wrong digest")
    require_fresh_directory(options.work_root)
    bootstrap_state = options.work_root / "bootstrap-state"
    wrong_state = options.work_root / "wrong-key-state"
    tamper_state = options.work_root / "tamper-state"
    lifecycle_state = options.work_root / "lifecycle-state"
    lifecycle_report = options.work_root / "component-lifecycle.json"

    commands: list[dict[str, Any]] = []
    kernel = str(options.kernel)
    commands.append(
        run_command(
            "initialize-fresh-state",
            [
                kernel,
                "init",
                str(bootstrap_state),
                incumbent_digest,
                options.public_key_hex,
                str(options.operator_capacity),
            ],
            expected_success=True,
        )
    )
    commands.append(
        run_command(
            "admit-incumbent",
            [kernel, "admit", str(options.incumbent), str(bootstrap_state)],
            expected_success=True,
        )
    )
    commands.append(
        run_command(
            "bootstrap-incumbent",
            [kernel, "serve", str(options.incumbent), str(bootstrap_state)],
            expected_success=True,
            input_bytes=b"",
        )
    )
    mechanisms_before = digest_file(bootstrap_state / "mechanisms.json")
    commands.append(
        run_command(
            "admit-inactive-successor",
            [kernel, "admit", str(options.successor), str(bootstrap_state)],
            expected_success=True,
        )
    )
    commands.append(
        run_command(
            "reject-unselected-successor-serve",
            [kernel, "serve", str(options.successor), str(bootstrap_state)],
            expected_success=False,
            input_bytes=b"",
        )
    )
    commands.append(
        run_command(
            "incumbent-remains-selected",
            [kernel, "serve", str(options.incumbent), str(bootstrap_state)],
            expected_success=True,
            input_bytes=b"",
        )
    )
    mechanisms_after = digest_file(bootstrap_state / "mechanisms.json")

    commands.append(
        run_command(
            "initialize-wrong-key-state",
            [
                kernel,
                "init",
                str(wrong_state),
                incumbent_digest,
                options.wrong_public_key_hex,
                str(options.operator_capacity),
            ],
            expected_success=True,
        )
    )
    commands.append(
        run_command(
            "reject-wrong-public-key",
            [kernel, "admit", str(options.incumbent), str(wrong_state)],
            expected_success=False,
        )
    )

    tampered = tampered_package(options.incumbent, options.work_root / "tampered-package")
    commands.append(
        run_command(
            "initialize-tamper-state",
            [
                kernel,
                "init",
                str(tamper_state),
                incumbent_digest,
                options.public_key_hex,
                str(options.operator_capacity),
            ],
            expected_success=True,
        )
    )
    commands.append(
        run_command(
            "reject-tampered-package",
            [kernel, "admit", str(tampered), str(tamper_state)],
            expected_success=False,
        )
    )

    commands.append(
        run_command(
            "component-owned-upgrade-rollback-restart",
            [
                str(options.lifecycle_runner),
                "--incumbent",
                str(options.incumbent),
                "--successor",
                str(options.successor),
                "--public-key-hex",
                options.public_key_hex,
                "--operator-capacity",
                str(options.operator_capacity),
                "--state-dir",
                str(lifecycle_state),
                "--out",
                str(lifecycle_report),
            ],
            expected_success=True,
        )
    )
    lifecycle, lifecycle_bytes = read_json(lifecycle_report, "component lifecycle report")
    validate_component_lifecycle(
        lifecycle,
        incumbent_digest=incumbent_digest,
        successor_digest=successor_digest,
        public_key_hex=options.public_key_hex,
        operator_capacity_sha256=digest_file(options.operator_capacity),
    )
    inactive = lifecycle.get("inactive_successor_admission", {})
    require(inactive.get("active_manifest_unchanged") is True, "successor admission was not inactive")

    return {
        "archive": archive_evidence,
        "commands": commands,
        "component_lifecycle_report": lifecycle,
        "component_lifecycle_report_sha256": digest_bytes(lifecycle_bytes),
        "generated_at": dt.datetime.fromtimestamp(options.epoch, dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "host": {
            "architecture": platform.machine(),
            "operating_system": platform.system(),
            "physical_machine": True,
            "release": platform.release(),
            "target": options.target,
            "witness_id": options.witness_id,
        },
        "inactive_admission": {
            "active_mechanism_state_after_sha256": mechanisms_after,
            "active_mechanism_state_before_sha256": mechanisms_before,
            "incumbent_remained_bootable": True,
            "successor_serve_rejected_before_component_activation": True,
        },
        "incumbent_graph_manifest_digest": incumbent_digest,
        "kernel": {
            "expected_sha256": options.expected_kernel_sha256,
            "observed_sha256": observed_kernel,
        },
        "negative_controls": {
            "automatic_successor_activation_rejected": True,
            "tampered_package_rejected": True,
            "wrong_public_key_rejected": True,
        },
        "operator_capacity": {
            "observed_sha256": digest_file(options.operator_capacity),
            "within_verified_install": True,
        },
        "outcome": "pass",
        "private_key_argument_supported": False,
        "private_key_required_or_read": False,
        "schema": SCHEMA,
        "successor_graph_manifest_digest": successor_digest,
    }


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(description=__doc__)
    command.add_argument("--kernel", required=True, type=Path)
    command.add_argument("--expected-kernel-sha256", required=True)
    command.add_argument("--incumbent", required=True, type=Path)
    command.add_argument("--successor", required=True, type=Path)
    command.add_argument("--public-key-hex", required=True)
    command.add_argument("--wrong-public-key-hex", required=True)
    command.add_argument("--lifecycle-runner", required=True, type=Path)
    command.add_argument("--operator-capacity", required=True, type=Path)
    command.add_argument("--install-archive", required=True, type=Path)
    command.add_argument("--install-archive-sha256", required=True)
    command.add_argument("--archive-tool", required=True, type=Path)
    command.add_argument("--extracted-root", required=True, type=Path)
    command.add_argument("--work-root", required=True, type=Path)
    command.add_argument("--target", required=True)
    command.add_argument("--witness-id", required=True)
    command.add_argument("--epoch", type=int, default=int(os.environ.get("SOURCE_DATE_EPOCH", "0")))
    command.add_argument("--out", required=True, type=Path)
    return command


def main(arguments: list[str] | None = None) -> int:
    options = parser().parse_args(arguments)
    try:
        report = build_report(options)
        options.out.parent.mkdir(parents=True, exist_ok=True)
        options.out.write_bytes(canonical_json(report))
        print(f"verified {digest_file(options.out)} {options.out}")
        return 0
    except (InstallError, OSError, ValueError) as error:
        print(f"r4-public-install: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
