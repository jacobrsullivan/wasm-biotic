#!/usr/bin/env python3
"""Build the closed cross-substrate R3 transport-confinement evidence object."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
from typing import Any

from r3_release_authority import (
    R3AuthorityError,
    canonical_json,
    digest_bytes,
    inspect_r3_http_authority,
    reject_duplicate_keys,
    require,
    require_digest,
    require_fields,
)


CASE_GROUPS = {
    "confinement": [
        "destination-dns-tls",
        "operator-capacity-intersection",
        "path-method-header-body-timeout-redirect",
    ],
    "durability": [
        "dispatch-boundary-indeterminate",
        "prepared-before-dispatch",
        "terminal-restart-replay",
    ],
    "owner": [
        "cross-owner-poll-cancel",
        "graph-principal-alias-constraint",
        "idempotency-request-conflict",
    ],
    "secret_non_observation": [
        "exact-prefix-injection",
        "no-journal-log-receipt-or-response-secret",
        "opaque-handle-only",
    ],
    "non_retry": [
        "cancel-before-dispatch-only",
        "indeterminate-never-redispatch",
        "single-native-dispatch",
    ],
}

EXPECTED_TRANSCRIPTS = {
    "kernel-r3-http-production": {
        "local::http_tests::credential_is_injected_only_after_authorization_and_reflection_never_persists",
        "local::http_tests::dispatch_boundary_restart_becomes_indeterminate_and_never_retries",
        "local::http_tests::prepared_operation_can_only_be_cancelled_before_dispatch",
        "local::http_tests::production_tls_dispatch_is_durable_owned_and_replayed_without_resend",
    },
    "independent-r3-http-confinement": {
        "transport::tests::cancellation_and_recovery_are_terminal_and_never_delete_identity",
        "transport::tests::concurrency_and_credential_expansion_are_bounded_before_send",
        "transport::tests::mixed_dns_answer_sets_fail_closed_and_exact_sets_are_sorted",
        "transport::tests::operation_ownership_and_dispatch_recovery_fail_closed",
        "transport::tests::operator_capacity_is_explicit_closed_and_intersected_with_signed_authority",
        "transport::tests::path_credential_and_response_representation_edge_cases_fail_closed",
        "transport::tests::public_only_rejects_special_ipv6_ranges",
        "transport::tests::reflection_search_is_exact_and_der_reader_fails_closed",
        "transport::tests::static_bounds_credentials_and_exact_replay_are_enforced_before_dispatch",
    },
    "independent-r3-http-wit-boundary": {
        "substrate::tests::r3_http_is_disabled_without_explicit_operator_capacity",
        "substrate::tests::r3_wit_http_boundary_uses_the_signed_alias_and_async_journal",
    },
    "independent-r3-package-admission": {
        "package::tests::r3_http_constraint_rejects_bounds_dns_paths_headers_and_unknown_fields",
        "package::tests::r3_profile_and_closed_http_constraints_are_exactly_projected",
    },
    "compiled-exchange-r3-http-adapter": {
        "compiled_component_assigns_rejection_meaning_to_opaque_http_status",
        "compiled_component_latches_unknown_outcome_and_never_resends",
        "compiled_component_owns_http_request_status_and_exact_replay_policy",
        "compiled_component_rejects_expired_prepared_replay_without_resigning_or_resending",
        "compiled_component_resumes_one_durable_operation_after_poll_budget",
        "compiled_component_resumes_pre_start_outbox_without_resigning",
    },
}

EXPECTED_COMMANDS = {
    "kernel-r3-http-production": [
        "cargo",
        "test",
        "--locked",
        "--offline",
        "--manifest-path",
        "kernel/Cargo.toml",
        "--lib",
        "local::http_tests::",
        "--",
        "--nocapture",
    ],
    "independent-r3-http-confinement": [
        "cargo",
        "test",
        "--locked",
        "--offline",
        "--manifest-path",
        "tools/independent-substrate/Cargo.toml",
        "--lib",
        "transport::tests::",
        "--",
        "--nocapture",
    ],
    "independent-r3-http-wit-boundary": [
        "cargo",
        "test",
        "--locked",
        "--offline",
        "--manifest-path",
        "tools/independent-substrate/Cargo.toml",
        "--lib",
        "substrate::tests::r3_",
        "--",
        "--nocapture",
    ],
    "independent-r3-package-admission": [
        "cargo",
        "test",
        "--locked",
        "--offline",
        "--manifest-path",
        "tools/independent-substrate/Cargo.toml",
        "--lib",
        "package::tests::r3_",
        "--",
        "--nocapture",
    ],
    "compiled-exchange-r3-http-adapter": [
        "cargo",
        "test",
        "--locked",
        "--offline",
        "--manifest-path",
        "components/Cargo.toml",
        "-p",
        "wasm-biotic-exchange-service",
        "--test",
        "wasm_adapter",
        "--",
        "--nocapture",
    ],
}

TRANSCRIPT_FIELDS = {
    "schema",
    "id",
    "command",
    "cwd",
    "exit_code",
    "passed_test_identities",
    "tests_passed",
    "tests_failed",
}

SIGNED_GATE_FIELDS = {
    "schema",
    "cases",
    "constraint_digest",
    "graph_manifest_digest",
    "http_authority_trace_entries",
    "native_tcb_inventory_digest",
}

SIGNED_GATE_CASES = [
    {"case_id": "r3-http-confinement", "passed": True},
    {"case_id": "r3-http-durability-replay", "passed": True},
    {"case_id": "r3-http-owner-isolation", "passed": True},
    {"case_id": "r3-http-secret-non-observation", "passed": True},
    {"case_id": "r3-http-indeterminate-no-retry", "passed": True},
]

PEER_REPORT_FIELDS = {
    "schema",
    "body_sha256",
    "body_size_bytes",
    "component_header_names",
    "credential_header_exact",
    "framing_header_names",
    "observed_header_order",
    "request_line",
    "result",
    "tls_cipher",
    "tls_version",
}


class ReportError(R3AuthorityError):
    pass


def read_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        data = path.read_bytes()
        value = json.loads(data, object_pairs_hook=reject_duplicate_keys)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReportError(f"cannot read {label} at {path}: {error}") from error
    require(isinstance(value, dict), f"{label} must be a JSON object")
    return value, data


def file_digest(path: Path) -> str:
    return digest_bytes(path.read_bytes())


def package_facts(directory: Path, label: str) -> dict[str, Any]:
    package, _ = read_json(directory / "package.json", f"{label} package index")
    manifest, manifest_bytes = read_json(directory / "manifest.json", f"{label} manifest")
    profile, profile_bytes = read_json(directory / "substrate-profile.json", f"{label} profile")
    certificate, _ = read_json(
        directory / "certification/release-certification.json", f"{label} certificate"
    )
    graph = digest_bytes(manifest_bytes)
    require(package.get("graph_manifest_digest") == graph, f"{label} package manifest binding differs")
    statement = certificate.get("statement")
    require(isinstance(statement, dict), f"{label} certificate statement is absent")
    require(
        statement.get("substrate_profile_digest") == digest_bytes(profile_bytes),
        f"{label} certificate profile binding differs",
    )
    authority = inspect_r3_http_authority(directory, profile, manifest, statement, label)
    nodes = manifest.get("nodes")
    require(isinstance(nodes, list), f"{label} manifest nodes are absent")
    exchange = [
        node
        for node in nodes
        if isinstance(node, dict) and node.get("id") == "exchange-service"
    ]
    require(len(exchange) == 1, f"{label} does not contain one exchange-service")
    component_digest = require_digest(
        exchange[0].get("component_digest"), f"{label} exchange digest"
    )
    native_tcb_inventory_digest = require_digest(
        statement.get("native_tcb_inventory_digest"),
        f"{label} native TCB inventory digest",
    )
    component_path = directory / "components" / (component_digest.replace(":", "-", 1) + ".wasm")
    require(file_digest(component_path) == component_digest, f"{label} exchange bytes differ")
    constraint_path = directory / "constraints" / (
        authority["constraint_digest"].replace(":", "-", 1) + ".json"
    )
    constraint, _ = read_json(constraint_path, f"{label} HTTP constraint")
    credentials = constraint.get("credential_bindings")
    require(isinstance(credentials, list), f"{label} credential bindings are absent")
    prefixes = sorted(
        {
            binding.get("value_prefix")
            for binding in credentials
            if isinstance(binding, dict) and isinstance(binding.get("value_prefix"), str)
        }
    )
    return {
        "component_digest": component_digest,
        "component_path": component_path,
        "constraint_digest": authority["constraint_digest"],
        "credential_value_prefixes": prefixes,
        "graph_manifest_digest": graph,
        "native_tcb_inventory_digest": native_tcb_inventory_digest,
        "profile_digest": digest_bytes(profile_bytes),
    }


def transcript(directory: Path, identifier: str) -> dict[str, Any]:
    path = directory / f"{identifier}.json"
    value, data = read_json(path, f"{identifier} transcript")
    require_fields(value, TRANSCRIPT_FIELDS, f"{identifier} transcript")
    require(
        value.get("schema") == "wasm-biotic.r3-gate-command-transcript.v1",
        f"{identifier} transcript schema differs",
    )
    require(
        data == canonical_json(value) + b"\n",
        f"{identifier} transcript is not the canonical deterministic projection",
    )
    require(value.get("id") == identifier, f"{identifier} transcript id differs")
    require(value.get("command") == EXPECTED_COMMANDS[identifier], f"{identifier} command differs")
    require(value.get("cwd") == ".", f"{identifier} transcript cwd differs")
    require(
        type(value.get("exit_code")) is int
        and value["exit_code"] == 0
        and type(value.get("tests_failed")) is int
        and value["tests_failed"] == 0,
        f"{identifier} did not pass",
    )
    identities = value.get("passed_test_identities")
    require(isinstance(identities, list), f"{identifier} test identities are absent")
    expected_identities = sorted(EXPECTED_TRANSCRIPTS[identifier])
    require(identities == expected_identities, f"{identifier} test identities differ")
    require(
        type(value.get("tests_passed")) is int
        and value["tests_passed"] == len(expected_identities),
        f"{identifier} passing-test count differs",
    )
    return {
        "id": identifier,
        "passed_test_identities": identities,
        "sha256": digest_bytes(data),
        "tests_passed": len(identities),
        "result": "pass",
    }


def parse_gate_log(path: Path, incumbent: dict[str, Any]) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ReportError(f"cannot read signed-package gate log: {error}") from error
    reports: list[dict[str, Any]] = []
    for line in text.splitlines():
        candidate = line.strip()
        if not candidate.startswith("{"):
            continue
        try:
            value = json.loads(candidate, object_pairs_hook=reject_duplicate_keys)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and value.get("schema") == "wasm-biotic.r3-signed-http-gate-report.v1":
            reports.append(value)
    require(len(reports) == 1, "signed-package gate log must contain one exact report")
    report = require_fields(reports[0], SIGNED_GATE_FIELDS, "signed-package gate report")
    require(report.get("graph_manifest_digest") == incumbent["graph_manifest_digest"], "signed gate graph differs")
    require(report.get("constraint_digest") == incumbent["constraint_digest"], "signed gate constraint differs")
    require(
        report.get("native_tcb_inventory_digest")
        == incumbent["native_tcb_inventory_digest"],
        "signed gate native TCB differs",
    )
    cases = report.get("cases")
    require(cases == SIGNED_GATE_CASES, "signed gate case identities or order differ")
    require(
        type(report.get("http_authority_trace_entries")) is int
        and report["http_authority_trace_entries"] >= 2,
        "signed gate lacks start/poll trace",
    )
    return report


def peer_report(path: Path) -> dict[str, Any]:
    value, data = read_json(path, "local TLS peer report")
    require_fields(value, PEER_REPORT_FIELDS, "local TLS peer report")
    require(data == canonical_json(value), "local TLS peer report is not canonical JSON")
    require(value.get("schema") == "wasm-biotic.r3-local-tls-peer-report.v1", "TLS peer schema differs")
    require(value.get("result") == "pass" and value.get("tls_version") == "TLSv1.3", "TLS peer did not pass TLS 1.3")
    require(value.get("credential_header_exact") is True, "TLS peer did not observe exact credential placement")
    require_digest(value.get("body_sha256"), "TLS peer request-body digest")
    require(
        type(value.get("body_size_bytes")) is int
        and 0 < value["body_size_bytes"] <= 1_114_112,
        "TLS peer request-body size is outside the fixture bound",
    )
    require(
        value.get("component_header_names") == ["authorization", "content-type"],
        "TLS peer component-header set differs",
    )
    require(
        value.get("framing_header_names") == ["connection", "content-length", "host"],
        "TLS peer framing-header set differs",
    )
    require(
        value.get("observed_header_order")
        == ["host", "connection", "content-type", "authorization", "content-length"],
        "TLS peer request-header order differs from the production encoder",
    )
    require(value.get("request_line") == "POST /exchange HTTP/1.1", "TLS peer request line differs")
    require(
        isinstance(value.get("tls_cipher"), str) and bool(value["tls_cipher"]),
        "TLS peer cipher is absent",
    )
    return {"sha256": digest_bytes(data), "result": "pass"}


def write(path: Path, value: dict[str, Any]) -> str:
    data = canonical_json(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return digest_bytes(data)


def validate_component(path: Path, wasm_tools: Path) -> None:
    completed = subprocess.run(
        [str(wasm_tools), "validate", str(path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=120,
    )
    require(completed.returncode == 0, "compiled exchange component does not validate")


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(description=__doc__)
    command.add_argument("--incumbent-package", type=Path, required=True)
    command.add_argument("--successor-package", type=Path, required=True)
    command.add_argument("--transcript-dir", type=Path, required=True)
    command.add_argument("--signed-gate-log", type=Path, required=True)
    command.add_argument("--peer-report", type=Path, required=True)
    command.add_argument("--compiled-component", type=Path, required=True)
    command.add_argument("--wasm-tools", type=Path, required=True)
    command.add_argument("--production-out", type=Path, required=True)
    command.add_argument("--independent-out", type=Path, required=True)
    command.add_argument("--out", type=Path, required=True)
    return command


def main(arguments: list[str] | None = None) -> int:
    options = parser().parse_args(arguments)
    try:
        output_paths = {
            options.production_out.resolve(),
            options.independent_out.resolve(),
            options.out.resolve(),
        }
        require(len(output_paths) == 3, "R3 evidence outputs must be three distinct paths")
        incumbent = package_facts(options.incumbent_package.resolve(strict=True), "incumbent R3")
        successor = package_facts(options.successor_package.resolve(strict=True), "successor R3")
        require(incumbent["profile_digest"] == successor["profile_digest"], "R3 profiles differ")
        require(
            incumbent["native_tcb_inventory_digest"]
            == successor["native_tcb_inventory_digest"],
            "R3 package native TCB identities differ",
        )
        compiled = options.compiled_component.resolve(strict=True)
        compiled_digest = file_digest(compiled)
        require(
            compiled_digest == incumbent["component_digest"] == successor["component_digest"],
            "compiled exchange fixture differs from the signed pair",
        )
        validate_component(compiled, options.wasm_tools.resolve(strict=True))
        production_transcript = transcript(options.transcript_dir, "kernel-r3-http-production")
        independent_transcripts = [
            transcript(options.transcript_dir, identifier)
            for identifier in (
                "independent-r3-http-confinement",
                "independent-r3-http-wit-boundary",
                "independent-r3-package-admission",
            )
        ]
        compiled_transcript = transcript(options.transcript_dir, "compiled-exchange-r3-http-adapter")
        signed_gate = parse_gate_log(options.signed_gate_log, incumbent)
        peer = peer_report(options.peer_report)
        graphs = [incumbent["graph_manifest_digest"], successor["graph_manifest_digest"]]
        constraints = [incumbent["constraint_digest"], successor["constraint_digest"]]
        production = {
            "schema": "wasm-biotic.transport-confinement-substrate-report.v1",
            "implementation": "production-kernel",
            "graph_manifest_digests": graphs,
            "http_transport_constraint_digests": constraints,
            "case_groups": CASE_GROUPS,
            "unit_transcript": production_transcript,
            "compiled_component_transcript": compiled_transcript,
            "exact_signed_package_gate": signed_gate,
            "one_shot_tls_peer": peer,
            "remaining_blockers": [],
            "result": "pass",
        }
        independent = {
            "schema": "wasm-biotic.transport-confinement-substrate-report.v1",
            "implementation": "independent-substrate",
            "graph_manifest_digests": graphs,
            "http_transport_constraint_digests": constraints,
            "case_groups": CASE_GROUPS,
            "transcripts": independent_transcripts,
            "remaining_blockers": [],
            "result": "pass",
        }
        production_digest = write(options.production_out, production)
        independent_digest = write(options.independent_out, independent)
        require(
            production_digest != independent_digest,
            "production and independent substrate reports must have distinct identities",
        )
        prefixes = sorted(
            set(incumbent["credential_value_prefixes"])
            | set(successor["credential_value_prefixes"])
        )
        report = {
            "schema": "wasm-biotic.transport-confinement.v1",
            "claim_profile": "r3-bounded-external-transport-v1",
            "incumbent_graph_manifest_digest": graphs[0],
            "successor_graph_manifest_digest": graphs[1],
            "capability_profile_digest": incumbent["profile_digest"],
            "incumbent_http_transport_constraint_digest": constraints[0],
            "successor_http_transport_constraint_digest": constraints[1],
            "production_kernel": {
                "implementation": "production-kernel",
                "graph_manifest_digests": graphs,
                "http_transport_constraint_digests": constraints,
                "case_groups": CASE_GROUPS,
                "report_digest": production_digest,
                "result": "pass",
            },
            "independent_substrate": {
                "implementation": "independent-substrate",
                "graph_manifest_digests": graphs,
                "http_transport_constraint_digests": constraints,
                "case_groups": CASE_GROUPS,
                "report_digest": independent_digest,
                "result": "pass",
            },
            "compiled_exchange_component": {
                "component_id": "exchange-service",
                "incumbent_component_digest": incumbent["component_digest"],
                "successor_component_digest": successor["component_digest"],
                "component_type_checked": True,
                "request_formation_component_owned": True,
                "response_interpretation_component_owned": True,
                "retry_cancel_fallback_component_owned": True,
                "native_provider_logic_absent": True,
                "credential_value_prefixes": prefixes,
                "result": "pass",
            },
            "remaining_blockers": [],
            "report_complete": True,
            "result": "pass",
        }
        report_digest = write(options.out, report)
        print(json.dumps({"report": str(options.out), "sha256": report_digest, "result": "pass"}, sort_keys=True))
        return 0
    except (OSError, ReportError, R3AuthorityError, subprocess.SubprocessError) as error:
        print(f"r3-transport-confinement-report: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
