#!/usr/bin/env python3
"""Focused producer/consumer compatibility tests for the R3 transport report."""

from __future__ import annotations

import copy
from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


TOOLS = Path(__file__).parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))


def load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, TOOLS / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


REPORT = load("r3_transport_confinement_report", "r3-transport-confinement-report.py")
PEER = load("r3_local_tls_peer_for_report", "r3-local-tls-peer.py")
BUNDLE = load("component_release_bundle_for_r3_report", "component-release-bundle.py")
GATES = load("r1_release_gate_reports_for_r3_report", "r1-release-gate-reports.py")


def digest(label: str) -> str:
    return REPORT.digest_bytes(label.encode("utf-8"))


def exact_transcript(identifier: str) -> dict:
    identities = sorted(REPORT.EXPECTED_TRANSCRIPTS[identifier])
    return {
        "schema": "wasm-biotic.r3-gate-command-transcript.v1",
        "id": identifier,
        "command": REPORT.EXPECTED_COMMANDS[identifier],
        "cwd": ".",
        "exit_code": 0,
        "passed_test_identities": identities,
        "tests_passed": len(identities),
        "tests_failed": 0,
    }


def write_transcript(directory: Path, identifier: str, value: dict | None = None) -> Path:
    selected = exact_transcript(identifier) if value is None else value
    path = directory / f"{identifier}.json"
    path.write_bytes(REPORT.canonical_json(selected) + b"\n")
    return path


def signed_gate(incumbent: dict) -> dict:
    return {
        "schema": "wasm-biotic.r3-signed-http-gate-report.v1",
        "cases": copy.deepcopy(REPORT.SIGNED_GATE_CASES),
        "constraint_digest": incumbent["constraint_digest"],
        "graph_manifest_digest": incumbent["graph_manifest_digest"],
        "http_authority_trace_entries": 4,
        "native_tcb_inventory_digest": incumbent["native_tcb_inventory_digest"],
    }


def peer_facts() -> dict:
    secret = b"fixture-secret-123456"
    body = b'{"schema":"test"}'
    request = (
        b"POST /exchange HTTP/1.1\r\n"
        b"Host: 127.0.0.1:18443\r\n"
        b"Connection: close\r\n"
        b"content-type: application/json\r\n"
        b"authorization: Bearer "
        + secret
        + b"\r\nContent-Length: "
        + str(len(body)).encode()
        + b"\r\n\r\n"
        + body
    )
    facts = PEER.inspect_request(request, "127.0.0.1", 18443, "/exchange", secret)
    facts.update(
        {
            "schema": "wasm-biotic.r3-local-tls-peer-report.v1",
            "tls_cipher": "TLS_AES_256_GCM_SHA384",
            "tls_version": "TLSv1.3",
        }
    )
    return facts


class TranscriptCompatibilityTests(unittest.TestCase):
    def test_expected_commands_match_the_current_gate_inventory(self) -> None:
        commands = {
            identifier: command
            for identifier, command, _count, _group in GATES.command_specs("R3")
        }
        self.assertEqual(
            {identifier: commands[identifier] for identifier in REPORT.EXPECTED_COMMANDS},
            REPORT.EXPECTED_COMMANDS,
        )

    def test_current_gate_transcripts_are_accepted_exactly(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for identifier in REPORT.EXPECTED_TRANSCRIPTS:
                with self.subTest(identifier=identifier):
                    path = write_transcript(directory, identifier)
                    projection = REPORT.transcript(directory, identifier)
                    self.assertEqual(projection["tests_passed"], len(REPORT.EXPECTED_TRANSCRIPTS[identifier]))
                    self.assertEqual(projection["sha256"], REPORT.digest_bytes(path.read_bytes()))

    def test_schema_command_counts_and_canonical_bytes_are_closed(self) -> None:
        identifier = "kernel-r3-http-production"
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            mutations = []
            wrong_schema = exact_transcript(identifier)
            wrong_schema["schema"] = "wasm-biotic.r2-gate-command-transcript.v1"
            mutations.append(("schema", wrong_schema, None))
            wrong_command = exact_transcript(identifier)
            wrong_command["command"] = [*wrong_command["command"], "--ignored"]
            mutations.append(("command", wrong_command, None))
            wrong_count = exact_transcript(identifier)
            wrong_count["tests_passed"] -= 1
            mutations.append(("count", wrong_count, None))
            extra_field = exact_transcript(identifier)
            extra_field["ambient"] = True
            mutations.append(("field closure", extra_field, None))
            mutations.append(("canonical bytes", exact_transcript(identifier), b" "))
            for label, value, suffix in mutations:
                with self.subTest(label=label):
                    path = write_transcript(directory, identifier, value)
                    if suffix is not None:
                        path.write_bytes(path.read_bytes() + suffix)
                    with self.assertRaises(REPORT.R3AuthorityError):
                        REPORT.transcript(directory, identifier)


class RuntimeEvidenceCompatibilityTests(unittest.TestCase):
    def incumbent(self) -> dict:
        return {
            "graph_manifest_digest": digest("incumbent graph"),
            "constraint_digest": digest("incumbent HTTP constraint"),
            "native_tcb_inventory_digest": digest("native TCB"),
        }

    def test_signed_gate_requires_the_exact_closed_case_campaign(self) -> None:
        incumbent = self.incumbent()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "gate.log"
            exact = signed_gate(incumbent)
            path.write_text("cargo output\n" + json.dumps(exact) + "\n", encoding="utf-8")
            self.assertEqual(REPORT.parse_gate_log(path, incumbent), exact)

            mutations = []
            repeated = copy.deepcopy(exact)
            repeated["cases"][-1] = copy.deepcopy(repeated["cases"][0])
            mutations.append(("repeated case", repeated))
            extra = copy.deepcopy(exact)
            extra["ambient"] = "not signed"
            mutations.append(("extra field", extra))
            boolean_trace = copy.deepcopy(exact)
            boolean_trace["http_authority_trace_entries"] = True
            mutations.append(("boolean trace count", boolean_trace))
            for label, value in mutations:
                with self.subTest(label=label):
                    path.write_text(json.dumps(value) + "\n", encoding="utf-8")
                    with self.assertRaises(REPORT.R3AuthorityError):
                        REPORT.parse_gate_log(path, incumbent)

    def test_local_peer_output_is_compatible_and_secret_fields_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "peer.json"
            exact = peer_facts()
            path.write_bytes(REPORT.canonical_json(exact))
            projection = REPORT.peer_report(path)
            self.assertEqual(projection["result"], "pass")
            self.assertEqual(projection["sha256"], REPORT.digest_bytes(path.read_bytes()))

            mutations = []
            leaked = copy.deepcopy(exact)
            leaked["credential"] = "fixture-secret-123456"
            mutations.append(("secret-bearing extra field", leaked, b""))
            reordered = copy.deepcopy(exact)
            reordered["observed_header_order"] = sorted(reordered["observed_header_order"])
            mutations.append(("wire-order drift", reordered, b""))
            mutations.append(("noncanonical trailing newline", exact, b"\n"))
            for label, value, suffix in mutations:
                with self.subTest(label=label):
                    path.write_bytes(REPORT.canonical_json(value) + suffix)
                    with self.assertRaises(REPORT.R3AuthorityError):
                        REPORT.peer_report(path)

    def test_local_peer_rejects_credential_bytes_outside_authorization(self) -> None:
        secret = b"fixture-secret-123456"
        body = b'{"leaked":"fixture-secret-123456"}'
        request = (
            b"POST /exchange HTTP/1.1\r\n"
            b"Host: 127.0.0.1:18443\r\n"
            b"Connection: close\r\n"
            b"content-type: application/json\r\n"
            b"authorization: Bearer "
            + secret
            + b"\r\nContent-Length: "
            + str(len(body)).encode()
            + b"\r\n\r\n"
            + body
        )
        with self.assertRaisesRegex(PEER.PeerError, "escaped into the exchange envelope"):
            PEER.inspect_request(request, "127.0.0.1", 18443, "/exchange", secret)


class AggregateProducerTests(unittest.TestCase):
    def test_main_emits_the_frozen_aggregate_and_binds_compiled_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            incumbent_directory = root / "incumbent"
            successor_directory = root / "successor"
            transcript_directory = root / "transcripts"
            incumbent_directory.mkdir()
            successor_directory.mkdir()
            transcript_directory.mkdir()
            for identifier in REPORT.EXPECTED_TRANSCRIPTS:
                write_transcript(transcript_directory, identifier)

            compiled = root / "exchange-service.wasm"
            compiled.write_bytes(b"compiled exchange fixture")
            wasm_tools = root / "wasm-tools"
            wasm_tools.write_bytes(b"fixture")
            component_digest = REPORT.file_digest(compiled)
            incumbent = {
                "component_digest": component_digest,
                "constraint_digest": digest("incumbent HTTP constraint"),
                "credential_value_prefixes": ["Bearer "],
                "graph_manifest_digest": digest("incumbent graph"),
                "native_tcb_inventory_digest": digest("native TCB"),
                "profile_digest": digest("R3 profile"),
            }
            successor = {
                **incumbent,
                "constraint_digest": digest("successor HTTP constraint"),
                "graph_manifest_digest": digest("successor graph"),
            }
            gate_log = root / "gate.log"
            gate_log.write_text(json.dumps(signed_gate(incumbent)) + "\n", encoding="utf-8")
            peer_path = root / "peer.json"
            peer_path.write_bytes(REPORT.canonical_json(peer_facts()))
            production_path = root / "production.json"
            independent_path = root / "independent.json"
            aggregate_path = root / "aggregate.json"
            arguments = [
                "--incumbent-package",
                str(incumbent_directory),
                "--successor-package",
                str(successor_directory),
                "--transcript-dir",
                str(transcript_directory),
                "--signed-gate-log",
                str(gate_log),
                "--peer-report",
                str(peer_path),
                "--compiled-component",
                str(compiled),
                "--wasm-tools",
                str(wasm_tools),
                "--production-out",
                str(production_path),
                "--independent-out",
                str(independent_path),
                "--out",
                str(aggregate_path),
            ]
            with redirect_stdout(io.StringIO()), mock.patch.object(
                REPORT, "package_facts", side_effect=[incumbent, successor]
            ), mock.patch.object(REPORT, "validate_component") as validate:
                self.assertEqual(REPORT.main(arguments), 0)
            validate.assert_called_once_with(compiled.resolve(), wasm_tools.resolve())

            aggregate_bytes = aggregate_path.read_bytes()
            identities = {
                "incumbent_graph_manifest_digest": incumbent["graph_manifest_digest"],
                "successor_graph_manifest_digest": successor["graph_manifest_digest"],
                "capability_profile_digest": incumbent["profile_digest"],
                "incumbent_http_transport_constraint_digest": incumbent["constraint_digest"],
                "successor_http_transport_constraint_digest": successor["constraint_digest"],
            }
            BUNDLE.validate_transport_confinement_report(
                aggregate_bytes, identities, "generated R3 transport evidence"
            )
            aggregate = json.loads(aggregate_bytes)
            self.assertEqual(
                aggregate["production_kernel"]["report_digest"],
                REPORT.digest_bytes(production_path.read_bytes()),
            )
            self.assertEqual(
                aggregate["independent_substrate"]["report_digest"],
                REPORT.digest_bytes(independent_path.read_bytes()),
            )
            production = json.loads(production_path.read_bytes())
            self.assertEqual(
                production["compiled_component_transcript"]["id"],
                "compiled-exchange-r3-http-adapter",
            )

    def test_output_paths_must_not_alias(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "same.json"
            with redirect_stderr(io.StringIO()), mock.patch.object(
                REPORT, "package_facts"
            ) as package_facts:
                result = REPORT.main(
                    [
                        "--incumbent-package",
                        temporary,
                        "--successor-package",
                        temporary,
                        "--transcript-dir",
                        temporary,
                        "--signed-gate-log",
                        str(path),
                        "--peer-report",
                        str(path),
                        "--compiled-component",
                        str(path),
                        "--wasm-tools",
                        str(path),
                        "--production-out",
                        str(path),
                        "--independent-out",
                        str(path),
                        "--out",
                        str(path),
                    ]
                )
            self.assertEqual(result, 1)
            package_facts.assert_not_called()


if __name__ == "__main__":
    unittest.main()
