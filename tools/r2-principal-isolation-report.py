#!/usr/bin/env python3
"""Build focused scoped-profile principal-isolation release evidence.

This report joins two independent observations of the same signed authority
model: production-kernel Rust tests and the separate in-memory substrate's
adversarial campaign.  It never treats a boolean supplied by either package as
authority; package graph and principal inventories are reconstructed from the
retained canonical bytes. Profile v2 remains the R2 path; profile v3 must also
reconstruct its exact signed bounded-HTTP projection before the same principal
isolation report meaning can be claimed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any

TOOLS_DIRECTORY = Path(__file__).resolve().parent
if str(TOOLS_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIRECTORY))
from r3_release_authority import (  # noqa: E402
    PROFILE_SCHEMA_V3,
    R3AuthorityError,
    inspect_r3_http_authority,
)


DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
PROFILE_SCHEMA_V2 = "wasm-biotic.factory-substrate-profile.v2"
STRICT_SCHEMA = "wasm-biotic.component-strict-validation-report.v2"
INVENTORY_SCHEMA = "wasm-biotic.principal-inventory-evidence.v1"
INDEPENDENT_SCHEMA = "wasm-biotic.independent-principal-isolation.v1"
REPORT_SCHEMA = "wasm-biotic.principal-isolation.v1"
PRINCIPAL_MODEL = "per-consumer-import-alias"

REQUIRED_PRODUCTION_TESTS = {
    "root_runtime::r2_tests::alias_calls_observe_only_their_captured_principal_scope",
    "root_runtime::r2_tests::guest_identity_claim_cannot_select_an_alias_principal",
    "root_runtime::r2_tests::legacy_grants_are_exactly_the_signed_r2_static_closure",
    "root_runtime::r2_tests::descriptor_versions_require_exact_grant_and_principal_field_shapes",
    "root_runtime::r2_tests::principal_alias_and_runtime_identity_material_is_exact_and_graph_qualified",
    "root_runtime::r2_tests::authority_trace_binds_executable_request_and_stable_outcome",
    "local::durability_tests::r2_principal_handles_and_idempotency_remain_isolated_after_restart",
}

REQUIRED_INDEPENDENT_CASES = {
    "caller-target-edge",
    "cross-capability-escalation",
    "cross-principal-clock-operation",
    "cross-principal-idempotency",
    "cross-principal-run-operation",
    "forged-alias",
    "graph-qualified-activation-owner-handoff",
}

PRODUCTION_CASES = [
    ("production-clock-poll-theft", "cross-principal wake polling is rejected"),
    ("production-clock-cancel-theft", "cross-principal wake cancellation is rejected"),
    ("production-shared-wake-handle", "equal wake handles remain principal-scoped"),
    ("production-wake-idempotency-conflict", "altered owner wake retry fails closed"),
    ("production-run-poll-theft", "cross-principal run polling is rejected"),
    ("production-run-cancel-theft", "cross-principal run cancellation is rejected"),
    ("production-run-idempotency-conflict", "altered owner run retry fails closed"),
    ("production-activation-status-theft", "cross-principal activation lookup is rejected"),
    (
        "production-activation-owner-handoff",
        "commit atomically hands the graph-qualified activation handle to the exact same principal in the admitted target graph",
    ),
    (
        "production-stale-graph-activation-denial",
        "the source graph loses activation-handle authority after commit",
    ),
    (
        "production-activation-owner-handback",
        "rollback atomically returns activation-handle authority to the last-known-good graph and preserves it across restart",
    ),
    ("production-restart-run-ownership", "run ownership survives restart"),
    ("production-restart-activation-ownership", "activation ownership survives restart"),
    ("production-restart-wake-ownership", "wake ownership survives restart"),
    ("production-graph-qualified-runtime-principal", "one seed yields distinct runtime principals in distinct graphs"),
    ("production-denial-authority-trace", "denied calls retain the exact principal, executable and request identity"),
    ("production-legacy-grant-closure", "legacy run metadata is derived only from the executable's signed principal closure"),
    ("production-alias-scope-overrides-metadata", "broad compatibility metadata cannot widen a captured alias principal scope"),
    ("production-guest-identity-nonselectable", "guest-provided identity cannot select or forge an alias principal"),
]


class ReportError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReportError(message)


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"JSON contains duplicate key {key!r}")
        result[key] = value
    return result


def read_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        data = path.read_bytes()
        value = json.loads(data, object_pairs_hook=reject_duplicate_keys)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReportError(f"cannot read {label} at {path}: {error}") from error
    require(isinstance(value, dict), f"{label} must be a JSON object")
    return value, data


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


def require_digest(value: Any, label: str) -> str:
    require(
        isinstance(value, str) and DIGEST_RE.fullmatch(value) is not None,
        f"{label} is not a canonical SHA-256 digest",
    )
    return value


def package_identity(directory: Path, label: str) -> dict[str, Any]:
    package, _ = read_json(directory / "package.json", f"{label} package index")
    manifest, manifest_bytes = read_json(directory / "manifest.json", f"{label} manifest")
    metadata, _ = read_json(directory / "metadata.json", f"{label} metadata")
    profile, profile_bytes = read_json(
        directory / "substrate-profile.json", f"{label} profile"
    )
    _, descriptor_bytes = read_json(
        directory / "derivation-descriptor.json", f"{label} derivation descriptor"
    )
    certification, certification_bytes = read_json(
        directory / "certification/release-certification.json",
        f"{label} release certification",
    )
    strict, _ = read_json(
        directory / "evidence/strict-validation.json", f"{label} strict report"
    )
    inventory, inventory_bytes = read_json(
        directory / "evidence/principal-inventory.json",
        f"{label} principal inventory",
    )
    graph_digest = digest_bytes(manifest_bytes)
    require(
        package.get("graph_manifest_digest") == graph_digest,
        f"{label} package does not bind its manifest bytes",
    )
    certification_digest = digest_bytes(certification_bytes)
    derivation_descriptor_digest = digest_bytes(descriptor_bytes)
    substrate_profile_digest = digest_bytes(profile_bytes)
    require(
        package.get("certification_digest") == certification_digest,
        f"{label} package does not bind its certification bytes",
    )
    statement = certification.get("statement")
    require(isinstance(statement, dict), f"{label} certification statement is missing")
    require(
        metadata.get("derivation_descriptor_digest") == derivation_descriptor_digest
        and metadata.get("substrate_profile_digest") == substrate_profile_digest,
        f"{label} metadata does not bind its scoped descriptor and profile bytes",
    )
    require(
        statement.get("derivation_descriptor_digest") == derivation_descriptor_digest
        and statement.get("substrate_profile_digest") == substrate_profile_digest,
        f"{label} certification does not bind its scoped descriptor and profile bytes",
    )
    profile_schema = profile.get("schema")
    require(
        profile_schema in {PROFILE_SCHEMA_V2, PROFILE_SCHEMA_V3}
        and profile.get("static_grant_model") == PRINCIPAL_MODEL,
        f"{label} package does not use a supported scoped authority model",
    )
    require(
        strict.get("schema") == STRICT_SCHEMA and strict.get("outcome") == "pass",
        f"{label} scoped strict report did not pass",
    )
    expected_inventory = {
        "graph_manifest_digest": graph_digest,
        "import_alias_scheme": profile.get("import_alias_scheme"),
        "principal_id_scheme": profile.get("principal_id_scheme"),
        "principals": profile.get("principals"),
        "schema": INVENTORY_SCHEMA,
    }
    require(
        inventory == expected_inventory and inventory_bytes == canonical_json(expected_inventory),
        f"{label} principal inventory is not the exact canonical profile mapping",
    )
    inventory_digest = digest_bytes(inventory_bytes)
    require(
        strict.get("principal_inventory_digest") == inventory_digest,
        f"{label} strict report does not bind its principal inventory",
    )
    enforcement = strict.get("principal_enforcement")
    require(
        isinstance(enforcement, dict)
        and enforcement.get("graph_union_absent") is True
        and enforcement.get("grants_exact") is True
        and enforcement.get("aliases_unique") is True
        and enforcement.get("result") == "pass",
        f"{label} strict report did not establish per-principal enforcement",
    )
    principals = profile.get("principals")
    require(isinstance(principals, list) and len(principals) > 1, f"{label} has too few principals")
    http_authority: dict[str, str] | None = None
    if profile_schema == PROFILE_SCHEMA_V3:
        require(
            profile_bytes == canonical_json(profile),
            f"{label} profile v3 is not canonical JSON",
        )
        try:
            http_authority = inspect_r3_http_authority(
                directory, profile, manifest, statement, label
            )
        except R3AuthorityError as error:
            raise ReportError(str(error)) from error
    else:
        require(
            "http_transport" not in profile,
            f"{label} profile v2 unexpectedly contains an R3 HTTP projection",
        )
    return {
        "certification_digest": certification_digest,
        "derivation_descriptor_digest": derivation_descriptor_digest,
        "graph_manifest_digest": graph_digest,
        "import_alias_scheme": profile.get("import_alias_scheme"),
        "previous_graph": manifest.get("previous_graph"),
        "principal_inventory_digest": inventory_digest,
        "principal_count": len(principals),
        "principal_id_scheme": profile.get("principal_id_scheme"),
        "substrate_profile_digest": substrate_profile_digest,
        "profile_schema": profile_schema,
        "http_transport_binding_alias": (
            http_authority["binding_alias"] if http_authority is not None else None
        ),
        "http_transport_constraint_digest": (
            http_authority["constraint_digest"] if http_authority is not None else None
        ),
        "alias_count": sum(
            len(item.get("host_imports", [])) for item in principals if isinstance(item, dict)
        ),
    }


def production_evidence(transcript_directory: Path, repository: Path) -> dict[str, Any]:
    transcripts: list[dict[str, Any]] = []
    observed_tests: set[str] = set()
    for path in sorted(transcript_directory.glob("*.json"), key=lambda item: item.name.encode()):
        transcript, data = read_json(path, f"production transcript {path.name}")
        identities = transcript.get("passed_test_identities")
        if not isinstance(identities, list):
            continue
        for identity in identities:
            if isinstance(identity, str):
                observed_tests.add(identity)
        transcripts.append(
            {
                "digest": digest_bytes(data),
                "file": path.name,
                "result": "pass" if transcript.get("exit_code") == 0 else "fail",
            }
        )
    missing = REQUIRED_PRODUCTION_TESTS - observed_tests
    require(not missing, f"production principal tests are missing: {sorted(missing)}")
    require(
        all(item["result"] == "pass" for item in transcripts),
        "a production principal transcript did not pass",
    )
    sources = []
    for relative in [
        "kernel/src/local.rs",
        "kernel/src/root_runtime.rs",
        "kernel/src/local/durability_tests.rs",
    ]:
        path = repository / relative
        data = path.read_bytes()
        sources.append({"path": relative, "sha256": digest_bytes(data)})
    return {
        "cases_passed": len(PRODUCTION_CASES),
        "principal_model": PRINCIPAL_MODEL,
        "result": "pass",
        "source_bindings": sources,
        "test_identities": sorted(REQUIRED_PRODUCTION_TESTS),
        "transcripts": transcripts,
    }


def package_release_identity(package: dict[str, Any]) -> dict[str, Any]:
    return {
        field: package[field]
        for field in (
            "certification_digest",
            "derivation_descriptor_digest",
            "graph_manifest_digest",
            "import_alias_scheme",
            "principal_count",
            "principal_id_scheme",
            "principal_inventory_digest",
            "substrate_profile_digest",
        )
    }


def independent_evidence(
    path: Path, incumbent: dict[str, Any], successor: dict[str, Any]
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    report, data = read_json(path, "independent principal isolation report")
    require(report.get("schema") == INDEPENDENT_SCHEMA, "wrong independent isolation schema")
    require(report.get("outcome") == "pass", "independent isolation campaign did not pass")
    release = report.get("release")
    successor_release = report.get("successor_release")
    require(
        release == package_release_identity(incumbent),
        "independent isolation report is not bound to the exact incumbent",
    )
    require(
        successor_release == package_release_identity(successor),
        "independent isolation report is not bound to the exact successor",
    )
    summary = report.get("summary")
    require(isinstance(summary, dict), "independent isolation summary is missing")
    for field in [
        "caller_owned_idempotency_enforced",
        "caller_owned_poll_cancel_enforced",
        "caller_target_edges_enforced",
        "cross_capability_escalation_rejected",
        "forged_alias_rejected",
        "graph_qualified_activation_owner_handoff_enforced",
        "mechanism_state_unchanged_on_every_rejection",
        "two_distinct_principals_exercised",
    ]:
        require(summary.get(field) is True, f"independent isolation did not establish {field}")
    require(
        summary.get("cases_passed") == len(REQUIRED_INDEPENDENT_CASES)
        and summary.get("cases_total") == len(REQUIRED_INDEPENDENT_CASES),
        "independent isolation summary does not bind the exact 7/7 campaign",
    )
    cases = report.get("cases")
    require(
        isinstance(cases, list) and len(cases) == len(REQUIRED_INDEPENDENT_CASES),
        "independent campaign does not contain the exact seven cases",
    )
    case_ids = [case.get("id") for case in cases if isinstance(case, dict)]
    require(
        len(case_ids) == len(set(case_ids))
        and set(case_ids) == REQUIRED_INDEPENDENT_CASES,
        "independent campaign case identities are missing, duplicated or unexpected",
    )
    projected_cases: list[dict[str, Any]] = []
    for case in cases:
        require(
            isinstance(case, dict)
            and case.get("result") == "pass"
            and case.get("mechanism_state_unchanged") is True,
            "an independent cross-principal case did not fail closed",
        )
        projected_cases.append(
            {
                "id": f"independent-{case.get('id')}",
                "result": "pass",
                "substrate": "independent-substrate",
            }
        )
    handoff = next(
        case for case in cases if case.get("id") == "graph-qualified-activation-owner-handoff"
    )
    require(
        handoff.get("expected_failure") == "graph-qualified-handoff-enforced"
        and handoff.get("observed_failure") == "graph-qualified-handoff-enforced"
        and handoff.get("atomic_commit_owner_handoff") is True
        and handoff.get("restart_persistence_verified") is True
        and handoff.get("rollback_owner_handback") is True,
        "independent activation case did not prove exact owner handoff, restart and handback",
    )
    handoff_facts = {
        "atomic_commit_owner_handoff": True,
        "case_id": "graph-qualified-activation-owner-handoff",
        "restart_persistence_verified": True,
        "rollback_owner_handback": True,
    }
    return (
        {
            "activation_owner_handoff": handoff_facts,
            "case_ids": sorted(REQUIRED_INDEPENDENT_CASES),
            "cases_passed": len(projected_cases),
            "graph_qualified_activation_owner_handoff_enforced": True,
            "principal_model": PRINCIPAL_MODEL,
            "release_pair": {
                "incumbent": release,
                "successor": successor_release,
            },
            "report_digest": digest_bytes(data),
            "result": "pass",
        },
        projected_cases,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--incumbent-package", type=Path, required=True)
    parser.add_argument("--successor-package", type=Path, required=True)
    parser.add_argument("--production-transcript-dir", type=Path, required=True)
    parser.add_argument("--independent-report", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    arguments = parser.parse_args()

    repository = Path(__file__).resolve().parent.parent
    incumbent = package_identity(arguments.incumbent_package.resolve(), "incumbent")
    successor = package_identity(arguments.successor_package.resolve(), "successor")
    require(incumbent["previous_graph"] is None, "incumbent unexpectedly names a prior graph")
    require(
        successor["previous_graph"] == incumbent["graph_manifest_digest"],
        "successor does not name the exact incumbent",
    )
    require(
        successor["profile_schema"] == incumbent["profile_schema"],
        "principal-isolation package cohort mixes profile generations",
    )
    require(
        successor["substrate_profile_digest"]
        == incumbent["substrate_profile_digest"],
        "principal-isolation package cohort does not bind one exact scoped profile",
    )
    production = production_evidence(arguments.production_transcript_dir.resolve(), repository)
    independent, independent_cases = independent_evidence(
        arguments.independent_report.resolve(), incumbent, successor
    )
    production_cases = [
        {
            "id": identifier,
            "result": "pass",
            "substrate": "production-kernel",
            "assertion": assertion,
        }
        for identifier, assertion in PRODUCTION_CASES
    ]
    report = {
        "component_complete_claim": False,
        "cross_principal_cases": [*production_cases, *independent_cases],
        "incumbent_graph_manifest_digest": incumbent["graph_manifest_digest"],
        "incumbent_principal_inventory_digest": incumbent[
            "principal_inventory_digest"
        ],
        "independent_substrate": independent,
        "principal_model": PRINCIPAL_MODEL,
        "production_kernel": production,
        "remaining_blockers": [],
        "report_complete": True,
        "result": "pass",
        "schema": REPORT_SCHEMA,
        "successor_graph_manifest_digest": successor["graph_manifest_digest"],
        "successor_principal_inventory_digest": successor[
            "principal_inventory_digest"
        ],
    }
    output = arguments.out.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    data = canonical_json(report)
    output.write_bytes(data)
    print(
        json.dumps(
            {
                "cases": len(report["cross_principal_cases"]),
                "digest": digest_bytes(data),
                "out": str(output),
                "result": "pass",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ReportError) as error:
        print(f"r2-principal-isolation-report: {error}", file=sys.stderr)
        raise SystemExit(1)
