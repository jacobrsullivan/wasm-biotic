#!/usr/bin/env python3
"""Build and verify a content-addressed Wasm-Biotic component release bundle.

Only Python's standard library and the ``openssl`` command are required.

Build-spec schema (``wasm-biotic.component-complete-release-build-spec.v1``)::

    {
      "schema": "wasm-biotic.component-complete-release-build-spec.v1",
      "component_complete_claim": true,
      "external_north_star_claim": false,
      "identities": {
        "incumbent_graph_manifest_digest": "sha256:<64 lowercase hex>",
        "successor_graph_manifest_digest": "sha256:<64 lowercase hex>",
        "native_tcb_inventory_digest": "sha256:<64 lowercase hex>",
        "capability_profile_digest": "sha256:<64 lowercase hex>",
        "wit_contract_digest": "sha256:<64 lowercase hex>",
        "component_complete_contract_digest": "sha256:<CONFORMANCE.md bytes>",
        "native_target": "aarch64-apple-darwin"
      },
      "successor_lineage": {
        "incumbent_graph_manifest_digest": "sha256:<...>",
        "successor_graph_manifest_digest": "sha256:<...>",
        "successor_previous_graph_digest": "sha256:<incumbent>"
      },
      "gates": {"C0":"pass", "C1":"pass", ..., "C7":"pass"},
      "open_release_blockers": [],
      "trees": [
        {
          "role": "incumbent-package",
          "sources": [{"source": "path/from/spec", "prefix": ""}]
        }
      ],
      "objects": [
        {"role": "native-executable", "source": "path/from/spec"},
        {"role": "signed-semantic-admission", "source": "..."}
      ]
    }

The v1 schema remains the exact R0/R1 contract. Build-spec v2 adds
``claim_profile: r2-per-consumer-least-authority-v1``, per-package derivation
and principal-inventory identities, and the mandatory ``principal-isolation``
evidence role. Its verifier reconstructs the complete package certificate and
per-consumer alias closure. The outer release root and Ed25519 signature
envelopes remain v1 because they sign an opaque claim-manifest digest.

Build-spec v3 retains the complete R2 authority contract and adds
``claim_profile: r3-bounded-external-transport-v1``, exact incumbent and
successor HTTP-constraint identities, and mandatory ``transport-confinement``
evidence. Its verifier accepts only profile v3 plus descriptor v2, reconstructs
the single exchange-service HTTP alias/grant projection and the exact
two-constraint certificate closure, validates the closed transport document,
and joins compiled exchange-component evidence back to retained manifest bytes.

The four mandatory trees are ``incumbent-package``, ``successor-package``,
``native-source`` and ``normative-contract``. ``certifier-public-key`` is
derived from the private key and must not be supplied as an object.

Behavioural-equivalence evidence accepts the retained v1 schema and the
expanded v2 schema. Both must bind the exact incumbent/successor graph pair in
the build spec. V2 must additionally retain the exact twelve-call synthetic
policy trace and explicitly disclaim useful-R1 semantic execution; the useful
work-state proof remains a separate lifecycle/package verifier responsibility.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any, Iterable, NoReturn


SPEC_SCHEMA_V1 = "wasm-biotic.component-complete-release-build-spec.v1"
SPEC_SCHEMA_V2 = "wasm-biotic.component-complete-release-build-spec.v2"
SPEC_SCHEMA_V3 = "wasm-biotic.component-complete-release-build-spec.v3"
SPEC_SCHEMAS = frozenset((SPEC_SCHEMA_V1, SPEC_SCHEMA_V2, SPEC_SCHEMA_V3))
# Retained aliases are part of the public Python surface used by the historical
# v1 regression tests and downstream release scripts.
SPEC_SCHEMA = SPEC_SCHEMA_V1
CLAIM_SCHEMA_V1 = "wasm-biotic.component-complete-claim-manifest.v1"
CLAIM_SCHEMA_V2 = "wasm-biotic.component-complete-claim-manifest.v2"
CLAIM_SCHEMA_V3 = "wasm-biotic.component-complete-claim-manifest.v3"
CLAIM_SCHEMAS = frozenset((CLAIM_SCHEMA_V1, CLAIM_SCHEMA_V2, CLAIM_SCHEMA_V3))
CLAIM_SCHEMA = CLAIM_SCHEMA_V1
SIGNATURE_SCHEMA = "wasm-biotic.component-complete-claim-signature.v1"
SIGNING_PAYLOAD_SCHEMA = "wasm-biotic.component-complete-claim-signing-payload.v1"
PACKAGE_SIGNING_PAYLOAD_SCHEMA = "wasm-biotic.release-certification-signing-payload.v1"
RELEASE_SCHEMA = "wasm-biotic.component-complete-release-root.v1"
TREE_SCHEMA = "wasm-biotic.content-tree.v1"
CANONICALIZATION = "wasm-biotic.canonical-json.v1"

DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
HEX_64_RE = re.compile(r"[0-9a-f]{64}\Z")
HEX_128_RE = re.compile(r"[0-9a-f]{128}\Z")
ROLE_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")

TREE_ROLES = frozenset(
    {
        "incumbent-package",
        "successor-package",
        "native-source",
        "normative-contract",
    }
)
SECTION_7_ROLES_V1 = (
    "adversarial-isolation",
    "behavioural-equivalence",
    "candidate-graph-shadow",
    "component-lifecycle",
    "durability-fault-matrix",
    "independent-substrate-reproduction",
    "native-build-attestation",
    "signed-semantic-admission",
)
SECTION_7_ROLES_V2 = (
    "adversarial-isolation",
    "behavioural-equivalence",
    "candidate-graph-shadow",
    "component-lifecycle",
    "durability-fault-matrix",
    "independent-substrate-reproduction",
    "native-build-attestation",
    "principal-isolation",
    "signed-semantic-admission",
)
SECTION_7_ROLES_V3 = (
    *SECTION_7_ROLES_V2,
    "transport-confinement",
)
SECTION_7_ROLES = SECTION_7_ROLES_V1
REQUIRED_OBJECT_ROLES_V1 = frozenset(("native-executable", *SECTION_7_ROLES_V1))
REQUIRED_OBJECT_ROLES_V2 = frozenset(("native-executable", *SECTION_7_ROLES_V2))
REQUIRED_OBJECT_ROLES_V3 = frozenset(("native-executable", *SECTION_7_ROLES_V3))
REQUIRED_OBJECT_ROLES = REQUIRED_OBJECT_ROLES_V1
R2_CLAIM_PROFILE = "r2-per-consumer-least-authority-v1"
R3_CLAIM_PROFILE = "r3-bounded-external-transport-v1"
BEHAVIOURAL_EQUIVALENCE_SCHEMA_V1 = "wasm-biotic.behavioural-equivalence.v1"
BEHAVIOURAL_EQUIVALENCE_SCHEMA_V2 = "wasm-biotic.behavioural-equivalence.v2"
BEHAVIOURAL_EQUIVALENCE_SCHEMAS = frozenset(
    (BEHAVIOURAL_EQUIVALENCE_SCHEMA_V1, BEHAVIOURAL_EQUIVALENCE_SCHEMA_V2)
)
COMPONENT_LIFECYCLE_SCHEMA_V2 = "wasm-biotic.component-lifecycle-execution.v2"
R2_AUTHORITY_TRACE_PHASES = (
    "incumbent-cycle",
    "activation-and-successor-cycle",
    "rollback",
    "restart-post-rollback-cycle",
)
PRINCIPAL_ISOLATION_SCHEMA_V1 = "wasm-biotic.principal-isolation.v1"
TRANSPORT_CONFINEMENT_SCHEMA_V1 = "wasm-biotic.transport-confinement.v1"
R3_TRANSPORT_CASE_GROUPS = {
    "confinement": (
        "destination-dns-tls",
        "operator-capacity-intersection",
        "path-method-header-body-timeout-redirect",
    ),
    "durability": (
        "dispatch-boundary-indeterminate",
        "prepared-before-dispatch",
        "terminal-restart-replay",
    ),
    "owner": (
        "cross-owner-poll-cancel",
        "graph-principal-alias-constraint",
        "idempotency-request-conflict",
    ),
    "secret_non_observation": (
        "exact-prefix-injection",
        "no-journal-log-receipt-or-response-secret",
        "opaque-handle-only",
    ),
    "non_retry": (
        "cancel-before-dispatch-only",
        "indeterminate-never-redispatch",
        "single-native-dispatch",
    ),
}
R2_INDEPENDENT_PRINCIPAL_CASE_IDS = (
    "caller-target-edge",
    "cross-capability-escalation",
    "cross-principal-clock-operation",
    "cross-principal-idempotency",
    "cross-principal-run-operation",
    "forged-alias",
    "graph-qualified-activation-owner-handoff",
)
R2_INDEPENDENT_AGGREGATE_CASE_IDS = tuple(
    f"independent-{case_id}" for case_id in R2_INDEPENDENT_PRINCIPAL_CASE_IDS
)
R2_PRODUCTION_PRINCIPAL_CASE_IDS = (
    "production-activation-owner-handback",
    "production-activation-owner-handoff",
    "production-activation-status-theft",
    "production-alias-scope-overrides-metadata",
    "production-clock-cancel-theft",
    "production-clock-poll-theft",
    "production-denial-authority-trace",
    "production-graph-qualified-runtime-principal",
    "production-guest-identity-nonselectable",
    "production-legacy-grant-closure",
    "production-restart-activation-ownership",
    "production-restart-run-ownership",
    "production-restart-wake-ownership",
    "production-run-cancel-theft",
    "production-run-idempotency-conflict",
    "production-run-poll-theft",
    "production-shared-wake-handle",
    "production-stale-graph-activation-denial",
    "production-wake-idempotency-conflict",
)
R2_PRODUCTION_PRINCIPAL_CASE_COUNT = len(R2_PRODUCTION_PRINCIPAL_CASE_IDS)
R2_PRINCIPAL_CASE_COUNT = (
    R2_PRODUCTION_PRINCIPAL_CASE_COUNT + len(R2_INDEPENDENT_PRINCIPAL_CASE_IDS)
)
R2_NATIVE_SOURCE_ALGORITHM = (
    "SHA-256 of '<file-sha256><two spaces><repository-relative-path><LF>' "
    "in bytewise path order"
)
R2_NATIVE_SOURCE_SCOPE = (
    "kernel/Cargo.toml, kernel/Cargo.lock, kernel/src/**/*.rs and "
    "wit/wasm-biotic/*.wit; this self-referential inventory is excluded"
)
R1_SYNTHETIC_POLICY_TRACE = (
    ("planner", "build", "workspace-open", "observe"),
    ("planner", "build", "workspace-snapshot", "observe"),
    ("planner", "build", "workspace-patch", "local-mutate"),
    ("planner", "scheduling", "schedule-job", "automation-control"),
    ("builder", "build", "candidate-build", "local-mutate"),
    (
        "validator",
        "validation",
        "factory-provider-proposal",
        "local-mutate",
    ),
    ("validator", "validation", "validation-prove", "automation-control"),
    ("reviewer", "review", "review-candidate", "observe"),
    ("packager", "packaging", "package-publish", "local-mutate"),
    ("packager", "packaging", "package-verify", "observe"),
    (
        "continuity-worker",
        "continuity",
        "evidence-publish",
        "local-mutate",
    ),
    ("continuity-worker", "continuity", "evidence-resolve", "observe"),
)
DER_ED25519_PRIVATE_PREFIX = bytes.fromhex("302e020100300506032b657004220420")
PRIVATE_MARKERS = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    DER_ED25519_PRIVATE_PREFIX,
)
STATE_MARKERS = (
    b'"schema":"wasm-biotic.mechanism-state.',
    b'"schema": "wasm-biotic.mechanism-state.',
)
FORBIDDEN_NAME_PARTS = frozenset(
    {
        ".env",
        "credentials",
        "credential",
        "mechanism-state",
        "mechanism_state",
        "mechanisms.json",
        "mechanisms.json.tmp",
        "private-key",
        "private_key",
        "secret",
        "secrets",
    }
)
FORBIDDEN_SUFFIXES = (".key", ".p8", ".pk8")


class BundleError(RuntimeError):
    """A release bundle is malformed or cannot be trusted."""


def fail(message: str) -> NoReturn:
    raise BundleError(message)


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
            size += len(block)
    return "sha256:" + digest.hexdigest(), size


def canonical_json(value: Any) -> bytes:
    validate_json_domain(value, "JSON value")
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        fail(f"cannot canonicalize JSON: {error}")


def validate_json_domain(value: Any, where: str) -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        fail(f"{where} contains a float; canonical JSON permits integers only")
    if isinstance(value, list):
        for index, child in enumerate(value):
            validate_json_domain(child, f"{where}[{index}]")
        return
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                fail(f"{where} contains a non-string object key")
            validate_json_domain(child, f"{where}.{key}")
        return
    fail(f"{where} contains unsupported JSON value {type(value).__name__}")


def _reject_constant(value: str) -> NoReturn:
    fail(f"JSON contains forbidden numeric constant {value}")


def _reject_float(value: str) -> NoReturn:
    fail(f"JSON contains float {value}; canonical JSON permits integers only")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"JSON contains duplicate object key {key!r}")
        result[key] = value
    return result


def parse_json_bytes(raw: bytes, where: str, *, canonical: bool) -> Any:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        fail(f"{where} is not UTF-8: {error}")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except BundleError:
        raise
    except json.JSONDecodeError as error:
        fail(f"{where} is not valid JSON: {error}")
    validate_json_domain(value, where)
    if canonical and raw != canonical_json(value):
        fail(f"{where} is not compact, sorted canonical JSON with no newline")
    return value


def load_json(path: Path, *, canonical: bool) -> Any:
    require_regular_file(path, str(path))
    return parse_json_bytes(path.read_bytes(), str(path), canonical=canonical)


def require_fields(value: Any, fields: Iterable[str], where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{where} must be an object")
    expected = set(fields)
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        fail(f"{where} has missing fields {missing} and unknown fields {unknown}")
    return value


def require_list(value: Any, where: str) -> list[Any]:
    if not isinstance(value, list):
        fail(f"{where} must be an array")
    return value


def require_string(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value:
        fail(f"{where} must be a non-empty string")
    return value


def require_bool(value: Any, expected: bool, where: str) -> None:
    if value is not expected:
        fail(f"{where} must be {str(expected).lower()}")


def require_object(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{where} must be an object")
    return value


def require_object_field(value: Any, field: str, where: str) -> Any:
    value = require_object(value, where)
    if field not in value:
        fail(f"{where} is missing field {field!r}")
    return value[field]


def require_nonnegative_int(value: Any, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        fail(f"{where} must be a non-negative integer")
    return value


def require_digest(value: Any, where: str) -> str:
    text = require_string(value, where)
    if not DIGEST_RE.fullmatch(text):
        fail(f"{where} must be sha256:<64 lowercase hex>")
    return text


def digest_stem(value: Any) -> str:
    """Return the canonical content-addressed filename stem for a digest."""

    digest = require_digest(value, "content digest")
    return f"sha256-{digest.removeprefix('sha256:')}"


def require_role(value: Any, where: str) -> str:
    role = require_string(value, where)
    if not ROLE_RE.fullmatch(role):
        fail(f"{where} is not a lowercase hyphenated role")
    return role


def require_sorted_unique_strings(value: Any, where: str) -> list[str]:
    values = [
        require_string(item, f"{where}[{index}]")
        for index, item in enumerate(require_list(value, where))
    ]
    if not values:
        fail(f"{where} must not be empty")
    if values != sorted(set(values)):
        fail(f"{where} must contain sorted unique strings")
    return values


def validate_r2_behavioural_lifecycle(
    lifecycle: dict[str, Any],
    identities: dict[str, Any],
    component_lifecycle_digest: str,
    where: str,
) -> None:
    source_path = require_string(
        require_object_field(lifecycle, "source_report_path", where),
        f"{where}.source_report_path",
    )
    if source_path != "package:evidence/component-lifecycle.json":
        fail(
            f"{where}.source_report_path must be the canonical package lifecycle path"
        )
    source_digest = require_digest(
        require_object_field(lifecycle, "source_report_digest", where),
        f"{where}.source_report_digest",
    )
    expected_lifecycle_digest = require_digest(
        component_lifecycle_digest, "component-lifecycle object digest"
    )
    if source_digest != expected_lifecycle_digest:
        fail(
            f"{where}.source_report_digest does not match the signed "
            "component-lifecycle object"
        )
    source_schema = require_string(
        require_object_field(lifecycle, "source_schema", where),
        f"{where}.source_schema",
    )
    if source_schema != COMPONENT_LIFECYCLE_SCHEMA_V2:
        fail(
            f"{where}.source_schema must be {COMPONENT_LIFECYCLE_SCHEMA_V2!r} "
            "for an R2 claim"
        )
    for field in (
        "graph_qualified_activation_ownership_handoff_verified",
        "principal_mapping_stable_across_restart_activation_and_rollback",
    ):
        require_bool(
            require_object_field(lifecycle, field, where),
            True,
            f"{where}.{field}",
        )

    inventories_where = f"{where}.principal_inventory_digests"
    inventories = require_fields(
        require_object_field(lifecycle, "principal_inventory_digests", where),
        ("incumbent", "successor"),
        inventories_where,
    )
    for kind in ("incumbent", "successor"):
        actual = require_digest(inventories[kind], f"{inventories_where}.{kind}")
        expected = identities[f"{kind}_principal_inventory_digest"]
        if actual != expected:
            fail(
                f"{inventories_where}.{kind} does not match the R2 release cohort"
            )
    if inventories["incumbent"] == inventories["successor"]:
        fail(f"{inventories_where} must bind two distinct inventories")

    summaries_where = f"{where}.authority_trace_summaries"
    summaries = require_list(
        require_object_field(lifecycle, "authority_trace_summaries", where),
        summaries_where,
    )
    if len(summaries) != len(R2_AUTHORITY_TRACE_PHASES):
        fail(
            f"{summaries_where} must contain the exact four ordered R2 phases"
        )
    incumbent = identities["incumbent_graph_manifest_digest"]
    successor = identities["successor_graph_manifest_digest"]
    graph_scopes = (
        [incumbent],
        sorted((incumbent, successor)),
        [successor],
        [incumbent],
    )
    trace_digests: list[str] = []
    for index, (value, expected_phase, expected_graphs) in enumerate(
        zip(summaries, R2_AUTHORITY_TRACE_PHASES, graph_scopes)
    ):
        summary_where = f"{summaries_where}[{index}]"
        summary = require_fields(
            value,
            (
                "aliases",
                "call_count",
                "consumers",
                "graph_manifest_digests",
                "phase",
                "profile_mapping_verified",
                "trace_digest",
            ),
            summary_where,
        )
        if summary["phase"] != expected_phase:
            fail(
                f"{summary_where}.phase must be {expected_phase!r}; "
                "R2 authority phases must remain ordered"
            )
        call_count = require_nonnegative_int(
            summary["call_count"], f"{summary_where}.call_count"
        )
        if call_count == 0:
            fail(f"{summary_where}.call_count must be positive")
        require_bool(
            summary["profile_mapping_verified"],
            True,
            f"{summary_where}.profile_mapping_verified",
        )
        require_sorted_unique_strings(summary["aliases"], f"{summary_where}.aliases")
        require_sorted_unique_strings(
            summary["consumers"], f"{summary_where}.consumers"
        )
        actual_graphs = [
            require_digest(item, f"{summary_where}.graph_manifest_digests[{item_index}]")
            for item_index, item in enumerate(
                require_list(
                    summary["graph_manifest_digests"],
                    f"{summary_where}.graph_manifest_digests",
                )
            )
        ]
        if actual_graphs != expected_graphs:
            fail(
                f"{summary_where}.graph_manifest_digests does not match the "
                "exact R2 phase graph scope"
            )
        trace_digests.append(
            require_digest(summary["trace_digest"], f"{summary_where}.trace_digest")
        )
    if len(set(trace_digests)) != len(trace_digests):
        fail(f"{summaries_where} must retain a different trace digest for each phase")


def validate_behavioural_equivalence_report(
    payload: bytes,
    identities: dict[str, Any],
    where: str,
    *,
    r2_claim: bool = False,
    component_lifecycle_digest: str | None = None,
) -> str:
    """Validate v1 compatibility or the truthful expanded v2 policy trace.

    The object remains content-addressed opaque evidence in the signed claim,
    so this adds no claim-manifest fields and preserves historical bundle
    compatibility. Schema-specific validation prevents a report bound to an
older lifecycle graph pair from being substituted into a new cohort. For an
R2 claim, the report must also name the signed lifecycle object's exact digest
and retain its graph-qualified authority-handoff and principal evidence.
    """

    report = require_object(parse_json_bytes(payload, where, canonical=False), where)
    schema = require_string(
        require_object_field(report, "schema", where), f"{where}.schema"
    )
    if schema not in BEHAVIOURAL_EQUIVALENCE_SCHEMAS:
        fail(f"{where} has unsupported schema {schema!r}")
    if r2_claim and schema != BEHAVIOURAL_EQUIVALENCE_SCHEMA_V2:
        fail(f"{where} must use behavioural-equivalence v2 for an R2 claim")
    require_bool(
        require_object_field(report, "report_complete", where),
        True,
        f"{where}.report_complete",
    )
    blockers = require_list(
        require_object_field(report, "blockers", where), f"{where}.blockers"
    )
    if blockers:
        fail(f"{where}.blockers must be empty")

    lifecycle = require_object(
        require_object_field(report, "lifecycle", where), f"{where}.lifecycle"
    )
    for field in (
        "incumbent_graph_manifest_digest",
        "successor_graph_manifest_digest",
    ):
        actual = require_digest(
            require_object_field(lifecycle, field, f"{where}.lifecycle"),
            f"{where}.lifecycle.{field}",
        )
        if actual != identities[field]:
            fail(f"{where}.lifecycle.{field} does not match the release cohort")

    if r2_claim:
        if component_lifecycle_digest is None:
            fail(f"{where} R2 validation requires the component-lifecycle object digest")
        validate_r2_behavioural_lifecycle(
            lifecycle,
            identities,
            component_lifecycle_digest,
            f"{where}.lifecycle",
        )

    if schema == BEHAVIOURAL_EQUIVALENCE_SCHEMA_V1:
        return schema

    for field, expected in (
        ("synthetic_policy_service_outputs", True),
        ("synthetic_policy_trace_claims_useful_r1_semantics", False),
        ("lifecycle_r1_semantics_verified_by_this_report", False),
    ):
        require_bool(
            require_object_field(report, field, where),
            expected,
            f"{where}.{field}",
        )

    trace = require_object(
        require_object_field(report, "component_trace", where),
        f"{where}.component_trace",
    )
    count = require_nonnegative_int(
        require_object_field(
            trace, "expected_capability_request_count", f"{where}.component_trace"
        ),
        f"{where}.component_trace.expected_capability_request_count",
    )
    if count != len(R1_SYNTHETIC_POLICY_TRACE):
        fail(f"{where} does not require the exact twelve-call policy trace")
    require_bool(
        require_object_field(
            trace, "capability_request_order_verified", f"{where}.component_trace"
        ),
        True,
        f"{where}.component_trace.capability_request_order_verified",
    )
    output_mode = require_string(
        require_object_field(trace, "service_output_mode", f"{where}.component_trace"),
        f"{where}.component_trace.service_output_mode",
    )
    if output_mode != "deterministic-synthetic-blob; no useful R1 semantics executed":
        fail(f"{where} does not label its synthetic service-output boundary")
    calls = require_list(
        require_object_field(trace, "capability_requests", f"{where}.component_trace"),
        f"{where}.component_trace.capability_requests",
    )
    if len(calls) != len(R1_SYNTHETIC_POLICY_TRACE):
        fail(f"{where} has the wrong policy-call count")
    for index, (actual, expected) in enumerate(zip(calls, R1_SYNTHETIC_POLICY_TRACE)):
        call_where = f"{where}.component_trace.capability_requests[{index}]"
        call = require_fields(
            actual, ("role", "family", "operation", "authority"), call_where
        )
        actual_tuple = tuple(
            require_string(call[field], f"{call_where}.{field}")
            for field in ("role", "family", "operation", "authority")
        )
        if actual_tuple != expected:
            fail(f"{call_where} differs from the expanded R1 worker policy")

    receipts = require_object(
        require_object_field(report, "receipt_normalization", where),
        f"{where}.receipt_normalization",
    )
    receipt_count = require_nonnegative_int(
        require_object_field(
            receipts, "policy_component_receipt_count", f"{where}.receipt_normalization"
        ),
        f"{where}.receipt_normalization.policy_component_receipt_count",
    )
    if receipt_count != len(R1_SYNTHETIC_POLICY_TRACE):
        fail(f"{where} does not retain one receipt per synthetic policy call")
    return schema


def validate_principal_isolation_report(
    data: bytes, identities: dict[str, Any], where: str
) -> None:
    report = parse_json_bytes(data, where, canonical=False)
    report = require_fields(
        report,
        (
            "schema",
            "component_complete_claim",
            "report_complete",
            "result",
            "principal_model",
            "incumbent_graph_manifest_digest",
            "successor_graph_manifest_digest",
            "incumbent_principal_inventory_digest",
            "successor_principal_inventory_digest",
            "production_kernel",
            "independent_substrate",
            "cross_principal_cases",
            "remaining_blockers",
        ),
        where,
    )
    expect_field(report, "schema", PRINCIPAL_ISOLATION_SCHEMA_V1, where)
    require_bool(
        report["component_complete_claim"], False, f"{where}.component_complete_claim"
    )
    require_bool(report["report_complete"], True, f"{where}.report_complete")
    expect_field(report, "result", "pass", where)
    expect_field(report, "principal_model", "per-consumer-import-alias", where)
    for field in (
        "incumbent_graph_manifest_digest",
        "successor_graph_manifest_digest",
        "incumbent_principal_inventory_digest",
        "successor_principal_inventory_digest",
    ):
        expect_field(report, field, identities[field], where)
    blockers = require_list(report["remaining_blockers"], f"{where}.remaining_blockers")
    if blockers:
        fail(f"{where}.remaining_blockers must be empty")

    production_where = f"{where}.production_kernel"
    production = require_fields(
        report["production_kernel"],
        (
            "cases_passed",
            "principal_model",
            "result",
            "source_bindings",
            "test_identities",
            "transcripts",
        ),
        production_where,
    )
    expect_field(production, "result", "pass", production_where)
    expect_field(
        production, "principal_model", "per-consumer-import-alias", production_where
    )
    if (
        require_nonnegative_int(
            production["cases_passed"], f"{production_where}.cases_passed"
        )
        != R2_PRODUCTION_PRINCIPAL_CASE_COUNT
    ):
        fail(f"{production_where} does not retain the exact production case count")
    require_list(production["source_bindings"], f"{production_where}.source_bindings")
    require_list(production["test_identities"], f"{production_where}.test_identities")
    require_list(production["transcripts"], f"{production_where}.transcripts")

    independent_where = f"{where}.independent_substrate"
    independent = require_fields(
        report["independent_substrate"],
        (
            "activation_owner_handoff",
            "case_ids",
            "cases_passed",
            "graph_qualified_activation_owner_handoff_enforced",
            "principal_model",
            "release_pair",
            "report_digest",
            "result",
        ),
        independent_where,
    )
    expect_field(independent, "result", "pass", independent_where)
    expect_field(
        independent, "principal_model", "per-consumer-import-alias", independent_where
    )
    require_digest(independent["report_digest"], f"{independent_where}.report_digest")
    if (
        require_nonnegative_int(
            independent["cases_passed"], f"{independent_where}.cases_passed"
        )
        != len(R2_INDEPENDENT_PRINCIPAL_CASE_IDS)
    ):
        fail(f"{independent_where} does not retain the exact independent case count")
    independent_case_ids = require_list(
        independent["case_ids"], f"{independent_where}.case_ids"
    )
    if independent_case_ids != list(R2_INDEPENDENT_PRINCIPAL_CASE_IDS):
        fail(f"{independent_where}.case_ids are not the exact ordered campaign")
    require_bool(
        independent["graph_qualified_activation_owner_handoff_enforced"],
        True,
        f"{independent_where}.graph_qualified_activation_owner_handoff_enforced",
    )
    pair_where = f"{independent_where}.release_pair"
    release_pair = require_fields(
        independent["release_pair"], ("incumbent", "successor"), pair_where
    )
    release_identity_fields = (
        "certification_digest",
        "derivation_descriptor_digest",
        "graph_manifest_digest",
        "import_alias_scheme",
        "principal_count",
        "principal_id_scheme",
        "principal_inventory_digest",
        "substrate_profile_digest",
    )
    for kind in ("incumbent", "successor"):
        identity_where = f"{pair_where}.{kind}"
        release_identity = require_fields(
            release_pair[kind], release_identity_fields, identity_where
        )
        for field in (
            "certification_digest",
            "derivation_descriptor_digest",
            "graph_manifest_digest",
            "principal_inventory_digest",
            "substrate_profile_digest",
        ):
            require_digest(release_identity[field], f"{identity_where}.{field}")
        expect_field(
            release_identity,
            "graph_manifest_digest",
            identities[f"{kind}_graph_manifest_digest"],
            identity_where,
        )
        expect_field(
            release_identity,
            "principal_inventory_digest",
            identities[f"{kind}_principal_inventory_digest"],
            identity_where,
        )
        expect_field(
            release_identity,
            "derivation_descriptor_digest",
            identities[f"{kind}_derivation_descriptor_digest"],
            identity_where,
        )
        expect_field(
            release_identity,
            "substrate_profile_digest",
            identities["capability_profile_digest"],
            identity_where,
        )
        expect_field(
            release_identity,
            "import_alias_scheme",
            "wasm-biotic.per-consumer-host-import.v1",
            identity_where,
        )
        expect_field(
            release_identity,
            "principal_id_scheme",
            "wasm-biotic.graph-node-principal.v1",
            identity_where,
        )
        if (
            require_nonnegative_int(
                release_identity["principal_count"],
                f"{identity_where}.principal_count",
            )
            != 22
        ):
            fail(f"{identity_where} does not bind all 22 principals")
    handoff_where = f"{independent_where}.activation_owner_handoff"
    handoff = require_fields(
        independent["activation_owner_handoff"],
        (
            "atomic_commit_owner_handoff",
            "case_id",
            "restart_persistence_verified",
            "rollback_owner_handback",
        ),
        handoff_where,
    )
    expect_field(
        handoff,
        "case_id",
        "graph-qualified-activation-owner-handoff",
        handoff_where,
    )
    for field in (
        "atomic_commit_owner_handoff",
        "restart_persistence_verified",
        "rollback_owner_handback",
    ):
        require_bool(handoff[field], True, f"{handoff_where}.{field}")

    cases = require_list(report["cross_principal_cases"], f"{where}.cross_principal_cases")
    if len(cases) != R2_PRINCIPAL_CASE_COUNT:
        fail(f"{where} does not retain the exact 26-case principal campaign")
    production_case_ids: set[str] = set()
    independent_aggregate_case_ids: set[str] = set()
    all_case_ids: set[str] = set()
    for index, raw_case in enumerate(cases):
        case_where = f"{where}.cross_principal_cases[{index}]"
        if not isinstance(raw_case, dict):
            fail(f"{case_where} must be an object")
        substrate = require_string(
            raw_case.get("substrate"), f"{case_where}.substrate"
        )
        fields = (
            ("assertion", "id", "result", "substrate")
            if substrate == "production-kernel"
            else ("id", "result", "substrate")
        )
        case = require_fields(raw_case, fields, case_where)
        case_id = require_string(case["id"], f"{case_where}.id")
        if case_id in all_case_ids:
            fail(f"{where} duplicates principal case {case_id!r}")
        all_case_ids.add(case_id)
        expect_field(case, "result", "pass", case_where)
        if substrate == "production-kernel":
            require_string(case["assertion"], f"{case_where}.assertion")
            production_case_ids.add(case_id)
        elif substrate == "independent-substrate":
            independent_aggregate_case_ids.add(case_id)
        else:
            fail(f"{case_where} names unknown substrate {substrate!r}")
    if production_case_ids != set(R2_PRODUCTION_PRINCIPAL_CASE_IDS):
        fail(f"{where} production case identities are not exact")
    if independent_aggregate_case_ids != set(R2_INDEPENDENT_AGGREGATE_CASE_IDS):
        fail(f"{where} independent case identities are not exact")


def validate_transport_confinement_report(
    data: bytes, identities: dict[str, Any], where: str
) -> dict[str, Any]:
    """Validate the closed, signed R3 cross-substrate evidence summary."""

    report = require_fields(
        parse_json_bytes(data, where, canonical=False),
        (
            "schema",
            "claim_profile",
            "incumbent_graph_manifest_digest",
            "successor_graph_manifest_digest",
            "capability_profile_digest",
            "incumbent_http_transport_constraint_digest",
            "successor_http_transport_constraint_digest",
            "production_kernel",
            "independent_substrate",
            "compiled_exchange_component",
            "remaining_blockers",
            "report_complete",
            "result",
        ),
        where,
    )
    expect_field(report, "schema", TRANSPORT_CONFINEMENT_SCHEMA_V1, where)
    expect_field(report, "claim_profile", R3_CLAIM_PROFILE, where)
    for field in (
        "incumbent_graph_manifest_digest",
        "successor_graph_manifest_digest",
        "capability_profile_digest",
        "incumbent_http_transport_constraint_digest",
        "successor_http_transport_constraint_digest",
    ):
        expect_field(report, field, identities[field], where)
    require_bool(report["report_complete"], True, f"{where}.report_complete")
    expect_field(report, "result", "pass", where)
    blockers = require_list(report["remaining_blockers"], f"{where}.remaining_blockers")
    if blockers:
        fail(f"{where}.remaining_blockers must be empty")

    expected_graphs = [
        identities["incumbent_graph_manifest_digest"],
        identities["successor_graph_manifest_digest"],
    ]
    expected_constraints = [
        identities["incumbent_http_transport_constraint_digest"],
        identities["successor_http_transport_constraint_digest"],
    ]
    report_digests: list[str] = []
    for field, implementation in (
        ("production_kernel", "production-kernel"),
        ("independent_substrate", "independent-substrate"),
    ):
        substrate_where = f"{where}.{field}"
        substrate = require_fields(
            report[field],
            (
                "implementation",
                "graph_manifest_digests",
                "http_transport_constraint_digests",
                "case_groups",
                "report_digest",
                "result",
            ),
            substrate_where,
        )
        expect_field(substrate, "implementation", implementation, substrate_where)
        expect_field(substrate, "result", "pass", substrate_where)
        if substrate["graph_manifest_digests"] != expected_graphs:
            fail(f"{substrate_where}.graph_manifest_digests must bind the exact ordered cohort")
        if substrate["http_transport_constraint_digests"] != expected_constraints:
            fail(
                f"{substrate_where}.http_transport_constraint_digests must bind "
                "the exact ordered R3 constraints"
            )
        for index, value in enumerate(expected_graphs):
            require_digest(value, f"{substrate_where}.graph_manifest_digests[{index}]")
        for index, value in enumerate(expected_constraints):
            require_digest(
                value,
                f"{substrate_where}.http_transport_constraint_digests[{index}]",
            )
        groups = require_fields(
            substrate["case_groups"],
            tuple(R3_TRANSPORT_CASE_GROUPS),
            f"{substrate_where}.case_groups",
        )
        for group, expected_cases in R3_TRANSPORT_CASE_GROUPS.items():
            if groups[group] != list(expected_cases):
                fail(
                    f"{substrate_where}.case_groups.{group} must contain the "
                    "exact ordered R3 campaign"
                )
        report_digests.append(
            require_digest(substrate["report_digest"], f"{substrate_where}.report_digest")
        )
    if len(set(report_digests)) != 2:
        fail(f"{where} must bind distinct production and independent report digests")

    compiled_where = f"{where}.compiled_exchange_component"
    compiled = require_fields(
        report["compiled_exchange_component"],
        (
            "component_id",
            "incumbent_component_digest",
            "successor_component_digest",
            "component_type_checked",
            "request_formation_component_owned",
            "response_interpretation_component_owned",
            "retry_cancel_fallback_component_owned",
            "native_provider_logic_absent",
            "credential_value_prefixes",
            "result",
        ),
        compiled_where,
    )
    expect_field(compiled, "component_id", "exchange-service", compiled_where)
    expect_field(compiled, "result", "pass", compiled_where)
    for field in ("incumbent_component_digest", "successor_component_digest"):
        require_digest(compiled[field], f"{compiled_where}.{field}")
    for field in (
        "component_type_checked",
        "request_formation_component_owned",
        "response_interpretation_component_owned",
        "retry_cancel_fallback_component_owned",
        "native_provider_logic_absent",
    ):
        require_bool(compiled[field], True, f"{compiled_where}.{field}")
    require_sorted_unique_strings(
        compiled["credential_value_prefixes"],
        f"{compiled_where}.credential_value_prefixes",
    )
    return report


def validate_transport_confinement_package_bindings(
    report: dict[str, Any], package_facts: dict[str, dict[str, Any]], where: str
) -> None:
    """Join the evidence's compiled-component assertions to retained packages."""

    compiled = report["compiled_exchange_component"]
    for kind in ("incumbent", "successor"):
        facts = package_facts[kind]
        expect_field(
            compiled,
            f"{kind}_component_digest",
            facts["exchange_component_digest"],
            f"{where}.compiled_exchange_component",
        )
    expected_prefixes = sorted(
        {
            prefix
            for facts in package_facts.values()
            for prefix in facts["credential_value_prefixes"]
        }
    )
    if compiled["credential_value_prefixes"] != expected_prefixes:
        fail(
            f"{where}.compiled_exchange_component.credential_value_prefixes "
            "do not match the canonical signed HTTP constraints"
        )


def validate_relative_path(value: Any, where: str, *, allow_empty: bool = False) -> str:
    path = value if isinstance(value, str) else ""
    if path == "" and allow_empty:
        return path
    if not path or not path.isascii():
        fail(f"{where} must be a non-empty ASCII POSIX path")
    if "\\" in path or any(
        ord(character) < 32 or ord(character) == 127 for character in path
    ):
        fail(f"{where} contains a backslash or control character")
    pure = PurePosixPath(path)
    if pure.is_absolute() or path.startswith("/"):
        fail(f"{where} must be relative")
    parts = path.split("/")
    if any(part in ("", ".", "..") for part in parts):
        fail(f"{where} contains an empty, '.' or '..' segment")
    return path


def validate_host_path_name(path: Path, where: str) -> None:
    for part in path.parts:
        folded = part.casefold()
        if folded in FORBIDDEN_NAME_PARTS or folded.endswith(FORBIDDEN_SUFFIXES):
            fail(f"{where} has forbidden private/state-bearing name {part!r}")


def reject_private_or_state_bytes(data: bytes, where: str) -> None:
    if any(marker in data for marker in PRIVATE_MARKERS):
        fail(f"{where} contains private-key material")
    if any(marker in data for marker in STATE_MARKERS):
        fail(f"{where} contains mechanism-state material")
    # Reject the unencrypted PKCS#8, PKCS#1 and SEC1 DER shapes without
    # confusing X.509 certificates or SubjectPublicKeyInfo values for keys.
    if data.startswith(b"\x30"):
        offset = 2
        if len(data) > 2 and data[1] & 0x80:
            length_bytes = data[1] & 0x7F
            offset = 2 + length_bytes
        body = data[offset : offset + 5]
        if body.startswith(
            (b"\x02\x01\x00\x30", b"\x02\x01\x00\x02", b"\x02\x01\x01\x04")
        ):
            fail(f"{where} contains DER private-key material")
    try:
        candidate = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, BundleError):
        return
    if isinstance(candidate, dict) and {
        "schema",
        "total_blob_bytes",
        "blobs",
        "transaction_version",
        "values",
        "runs",
        "keys",
    }.issubset(candidate):
        fail(f"{where} contains a serialized mechanism-state root")


def require_regular_file(path: Path, where: str) -> os.stat_result:
    try:
        info = path.lstat()
    except FileNotFoundError:
        fail(f"{where} is missing")
    if stat.S_ISLNK(info.st_mode):
        fail(f"{where} is a symlink")
    if not stat.S_ISREG(info.st_mode):
        fail(f"{where} is not a regular file")
    return info


def require_directory(path: Path, where: str) -> os.stat_result:
    try:
        info = path.lstat()
    except FileNotFoundError:
        fail(f"{where} is missing")
    if stat.S_ISLNK(info.st_mode):
        fail(f"{where} is a symlink")
    if not stat.S_ISDIR(info.st_mode):
        fail(f"{where} is not a directory")
    return info


def inspect_regular_bytes(path: Path, where: str) -> bytes:
    require_regular_file(path, where)
    validate_host_path_name(path, where)
    data = path.read_bytes()
    reject_private_or_state_bytes(data, where)
    return data


def source_path(spec_path: Path, value: Any, where: str) -> Path:
    raw = require_string(value, where)
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = spec_path.parent / candidate
    return candidate


def release_contract(schema: str) -> tuple[str, tuple[str, ...], frozenset[str]]:
    if schema == SPEC_SCHEMA_V1:
        return CLAIM_SCHEMA_V1, SECTION_7_ROLES_V1, REQUIRED_OBJECT_ROLES_V1
    if schema == SPEC_SCHEMA_V2:
        return CLAIM_SCHEMA_V2, SECTION_7_ROLES_V2, REQUIRED_OBJECT_ROLES_V2
    if schema == SPEC_SCHEMA_V3:
        return CLAIM_SCHEMA_V3, SECTION_7_ROLES_V3, REQUIRED_OBJECT_ROLES_V3
    if schema == CLAIM_SCHEMA_V1:
        return SPEC_SCHEMA_V1, SECTION_7_ROLES_V1, REQUIRED_OBJECT_ROLES_V1
    if schema == CLAIM_SCHEMA_V2:
        return SPEC_SCHEMA_V2, SECTION_7_ROLES_V2, REQUIRED_OBJECT_ROLES_V2
    if schema == CLAIM_SCHEMA_V3:
        return SPEC_SCHEMA_V3, SECTION_7_ROLES_V3, REQUIRED_OBJECT_ROLES_V3
    fail(f"unsupported release contract schema {schema!r}")


def validate_identities(
    value: Any, where: str, *, r2: bool = False, r3: bool = False
) -> dict[str, Any]:
    fields: tuple[str, ...] = (
        "incumbent_graph_manifest_digest",
        "successor_graph_manifest_digest",
        "native_tcb_inventory_digest",
        "capability_profile_digest",
        "wit_contract_digest",
        "component_complete_contract_digest",
        "native_target",
    )
    if r2:
        fields = (
            *fields[:-1],
            "incumbent_principal_inventory_digest",
            "successor_principal_inventory_digest",
            "incumbent_derivation_descriptor_digest",
            "successor_derivation_descriptor_digest",
            fields[-1],
        )
    if r3:
        if not r2:
            fail("R3 identities must retain the complete R2 identity set")
        fields = (
            *fields[:-1],
            "incumbent_http_transport_constraint_digest",
            "successor_http_transport_constraint_digest",
            fields[-1],
        )
    identities = require_fields(value, fields, where)
    for field in fields[:-1]:
        require_digest(identities[field], f"{where}.{field}")
    target = require_string(identities["native_target"], f"{where}.native_target")
    if not target.isascii() or any(ord(character) < 32 for character in target):
        fail(f"{where}.native_target must be printable ASCII")
    return identities


def validate_lineage(
    value: Any, identities: dict[str, Any], where: str
) -> dict[str, Any]:
    fields = (
        "incumbent_graph_manifest_digest",
        "successor_graph_manifest_digest",
        "successor_previous_graph_digest",
    )
    lineage = require_fields(value, fields, where)
    for field in fields:
        require_digest(lineage[field], f"{where}.{field}")
    incumbent = identities["incumbent_graph_manifest_digest"]
    successor = identities["successor_graph_manifest_digest"]
    if lineage["incumbent_graph_manifest_digest"] != incumbent:
        fail(f"{where} incumbent does not match identities")
    if lineage["successor_graph_manifest_digest"] != successor:
        fail(f"{where} successor does not match identities")
    if lineage["successor_previous_graph_digest"] != incumbent:
        fail(f"{where} predecessor is not the incumbent graph")
    if successor == incumbent:
        fail(f"{where} successor and incumbent graph identities are equal")
    return lineage


def validate_gates(value: Any, where: str) -> dict[str, str]:
    expected = {f"C{index}" for index in range(8)}
    gates = require_fields(value, expected, where)
    for gate in sorted(expected):
        if gates[gate] != "pass":
            fail(f"{where}.{gate} must be 'pass'")
    return gates


def resolve_spec(spec_path: Path) -> dict[str, Any]:
    spec = load_json(spec_path, canonical=False)
    if not isinstance(spec, dict):
        fail("build spec must be an object")
    schema = spec.get("schema")
    if not isinstance(schema, str) or schema not in SPEC_SCHEMAS:
        fail(
            "build spec schema must be one of "
            + ", ".join(repr(item) for item in sorted(SPEC_SCHEMAS))
        )
    is_r3 = schema == SPEC_SCHEMA_V3
    is_r2 = schema in (SPEC_SCHEMA_V2, SPEC_SCHEMA_V3)
    fields: tuple[str, ...] = (
        "schema",
        "component_complete_claim",
        "external_north_star_claim",
        "identities",
        "successor_lineage",
        "gates",
        "open_release_blockers",
        "trees",
        "objects",
    )
    if is_r2:
        fields = (*fields[:3], "claim_profile", *fields[3:])
    spec = require_fields(spec, fields, "build spec")
    require_bool(spec["component_complete_claim"], True, "component_complete_claim")
    require_bool(spec["external_north_star_claim"], False, "external_north_star_claim")
    expected_profile = R3_CLAIM_PROFILE if is_r3 else R2_CLAIM_PROFILE
    if is_r2 and spec["claim_profile"] != expected_profile:
        fail(f"claim_profile must be {expected_profile!r}")
    identities = validate_identities(
        spec["identities"], "identities", r2=is_r2, r3=is_r3
    )
    validate_lineage(spec["successor_lineage"], identities, "successor_lineage")
    validate_gates(spec["gates"], "gates")
    blockers = require_list(spec["open_release_blockers"], "open_release_blockers")
    if blockers:
        fail("open_release_blockers must be empty")

    trees = require_list(spec["trees"], "trees")
    tree_roles: set[str] = set()
    for index, tree in enumerate(trees):
        tree = require_fields(tree, ("role", "sources"), f"trees[{index}]")
        role = require_role(tree["role"], f"trees[{index}].role")
        if role in tree_roles:
            fail(f"duplicate tree role {role!r}")
        tree_roles.add(role)
        sources = require_list(tree["sources"], f"trees[{index}].sources")
        if not sources:
            fail(f"trees[{index}].sources must not be empty")
        for source_index, source in enumerate(sources):
            source = require_fields(
                source, ("source", "prefix"), f"trees[{index}].sources[{source_index}]"
            )
            source_path(
                spec_path,
                source["source"],
                f"trees[{index}].sources[{source_index}].source",
            )
            validate_relative_path(
                source["prefix"],
                f"trees[{index}].sources[{source_index}].prefix",
                allow_empty=True,
            )
    missing_trees = sorted(TREE_ROLES - tree_roles)
    if missing_trees:
        fail(f"missing mandatory tree roles {missing_trees}")

    objects = require_list(spec["objects"], "objects")
    object_roles: set[str] = set()
    for index, item in enumerate(objects):
        item = require_fields(item, ("role", "source"), f"objects[{index}]")
        role = require_role(item["role"], f"objects[{index}].role")
        if role == "certifier-public-key":
            fail(
                "certifier-public-key is derived and must not appear in the build spec"
            )
        if role in object_roles:
            fail(f"duplicate object role {role!r}")
        object_roles.add(role)
        source_path(spec_path, item["source"], f"objects[{index}].source")
    _, _, required_object_roles = release_contract(schema)
    missing_objects = sorted(required_object_roles - object_roles)
    if missing_objects:
        fail(f"missing mandatory object roles {missing_objects}")
    return spec


def relative_tree_files(root: Path) -> list[tuple[str, Path]]:
    require_directory(root, str(root))
    validate_host_path_name(root, str(root))
    files: list[tuple[str, Path]] = []
    seen_case: dict[str, str] = {}
    seen_inode: dict[tuple[int, int], str] = {}
    for current, directory_names, file_names in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in tuple(directory_names):
            path = current_path / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                fail(f"source tree contains symlink {path}")
            if not stat.S_ISDIR(info.st_mode):
                fail(f"source tree contains special entry {path}")
            relative = path.relative_to(root).as_posix()
            validate_relative_path(relative, str(path))
            validate_host_path_name(Path(relative), str(path))
        for name in file_names:
            path = current_path / name
            info = require_regular_file(path, str(path))
            relative = path.relative_to(root).as_posix()
            validate_relative_path(relative, str(path))
            validate_host_path_name(Path(relative), str(path))
            folded = relative.casefold()
            if folded in seen_case:
                fail(
                    f"source tree has case-colliding paths {seen_case[folded]!r} and {relative!r}"
                )
            seen_case[folded] = relative
            inode = (info.st_dev, info.st_ino)
            if inode in seen_inode:
                fail(
                    f"source tree has hard-linked aliases {seen_inode[inode]!r} and {relative!r}"
                )
            seen_inode[inode] = relative
            reject_private_or_state_bytes(path.read_bytes(), str(path))
            files.append((relative, path))
    files.sort(key=lambda pair: pair[0].encode("utf-8"))
    return files


def copy_tree_from_spec(
    tree_spec: dict[str, Any], spec_path: Path, stage: Path
) -> dict[str, Any]:
    role = tree_spec["role"]
    gathered: list[tuple[str, Path]] = []
    paths: set[str] = set()
    folded_paths: dict[str, str] = {}
    source_inodes: dict[tuple[int, int], str] = {}
    for source_index, source in enumerate(tree_spec["sources"]):
        root = source_path(
            spec_path, source["source"], f"tree {role} source {source_index}"
        )
        require_directory(root, f"tree {role} source {source_index}")
        if stage.resolve().is_relative_to(root.resolve()):
            fail(
                f"tree {role} source {root} contains the output staging directory; "
                "build outside every retained source tree"
            )
        prefix = source["prefix"]
        for relative, path in relative_tree_files(root):
            destination = f"{prefix}/{relative}" if prefix else relative
            validate_relative_path(destination, f"tree {role} destination")
            if destination in paths:
                fail(f"tree {role} has duplicate destination {destination!r}")
            folded = destination.casefold()
            if folded in folded_paths:
                fail(
                    f"tree {role} has case-colliding destinations "
                    f"{folded_paths[folded]!r} and {destination!r}"
                )
            info = path.lstat()
            inode = (info.st_dev, info.st_ino)
            if inode in source_inodes:
                fail(
                    f"tree {role} has hard-linked source aliases "
                    f"{source_inodes[inode]!r} and {destination!r}"
                )
            source_inodes[inode] = destination
            paths.add(destination)
            folded_paths[folded] = destination
            gathered.append((destination, path))
    gathered.sort(key=lambda pair: pair[0].encode("utf-8"))
    if not gathered:
        fail(f"tree {role} contains no files")

    entries: list[dict[str, Any]] = []
    files_size = 0
    pending: list[tuple[str, Path, str, int]] = []
    for destination, source in gathered:
        digest, size = sha256_file(source)
        entries.append({"path": destination, "sha256": digest, "size_bytes": size})
        pending.append((destination, source, digest, size))
        files_size += size
    tree_manifest = {
        "schema": TREE_SCHEMA,
        "digest_algorithm": "sha256",
        "entries": entries,
    }
    manifest_bytes = canonical_json(tree_manifest)
    manifest_digest = sha256_bytes(manifest_bytes)
    relative_tree_path = f"trees/sha256-{manifest_digest.removeprefix('sha256:')}"
    tree_directory = stage / relative_tree_path
    (tree_directory / "files").mkdir(parents=True)
    (tree_directory / "tree.json").write_bytes(manifest_bytes)
    for destination, source, _digest, _size in pending:
        target = tree_directory / "files" / destination
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target, follow_symlinks=False)
    return {
        "role": role,
        "path": relative_tree_path,
        "tree_manifest_sha256": manifest_digest,
        "tree_manifest_size_bytes": len(manifest_bytes),
        "file_count": len(entries),
        "files_size_bytes": files_size,
    }


def add_object(
    stage: Path, role: str, source: Path | None, data: bytes | None
) -> dict[str, Any]:
    if (source is None) == (data is None):
        fail("internal error: object requires exactly one source")
    if source is not None:
        payload = inspect_regular_bytes(source, f"object {role}")
        mode = source.stat().st_mode
    else:
        assert data is not None
        payload = data
        reject_private_or_state_bytes(payload, f"object {role}")
        mode = 0o100644
    digest = sha256_bytes(payload)
    relative = f"objects/sha256-{digest.removeprefix('sha256:')}"
    target = stage / relative
    if target.exists():
        if target.read_bytes() != payload:
            fail(f"object digest collision at {relative}")
    else:
        target.write_bytes(payload)
        os.chmod(target, stat.S_IMODE(mode))
    return {
        "role": role,
        "path": relative,
        "sha256": digest,
        "size_bytes": len(payload),
    }


def openssl_command(
    arguments: list[str], where: str
) -> subprocess.CompletedProcess[bytes]:
    executable = shutil.which("openssl")
    if executable is None:
        fail("openssl is required but was not found on PATH")
    result = subprocess.run(
        [executable, *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        fail(f"openssl failed while {where}: {detail}")
    return result


def normalize_private_key(private_key: Path, output: Path) -> tuple[Path, bytes]:
    require_regular_file(private_key, "private key")
    attempts = (
        [
            "pkey",
            "-in",
            str(private_key),
            "-inform",
            "DER",
            "-outform",
            "DER",
            "-out",
            str(output),
        ],
        ["pkey", "-in", str(private_key), "-outform", "DER", "-out", str(output)],
    )
    errors: list[str] = []
    for command in attempts:
        executable = shutil.which("openssl")
        if executable is None:
            fail("openssl is required but was not found on PATH")
        result = subprocess.run(
            [executable, *command],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode == 0:
            os.chmod(output, 0o600)
            break
        errors.append(result.stderr.decode("utf-8", "replace").strip())
    else:
        fail(
            "private key is not an openssl-readable DER or PEM key: "
            + " | ".join(errors)
        )
    public_der = openssl_command(
        ["pkey", "-in", str(output), "-inform", "DER", "-pubout", "-outform", "DER"],
        "deriving the Ed25519 public key",
    ).stdout
    prefix = bytes.fromhex("302a300506032b6570032100")
    if len(public_der) != len(prefix) + 32 or not public_der.startswith(prefix):
        fail("private key is not Ed25519")
    return output, public_der[len(prefix) :]


def sign_payload(private_key_der: Path, payload: bytes, temporary: Path) -> bytes:
    payload_path = temporary / "claim-signing-payload.json"
    signature_path = temporary / "claim-signature.bin"
    payload_path.write_bytes(payload)
    openssl_command(
        [
            "pkeyutl",
            "-sign",
            "-rawin",
            "-inkey",
            str(private_key_der),
            "-keyform",
            "DER",
            "-in",
            str(payload_path),
            "-out",
            str(signature_path),
        ],
        "signing the claim manifest",
    )
    signature = signature_path.read_bytes()
    if len(signature) != 64:
        fail(f"openssl produced an invalid Ed25519 signature length {len(signature)}")
    return signature


def build_bundle(spec_path: Path, private_key: Path, out_root: Path) -> Path:
    spec_path = spec_path.absolute()
    spec = resolve_spec(spec_path)
    claim_schema, section_7_roles, _ = release_contract(spec["schema"])
    is_r3 = spec["schema"] == SPEC_SCHEMA_V3
    is_r2 = spec["schema"] in (SPEC_SCHEMA_V2, SPEC_SCHEMA_V3)
    component_lifecycle_digest: str | None = None
    if is_r2:
        lifecycle_item = next(
            item for item in spec["objects"] if item["role"] == "component-lifecycle"
        )
        lifecycle_path = source_path(
            spec_path,
            lifecycle_item["source"],
            "object component-lifecycle",
        )
        component_lifecycle_digest = sha256_bytes(
            inspect_regular_bytes(lifecycle_path, "object component-lifecycle")
        )
    if out_root.exists():
        require_directory(out_root, "output root")
    else:
        out_root.mkdir(parents=True)
    if out_root.is_symlink():
        fail("output root must not be a symlink")

    with tempfile.TemporaryDirectory(
        prefix="wasm-biotic-release-key-"
    ) as key_temp_text:
        key_temp = Path(key_temp_text)
        normalized_key, public_key = normalize_private_key(
            private_key.absolute(), key_temp / "private.pk8"
        )
        key_id = sha256_bytes(public_key)
        stage = Path(tempfile.mkdtemp(prefix=".component-release-stage-", dir=out_root))
        try:
            (stage / "claim").mkdir()
            (stage / "objects").mkdir()
            (stage / "trees").mkdir()

            tree_refs = [
                copy_tree_from_spec(tree, spec_path, stage) for tree in spec["trees"]
            ]
            tree_refs.sort(key=lambda item: item["role"].encode("utf-8"))

            object_refs: list[dict[str, Any]] = []
            for item in spec["objects"]:
                path = source_path(spec_path, item["source"], f"object {item['role']}")
                if item["role"] == "behavioural-equivalence":
                    validate_behavioural_equivalence_report(
                        inspect_regular_bytes(path, "object behavioural-equivalence"),
                        spec["identities"],
                        "object behavioural-equivalence",
                        r2_claim=is_r2,
                        component_lifecycle_digest=component_lifecycle_digest,
                    )
                if item["role"] == "principal-isolation":
                    validate_principal_isolation_report(
                        inspect_regular_bytes(path, "object principal-isolation"),
                        spec["identities"],
                        "object principal-isolation",
                    )
                if item["role"] == "transport-confinement":
                    validate_transport_confinement_report(
                        inspect_regular_bytes(path, "object transport-confinement"),
                        spec["identities"],
                        "object transport-confinement",
                    )
                object_refs.append(add_object(stage, item["role"], path, None))
            object_refs.append(
                add_object(stage, "certifier-public-key", None, public_key)
            )
            object_refs.sort(key=lambda item: item["role"].encode("utf-8"))
            objects_by_role = {item["role"]: item for item in object_refs}
            section_7 = [dict(objects_by_role[role]) for role in section_7_roles]

            claim = {
                "schema": claim_schema,
                "component_complete_claim": True,
                "external_north_star_claim": False,
                "certifier": {"algorithm": "ed25519", "key_id": key_id},
                "identities": spec["identities"],
                "successor_lineage": spec["successor_lineage"],
                "gates": spec["gates"],
                "open_release_blockers": [],
                "trees": tree_refs,
                "objects": object_refs,
                "section_7_evidence": section_7,
            }
            if is_r2:
                claim["claim_profile"] = spec["claim_profile"]
            claim_bytes = canonical_json(claim)
            claim_digest = sha256_bytes(claim_bytes)
            (stage / "claim" / "manifest.json").write_bytes(claim_bytes)

            signing_payload = canonical_json(
                {
                    "claim_manifest_digest": claim_digest,
                    "schema": SIGNING_PAYLOAD_SCHEMA,
                }
            )
            signature = sign_payload(normalized_key, signing_payload, key_temp)
            signature_envelope = {
                "schema": SIGNATURE_SCHEMA,
                "algorithm": "ed25519",
                "certifier_key_id": key_id,
                "claim_manifest_digest": claim_digest,
                "signature_hex": signature.hex(),
            }
            signature_bytes = canonical_json(signature_envelope)
            signature_digest = sha256_bytes(signature_bytes)
            (stage / "claim" / "signature.json").write_bytes(signature_bytes)

            release = {
                "schema": RELEASE_SCHEMA,
                "digest_algorithm": "sha256",
                "canonicalization": CANONICALIZATION,
                "claim_manifest": {
                    "path": "claim/manifest.json",
                    "sha256": claim_digest,
                    "size_bytes": len(claim_bytes),
                },
                "claim_signature": {
                    "path": "claim/signature.json",
                    "sha256": signature_digest,
                    "size_bytes": len(signature_bytes),
                },
            }
            release_bytes = canonical_json(release)
            release_digest = sha256_bytes(release_bytes)
            (stage / "release.json").write_bytes(release_bytes)
            destination = out_root / f"sha256-{release_digest.removeprefix('sha256:')}"

            verify_bundle(stage, public_key.hex(), require_root_name=False)
            if destination.exists():
                require_directory(destination, "existing release destination")
                verify_bundle(destination, public_key.hex(), require_root_name=True)
                if release_bytes != (destination / "release.json").read_bytes():
                    fail(
                        f"release destination already exists with different bytes: {destination}"
                    )
                shutil.rmtree(stage)
                return destination
            os.replace(stage, destination)
            verify_bundle(destination, public_key.hex(), require_root_name=True)
            return destination
        except BaseException:
            if stage.exists():
                shutil.rmtree(stage)
            raise


def parse_object_ref(value: Any, where: str) -> dict[str, Any]:
    item = require_fields(value, ("role", "path", "sha256", "size_bytes"), where)
    role = require_role(item["role"], f"{where}.role")
    path = validate_relative_path(item["path"], f"{where}.path")
    digest = require_digest(item["sha256"], f"{where}.sha256")
    require_nonnegative_int(item["size_bytes"], f"{where}.size_bytes")
    if path != f"objects/sha256-{digest.removeprefix('sha256:')}":
        fail(f"{where}.path is not content-addressed by its digest")
    return item | {"role": role, "path": path}


def parse_tree_ref(value: Any, where: str) -> dict[str, Any]:
    fields = (
        "role",
        "path",
        "tree_manifest_sha256",
        "tree_manifest_size_bytes",
        "file_count",
        "files_size_bytes",
    )
    item = require_fields(value, fields, where)
    role = require_role(item["role"], f"{where}.role")
    path = validate_relative_path(item["path"], f"{where}.path")
    digest = require_digest(
        item["tree_manifest_sha256"], f"{where}.tree_manifest_sha256"
    )
    for field in ("tree_manifest_size_bytes", "file_count", "files_size_bytes"):
        require_nonnegative_int(item[field], f"{where}.{field}")
    if path != f"trees/sha256-{digest.removeprefix('sha256:')}":
        fail(f"{where}.path is not content-addressed by its tree-manifest digest")
    return item | {"role": role, "path": path}


def validate_sorted_unique_roles(items: list[dict[str, Any]], where: str) -> None:
    roles = [item["role"] for item in items]
    if len(roles) != len(set(roles)):
        fail(f"{where} contains duplicate roles")
    if roles != sorted(roles, key=lambda role: role.encode("utf-8")):
        fail(f"{where} is not sorted by UTF-8 role bytes")


def verify_file_ref(root: Path, ref: dict[str, Any], where: str) -> Path:
    relative = validate_relative_path(ref["path"], f"{where}.path")
    path = root / relative
    require_regular_file(path, where)
    digest, size = sha256_file(path)
    if digest != ref["sha256"] or size != ref["size_bytes"]:
        fail(f"{where} digest or size does not match its reference")
    return path


def verify_tree(root: Path, ref: dict[str, Any]) -> tuple[set[str], set[str]]:
    tree_root = root / ref["path"]
    require_directory(tree_root, f"tree {ref['role']}")
    tree_path = tree_root / "tree.json"
    digest, size = sha256_file(tree_path)
    if digest != ref["tree_manifest_sha256"] or size != ref["tree_manifest_size_bytes"]:
        fail(f"tree {ref['role']} manifest digest or size does not match")
    tree = load_json(tree_path, canonical=True)
    tree = require_fields(
        tree, ("schema", "digest_algorithm", "entries"), str(tree_path)
    )
    if tree["schema"] != TREE_SCHEMA or tree["digest_algorithm"] != "sha256":
        fail(f"tree {ref['role']} has an invalid schema or digest algorithm")
    entries = require_list(tree["entries"], f"tree {ref['role']}.entries")
    expected_files = {f"{ref['path']}/tree.json"}
    expected_dirs = {ref["path"], f"{ref['path']}/files"}
    seen: set[str] = set()
    folded: dict[str, str] = {}
    paths_in_order: list[str] = []
    total_size = 0
    for index, raw_entry in enumerate(entries):
        entry = require_fields(
            raw_entry,
            ("path", "sha256", "size_bytes"),
            f"tree {ref['role']} entry {index}",
        )
        relative = validate_relative_path(
            entry["path"], f"tree {ref['role']} entry {index}.path"
        )
        require_digest(entry["sha256"], f"tree {ref['role']} entry {index}.sha256")
        require_nonnegative_int(
            entry["size_bytes"], f"tree {ref['role']} entry {index}.size_bytes"
        )
        if relative in seen:
            fail(f"tree {ref['role']} contains duplicate path {relative!r}")
        case = relative.casefold()
        if case in folded:
            fail(
                f"tree {ref['role']} has case-colliding paths {folded[case]!r} and {relative!r}"
            )
        seen.add(relative)
        folded[case] = relative
        paths_in_order.append(relative)
        file_ref = {
            "path": f"{ref['path']}/files/{relative}",
            "sha256": entry["sha256"],
            "size_bytes": entry["size_bytes"],
        }
        verify_file_ref(root, file_ref, f"tree {ref['role']} file {relative}")
        expected_files.add(file_ref["path"])
        parent = PurePosixPath(file_ref["path"]).parent
        while str(parent) not in (".", ""):
            expected_dirs.add(str(parent))
            parent = parent.parent
        total_size += entry["size_bytes"]
    if paths_in_order != sorted(paths_in_order, key=lambda path: path.encode("utf-8")):
        fail(f"tree {ref['role']} entries are not sorted by UTF-8 path bytes")
    if len(entries) != ref["file_count"] or total_size != ref["files_size_bytes"]:
        fail(f"tree {ref['role']} aggregate file count or size does not match")
    return expected_files, expected_dirs


def tree_file(root: Path, tree_ref: dict[str, Any], relative: str, where: str) -> Path:
    validate_relative_path(relative, where)
    path = root / tree_ref["path"] / "files" / relative
    require_regular_file(path, where)
    return path


def expect_field(value: Any, field: str, expected: Any, where: str) -> None:
    if not isinstance(value, dict):
        fail(f"{where} must be an object")
    if field not in value:
        fail(f"{where} is missing field {field!r}")
    if value[field] != expected:
        fail(f"{where}.{field} does not match the signed release claim")


def require_positive_int(value: Any, where: str, *, maximum: int = (1 << 64) - 1) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        fail(f"{where} must be an integer in the inclusive range 1..{maximum}")
    return value


def _strict_string_array(
    value: Any, where: str, *, nonempty: bool = False
) -> list[str]:
    items = [
        require_string(item, f"{where}[{index}]")
        for index, item in enumerate(require_list(value, where))
    ]
    if nonempty and not items:
        fail(f"{where} must not be empty")
    if items != sorted(set(items)):
        fail(f"{where} must contain strictly sorted unique strings")
    return items


def _canonical_http_host(value: Any, where: str) -> str:
    host = require_string(value, where)
    if len(host) > 253 or not host.isascii() or host.lower() != host:
        fail(f"{where} is not a canonical HTTP host")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        labels = host.split(".")
        if any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not all(character.islower() or character.isdigit() or character == "-" for character in label)
            for label in labels
        ):
            fail(f"{where} is not a canonical HTTP host")
    else:
        if str(address) != host:
            fail(f"{where} is not a canonical IP address")
    return host


def _canonical_http_path_prefix(value: Any, where: str) -> str:
    path = require_string(value, where)
    if (
        len(path) > 4096
        or not path.isascii()
        or not path.startswith("/")
        or any(not 0x21 <= byte <= 0x7E for byte in path.encode("ascii"))
        or any(character in path for character in ("\\", "?", "#", "%"))
        or "//" in path
        or any(segment in (".", "..") for segment in path.split("/"))
    ):
        fail(f"{where} is not a canonical HTTP path prefix")
    return path


def _canonical_cidr(value: Any, where: str) -> str:
    cidr = require_string(value, where)
    try:
        network = ipaddress.ip_network(cidr, strict=True)
    except ValueError:
        fail(f"{where} is not a canonical non-host CIDR network")
    address, prefix = cidr.split("/", 1)
    if str(network.network_address) != address or str(network.prefixlen) != prefix:
        fail(f"{where} is not a canonical CIDR network")
    if network.prefixlen == 0:
        fail(f"{where} must not use a zero-length CIDR prefix")
    return cidr


def validate_http_transport_constraints(
    value: Any, ceilings: Any, where: str
) -> list[str]:
    """Validate the closed Rust R3 constraint model and return secret prefixes."""

    ceilings = require_fields(
        ceilings,
        (
            "schema",
            "max_blob_bytes",
            "max_total_blob_bytes",
            "max_random_bytes",
            "max_wake_delay_ms",
            "max_http_timeout_ms",
            "max_component_fuel",
            "max_component_memory_bytes",
            "max_component_output_bytes",
            "max_component_wall_time_ms",
            "transaction_namespaces",
        ),
        f"{where} shared ceilings",
    )
    expect_field(
        ceilings,
        "schema",
        "wasm-biotic.capability-constraints.v1",
        f"{where} shared ceilings",
    )
    max_blob_bytes = require_positive_int(
        ceilings["max_blob_bytes"], f"{where} shared ceilings.max_blob_bytes"
    )
    max_http_timeout_ms = require_positive_int(
        ceilings["max_http_timeout_ms"],
        f"{where} shared ceilings.max_http_timeout_ms",
    )
    for field in (
        "max_total_blob_bytes",
        "max_random_bytes",
        "max_wake_delay_ms",
        "max_component_fuel",
        "max_component_memory_bytes",
        "max_component_output_bytes",
        "max_component_wall_time_ms",
    ):
        require_positive_int(ceilings[field], f"{where} shared ceilings.{field}")
    _strict_string_array(
        ceilings["transaction_namespaces"],
        f"{where} shared ceilings.transaction_namespaces",
        nonempty=True,
    )

    constraint = require_fields(
        value,
        (
            "schema",
            "origins",
            "methods",
            "request_headers",
            "response_headers",
            "max_url_bytes",
            "max_request_body_bytes",
            "max_response_body_bytes",
            "max_timeout_ms",
            "max_concurrency",
            "redirects",
            "credential_bindings",
        ),
        where,
    )
    expect_field(
        constraint, "schema", "wasm-biotic.http-transport-constraints.v1", where
    )
    methods = _strict_string_array(constraint["methods"], f"{where}.methods", nonempty=True)
    if any(method not in ("delete", "get", "head", "patch", "post", "put") for method in methods):
        fail(f"{where}.methods contains a method outside the closed vocabulary")

    forbidden_headers = {
        "connection",
        "content-length",
        "host",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "via",
    }
    header_pattern = re.compile(r"[!#$%&'*+.^_`|~0-9a-z-]{1,256}\Z")
    request = require_fields(
        constraint["request_headers"],
        ("allowed_names", "max_count", "max_total_bytes"),
        f"{where}.request_headers",
    )
    response = require_fields(
        constraint["response_headers"],
        ("exposed_names", "max_count", "max_total_bytes"),
        f"{where}.response_headers",
    )
    allowed_names = _strict_string_array(
        request["allowed_names"], f"{where}.request_headers.allowed_names"
    )
    exposed_names = _strict_string_array(
        response["exposed_names"], f"{where}.response_headers.exposed_names"
    )
    for name in allowed_names:
        if not header_pattern.fullmatch(name) or name in forbidden_headers:
            fail(f"{where} request header {name!r} is invalid or permanently forbidden")
    for name in exposed_names:
        if not header_pattern.fullmatch(name):
            fail(f"{where} response header {name!r} is not canonical")
    require_positive_int(
        request["max_count"], f"{where}.request_headers.max_count", maximum=(1 << 32) - 1
    )
    request_header_bytes = require_positive_int(
        request["max_total_bytes"], f"{where}.request_headers.max_total_bytes"
    )
    require_positive_int(
        response["max_count"], f"{where}.response_headers.max_count", maximum=(1 << 32) - 1
    )
    response_header_bytes = require_positive_int(
        response["max_total_bytes"], f"{where}.response_headers.max_total_bytes"
    )
    max_url_bytes = require_positive_int(constraint["max_url_bytes"], f"{where}.max_url_bytes")
    max_request_body = require_positive_int(
        constraint["max_request_body_bytes"], f"{where}.max_request_body_bytes"
    )
    max_response_body = require_positive_int(
        constraint["max_response_body_bytes"], f"{where}.max_response_body_bytes"
    )
    max_timeout = require_positive_int(
        constraint["max_timeout_ms"], f"{where}.max_timeout_ms"
    )
    require_positive_int(
        constraint["max_concurrency"], f"{where}.max_concurrency", maximum=(1 << 32) - 1
    )
    if (
        max_timeout > max_http_timeout_ms
        or any(
            bound > max_blob_bytes
            for bound in (
                max_url_bytes,
                max_request_body,
                max_response_body,
                request_header_bytes,
                response_header_bytes,
            )
        )
    ):
        fail(f"{where} transport bounds exceed the shared capability ceilings")
    expect_field(constraint, "redirects", "deny", where)

    origins_value = require_list(constraint["origins"], f"{where}.origins")
    if not origins_value:
        fail(f"{where}.origins must not be empty")
    origins: dict[str, dict[str, Any]] = {}
    authorities: set[tuple[str, str, int]] = set()
    ordered_origin_ids: list[str] = []
    for index, raw_origin in enumerate(origins_value):
        origin_where = f"{where}.origins[{index}]"
        origin = require_fields(
            raw_origin,
            ("id", "scheme", "host", "port", "path_prefixes", "dns", "tls"),
            origin_where,
        )
        origin_id = require_string(origin["id"], f"{origin_where}.id")
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,126}", origin_id):
            fail(f"{origin_where}.id is not a canonical contract id")
        ordered_origin_ids.append(origin_id)
        expect_field(origin, "scheme", "https", origin_where)
        host = _canonical_http_host(origin["host"], f"{origin_where}.host")
        port = require_positive_int(origin["port"], f"{origin_where}.port", maximum=65535)
        authority = ("https", host, port)
        if authority in authorities:
            fail(f"{where}.origins contains a duplicate HTTPS authority")
        authorities.add(authority)
        paths = _strict_string_array(
            origin["path_prefixes"], f"{origin_where}.path_prefixes", nonempty=True
        )
        for path_index, path in enumerate(paths):
            _canonical_http_path_prefix(path, f"{origin_where}.path_prefixes[{path_index}]")
        dns = require_fields(origin["dns"], ("policy", "cidrs"), f"{origin_where}.dns")
        cidrs = _strict_string_array(dns["cidrs"], f"{origin_where}.dns.cidrs")
        if dns["policy"] == "public-only":
            if cidrs:
                fail(f"{origin_where}.dns public-only policy must have no CIDRs")
        elif dns["policy"] == "exact-cidrs":
            if not cidrs:
                fail(f"{origin_where}.dns exact-cidrs policy requires CIDRs")
        else:
            fail(f"{origin_where}.dns.policy is outside the closed vocabulary")
        for cidr_index, cidr in enumerate(cidrs):
            _canonical_cidr(cidr, f"{origin_where}.dns.cidrs[{cidr_index}]")
        tls = require_fields(
            origin["tls"],
            ("minimum_version", "server_name", "peer_spki_sha256"),
            f"{origin_where}.tls",
        )
        expect_field(tls, "minimum_version", "tls-1.3", f"{origin_where}.tls")
        server_name = _canonical_http_host(
            tls["server_name"], f"{origin_where}.tls.server_name"
        )
        if server_name != host:
            fail(f"{origin_where}.tls.server_name must equal the signed host")
        pins = _strict_string_array(
            tls["peer_spki_sha256"],
            f"{origin_where}.tls.peer_spki_sha256",
            nonempty=True,
        )
        for pin_index, pin in enumerate(pins):
            require_digest(pin, f"{origin_where}.tls.peer_spki_sha256[{pin_index}]")
        origins[origin_id] = origin
    if ordered_origin_ids != sorted(set(ordered_origin_ids)):
        fail(f"{where}.origins must be unique and strictly sorted by id")

    credential_values = require_list(
        constraint["credential_bindings"], f"{where}.credential_bindings"
    )
    credential_keys: list[tuple[str, str, str]] = []
    handles: set[str] = set()
    prefixes: list[str] = []
    for index, raw_binding in enumerate(credential_values):
        binding_where = f"{where}.credential_bindings[{index}]"
        binding = require_fields(
            raw_binding,
            ("handle", "origin_id", "header_name", "value_prefix", "placement"),
            binding_where,
        )
        handle = require_string(binding["handle"], f"{binding_where}.handle")
        if len(handle) > 256 or not handle.isascii() or any(not 0x21 <= ord(ch) <= 0x7E for ch in handle):
            fail(f"{binding_where}.handle is not a visible ASCII token")
        if handle in handles:
            fail(f"{where}.credential_bindings repeats credential handle {handle!r}")
        handles.add(handle)
        origin_id = require_string(binding["origin_id"], f"{binding_where}.origin_id")
        if origin_id not in origins:
            fail(f"{binding_where}.origin_id does not name a signed origin")
        header_name = require_string(binding["header_name"], f"{binding_where}.header_name")
        if (
            not header_pattern.fullmatch(header_name)
            or header_name in forbidden_headers
            or header_name not in allowed_names
        ):
            fail(f"{binding_where}.header_name is not an allowed exact placement")
        prefix = require_string(binding["value_prefix"], f"{binding_where}.value_prefix")
        if len(prefix) > 1024 or not prefix.isascii() or any(not 0x20 <= ord(ch) <= 0x7E for ch in prefix):
            fail(f"{binding_where}.value_prefix is not printable ASCII")
        expect_field(binding, "placement", "append-to-header-value", binding_where)
        credential_keys.append((handle, origin_id, header_name))
        prefixes.append(prefix)
    if credential_keys != sorted(set(credential_keys)):
        fail(
            f"{where}.credential_bindings must be unique and sorted by handle, origin and header"
        )
    return sorted(set(prefixes))


def verify_package_cross_bindings(
    root: Path,
    tree_ref: dict[str, Any],
    kind: str,
    identities: dict[str, Any],
    expected_key_id: str,
    public_key: bytes,
    *,
    r2: bool = False,
    r3: bool = False,
) -> dict[str, Any] | None:
    graph_digest = identities[f"{kind}_graph_manifest_digest"]
    tcb_digest = identities["native_tcb_inventory_digest"]
    profile_digest = identities["capability_profile_digest"]
    wit_digest = identities["wit_contract_digest"]

    manifest_path = tree_file(root, tree_ref, "manifest.json", f"{kind} manifest")
    actual_manifest_digest, _ = sha256_file(manifest_path)
    if actual_manifest_digest != graph_digest:
        fail(f"{kind} manifest bytes do not match its signed graph identity")
    manifest = load_json(manifest_path, canonical=True)
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema") != "wasm-biotic.factory-graph.v1"
    ):
        fail(f"{kind} manifest has the wrong schema")
    incumbent_digest = identities["incumbent_graph_manifest_digest"]
    if kind == "incumbent":
        if "previous_graph" in manifest:
            fail("incumbent manifest must not contain previous_graph")
    elif manifest.get("previous_graph") != incumbent_digest:
        fail("successor manifest previous_graph does not name the incumbent")

    package_path = tree_file(root, tree_ref, "package.json", f"{kind} package index")
    package = load_json(package_path, canonical=True)
    package = require_fields(
        package,
        (
            "certification_digest",
            "certified_kernel_tcb_inventory_digest",
            "graph_manifest_digest",
            "package_schema",
            "root_authority_digest",
            "root_executable_digest",
            "validation_report_digest",
        ),
        f"{kind} package index",
    )
    expect_field(
        package,
        "package_schema",
        "wasm-biotic.component-graph-package.v1",
        f"{kind} package index",
    )
    expect_field(
        package, "graph_manifest_digest", graph_digest, f"{kind} package index"
    )
    expect_field(
        package,
        "certified_kernel_tcb_inventory_digest",
        tcb_digest,
        f"{kind} package index",
    )

    certification_path = tree_file(
        root,
        tree_ref,
        "certification/release-certification.json",
        f"{kind} release certification",
    )
    certification_digest, _ = sha256_file(certification_path)
    expect_field(
        package,
        "certification_digest",
        certification_digest,
        f"{kind} package index",
    )
    certification = load_json(certification_path, canonical=True)
    certification = require_fields(
        certification,
        ("certifier_key_id", "schema", "signature", "statement"),
        f"{kind} release certification",
    )
    expect_field(
        certification,
        "schema",
        "wasm-biotic.release-certification.v1",
        f"{kind} release certification",
    )
    expect_field(
        certification,
        "certifier_key_id",
        expected_key_id,
        f"{kind} release certification",
    )
    signature = certification["signature"]
    if not isinstance(signature, dict):
        fail(f"{kind} release certification signature must be an object")
    expect_field(
        signature, "algorithm", "ed25519", f"{kind} release certification signature"
    )
    signature_hex = signature.get("signature_hex")
    if not isinstance(signature_hex, str) or not HEX_128_RE.fullmatch(signature_hex):
        fail(f"{kind} release certification has a malformed Ed25519 signature")
    statement = certification["statement"]
    if not isinstance(statement, dict):
        fail(f"{kind} release certification statement must be an object")
    expect_field(
        statement,
        "graph_manifest_digest",
        graph_digest,
        f"{kind} certificate statement",
    )
    expect_field(
        statement,
        "native_tcb_inventory_digest",
        tcb_digest,
        f"{kind} certificate statement",
    )
    expect_field(
        statement,
        "substrate_profile_digest",
        profile_digest,
        f"{kind} certificate statement",
    )
    expect_field(
        statement, "wit_package_digest", wit_digest, f"{kind} certificate statement"
    )
    package_signing_payload = canonical_json(
        {
            "certifier_key_id": expected_key_id,
            "schema": PACKAGE_SIGNING_PAYLOAD_SCHEMA,
            "statement": statement,
        }
    )
    verify_signature(public_key, package_signing_payload, bytes.fromhex(signature_hex))

    tcb_relative = (
        "certified-kernel-tcb/sha256-" + tcb_digest.removeprefix("sha256:") + ".json"
    )
    tcb_path = tree_file(
        root, tree_ref, tcb_relative, f"{kind} certified TCB inventory"
    )
    actual_tcb_digest, _ = sha256_file(tcb_path)
    if actual_tcb_digest != tcb_digest:
        fail(f"{kind} certified TCB inventory bytes do not match the claim")
    inventory = load_json(tcb_path, canonical=False)
    if (
        not isinstance(inventory, dict)
        or inventory.get("schema") != "wasm-biotic.native-tcb-inventory.v1"
    ):
        fail(f"{kind} certified TCB inventory has the wrong schema")
    conformance = inventory.get("conformance")
    if (
        not isinstance(conformance, dict)
        or conformance.get("component_complete_claim") is not True
    ):
        fail(
            f"{kind} certified TCB inventory does not self-declare component completeness"
        )

    profile_path = tree_file(
        root, tree_ref, "substrate-profile.json", f"{kind} profile"
    )
    actual_profile_digest, _ = sha256_file(profile_path)
    if actual_profile_digest != profile_digest:
        fail(f"{kind} substrate profile bytes do not match the claim")
    wit_relative = "wit/sha256-" + wit_digest.removeprefix("sha256:") + "-package.json"
    wit_path = tree_file(root, tree_ref, wit_relative, f"{kind} WIT package")
    actual_wit_digest, _ = sha256_file(wit_path)
    if actual_wit_digest != wit_digest:
        fail(f"{kind} WIT package bytes do not match the claim")
    if r2:
        return verify_r2_package_closure(
            root,
            tree_ref,
            kind,
            identities,
            manifest,
            package,
            statement,
            r3=r3,
        )
    return None


def verify_r2_package_closure(
    root: Path,
    tree_ref: dict[str, Any],
    kind: str,
    identities: dict[str, Any],
    manifest: dict[str, Any],
    package: dict[str, Any],
    statement: dict[str, Any],
    *,
    r3: bool = False,
) -> dict[str, Any] | None:
    """Reconstruct the complete R2 package/certificate/principal closure.

    Historical v1 bundles retain their exact verifier behaviour. R2 has a
    stronger contract: every certificate join and every per-consumer alias is
    independently re-derived from retained bytes before the aggregate claim is
    accepted.
    """

    statement_fields = (
        "schema",
        "graph_manifest_digest",
        "native_tcb_inventory_digest",
        "wit_package_digest",
        "metadata_digest",
        "raw_artifacts",
        "derived_artifacts",
        "derivation_descriptor_digest",
        "substrate_profile_digest",
        "wit_world_digests",
        "composition_configuration_digests",
        "constraint_digests",
        "validation_report_digest",
        "validator_identity",
        "validator_version",
    )
    phase = "R3" if r3 else "R2"
    statement = require_fields(statement, statement_fields, f"{kind} {phase} statement")
    expect_field(
        statement,
        "schema",
        "wasm-biotic.release-certification-statement.v1",
        f"{kind} {phase} statement",
    )

    metadata_digest = require_digest(
        manifest.get("metadata"), f"{kind} manifest metadata"
    )
    expect_field(statement, "metadata_digest", metadata_digest, f"{kind} {phase} statement")
    metadata_path = tree_file(root, tree_ref, "metadata.json", f"{kind} metadata")
    actual_metadata_digest, _ = sha256_file(metadata_path)
    if actual_metadata_digest != metadata_digest:
        fail(f"{kind} metadata bytes do not match the manifest")
    metadata = load_json(metadata_path, canonical=True)
    metadata = require_fields(
        metadata,
        (
            "schema",
            "wit_package_digest",
            "wit_world_digests",
            "substrate_profile_digest",
            "derivation_descriptor_digest",
        ),
        f"{kind} metadata",
    )
    expect_field(
        metadata,
        "schema",
        "wasm-biotic.factory-graph-metadata.v1",
        f"{kind} metadata",
    )

    profile_digest = identities["capability_profile_digest"]
    expect_field(
        metadata, "substrate_profile_digest", profile_digest, f"{kind} metadata"
    )
    descriptor_identity = identities[f"{kind}_derivation_descriptor_digest"]
    expect_field(
        metadata,
        "derivation_descriptor_digest",
        descriptor_identity,
        f"{kind} metadata",
    )
    expect_field(
        statement,
        "derivation_descriptor_digest",
        descriptor_identity,
        f"{kind} {phase} statement",
    )

    profile_path = tree_file(
        root, tree_ref, "substrate-profile.json", f"{kind} {phase} profile"
    )
    profile = load_json(profile_path, canonical=True)
    profile_fields = (
            "schema",
            "wit_package",
            "primitives",
            "static_grant_model",
            "root_node",
            "import_alias_scheme",
            "principal_id_scheme",
            "principals",
            "ceilings",
    )
    if r3:
        profile_fields = (*profile_fields, "http_transport")
    profile = require_fields(profile, profile_fields, f"{kind} {phase} profile")
    for field, expected in (
        (
            "schema",
            "wasm-biotic.factory-substrate-profile.v3"
            if r3
            else "wasm-biotic.factory-substrate-profile.v2",
        ),
        ("wit_package", "wasm-biotic:factory@0.1.0"),
        ("static_grant_model", "per-consumer-import-alias"),
        ("import_alias_scheme", "wasm-biotic.per-consumer-host-import.v1"),
        ("principal_id_scheme", "wasm-biotic.graph-node-principal.v1"),
    ):
        expect_field(profile, field, expected, f"{kind} {phase} profile")
    expect_field(
        profile, "root_node", manifest.get("root_node"), f"{kind} {phase} profile"
    )
    expected_primitives = [
        "blob-store",
        "transaction-store",
        "clock",
        "component-runner",
        "http-transport",
        "key-service",
        "activation",
        "audit-log",
    ]
    if profile["primitives"] != expected_primitives:
        fail(f"{kind} {phase} profile does not declare the exact eight mechanisms")

    descriptor_path = tree_file(
        root,
        tree_ref,
        "derivation-descriptor.json",
        f"{kind} R2 derivation descriptor",
    )
    actual_descriptor_digest, _ = sha256_file(descriptor_path)
    if actual_descriptor_digest != descriptor_identity:
        fail(f"{kind} R2 descriptor bytes do not match the claim")
    descriptor = load_json(descriptor_path, canonical=True)
    descriptor = require_fields(
        descriptor,
        ("schema", "wit_package_digest", "sources", "executables", "tool"),
        f"{kind} R2 descriptor",
    )
    expect_field(
        descriptor,
        "schema",
        "wasm-biotic.component-derivation-descriptor.v2",
        f"{kind} R2 descriptor",
    )
    expect_field(
        descriptor,
        "wit_package_digest",
        metadata["wit_package_digest"],
        f"{kind} R2 descriptor",
    )

    nodes_value = manifest.get("nodes")
    if not isinstance(nodes_value, list) or not nodes_value:
        fail(f"{kind} R2 manifest has no component nodes")
    nodes: dict[str, dict[str, Any]] = {}
    for index, value in enumerate(nodes_value):
        if not isinstance(value, dict):
            fail(f"{kind} R2 manifest node {index} is not an object")
        node_id = require_string(value.get("id"), f"{kind} node {index}.id")
        if node_id in nodes:
            fail(f"{kind} R2 manifest repeats node {node_id!r}")
        require_digest(value.get("component_digest"), f"{kind} node {node_id}")
        if not isinstance(value.get("grants"), list):
            fail(f"{kind} node {node_id} grants are absent")
        nodes[node_id] = value

    raw_artifacts = {
        node_id: node["component_digest"] for node_id, node in nodes.items()
    }
    if statement["raw_artifacts"] != raw_artifacts:
        fail(f"{kind} R2 certificate raw artifact map is incomplete or substituted")
    for node_id, digest in raw_artifacts.items():
        raw_path = tree_file(
            root,
            tree_ref,
            f"components/{digest_stem(digest)}.wasm",
            f"{kind} raw component {node_id}",
        )
        actual, _ = sha256_file(raw_path)
        if actual != digest:
            fail(f"{kind} raw component {node_id} digest mismatch")

    sources = descriptor["sources"]
    if not isinstance(sources, list):
        fail(f"{kind} R2 descriptor sources are absent")
    expected_sources = [
        {
            "node_id": node_id,
            "component_digest": node["component_digest"],
            "world": node.get("world"),
        }
        for node_id, node in sorted(nodes.items())
    ]
    if sources != expected_sources:
        fail(f"{kind} R2 descriptor source map differs from the manifest")

    bindings = manifest.get("bindings")
    if not isinstance(bindings, list):
        fail(f"{kind} R2 manifest bindings are absent")
    direct_host_bindings: dict[str, list[tuple[str, str]]] = {
        node_id: [] for node_id in nodes
    }
    component_dependencies: dict[str, list[str]] = {node_id: [] for node_id in nodes}
    for index, binding in enumerate(bindings):
        if not isinstance(binding, dict):
            fail(f"{kind} R2 binding {index} is not an object")
        consumer = binding.get("consumer")
        import_name = binding.get("import")
        provider = binding.get("provider")
        if consumer not in nodes or not isinstance(import_name, str) or not isinstance(provider, dict):
            fail(f"{kind} R2 binding {index} is malformed")
        provider_kind = provider.get("kind")
        if provider_kind == "host":
            capability = provider.get("capability")
            if not isinstance(capability, str):
                fail(f"{kind} R2 host binding {index} has no capability")
            direct_host_bindings[consumer].append((capability, import_name))
        elif provider_kind == "component":
            target = provider.get("node")
            if target not in nodes:
                fail(f"{kind} R2 component binding {index} has an unknown target")
            component_dependencies[consumer].append(target)
        else:
            fail(f"{kind} R2 binding {index} has an unknown provider kind")

    principals_value = profile["principals"]
    if not isinstance(principals_value, list):
        fail(f"{kind} R2 profile principals are absent")
    principal_consumers = [
        principal.get("consumer") if isinstance(principal, dict) else None
        for principal in principals_value
    ]
    if principal_consumers != sorted(nodes):
        fail(f"{kind} R2 profile must contain one canonically ordered principal per node")
    principals: dict[str, dict[str, Any]] = {}
    aliases: set[str] = set()
    for principal in principals_value:
        assert isinstance(principal, dict)
        principal = require_fields(
            principal,
            (
                "consumer",
                "authority_component_digest",
                "principal_seed",
                "scoped_component_digest",
                "host_imports",
            ),
            f"{kind} R2 principal",
        )
        consumer = principal["consumer"]
        node = nodes[consumer]
        expect_field(
            principal,
            "authority_component_digest",
            node["component_digest"],
            f"{kind} principal {consumer}",
        )
        expected_seed = sha256_bytes(
            canonical_json(
                {
                    "authority_component_digest": node["component_digest"],
                    "consumer": consumer,
                    "schema": "wasm-biotic.principal-seed.v1",
                }
            )
        )
        expect_field(
            principal,
            "principal_seed",
            expected_seed,
            f"{kind} principal {consumer}",
        )
        scoped_digest = require_digest(
            principal["scoped_component_digest"],
            f"{kind} principal {consumer} scoped component",
        )
        scoped_path = tree_file(
            root,
            tree_ref,
            f"scoped-components/{digest_stem(scoped_digest)}.wasm",
            f"{kind} scoped component {consumer}",
        )
        actual_scoped, _ = sha256_file(scoped_path)
        if actual_scoped != scoped_digest:
            fail(f"{kind} scoped component {consumer} digest mismatch")

        imports_value = principal["host_imports"]
        if not isinstance(imports_value, list):
            fail(f"{kind} principal {consumer} host imports are absent")
        if imports_value != sorted(imports_value, key=lambda item: item.get("alias", "")):
            fail(f"{kind} principal {consumer} host imports are not canonical")
        node_grants = node["grants"]
        expected_imports: list[dict[str, Any]] = []
        for capability, source_import in direct_host_bindings[consumer]:
            matching_grants = [
                grant
                for grant in node_grants
                if isinstance(grant, dict) and grant.get("capability") == capability
            ]
            if len(matching_grants) != 1:
                fail(f"{kind} node {consumer} lacks one exact direct {capability} grant")
            grant = matching_grants[0]
            expected_source = f"wasm-biotic:factory/{capability}@0.1.0"
            if source_import != expected_source:
                fail(f"{kind} node {consumer} has a noncanonical host binding")
            alias_token = sha256_bytes(
                canonical_json(
                    {
                        "authority_component_digest": node["component_digest"],
                        "capability": capability,
                        "consumer": consumer,
                        "schema": "wasm-biotic.host-import-alias-material.v1",
                        "source_import": source_import,
                    }
                )
            )[7:]
            expected_imports.append(
                {
                    "alias": f"wasm-biotic:factory/host-{alias_token}@0.1.0",
                    "source_import": source_import,
                    "capability": capability,
                    "scope": grant.get("scope"),
                    "constraints": grant.get("constraints"),
                }
            )
        expected_imports.sort(key=lambda item: item["alias"].encode("utf-8"))
        if imports_value != expected_imports:
            fail(f"{kind} principal {consumer} imports do not equal direct manifest grants")
        for item in imports_value:
            alias = item["alias"]
            if alias in aliases:
                fail(f"{kind} R2 profile repeats host alias {alias!r}")
            aliases.add(alias)
        principals[consumer] = principal

    r3_http_digest: str | None = None
    r3_common_constraint_digest: str | None = None
    r3_http_import: dict[str, Any] | None = None
    if r3:
        http_profile_where = f"{kind} R3 profile.http_transport"
        http_profile = require_fields(
            profile["http_transport"], ("mode", "bindings"), http_profile_where
        )
        expect_field(http_profile, "mode", "bounded-external", http_profile_where)
        http_bindings = require_list(
            http_profile["bindings"], f"{http_profile_where}.bindings"
        )
        if len(http_bindings) != 1:
            fail(f"{kind} R3 profile must contain exactly one HTTP transport binding")
        http_binding = require_fields(
            http_bindings[0],
            ("consumer", "alias", "constraints"),
            f"{http_profile_where}.bindings[0]",
        )
        expect_field(
            http_binding,
            "consumer",
            "exchange-service",
            f"{http_profile_where}.bindings[0]",
        )
        exchange_principal = principals.get("exchange-service")
        if exchange_principal is None:
            fail(f"{kind} R3 profile omits the exchange-service principal")
        exchange_http_imports = [
            item
            for item in exchange_principal["host_imports"]
            if item.get("capability") == "http-transport"
        ]
        if len(exchange_http_imports) != 1:
            fail(
                f"{kind} R3 exchange-service principal must contain exactly one HTTP import"
            )
        r3_http_import = exchange_http_imports[0]
        if http_binding != {
            "consumer": "exchange-service",
            "alias": r3_http_import["alias"],
            "constraints": r3_http_import["constraints"],
        }:
            fail(
                f"{kind} R3 profile HTTP binding is not the exact principal projection"
            )
        direct_http_bindings = [
            (consumer, source_import)
            for consumer, consumer_bindings in direct_host_bindings.items()
            for capability, source_import in consumer_bindings
            if capability == "http-transport"
        ]
        if direct_http_bindings != [
            ("exchange-service", "wasm-biotic:factory/http-transport@0.1.0")
        ]:
            fail(
                f"{kind} R3 manifest must contain only the exchange-service HTTP host binding"
            )
        http_grants = [
            (node_id, grant)
            for node_id, node in nodes.items()
            for grant in node["grants"]
            if isinstance(grant, dict) and grant.get("capability") == "http-transport"
        ]
        if len(http_grants) != 1 or http_grants[0][0] != "exchange-service":
            fail(f"{kind} R3 manifest must contain one exchange-service HTTP grant")
        r3_http_digest = require_digest(
            http_grants[0][1].get("constraints"), f"{kind} R3 HTTP grant constraints"
        )
        expect_field(
            identities,
            f"{kind}_http_transport_constraint_digest",
            r3_http_digest,
            "R3 release identities",
        )
        expect_field(
            r3_http_import,
            "constraints",
            r3_http_digest,
            f"{kind} exchange HTTP principal import",
        )
        r3_common_constraint_digest = sha256_bytes(canonical_json(profile["ceilings"]))
        if r3_common_constraint_digest == r3_http_digest:
            fail(f"{kind} R3 HTTP constraint must be separate from the shared ceiling")
        for node_id, node in nodes.items():
            for grant in node["grants"]:
                if not isinstance(grant, dict):
                    fail(f"{kind} R3 node {node_id} contains a malformed grant")
                expected_constraint = (
                    r3_http_digest
                    if grant.get("capability") == "http-transport"
                    else r3_common_constraint_digest
                )
                if grant.get("constraints") != expected_constraint:
                    fail(
                        f"{kind} R3 grant constraints do not equal the exact "
                        "HTTP constraint or shared ceiling"
                    )

    # The human-readable principal inventory is a retained release object, not
    # a disposable projection.  Reconstruct its exact canonical bytes from the
    # signed graph/profile mapping, bind the build-spec identity to those
    # bytes, and require the package copy to be byte-for-byte identical.
    expected_principal_inventory = {
        "graph_manifest_digest": identities[f"{kind}_graph_manifest_digest"],
        "import_alias_scheme": profile["import_alias_scheme"],
        "principal_id_scheme": profile["principal_id_scheme"],
        "principals": principals_value,
        "schema": "wasm-biotic.principal-inventory-evidence.v1",
    }
    expected_principal_inventory_bytes = canonical_json(expected_principal_inventory)
    expected_principal_inventory_digest = sha256_bytes(
        expected_principal_inventory_bytes
    )
    expect_field(
        identities,
        f"{kind}_principal_inventory_digest",
        expected_principal_inventory_digest,
        "R2 release identities",
    )
    principal_inventory_path = tree_file(
        root,
        tree_ref,
        "evidence/principal-inventory.json",
        f"{kind} principal inventory",
    )
    actual_principal_inventory_digest, _ = sha256_file(principal_inventory_path)
    actual_principal_inventory_bytes = inspect_regular_bytes(
        principal_inventory_path, f"{kind} principal inventory"
    )
    if (
        actual_principal_inventory_digest != expected_principal_inventory_digest
        or actual_principal_inventory_bytes != expected_principal_inventory_bytes
    ):
        fail(f"{kind} retained principal inventory differs from the signed mapping")

    def static_closure(authority: str) -> set[str]:
        pending = [authority]
        reached: set[str] = set()
        while pending:
            node_id = pending.pop()
            if node_id in reached:
                continue
            reached.add(node_id)
            pending.extend(component_dependencies[node_id])
        return reached

    executables_value = descriptor["executables"]
    if not isinstance(executables_value, list):
        fail(f"{kind} R2 descriptor executables are absent")
    invocations = manifest.get("invocations")
    if not isinstance(invocations, list):
        fail(f"{kind} R2 manifest invocations are absent")
    expected_authorities = sorted(
        {manifest.get("root_node"), *(
            edge.get("target") for edge in invocations if isinstance(edge, dict)
        )}
    )
    authority_ids = [
        item.get("authority_node") if isinstance(item, dict) else None
        for item in executables_value
    ]
    if authority_ids != expected_authorities:
        fail(f"{kind} R2 executable authority set differs from graph topology")
    executable_map: dict[str, str] = {}
    for executable in executables_value:
        assert isinstance(executable, dict)
        executable = require_fields(
            executable,
            (
                "authority_node",
                "authority_digest",
                "executable_digest",
                "source_digests",
                "scoped_source_digests",
                "principal_seeds",
                "world",
                "configuration_digest",
            ),
            f"{kind} R2 executable",
        )
        authority = executable["authority_node"]
        node = nodes[authority]
        expect_field(
            executable,
            "authority_digest",
            node["component_digest"],
            f"{kind} R2 executable {authority}",
        )
        closure = static_closure(authority)
        expected_raw = sorted({nodes[item]["component_digest"] for item in closure})
        expected_scoped = sorted(
            {principals[item]["scoped_component_digest"] for item in closure}
        )
        expected_seeds = sorted({principals[item]["principal_seed"] for item in closure})
        if executable["source_digests"] != expected_raw:
            fail(f"{kind} R2 executable {authority} has an incomplete raw closure")
        if executable["scoped_source_digests"] != expected_scoped:
            fail(f"{kind} R2 executable {authority} has an incomplete scoped closure")
        if executable["principal_seeds"] != expected_seeds:
            fail(f"{kind} R2 executable {authority} has an incomplete principal closure")
        executable_digest = require_digest(
            executable["executable_digest"], f"{kind} executable {authority}"
        )
        executable_path = tree_file(
            root,
            tree_ref,
            f"derived/{digest_stem(executable_digest)}.wasm",
            f"{kind} R2 executable {authority}",
        )
        actual_executable, _ = sha256_file(executable_path)
        if actual_executable != executable_digest:
            fail(f"{kind} R2 executable {authority} digest mismatch")
        configuration_digest = require_digest(
            executable["configuration_digest"],
            f"{kind} executable {authority} configuration",
        )
        configuration_path = tree_file(
            root,
            tree_ref,
            f"composition-configs/{digest_stem(configuration_digest)}.config",
            f"{kind} composition configuration {authority}",
        )
        actual_configuration, _ = sha256_file(configuration_path)
        if actual_configuration != configuration_digest:
            fail(f"{kind} composition configuration {authority} digest mismatch")
        executable_map[authority] = executable_digest

    derived_artifacts = dict(executable_map)
    derived_artifacts.update(
        {
            f"scoped:{consumer}": principal["scoped_component_digest"]
            for consumer, principal in principals.items()
        }
    )
    if statement["derived_artifacts"] != dict(sorted(derived_artifacts.items())):
        fail(f"{kind} R2 certificate derived artifact map is incomplete or substituted")

    root_node = manifest.get("root_node")
    if root_node not in nodes:
        fail(f"{kind} R2 root node is absent")
    expect_field(
        package,
        "root_authority_digest",
        nodes[root_node]["component_digest"],
        f"{kind} package index",
    )
    expect_field(
        package,
        "root_executable_digest",
        executable_map[root_node],
        f"{kind} package index",
    )
    root_path = tree_file(root, tree_ref, "factory-root.wasm", f"{kind} factory root")
    root_digest, _ = sha256_file(root_path)
    if root_digest != executable_map[root_node]:
        fail(f"{kind} factory-root bytes differ from the descriptor")

    configuration_digests = sorted(
        {item["configuration_digest"] for item in executables_value}
    )
    if statement["composition_configuration_digests"] != configuration_digests:
        fail(f"{kind} R2 certificate configuration closure mismatch")
    constraint_digests = sorted(
        {
            grant["constraints"]
            for node in nodes.values()
            for grant in node["grants"]
            if isinstance(grant, dict)
        }
    )
    if statement["constraint_digests"] != constraint_digests:
        fail(f"{kind} R2 certificate constraint closure mismatch")
    if r3:
        assert r3_common_constraint_digest is not None
        assert r3_http_digest is not None
        expected_r3_constraints = sorted(
            (r3_common_constraint_digest, r3_http_digest)
        )
        if constraint_digests != expected_r3_constraints:
            fail(
                f"{kind} R3 certificate must close over exactly the shared ceiling "
                "and one HTTP constraint"
            )
        package_tree = load_json(root / tree_ref["path"] / "tree.json", canonical=True)
        package_entries = require_list(
            require_object_field(package_tree, "entries", f"{kind} R3 package tree"),
            f"{kind} R3 package tree.entries",
        )
        retained_constraint_paths = {
            entry.get("path")
            for entry in package_entries
            if isinstance(entry, dict)
            and isinstance(entry.get("path"), str)
            and entry["path"].startswith("constraints/")
        }
        expected_constraint_paths = {
            f"constraints/{digest_stem(digest)}.json"
            for digest in expected_r3_constraints
        }
        if retained_constraint_paths != expected_constraint_paths:
            fail(
                f"{kind} R3 package contains a missing or extra retained constraint file"
            )
    r3_credential_prefixes: list[str] = []
    for digest in constraint_digests:
        constraint_path = tree_file(
            root,
            tree_ref,
            f"constraints/{digest_stem(digest)}.json",
            f"{kind} constraint {digest}",
        )
        actual_constraint, _ = sha256_file(constraint_path)
        if actual_constraint != digest:
            fail(f"{kind} constraint digest mismatch")
        constraint = load_json(constraint_path, canonical=True)
        if r3 and digest == r3_common_constraint_digest:
            if constraint != profile["ceilings"]:
                fail(f"{kind} R3 shared constraint bytes differ from profile ceilings")
        elif r3 and digest == r3_http_digest:
            r3_credential_prefixes = validate_http_transport_constraints(
                constraint, profile["ceilings"], f"{kind} R3 HTTP constraint"
            )

    world_digests = metadata["wit_world_digests"]
    if not isinstance(world_digests, dict) or statement["wit_world_digests"] != world_digests:
        fail(f"{kind} R2 certificate WIT-world closure mismatch")
    for digest in set(world_digests.values()):
        require_digest(digest, f"{kind} WIT world")
        world_path = tree_file(
            root,
            tree_ref,
            f"wit/{digest_stem(digest)}-worlds.wit",
            f"{kind} WIT world",
        )
        actual_world, _ = sha256_file(world_path)
        if actual_world != digest:
            fail(f"{kind} WIT world digest mismatch")

    validation_digest = require_digest(
        package["validation_report_digest"], f"{kind} strict validation report"
    )
    expect_field(
        statement,
        "validation_report_digest",
        validation_digest,
        f"{kind} R2 statement",
    )
    strict_path = tree_file(
        root,
        tree_ref,
        "evidence/strict-validation.json",
        f"{kind} strict validation report",
    )
    actual_validation, _ = sha256_file(strict_path)
    if actual_validation != validation_digest:
        fail(f"{kind} strict validation report digest mismatch")
    strict = load_json(strict_path, canonical=True)
    if strict.get("schema") != "wasm-biotic.component-strict-validation-report.v2":
        fail(f"{kind} strict validation report has the wrong R2 schema")
    expected_inventory = identities[f"{kind}_principal_inventory_digest"]
    expect_field(
        strict,
        "principal_inventory_digest",
        expected_inventory,
        f"{kind} strict validation report",
    )
    enforcement = strict.get("principal_enforcement")
    if not isinstance(enforcement, dict):
        fail(f"{kind} strict validation report omits principal enforcement")
    for flag in (
        "graph_union_absent",
        "all_manifest_nodes_covered",
        "all_direct_host_bindings_aliased",
        "no_unaliased_host_imports",
        "aliases_unique",
        "grants_exact",
    ):
        if enforcement.get(flag) is not True:
            fail(f"{kind} strict validation report does not prove {flag}")
    if enforcement.get("result") != "pass":
        fail(f"{kind} strict principal enforcement did not pass")
    if r3:
        assert r3_http_import is not None
        return {
            "exchange_component_digest": nodes["exchange-service"]["component_digest"],
            "http_transport_alias": r3_http_import["alias"],
            "http_transport_constraint_digest": r3_http_digest,
            "credential_value_prefixes": r3_credential_prefixes,
        }
    return None


def verify_native_cross_bindings(
    root: Path,
    trees_by_role: dict[str, dict[str, Any]],
    objects_by_role: dict[str, dict[str, Any]],
    identities: dict[str, Any],
) -> None:
    tcb_digest = identities["native_tcb_inventory_digest"]
    native_tcb = tree_file(
        root,
        trees_by_role["native-source"],
        "kernel/native-tcb.json",
        "native source TCB inventory",
    )
    actual_tcb_digest, _ = sha256_file(native_tcb)
    if actual_tcb_digest != tcb_digest:
        fail("native source TCB inventory bytes do not match the claim")
    inventory = load_json(native_tcb, canonical=False)
    if not isinstance(inventory, dict):
        fail("native source TCB inventory must be an object")

    contract = tree_file(
        root,
        trees_by_role["normative-contract"],
        "contracts/component-complete/CONFORMANCE.md",
        "component-complete conformance contract",
    )
    actual_contract_digest, _ = sha256_file(contract)
    if actual_contract_digest != identities["component_complete_contract_digest"]:
        fail("component-complete conformance contract bytes do not match the claim")

    executable = objects_by_role["native-executable"]
    attestation_ref = objects_by_role["native-build-attestation"]
    attestation_path = root / attestation_ref["path"]
    attestation = load_json(attestation_path, canonical=False)
    if not isinstance(attestation, dict):
        fail("native build attestation must be an object")
    expect_field(
        attestation,
        "schema",
        "wasm-biotic.native-build-attestation.v1",
        "native build attestation",
    )
    expect_field(attestation, "gate_result", "pass", "native build attestation")
    artifact = attestation.get("native_artifact")
    if not isinstance(artifact, dict):
        fail("native build attestation native_artifact must be an object")
    expect_field(artifact, "sha256", executable["sha256"], "native build artifact")
    expect_field(
        artifact, "size_bytes", executable["size_bytes"], "native build artifact"
    )
    compiled = attestation.get("compiled_inventory")
    if not isinstance(compiled, dict):
        fail("native build attestation compiled_inventory must be an object")
    expect_field(compiled, "sha256", tcb_digest, "native build compiled inventory")
    build = attestation.get("build")
    if not isinstance(build, dict):
        fail("native build attestation build must be an object")
    expect_field(
        build, "target", identities["native_target"], "native build attestation"
    )
    if "incumbent_principal_inventory_digest" in identities:
        verify_r2_native_source_closure(
            root,
            trees_by_role["native-source"],
            inventory,
            attestation,
        )


def verify_r2_native_source_closure(
    root: Path,
    native_tree: dict[str, Any],
    inventory: dict[str, Any],
    attestation: dict[str, Any],
) -> None:
    """Recompute the R2 native source identity from retained source bytes."""

    crate = inventory.get("crate")
    if not isinstance(crate, dict):
        fail("R2 native inventory has no crate identity")
    source_revision = crate.get("source_revision")
    if not isinstance(source_revision, dict):
        fail("R2 native inventory has no source revision")
    expect_field(
        source_revision,
        "status",
        "content-addressed-source-closure",
        "R2 native source revision",
    )
    expect_field(
        source_revision,
        "algorithm",
        R2_NATIVE_SOURCE_ALGORITHM,
        "R2 native source revision",
    )
    expect_field(
        source_revision,
        "scope",
        R2_NATIVE_SOURCE_SCOPE,
        "R2 native source revision",
    )
    expected_revision = require_digest(
        source_revision.get("value"), "R2 native source revision.value"
    )

    tree_manifest = load_json(
        root / native_tree["path"] / "tree.json", canonical=True
    )
    if not isinstance(tree_manifest, dict):
        fail("R2 native source tree manifest is malformed")
    entries = require_list(tree_manifest.get("entries"), "R2 native source entries")
    retained_paths = {
        entry.get("path")
        for entry in entries
        if isinstance(entry, dict) and isinstance(entry.get("path"), str)
    }
    selected = sorted(
        (
            path
            for path in retained_paths
            if path in {"kernel/Cargo.toml", "kernel/Cargo.lock"}
            or (path.startswith("kernel/src/") and path.endswith(".rs"))
            or (
                path.startswith("wit/wasm-biotic/")
                and path.endswith(".wit")
                and "/" not in path.removeprefix("wit/wasm-biotic/")
            )
        ),
        key=lambda path: path.encode("utf-8"),
    )
    if not selected:
        fail("R2 native source closure contains no declared source files")
    required_singletons = {"kernel/Cargo.toml", "kernel/Cargo.lock"}
    if not required_singletons.issubset(selected):
        fail("R2 native source closure omits Cargo.toml or Cargo.lock")

    inventory_bytes = bytearray()
    file_rows: list[dict[str, Any]] = []
    for relative in selected:
        source = tree_file(
            root,
            native_tree,
            relative,
            f"R2 native source closure file {relative}",
        )
        digest, _ = sha256_file(source)
        inventory_bytes.extend(
            f"{digest.removeprefix('sha256:')}  {relative}\n".encode("utf-8")
        )
        file_rows.append({"path": relative, "sha256": digest})
    actual_revision = sha256_bytes(bytes(inventory_bytes))
    if actual_revision != expected_revision:
        fail(
            "R2 native source closure bytes do not reproduce the inventory source revision"
        )

    source_closure = attestation.get("source_closure")
    if not isinstance(source_closure, dict):
        fail("R2 native build attestation has no source closure")
    expect_field(
        source_closure,
        "sha256",
        actual_revision,
        "R2 native build source closure",
    )
    expect_field(
        source_closure,
        "algorithm",
        R2_NATIVE_SOURCE_ALGORITHM,
        "R2 native build source closure",
    )
    expected_attestation_scope = R2_NATIVE_SOURCE_SCOPE.replace(
        "this self-referential inventory is excluded",
        "kernel/native-tcb.json is excluded as self-referential",
    )
    expect_field(
        source_closure,
        "scope",
        expected_attestation_scope,
        "R2 native build source closure",
    )
    expect_field(
        source_closure,
        "inventory_entries_verified",
        len(file_rows),
        "R2 native build source closure",
    )
    expect_field(
        source_closure,
        "files",
        file_rows,
        "R2 native build source closure",
    )
    expect_field(
        source_closure,
        "recomputation_result",
        "pass",
        "R2 native build source closure",
    )


def scan_bundle(root: Path) -> tuple[set[str], set[str]]:
    require_directory(root, "bundle root")
    files: set[str] = set()
    directories: set[str] = set()
    folded: dict[str, str] = {}
    inodes: dict[tuple[int, int], str] = {}
    for current, directory_names, file_names in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in tuple(directory_names):
            path = current_path / name
            info = path.lstat()
            relative = path.relative_to(root).as_posix()
            validate_relative_path(relative, str(path))
            if stat.S_ISLNK(info.st_mode):
                fail(f"bundle contains symlink {relative!r}")
            if not stat.S_ISDIR(info.st_mode):
                fail(f"bundle contains special entry {relative!r}")
            case = relative.casefold()
            if case in folded:
                fail(
                    f"bundle has case-colliding paths {folded[case]!r} and {relative!r}"
                )
            folded[case] = relative
            directories.add(relative)
        for name in file_names:
            path = current_path / name
            info = require_regular_file(path, str(path))
            relative = path.relative_to(root).as_posix()
            validate_relative_path(relative, str(path))
            case = relative.casefold()
            if case in folded:
                fail(
                    f"bundle has case-colliding paths {folded[case]!r} and {relative!r}"
                )
            folded[case] = relative
            inode = (info.st_dev, info.st_ino)
            if info.st_nlink > 1 or inode in inodes:
                fail(f"bundle contains hard-linked file {relative!r}")
            inodes[inode] = relative
            reject_private_or_state_bytes(path.read_bytes(), relative)
            files.add(relative)
    return files, directories


def verify_signature(public_key: bytes, payload: bytes, signature: bytes) -> None:
    prefix = bytes.fromhex("302a300506032b6570032100")
    with tempfile.TemporaryDirectory(
        prefix="wasm-biotic-release-verify-"
    ) as temporary_text:
        temporary = Path(temporary_text)
        public_path = temporary / "public.der"
        payload_path = temporary / "payload.json"
        signature_path = temporary / "signature.bin"
        public_path.write_bytes(prefix + public_key)
        payload_path.write_bytes(payload)
        signature_path.write_bytes(signature)
        openssl_command(
            [
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                str(public_path),
                "-keyform",
                "DER",
                "-rawin",
                "-in",
                str(payload_path),
                "-sigfile",
                str(signature_path),
            ],
            "verifying the claim signature",
        )


def verify_bundle(
    root: Path, expected_public_key_hex: str, *, require_root_name: bool = True
) -> str:
    if not HEX_64_RE.fullmatch(expected_public_key_hex):
        fail("expected public key must be exactly 64 lowercase hex characters")
    public_key = bytes.fromhex(expected_public_key_hex)
    require_directory(root, "bundle root")
    if root.is_symlink():
        fail("bundle root must not be a symlink")
    # Preflight the physical tree before opening any manifest-selected path so
    # an intermediate symlink cannot redirect even a read outside the bundle.
    actual_files, actual_dirs = scan_bundle(root)

    release_path = root / "release.json"
    require_regular_file(release_path, "release.json")
    release_bytes = release_path.read_bytes()
    release = parse_json_bytes(release_bytes, str(release_path), canonical=True)
    release = require_fields(
        release,
        (
            "schema",
            "digest_algorithm",
            "canonicalization",
            "claim_manifest",
            "claim_signature",
        ),
        "release.json",
    )
    if release["schema"] != RELEASE_SCHEMA:
        fail("release.json has the wrong schema")
    if (
        release["digest_algorithm"] != "sha256"
        or release["canonicalization"] != CANONICALIZATION
    ):
        fail("release.json has an unsupported digest or canonicalization")
    release_digest = sha256_bytes(release_bytes)
    expected_name = f"sha256-{release_digest.removeprefix('sha256:')}"
    if require_root_name and root.name != expected_name:
        fail(f"bundle root name must be {expected_name!r}")

    root_ref_fields = ("path", "sha256", "size_bytes")
    claim_ref = require_fields(
        release["claim_manifest"], root_ref_fields, "claim_manifest"
    )
    signature_ref = require_fields(
        release["claim_signature"], root_ref_fields, "claim_signature"
    )
    if claim_ref["path"] != "claim/manifest.json":
        fail("claim_manifest path must be claim/manifest.json")
    if signature_ref["path"] != "claim/signature.json":
        fail("claim_signature path must be claim/signature.json")
    require_digest(claim_ref["sha256"], "claim_manifest.sha256")
    require_digest(signature_ref["sha256"], "claim_signature.sha256")
    require_nonnegative_int(claim_ref["size_bytes"], "claim_manifest.size_bytes")
    require_nonnegative_int(signature_ref["size_bytes"], "claim_signature.size_bytes")
    claim_path = verify_file_ref(root, claim_ref, "claim manifest")
    signature_path = verify_file_ref(root, signature_ref, "claim signature")

    claim = load_json(claim_path, canonical=True)
    if not isinstance(claim, dict):
        fail("claim manifest must be an object")
    claim_schema = claim.get("schema")
    if not isinstance(claim_schema, str) or claim_schema not in CLAIM_SCHEMAS:
        fail("claim manifest has the wrong schema")
    is_r3 = claim_schema == CLAIM_SCHEMA_V3
    is_r2 = claim_schema in (CLAIM_SCHEMA_V2, CLAIM_SCHEMA_V3)
    claim_fields: tuple[str, ...] = (
        "schema",
        "component_complete_claim",
        "external_north_star_claim",
        "certifier",
        "identities",
        "successor_lineage",
        "gates",
        "open_release_blockers",
        "trees",
        "objects",
        "section_7_evidence",
    )
    if is_r2:
        claim_fields = (*claim_fields[:3], "claim_profile", *claim_fields[3:])
    claim = require_fields(claim, claim_fields, "claim manifest")
    require_bool(claim["component_complete_claim"], True, "component_complete_claim")
    require_bool(claim["external_north_star_claim"], False, "external_north_star_claim")
    expected_claim_profile = R3_CLAIM_PROFILE if is_r3 else R2_CLAIM_PROFILE
    if is_r2 and claim["claim_profile"] != expected_claim_profile:
        fail("claim manifest has the wrong R2/R3 claim profile")
    identities = validate_identities(
        claim["identities"], "identities", r2=is_r2, r3=is_r3
    )
    validate_lineage(claim["successor_lineage"], identities, "successor_lineage")
    validate_gates(claim["gates"], "gates")
    blockers = require_list(claim["open_release_blockers"], "open_release_blockers")
    if blockers:
        fail("open_release_blockers is not empty")

    expected_key_id = sha256_bytes(public_key)
    certifier = require_fields(claim["certifier"], ("algorithm", "key_id"), "certifier")
    if certifier["algorithm"] != "ed25519" or certifier["key_id"] != expected_key_id:
        fail("claim certifier does not match the independently supplied public key")

    signature_envelope = load_json(signature_path, canonical=True)
    signature_envelope = require_fields(
        signature_envelope,
        (
            "schema",
            "algorithm",
            "certifier_key_id",
            "claim_manifest_digest",
            "signature_hex",
        ),
        "claim signature",
    )
    if signature_envelope["schema"] != SIGNATURE_SCHEMA:
        fail("claim signature has the wrong schema")
    if signature_envelope["algorithm"] != "ed25519":
        fail("claim signature algorithm is not Ed25519")
    if signature_envelope["certifier_key_id"] != expected_key_id:
        fail("claim signature key id does not match the independently supplied key")
    if signature_envelope["claim_manifest_digest"] != claim_ref["sha256"]:
        fail("claim signature names a different claim manifest")
    signature_hex = signature_envelope["signature_hex"]
    if not isinstance(signature_hex, str) or not HEX_128_RE.fullmatch(signature_hex):
        fail("claim signature must be exactly 128 lowercase hex characters")
    payload = canonical_json(
        {
            "claim_manifest_digest": claim_ref["sha256"],
            "schema": SIGNING_PAYLOAD_SCHEMA,
        }
    )
    verify_signature(public_key, payload, bytes.fromhex(signature_hex))

    tree_values = require_list(claim["trees"], "trees")
    trees = [
        parse_tree_ref(item, f"trees[{index}]")
        for index, item in enumerate(tree_values)
    ]
    validate_sorted_unique_roles(trees, "trees")
    tree_roles = {item["role"] for item in trees}
    missing_trees = sorted(TREE_ROLES - tree_roles)
    if missing_trees:
        fail(f"claim omits mandatory tree roles {missing_trees}")

    object_values = require_list(claim["objects"], "objects")
    objects = [
        parse_object_ref(item, f"objects[{index}]")
        for index, item in enumerate(object_values)
    ]
    validate_sorted_unique_roles(objects, "objects")
    objects_by_role = {item["role"]: item for item in objects}
    _, section_7_roles, required_object_roles = release_contract(claim_schema)
    missing_objects = sorted(
        (required_object_roles | {"certifier-public-key"}) - set(objects_by_role)
    )
    if missing_objects:
        fail(f"claim omits mandatory object roles {missing_objects}")

    evidence_values = require_list(claim["section_7_evidence"], "section_7_evidence")
    evidence = [
        parse_object_ref(item, f"section_7_evidence[{index}]")
        for index, item in enumerate(evidence_values)
    ]
    evidence_roles = [item["role"] for item in evidence]
    if evidence_roles != list(section_7_roles):
        fail(
            "section_7_evidence must contain every mandatory role exactly once in canonical order"
        )
    evidence_paths = [item["path"] for item in evidence]
    if len(evidence_paths) != len(set(evidence_paths)):
        fail("each mandatory Section 7 role must reference a distinct evidence object")
    for item in evidence:
        if item != objects_by_role[item["role"]]:
            fail(
                f"Section 7 evidence role {item['role']!r} does not match its object inventory entry"
            )

    expected_files = {
        "release.json",
        "claim/manifest.json",
        "claim/signature.json",
    }
    expected_dirs = {"claim", "objects", "trees"}
    transport_report: dict[str, Any] | None = None
    for item in objects:
        path = verify_file_ref(root, item, f"object {item['role']}")
        if item["role"] == "behavioural-equivalence":
            validate_behavioural_equivalence_report(
                path.read_bytes(),
                identities,
                "object behavioural-equivalence",
                r2_claim=is_r2,
                component_lifecycle_digest=objects_by_role["component-lifecycle"][
                    "sha256"
                ],
            )
        if item["role"] == "principal-isolation":
            validate_principal_isolation_report(
                path.read_bytes(), identities, "object principal-isolation"
            )
        if item["role"] == "transport-confinement":
            transport_report = validate_transport_confinement_report(
                path.read_bytes(), identities, "object transport-confinement"
            )
        expected_files.add(item["path"])
    public_ref = objects_by_role["certifier-public-key"]
    if (root / public_ref["path"]).read_bytes() != public_key:
        fail("retained public-key object differs from independently supplied key")
    for item in trees:
        files, directories = verify_tree(root, item)
        expected_files.update(files)
        expected_dirs.update(directories)

    trees_by_role = {item["role"]: item for item in trees}
    incumbent_package_facts = verify_package_cross_bindings(
        root,
        trees_by_role["incumbent-package"],
        "incumbent",
        identities,
        expected_key_id,
        public_key,
        r2=is_r2,
        r3=is_r3,
    )
    successor_package_facts = verify_package_cross_bindings(
        root,
        trees_by_role["successor-package"],
        "successor",
        identities,
        expected_key_id,
        public_key,
        r2=is_r2,
        r3=is_r3,
    )
    if is_r3:
        if (
            transport_report is None
            or incumbent_package_facts is None
            or successor_package_facts is None
        ):
            fail("R3 release omits reconstructed transport confinement facts")
        validate_transport_confinement_package_bindings(
            transport_report,
            {
                "incumbent": incumbent_package_facts,
                "successor": successor_package_facts,
            },
            "object transport-confinement",
        )
    verify_native_cross_bindings(root, trees_by_role, objects_by_role, identities)

    if actual_files != expected_files:
        missing = sorted(expected_files - actual_files)
        extra = sorted(actual_files - expected_files)
        fail(f"bundle closure has missing files {missing} and unlisted files {extra}")
    if actual_dirs != expected_dirs:
        missing = sorted(expected_dirs - actual_dirs)
        extra = sorted(actual_dirs - expected_dirs)
        fail(
            f"bundle closure has missing directories {missing} and unlisted directories {extra}"
        )
    return release_digest


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(
        description="Build or verify a signed, content-addressed Wasm-Biotic release bundle."
    )
    subcommands = command.add_subparsers(dest="command", required=True)
    build = subcommands.add_parser(
        "build", help="build and atomically publish a release bundle"
    )
    build.add_argument(
        "--spec", required=True, type=Path, help="release build-spec JSON"
    )
    build.add_argument(
        "--private-key",
        required=True,
        type=Path,
        help="one-shot Ed25519 PKCS#8 DER or PEM key",
    )
    build.add_argument(
        "--out-root",
        required=True,
        type=Path,
        help="parent directory for sha256-<root> releases",
    )
    verify = subcommands.add_parser("verify", help="verify the complete bundle closure")
    verify.add_argument("bundle", type=Path, help="sha256-<root> bundle directory")
    verify.add_argument(
        "--expected-public-key-hex",
        required=True,
        help="independently obtained raw 32-byte Ed25519 key as 64 lowercase hex",
    )
    return command


def main(arguments: list[str] | None = None) -> int:
    options = parser().parse_args(arguments)
    try:
        if options.command == "build":
            output = build_bundle(options.spec, options.private_key, options.out_root)
            print(output)
        else:
            digest = verify_bundle(options.bundle, options.expected_public_key_hex)
            print(f"verified {digest} {options.bundle}")
        return 0
    except BundleError as error:
        print(f"component-release-bundle: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
