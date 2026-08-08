#!/usr/bin/env python3
"""Execute and materialize the focused R1/R2/R3 isolation and durability gates.

The resulting reports are deliberately focused release inputs, not aggregate
component-complete claims.  Package and lifecycle identities are derived from
the supplied bytes.  A report is written only after every named command exits
successfully with the expected Rust test count.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any


DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
TEST_RESULT_RE = re.compile(
    r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; "
    r"(?:\d+) measured; (\d+) filtered out"
)
PASSED_TEST_RE = re.compile(r"^test (.+) \.\.\. ok$", re.MULTILINE)
R1_WORK_STATE_MEDIA_TYPE = "application/vnd.wasm-biotic.r1-work-state.v1+json"
STRICT_REPORT_SCHEMA_V1 = "wasm-biotic.component-strict-validation-report.v1"
STRICT_REPORT_SCHEMA_V2 = "wasm-biotic.component-strict-validation-report.v2"
LIFECYCLE_SCHEMA_V1 = "wasm-biotic.component-lifecycle-execution.v1"
LIFECYCLE_SCHEMA_V2 = "wasm-biotic.component-lifecycle-execution.v2"
R2_PROFILE_SCHEMA = "wasm-biotic.factory-substrate-profile.v2"
R3_PROFILE_SCHEMA = "wasm-biotic.factory-substrate-profile.v3"
R2_STATIC_GRANT_MODEL = "per-consumer-import-alias"
R2_IMPORT_ALIAS_SCHEME = "wasm-biotic.per-consumer-host-import.v1"
R2_PRINCIPAL_ID_SCHEME = "wasm-biotic.graph-node-principal.v1"
R2_PRINCIPAL_SEED_SCHEMA = "wasm-biotic.principal-seed.v1"
R2_ALIAS_MATERIAL_SCHEMA = "wasm-biotic.host-import-alias-material.v1"
R2_AUTHORITY_TRACE_PHASES = [
    "incumbent-cycle",
    "activation-and-successor-cycle",
    "rollback",
    "restart-post-rollback-cycle",
]
CARGO_WORKSPACE_TARGET_PARTITIONS = {
    None: "root",
    "Cargo.toml": "root",
    "components/Cargo.toml": "components",
    "kernel/Cargo.toml": "kernel",
    "tools/component-graph-package/Cargo.toml": "component-graph-package",
    "tools/independent-substrate/Cargo.toml": "independent-substrate",
}


class GateError(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def read_bytes(path: Path, label: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as error:
        raise GateError(f"cannot read {label} at {path}: {error}") from error


def read_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    data = read_bytes(path, label)
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise GateError(f"{label} is not JSON: {error}") from error
    if not isinstance(value, dict):
        raise GateError(f"{label} must be a JSON object")
    return value, data


def require(condition: bool, message: str) -> None:
    if not condition:
        raise GateError(message)


def relative_path(path: Path, repository: Path) -> str:
    try:
        return path.resolve().relative_to(repository).as_posix()
    except ValueError as error:
        raise GateError(f"release input is outside the repository: {path}") from error


def digest_file(path: Path, expected: str, label: str) -> str:
    require(bool(DIGEST_RE.fullmatch(expected)), f"invalid {label} digest: {expected}")
    actual = sha256_bytes(read_bytes(path, label))
    require(actual == expected, f"{label} digest mismatch: {actual} != {expected}")
    return actual


def require_digest(value: Any, label: str) -> str:
    require(
        isinstance(value, str) and DIGEST_RE.fullmatch(value) is not None,
        f"invalid {label} digest: {value!r}",
    )
    return value


def r2_package_authority_binding(
    package_dir: Path,
    manifest: dict[str, Any],
    graph_digest: str,
    statement: dict[str, Any],
    strict: dict[str, Any],
    cohort: str,
) -> dict[str, Any]:
    profile, profile_bytes = read_json(
        package_dir / "substrate-profile.json", "R2 substrate profile"
    )
    require(
        profile.get("schema")
        == (R3_PROFILE_SCHEMA if cohort == "R3" else R2_PROFILE_SCHEMA)
        and profile.get("static_grant_model") == R2_STATIC_GRANT_MODEL,
        f"{cohort} profile does not use per-consumer import-alias authority",
    )
    require(
        profile.get("import_alias_scheme") == R2_IMPORT_ALIAS_SCHEME
        and profile.get("principal_id_scheme") == R2_PRINCIPAL_ID_SCHEME,
        "R2 profile uses an unsupported principal or import-alias scheme",
    )
    require(
        statement.get("substrate_profile_digest") == sha256_bytes(profile_bytes),
        "release certificate does not bind the R2 substrate profile",
    )

    principals = profile.get("principals")
    nodes = manifest.get("nodes")
    require(isinstance(nodes, list), "R2 graph manifest nodes are absent")
    require(
        isinstance(principals, list) and len(principals) == len(nodes),
        "R2 principal inventory does not cover every manifest node",
    )
    nodes_by_id = {
        node.get("id"): node
        for node in nodes
        if isinstance(node, dict) and isinstance(node.get("id"), str)
    }
    require(
        len(nodes_by_id) == len(nodes),
        "R2 manifest node identities are absent or duplicated",
    )

    expected_inventory = {
        "graph_manifest_digest": graph_digest,
        "import_alias_scheme": R2_IMPORT_ALIAS_SCHEME,
        "principal_id_scheme": R2_PRINCIPAL_ID_SCHEME,
        "principals": principals,
        "schema": "wasm-biotic.principal-inventory-evidence.v1",
    }
    inventory, inventory_bytes = read_json(
        package_dir / "evidence/principal-inventory.json",
        "R2 principal inventory",
    )
    require(
        inventory == expected_inventory
        and inventory_bytes == canonical_json_bytes(expected_inventory),
        "retained R2 principal inventory is not the canonical signed profile projection",
    )
    inventory_digest = sha256_bytes(inventory_bytes)
    require(
        strict.get("principal_inventory_digest") == inventory_digest,
        "R2 strict report does not bind the retained principal inventory",
    )
    require(
        strict.get("principals") == principals,
        "R2 strict report principal inventory differs from the signed profile",
    )

    enforcement = strict.get("principal_enforcement")
    require(isinstance(enforcement, dict), "R2 strict principal enforcement is absent")
    for flag in [
        "graph_union_absent",
        "all_manifest_nodes_covered",
        "all_direct_host_bindings_aliased",
        "no_unaliased_host_imports",
        "aliases_unique",
        "grants_exact",
    ]:
        require(
            enforcement.get(flag) is True,
            f"R2 strict report did not establish {flag}",
        )
    require(
        enforcement.get("result") == "pass",
        "R2 strict principal enforcement did not pass",
    )

    derived_artifacts = statement.get("derived_artifacts")
    require(
        isinstance(derived_artifacts, dict),
        "R2 certificate has no derived artifact inventory",
    )
    consumers: list[str] = []
    aliases: set[str] = set()
    pure_principals = 0
    for principal in principals:
        require(isinstance(principal, dict), "R2 principal row is malformed")
        consumer = principal.get("consumer")
        require(
            isinstance(consumer, str)
            and consumer not in consumers
            and consumer in nodes_by_id,
            "R2 principal consumer is absent, duplicated or undeclared",
        )
        consumers.append(consumer)
        authority = require_digest(
            principal.get("authority_component_digest"),
            f"R2 principal {consumer} authority",
        )
        require(
            nodes_by_id[consumer].get("component_digest") == authority,
            f"R2 principal {consumer} is not bound to its manifest component",
        )
        expected_seed = sha256_bytes(
            canonical_json_bytes(
                {
                    "authority_component_digest": authority,
                    "consumer": consumer,
                    "schema": R2_PRINCIPAL_SEED_SCHEMA,
                }
            )
        )
        require(
            principal.get("principal_seed") == expected_seed,
            f"R2 principal {consumer} seed is not content-derived exactly",
        )
        scoped_digest = require_digest(
            principal.get("scoped_component_digest"),
            f"R2 principal {consumer} scoped component",
        )
        require(
            derived_artifacts.get(f"scoped:{consumer}") == scoped_digest,
            f"R2 certificate does not bind principal {consumer}'s scoped bytes",
        )
        digest_file(
            package_dir
            / "scoped-components"
            / f"{scoped_digest.replace(':', '-')}.wasm",
            scoped_digest,
            f"R2 principal {consumer} scoped component",
        )
        host_imports = principal.get("host_imports")
        require(
            isinstance(host_imports, list),
            f"R2 principal {consumer} host imports are malformed",
        )
        if not host_imports:
            pure_principals += 1
        principal_aliases: list[str] = []
        for host_import in host_imports:
            require(
                isinstance(host_import, dict),
                f"R2 principal {consumer} host import is malformed",
            )
            source_import = host_import.get("source_import")
            capability = host_import.get("capability")
            require(
                isinstance(source_import, str)
                and isinstance(capability, str)
                and isinstance(host_import.get("scope"), str),
                f"R2 principal {consumer} host import identity is malformed",
            )
            require_digest(
                host_import.get("constraints"),
                f"R2 principal {consumer} host import constraints",
            )
            alias_material = {
                "authority_component_digest": authority,
                "capability": capability,
                "consumer": consumer,
                "schema": R2_ALIAS_MATERIAL_SCHEMA,
                "source_import": source_import,
            }
            expected_alias = (
                "wasm-biotic:factory/host-"
                f"{sha256_bytes(canonical_json_bytes(alias_material))[7:]}@0.1.0"
            )
            alias = host_import.get("alias")
            require(
                alias == expected_alias and alias not in aliases,
                f"R2 principal {consumer} host alias is not exact and globally unique",
            )
            aliases.add(alias)
            principal_aliases.append(alias)
        require(
            principal_aliases == sorted(principal_aliases),
            f"R2 principal {consumer} host aliases are not canonical",
        )
    require(
        consumers == sorted(nodes_by_id),
        "R2 principal consumers do not exactly cover the sorted manifest",
    )
    result = {
        "principal_inventory_digest": inventory_digest,
        "principal_count": len(consumers),
        "principal_alias_count": len(aliases),
        "pure_principal_count": pure_principals,
        "import_alias_scheme": R2_IMPORT_ALIAS_SCHEME,
        "principal_id_scheme": R2_PRINCIPAL_ID_SCHEME,
        "_principal_consumers": consumers,
        "_principal_aliases": sorted(aliases),
    }
    if cohort == "R3":
        require(
            profile_bytes == canonical_json_bytes(profile),
            "R3 substrate profile is not canonical JSON",
        )
        http_profile = profile.get("http_transport")
        require(
            isinstance(http_profile, dict)
            and set(http_profile) == {"mode", "bindings"}
            and http_profile.get("mode") == "bounded-external",
            "R3 profile omits the closed bounded-external HTTP projection",
        )
        http_bindings = http_profile.get("bindings")
        require(
            isinstance(http_bindings, list) and len(http_bindings) == 1,
            "R3 profile must retain exactly one HTTP transport binding",
        )
        binding = http_bindings[0]
        require(
            isinstance(binding, dict)
            and set(binding) == {"consumer", "alias", "constraints"}
            and binding.get("consumer") == "exchange-service",
            "R3 HTTP binding is not the exact exchange-service projection",
        )
        constraint_digest = require_digest(
            binding.get("constraints"), "R3 HTTP transport constraint"
        )
        exchange_principal = next(
            (
                principal
                for principal in principals
                if isinstance(principal, dict)
                and principal.get("consumer") == "exchange-service"
            ),
            None,
        )
        require(
            isinstance(exchange_principal, dict),
            "R3 profile omits the exchange-service principal",
        )
        exchange_imports = [
            value
            for value in exchange_principal.get("host_imports", [])
            if isinstance(value, dict) and value.get("capability") == "http-transport"
        ]
        require(
            len(exchange_imports) == 1
            and binding
            == {
                "consumer": "exchange-service",
                "alias": exchange_imports[0].get("alias"),
                "constraints": exchange_imports[0].get("constraints"),
            },
            "R3 HTTP profile binding differs from its principal import",
        )
        common_constraint_digest = sha256_bytes(
            canonical_json_bytes(profile.get("ceilings"))
        )
        http_grants = []
        for node in nodes:
            require(isinstance(node, dict), "R3 manifest node is malformed")
            grants = node.get("grants")
            require(isinstance(grants, list), "R3 manifest grants are absent")
            for grant in grants:
                require(isinstance(grant, dict), "R3 manifest grant is malformed")
                if grant.get("capability") == "http-transport":
                    http_grants.append((node.get("id"), grant))
                    expected_constraint = constraint_digest
                else:
                    expected_constraint = common_constraint_digest
                require(
                    grant.get("constraints") == expected_constraint,
                    "R3 grant does not use the exact HTTP constraint or shared ceiling",
                )
        require(
            len(http_grants) == 1
            and http_grants[0][0] == "exchange-service"
            and http_grants[0][1].get("constraints") == constraint_digest,
            "R3 manifest does not contain one exact exchange HTTP grant",
        )
        constraint_path = (
            package_dir
            / "constraints"
            / f"{constraint_digest.replace(':', '-')}.json"
        )
        constraint, constraint_bytes = read_json(
            constraint_path, "R3 HTTP transport constraint"
        )
        require(
            constraint_bytes == canonical_json_bytes(constraint)
            and sha256_bytes(constraint_bytes) == constraint_digest
            and constraint.get("schema")
            == "wasm-biotic.http-transport-constraints.v1",
            "R3 HTTP transport constraint bytes are not canonical and exact",
        )
        require(
            statement.get("constraint_digests")
            == sorted([common_constraint_digest, constraint_digest]),
            "R3 certificate does not bind the exact two-constraint closure",
        )
        result.update(
            {
                "substrate_profile_digest": sha256_bytes(profile_bytes),
                "http_transport_constraint_digest": constraint_digest,
                "http_transport_alias": binding["alias"],
                "exchange_component_digest": nodes_by_id["exchange-service"][
                    "component_digest"
                ],
            }
        )
    return result


def package_binding(package_dir: Path, repository: Path) -> dict[str, Any]:
    package_dir = package_dir.resolve()
    package, package_bytes = read_json(package_dir / "package.json", "package index")
    manifest, manifest_bytes = read_json(package_dir / "manifest.json", "graph manifest")
    certificate, certificate_bytes = read_json(
        package_dir / "certification/release-certification.json",
        "release certification",
    )
    strict, strict_bytes = read_json(
        package_dir / "evidence/strict-validation.json", "strict-validation report"
    )

    graph_digest = sha256_bytes(manifest_bytes)
    require(package.get("package_schema") == "wasm-biotic.component-graph-package.v1", "wrong package schema")
    require(package.get("graph_manifest_digest") == graph_digest, "package index/manifest mismatch")
    require(package_dir.name == graph_digest.replace(":", "-"), "package directory is not named by its manifest digest")
    digest_file(
        package_dir / "certification/release-certification.json",
        package.get("certification_digest", ""),
        "release certification",
    )
    digest_file(
        package_dir / "evidence/strict-validation.json",
        package.get("validation_report_digest", ""),
        "strict-validation report",
    )
    tcb_digest = package.get("certified_kernel_tcb_inventory_digest", "")
    digest_file(
        package_dir / "certified-kernel-tcb" / f"{tcb_digest.replace(':', '-')}.json",
        tcb_digest,
        "certified native TCB inventory",
    )
    strict_schema = strict.get("schema")
    require(
        strict_schema in {STRICT_REPORT_SCHEMA_V1, STRICT_REPORT_SCHEMA_V2},
        f"unsupported strict-validation schema {strict_schema!r}",
    )
    require(strict.get("outcome") == "pass", "strict-validation report did not pass")

    statement = certificate.get("statement")
    require(isinstance(statement, dict), "release certificate has no statement")
    require(statement.get("graph_manifest_digest") == graph_digest, "certificate/manifest mismatch")
    require(statement.get("validation_report_digest") == package.get("validation_report_digest"), "certificate/strict-report mismatch")
    require(statement.get("native_tcb_inventory_digest") == tcb_digest, "certificate/TCB mismatch")
    certifier_key_id = certificate.get("certifier_key_id")
    require(isinstance(certifier_key_id, str) and DIGEST_RE.fullmatch(certifier_key_id), "invalid certificate key identity")

    cohort = "R1"
    if strict_schema == STRICT_REPORT_SCHEMA_V2:
        profile, _ = read_json(
            package_dir / "substrate-profile.json", "R2/R3 substrate profile"
        )
        if profile.get("schema") == R2_PROFILE_SCHEMA:
            cohort = "R2"
        elif profile.get("schema") == R3_PROFILE_SCHEMA:
            cohort = "R3"
        else:
            raise GateError(
                "strict-validation v2 package has an unsupported substrate profile"
            )
    authority_binding: dict[str, Any] = {}
    if cohort in {"R2", "R3"}:
        authority_binding = r2_package_authority_binding(
            package_dir,
            manifest,
            graph_digest,
            statement,
            strict,
            cohort,
        )

    binding = {
        "path": relative_path(package_dir, repository),
        "graph_manifest_digest": graph_digest,
        "package_index_digest": sha256_bytes(package_bytes),
        "strict_validation_report_digest": sha256_bytes(strict_bytes),
        "release_certification_digest": sha256_bytes(certificate_bytes),
        "certifier_key_id": certifier_key_id,
        "native_tcb_inventory_digest": tcb_digest,
        "root_authority_digest": package.get("root_authority_digest"),
        "root_executable_digest": package.get("root_executable_digest"),
        "previous_graph_digest": manifest.get("previous_graph"),
        "manifest": manifest,
        "_cohort": cohort,
    }
    if cohort in {"R2", "R3"}:
        binding["strict_validation_schema"] = strict_schema
        binding.update(authority_binding)
    return binding


def service_component_identities(
    incumbent: dict[str, Any], successor: dict[str, Any]
) -> dict[str, str]:
    required = [
        "build-service",
        "capability-router",
        "continuity-service",
        "exchange-service",
        "operations-service",
        "packaging-service",
        "review-service",
        "scheduling-service",
        "validation-service",
    ]

    def identities(binding: dict[str, Any]) -> dict[str, str]:
        nodes = binding["manifest"].get("nodes")
        require(isinstance(nodes, list), "graph manifest nodes are absent")
        result = {
            node.get("id"): node.get("component_digest")
            for node in nodes
            if isinstance(node, dict) and node.get("id") in required
        }
        require(set(result) == set(required), "graph omits an R1 service component")
        require(all(isinstance(value, str) and DIGEST_RE.fullmatch(value) for value in result.values()), "graph has invalid service component identity")
        return result  # type: ignore[return-value]

    first = identities(incumbent)
    second = identities(successor)
    require(first == second, "incumbent and successor use different R1 service component bytes")
    return dict(sorted(first.items()))


def r2_lifecycle_authority_binding(
    lifecycle: dict[str, Any],
    incumbent: dict[str, Any],
    successor: dict[str, Any],
) -> dict[str, Any]:
    inventory_digests = lifecycle.get("principal_inventory_digests")
    expected_inventory_digests = {
        "incumbent": incumbent["principal_inventory_digest"],
        "successor": successor["principal_inventory_digest"],
    }
    require(
        inventory_digests == expected_inventory_digests,
        "R2 lifecycle principal inventories do not bind the exact package pair",
    )
    require(
        lifecycle.get(
            "principal_mapping_stable_across_restart_activation_and_rollback"
        )
        is True,
        "R2 lifecycle did not establish stable per-consumer principal mapping",
    )
    require(
        lifecycle.get("graph_qualified_activation_ownership_handoff_verified")
        is True,
        "R2 lifecycle did not verify graph-qualified activation ownership handoff",
    )
    require(
        incumbent["_principal_consumers"] == successor["_principal_consumers"]
        and incumbent["_principal_aliases"] == successor["_principal_aliases"],
        "R2 package pair changes its per-consumer authority mapping",
    )

    summaries = lifecycle.get("authority_trace_summaries")
    require(
        isinstance(summaries, list) and len(summaries) == 4,
        "R2 lifecycle must contain exactly four authority trace phases",
    )
    require(
        [summary.get("phase") if isinstance(summary, dict) else None for summary in summaries]
        == R2_AUTHORITY_TRACE_PHASES,
        "R2 lifecycle authority trace phases are absent or out of order",
    )
    known_graphs = {
        incumbent["graph_manifest_digest"],
        successor["graph_manifest_digest"],
    }
    expected_phase_graph = {
        "incumbent-cycle": incumbent["graph_manifest_digest"],
        "activation-and-successor-cycle": successor["graph_manifest_digest"],
        "rollback": successor["graph_manifest_digest"],
        "restart-post-rollback-cycle": incumbent["graph_manifest_digest"],
    }
    known_consumers = set(incumbent["_principal_consumers"])
    known_aliases = set(incumbent["_principal_aliases"])
    validated_summaries: list[dict[str, Any]] = []
    for summary in summaries:
        require(isinstance(summary, dict), "R2 authority trace phase is malformed")
        require(
            set(summary)
            == {
                "aliases",
                "call_count",
                "consumers",
                "graph_manifest_digests",
                "phase",
                "profile_mapping_verified",
                "trace_digest",
            },
            f"R2 authority trace phase {summary.get('phase')!r} has the wrong fields",
        )
        phase = summary["phase"]
        aliases = summary["aliases"]
        consumers = summary["consumers"]
        graph_digests = summary["graph_manifest_digests"]
        call_count = summary["call_count"]
        require(
            summary.get("profile_mapping_verified") is True,
            f"R2 authority trace phase {phase} did not verify the profile mapping",
        )
        require_digest(summary.get("trace_digest"), f"R2 authority trace {phase}")
        require(
            type(call_count) is int and call_count > 0,
            f"R2 authority trace phase {phase} contains no calls",
        )
        require(
            isinstance(aliases, list)
            and aliases == sorted(set(aliases))
            and bool(aliases)
            and set(aliases) <= known_aliases
            and len(aliases) <= call_count,
            f"R2 authority trace phase {phase} aliases are not exact package aliases",
        )
        require(
            isinstance(consumers, list)
            and consumers == sorted(set(consumers))
            and bool(consumers)
            and set(consumers) <= known_consumers,
            f"R2 authority trace phase {phase} consumers are not exact package principals",
        )
        require(
            isinstance(graph_digests, list)
            and graph_digests == sorted(set(graph_digests))
            and bool(graph_digests)
            and set(graph_digests) <= known_graphs
            and expected_phase_graph[phase] in graph_digests,
            f"R2 authority trace phase {phase} is not bound to its active graph",
        )
        validated_summaries.append({**summary, "result": "pass"})

    return {
        "principal_inventory_digests": expected_inventory_digests,
        "principal_mapping_stable_across_restart_activation_and_rollback": True,
        "graph_qualified_activation_ownership_handoff_verified": True,
        "authority_trace_summaries": validated_summaries,
        "authority_trace_phase_count": 4,
        "result": "pass",
    }


def lifecycle_binding(
    lifecycle_path: Path,
    incumbent: dict[str, Any],
    successor: dict[str, Any],
    repository: Path,
) -> dict[str, Any]:
    lifecycle, lifecycle_bytes = read_json(lifecycle_path, "component lifecycle report")
    require(
        incumbent["_cohort"] == successor["_cohort"],
        "package pair mixes strict-validation cohorts",
    )
    cohort = incumbent["_cohort"]
    expected_schema = (
        LIFECYCLE_SCHEMA_V2 if cohort in {"R2", "R3"} else LIFECYCLE_SCHEMA_V1
    )
    require(lifecycle.get("schema") == expected_schema, "wrong lifecycle schema for package cohort")
    incumbent_digest = incumbent["graph_manifest_digest"]
    successor_digest = successor["graph_manifest_digest"]
    require(lifecycle.get("incumbent_graph_manifest_digest") == incumbent_digest, "lifecycle incumbent mismatch")
    require(lifecycle.get("successor_graph_manifest_digest") == successor_digest, "lifecycle successor mismatch")
    require(successor.get("previous_graph_digest") == incumbent_digest, "successor lineage does not name the incumbent")
    for flag in [
        "all_factory_semantics_executed_as_components",
        "component_decided_initial_state_binding",
        "component_decided_rollback",
        "component_decided_successor_activation",
        "restart_preserved_rollback_pair",
    ]:
        require(lifecycle.get(flag) is True, f"lifecycle flag {flag} is not true")

    cycle_graphs = {
        "incumbent_cycle": incumbent_digest,
        "successor_cycle": successor_digest,
        "post_rollback_cycle": incumbent_digest,
    }
    job_ids: set[str] = set()
    for cycle_name, expected_graph in cycle_graphs.items():
        cycle = lifecycle.get(cycle_name)
        require(isinstance(cycle, dict), f"lifecycle omits {cycle_name}")
        require(cycle.get("graph_manifest_digest") == expected_graph, f"{cycle_name} graph mismatch")
        terminal = cycle.get("terminal_result")
        require(isinstance(terminal, dict), f"{cycle_name} terminal result is absent")
        require(terminal.get("status") == "completed" and terminal.get("failure") is None, f"{cycle_name} did not complete")
        output = terminal.get("output")
        require(isinstance(output, dict) and output.get("media_type") == R1_WORK_STATE_MEDIA_TYPE, f"{cycle_name} is not an R1 work-state execution")
        completions = cycle.get("execution_completions")
        require(isinstance(completions, dict) and len(completions) == 6, f"{cycle_name} does not contain six worker completions")
        for role, completion in completions.items():
            outcome = completion.get("outcome") if isinstance(completion, dict) else None
            require(isinstance(outcome, dict) and outcome.get("kind") == "succeeded", f"{cycle_name}/{role} did not succeed")
        job_id = cycle.get("job_id")
        require(isinstance(job_id, str), f"{cycle_name} job identity is absent")
        job_ids.add(job_id)
    require(len(job_ids) == 3, "R1 lifecycle reused a job identity")

    r2_authority: dict[str, Any] | None = None
    if cohort in {"R2", "R3"}:
        r2_authority = r2_lifecycle_authority_binding(lifecycle, incumbent, successor)

    successor_copy = Path(successor["path"]) / "evidence/component-lifecycle.json"
    successor_copy_path = repository / successor_copy
    require(read_bytes(successor_copy_path, "successor lifecycle copy") == lifecycle_bytes, "package lifecycle copies differ")
    if cohort in {"R2", "R3"}:
        incumbent_copy = repository / Path(incumbent["path"]) / "evidence/component-lifecycle.json"
        require(
            read_bytes(incumbent_copy, "incumbent lifecycle copy") == lifecycle_bytes,
            "R2 package lifecycle copies differ",
        )

    binding = {
        "path": relative_path(lifecycle_path, repository),
        "sha256": sha256_bytes(lifecycle_bytes),
        "incumbent_graph_manifest_digest": incumbent_digest,
        "successor_graph_manifest_digest": successor_digest,
        "successor_previous_graph_digest": successor["previous_graph_digest"],
        "cycle_graph_sequence": [incumbent_digest, successor_digest, incumbent_digest],
        "distinct_job_identities": 3,
        "terminal_media_type": R1_WORK_STATE_MEDIA_TYPE,
        "restart_preserved_rollback_pair": True,
        "all_factory_semantics_executed_as_components": True,
        "result": "pass",
    }
    if cohort in {"R2", "R3"}:
        binding["schema"] = LIFECYCLE_SCHEMA_V2
        binding["per_consumer_authority"] = r2_authority
    return binding


def display_command(arguments: list[str]) -> str:
    return " ".join(arguments)


def cargo_workspace_partition(display_arguments: list[str]) -> str:
    """Return the isolated target partition for one known Cargo workspace.

    The gate command inventory is security-sensitive release input.  Resolve
    only its explicitly supported workspace manifests rather than normalizing
    arbitrary paths: otherwise a typo, traversal or newly introduced path
    crate could silently share another workspace's compilation cache.
    """

    require(
        bool(display_arguments) and display_arguments[0] == "cargo",
        "gate command must begin with the canonical cargo display executable",
    )
    option_arguments = display_arguments[1:]
    if "--" in option_arguments:
        option_arguments = option_arguments[: option_arguments.index("--")]

    manifest_values: list[str] = []
    index = 0
    while index < len(option_arguments):
        argument = option_arguments[index]
        if argument == "--manifest-path":
            require(
                index + 1 < len(option_arguments)
                and bool(option_arguments[index + 1])
                and not option_arguments[index + 1].startswith("-"),
                "Cargo --manifest-path requires one explicit path",
            )
            manifest_values.append(option_arguments[index + 1])
            index += 2
            continue
        if argument.startswith("--manifest-path="):
            manifest_values.append(argument.partition("=")[2])
        require(
            argument != "--target-dir" and not argument.startswith("--target-dir="),
            "gate Cargo command may not override its isolated target directory",
        )
        index += 1

    require(
        len(manifest_values) <= 1,
        "gate Cargo command has ambiguous duplicate --manifest-path options",
    )
    manifest = manifest_values[0] if manifest_values else None
    if manifest is not None:
        require(bool(manifest), "Cargo --manifest-path requires one explicit path")
        manifest_path = Path(manifest)
        require(
            not manifest_path.is_absolute() and ".." not in manifest_path.parts,
            f"unsafe Cargo manifest path: {manifest}",
        )
    require(
        manifest in CARGO_WORKSPACE_TARGET_PARTITIONS,
        f"unsupported or non-canonical Cargo workspace manifest: {manifest!r}",
    )
    return CARGO_WORKSPACE_TARGET_PARTITIONS[manifest]


def isolated_cargo_target_dir(
    display_arguments: list[str],
    repository: Path,
    environment: dict[str, str],
) -> Path:
    """Resolve a deterministic child of the caller's target-directory base."""

    raw_base = environment.get("CARGO_TARGET_DIR", str(repository / "target"))
    require(bool(raw_base.strip()), "CARGO_TARGET_DIR base may not be empty")
    base = Path(raw_base)
    if not base.is_absolute():
        base = repository / base
    base = base.resolve()
    repository = repository.resolve()
    require(
        base != Path(base.anchor),
        "CARGO_TARGET_DIR base may not be a filesystem root",
    )
    require(
        base != repository,
        "CARGO_TARGET_DIR base may not be the repository root",
    )
    require(
        not base.exists() or base.is_dir(),
        f"CARGO_TARGET_DIR base is not a directory: {base}",
    )
    target = (base / cargo_workspace_partition(display_arguments)).resolve()
    require(
        target.parent == base,
        f"isolated Cargo target escaped its base: {target}",
    )
    return target


def run_test(
    identifier: str,
    cargo: Path,
    display_arguments: list[str],
    expected_tests: int,
    cohort: str,
    repository: Path,
    transcript_dir: Path,
    environment: dict[str, str],
) -> dict[str, Any]:
    actual_arguments = [str(cargo), *display_arguments[1:]]
    command_environment = dict(environment)
    command_environment["CARGO_TARGET_DIR"] = str(
        isolated_cargo_target_dir(display_arguments, repository, environment)
    )
    completed = subprocess.run(
        actual_arguments,
        cwd=repository,
        env=command_environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    combined = completed.stdout + completed.stderr
    decoded = combined.decode("utf-8", errors="replace")
    matches = TEST_RESULT_RE.findall(decoded)
    passed = sum(int(match[0]) for match in matches)
    failed = sum(int(match[1]) for match in matches)
    if completed.returncode != 0:
        raise GateError(
            f"{identifier} failed with exit {completed.returncode}:\n{decoded[-4000:]}"
        )
    require(failed == 0, f"{identifier} reports failed tests")
    require(passed == expected_tests, f"{identifier} ran {passed} tests, expected {expected_tests}")
    passed_tests = sorted(set(PASSED_TEST_RE.findall(decoded)))
    require(
        len(passed_tests) == expected_tests,
        f"{identifier} exposed {len(passed_tests)} passing test identities, expected {expected_tests}",
    )

    # Cargo emits wall-clock timings, cache/build status and interleaved test
    # order.  None is semantic evidence.  Bind the report to this canonical,
    # deterministic projection and print raw output only on failure above.
    transcript = {
        "schema": f"wasm-biotic.{cohort.lower()}-gate-command-transcript.v1",
        "id": identifier,
        "command": display_arguments,
        "cwd": ".",
        "exit_code": completed.returncode,
        "passed_test_identities": passed_tests,
        "tests_passed": passed,
        "tests_failed": failed,
    }
    transcript_bytes = (json.dumps(transcript, sort_keys=True, separators=(",", ":")) + "\n").encode()
    transcript_path = transcript_dir / f"{identifier}.json"
    transcript_path.write_bytes(transcript_bytes)
    return {
        "id": identifier,
        "command": display_command(display_arguments),
        "tests_passed": passed,
        "tests_failed": failed,
        "exit_code": completed.returncode,
        "transcript_sha256": sha256_bytes(transcript_bytes),
        "result": "pass",
    }


def command_specs(cohort: str) -> list[tuple[str, list[str], int, str]]:
    specs = [
        (
            "service-policy-core-r1",
            ["cargo", "test", "--locked", "--offline", "--manifest-path", "components/Cargo.toml", "-p", "wasm-biotic-service-policy-core", "--lib", "r1::tests::", "--", "--nocapture"],
            12,
            "adversarial",
        ),
        (
            "kernel-adversarial-isolation",
            ["cargo", "test", "--locked", "--offline", "--manifest-path", "kernel/Cargo.toml", "--test", "adversarial_isolation", "--", "--skip", "historical_adversarial_report_is_closed_and_bound_to_its_certified_inventory", "--nocapture"],
            5,
            "adversarial",
        ),
        (
            "active-graph-target-isolation",
            ["cargo", "test", "--locked", "--offline", "--manifest-path", "kernel/Cargo.toml", "--test", "root_engine", "active_graph_scope_rejects_globally_admitted_unlisted_run_and_wake_targets", "--", "--exact", "--nocapture"],
            1,
            "adversarial",
        ),
        (
            "activation-cas-isolation",
            ["cargo", "test", "--locked", "--offline", "--manifest-path", "kernel/Cargo.toml", "--test", "root_engine", "activation_rejects_stale_expected_digest_without_state_change", "--", "--exact", "--nocapture"],
            1,
            "adversarial",
        ),
        (
            "native-boundary",
            ["cargo", "test", "--locked", "--offline", "--manifest-path", "kernel/Cargo.toml", "--test", "native_boundary", "--", "--nocapture"],
            2,
            "adversarial",
        ),
        (
            "compiled-capability-router-approval",
            ["cargo", "test", "--locked", "--offline", "--manifest-path", "components/Cargo.toml", "-p", "wasm-biotic-capability-router", "--test", "wasm_adapter", "--", "--nocapture"],
            1,
            "adversarial",
        ),
        (
            "kernel-durability-fault-matrix",
            ["cargo", "test", "--locked", "--offline", "--manifest-path", "kernel/Cargo.toml", "--test", "durability_fault_matrix", "--", "--nocapture"],
            5,
            "durability",
        ),
        (
            "kernel-activation-restart-durability",
            ["cargo", "test", "--locked", "--offline", "--manifest-path", "kernel/Cargo.toml", "--lib", "durability_tests", "--", "--nocapture"],
            5,
            "durability",
        ),
    ]
    if cohort in {"R2", "R3"}:
        specs.extend(
            [
                (
                    "component-graph-r2-principal-contract",
                    [
                        "cargo",
                        "test",
                        "--locked",
                        "--offline",
                        "--lib",
                        "component_graph::tests::r2_",
                        "--",
                        "--nocapture",
                    ],
                    1,
                    "adversarial",
                ),
                (
                    "component-graph-package-r2-least-authority",
                    [
                        "cargo",
                        "test",
                        "--locked",
                        "--offline",
                        "--manifest-path",
                        "tools/component-graph-package/Cargo.toml",
                        "--lib",
                        "tests::r2_",
                        "--",
                        "--nocapture",
                    ],
                    3,
                    "adversarial",
                ),
                (
                    "kernel-r2-principal-linking-and-trace",
                    [
                        "cargo",
                        "test",
                        "--locked",
                        "--offline",
                        "--manifest-path",
                        "kernel/Cargo.toml",
                        "--lib",
                        "root_runtime::r2_tests::",
                        "--",
                        "--nocapture",
                    ],
                    6,
                    "adversarial",
                ),
                (
                    "independent-substrate-r2-principal-isolation",
                    [
                        "cargo",
                        "test",
                        "--locked",
                        "--offline",
                        "--manifest-path",
                        "tools/independent-substrate/Cargo.toml",
                        "--lib",
                        "r2_",
                        "--",
                        "--nocapture",
                    ],
                    6,
                    "adversarial",
                ),
            ]
        )
    if cohort == "R3":
        specs.extend(
            [
                (
                    "component-graph-r3-http-contract",
                    [
                        "cargo",
                        "test",
                        "--locked",
                        "--offline",
                        "--lib",
                        "component_graph::tests::r3_",
                        "--",
                        "--nocapture",
                    ],
                    3,
                    "adversarial",
                ),
                (
                    "component-graph-package-r3-http-contract",
                    [
                        "cargo",
                        "test",
                        "--locked",
                        "--offline",
                        "--manifest-path",
                        "tools/component-graph-package/Cargo.toml",
                        "--lib",
                        "tests::r3_",
                        "--",
                        "--nocapture",
                    ],
                    2,
                    "adversarial",
                ),
                (
                    "kernel-r3-http-production",
                    [
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
                    4,
                    "durability",
                ),
                (
                    "independent-r3-http-confinement",
                    [
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
                    9,
                    "adversarial",
                ),
                (
                    "independent-r3-http-wit-boundary",
                    [
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
                    2,
                    "durability",
                ),
                (
                    "independent-r3-package-admission",
                    [
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
                    2,
                    "adversarial",
                ),
                (
                    "compiled-exchange-r3-http-adapter",
                    [
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
                    6,
                    "durability",
                ),
            ]
        )
    return specs


def negative_cases() -> list[dict[str, Any]]:
    return [
        {"id": "r1-malformed-reserved-media", "test": "malformed_reserved_media_never_falls_back_to_legacy_envelope", "expected_codes": ["invalid-r1-json"], "result": "pass"},
        {"id": "r1-noncanonical-json", "test": "canonical_json_and_exact_cas_are_enforced", "expected_codes": ["noncanonical-r1-json"], "result": "pass"},
        {"id": "r1-patch-cas-forgery", "test": "canonical_json_and_exact_cas_are_enforced", "expected_codes": ["r1-patch-cas-mismatch"], "result": "pass"},
        {"id": "r1-path-traversal", "test": "traversal_duplicate_and_digest_forgery_are_rejected", "expected_codes": ["invalid-r1-path"], "result": "pass"},
        {"id": "r1-duplicate-unsorted-files", "test": "traversal_duplicate_and_digest_forgery_are_rejected", "expected_codes": ["unsorted-r1-files"], "result": "pass"},
        {"id": "r1-file-digest-forgery", "test": "traversal_duplicate_and_digest_forgery_are_rejected", "expected_codes": ["r1-file-digest-mismatch"], "result": "pass"},
        {"id": "r1-invalid-program-stack", "test": "invalid_stack_program_fails_build_inside_component_semantics", "expected_codes": ["r1-program-stack-underflow"], "result": "pass"},
        {"id": "r1-remote-provider-disabled", "test": "remote_provider_rejects_closed_before_validation", "expected_codes": ["external-transport-disabled"], "result": "pass"},
        {"id": "r1-failing-tests-block-package", "test": "failing_discovered_test_is_reviewed_but_cannot_be_packaged", "expected_codes": ["r1-package-not-approved"], "result": "pass"},
        {"id": "r1-rehashed-unapproved-review", "test": "final_verifier_rejects_rehashed_but_unapproved_review", "expected_codes": ["r1-review-closure-mismatch"], "result": "pass"},
        {"id": "r1-remote-deployment-disabled", "test": "deployment_rejects_remote_target_and_stale_transition", "expected_codes": ["external-transport-disabled"], "result": "pass"},
        {"id": "r1-stale-deployment-transition", "test": "deployment_rejects_remote_target_and_stale_transition", "expected_codes": ["r1-deployment-cas-mismatch"], "result": "pass"},
    ]


def public_package_binding(binding: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in binding.items()
        if key != "manifest" and not key.startswith("_")
    }


def write_report(path: Path, report: dict[str, Any]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
    path.write_bytes(data)
    return sha256_bytes(data)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--incumbent-package", type=Path, required=True)
    parser.add_argument("--successor-package", type=Path, required=True)
    parser.add_argument("--lifecycle", type=Path, required=True)
    parser.add_argument("--adversarial-out", type=Path, required=True)
    parser.add_argument("--durability-out", type=Path, required=True)
    parser.add_argument("--transcript-dir", type=Path, required=True)
    parser.add_argument("--cargo", type=Path, default=Path("cargo"))
    arguments = parser.parse_args()

    repository = Path(__file__).resolve().parent.parent
    incumbent = package_binding(arguments.incumbent_package, repository)
    successor = package_binding(arguments.successor_package, repository)
    require(incumbent["_cohort"] == successor["_cohort"], "package cohorts differ")
    cohort = incumbent["_cohort"]
    require(incumbent["certifier_key_id"] == successor["certifier_key_id"], "package certifier identities differ")
    require(incumbent["native_tcb_inventory_digest"] == successor["native_tcb_inventory_digest"], "package TCB identities differ")
    lifecycle = lifecycle_binding(arguments.lifecycle.resolve(), incumbent, successor, repository)
    service_identities = service_component_identities(incumbent, successor)

    arguments.transcript_dir.mkdir(parents=True, exist_ok=True)
    environment = dict(os.environ)
    # Treat this value as a base only. Each Cargo workspace gets a deterministic
    # child target in run_test so independently resolved dependency graphs can
    # never reuse incompatible build artifacts.
    environment.setdefault("CARGO_TARGET_DIR", str(repository / "target"))
    results: list[dict[str, Any]] = []
    groups: dict[str, list[dict[str, Any]]] = {"adversarial": [], "durability": []}
    for identifier, command, count, group in command_specs(cohort):
        print(f"running {display_command(command)}", flush=True)
        result = run_test(
            identifier,
            arguments.cargo,
            command,
            count,
            cohort,
            repository,
            arguments.transcript_dir,
            environment,
        )
        results.append(result)
        groups[group].append(result)

    adversarial_template, _ = read_json(
        repository / "artifacts/component-complete/2026-08-02-adversarial-isolation.v1.json",
        "R0 adversarial template",
    )
    durability_template, _ = read_json(
        repository / "artifacts/component-complete/2026-08-02-durability-fault-matrix.v1.json",
        "R0 durability template",
    )
    release_binding = {
        "cohort": cohort,
        "incumbent_package": public_package_binding(incumbent),
        "successor_package": public_package_binding(successor),
        "lifecycle": lifecycle,
        "service_component_identities": service_identities,
        "result": "pass",
    }
    if cohort in {"R2", "R3"}:
        require(
            incumbent["principal_count"] == successor["principal_count"]
            and incumbent["principal_alias_count"]
            == successor["principal_alias_count"],
            f"{cohort} package pair has different principal authority cardinality",
        )
        release_binding["per_consumer_authority"] = {
            "static_grant_model": R2_STATIC_GRANT_MODEL,
            "import_alias_scheme": R2_IMPORT_ALIAS_SCHEME,
            "principal_id_scheme": R2_PRINCIPAL_ID_SCHEME,
            "principal_count": incumbent["principal_count"],
            "principal_alias_count": incumbent["principal_alias_count"],
            "pure_principal_count": incumbent["pure_principal_count"],
            "principal_inventory_digests": lifecycle["per_consumer_authority"][
                "principal_inventory_digests"
            ],
            "principal_mapping_stable_across_restart_activation_and_rollback": True,
            "graph_qualified_activation_ownership_handoff_verified": True,
            "authority_trace_summaries": lifecycle["per_consumer_authority"][
                "authority_trace_summaries"
            ],
            "result": "pass",
        }
    if cohort == "R3":
        require(
            incumbent["substrate_profile_digest"]
            == successor["substrate_profile_digest"],
            "R3 package pair has different substrate profiles",
        )
        release_binding["bounded_external_transport"] = {
            "claim_profile": "r3-bounded-external-transport-v1",
            "capability_profile_digest": incumbent["substrate_profile_digest"],
            "incumbent_http_transport_constraint_digest": incumbent[
                "http_transport_constraint_digest"
            ],
            "successor_http_transport_constraint_digest": successor[
                "http_transport_constraint_digest"
            ],
            "incumbent_exchange_component_digest": incumbent[
                "exchange_component_digest"
            ],
            "successor_exchange_component_digest": successor[
                "exchange_component_digest"
            ],
            "incumbent_http_transport_alias": incumbent["http_transport_alias"],
            "successor_http_transport_alias": successor["http_transport_alias"],
            "external_dispatch_evidence_role": "transport-confinement",
            "result": "package-bound; covered-by-separate-signed-report",
        }

    adversarial = copy.deepcopy(adversarial_template)
    adversarial["generated_at"] = "2026-08-03"
    adversarial["component_complete_claim"] = False
    adversarial["report_result"] = "pass"
    adversarial["release_binding"] = release_binding
    adversarial["test_commands"] = [result["command"] for result in groups["adversarial"]]
    adversarial["test_evidence"] = groups["adversarial"]
    policy_source = repository / "components/service-policy-core/src/r1.rs"
    adversarial["r1_service_policy_core"] = {
        "source_path": relative_path(policy_source, repository),
        "source_sha256": sha256_bytes(read_bytes(policy_source, "R1 service-policy source")),
        "negative_cases": negative_cases(),
        "negative_assertions": len(negative_cases()),
        "unit_tests_passed": 12,
        "execution_scope": "native Rust unit execution of the no_std policy library shared by the listed service components",
        "compiled_component_negative_execution_claim": False,
        "compiled_component_positive_execution": {
            "evidence": lifecycle["path"],
            "sha256": lifecycle["sha256"],
            "cycles": 3,
            "terminal_media_type": R1_WORK_STATE_MEDIA_TYPE,
            "result": "pass",
        },
        "interpretation": "The negative cases prove the shared policy source fails closed. They do not by themselves prove each negative stimulus traversed a packaged Wasm component ABI. The exact packaged components are bound above, and their useful positive R1 workflow is proved by the lifecycle.",
        "result": "pass-with-explicit-seam-scope",
    }
    adversarial["remaining_conformance_work"] = [
        "The R1 negative corpus in this focused report executes the shared no_std policy library natively; compiled-component negative ABI traversal remains distinct from the three positive packaged-component lifecycle cycles.",
        "Approval authenticity and replay execute through the compiled capability-router component with a focused Wasmtime adapter; the adapter is evidence, not a native policy substitute.",
        "Exchange replay is component policy and is covered by graph-level evidence rather than interpreted by native transport.",
        "This focused Sections 2 and 5 report keeps component_complete_claim false; only a separately signed aggregate release may make that claim.",
    ]
    if cohort == "R2":
        adversarial["r2_per_consumer_authority"] = release_binding[
            "per_consumer_authority"
        ]
        adversarial["r1_service_policy_core"]["interpretation"] = (
            "The negative cases prove the shared policy source fails closed. They do "
            "not by themselves prove each negative stimulus traversed a packaged Wasm "
            "component ABI. The exact R2 packaged components and their independently "
            "linked per-consumer host authorities are bound above; their useful positive "
            "R1 workflow is proved by the four-phase R2 lifecycle authority trace."
        )
        adversarial["remaining_conformance_work"] = [
            "The R1 semantic negative corpus in this focused report executes the shared no_std policy library natively; compiled-component negative ABI traversal remains distinct from the three positive R2 package lifecycle cycles.",
            "Approval authenticity and replay execute through the compiled capability-router component under its exact per-consumer import alias; the adapter is evidence, not a native policy substitute.",
            "Production-kernel and independent-substrate R2 tests above reject cross-principal authority, handle and idempotency theft and verify atomic graph-qualified activation-owner handoff; the signed lifecycle separately binds all four live authority-trace phases.",
            "This focused Sections 2 and 5 report keeps component_complete_claim false; only a separately signed aggregate R2 release may make that claim.",
        ]
    elif cohort == "R3":
        adversarial["r2_per_consumer_authority"] = release_binding[
            "per_consumer_authority"
        ]
        adversarial["r3_bounded_external_transport"] = release_binding[
            "bounded_external_transport"
        ]
        adversarial["r1_service_policy_core"]["interpretation"] = (
            "The shared semantic policy negatives remain source-level evidence. The "
            "exact R3 packages, per-consumer aliases, closed HTTP constraint and "
            "compiled exchange-service HTTP adapter are bound above. Production and "
            "independent confinement, durability, ownership, secret non-observation "
            "and non-retry results are closed by the separately signed "
            "transport-confinement evidence role."
        )
        adversarial["remaining_conformance_work"] = [
            "This focused report does not duplicate the production/independent external-dispatch campaign; the signed aggregate must include the distinct transport-confinement report bound to this exact graph pair, profile and constraints.",
            "This focused Sections 2 and 5 report keeps component_complete_claim false; only a separately signed aggregate R3 release may make that claim.",
        ]

    durability = copy.deepcopy(durability_template)
    durability["generated_at"] = "2026-08-03"
    durability["component_complete_claim"] = False
    durability["report_result"] = "pass"
    durability["release_binding"] = release_binding
    durability["paired_complete_graph_lifecycle"] = {
        "path": lifecycle["path"],
        "sha256": lifecycle["sha256"],
        "incumbent_graph_manifest_digest": lifecycle["incumbent_graph_manifest_digest"],
        "successor_graph_manifest_digest": lifecycle["successor_graph_manifest_digest"],
        "successor_previous_graph_digest": lifecycle["successor_previous_graph_digest"],
        "terminal_media_type": lifecycle["terminal_media_type"],
        "coverage": "R1 incumbent cycle, component-decided state binding, signed successor admission, migration, activation, R1 successor cycle, component-decided rollback, durable reopen and post-rollback R1 incumbent cycle",
        "result": "pass",
    }
    if cohort in {"R2", "R3"}:
        durability["paired_complete_graph_lifecycle"].update(
            {
                "coverage": "R2 incumbent cycle with per-consumer authority, component-decided state binding, signed R2 successor admission, atomic graph-qualified activation-owner handoff, migration, activation, R2 successor cycle, component-decided rollback with owner handback, durable reopen and post-rollback R2 incumbent cycle with the same principal mapping",
                "per_consumer_authority": lifecycle["per_consumer_authority"],
            }
        )
    if cohort == "R3":
        durability["paired_complete_graph_lifecycle"]["coverage"] = (
            "R3 paired lifecycle retaining the R2 per-consumer authority mapping; "
            "external HTTP dispatch durability and non-retry are covered by the "
            "separate transport-confinement report bound to this pair"
        )
        durability["paired_complete_graph_lifecycle"][
            "bounded_external_transport"
        ] = release_binding["bounded_external_transport"]
    durability["gate_status"] = {
        "bounded_local_mechanism_matrix": "pass",
        "external_effect_dispatch_and_completion": (
            "covered-by-separate-signed-transport-confinement-report"
            if cohort == "R3"
            else "not-applicable-signed-bounded-disabled-http-profile"
        ),
        "full_22_component_graph_restart_campaign": f"pass-paired-complete-{cohort}-graph-lifecycle",
        "conformance_section_4_overall": "pass-exact-profile",
    }
    durability["test_evidence"] = groups["durability"]
    durability["kernel_quality_gates"] = [
        {
            "command": "cargo fmt --manifest-path kernel/Cargo.toml --all -- --check",
            "result": "not-executed-by-this-focused-report",
            "scope": "separate aggregate release gate",
        },
        {
            "command": "cargo clippy --locked --offline --manifest-path kernel/Cargo.toml --all-targets -- -D warnings",
            "result": "not-executed-by-this-focused-report",
            "scope": "separate aggregate release gate",
        },
        {
            "command": "cargo test --locked --offline --manifest-path kernel/Cargo.toml --all-targets -- --nocapture",
            "result": "not-executed-by-this-focused-report",
            "scope": "targeted durability and restart suites above are the evidence claimed here",
        },
    ]
    durability["uncovered_external_effect_cases"][-2:] = [
        "The 73-case matrix exercises an admitted fixture component at identity-parametric native seams; it is paired above with the exact signed R1 22-component cohort and its three-cycle lifecycle.",
        "The paired R1 lifecycle spans useful software work, migration, successor activation, component-decided rollback, restart and post-rollback execution. Repeating identical native seam injections once per semantic node would not add durability isolation evidence.",
    ]
    if cohort == "R2":
        durability["uncovered_external_effect_cases"][-2:] = [
            "The 73-case matrix exercises an admitted fixture component at identity-parametric native seams; it is paired above with the exact signed R2 22-component cohort, per-consumer authority inventories and four-phase live authority trace.",
            "The paired R2 lifecycle spans useful software work, migration, successor activation, component-decided rollback, restart and post-rollback execution while preserving the exact principal mapping. Repeating identical native seam injections once per semantic node would not add durability isolation evidence.",
        ]
    elif cohort == "R3":
        durability["uncovered_external_effect_cases"][-2:] = [
            "External dispatch is applicable in R3. This report binds the exact pair, profile, constraint and focused HTTP command transcripts; the complete production/independent confinement and durability campaign is the distinct signed transport-confinement evidence object.",
            "The aggregate verifier must reject a missing, swapped or extra transport constraint or transport-confinement report; this focused durability report does not stand in for that closure.",
        ]

    adversarial_digest = write_report(arguments.adversarial_out, adversarial)
    durability_digest = write_report(arguments.durability_out, durability)
    summary = {
        "adversarial_report": str(arguments.adversarial_out.resolve()),
        "adversarial_report_digest": adversarial_digest,
        "durability_report": str(arguments.durability_out.resolve()),
        "durability_report_digest": durability_digest,
        "lifecycle_digest": lifecycle["sha256"],
        "tests_passed": sum(result["tests_passed"] for result in results),
        "tests_failed": sum(result["tests_failed"] for result in results),
        "commands": len(results),
        "result": "pass",
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except GateError as error:
        print(f"r1-release-gate-reports: {error}", file=sys.stderr)
        raise SystemExit(1)
