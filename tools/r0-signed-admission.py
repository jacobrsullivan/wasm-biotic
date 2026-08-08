#!/usr/bin/env python3
"""Run the public-key-only signed-admission conformance campaign.

The harness deliberately has no private-key argument.  It executes an already
built production kernel against two already certified package directories,
performs destructive negative controls only on temporary copies, and emits one
canonical JSON report. R0 through R3 package/evidence generations are accepted
only through explicit, schema- and profile-specific validation paths.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any, Iterable

TOOLS_DIRECTORY = Path(__file__).resolve().parent
if str(TOOLS_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIRECTORY))
from r3_release_authority import (  # noqa: E402
    PROFILE_SCHEMA_V3,
    R3AuthorityError,
    inspect_r3_http_authority,
)


COMMAND_TIMEOUT_SECONDS = 240
PACKAGE_SCHEMA = "wasm-biotic.component-graph-package.v1"
MANIFEST_SCHEMA = "wasm-biotic.factory-graph.v1"
CERTIFICATION_SCHEMA = "wasm-biotic.release-certification.v1"
STRICT_REPORT_SCHEMA = "wasm-biotic.component-strict-validation-report.v1"
STRICT_REPORT_SCHEMA_V2 = "wasm-biotic.component-strict-validation-report.v2"
STRICT_REPORT_SCHEMAS = frozenset([STRICT_REPORT_SCHEMA, STRICT_REPORT_SCHEMA_V2])
INDEPENDENT_REPORT_SCHEMA = "wasm-biotic.independent-substrate-reproduction.v1"
INDEPENDENT_REPORT_SCHEMA_V2 = "wasm-biotic.independent-substrate-reproduction.v2"
INDEPENDENT_REPORT_SCHEMAS = frozenset(
    [INDEPENDENT_REPORT_SCHEMA, INDEPENDENT_REPORT_SCHEMA_V2]
)
CANDIDATE_REPORT_SCHEMA_V1 = "wasm-biotic.candidate-graph-shadow.v1"
CANDIDATE_REPORT_SCHEMA_V2 = "wasm-biotic.candidate-graph-shadow.v2"
CANDIDATE_REPORT_SCHEMA_V3 = "wasm-biotic.candidate-graph-shadow.v3"
CANDIDATE_REPORT_SCHEMAS = frozenset(
    [
        CANDIDATE_REPORT_SCHEMA_V1,
        CANDIDATE_REPORT_SCHEMA_V2,
        CANDIDATE_REPORT_SCHEMA_V3,
    ]
)
NATIVE_BUILD_SCHEMA = "wasm-biotic.native-build-attestation.v1"
REPORT_SCHEMA_R0 = "wasm-biotic.r0-signed-semantic-admission.v1"
REPORT_SCHEMA_R1 = "wasm-biotic.r1-signed-semantic-admission.v1"
REPORT_SCHEMA_R2 = "wasm-biotic.r2-signed-semantic-admission.v1"
REPORT_SCHEMA_R3 = "wasm-biotic.r3-signed-semantic-admission.v1"
PROFILE_SCHEMA_V1 = "wasm-biotic.factory-substrate-profile.v1"
PROFILE_SCHEMA_V2 = "wasm-biotic.factory-substrate-profile.v2"
DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
PUBLIC_KEY_PATTERN = re.compile(r"^[0-9a-f]{64}$")
SHA256_HEX_PATTERN = re.compile(r"^[0-9a-f]{64}$")
R1_CHANGE_REQUEST_MEDIA_TYPE = "application/vnd.wasm-biotic.r1-change-request.v1+json"
R1_WORK_STATE_MEDIA_TYPE = "application/vnd.wasm-biotic.r1-work-state.v1+json"
R1_OPERATION_HISTORY = [
    "workspace-open",
    "workspace-snapshot",
    "workspace-patch",
    "schedule-job",
    "candidate-build",
    "factory-provider-proposal",
    "validation-prove",
    "review-candidate",
    "package-publish",
    "package-verify",
    "evidence-publish",
    "evidence-resolve",
]
R2_DYNAMIC_TARGETS = {
    "planner": "planner-worker",
    "builder": "builder-worker",
    "validator": "validator-worker",
    "reviewer": "reviewer-worker",
    "packager": "packager-worker",
    "continuity-worker": "continuity-worker",
    "admitted-tool-probe": "admitted-tool-probe",
}
R2_PRINCIPAL_SEED_SCHEMA = "wasm-biotic.principal-seed.v1"
R2_ALIAS_MATERIAL_SCHEMA = "wasm-biotic.host-import-alias-material.v1"
R2_IMPORT_ALIAS_SCHEME = "wasm-biotic.per-consumer-host-import.v1"
R2_PRINCIPAL_ID_SCHEME = "wasm-biotic.graph-node-principal.v1"
R0_CLAIM_SCOPE = (
    "Focused public-key-only production-kernel admission and restart evidence for the "
    "exact incumbent/successor package cohort. The aggregate Section 7 release bundle "
    "decides component completeness."
)
R1_CLAIM_SCOPE = (
    "Focused public-key-only production-kernel admission, exact canonical R1 "
    "source-change reproduction, replay and restart evidence for the exact R1 "
    "incumbent/successor package cohort. The aggregate R1 release bundle decides "
    "component completeness."
)
R2_CLAIM_SCOPE = (
    "Focused public-key-only production-kernel admission, exact canonical R1 "
    "source-change reproduction, replay, restart and R2 per-consumer principal "
    "binding evidence for the exact R2 incumbent/successor package cohort. The "
    "aggregate R2 release bundle decides component completeness."
)
R3_CLAIM_SCOPE = (
    "Focused public-key-only production-kernel admission, exact canonical R1 "
    "source-change reproduction, replay, restart, per-consumer principal binding "
    "and exact signed bounded-HTTP profile/constraint identity evidence for the "
    "R3 incumbent/successor package cohort. The aggregate R3 release bundle decides "
    "component completeness and transport-confinement evidence."
)


class HarnessError(RuntimeError):
    """A closed precondition or conformance check failed."""


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise HarnessError(message)


def require_digest(value: Any, label: str) -> str:
    require(
        isinstance(value, str) and DIGEST_PATTERN.fullmatch(value) is not None,
        f"{label} is not a canonical SHA-256 digest",
    )
    return value


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise HarnessError(f"JSON contains duplicate key {key!r}")
        result[key] = value
    return result


def load_json(
    path: Path, expected_schema: str | None = None
) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise HarnessError(
            f"cannot read required input {path.name}: {error.strerror}"
        ) from error
    try:
        value = json.loads(raw, object_pairs_hook=reject_duplicate_keys)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise HarnessError(f"{path.name} is not valid UTF-8 JSON: {error}") from error
    require(isinstance(value, dict), f"{path.name} must contain a JSON object")
    if expected_schema is not None:
        require(
            value.get("schema") == expected_schema,
            f"{path.name} has unexpected schema {value.get('schema')!r}",
        )
    return value, raw


def is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def resolve_file(path: str, label: str, executable: bool = False) -> Path:
    supplied = Path(path).expanduser()
    require(not supplied.is_symlink(), f"{label} must not be a symbolic link")
    candidate = supplied.resolve(strict=True)
    require(candidate.is_file(), f"{label} is not a regular file")
    if executable:
        require(os.access(candidate, os.X_OK), f"{label} is not executable")
    return candidate


def resolve_directory(path: str, label: str) -> Path:
    supplied = Path(path).expanduser()
    require(not supplied.is_symlink(), f"{label} must not be a symbolic link")
    candidate = supplied.resolve(strict=True)
    require(candidate.is_dir(), f"{label} is not a directory")
    return candidate


def package_tree(path: Path) -> dict[str, Any]:
    files: list[tuple[bytes, str, Path, int]] = []
    for root, directories, names in os.walk(path, topdown=True, followlinks=False):
        root_path = Path(root)
        for directory in directories:
            entry = root_path / directory
            mode = entry.lstat().st_mode
            require(
                stat.S_ISDIR(mode) and not stat.S_ISLNK(mode),
                "package trees may contain only real directories and regular files",
            )
        for name in names:
            entry = root_path / name
            mode = entry.lstat().st_mode
            require(
                stat.S_ISREG(mode) and not stat.S_ISLNK(mode),
                "package trees may contain only real directories and regular files",
            )
            relative = entry.relative_to(path).as_posix()
            relative_bytes = relative.encode("utf-8")
            files.append((relative_bytes, relative, entry, entry.stat().st_size))
    files.sort(key=lambda item: item[0])
    inventory = bytearray()
    total_bytes = 0
    for _, relative, entry, size in files:
        inventory.extend(f"{sha256_file(entry)[7:]}  {relative}\n".encode("utf-8"))
        total_bytes += size
    return {
        "digest": sha256_bytes(bytes(inventory)),
        "file_count": len(files),
        "size_bytes": total_bytes,
    }


def require_actual_digest(path: Path, expected: Any, label: str) -> str:
    expected_digest = require_digest(expected, label)
    actual = sha256_file(path)
    require(
        actual == expected_digest,
        f"{label} digest mismatch: expected {expected_digest}, observed {actual}",
    )
    return actual


def digest_stem(digest: str) -> str:
    require_digest(digest, "content digest")
    return digest.replace(":", "-", 1)


def package_report_identity(package: dict[str, Any]) -> dict[str, Any]:
    return {
        "certification_digest": package["certification_digest"],
        "graph_manifest_digest": package["manifest_digest"],
        "previous_graph": package["previous_graph"],
        "root_authority_digest": package["root_authority_digest"],
        "root_executable_digest": package["root_executable_digest"],
        "validation_report_digest": package["strict_report_digest"],
        "wit_package_digest": package["wit_package_digest"],
    }


def inspect_package(path: Path, kind: str, expected_key_id: str) -> dict[str, Any]:
    index, _ = load_json(path / "package.json")
    require(
        index.get("package_schema") == PACKAGE_SCHEMA,
        f"{kind} package has unexpected package schema",
    )
    manifest_digest = require_digest(
        index.get("graph_manifest_digest"), f"{kind} graph manifest"
    )
    canonical_package_name = digest_stem(manifest_digest)
    retained_tree_root = path.name == "files" and path.parent.name.startswith("sha256-")
    require(
        path.name == canonical_package_name or retained_tree_root,
        f"{kind} package is neither a manifest-named directory nor a retained content tree",
    )
    require_actual_digest(
        path / "manifest.json", manifest_digest, f"{kind} graph manifest"
    )
    manifest, _ = load_json(path / "manifest.json", MANIFEST_SCHEMA)

    certification_digest = require_digest(
        index.get("certification_digest"), f"{kind} certification"
    )
    certificate_path = path / "certification" / "release-certification.json"
    require_actual_digest(
        certificate_path, certification_digest, f"{kind} release certification"
    )
    certificate, _ = load_json(certificate_path, CERTIFICATION_SCHEMA)
    require(
        certificate.get("certifier_key_id") == expected_key_id,
        f"{kind} certificate is not signed by the supplied public-key identity",
    )
    statement = certificate.get("statement")
    require(isinstance(statement, dict), f"{kind} certificate has no statement")

    strict_digest = require_digest(
        index.get("validation_report_digest"), f"{kind} strict report"
    )
    strict_path = path / "evidence" / "strict-validation.json"
    require_actual_digest(strict_path, strict_digest, f"{kind} strict report")
    strict, _ = load_json(strict_path)
    strict_schema = strict.get("schema")
    require(
        strict_schema in STRICT_REPORT_SCHEMAS,
        f"{kind} strict report has unsupported schema {strict_schema!r}",
    )
    require(strict.get("outcome") == "pass", f"{kind} strict report did not pass")
    r2 = strict_schema == STRICT_REPORT_SCHEMA_V2

    inventory_digest = require_digest(
        index.get("certified_kernel_tcb_inventory_digest"),
        f"{kind} certified kernel TCB inventory",
    )
    inventory_path = (
        path / "certified-kernel-tcb" / f"{digest_stem(inventory_digest)}.json"
    )
    require_actual_digest(
        inventory_path, inventory_digest, f"{kind} certified kernel TCB inventory"
    )

    descriptor_path = path / "derivation-descriptor.json"
    descriptor, descriptor_bytes = load_json(descriptor_path)
    profile_path = path / "substrate-profile.json"
    profile, profile_bytes = load_json(profile_path)
    descriptor_digest = sha256_bytes(descriptor_bytes)
    profile_digest = sha256_bytes(profile_bytes)
    require(
        statement.get("derivation_descriptor_digest") == descriptor_digest,
        f"{kind} certificate does not bind the retained derivation descriptor",
    )
    require(
        statement.get("substrate_profile_digest") == profile_digest,
        f"{kind} certificate does not bind the retained substrate profile",
    )
    principal_inventory_digest: str | None = None
    principal_seeds: dict[str, str] = {}
    principal_alias_count = 0
    pure_principal_count = 0
    scoped_component_digests: dict[str, str] = {}
    expected_dynamic_caller_principals: dict[str, str] = {}
    expected_dynamic_caller_consumers: dict[str, str] = {}
    http_authority: dict[str, str] | None = None
    if r2:
        require(
            descriptor.get("schema")
            == "wasm-biotic.component-derivation-descriptor.v2",
            f"{kind} R2 descriptor has the wrong schema",
        )
        profile_schema = profile.get("schema")
        require(
            profile_schema in {PROFILE_SCHEMA_V2, PROFILE_SCHEMA_V3}
            and profile.get("static_grant_model") == "per-consumer-import-alias",
            f"{kind} scoped profile does not use an exact supported authority model",
        )
        require(
            profile.get("import_alias_scheme") == R2_IMPORT_ALIAS_SCHEME
            and profile.get("principal_id_scheme") == R2_PRINCIPAL_ID_SCHEME,
            f"{kind} R2 profile uses an unsupported principal or alias identity scheme",
        )
        principals = profile.get("principals")
        require(
            isinstance(principals, list) and len(principals) == len(manifest.get("nodes", [])),
            f"{kind} R2 principal inventory does not cover the manifest",
        )
        manifest_nodes = manifest.get("nodes")
        require(isinstance(manifest_nodes, list), f"{kind} R2 manifest nodes are malformed")
        nodes_by_id = {
            node.get("id"): node
            for node in manifest_nodes
            if isinstance(node, dict) and isinstance(node.get("id"), str)
        }
        require(
            len(nodes_by_id) == len(manifest_nodes),
            f"{kind} R2 manifest node identities are missing or duplicated",
        )
        observed_aliases: set[str] = set()
        for principal in principals:
            require(isinstance(principal, dict), f"{kind} R2 principal is malformed")
            consumer = principal.get("consumer")
            seed = principal.get("principal_seed")
            require(isinstance(consumer, str), f"{kind} R2 principal has no consumer")
            require(
                consumer not in principal_seeds and consumer in nodes_by_id,
                f"{kind} R2 principal consumer is duplicated or undeclared",
            )
            authority = require_digest(
                principal.get("authority_component_digest"),
                f"{kind} principal {consumer} authority",
            )
            require(
                nodes_by_id[consumer].get("component_digest") == authority,
                f"{kind} principal {consumer} is not bound to its manifest authority",
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
            principal_seeds[consumer] = require_digest(
                seed, f"{kind} principal {consumer} seed"
            )
            require(
                principal_seeds[consumer] == expected_seed,
                f"{kind} principal {consumer} seed is not content-derived exactly",
            )
            scoped_component_digest = require_digest(
                principal.get("scoped_component_digest"),
                f"{kind} principal {consumer} scoped component",
            )
            scoped_component_digests[consumer] = scoped_component_digest
            require_actual_digest(
                path
                / "scoped-components"
                / f"{digest_stem(scoped_component_digest)}.wasm",
                scoped_component_digest,
                f"{kind} principal {consumer} scoped component",
            )
            derived_artifacts = statement.get("derived_artifacts")
            require(
                isinstance(derived_artifacts, dict)
                and derived_artifacts.get(f"scoped:{consumer}")
                == principal.get("scoped_component_digest"),
                f"{kind} certificate does not bind principal {consumer}'s scoped bytes",
            )
            host_imports = principal.get("host_imports")
            require(
                isinstance(host_imports, list),
                f"{kind} principal {consumer} host imports are malformed",
            )
            if not host_imports:
                pure_principal_count += 1
            principal_alias_count += len(host_imports)
            for host_import in host_imports:
                require(
                    isinstance(host_import, dict),
                    f"{kind} principal {consumer} host import is malformed",
                )
                source_import = host_import.get("source_import")
                capability = host_import.get("capability")
                require(
                    isinstance(source_import, str) and isinstance(capability, str),
                    f"{kind} principal {consumer} host import identity is malformed",
                )
                alias = host_import.get("alias")
                expected_alias_hex = sha256_bytes(
                    canonical_json_bytes(
                        {
                            "authority_component_digest": authority,
                            "capability": capability,
                            "consumer": consumer,
                            "schema": R2_ALIAS_MATERIAL_SCHEMA,
                            "source_import": source_import,
                        }
                    )
                )[7:]
                expected_alias = (
                    f"wasm-biotic:factory/host-{expected_alias_hex}@0.1.0"
                )
                require(
                    alias == expected_alias and alias not in observed_aliases,
                    f"{kind} principal {consumer} alias is not exact and unique",
                )
                observed_aliases.add(alias)
        require(
            set(principal_seeds) == set(nodes_by_id),
            f"{kind} R2 principal consumers differ from the manifest node identities",
        )
        invocations = manifest.get("invocations")
        callers_by_target: dict[str, str] = {}
        for edge in invocations:
            require(isinstance(edge, dict), f"{kind} R2 invocation is malformed")
            target = edge.get("target")
            caller = edge.get("consumer")
            if isinstance(target, str) and isinstance(caller, str):
                callers_by_target.setdefault(target, caller)
        for label, target in R2_DYNAMIC_TARGETS.items():
            caller = callers_by_target.get(target)
            require(
                caller in principal_seeds,
                f"{kind} R2 dynamic target {target} has no declared caller principal",
            )
            expected_dynamic_caller_principals[label] = principal_seeds[caller]
            expected_dynamic_caller_consumers[label] = caller
        expected_inventory = {
            "graph_manifest_digest": manifest_digest,
            "import_alias_scheme": profile.get("import_alias_scheme"),
            "principal_id_scheme": profile.get("principal_id_scheme"),
            "principals": principals,
            "schema": "wasm-biotic.principal-inventory-evidence.v1",
        }
        expected_inventory_bytes = canonical_json_bytes(expected_inventory)
        inventory_evidence_path = path / "evidence" / "principal-inventory.json"
        inventory_evidence, inventory_evidence_bytes = load_json(inventory_evidence_path)
        require(
            inventory_evidence_bytes == expected_inventory_bytes
            and inventory_evidence == expected_inventory,
            f"{kind} retained principal inventory differs from the signed R2 mapping",
        )
        principal_inventory_digest = sha256_bytes(inventory_evidence_bytes)
        require(
            strict.get("principal_inventory_digest") == principal_inventory_digest,
            f"{kind} strict report does not bind the retained principal inventory",
        )
        enforcement = strict.get("principal_enforcement")
        require(isinstance(enforcement, dict), f"{kind} R2 enforcement evidence is absent")
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
                f"{kind} R2 strict report did not establish {flag}",
            )
        require(
            enforcement.get("result") == "pass",
            f"{kind} R2 strict principal enforcement did not pass",
        )
        if profile_schema == PROFILE_SCHEMA_V3:
            require(
                profile_bytes == canonical_json_bytes(profile),
                f"{kind} profile v3 is not canonical JSON",
            )
            try:
                http_authority = inspect_r3_http_authority(
                    path, profile, manifest, statement, kind
                )
            except R3AuthorityError as error:
                raise HarnessError(str(error)) from error
        else:
            require(
                "http_transport" not in profile,
                f"{kind} profile v2 unexpectedly contains an R3 HTTP projection",
            )
    else:
        require(
            descriptor.get("schema")
            == "wasm-biotic.component-derivation-descriptor.v1",
            f"{kind} v1 descriptor has the wrong schema",
        )
        require(
            profile.get("schema") == PROFILE_SCHEMA_V1,
            f"{kind} v1 profile has the wrong schema",
        )
        require(
            "http_transport" not in profile,
            f"{kind} profile v1 unexpectedly contains an R3 HTTP projection",
        )
    nodes = manifest.get("nodes")
    bindings = manifest.get("bindings")
    invocations = manifest.get("invocations")
    sources = descriptor.get("sources")
    executables = descriptor.get("executables")
    for value, label in [
        (nodes, "nodes"),
        (bindings, "bindings"),
        (invocations, "invocations"),
        (sources, "descriptor sources"),
        (executables, "descriptor executables"),
    ]:
        require(isinstance(value, list), f"{kind} package {label} must be an array")

    expected_statement = {
        "graph_manifest_digest": manifest_digest,
        "native_tcb_inventory_digest": inventory_digest,
        "validation_report_digest": strict_digest,
    }
    for field, expected in expected_statement.items():
        require(
            statement.get(field) == expected,
            f"{kind} certificate statement has the wrong {field}",
        )
    root_authority = require_digest(
        index.get("root_authority_digest"), f"{kind} root authority"
    )
    root_executable = require_digest(
        index.get("root_executable_digest"), f"{kind} root executable"
    )
    require_actual_digest(
        path / "factory-root.wasm", root_executable, f"{kind} root executable"
    )
    tree = package_tree(path)

    return {
        "kind": kind,
        "directory_name": path.name,
        "directory_tree_digest": tree["digest"],
        "directory_file_count": tree["file_count"],
        "directory_bytes": tree["size_bytes"],
        "manifest_digest": manifest_digest,
        "previous_graph": manifest.get("previous_graph"),
        "component_nodes": len(nodes),
        "bindings": len(bindings),
        "invocation_edges": len(invocations),
        "raw_components": len(sources),
        "derived_executables": len(executables),
        "root_authority_digest": root_authority,
        "root_executable_digest": root_executable,
        "strict_report_digest": strict_digest,
        "strict_report_outcome": strict["outcome"],
        "strict_report_schema": strict_schema,
        "certification_digest": certification_digest,
        "certified_kernel_tcb_inventory_digest": inventory_digest,
        "wit_package_digest": require_digest(
            statement.get("wit_package_digest"), f"{kind} WIT package"
        ),
        "derivation_descriptor_digest": descriptor_digest,
        "substrate_profile_digest": profile_digest,
        "principal_inventory_digest": principal_inventory_digest,
        "principal_seeds": principal_seeds,
        "principal_count": len(principal_seeds),
        "principal_alias_count": principal_alias_count,
        "pure_principal_count": pure_principal_count,
        "scoped_component_digests": scoped_component_digests,
        "expected_dynamic_caller_principals": expected_dynamic_caller_principals,
        "expected_dynamic_caller_consumers": expected_dynamic_caller_consumers,
        "import_alias_scheme": profile.get("import_alias_scheme") if r2 else None,
        "principal_id_scheme": profile.get("principal_id_scheme") if r2 else None,
        "profile_schema": profile.get("schema"),
        "http_transport_binding_alias": (
            http_authority["binding_alias"] if http_authority is not None else None
        ),
        "http_transport_constraint_digest": (
            http_authority["constraint_digest"] if http_authority is not None else None
        ),
        "http_transport_constraint_schema": (
            http_authority["constraint_schema"] if http_authority is not None else None
        ),
        "certifier_key_id": expected_key_id,
    }


def require_mapping_equal(actual: Any, expected: dict[str, Any], label: str) -> None:
    require(isinstance(actual, dict), f"{label} is missing")
    for key, value in expected.items():
        require(
            actual.get(key) == value, f"{label}.{key} does not match the exact package"
        )


def require_true_fields(
    value: Any, fields: Iterable[str], label: str
) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} is missing")
    for field in fields:
        require(value.get(field) is True, f"{label} did not establish {field}")
    return value


def require_r1_summary(value: Any, label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} is missing")
    for field in [
        "request_digest_hex",
        "base_tree_digest_hex",
        "patched_tree_digest_hex",
        "artifact_digest_hex",
        "validation_digest_hex",
        "review_digest_hex",
        "package_digest_hex",
        "verification_digest_hex",
        "evidence_digest_hex",
        "resolved_digest_hex",
    ]:
        require(
            isinstance(value.get(field), str)
            and SHA256_HEX_PATTERN.fullmatch(value[field]) is not None,
            f"{label}.{field} is not a lower-case SHA-256 hex value",
        )
    require(value.get("source_changed") is True, f"{label} records no source change")
    require(
        value["base_tree_digest_hex"] != value["patched_tree_digest_hex"],
        f"{label} does not bind a changed source tree",
    )
    require(
        type(value.get("bytecode_size_bytes")) is int
        and value["bytecode_size_bytes"] > 0,
        f"{label} records no compiled bytecode",
    )
    require(
        value.get("provider_policy") == "local-fixture",
        f"{label} did not use the bounded local-fixture provider policy",
    )
    for field in ["tests_discovered", "passed_tests", "total_tests"]:
        require(
            type(value.get(field)) is int and value[field] > 0,
            f"{label}.{field} must be a positive integer",
        )
    require(
        value["tests_discovered"] == value["total_tests"]
        and value["passed_tests"] == value["total_tests"],
        f"{label} did not discover and pass the exact test corpus",
    )
    for field in ["review_approved", "package_verified", "evidence_resolved"]:
        require(value.get(field) is True, f"{label} did not establish {field}")
    require(
        value.get("operation_history") == R1_OPERATION_HISTORY,
        f"{label} does not contain the exact 12-operation R1 history",
    )
    return value


def require_r1_output(
    value: Any, summary: dict[str, Any], label: str
) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} is missing")
    digest = require_digest(value.get("digest"), f"{label} digest")
    require(
        value.get("media_type") == R1_WORK_STATE_MEDIA_TYPE,
        f"{label} is not a resolved R1 work state",
    )
    require(
        type(value.get("size_bytes")) is int and value["size_bytes"] > 0,
        f"{label} has no exact positive byte length",
    )
    require(
        digest == f"sha256:{summary['resolved_digest_hex']}",
        f"{label} digest does not bind the strictly verified semantic summary",
    )
    return value


def require_r1_schedule(observation: Any, label: str) -> None:
    require(isinstance(observation, dict), f"{label} is missing")
    mechanism = observation.get("mechanism_behavior")
    require(isinstance(mechanism, dict), f"{label} mechanism behavior is missing")
    transactions = mechanism.get("transaction_entries_by_namespace")
    require(
        isinstance(transactions, dict)
        and type(transactions.get("wasm-biotic.schedule.v1")) is int
        and transactions["wasm-biotic.schedule.v1"] == 1,
        f"{label} does not contain exactly one durable schedule transaction",
    )
    wakes = mechanism.get("wakes")
    require(
        isinstance(wakes, list) and len(wakes) == 1,
        f"{label} does not contain exactly one durable schedule wake",
    )
    wake = wakes[0]
    require(isinstance(wake, dict), f"{label} durable wake is malformed")
    require(
        type(wake.get("not_before_ms")) is int and wake["not_before_ms"] == 0,
        f"{label} durable wake is not replay-stable at not-before zero",
    )
    wake_id = wake.get("wake_id")
    job_id = observation.get("job_id")
    require(
        isinstance(wake_id, str)
        and isinstance(job_id, str)
        and wake_id.startswith(f"{job_id}:")
        and wake_id.endswith(":3:scheduling:schedule-job"),
        f"{label} durable wake is not the planner's fourth capability call",
    )
    for field in ["idempotency_key", "payload_digest", "target_component"]:
        require_digest(wake.get(field), f"{label} wake {field}")
    provenance = observation.get("normalized_dynamic_provenance")
    require(isinstance(provenance, dict), f"{label} provenance is missing")
    planner = provenance.get("planner")
    require(isinstance(planner, dict), f"{label} planner provenance is missing")
    require(
        wake["target_component"] == planner.get("authority_component_digest"),
        f"{label} durable wake is not targeted to the exact planner authority",
    )


def validate_candidate_shadow_v2(candidate: dict[str, Any]) -> None:
    incumbent_observation = candidate.get("incumbent_observation")
    candidate_observation = candidate.get("candidate_observation")
    require(
        isinstance(incumbent_observation, dict),
        "candidate shadow incumbent R1 observation is missing",
    )
    require(
        isinstance(candidate_observation, dict),
        "candidate shadow successor R1 observation is missing",
    )

    incumbent_summary = require_r1_summary(
        incumbent_observation.get("resolved_work_summary"),
        "candidate shadow incumbent semantic summary",
    )
    candidate_summary = require_r1_summary(
        candidate_observation.get("resolved_work_summary"),
        "candidate shadow successor semantic summary",
    )
    require(
        incumbent_summary == candidate_summary,
        "candidate shadow R1 semantic summaries are not exactly equal",
    )
    incumbent_output = require_r1_output(
        incumbent_observation.get("resolved_output"),
        incumbent_summary,
        "candidate shadow incumbent resolved output",
    )
    candidate_output = require_r1_output(
        candidate_observation.get("resolved_output"),
        candidate_summary,
        "candidate shadow successor resolved output",
    )
    require(
        incumbent_output == candidate_output,
        "candidate shadow R1 resolved outputs are not exactly equal",
    )

    for observation, label in [
        (incumbent_observation, "candidate shadow incumbent observation"),
        (candidate_observation, "candidate shadow successor observation"),
    ]:
        require(observation.get("status") == "completed", f"{label} did not complete")
        require(
            observation.get("terminal_failure") is None,
            f"{label} reports a terminal failure",
        )
        require(
            observation.get("service_operations_in_execution_order")
            == R1_OPERATION_HISTORY,
            f"{label} does not report the exact 12 service calls",
        )
        require_r1_schedule(observation, label)

    corpus = candidate.get("corpus")
    require(isinstance(corpus, dict), "candidate shadow R1 corpus is missing")
    require(
        corpus.get("source_media_type") == R1_CHANGE_REQUEST_MEDIA_TYPE,
        "candidate shadow did not use the canonical R1 change-request media type",
    )
    require(
        corpus.get("operations_probe_media_type") == "application/octet-stream",
        "candidate shadow operations probe did not use the isolated legacy media type",
    )
    require_digest(corpus.get("source_digest"), "candidate shadow R1 source")
    require_digest(
        corpus.get("operations_probe_digest"),
        "candidate shadow operations compatibility probe",
    )


def report_contract_for_candidate_schema(
    candidate_schema: str, profile_schema: str | None = None
) -> dict[str, str]:
    if candidate_schema == CANDIDATE_REPORT_SCHEMA_V1:
        require(
            profile_schema in {None, PROFILE_SCHEMA_V1},
            "candidate shadow v1 is paired with an unsupported profile generation",
        )
        return {
            "schema": REPORT_SCHEMA_R0,
            "evidence_profile": "r0-bounded-cycle",
            "claim_scope": R0_CLAIM_SCOPE,
        }
    if candidate_schema == CANDIDATE_REPORT_SCHEMA_V2:
        require(
            profile_schema in {None, PROFILE_SCHEMA_V1},
            "candidate shadow v2 is paired with an unsupported profile generation",
        )
        return {
            "schema": REPORT_SCHEMA_R1,
            "evidence_profile": "r1-bounded-local-source-change",
            "claim_scope": R1_CLAIM_SCOPE,
        }
    if candidate_schema == CANDIDATE_REPORT_SCHEMA_V3:
        if profile_schema == PROFILE_SCHEMA_V3:
            return {
                "schema": REPORT_SCHEMA_R3,
                "evidence_profile": "r3-bounded-http-component-authority",
                "claim_scope": R3_CLAIM_SCOPE,
            }
        require(
            profile_schema in {None, PROFILE_SCHEMA_V2},
            "candidate shadow v3 is paired with an unsupported profile generation",
        )
        return {
            "schema": REPORT_SCHEMA_R2,
            "evidence_profile": "r2-per-consumer-least-authority",
            "claim_scope": R2_CLAIM_SCOPE,
        }
    raise HarnessError(f"candidate shadow has unsupported schema {candidate_schema!r}")


def validate_independent_r1_reproduction(reproduction: dict[str, Any]) -> None:
    require_true_fields(
        reproduction,
        [
            "boundary_probe_component_root",
            "complete_six_worker_cycle",
            "evolution_shadow_matched",
            "r1_semantics_verified",
            "reference_exact_replay_claim_complete",
            "reference_final_output_exact_match",
            "reference_provenance_exact_match",
            "reference_r1_semantics_exact_match",
            "reference_terminal_result_exact_match",
        ],
        "independent R1 reproduction",
    )
    require(
        reproduction.get("boundary_probe_status") == 200,
        "independent R1 reproduction did not pass the component-root probe",
    )
    require(
        reproduction.get("terminal_status") == "completed",
        "independent R1 reproduction did not complete",
    )
    require(
        reproduction.get("source_label") == "kernel-probe",
        "independent R1 reproduction did not use the signed kernel fixture",
    )
    require(
        reproduction.get("source_media_type") == R1_CHANGE_REQUEST_MEDIA_TYPE,
        "independent R1 reproduction did not use canonical R1 change-request media",
    )
    source_digest = require_digest(
        reproduction.get("source_digest"), "independent R1 source"
    )
    final_output_digest = require_digest(
        reproduction.get("final_output_digest"), "independent R1 output"
    )
    require(
        reproduction.get("final_output_media_type") == R1_WORK_STATE_MEDIA_TYPE,
        "independent R1 reproduction did not resolve to R1 work-state media",
    )
    require_digest(
        reproduction.get("terminal_result_digest"), "independent R1 terminal result"
    )
    require(
        reproduction.get("admitted_dynamic_authorities") == 7
        and isinstance(reproduction.get("dynamic_execution_provenance"), dict)
        and len(reproduction["dynamic_execution_provenance"]) == 7,
        "independent R1 reproduction did not bind exactly seven dynamic authorities",
    )

    exact_replay = require_true_fields(
        reproduction.get("exact_replay"),
        [
            "inspect_blob_equal",
            "inspect_bytes_equal",
            "job_id_equal",
            "mechanism_snapshot_unchanged",
            "output_blob_equal",
            "output_bytes_equal",
            "provenance_unchanged",
            "resubmitted_exact_submit_blob",
        ],
        "independent R1 exact replay",
    )
    require(
        exact_replay.get("mechanism_snapshot_before_digest")
        == exact_replay.get("mechanism_snapshot_after_digest"),
        "independent R1 replay changed its mechanism snapshot digest",
    )
    require_digest(
        exact_replay.get("mechanism_snapshot_before_digest"),
        "independent R1 pre-replay mechanism snapshot",
    )

    semantics = require_r1_summary(
        reproduction.get("r1_semantics"), "independent R1 semantic summary"
    )
    require(
        semantics.get("fixture_label") == "kernel-probe",
        "independent R1 semantic summary has the wrong fixture label",
    )
    require(
        semantics.get("input_media_type") == R1_CHANGE_REQUEST_MEDIA_TYPE,
        "independent R1 semantic summary has the wrong input media",
    )
    require(
        semantics.get("output_media_type") == R1_WORK_STATE_MEDIA_TYPE,
        "independent R1 semantic summary has the wrong output media",
    )
    require(
        semantics.get("input_digest")
        == source_digest
        == f"sha256:{semantics['request_digest_hex']}",
        "independent R1 semantic summary is not bound to the source bytes",
    )
    require(
        semantics.get("output_digest")
        == final_output_digest
        == f"sha256:{semantics['resolved_digest_hex']}",
        "independent R1 semantic summary is not bound to the output bytes",
    )


def require_r2_graph_identity(
    actual: Any, package: dict[str, Any], label: str
) -> None:
    require_mapping_equal(
        actual,
        {
            **package_report_identity(package),
            "derivation_descriptor_digest": package[
                "derivation_descriptor_digest"
            ],
            "principal_inventory_digest": package["principal_inventory_digest"],
            "substrate_profile_digest": package["substrate_profile_digest"],
        },
        label,
    )


def require_r2_dynamic_provenance(
    provenance: Any, package: dict[str, Any], labels: Iterable[str], label: str
) -> None:
    require(isinstance(provenance, dict), f"{label} is missing")
    expected = package["expected_dynamic_caller_principals"]
    for role in labels:
        item = provenance.get(role)
        require(isinstance(item, dict), f"{label}.{role} is missing")
        require(
            item.get("caller_principal_seed") == expected[role],
            f"{label}.{role} has the wrong caller principal",
        )
        graph = item.get("graph_manifest_digest")
        if graph is not None:
            require(
                graph == package["manifest_digest"],
                f"{label}.{role} has the wrong graph identity",
            )
        require_digest(
            item.get("authority_component_digest"), f"{label}.{role} authority"
        )
        require_digest(
            item.get("executable_component_digest"), f"{label}.{role} executable"
        )
        sources = item.get("source_component_digests")
        require(
            isinstance(sources, list) and bool(sources),
            f"{label}.{role} has no source-component provenance",
        )
        for index, digest in enumerate(sources):
            require_digest(digest, f"{label}.{role} source {index}")


def validate_independent_r2_reproduction(
    independent: dict[str, Any],
    reproduction: dict[str, Any],
    incumbent: dict[str, Any],
) -> None:
    substrate = independent.get("independent_substrate")
    require(isinstance(substrate, dict), "independent R2 substrate identity is missing")
    require(
        substrate.get("dependencies_on_forbidden_native_implementations") is False,
        "independent R2 substrate depends on forbidden native implementations",
    )
    require(
        substrate.get("mechanism_interfaces")
        == [
            "blob-store",
            "transaction-store",
            "clock",
            "component-runner",
            "http-transport",
            "key-service",
            "activation",
            "audit-log",
        ],
        "independent R2 substrate does not expose exactly the eight native mechanisms",
    )
    enforcement = independent.get("principal_enforcement")
    require(isinstance(enforcement, dict), "independent R2 principal enforcement is missing")
    require_mapping_equal(
        enforcement,
        {
            "alias_count": incumbent["principal_alias_count"],
            "caller_identity_source": (
                "validated-linker-alias-bound-to-signed-principal-seed-v1"
            ),
            "caller_owned_operations_enforced": True,
            "caller_target_edges_enforced": True,
            "canonical_host_imports_absent": True,
            "descriptor_schema": "wasm-biotic.component-derivation-descriptor.v2",
            "fixed_linker_alias_contexts": True,
            "import_alias_scheme": incumbent["import_alias_scheme"],
            "principal_count": incumbent["principal_count"],
            "principal_id_scheme": incumbent["principal_id_scheme"],
            "principal_inventory_digest": incumbent[
                "principal_inventory_digest"
            ],
            "profile_schema": incumbent["profile_schema"],
            "pure_principal_count": incumbent["pure_principal_count"],
            "result": "pass",
        },
        "independent R2 principal enforcement",
    )
    require(
        reproduction.get("caller_principals_exact") is True,
        "independent R2 reproduction did not establish exact caller principals",
    )
    expected_observed: dict[str, str] = {}
    for role, consumer in incumbent["expected_dynamic_caller_consumers"].items():
        expected_observed[consumer] = incumbent["expected_dynamic_caller_principals"][
            role
        ]
    require(
        reproduction.get("observed_caller_principals") == expected_observed,
        "independent R2 observed caller inventory is not the signed exact mapping",
    )
    require_r2_dynamic_provenance(
        reproduction.get("dynamic_execution_provenance"),
        incumbent,
        R2_DYNAMIC_TARGETS,
        "independent R2 dynamic provenance",
    )


def validate_candidate_shadow_v3(
    candidate: dict[str, Any],
    incumbent: dict[str, Any],
    successor: dict[str, Any],
) -> None:
    require_r2_graph_identity(
        candidate.get("incumbent"), incumbent, "candidate R2 incumbent identity"
    )
    require_r2_graph_identity(
        candidate.get("candidate"), successor, "candidate R2 successor identity"
    )
    shadow_roles = [
        "planner",
        "builder",
        "validator",
        "reviewer",
        "packager",
        "continuity-worker",
    ]
    for observation_name, package in [
        ("incumbent_observation", incumbent),
        ("candidate_observation", successor),
    ]:
        observation = candidate.get(observation_name)
        require(
            isinstance(observation, dict),
            f"candidate R2 {observation_name} is missing",
        )
        require_r2_dynamic_provenance(
            observation.get("normalized_dynamic_provenance"),
            package,
            shadow_roles,
            f"candidate R2 {observation_name} provenance",
        )


def inspect_evidence_inputs(
    independent_path: Path,
    candidate_path: Path,
    native_build_path: Path,
    incumbent: dict[str, Any],
    successor: dict[str, Any],
    kernel: Path,
    expected_key_id: str,
) -> dict[str, Any]:
    independent, _ = load_json(independent_path)
    independent_schema = independent.get("schema")
    require(
        independent_schema in INDEPENDENT_REPORT_SCHEMAS,
        f"independent reproduction has unsupported schema {independent_schema!r}",
    )
    require(
        independent.get("artifact_closure_verified") is True,
        "independent reproduction did not verify the artifact closure",
    )
    require(
        independent.get("certificate_signature_verified") is True,
        "independent reproduction did not verify the release signature",
    )
    reproduction = independent.get("reproduction")
    require(
        isinstance(reproduction, dict), "independent reproduction result is missing"
    )
    for field in [
        "complete_six_worker_cycle",
        "evolution_shadow_matched",
        "reference_provenance_exact_match",
        "reference_terminal_result_exact_match",
    ]:
        require(
            reproduction.get(field) is True,
            f"independent reproduction did not establish {field}",
        )
    independent_release = package_report_identity(incumbent)
    independent_release.update(
        {
            "certified_kernel_tcb_inventory_digest": incumbent[
                "certified_kernel_tcb_inventory_digest"
            ],
            "certifier_key_id": expected_key_id,
        }
    )
    require_mapping_equal(
        independent.get("release"), independent_release, "independent report release"
    )

    candidate, _ = load_json(candidate_path)
    candidate_schema = candidate.get("schema")
    require(
        isinstance(candidate_schema, str)
        and candidate_schema in CANDIDATE_REPORT_SCHEMAS,
        f"candidate shadow has unsupported schema {candidate_schema!r}",
    )
    require(candidate.get("outcome") == "pass", "candidate shadow did not pass")
    require(
        candidate.get("remaining_conformance_gaps") == [],
        "candidate shadow reports remaining conformance gaps",
    )
    require_mapping_equal(
        candidate.get("incumbent"),
        package_report_identity(incumbent),
        "candidate report incumbent",
    )
    require_mapping_equal(
        candidate.get("candidate"),
        package_report_identity(successor),
        "candidate report candidate",
    )
    comparison_fields = [
        "all_seven_capability_service_families_executed",
        "all_six_worker_roles_executed",
        "candidate_previous_graph_is_incumbent",
        "composed_root_source_closure_equal",
        "mechanism_behavior_equal",
        "normalized_dynamic_provenance_equal",
        "normalized_supervisor_state_equal",
        "operations_probe_equal",
        "operations_route_request_equal",
        "service_operation_sequence_equal",
        "supervisor_terminal_semantics_equal",
    ]
    if candidate_schema == CANDIDATE_REPORT_SCHEMA_V1:
        comparison_fields.extend(
            ["service_layers_equal", "terminal_output_exactly_equal"]
        )
    else:
        comparison_fields.extend(
            ["resolved_work_summary_equal", "resolved_output_exactly_equal"]
        )
    require_true_fields(
        candidate.get("comparison"), comparison_fields, "candidate shadow comparison"
    )
    isolation = candidate.get("isolation")
    require_true_fields(
        isolation,
        [
            "candidate_active_pair_unchanged",
            "incumbent_active_pair_unchanged_during_candidate",
            "mechanism_roots_distinct",
        ],
        "candidate shadow isolation",
    )
    require(
        isolation.get("candidate_had_incumbent_mechanism_handle") is False,
        "candidate shadow reused the incumbent mechanism handle",
    )
    require(
        type(isolation.get("candidate_activation_count_after")) is int
        and isolation["candidate_activation_count_after"] == 0,
        "candidate shadow activated the candidate",
    )
    require(
        isolation.get("incumbent_mechanism_snapshot_before_candidate")
        == isolation.get("incumbent_mechanism_snapshot_after_candidate"),
        "candidate shadow changed the incumbent mechanism root",
    )
    r2_packages = (
        incumbent["strict_report_schema"] == STRICT_REPORT_SCHEMA_V2
        and successor["strict_report_schema"] == STRICT_REPORT_SCHEMA_V2
    )
    require(
        (candidate_schema == CANDIDATE_REPORT_SCHEMA_V3) == r2_packages,
        "candidate shadow schema does not match the exact package authority model",
    )
    require(
        (independent_schema == INDEPENDENT_REPORT_SCHEMA_V2) == r2_packages,
        "independent reproduction schema does not match the exact package authority model",
    )
    if candidate_schema in {
        CANDIDATE_REPORT_SCHEMA_V2,
        CANDIDATE_REPORT_SCHEMA_V3,
    }:
        validate_candidate_shadow_v2(candidate)
        validate_independent_r1_reproduction(reproduction)
    if candidate_schema == CANDIDATE_REPORT_SCHEMA_V3:
        validate_candidate_shadow_v3(candidate, incumbent, successor)
        validate_independent_r2_reproduction(independent, reproduction, incumbent)

    native_build, _ = load_json(native_build_path, NATIVE_BUILD_SCHEMA)
    require(
        native_build.get("gate_result") == "pass",
        "native build attestation did not pass",
    )
    kernel_digest = sha256_file(kernel)
    kernel_size = kernel.stat().st_size
    native_artifact = native_build.get("native_artifact")
    require(
        isinstance(native_artifact, dict), "native build artifact binding is missing"
    )
    require(
        native_artifact.get("sha256") == kernel_digest,
        "native build attestation does not bind the supplied kernel bytes",
    )
    require(
        native_artifact.get("size_bytes") == kernel_size,
        "native build attestation has the wrong kernel size",
    )
    compiled_inventory = native_build.get("compiled_inventory")
    require(
        isinstance(compiled_inventory, dict), "compiled inventory binding is missing"
    )
    require(
        compiled_inventory.get("sha256")
        == incumbent["certified_kernel_tcb_inventory_digest"],
        "native build inventory does not match the signed packages",
    )

    return {
        "independent_substrate_reproduction": {
            "digest": sha256_file(independent_path),
            "schema": independent_schema,
            "result": "pass",
        },
        "candidate_graph_shadow": {
            "digest": sha256_file(candidate_path),
            "schema": candidate_schema,
            "result": "pass",
        },
        "native_build_attestation": {
            "digest": sha256_file(native_build_path),
            "schema": NATIVE_BUILD_SCHEMA,
            "result": "pass",
        },
    }


def diagnostic_digest(completed: subprocess.CompletedProcess[bytes]) -> str:
    return sha256_bytes(completed.stdout + b"\0" + completed.stderr)


def run_kernel(
    kernel: Path, arguments: Iterable[Path | str], cwd: Path
) -> subprocess.CompletedProcess[bytes]:
    command = [str(kernel), *(str(argument) for argument in arguments)]
    environment = {"PATH": os.defpath, "LANG": "C", "LC_ALL": "C"}
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            env=environment,
            input=b"",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=COMMAND_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise HarnessError(
            f"kernel command exceeded the closed {COMMAND_TIMEOUT_SECONDS}-second bound"
        ) from error


def successful_observation(
    identifier: str,
    completed: subprocess.CompletedProcess[bytes],
    required_stderr: bytes,
) -> dict[str, Any]:
    require(
        completed.returncode == 0,
        f"positive command {identifier} exited {completed.returncode}",
    )
    require(
        required_stderr in completed.stderr,
        f"positive command {identifier} did not emit its expected readiness marker",
    )
    return {
        "id": identifier,
        "result": "pass",
        "process_exit": completed.returncode,
        "diagnostic_sha256": diagnostic_digest(completed),
        "stdout_bytes": len(completed.stdout),
        "stderr_bytes": len(completed.stderr),
    }


def failed_observation(
    identifier: str,
    completed: subprocess.CompletedProcess[bytes],
    required_diagnostics: Iterable[bytes],
    expected: str,
    mutation_scope: str,
    observed: str,
    **extra: Any,
) -> dict[str, Any]:
    require(
        completed.returncode != 0,
        f"negative control {identifier} unexpectedly succeeded",
    )
    diagnostic = completed.stdout + b"\n" + completed.stderr
    for marker in required_diagnostics:
        require(
            marker.lower() in diagnostic.lower(),
            f"negative control {identifier} failed without expected diagnostic marker",
        )
    result = {
        "id": identifier,
        "result": "pass",
        "expected": expected,
        "mutation_scope": mutation_scope,
        "observed": observed,
        "process_exit": completed.returncode,
        "diagnostic_sha256": diagnostic_digest(completed),
    }
    result.update(extra)
    return result


def initialize_state(
    kernel: Path,
    state: Path,
    manifest_digest: str,
    public_key_hex: str,
    operator_config: Path,
    cwd: Path,
) -> subprocess.CompletedProcess[bytes]:
    return run_kernel(
        kernel,
        ["init", state, manifest_digest, public_key_hex, operator_config],
        cwd,
    )


def canonical_rewrite(path: Path, value: Any) -> None:
    path.write_bytes(canonical_json_bytes(value))


def run_campaign(
    kernel: Path,
    incumbent_path: Path,
    successor_path: Path,
    public_key_hex: str,
    operator_config: Path,
    independent_report: Path,
    candidate_report: Path,
    native_build_attestation: Path,
) -> dict[str, Any]:
    public_key_bytes = bytes.fromhex(public_key_hex)
    certifier_key_id = sha256_bytes(public_key_bytes)
    incumbent = inspect_package(incumbent_path, "incumbent", certifier_key_id)
    successor = inspect_package(successor_path, "successor", certifier_key_id)
    require(
        incumbent["previous_graph"] is None,
        "incumbent package unexpectedly declares a previous graph",
    )
    require(
        successor["previous_graph"] == incumbent["manifest_digest"],
        "successor package does not name the exact incumbent graph",
    )
    require(
        successor["manifest_digest"] != incumbent["manifest_digest"],
        "incumbent and successor graph identities must be distinct",
    )
    require(
        successor["certification_digest"] != incumbent["certification_digest"],
        "incumbent and successor certificates must be distinct",
    )
    require(
        successor["certified_kernel_tcb_inventory_digest"]
        == incumbent["certified_kernel_tcb_inventory_digest"],
        "package cohort does not bind one exact native TCB inventory",
    )
    require(
        successor["strict_report_schema"] == incumbent["strict_report_schema"],
        "package cohort mixes authority-model generations",
    )
    require(
        successor["profile_schema"] == incumbent["profile_schema"],
        "package cohort mixes substrate-profile generations",
    )

    evidence_inputs = inspect_evidence_inputs(
        independent_report,
        candidate_report,
        native_build_attestation,
        incumbent,
        successor,
        kernel,
        certifier_key_id,
    )
    candidate_schema = evidence_inputs["candidate_graph_shadow"]["schema"]
    report_contract = report_contract_for_candidate_schema(
        candidate_schema, incumbent["profile_schema"]
    )

    with tempfile.TemporaryDirectory(
        prefix="wasm-biotic-signed-admission-"
    ) as temporary:
        temporary_root = Path(temporary)
        positive_state = temporary_root / "positive-state"
        positive_commands = []

        completed = initialize_state(
            kernel,
            positive_state,
            incumbent["manifest_digest"],
            public_key_hex,
            operator_config,
            temporary_root,
        )
        positive_commands.append(
            successful_observation(
                "initialize-public-key-only-state",
                completed,
                b"initialized operator capacity",
            )
        )
        completed = run_kernel(
            kernel, ["admit", incumbent_path, positive_state], temporary_root
        )
        positive_commands.append(
            successful_observation(
                "admit-incumbent",
                completed,
                f"admitted manifest={incumbent['manifest_digest']}".encode("ascii"),
            )
        )
        completed = run_kernel(
            kernel, ["admit", successor_path, positive_state], temporary_root
        )
        positive_commands.append(
            successful_observation(
                "admit-successor",
                completed,
                f"admitted manifest={successor['manifest_digest']}".encode("ascii"),
            )
        )
        completed = run_kernel(
            kernel, ["serve", incumbent_path, positive_state], temporary_root
        )
        positive_commands.append(
            successful_observation(
                "serve-incumbent-bootstrap",
                completed,
                f"ready manifest={incumbent['manifest_digest']}".encode("ascii"),
            )
        )
        completed = run_kernel(
            kernel, ["serve", incumbent_path, positive_state], temporary_root
        )
        positive_commands.append(
            successful_observation(
                "serve-incumbent-reopen",
                completed,
                f"ready manifest={incumbent['manifest_digest']}".encode("ascii"),
            )
        )

        negative_controls: list[dict[str, Any]] = []

        strict_copy = temporary_root / "strict-report-substitution"
        shutil.copytree(incumbent_path, strict_copy)
        shutil.copyfile(
            successor_path / "evidence" / "strict-validation.json",
            strict_copy / "evidence" / "strict-validation.json",
        )
        strict_state = temporary_root / "strict-report-state"
        completed = initialize_state(
            kernel,
            strict_state,
            incumbent["manifest_digest"],
            public_key_hex,
            operator_config,
            temporary_root,
        )
        successful_observation(
            "strict-report-state-init", completed, b"initialized operator capacity"
        )
        completed = run_kernel(
            kernel, ["admit", strict_copy, strict_state], temporary_root
        )
        negative_controls.append(
            failed_observation(
                "strict-report-substitution",
                completed,
                [b"evidence/strict-validation.json", b"digest"],
                "reject before admission",
                "temporary incumbent copy only; strict-validation bytes replaced by successor report bytes",
                "kernel rejected a strict-validation content-digest mismatch before root admission",
            )
        )

        wrong_key_hex = "00" * 32
        if wrong_key_hex == public_key_hex:
            wrong_key_hex = "01" * 32
        wrong_key_id = sha256_bytes(bytes.fromhex(wrong_key_hex))
        wrong_key_state = temporary_root / "wrong-key-state"
        completed = initialize_state(
            kernel,
            wrong_key_state,
            incumbent["manifest_digest"],
            wrong_key_hex,
            operator_config,
            temporary_root,
        )
        successful_observation(
            "wrong-key-state-init", completed, b"initialized operator capacity"
        )
        completed = run_kernel(
            kernel, ["admit", incumbent_path, wrong_key_state], temporary_root
        )
        negative_controls.append(
            failed_observation(
                "wrong-operator-public-key",
                completed,
                [b"signer does not match operator trust"],
                "reject signer before admission",
                "fresh temporary mechanism state pinned to a distinct deterministic public key",
                "kernel rejected the release signer against independently persisted operator trust",
                wrong_key_id=wrong_key_id,
            )
        )

        omission_copy = temporary_root / "raw-component-omission"
        shutil.copytree(incumbent_path, omission_copy)
        certificate, _ = load_json(
            incumbent_path / "certification" / "release-certification.json",
            CERTIFICATION_SCHEMA,
        )
        raw_artifacts = certificate["statement"].get("raw_artifacts")
        require(
            isinstance(raw_artifacts, dict) and raw_artifacts,
            "incumbent certificate has no raw artifact set",
        )
        omitted_node = sorted(raw_artifacts)[0]
        omitted_digest = require_digest(
            raw_artifacts[omitted_node], "omitted raw component"
        )
        omitted_file = (
            omission_copy / "components" / f"{digest_stem(omitted_digest)}.wasm"
        )
        require(
            omitted_file.is_file(),
            "selected raw component is absent before omission control",
        )
        omitted_file.unlink()
        omission_state = temporary_root / "raw-omission-state"
        completed = initialize_state(
            kernel,
            omission_state,
            incumbent["manifest_digest"],
            public_key_hex,
            operator_config,
            temporary_root,
        )
        successful_observation(
            "raw-omission-state-init", completed, b"initialized operator capacity"
        )
        completed = run_kernel(
            kernel, ["admit", omission_copy, omission_state], temporary_root
        )
        negative_controls.append(
            failed_observation(
                "raw-component-omission",
                completed,
                [b"persistence", b"No such file"],
                "reject incomplete closure before admission",
                "temporary incumbent copy only; one certificate-listed raw component removed",
                "kernel rejected the absent content-addressed source component before root admission",
                omitted_node=omitted_node,
                omitted_component_digest=omitted_digest,
            )
        )

        if incumbent["strict_report_schema"] == STRICT_REPORT_SCHEMA_V2:
            scoped_copy = temporary_root / "scoped-component-omission"
            shutil.copytree(incumbent_path, scoped_copy)
            scoped_components = incumbent["scoped_component_digests"]
            require(
                isinstance(scoped_components, dict) and bool(scoped_components),
                "R2 incumbent has no retained scoped component set",
            )
            scoped_consumer = sorted(scoped_components)[0]
            scoped_digest = scoped_components[scoped_consumer]
            scoped_file = (
                scoped_copy
                / "scoped-components"
                / f"{digest_stem(scoped_digest)}.wasm"
            )
            require(
                scoped_file.is_file(),
                "selected scoped component is absent before omission control",
            )
            scoped_file.unlink()
            scoped_state = temporary_root / "scoped-omission-state"
            completed = initialize_state(
                kernel,
                scoped_state,
                incumbent["manifest_digest"],
                public_key_hex,
                operator_config,
                temporary_root,
            )
            successful_observation(
                "scoped-omission-state-init",
                completed,
                b"initialized operator capacity",
            )
            completed = run_kernel(
                kernel, ["admit", scoped_copy, scoped_state], temporary_root
            )
            negative_controls.append(
                failed_observation(
                    "r2-scoped-component-omission",
                    completed,
                    [b"No such file"],
                    "reject incomplete per-consumer executable closure before admission",
                    "temporary incumbent copy only; one certificate-bound scoped component removed",
                    "kernel rejected the absent content-addressed per-consumer component before root admission",
                    omitted_consumer=scoped_consumer,
                    omitted_scoped_component_digest=scoped_digest,
                )
            )

        if incumbent["profile_schema"] == PROFILE_SCHEMA_V3:
            constraint_copy = temporary_root / "r3-http-constraint-omission"
            shutil.copytree(incumbent_path, constraint_copy)
            http_constraint_digest = incumbent["http_transport_constraint_digest"]
            require(
                isinstance(http_constraint_digest, str),
                "R3 incumbent has no exact HTTP constraint identity",
            )
            http_constraint_file = (
                constraint_copy
                / "constraints"
                / f"{digest_stem(http_constraint_digest)}.json"
            )
            require(
                http_constraint_file.is_file(),
                "selected R3 HTTP constraint is absent before omission control",
            )
            http_constraint_file.unlink()
            constraint_state = temporary_root / "r3-http-constraint-state"
            completed = initialize_state(
                kernel,
                constraint_state,
                incumbent["manifest_digest"],
                public_key_hex,
                operator_config,
                temporary_root,
            )
            successful_observation(
                "r3-http-constraint-state-init",
                completed,
                b"initialized operator capacity",
            )
            completed = run_kernel(
                kernel, ["admit", constraint_copy, constraint_state], temporary_root
            )
            negative_controls.append(
                failed_observation(
                    "r3-http-constraint-omission",
                    completed,
                    [b"No such file"],
                    "reject incomplete bounded-HTTP authority before admission",
                    "temporary incumbent copy only; the profile-bound HTTP constraint file was removed",
                    "kernel rejected the absent content-addressed HTTP constraint before root admission",
                    omitted_http_transport_constraint_digest=http_constraint_digest,
                )
            )

        certificate_copy = temporary_root / "certificate-substitution"
        shutil.copytree(incumbent_path, certificate_copy)
        successor_certificate = (
            successor_path / "certification" / "release-certification.json"
        )
        shutil.copyfile(
            successor_certificate,
            certificate_copy / "certification" / "release-certification.json",
        )
        substituted_digest = sha256_file(successor_certificate)
        substituted_index, _ = load_json(certificate_copy / "package.json")
        substituted_index["certification_digest"] = substituted_digest
        canonical_rewrite(certificate_copy / "package.json", substituted_index)
        substitution_state = temporary_root / "certificate-substitution-state"
        completed = initialize_state(
            kernel,
            substitution_state,
            incumbent["manifest_digest"],
            public_key_hex,
            operator_config,
            temporary_root,
        )
        successful_observation(
            "certificate-substitution-state-init",
            completed,
            b"initialized operator capacity",
        )
        completed = run_kernel(
            kernel, ["admit", certificate_copy, substitution_state], temporary_root
        )
        negative_controls.append(
            failed_observation(
                "valid-successor-certificate-substitution",
                completed,
                [b"does not exactly bind the admitted content set"],
                "reject a valid signature over a different manifest closure",
                "temporary incumbent copy only; successor certificate installed and only the convenience index certification digest updated",
                "kernel verified the signature but rejected its statement as a different content closure",
                substituted_certificate_digest=substituted_digest,
            )
        )

        tampered_state = temporary_root / "persisted-certificate-tamper-state"
        shutil.copytree(positive_state, tampered_state)
        certificate_blob = (
            tampered_state / "blobs" / incumbent["certification_digest"][7:]
        )
        require(
            certificate_blob.is_file(),
            "successful bootstrap did not persist the incumbent certificate blob",
        )
        corrupted = bytearray(certificate_blob.read_bytes())
        require(bool(corrupted), "persisted certificate blob is empty")
        corrupted[0] ^= 0x01
        certificate_blob.write_bytes(bytes(corrupted))
        completed = run_kernel(
            kernel, ["serve", incumbent_path, tampered_state], temporary_root
        )
        negative_controls.append(
            failed_observation(
                "restart-persisted-certificate-tamper",
                completed,
                [b"content-addressed bytes failed size or digest verification"],
                "restart must reconstruct and reject corrupted persisted certification content",
                "temporary copy of the successfully bootstrapped mechanism state only; one certificate-blob byte flipped under its original digest key",
                "kernel reconstructed from persistent state and rejected the corrupted certificate blob before serving",
            )
        )

    incumbent["admission_result"] = "pass"
    incumbent["signature_result"] = "pass"
    successor["admission_result"] = "pass"
    successor["signature_result"] = "pass"
    r2_principal_enforcement = (
        {
            "caller_identity_source": "validated-linker-alias-not-component-input",
            "graph_union_principal_absent": True,
            "incumbent_principal_inventory_digest": incumbent[
                "principal_inventory_digest"
            ],
            "independent_substrate_observed_exact_callers": True,
            "model": "per-consumer-import-alias",
            "production_linker_contexts_fixed": True,
            "successor_principal_inventory_digest": successor[
                "principal_inventory_digest"
            ],
            "result": "pass",
        }
        if candidate_schema == CANDIDATE_REPORT_SCHEMA_V3
        else None
    )
    r3_http_authority = (
        {
            "consumer": "exchange-service",
            "incumbent_binding_alias": incumbent["http_transport_binding_alias"],
            "incumbent_constraint_digest": incumbent[
                "http_transport_constraint_digest"
            ],
            "incumbent_profile_digest": incumbent["substrate_profile_digest"],
            "profile_schema": PROFILE_SCHEMA_V3,
            "result": "pass",
            "successor_binding_alias": successor["http_transport_binding_alias"],
            "successor_constraint_digest": successor[
                "http_transport_constraint_digest"
            ],
            "successor_profile_digest": successor["substrate_profile_digest"],
            "transport_constraint_schema": incumbent[
                "http_transport_constraint_schema"
            ],
        }
        if incumbent["profile_schema"] == PROFILE_SCHEMA_V3
        else None
    )
    return {
        "schema": report_contract["schema"],
        "generated_at": dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "outcome": "pass",
        "component_complete_claim": False,
        "claim_scope": report_contract["claim_scope"],
        "evidence_profile": report_contract["evidence_profile"],
        "kernel": {
            "binary_name": kernel.name,
            "sha256": sha256_file(kernel),
            "size_bytes": kernel.stat().st_size,
            "private_signing_key_read": False,
        },
        "certifier": {
            "algorithm": "ed25519",
            "public_key_hex": public_key_hex,
            "key_id": certifier_key_id,
            "public_key_identity_recomputed": True,
            "private_key_required_or_read": False,
        },
        "operator_capacity": {
            "digest": sha256_file(operator_config),
            "source_name": operator_config.name,
        },
        "packages": [incumbent, successor],
        "evidence_inputs": evidence_inputs,
        **(
            {"principal_enforcement": r2_principal_enforcement}
            if r2_principal_enforcement is not None
            else {}
        ),
        **(
            {"bounded_http_authority": r3_http_authority}
            if r3_http_authority is not None
            else {}
        ),
        "positive_execution": {
            "result": "pass",
            "commands": positive_commands,
            "incumbent_exact_admission": "pass",
            "successor_exact_admission": "pass",
            "incumbent_bootstrap_serve": "pass",
            "incumbent_persistent_reopen": "pass",
            "signature_and_exact_closure_reverified_after_reopen": True,
        },
        "negative_controls": negative_controls,
        "original_package_immutability": {
            "negative_controls_used_only_temporary_copies": True,
            "post_verification_tree_hashes_match_pre_verification": True,
        },
        "tree_digest_algorithm": (
            "For each regular file, compute lowercase SHA-256; emit "
            "'<digest><two spaces><relative-path><LF>' in bytewise-sorted UTF-8 relative-path "
            "order; SHA-256 the concatenated inventory."
        ),
    }


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--kernel", required=True, help="optimized wasm-biotic-kernel executable"
    )
    parser.add_argument(
        "--incumbent", required=True, help="exact signed incumbent package directory"
    )
    parser.add_argument(
        "--successor", required=True, help="exact signed successor package directory"
    )
    parser.add_argument(
        "--public-key-hex",
        required=True,
        help="lowercase raw Ed25519 public key (32 bytes)",
    )
    parser.add_argument(
        "--operator-config",
        required=True,
        help="canonical operator mechanism-capacity JSON",
    )
    parser.add_argument(
        "--independent-report",
        required=True,
        help="independent-substrate reproduction report",
    )
    parser.add_argument(
        "--candidate-shadow-report", required=True, help="candidate-graph shadow report"
    )
    parser.add_argument(
        "--native-build-attestation",
        required=True,
        help="detached native-build attestation",
    )
    parser.add_argument(
        "--out", required=True, help="canonical JSON report destination"
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        require(
            PUBLIC_KEY_PATTERN.fullmatch(arguments.public_key_hex) is not None,
            "--public-key-hex must be exactly 64 lowercase hexadecimal characters",
        )
        kernel = resolve_file(arguments.kernel, "kernel", executable=True)
        incumbent = resolve_directory(arguments.incumbent, "incumbent package")
        successor = resolve_directory(arguments.successor, "successor package")
        require(
            incumbent != successor,
            "incumbent and successor directories must be distinct",
        )
        operator_config = resolve_file(arguments.operator_config, "operator config")
        independent_report = resolve_file(
            arguments.independent_report, "independent report"
        )
        candidate_report = resolve_file(
            arguments.candidate_shadow_report, "candidate shadow report"
        )
        native_build = resolve_file(
            arguments.native_build_attestation, "native build attestation"
        )
        output = Path(arguments.out).expanduser().resolve(strict=False)
        require(
            not is_within(output, incumbent) and not is_within(output, successor),
            "--out must not be inside either immutable package directory",
        )

        before = {
            "incumbent": package_tree(incumbent),
            "successor": package_tree(successor),
        }
        campaign_error: Exception | None = None
        report: dict[str, Any] | None = None
        try:
            report = run_campaign(
                kernel,
                incumbent,
                successor,
                arguments.public_key_hex,
                operator_config,
                independent_report,
                candidate_report,
                native_build,
            )
        except (
            Exception
        ) as error:  # Recheck immutability before propagating any failure.
            campaign_error = error
        after = {
            "incumbent": package_tree(incumbent),
            "successor": package_tree(successor),
        }
        require(before == after, "an original package tree changed during the campaign")
        if campaign_error is not None:
            raise campaign_error
        require(report is not None, "campaign produced no report")
        report["original_package_immutability"]["pre_and_post"] = before

        output.parent.mkdir(parents=True, exist_ok=True)
        encoded = canonical_json_bytes(report)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{output.name}.", suffix=".tmp", dir=output.parent
        )
        temporary_output = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as destination:
                destination.write(encoded)
                destination.flush()
                os.fsync(destination.fileno())
            os.replace(temporary_output, output)
        finally:
            if temporary_output.exists():
                temporary_output.unlink()
        print(f"wrote {report['schema']} {sha256_bytes(encoded)} to {output}")
        return 0
    except (HarnessError, OSError, subprocess.SubprocessError) as error:
        print(f"signed-admission: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
