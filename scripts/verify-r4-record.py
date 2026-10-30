#!/usr/bin/env python3
"""Verify the small Git-resident index for the exact signed R4 release.

This deliberately verifies the retained compact record, not the detached
Ed25519 signatures or omitted large byte closure. Full release verification
must start from the independently held trust policy and complete custody tree.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any


ROOT = "sha256:659cdf6b1de2196a7f33fbd3cb55ed4dd7e7a8b514ce6970e1e392e6aabb8b12"
AGGREGATE = "sha256:60a8cd54195e479f766c03cf5ecae4418e1f20b7ba895727273e46862fa975ae"
SOURCE_SNAPSHOT = "sha256:db64731d0e461bf3e146e30702c45fff9547f3ba9fb89f73385b8b15471e2716"
MATRIX = "sha256:bddb4e8520d6d30b3757504337dace9f6cd43304142b1572de205c84f35649e8"
TARGETS = ["aarch64-apple-darwin", "x86_64-unknown-linux-gnu"]

EXPECTED = {
    "SOURCE-SNAPSHOT.json": SOURCE_SNAPSHOT,
    "aggregate.json": AGGREGATE,
    "governance-report.json": "sha256:e19747f3100b9d8c64ddf558b946454af292c34d81d8bf125b7682d0b18cfd25",
    "postpublication-lifecycle.json": "sha256:8b42a8a221e6ffd30bd6c949ae21d343fca9e39b1e757fa4c58b81240904565e",
    "postpublication-recovery.json": "sha256:08b7c9957ce51886c793ed623b7312e90834180b3ffeb1fc92fcd5426659aa2e",
    "prepublication-negatives.json": "sha256:b9ac7e3aae6232c535d85c7272252b5ce819ced4a0b5d01521f47852ba071b0b",
    "public-lifecycle.json": "sha256:273ad23971cd12fd9974698dd645eb63ddcfefb71b20149e21cf1c56d8f4cb4d",
    "publication-negatives.json": "sha256:1ef51f0a9234dcbc533b553c5d802d4d70803e01aa724b5db75ede68044b0a07",
    "r3-certifier-public-key.raw": "sha256:7bbbb6a94cb24edf5ccbaa34129598698deaf3aa5115130abb85602ab68f3014",
    "reproduction-matrix.json": MATRIX,
    "trust-policy.json": "sha256:f14378e9ec55233a0fe1519e566605f65be586479c97758724460a267680ed3f",
}


class RecordError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RecordError(message)


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def load_canonical(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RecordError(f"{path.name} is not valid JSON: {error}") from error
    require(isinstance(value, dict), f"{path.name} is not a JSON object")
    require(canonical_json(value) == data, f"{path.name} is not canonical JSON")
    return value


def verify(record: Path, repository: Path) -> None:
    require(not record.is_symlink() and record.is_dir(), "compact record directory is absent or linked")
    entries = list(record.iterdir())
    require(
        all(not path.is_symlink() and path.is_file() for path in entries),
        "compact record contains a linked or non-file entry",
    )
    actual_names = {path.name for path in entries}
    expected_names = set(EXPECTED) | {"README.md"}
    require(actual_names == expected_names, "compact record file set differs")

    for name, expected in EXPECTED.items():
        path = record / name
        require(not path.is_symlink(), f"{name} must not be a link")
        require(digest(path.read_bytes()) == expected, f"{name} digest differs")

    for name in EXPECTED:
        if name.endswith(".json"):
            load_canonical(record / name)

    aggregate = load_canonical(record / "aggregate.json")
    require(aggregate.get("schema") == "wasm-biotic.r4-release-aggregate.v1", "aggregate schema differs")
    require(aggregate.get("publication_root") == ROOT, "aggregate publication root differs")
    require(aggregate.get("matrix_sha256") == MATRIX, "aggregate matrix binding differs")
    require(aggregate.get("result") == "pass" and aggregate.get("blockers") == [], "aggregate is not closed")
    require(aggregate.get("component_complete_claim") is True, "bounded component-complete claim is absent")
    require(aggregate.get("external_north_star_claim") is False, "external North Star boundary differs")
    require(aggregate.get("private_key_dependency") is False, "aggregate declares a private-key dependency")
    require(aggregate.get("targets") == TARGETS, "aggregate target set differs")
    gates = aggregate.get("gates")
    require(isinstance(gates, list) and len(gates) == 8, "aggregate gate set differs")
    require(
        [(gate.get("gate"), gate.get("result")) for gate in gates]
        == [(f"R4-C{index}", "pass") for index in range(8)],
        "aggregate gates are not the exact passing R4-C0 through R4-C7 sequence",
    )

    matrix = load_canonical(record / "reproduction-matrix.json")
    require(matrix.get("schema") == "wasm-biotic.r4-reproduction-matrix.v1", "matrix schema differs")
    require(matrix.get("result") == "pass" and matrix.get("blockers") == [], "matrix is not closed")
    require(matrix.get("component_complete_claim") is True, "matrix component-complete claim differs")
    require(matrix.get("external_north_star_claim") is False, "matrix North Star boundary differs")
    require(matrix.get("private_key_dependency") is False, "matrix declares a private-key dependency")
    require(matrix.get("targets") == TARGETS, "matrix target set differs")
    snapshot = matrix.get("source_snapshot")
    require(isinstance(snapshot, dict), "matrix source snapshot is absent")
    require(snapshot.get("manifest_sha256") == SOURCE_SNAPSHOT, "matrix source snapshot differs")
    require(snapshot.get("source_file_count") == 325, "matrix source file count differs")
    require(snapshot.get("vendor_file_count") == 25_441, "matrix vendor file count differs")
    require(
        snapshot.get("vendor_closure_sha256")
        == "sha256:5d8b016343d75fc42088cca3fa5ac7b26f9ee85b27e049dcaaf72ed3f7789bc9",
        "matrix vendor closure differs",
    )
    components = matrix.get("components")
    require(isinstance(components, dict) and components.get("component_count") == 22, "component count differs")

    repository_snapshot = repository / "SOURCE-SNAPSHOT.json"
    require(repository_snapshot.is_file(), "repository SOURCE-SNAPSHOT.json is absent")
    require(repository_snapshot.read_bytes() == (record / "SOURCE-SNAPSHOT.json").read_bytes(), "repository source snapshot differs from compact record")


def main() -> int:
    repository = Path(__file__).resolve().parents[1]
    default_record = repository / "artifacts" / "component-complete" / "r4-releases" / ROOT.replace(":", "-")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record", type=Path, default=default_record)
    options = parser.parse_args()
    try:
        verify(options.record, repository)
    except (OSError, RecordError) as error:
        print(f"verify-r4-record: {error}", file=sys.stderr)
        return 1
    print(f"verified compact R4 record aggregate={AGGREGATE} root={ROOT}")
    print("full signature and byte-closure verification still requires the external custody tree")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
