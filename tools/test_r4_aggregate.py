#!/usr/bin/env python3
"""Focused two-stage R4 reproduction-matrix and aggregate tests."""

from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
import unittest
from unittest import mock

from tools import test_r4_publication as publication_fixture


TOOL = Path(__file__).with_name("r4-aggregate.py")
SPEC = importlib.util.spec_from_file_location("r4_aggregate", TOOL)
if SPEC is None or SPEC.loader is None:  # pragma: no cover
    raise RuntimeError(f"cannot import {TOOL}")
AGGREGATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AGGREGATE)
PUBLICATION = AGGREGATE.PUBLICATION


class R4AggregateTests(unittest.TestCase):
    """R4 closes only after exact pre- and post-publication evidence joins."""

    @classmethod
    def setUpClass(cls) -> None:
        publication_fixture.R4PublicationTests.setUpClass()

    @classmethod
    def tearDownClass(cls) -> None:
        publication_fixture.R4PublicationTests.tearDownClass()

    def setUp(self) -> None:
        self._negative_verify = mock.patch.object(
            AGGREGATE.PREPUBLICATION_NEGATIVES,
            "verify_report",
            side_effect=lambda _spec, report: AGGREGATE.read_canonical(
                report, "fixture pre-publication negative report"
            )[0],
        )
        self._negative_verify.start()
        self._component_bundle_verifier = mock.patch.object(
            PUBLICATION.COMPONENT_RELEASE,
            "verify_bundle",
            side_effect=lambda root, _key, require_root_name=False: (
                PUBLICATION.digest_bytes((root / "release.json").read_bytes())
            ),
        )
        self._component_bundle_verifier.start()
        self.fixture = publication_fixture.R4PublicationTests(
            methodName="test_prepare_assemble_and_independently_verify"
        )
        self.fixture.setUp()
        self.context = self.build_evidence()

    def tearDown(self) -> None:
        self.fixture.tearDown()
        self._component_bundle_verifier.stop()
        self._negative_verify.stop()

    def role_path(self, role: str, target: str | None = None) -> Path:
        item = next(
            value
            for value in self.fixture.objects
            if value["role"] == role and value.get("target") == target
        )
        return Path(item["path"])

    def write_json(self, name: str, value: object) -> Path:
        return self.fixture.write_input(name, AGGREGATE.canonical_json(value))

    def source_snapshot(self) -> tuple[Path, Path]:
        source_tool = AGGREGATE.SOURCE_SNAPSHOT
        self.source_snapshot_root = self.fixture.root / "source-snapshot-full"
        files = {
            ".cargo/config.toml": source_tool.CONFIG_BYTES,
            "Cargo.lock": b"version = 4\n",
            "Cargo.toml": b'[package]\nname="r4-fixture"\nversion="0.1.0"\n',
            "README.md": b"# R4 fixture\n",
            "components/factory.rs": b"pub fn factory() {}\n",
            "contracts/component-complete/BOUNDARY.md": b"component boundary\n",
            "kernel/kernel.rs": b"pub fn kernel() {}\n",
            "src/lib.rs": b"pub fn release_tool() {}\n",
            "tools/release.py": b"print('release')\n",
            "tools/r4-path-alias.c": Path(__file__)
            .with_name("r4-path-alias.c")
            .read_bytes(),
            "tools/r4-path-alias-launch.c": Path(__file__)
            .with_name("r4-path-alias-launch.c")
            .read_bytes(),
            "vendor/example-1.0.0/src/lib.rs": b"pub fn dependency() {}\n",
            "wit/wasm-biotic/factory.wit": b"package wasm-biotic:factory;\n",
        }
        for relative in source_tool.FROZEN_EMBEDDED_BUILD_INPUTS:
            files[relative] = f"fixture: {relative}\n".encode("utf-8")
        for relative, data in files.items():
            path = self.source_snapshot_root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(0o644)
        source_items = []
        for path in sorted(self.source_snapshot_root.rglob("*")):
            relative = path.relative_to(self.source_snapshot_root).as_posix()
            if (
                not path.is_file()
                or relative == ".cargo/config.toml"
                or relative.startswith("vendor/")
            ):
                continue
            source_items.append(
                {
                    "mode": "0644",
                    "path": relative,
                    "sha256": source_tool.digest_file(path),
                    "size_bytes": path.stat().st_size,
                }
            )
        vendor_items = source_tool.actual_inventory(self.source_snapshot_root, "vendor")
        snapshot = source_tool.snapshot_manifest(
            source_items,
            vendor_items,
            {
                "cargo": ["cargo test"],
                "rustc": ["rustc test"],
                "wasm_target": "wasm32-wasip2",
                "wasm_tools": "wasm-tools test",
            },
        )
        snapshot_path = self.source_snapshot_root / "SOURCE-SNAPSHOT.json"
        snapshot_path.write_bytes(source_tool.canonical_json(snapshot))
        source_tool.verify_snapshot(self.source_snapshot_root)
        archive_path, _ = self.fixture.write_archive(
            "source-archive-full",
            {
                path.relative_to(
                    self.source_snapshot_root
                ).as_posix(): path.read_bytes()
                for path in self.source_snapshot_root.rglob("*")
                if path.is_file()
            },
        )
        return snapshot_path, archive_path

    def component_report(
        self, witness: str, snapshot_digest: str, *, changed: bool = False
    ) -> dict[str, object]:
        components = [
            {
                "node": node,
                "published_sha256": AGGREGATE.digest_bytes(
                    f"fixture component {node}\n".encode("utf-8")
                ),
                "rebuilt_sha256": (
                    "sha256:" + "ee" * 32
                    if changed and index == 0
                    else AGGREGATE.digest_bytes(
                        f"fixture component {node}\n".encode("utf-8")
                    )
                ),
                "size_bytes": len(f"fixture component {node}\n".encode("utf-8")),
            }
            for index, node in enumerate(
                sorted(PUBLICATION.COMPONENT_REPRODUCTION.EXPECTED_NODES)
            )
        ]
        alias_profile = PUBLICATION.COMPONENT_REPRODUCTION.sandbox_profile(
            self.source_snapshot_root.resolve()
        )
        operator_path_alias = {
            "artifacts": {
                "dylib": {
                    "sha256": "sha256:" + "45" * 32,
                    "size_bytes": 4096,
                },
                "launcher": {
                    "sha256": "sha256:" + "46" * 32,
                    "size_bytes": 8192,
                },
            },
            "build_recipe": {
                "dylib": [
                    "xcrun",
                    "clang",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-O2",
                    "-dynamiclib",
                    "-o",
                    "r4-path-alias.dylib",
                    "tools/r4-path-alias.c",
                ],
                "launcher": [
                    "xcrun",
                    "clang",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-O2",
                    "-o",
                    "r4-path-alias-launch",
                    "tools/r4-path-alias-launch.c",
                ],
            },
            "compiler": ["Apple clang version fixture"],
            "compiler_executable": "/usr/bin/clang",
            "dyld_injected_after_sandbox_activation": True,
            "physical_source_root": str(self.source_snapshot_root.resolve()),
            "read_fallback_to_historical_checkout_denied": True,
            "read_only_mapping": True,
            "sandbox_profile": alias_profile,
            "sandbox_profile_sha256": AGGREGATE.digest_bytes(
                alias_profile.encode("utf-8")
            ),
            "schema": PUBLICATION.COMPONENT_REPRODUCTION.PATH_ALIAS_SCHEMA,
            "sources": {
                relative: AGGREGATE.digest_bytes(
                    (self.source_snapshot_root / relative).read_bytes()
                )
                for relative in (
                    "tools/r4-path-alias.c",
                    "tools/r4-path-alias-launch.c",
                )
            },
            "virtual_source_root": PUBLICATION.COMPONENT_REPRODUCTION.FROZEN_SOURCE_ROOT,
        }
        return {
            "build": {
                "builder": {
                    "cargo": ["cargo test"],
                    "cargo_executable": "/tmp/wasmbiotic-cargo/bin/cargo",
                    "host": "aarch64-apple-darwin",
                    "rustc": ["rustc test"],
                    "rustc_executable": "/tmp/wasmbiotic-cargo/bin/rustc",
                    "wasm_target_libdir": "/tmp/wasmbiotic-rustup/toolchains/test/lib/rustlib/wasm32-wasip2/lib",
                },
                "cargo": ["cargo test"],
                "frozen_read_only_path_projection": True,
                "fresh_target_directory": True,
                "incremental": False,
                "network_disabled": True,
                "offline": True,
                "operator_path_alias": operator_path_alias,
                "registry_projection": PUBLICATION.COMPONENT_REPRODUCTION.R3_VENDOR_LOGICAL_PREFIX,
                "rustc": ["rustc test"],
                "source_projection": PUBLICATION.COMPONENT_REPRODUCTION.FROZEN_SOURCE_ROOT,
                "target": "wasm32-wasip2",
                "target_scoped_path_remapping": False,
                "verified_projection": {
                    "cargo_registry_package_count": 1,
                    "cargo_registry_projection_sha256": "sha256:" + "47" * 32,
                    "source_file_count": 1,
                    "source_projection_sha256": "sha256:" + "48" * 32,
                },
            },
            "component_count": 22,
            "component_set_sha256": AGGREGATE._component_set_digest(components),
            "components": components,
            "generated_at": "1970-01-01T00:00:00Z",
            "graph_manifest_digest": self.fixture.incumbent_graph_digest,
            "host": {
                "architecture": "arm64",
                "operating_system": "Darwin",
                "physical_machine": True,
                "release": "26",
                "witness_id": witness,
            },
            "package_authentication": {
                "certification_sha256": self.fixture.incumbent_certification_digest,
                "certifier_key_id": self.release_certifier_key_id,
                "signature_verified": True,
            },
            "private_key_accepted_or_read": False,
            "published_raw_components_reproduced_byte_for_byte": True,
            "result": "pass",
            "schema": AGGREGATE.COMPONENT_REPRODUCTION_SCHEMA,
            "source_snapshot_manifest_sha256": snapshot_digest,
        }

    def component_lifecycle(
        self, incumbent: str, successor: str
    ) -> dict[str, object]:
        def sha(value: str) -> dict[str, str]:
            return {"algorithm": "sha256", "hex": value[7:]}

        def cycle(graph: str, marker: str) -> dict[str, object]:
            return {
                "exact_replay": {
                    "inspect_blob_equal": True,
                    "inspect_bytes_equal": True,
                    "job_id_equal": True,
                    "mechanism_counters_after": {"transactions": 1},
                    "mechanism_counters_before": {"transactions": 1},
                    "mechanism_counters_unchanged": True,
                    "mechanism_state_digest_after": marker,
                    "mechanism_state_digest_before": marker,
                    "mechanism_state_unchanged": True,
                    "output_blob_equal": True,
                    "output_bytes_equal": True,
                    "resubmitted_exact_submit_blob": True,
                },
                "execution_completions": {
                    name: {}
                    for name in (
                        "builder",
                        "continuity-worker",
                        "packager",
                        "planner",
                        "reviewer",
                        "validator",
                    )
                },
                "graph_manifest_digest": graph,
                "terminal_result": {"failure": None, "status": "completed"},
            }

        return {
            "build_performed": False,
            "certifier_key_id": self.release_certifier_key_id,
            "component_complete_claim": False,
            "inactive_successor_admission": {
                "active_manifest_after_admission": incumbent,
                "active_manifest_before_admission": incumbent,
                "active_manifest_unchanged": True,
                "admitted_successor_manifest_digest": successor,
            },
            "incumbent": {
                "graph_manifest_digest": incumbent,
                "previous_graph_manifest_digest": None,
                "signature_and_exact_closure_verified_by_production_admission": True,
            },
            "lifecycle": {
                "all_factory_semantics_executed_as_components": True,
                "component_decided_initial_state_binding": True,
                "component_decided_rollback": True,
                "component_decided_successor_activation": True,
                "graph_qualified_activation_ownership_handoff_verified": True,
                "incumbent_cycle": cycle(incumbent, "sha256:" + "81" * 32),
                "incumbent_graph_manifest_digest": incumbent,
                "native_substrate_responsibility": (
                    "verified admission, instantiation, metering, opaque persistence, "
                    "communication and declared-capability enforcement only"
                ),
                "post_rollback_cycle": cycle(incumbent, "sha256:" + "82" * 32),
                "principal_mapping_stable_across_restart_activation_and_rollback": True,
                "restart_preserved_rollback_pair": True,
                "rollback_observation_result": {
                    "action": "rolled-back",
                    "observed_graph": sha(successor),
                    "status": {
                        "active_graph": sha(incumbent),
                        "state": "rolled-back",
                    },
                },
                "successor_cycle": cycle(successor, "sha256:" + "83" * 32),
                "successor_graph_manifest_digest": successor,
                "upgrade_result": {
                    "committed": {"active_graph": sha(successor)},
                    "previous_graph": sha(incumbent),
                    "target_graph": sha(successor),
                },
            },
            "outcome": "pass",
            "operator_capacity_sha256": "sha256:" + "74" * 32,
            "private_signing_key_required_or_read": False,
            "public_key_hex": self.release_public_key.hex(),
            "schema": AGGREGATE.PUBLIC_INSTALL.LIFECYCLE_SCHEMA,
            "signing_performed": False,
            "state": {
                "final_active_manifest_digest": incumbent,
                "fresh_state_directory_required": True,
                "incumbent_bootstrap_manifest_digest": incumbent,
                "restart_reopened_persisted_state": True,
            },
            "successor": {
                "graph_manifest_digest": successor,
                "previous_graph_manifest_digest": incumbent,
                "signature_and_exact_closure_verified_by_production_admission": True,
            },
        }

    def full_native_report(
        self, target: str, binary: bytes, snapshot_digest: str, witness_id: str
    ) -> dict[str, object]:
        report = self.fixture.native_report(target, binary, witness_id=witness_id)
        report["build_recipe"] = {"sha256": "sha256:" + "61" * 32}
        report["reference_digest_verification"] = {"match": True}
        report["source"]["snapshot_manifest"] = {
            "schema": AGGREGATE.SOURCE_SNAPSHOT_SCHEMA,
            "sha256": snapshot_digest,
        }
        report["toolchain"] = {"rustc": {"version": "test"}}
        return report

    def prepublication_negatives(self, inputs: dict[str, object]) -> dict[str, object]:
        def controls(names: frozenset[str]) -> dict[str, object]:
            return {
                name: {
                    "attack_sha256": AGGREGATE.digest_bytes(
                        AGGREGATE.canonical_json({"attack": name})
                    ),
                    "rejection_sha256": AGGREGATE.digest_bytes(
                        AGGREGATE.canonical_json({"rejection": name})
                    ),
                    "result": "pass",
                }
                for name in names
            }

        archive_controls = controls(AGGREGATE.ARCHIVE_NEGATIVES)
        governance_controls = controls(AGGREGATE.GOVERNANCE_NEGATIVES)
        lifecycle_controls = controls(AGGREGATE.LIFECYCLE_NEGATIVES)
        sbom_controls = controls(AGGREGATE.SBOM_NEGATIVES)
        tool_sources = AGGREGATE.PREPUBLICATION_NEGATIVES.tool_sources()
        closure_value = {
            "controls": {
                "archives": archive_controls,
                "governance": governance_controls,
                "public_lifecycle": lifecycle_controls,
                "sbom": sbom_controls,
            },
            "inputs": inputs,
            "tool_sources": tool_sources,
        }
        return {
            "archives": archive_controls,
            "blockers": [],
            "evidence_closure_sha256": AGGREGATE.digest_bytes(
                AGGREGATE.canonical_json(closure_value)
            ),
            "governance": governance_controls,
            "inputs": inputs,
            "private_key_dependency": False,
            "public_lifecycle": lifecycle_controls,
            "result": "pass",
            "sbom": sbom_controls,
            "schema": AGGREGATE.PREPUBLICATION_NEGATIVE_SCHEMA,
            "tool_sources": tool_sources,
        }

    def publication_negatives(self, root: str) -> dict[str, object]:
        return {
            "blockers": [],
            "controls": {key: True for key in AGGREGATE.PUBLICATION_NEGATIVES},
            "pristine_verified_after_mutations": True,
            "pristine_verified_before_mutations": True,
            "private_key_dependency": False,
            "publication_root": root,
            "result": "pass",
            "schema": AGGREGATE.PUBLICATION_NEGATIVE_SCHEMA,
        }

    def build_evidence(self) -> dict[str, object]:
        snapshot_path, source_archive = self.source_snapshot()
        snapshot_digest = AGGREGATE.digest_bytes(snapshot_path.read_bytes())
        self.release_public_key = self.fixture.release_public_key
        self.release_certifier_key_id = self.fixture.release_certifier_key_id
        release_public_key_path = self.fixture.release_public_key_path
        component_paths = [
            self.write_json(
                f"component-witness-{index}.json",
                self.component_report(f"physical-component-{index}", snapshot_digest),
            )
            for index in (1, 2)
        ]

        native_paths: dict[str, list[Path]] = {}
        for target in AGGREGATE.CLOSED_TARGETS:
            binary_path = self.role_path("native-executable", target)
            count = 2 if target == AGGREGATE.MACOS_TARGET else 1
            native_paths[target] = [
                self.write_json(
                    f"full-native-{target}-{index}.json",
                    self.full_native_report(
                        target,
                        binary_path.read_bytes(),
                        snapshot_digest,
                        f"physical-{target}-{index}",
                    ),
                )
                for index in range(1, count + 1)
            ]

        install_archive = self.role_path("install-archive")
        component_archive = self.role_path("component-release-archive")
        sbom_artifacts = {
            "component-release-archive": component_archive,
            "install-archive": install_archive,
            "native-executable-aarch64-apple-darwin": self.role_path(
                "native-executable", AGGREGATE.MACOS_TARGET
            ),
            "native-executable-x86_64-unknown-linux-gnu": self.role_path(
                "native-executable", AGGREGATE.LINUX_TARGET
            ),
            "source-archive": source_archive,
        }
        system_values = [
            f"{AGGREGATE.MACOS_TARGET}|libSystem|1",
            f"{AGGREGATE.LINUX_TARGET}|glibc|2",
        ]
        sbom, coverage = AGGREGATE.SBOM_TOOL.build_documents(
            self.source_snapshot_root,
            sorted(sbom_artifacts.items()),
            system_values,
            0,
        )
        sbom_path = self.write_json("aggregate-sbom.json", sbom)
        coverage_path = self.write_json("aggregate-sbom-coverage.json", coverage)

        install_digest, _, _ = AGGREGATE.ARCHIVE.verify_archive(install_archive)
        mac_binary = self.role_path("native-executable", AGGREGATE.MACOS_TARGET)
        mac_digest = AGGREGATE.digest_bytes(mac_binary.read_bytes())
        incumbent_digest = self.fixture.incumbent_graph_digest
        successor_digest = self.fixture.successor_graph_digest
        component_lifecycle = self.component_lifecycle(
            incumbent_digest, successor_digest
        )
        lifecycle = {
            "archive": {
                "entry_count": 1,
                "extracted_tree_exactly_matches_manifest": True,
                "install_archive_sha256": install_digest,
                "safe_archive_verifier_passed": True,
            },
            "commands": [
                {"label": label} for label in sorted(AGGREGATE.LIFECYCLE_COMMANDS)
            ],
            "component_lifecycle_report": component_lifecycle,
            "component_lifecycle_report_sha256": AGGREGATE.digest_bytes(
                AGGREGATE.canonical_json(component_lifecycle)
            ),
            "generated_at": "1970-01-01T00:00:00Z",
            "host": {
                "architecture": "aarch64",
                "operating_system": "Darwin",
                "physical_machine": True,
                "release": "26",
                "target": AGGREGATE.MACOS_TARGET,
                "witness_id": "physical-lifecycle-1",
            },
            "inactive_admission": {
                "active_mechanism_state_after_sha256": "sha256:" + "73" * 32,
                "active_mechanism_state_before_sha256": "sha256:" + "73" * 32,
                "incumbent_remained_bootable": True,
                "successor_serve_rejected_before_component_activation": True,
            },
            "incumbent_graph_manifest_digest": incumbent_digest,
            "kernel": {"expected_sha256": mac_digest, "observed_sha256": mac_digest},
            "negative_controls": {
                "automatic_successor_activation_rejected": True,
                "tampered_package_rejected": True,
                "wrong_public_key_rejected": True,
            },
            "operator_capacity": {
                "observed_sha256": "sha256:" + "74" * 32,
                "within_verified_install": True,
            },
            "outcome": "pass",
            "private_key_argument_supported": False,
            "private_key_required_or_read": False,
            "schema": AGGREGATE.PUBLIC_LIFECYCLE_SCHEMA,
            "successor_graph_manifest_digest": successor_digest,
        }
        lifecycle_path = self.write_json("aggregate-lifecycle.json", lifecycle)
        governance_path = self.role_path("governance-report")
        governance_report, _ = AGGREGATE.read_canonical(
            governance_path, "governance report"
        )
        ceremony_result = AGGREGATE.CEREMONY.verify_ceremony(
            self.fixture.governance_ceremony
        )
        negative_inputs = {
            "archives": {
                role: {
                    "sha256": AGGREGATE.ARCHIVE.verify_archive(path)[0]
                }
                for role, path in {
                    "component-release-archive": component_archive,
                    "install-archive": install_archive,
                    "source-archive": source_archive,
                }.items()
            },
            "governance": {
                "ceremony_manifest_sha256": ceremony_result["ceremony_sha256"],
                "governance_report_sha256": AGGREGATE.digest_bytes(
                    AGGREGATE.canonical_json(governance_report)
                ),
                "policy_digest": ceremony_result["policy_digest"],
            },
            "public_lifecycle": {
                "incumbent_manifest_sha256": incumbent_digest,
                "install_archive_sha256": install_digest,
                "kernel_sha256": mac_digest,
                "operator_capacity_sha256": "sha256:" + "74" * 32,
                "parser_option_inventory_sha256": "sha256:" + "77" * 32,
                "release_certifier_key_id": self.release_certifier_key_id,
                "successor_manifest_sha256": successor_digest,
                "target": AGGREGATE.MACOS_TARGET,
            },
            "sbom": {
                "artifact_inventory": [],
                "coverage_sha256": AGGREGATE.digest_bytes(
                    AGGREGATE.canonical_json(coverage)
                ),
                "spdx_sha256": AGGREGATE.digest_bytes(
                    AGGREGATE.canonical_json(sbom)
                ),
                "system_packages": system_values,
            },
        }
        negatives_path = self.write_json(
            "prepublication-negatives.json",
            self.prepublication_negatives(negative_inputs),
        )
        negatives_spec_path = self.write_json(
            "prepublication-negative-input.json",
            {"schema": AGGREGATE.PREPUBLICATION_NEGATIVES.INPUT_SCHEMA},
        )
        contract_path = (
            Path(__file__).resolve().parents[1]
            / "contracts/component-complete/R4_RELEASE.md"
        )
        spec = {
            "archives": {
                "component-release-archive": str(component_archive),
                "install-archive": str(install_archive),
                "source-archive": str(source_archive),
            },
            "blockers": [],
            "component_witnesses": [str(path) for path in component_paths],
            "contract": str(contract_path),
            "governance_report": str(governance_path),
            "governance_ceremony": str(self.fixture.governance_ceremony),
            "native_witnesses": [
                {
                    "path": str(path),
                    "target": target,
                    "witness_id": f"physical-{target}-{index}",
                }
                for target in AGGREGATE.CLOSED_TARGETS
                for index, path in enumerate(native_paths[target], 1)
            ],
            "negative_controls": str(negatives_path),
            "negative_controls_spec": str(negatives_spec_path),
            "public_lifecycle_report": str(lifecycle_path),
            "release_public_key": str(release_public_key_path),
            "sbom": str(sbom_path),
            "sbom_artifacts": {
                role: str(path) for role, path in sbom_artifacts.items()
            },
            "sbom_coverage": str(coverage_path),
            "schema": AGGREGATE.MATRIX_INPUT_SCHEMA,
            "source_snapshot": str(snapshot_path),
        }
        spec_path = self.write_json("matrix-spec.json", spec)
        matrix = AGGREGATE.build_matrix(spec_path)
        matrix_path = self.write_json("reproduction-matrix-full.json", matrix)

        publication_objects = copy.deepcopy(self.fixture.objects)
        replacements = {
            "public-lifecycle-report": lifecycle_path,
            "reproduction-matrix": matrix_path,
            "sbom-coverage": coverage_path,
            "source-archive": source_archive,
            "spdx-sbom": sbom_path,
        }
        for item in publication_objects:
            role = item["role"]
            if role in replacements:
                item["path"] = str(replacements[role])
            if role == "native-attestation":
                item["path"] = str(native_paths[item["target"]][0])
        publication_objects.sort(key=PUBLICATION.object_identity)
        self.fixture.objects = publication_objects
        self.fixture.write_spec(publication_objects)
        staging = self.fixture.prepare()
        publication = PUBLICATION.assemble(
            staging,
            self.fixture.policy_path,
            release_public_key_path,
            self.fixture.signatures(staging, (0, 1)),
            self.fixture.root / "aggregate-publication",
        )
        publication_report = PUBLICATION.verify(
            publication, self.fixture.policy_path, release_public_key_path
        )
        publication_negatives_path = self.write_json(
            "publication-negatives.json",
            self.publication_negatives(publication_report["publication_root"]),
        )
        postpublication_lifecycle = copy.deepcopy(lifecycle)
        postpublication_lifecycle["generated_at"] = "1970-01-01T00:00:01Z"
        postpublication_lifecycle["host"]["witness_id"] = (
            "physical-postpublication-lifecycle-1"
        )
        postpublication_lifecycle_path = self.write_json(
            "postpublication-lifecycle.json", postpublication_lifecycle
        )
        postpublication_recovery = {
            "blockers": [],
            "independent_policy_sha256": AGGREGATE.digest_bytes(
                self.fixture.policy_path.read_bytes()
            ),
            "lifecycle": {
                "fresh_mechanism_state": True,
                "operator_capacity_sha256": "sha256:" + "74" * 32,
                "outcome": "pass",
                "private_key_argument_supported": False,
                "private_key_required_or_read": False,
                "report_sha256": AGGREGATE.digest_bytes(
                    postpublication_lifecycle_path.read_bytes()
                ),
            },
            "phase": "post-publication",
            "private_key_dependency": False,
            "publication": {
                "publication_root": publication_report["publication_root"],
                "verified_before_recovery": True,
            },
            "result": "pass",
            "schema": AGGREGATE.POSTPUBLICATION_RECOVERY_SCHEMA,
            "targets": list(AGGREGATE.CLOSED_TARGETS),
        }
        postpublication_recovery_path = self.write_json(
            "postpublication-recovery.json", postpublication_recovery
        )
        return {
            "aggregate_path": self.fixture.root / "R4-AGGREGATE.json",
            "component_paths": component_paths,
            "matrix": matrix,
            "matrix_path": matrix_path,
            "native_paths": native_paths,
            "policy_path": self.fixture.policy_path,
            "postpublication_lifecycle_path": postpublication_lifecycle_path,
            "postpublication_recovery_path": postpublication_recovery_path,
            "publication": publication,
            "publication_negatives_path": publication_negatives_path,
            "release_public_key_path": release_public_key_path,
            "spec": spec,
            "spec_path": spec_path,
        }

    def assert_aggregate_error(self, pattern: str):
        return self.assertRaisesRegex(AGGREGATE.AggregateError, pattern)

    def test_matrix_and_post_publication_aggregate_close_c0_through_c7(self) -> None:
        rebuilt_matrix = AGGREGATE.build_matrix(self.context["spec_path"])
        self.assertEqual(
            AGGREGATE.canonical_json(rebuilt_matrix),
            self.context["matrix_path"].read_bytes(),
        )
        self.assertEqual(
            AGGREGATE.main(
                [
                    "verify-matrix",
                    "--spec",
                    str(self.context["spec_path"]),
                    "--matrix",
                    str(self.context["matrix_path"]),
                ]
            ),
            0,
        )
        aggregate = AGGREGATE.build_aggregate(
            self.context["matrix_path"],
            self.context["publication"],
            self.context["policy_path"],
            self.context["release_public_key_path"],
            self.context["publication_negatives_path"],
            self.context["postpublication_recovery_path"],
            self.context["postpublication_lifecycle_path"],
        )
        self.assertTrue(aggregate["component_complete_claim"])
        self.assertFalse(aggregate["external_north_star_claim"])
        self.assertFalse(aggregate["private_key_dependency"])
        self.assertEqual(aggregate["blockers"], [])
        self.assertEqual(
            [item["gate"] for item in aggregate["gates"]],
            [f"R4-C{index}" for index in range(8)],
        )
        self.assertTrue(all(item["result"] == "pass" for item in aggregate["gates"]))
        self.assertEqual(
            aggregate["publication_root"],
            PUBLICATION.verify(
                self.context["publication"],
                self.context["policy_path"],
                self.context["release_public_key_path"],
            )["publication_root"],
        )
        AGGREGATE.write_atomic(self.context["aggregate_path"], aggregate)
        self.assertEqual(
            AGGREGATE.main(
                [
                    "verify",
                    "--matrix",
                    str(self.context["matrix_path"]),
                    "--publication",
                    str(self.context["publication"]),
                    "--policy",
                    str(self.context["policy_path"]),
                    "--release-public-key",
                    str(self.context["release_public_key_path"]),
                    "--publication-negatives",
                    str(self.context["publication_negatives_path"]),
                    "--postpublication-recovery",
                    str(self.context["postpublication_recovery_path"]),
                    "--postpublication-lifecycle",
                    str(self.context["postpublication_lifecycle_path"]),
                    "--aggregate",
                    str(self.context["aggregate_path"]),
                ]
            ),
            0,
        )

    def test_component_witness_count_and_set_mismatch_fail(self) -> None:
        spec = copy.deepcopy(self.context["spec"])
        spec["component_witnesses"] = spec["component_witnesses"][:1]
        path = self.write_json("one-component-witness.json", spec)
        with self.subTest("count"), self.assert_aggregate_error("at least two"):
            AGGREGATE.build_matrix(path)

        report_path = Path(self.context["component_paths"][1])
        original = report_path.read_bytes()
        report = AGGREGATE.parse_canonical_object(original, "component report")
        report["build"]["network_disabled"] = False
        report_path.write_bytes(AGGREGATE.canonical_json(report))
        with (
            self.subTest("sandbox"),
            self.assert_aggregate_error("frozen offline read-only projection"),
        ):
            AGGREGATE.build_matrix(self.context["spec_path"])

        report = AGGREGATE.parse_canonical_object(original, "component report")
        report["build"]["operator_path_alias"][
            "read_fallback_to_historical_checkout_denied"
        ] = False
        report_path.write_bytes(AGGREGATE.canonical_json(report))
        with (
            self.subTest("operator alias fallback"),
            self.assert_aggregate_error("sandbox/fallback evidence"),
        ):
            AGGREGATE.build_matrix(self.context["spec_path"])

        report = AGGREGATE.parse_canonical_object(original, "component report")
        report["host"]["physical_machine"] = False
        report_path.write_bytes(AGGREGATE.canonical_json(report))
        with self.subTest("physical"), self.assert_aggregate_error("physical machine"):
            AGGREGATE.build_matrix(self.context["spec_path"])

        report = AGGREGATE.parse_canonical_object(original, "component report")
        report["component_set_sha256"] = "sha256:" + "ff" * 32
        report_path.write_bytes(AGGREGATE.canonical_json(report))
        with self.subTest("set"), self.assert_aggregate_error("component-set digest"):
            AGGREGATE.build_matrix(self.context["spec_path"])

        report = AGGREGATE.parse_canonical_object(original, "component report")
        report["build"]["builder"]["wasm_target_libdir"] = (
            "/private/tmp/wasmbiotic-rustup/toolchains/test/lib/rustlib/"
            "wasm32-wasip2/lib"
        )
        report_path.write_bytes(AGGREGATE.canonical_json(report))
        with self.subTest("macOS private tmp alias"):
            AGGREGATE.build_matrix(self.context["spec_path"])

        report = AGGREGATE.parse_canonical_object(original, "component report")
        report["build"]["builder"]["wasm_target_libdir"] = (
            "/private/tmp/not-wasmbiotic-rustup/toolchains/test/lib/rustlib/"
            "wasm32-wasip2/lib"
        )
        report_path.write_bytes(AGGREGATE.canonical_json(report))
        with (
            self.subTest("outside frozen rustup root"),
            self.assert_aggregate_error("builder/toolchain differs"),
        ):
            AGGREGATE.build_matrix(self.context["spec_path"])

    def test_postpublication_recovery_must_bind_fresh_external_lifecycle(
        self,
    ) -> None:
        recovery_path = self.context["postpublication_recovery_path"]
        lifecycle_path = self.context["postpublication_lifecycle_path"]
        recovery_original = recovery_path.read_bytes()
        lifecycle_original = lifecycle_path.read_bytes()

        recovery = AGGREGATE.parse_canonical_object(
            recovery_original, "post-publication recovery"
        )
        recovery["publication"]["publication_root"] = "sha256:" + "00" * 32
        recovery_path.write_bytes(AGGREGATE.canonical_json(recovery))
        with (
            self.subTest("root"),
            self.assert_aggregate_error("exact final root"),
        ):
            AGGREGATE.build_aggregate(
                self.context["matrix_path"],
                self.context["publication"],
                self.context["policy_path"],
                self.context["release_public_key_path"],
                self.context["publication_negatives_path"],
                recovery_path,
                lifecycle_path,
            )

        recovery = AGGREGATE.parse_canonical_object(
            recovery_original, "post-publication recovery"
        )
        recovery["lifecycle"]["fresh_mechanism_state"] = False
        recovery_path.write_bytes(AGGREGATE.canonical_json(recovery))
        with (
            self.subTest("fresh state"),
            self.assert_aggregate_error("fresh state"),
        ):
            AGGREGATE.build_aggregate(
                self.context["matrix_path"],
                self.context["publication"],
                self.context["policy_path"],
                self.context["release_public_key_path"],
                self.context["publication_negatives_path"],
                recovery_path,
                lifecycle_path,
            )

        recovery = AGGREGATE.parse_canonical_object(
            recovery_original, "post-publication recovery"
        )
        recovery["lifecycle"]["operator_capacity_sha256"] = "sha256:" + "75" * 32
        recovery_path.write_bytes(AGGREGATE.canonical_json(recovery))
        with (
            self.subTest("operator capacity"),
            self.assert_aggregate_error("different operator capacity"),
        ):
            AGGREGATE.build_aggregate(
                self.context["matrix_path"],
                self.context["publication"],
                self.context["policy_path"],
                self.context["release_public_key_path"],
                self.context["publication_negatives_path"],
                recovery_path,
                lifecycle_path,
            )

        recovery_path.write_bytes(recovery_original)
        lifecycle = AGGREGATE.parse_canonical_object(
            lifecycle_original, "post-publication lifecycle"
        )
        lifecycle["host"]["physical_machine"] = False
        lifecycle_path.write_bytes(AGGREGATE.canonical_json(lifecycle))
        recovery = AGGREGATE.parse_canonical_object(
            recovery_original, "post-publication recovery"
        )
        recovery["lifecycle"]["report_sha256"] = AGGREGATE.digest_bytes(
            lifecycle_path.read_bytes()
        )
        recovery_path.write_bytes(AGGREGATE.canonical_json(recovery))
        with (
            self.subTest("physical"),
            self.assert_aggregate_error("physical machine"),
        ):
            AGGREGATE.build_aggregate(
                self.context["matrix_path"],
                self.context["publication"],
                self.context["policy_path"],
                self.context["release_public_key_path"],
                self.context["publication_negatives_path"],
                recovery_path,
                lifecycle_path,
            )

    def test_mac_requires_two_physical_witnesses_and_execution(self) -> None:
        spec = copy.deepcopy(self.context["spec"])
        spec["native_witnesses"] = [
            item
            for item in spec["native_witnesses"]
            if item["target"] != AGGREGATE.MACOS_TARGET
            or item["witness_id"].endswith("-1")
        ]
        path = self.write_json("one-mac-witness.json", spec)
        with (
            self.subTest("physical count"),
            self.assert_aggregate_error("at least two physical"),
        ):
            AGGREGATE.build_matrix(path)

        native_path = self.context["native_paths"][AGGREGATE.LINUX_TARGET][0]
        report, _ = AGGREGATE.read_canonical(native_path, "native report")
        report["reproduction"]["execution_verification"]["invoked"] = False
        native_path.write_bytes(AGGREGATE.canonical_json(report))
        with (
            self.subTest("execution"),
            self.assert_aggregate_error("not run successfully"),
        ):
            AGGREGATE.build_matrix(self.context["spec_path"])

    def test_native_snapshot_runtime_dependencies_and_witness_are_bound(self) -> None:
        native_path = self.context["native_paths"][AGGREGATE.LINUX_TARGET][0]
        original = native_path.read_bytes()

        report = AGGREGATE.parse_canonical_object(original, "native report")
        report["source"]["snapshot_manifest"]["sha256"] = "sha256:" + "ee" * 32
        native_path.write_bytes(AGGREGATE.canonical_json(report))
        with (
            self.subTest("source snapshot"),
            self.assert_aggregate_error("authoritative source snapshot"),
        ):
            AGGREGATE.build_matrix(self.context["spec_path"])

        report = AGGREGATE.parse_canonical_object(original, "native report")
        report["native_artifact"]["runtime_dependencies"][0]["version"] = "3"
        native_path.write_bytes(AGGREGATE.canonical_json(report))
        with (
            self.subTest("runtime dependencies"),
            self.assert_aggregate_error("SBOM system packages do not exactly match"),
        ):
            AGGREGATE.build_matrix(self.context["spec_path"])

        report = AGGREGATE.parse_canonical_object(original, "native report")
        report["witness"]["physical_machine"] = False
        native_path.write_bytes(AGGREGATE.canonical_json(report))
        with (
            self.subTest("physical witness"),
            self.assert_aggregate_error("named physical machine"),
        ):
            AGGREGATE.build_matrix(self.context["spec_path"])

        report = AGGREGATE.parse_canonical_object(original, "native report")
        report["witness"]["id"] = "substituted-witness"
        native_path.write_bytes(AGGREGATE.canonical_json(report))
        with (
            self.subTest("witness identity"),
            self.assert_aggregate_error("named physical machine"),
        ):
            AGGREGATE.build_matrix(self.context["spec_path"])

    def test_source_snapshot_requires_exact_component_toolchain_identity(self) -> None:
        snapshot_path = Path(self.context["spec"]["source_snapshot"])
        original = snapshot_path.read_bytes()
        snapshot = AGGREGATE.parse_canonical_object(
            original, "source snapshot manifest"
        )

        missing = copy.deepcopy(snapshot)
        missing["toolchain"].pop("wasm_tools")
        snapshot_path.write_bytes(AGGREGATE.canonical_json(missing))
        with (
            self.subTest("producer missing wasm-tools"),
            self.assert_aggregate_error("missing fields.*wasm_tools"),
        ):
            AGGREGATE.build_matrix(self.context["spec_path"])

        extra = copy.deepcopy(snapshot)
        extra["toolchain"]["unexpected"] = "phantom"
        snapshot_path.write_bytes(AGGREGATE.canonical_json(extra))
        with (
            self.subTest("producer extra tool"),
            self.assert_aggregate_error("unknown fields.*unexpected"),
        ):
            AGGREGATE.build_matrix(self.context["spec_path"])
        snapshot_path.write_bytes(original)

        retained_missing = copy.deepcopy(self.context["matrix"])
        retained_missing["source_snapshot"]["toolchain"].pop("wasm_tools")
        with (
            self.subTest("retained matrix missing wasm-tools"),
            self.assert_aggregate_error("missing fields.*wasm_tools"),
        ):
            AGGREGATE.validate_matrix(retained_missing)

        retained_extra = copy.deepcopy(self.context["matrix"])
        retained_extra["source_snapshot"]["toolchain"]["unexpected"] = "phantom"
        with (
            self.subTest("retained matrix extra tool"),
            self.assert_aggregate_error("unknown fields.*unexpected"),
        ):
            AGGREGATE.validate_matrix(retained_extra)

    def test_private_key_dependency_or_blocker_keeps_r4_open(self) -> None:
        negative_path = Path(self.context["spec"]["negative_controls"])
        negative, _ = AGGREGATE.read_canonical(negative_path, "negative controls")
        negative["private_key_dependency"] = True
        negative_path.write_bytes(AGGREGATE.canonical_json(negative))
        with self.assert_aggregate_error("private-key dependency"):
            AGGREGATE.build_matrix(self.context["spec_path"])

    def test_publication_negative_failure_and_matrix_substitution_fail(self) -> None:
        negatives_path = self.context["publication_negatives_path"]
        negatives, _ = AGGREGATE.read_canonical(negatives_path, "publication negatives")
        negatives["controls"]["root_rename_rejected"] = False
        negatives_path.write_bytes(AGGREGATE.canonical_json(negatives))
        with (
            self.subTest("negative"),
            self.assert_aggregate_error("failed or unexecuted"),
        ):
            AGGREGATE.build_aggregate(
                self.context["matrix_path"],
                self.context["publication"],
                self.context["policy_path"],
                self.context["release_public_key_path"],
                negatives_path,
                self.context["postpublication_recovery_path"],
                self.context["postpublication_lifecycle_path"],
            )

        negatives["controls"]["root_rename_rejected"] = True
        negatives_path.write_bytes(AGGREGATE.canonical_json(negatives))
        matrix, _ = AGGREGATE.read_canonical(self.context["matrix_path"], "matrix")
        matrix["source_snapshot"]["source_file_count"] += 1
        substituted = self.write_json("substituted-matrix.json", matrix)
        with (
            self.subTest("matrix"),
            self.assert_aggregate_error("reproduction-matrix does not match"),
        ):
            AGGREGATE.build_aggregate(
                substituted,
                self.context["publication"],
                self.context["policy_path"],
                self.context["release_public_key_path"],
                negatives_path,
                self.context["postpublication_recovery_path"],
                self.context["postpublication_lifecycle_path"],
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
