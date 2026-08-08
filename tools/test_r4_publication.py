#!/usr/bin/env python3
"""End-to-end and adversarial tests for detached R4 publication."""

from __future__ import annotations

import contextlib
import copy
import importlib.util
import io
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock


TOOL = Path(__file__).with_name("r4-publication.py")
SPEC = importlib.util.spec_from_file_location("r4_publication", TOOL)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - import machinery guard
    raise RuntimeError(f"cannot import {TOOL}")
PUBLICATION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PUBLICATION)
GOVERNANCE = PUBLICATION.GOVERNANCE


class R4PublicationTests(unittest.TestCase):
    """The publication remains closed before and after detached signing."""

    @classmethod
    def setUpClass(cls) -> None:
        openssl = shutil.which("openssl")
        if openssl is None:
            raise unittest.SkipTest("openssl is not installed")
        cls._key_temporary = tempfile.TemporaryDirectory(prefix="r4-publication-keys-")
        cls.key_root = Path(cls._key_temporary.name)
        cls.private_keys: list[Path] = []
        cls.key_entries: list[dict[str, str]] = []
        for index in range(5):
            private_key = cls.key_root / f"operator-{index}.der"
            subprocess.run(
                [
                    openssl,
                    "genpkey",
                    "-algorithm",
                    "ED25519",
                    "-outform",
                    "DER",
                    "-out",
                    str(private_key),
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            public_key = GOVERNANCE.public_key_from_private(private_key)
            cls.private_keys.append(private_key)
            cls.key_entries.append(
                {
                    "algorithm": GOVERNANCE.ALGORITHM,
                    "key_id": GOVERNANCE.digest_bytes(public_key),
                    "public_key_hex": public_key.hex(),
                }
            )

    @classmethod
    def tearDownClass(cls) -> None:
        cls._key_temporary.cleanup()

    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory(prefix="r4-publication-test-")
        self.root = Path(self._temporary.name)
        self.inputs = self.root / "inputs"
        self.inputs.mkdir()
        self.targets = list(PUBLICATION.CLOSED_TARGETS)
        self.target = self.targets[0]
        self.policy = self.make_policy((0, 1, 2))
        self.policy_path = self.inputs / "trust-policy.json"
        self.policy_path.write_bytes(GOVERNANCE.canonical_json(self.policy))
        self.release_public_key = bytes.fromhex(self.key_entries[0]["public_key_hex"])
        self.release_certifier_key_id = PUBLICATION.digest_bytes(
            self.release_public_key
        )
        self.release_public_key_path = self.write_input(
            "r3-release-public-key.raw", self.release_public_key
        )
        # Publication tests construct a compact content-addressed package-tree
        # fixture and exercise its package signatures/components below.  The
        # complete component-bundle verifier has its own end-to-end suite; the
        # R4 release gate additionally runs it against the retained bundle.
        self._component_bundle_verifier = mock.patch.object(
            PUBLICATION.COMPONENT_RELEASE,
            "verify_bundle",
            side_effect=lambda root, _key, require_root_name=False: (
                PUBLICATION.digest_bytes((root / "release.json").read_bytes())
            ),
        )
        self._component_bundle_verifier.start()
        self.objects = self.make_objects()
        self.spec_path = self.root / "publication-spec.json"
        self.write_spec(self.objects)

    def tearDown(self) -> None:
        self._component_bundle_verifier.stop()
        self._temporary.cleanup()

    def make_policy(self, indexes: tuple[int, int, int]) -> dict[str, object]:
        return {
            "generation": 1,
            "keys": sorted(
                (copy.deepcopy(self.key_entries[index]) for index in indexes),
                key=lambda item: item["key_id"],
            ),
            "predecessor_policy_digest": None,
            "revoked_key_ids": [],
            "schema": GOVERNANCE.POLICY_SCHEMA,
            "threshold": 2,
        }

    def write_input(self, name: str, data: bytes, *, mode: int = 0o644) -> Path:
        path = self.inputs / name
        path.write_bytes(data)
        path.chmod(mode)
        return path

    def write_archive(self, name: str, files: dict[str, bytes]) -> tuple[Path, str]:
        payload = self.root / f"{name}-payload"
        payload.mkdir()
        for relative, data in files.items():
            path = payload / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        archive_path = self.inputs / f"{name}.tar"
        digest, _ = PUBLICATION.ARCHIVE.write_archive(payload, archive_path, 0)
        return archive_path, digest

    def native_report(
        self, target: str, binary: bytes, *, witness_id: str | None = None
    ) -> dict[str, object]:
        digest = PUBLICATION.digest_bytes(binary)
        macos = target == "aarch64-apple-darwin"
        runtime_dependencies = [
            {"name": "libSystem", "version": "1"}
            if macos
            else {"name": "glibc", "version": "2"}
        ]
        return {
            "build_recipe": {"sha256": "sha256:" + "33" * 32},
            "component_complete_claim": False,
            "compiled_inventory": {
                "binary_embedding": {"occurrences": 1, "result": "pass"},
                "schema": "wasm-biotic.native-tcb-inventory.v1",
                "sha256": "sha256:" + "31" * 32,
                "source_revision": "sha256:" + "32" * 32,
            },
            "gate_result": "pass",
            "native_artifact": {
                "path": "objects/" + digest.replace(":", "-", 1),
                "platform_metadata": {
                    "format": "Mach-O" if macos else "ELF",
                },
                "runtime_dependencies": runtime_dependencies,
                "sha256": digest,
                "size_bytes": len(binary),
            },
            "platform": {
                "architecture": "aarch64" if macos else "x86_64",
                "binary_format": "Mach-O" if macos else "ELF",
                "os": "macos" if macos else "linux",
                "target": target,
            },
            "reference_digest_verification": {"match": True},
            "reproduction": {
                "binary_sha256": digest,
                "clean_builds": 2,
                "exact_complete_binary_match": True,
                "execution_verification": {
                    "expected_usage_error": True,
                    "invoked": True,
                    "process_loaded": True,
                    "result": "pass",
                },
                "physical_build_paths_embedded": False,
                "platform_identity_canonicalization": (
                    {
                        "linked_artifacts_equal_outside_allowed_regions": True,
                        "result": "pass",
                    }
                    if macos
                    else None
                ),
                "result": "pass",
                "target_directory_shapes": ["short", "materially-long"],
            },
            "schema": PUBLICATION.NATIVE_ATTESTATION_SCHEMA,
            "source": {
                "closure": {"sha256": "sha256:" + "32" * 32},
                "snapshot_manifest": {
                    "schema": PUBLICATION.SOURCE_SNAPSHOT_SCHEMA,
                    "sha256": self.source_snapshot_digest,
                },
            },
            "witness": {
                "id": witness_id or f"physical-{target}-a",
                "physical_machine": True,
            },
        }

    def signed_package_files(
        self, kind: str, previous_graph: str | None
    ) -> tuple[dict[str, bytes], str, str]:
        component_bytes = {
            node: f"fixture component {node}\n".encode("utf-8")
            for node in sorted(PUBLICATION.COMPONENT_REPRODUCTION.EXPECTED_NODES)
        }
        raw_nodes = {
            node: PUBLICATION.digest_bytes(data)
            for node, data in component_bytes.items()
        }
        manifest: dict[str, object] = {
            "nodes": raw_nodes,
            "package": kind,
            "schema": "wasm-biotic.component-graph-manifest.v1",
        }
        if previous_graph is not None:
            manifest["previous_graph"] = previous_graph
        manifest_bytes = PUBLICATION.canonical_json(manifest)
        graph_digest = PUBLICATION.digest_bytes(manifest_bytes)
        statement = {
            "graph_manifest_digest": graph_digest,
            "raw_artifacts": raw_nodes,
            "schema": PUBLICATION.COMPONENT_REPRODUCTION.CERTIFICATE_STATEMENT_SCHEMA,
        }
        payload = PUBLICATION.canonical_json(
            {
                "certifier_key_id": self.release_certifier_key_id,
                "schema": PUBLICATION.COMPONENT_REPRODUCTION.PACKAGE_SIGNING_PAYLOAD_SCHEMA,
                "statement": statement,
            }
        )
        public_key, signature = GOVERNANCE._sign_bytes(self.private_keys[0], payload)
        self.assertEqual(public_key, self.release_public_key)
        certification = PUBLICATION.canonical_json(
            {
                "certifier_key_id": self.release_certifier_key_id,
                "schema": PUBLICATION.COMPONENT_REPRODUCTION.CERTIFICATE_SCHEMA,
                "signature": {
                    "algorithm": "ed25519",
                    "signature_hex": signature.hex(),
                },
                "statement": statement,
            }
        )
        certification_digest = PUBLICATION.digest_bytes(certification)
        composition = PUBLICATION.canonical_json(
            {
                "graph_manifest_digest": graph_digest,
                "package_schema": PUBLICATION.COMPONENT_REPRODUCTION.PACKAGE_SCHEMA,
                "raw_nodes": raw_nodes,
                "validated": True,
            }
        )
        package_index = PUBLICATION.canonical_json(
            {
                "certification_digest": certification_digest,
                "graph_manifest_digest": graph_digest,
                "package_schema": PUBLICATION.COMPONENT_REPRODUCTION.PACKAGE_SCHEMA,
            }
        )
        files = {
            f"packages/{kind}/certification/release-certification.json": certification,
            f"packages/{kind}/evidence/composition.json": composition,
            f"packages/{kind}/manifest.json": manifest_bytes,
            f"packages/{kind}/package.json": package_index,
        }
        for node, data in component_bytes.items():
            digest = raw_nodes[node]
            files[
                f"packages/{kind}/components/sha256-{digest[7:]}.wasm"
            ] = data
        return files, graph_digest, certification_digest

    def content_addressed_package_tree(
        self,
        role: str,
        kind: str,
        package_files: dict[str, bytes],
    ) -> tuple[dict[str, object], dict[str, bytes]]:
        prefix = f"packages/{kind}/"
        entries: list[dict[str, object]] = []
        relative_files: dict[str, bytes] = {}
        for path, data in sorted(package_files.items()):
            self.assertTrue(path.startswith(prefix))
            relative = path[len(prefix) :]
            relative_files[relative] = data
            entries.append(
                {
                    "path": relative,
                    "sha256": PUBLICATION.digest_bytes(data),
                    "size_bytes": len(data),
                }
            )
        tree_manifest = PUBLICATION.canonical_json(
            {
                "digest_algorithm": "sha256",
                "entries": entries,
                "schema": PUBLICATION.COMPONENT_RELEASE.TREE_SCHEMA,
            }
        )
        tree_digest = PUBLICATION.digest_bytes(tree_manifest)
        tree_path = f"trees/sha256-{tree_digest[7:]}"
        files = {f"{tree_path}/tree.json": tree_manifest}
        files.update(
            {
                f"{tree_path}/files/{relative}": data
                for relative, data in relative_files.items()
            }
        )
        return (
            {
                "file_count": len(relative_files),
                "files_size_bytes": sum(len(data) for data in relative_files.values()),
                "path": tree_path,
                "role": role,
                "tree_manifest_sha256": tree_digest,
                "tree_manifest_size_bytes": len(tree_manifest),
            },
            files,
        )

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
            "schema": PUBLICATION.PUBLIC_INSTALL.LIFECYCLE_SCHEMA,
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

    def make_objects(self) -> list[dict[str, str]]:
        snapshot = {
            "dependency_delivery": "complete Cargo registry source vendoring; no registry access required",
            "schema": PUBLICATION.SOURCE_SNAPSHOT_SCHEMA,
            "source_closure_sha256": "sha256:" + "11" * 32,
            "vendor_closure_sha256": "sha256:" + "12" * 32,
        }
        self.source_snapshot_digest = PUBLICATION.digest_bytes(
            PUBLICATION.canonical_json(snapshot)
        )
        source_archive, source_digest = self.write_archive(
            "source-archive",
            {
                "SOURCE-SNAPSHOT.json": PUBLICATION.canonical_json(snapshot),
                "vendor/a": b"vendored\n",
            },
        )
        incumbent_files, self.incumbent_graph_digest, self.incumbent_certification_digest = (
            self.signed_package_files("incumbent", None)
        )
        successor_files, self.successor_graph_digest, self.successor_certification_digest = (
            self.signed_package_files("successor", self.incumbent_graph_digest)
        )
        self.incumbent_tree, incumbent_tree_files = (
            self.content_addressed_package_tree(
                "incumbent-package", "incumbent", incumbent_files
            )
        )
        self.successor_tree, successor_tree_files = (
            self.content_addressed_package_tree(
                "successor-package", "successor", successor_files
            )
        )
        claim_manifest = PUBLICATION.canonical_json(
            {
                "certifier": {
                    "algorithm": "ed25519",
                    "key_id": self.release_certifier_key_id,
                },
                "identities": {
                    "incumbent_graph_manifest_digest": self.incumbent_graph_digest,
                    "successor_graph_manifest_digest": self.successor_graph_digest,
                },
                "schema": "wasm-biotic.component-complete-claim-manifest.v3",
                "trees": sorted(
                    [self.incumbent_tree, self.successor_tree],
                    key=lambda item: item["role"],
                ),
            }
        )
        claim_manifest_digest = PUBLICATION.digest_bytes(claim_manifest)
        claim_payload = PUBLICATION.canonical_json(
            {
                "claim_manifest_digest": claim_manifest_digest,
                "schema": PUBLICATION.COMPONENT_CLAIM_SIGNING_PAYLOAD_SCHEMA,
            }
        )
        public_key, claim_signature_bytes = GOVERNANCE._sign_bytes(
            self.private_keys[0], claim_payload
        )
        self.assertEqual(public_key, self.release_public_key)
        claim_signature = PUBLICATION.canonical_json(
            {
                "algorithm": "ed25519",
                "certifier_key_id": self.release_certifier_key_id,
                "claim_manifest_digest": claim_manifest_digest,
                "schema": "wasm-biotic.component-complete-claim-signature.v1",
                "signature_hex": claim_signature_bytes.hex(),
            }
        )
        release = PUBLICATION.canonical_json(
            {
                "canonicalization": "wasm-biotic.canonical-json.v1",
                "claim_manifest": {
                    "path": "claim/manifest.json",
                    "sha256": claim_manifest_digest,
                    "size_bytes": len(claim_manifest),
                },
                "claim_signature": {
                    "path": "claim/signature.json",
                    "sha256": PUBLICATION.digest_bytes(claim_signature),
                    "size_bytes": len(claim_signature),
                },
                "digest_algorithm": "sha256",
                "schema": "wasm-biotic.component-complete-release-root.v1",
            }
        )
        component_files = {
            "claim/manifest.json": claim_manifest,
            "claim/signature.json": claim_signature,
            "release.json": release,
            **incumbent_tree_files,
            **successor_tree_files,
        }
        component_archive, component_digest = self.write_archive(
            "component-release-archive", component_files
        )

        self.governance_ceremony = self.root / "governance-ceremony"
        PUBLICATION.CEREMONY.run_ceremony(
            self.private_keys[:3],
            self.private_keys[3:5],
            {
                "closure_sha256": "sha256:" + "25" * 32,
                "schema": "wasm-biotic.r4-governance-release-test.v1",
            },
            {
                "closure_sha256": "sha256:" + "26" * 32,
                "schema": "wasm-biotic.r4-governance-publication-test.v1",
            },
            self.governance_ceremony,
        )
        governance_report = PUBLICATION.CEREMONY.read_object(
            self.governance_ceremony / PUBLICATION.CEREMONY.REPORT_NAME,
            "governance report",
        )
        self.assertEqual(
            governance_report["policy_digest"], GOVERNANCE.policy_digest(self.policy)
        )
        governance_path = self.write_input(
            "governance-report.json", PUBLICATION.canonical_json(governance_report)
        )
        install_files = {
            "README.txt": b"public install\n",
            "public/r3-certifier-public-key.raw": self.release_public_key,
        }
        install_files.update(
            {
                "governance/"
                + path.relative_to(
                    self.governance_ceremony
                ).as_posix(): path.read_bytes()
                for path in self.governance_ceremony.rglob("*")
                if path.is_file()
            }
        )
        install_archive, install_digest = self.write_archive(
            "install-archive", install_files
        )

        sbom = {
            "SPDXID": "SPDXRef-DOCUMENT",
            "dataLicense": "CC0-1.0",
            "files": [{"SPDXID": "SPDXRef-File", "fileName": "factory.wasm"}],
            "packages": [{"SPDXID": "SPDXRef-Package", "name": "wasm-biotic"}],
            "spdxVersion": "SPDX-2.3",
        }
        sbom_path = self.write_input("sbom.json", PUBLICATION.canonical_json(sbom))
        coverage = {
            "artifact_roles": [
                {"role": role}
                for role in (
                    "component-release-archive",
                    "install-archive",
                    "native-executable-aarch64-apple-darwin",
                    "native-executable-x86_64-unknown-linux-gnu",
                    "source-archive",
                )
            ],
            "result": "pass",
            "sbom_sha256": PUBLICATION.digest_bytes(PUBLICATION.canonical_json(sbom)),
            "schema": PUBLICATION.SBOM_COVERAGE_SCHEMA,
            "system_package_count": 2,
            "system_packages": [
                {"name": "libSystem", "target": self.targets[0], "version": "1"},
                {"name": "glibc", "target": self.targets[1], "version": "2"},
            ],
        }
        coverage_path = self.write_input(
            "sbom-coverage.json", PUBLICATION.canonical_json(coverage)
        )

        native_rows: list[dict[str, object]] = []
        native_objects: list[dict[str, str]] = []
        for target in self.targets:
            binary = (
                bytes.fromhex("cffaedfe") + b"R4 deterministic macOS executable\n"
                if target == self.targets[0]
                else b"\x7fELF\x02\x01R4 deterministic Linux executable\n"
            )
            executable = self.write_input(f"kernel-{target}", binary, mode=0o755)
            report = self.native_report(target, binary)
            report_bytes = PUBLICATION.canonical_json(report)
            report_path = self.write_input(f"native-{target}.json", report_bytes)
            report_digest = PUBLICATION.digest_bytes(report_bytes)
            native_rows.append(
                {
                    "binary_sha256": PUBLICATION.digest_bytes(binary),
                    "runtime_dependencies": report["native_artifact"][
                        "runtime_dependencies"
                    ],
                    "target": target,
                    "witness_count": 2 if target == self.targets[0] else 1,
                    "witnesses": [
                        {
                            "report_sha256": report_digest,
                            "runtime_dependencies": report["native_artifact"][
                                "runtime_dependencies"
                            ],
                            "source_snapshot_manifest_sha256": self.source_snapshot_digest,
                            "witness_id": f"physical-{target}-a",
                        },
                        *(
                            [
                                {
                                    "report_sha256": "sha256:" + "41" * 32,
                                    "runtime_dependencies": report["native_artifact"][
                                        "runtime_dependencies"
                                    ],
                                    "source_snapshot_manifest_sha256": self.source_snapshot_digest,
                                    "witness_id": "physical-mac-b",
                                }
                            ]
                            if target == self.targets[0]
                            else []
                        ),
                    ],
                }
            )
            native_objects.extend(
                [
                    {
                        "path": str(report_path),
                        "role": "native-attestation",
                        "target": target,
                    },
                    {
                        "path": str(executable),
                        "role": "native-executable",
                        "target": target,
                    },
                ]
            )

        component_lifecycle = self.component_lifecycle(
            self.incumbent_graph_digest, self.successor_graph_digest
        )
        lifecycle = {
            "archive": {
                "extracted_tree_exactly_matches_manifest": True,
                "install_archive_sha256": install_digest,
                "safe_archive_verifier_passed": True,
            },
            "component_lifecycle_report": component_lifecycle,
            "component_lifecycle_report_sha256": PUBLICATION.digest_bytes(
                PUBLICATION.canonical_json(component_lifecycle)
            ),
            "host": {
                "physical_machine": True,
                "target": self.targets[0],
                "witness_id": "physical-lifecycle",
            },
            "incumbent_graph_manifest_digest": self.incumbent_graph_digest,
            "kernel": {
                "expected_sha256": native_rows[0]["binary_sha256"],
                "observed_sha256": native_rows[0]["binary_sha256"],
            },
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
            "schema": PUBLICATION.PUBLIC_LIFECYCLE_SCHEMA,
            "successor_graph_manifest_digest": self.successor_graph_digest,
        }
        lifecycle_path = self.write_input(
            "public-lifecycle.json", PUBLICATION.canonical_json(lifecycle)
        )

        contract_path = (
            Path(__file__).resolve().parents[1]
            / "contracts/component-complete/R4_RELEASE.md"
        )
        matrix = {
            "archives": {
                "component-release-archive": {"sha256": component_digest},
                "install-archive": {"sha256": install_digest},
                "source-archive": {"sha256": source_digest},
            },
            "blockers": [],
            "component_complete_claim": True,
            "components": {
                "component_count": 22,
                "graph_manifest_digest": self.incumbent_graph_digest,
                "release_certification_sha256": self.incumbent_certification_digest,
                "release_certifier_key_id": self.release_certifier_key_id,
                "witness_count": 2,
            },
            "contract": {"sha256": PUBLICATION.FROZEN_CONTRACT_DIGEST},
            "external_north_star_claim": False,
            "governance": {
                "ceremony_manifest_sha256": governance_report[
                    "ceremony_manifest_sha256"
                ],
                "policy_digest": GOVERNANCE.policy_digest(self.policy),
                "report_sha256": PUBLICATION.digest_bytes(
                    PUBLICATION.canonical_json(governance_report)
                ),
            },
            "native": {
                "source_snapshot_manifest_sha256": self.source_snapshot_digest,
                "targets": native_rows,
            },
            "negative_controls": {"result": "pass"},
            "phase": "pre-publication",
            "private_key_dependency": False,
            "public_lifecycle": {
                "component_lifecycle_report_sha256": PUBLICATION.digest_bytes(
                    PUBLICATION.canonical_json(component_lifecycle)
                ),
                "incumbent_graph_manifest_digest": self.incumbent_graph_digest,
                "operator_capacity_sha256": "sha256:" + "74" * 32,
                "report_sha256": PUBLICATION.digest_bytes(
                    PUBLICATION.canonical_json(lifecycle)
                ),
                "successor_graph_manifest_digest": self.successor_graph_digest,
            },
            "result": "pass",
            "sbom": {
                "coverage_sha256": PUBLICATION.digest_bytes(
                    PUBLICATION.canonical_json(coverage)
                ),
                "spdx_sha256": PUBLICATION.digest_bytes(
                    PUBLICATION.canonical_json(sbom)
                ),
                "system_packages": coverage["system_packages"],
            },
            "schema": PUBLICATION.REPRODUCTION_MATRIX_SCHEMA,
            "source_snapshot": {"manifest_sha256": self.source_snapshot_digest},
            "targets": self.targets,
        }
        matrix_path = self.write_input(
            "reproduction-matrix.json", PUBLICATION.canonical_json(matrix)
        )
        paths = {
            "component-release-archive": component_archive,
            "governance-report": governance_path,
            "install-archive": install_archive,
            "public-lifecycle-report": lifecycle_path,
            "release-public-key": self.release_public_key_path,
            "r4-contract": contract_path,
            "reproduction-matrix": matrix_path,
            "sbom-coverage": coverage_path,
            "source-archive": source_archive,
            "spdx-sbom": sbom_path,
            "trust-policy": self.policy_path,
        }
        objects: list[dict[str, str]] = [
            {"path": str(paths[role]), "role": role}
            for role in sorted(PUBLICATION.GLOBAL_ROLES)
        ]
        objects.extend(native_objects)
        return sorted(objects, key=PUBLICATION.object_identity)

    def write_spec(
        self,
        objects: list[dict[str, str]],
        *,
        targets: list[str] | None = None,
        path: Path | None = None,
    ) -> Path:
        destination = path or self.spec_path
        spec = {
            "objects": objects,
            "schema": PUBLICATION.SPEC_SCHEMA,
            "targets": targets if targets is not None else self.targets,
        }
        destination.write_bytes(PUBLICATION.canonical_json(spec))
        return destination

    def prepare(self) -> Path:
        staging = self.root / "staging"
        PUBLICATION.prepare(self.spec_path, staging)
        return staging

    def resign_component_payload(self, payload: Path) -> None:
        claim_path = payload / "claim/manifest.json"
        claim = PUBLICATION.parse_canonical_object(
            claim_path.read_bytes(), "component claim"
        )
        claim_bytes = PUBLICATION.canonical_json(claim)
        claim_path.write_bytes(claim_bytes)
        claim_digest = PUBLICATION.digest_bytes(claim_bytes)
        signing_payload = PUBLICATION.canonical_json(
            {
                "claim_manifest_digest": claim_digest,
                "schema": PUBLICATION.COMPONENT_CLAIM_SIGNING_PAYLOAD_SCHEMA,
            }
        )
        public_key, signature_bytes = GOVERNANCE._sign_bytes(
            self.private_keys[0], signing_payload
        )
        self.assertEqual(public_key, self.release_public_key)
        signature = PUBLICATION.canonical_json(
            {
                "algorithm": "ed25519",
                "certifier_key_id": self.release_certifier_key_id,
                "claim_manifest_digest": claim_digest,
                "schema": "wasm-biotic.component-complete-claim-signature.v1",
                "signature_hex": signature_bytes.hex(),
            }
        )
        (payload / "claim/signature.json").write_bytes(signature)
        release = PUBLICATION.canonical_json(
            {
                "canonicalization": "wasm-biotic.canonical-json.v1",
                "claim_manifest": {
                    "path": "claim/manifest.json",
                    "sha256": claim_digest,
                    "size_bytes": len(claim_bytes),
                },
                "claim_signature": {
                    "path": "claim/signature.json",
                    "sha256": PUBLICATION.digest_bytes(signature),
                    "size_bytes": len(signature),
                },
                "digest_algorithm": "sha256",
                "schema": "wasm-biotic.component-complete-release-root.v1",
            }
        )
        (payload / "release.json").write_bytes(release)

    def signatures(self, staging: Path, indexes: tuple[int, ...]) -> list[Path]:
        payload, _ = PUBLICATION.read_canonical_file(
            staging / PUBLICATION.SIGNING_PAYLOAD_NAME, "signing payload"
        )
        paths: list[Path] = []
        for index in indexes:
            signature = GOVERNANCE.sign_detached(
                self.policy,
                GOVERNANCE.RELEASE_DOMAIN,
                payload,
                self.private_keys[index],
            )
            path = self.root / f"signature-{index}.json"
            path.write_bytes(GOVERNANCE.canonical_json(signature))
            paths.append(path)
        return paths

    def publish(self) -> Path:
        staging = self.prepare()
        return PUBLICATION.assemble(
            staging,
            self.policy_path,
            self.release_public_key_path,
            self.signatures(staging, (0, 1)),
            self.root / "published",
        )

    def entry(
        self, root: Path, role: str, target: str | None = None
    ) -> tuple[dict[str, object], Path]:
        claim, _ = PUBLICATION.read_canonical_file(
            root / PUBLICATION.CLAIM_NAME, "claim"
        )
        item = next(
            value
            for value in claim["objects"]
            if value["role"] == role and value.get("target") == target
        )
        return item, root / item["path"]

    def assert_publication_error(self, pattern: str):
        return self.assertRaisesRegex(PUBLICATION.PublicationError, pattern)

    def test_prepare_assemble_and_independently_verify(self) -> None:
        staging = self.root / "staging"
        claim_digest, returned = PUBLICATION.prepare(self.spec_path, staging)
        self.assertEqual(returned, staging)
        claim, claim_bytes = PUBLICATION.read_canonical_file(
            staging / PUBLICATION.CLAIM_NAME, "claim"
        )
        self.assertEqual(claim_digest, PUBLICATION.digest_bytes(claim_bytes))
        self.assertEqual(len(claim["objects"]), len(PUBLICATION.GLOBAL_ROLES) + 4)

        publication = PUBLICATION.assemble(
            staging,
            self.policy_path,
            self.release_public_key_path,
            self.signatures(staging, (0, 2)),
            self.root / "published",
        )
        _, root_bytes = PUBLICATION.read_canonical_file(
            publication / PUBLICATION.PUBLICATION_ROOT_NAME, "publication root"
        )
        publication_root = PUBLICATION.digest_bytes(root_bytes)
        self.assertEqual(publication.name, publication_root.replace(":", "-", 1))
        report = PUBLICATION.verify(
            publication, self.policy_path, self.release_public_key_path
        )
        self.assertEqual(report["claim_digest"], claim_digest)
        self.assertEqual(report["publication_root"], publication_root)
        self.assertEqual(report["signer_count"], 2)
        self.assertEqual(report["targets"], self.targets)
        self.assertFalse((publication / "policy.json").exists())

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(
                PUBLICATION.main(
                    [
                        "verify",
                        "--publication",
                        str(publication),
                        "--policy",
                        str(self.policy_path),
                        "--release-public-key",
                        str(self.release_public_key_path),
                    ]
                ),
                0,
            )
        self.assertIn("signers=2", output.getvalue())

    def test_missing_required_global_role_is_rejected(self) -> None:
        objects = [item for item in self.objects if item["role"] != "install-archive"]
        self.write_spec(objects)
        with self.assert_publication_error("missing.*install-archive"):
            PUBLICATION.prepare(self.spec_path, self.root / "staging")

    def test_duplicate_global_role_is_rejected(self) -> None:
        objects = copy.deepcopy(self.objects)
        source = next(item for item in objects if item["role"] == "source-archive")
        objects.append(copy.deepcopy(source))
        objects.sort(key=PUBLICATION.object_identity)
        self.write_spec(objects)
        with self.assert_publication_error("duplicate global.*source-archive"):
            PUBLICATION.prepare(self.spec_path, self.root / "staging")

    def test_target_requires_exactly_one_native_pair(self) -> None:
        objects = [
            item for item in self.objects if item["role"] != "native-attestation"
        ]
        self.write_spec(objects)
        with self.assert_publication_error("exactly one native executable"):
            PUBLICATION.prepare(self.spec_path, self.root / "staging")

    def test_single_target_and_schema_valid_nonsense_are_rejected(self) -> None:
        with (
            self.subTest("single target"),
            self.assert_publication_error("exact closed R4 target set"),
        ):
            PUBLICATION.validate_targets([self.targets[0]], "targets")

        nonsense = self.write_input(
            "nonsense-source-archive.json",
            PUBLICATION.canonical_json({"schema": PUBLICATION.SOURCE_SNAPSHOT_SCHEMA}),
        )
        objects = copy.deepcopy(self.objects)
        next(item for item in objects if item["role"] == "source-archive")["path"] = (
            str(nonsense)
        )
        self.write_spec(objects)
        with (
            self.subTest("hashed nonsense"),
            self.assert_publication_error("valid deterministic R4 archive"),
        ):
            PUBLICATION.prepare(self.spec_path, self.root / "staging")

    def test_object_sources_must_be_regular_files_not_links(self) -> None:
        replacement = self.inputs / "source-link"
        replacement.symlink_to(self.inputs / "source-archive.bin")
        objects = copy.deepcopy(self.objects)
        next(item for item in objects if item["role"] == "source-archive")["path"] = (
            str(replacement)
        )
        self.write_spec(objects)
        with self.assert_publication_error("regular file and not a link"):
            PUBLICATION.prepare(self.spec_path, self.root / "staging")

    def test_platform_mismatch_is_rejected_during_prepare(self) -> None:
        item = next(
            value for value in self.objects if value["role"] == "native-attestation"
        )
        path = Path(item["path"])
        attestation, _ = PUBLICATION.read_canonical_file(path, "attestation")
        attestation["platform"]["target"] = "x86_64-unknown-linux-gnu"
        path.write_bytes(PUBLICATION.canonical_json(attestation))
        with self.assert_publication_error("platform does not match"):
            PUBLICATION.prepare(self.spec_path, self.root / "staging")

    def test_native_executable_substitution_is_rejected(self) -> None:
        item = next(
            value for value in self.objects if value["role"] == "native-attestation"
        )
        path = Path(item["path"])
        attestation, _ = PUBLICATION.read_canonical_file(path, "attestation")
        attestation["native_artifact"]["sha256"] = "sha256:" + "00" * 32
        path.write_bytes(PUBLICATION.canonical_json(attestation))
        with self.assert_publication_error("does not bind its executable digest"):
            PUBLICATION.prepare(self.spec_path, self.root / "staging")

    def test_archived_package_signature_is_cryptographically_required(self) -> None:
        payload = self.root / "component-release-archive-payload"
        certificate_path = (
            payload
            / self.incumbent_tree["path"]
            / "files/certification/release-certification.json"
        )
        certificate = PUBLICATION.parse_canonical_object(
            certificate_path.read_bytes(), "release certification"
        )
        signature = certificate["signature"]["signature_hex"]
        certificate["signature"]["signature_hex"] = (
            ("0" if signature[0] != "0" else "1") + signature[1:]
        )
        certificate_path.write_bytes(PUBLICATION.canonical_json(certificate))
        tampered_archive = self.inputs / "tampered-component-release.tar"
        PUBLICATION.ARCHIVE.write_archive(payload, tampered_archive, 0)
        objects = copy.deepcopy(self.objects)
        next(
            item for item in objects if item["role"] == "component-release-archive"
        )["path"] = str(tampered_archive)
        objects.sort(key=PUBLICATION.object_identity)
        self.write_spec(objects)
        with self.assert_publication_error(
            "signed package verification failed.*signature"
        ):
            PUBLICATION.prepare(self.spec_path, self.root / "staging")

    def test_content_addressed_package_tree_roles_are_closed_and_bound(self) -> None:
        source_payload = self.root / "component-release-archive-payload"
        cases = (
            ("missing", "must retain exactly incumbent and successor"),
            ("duplicate", "duplicate roles"),
            ("swapped", "bound to the wrong role"),
            ("extra", "must retain exactly incumbent and successor"),
        )
        for label, expected_error in cases:
            with self.subTest(label):
                payload = self.root / f"component-tree-{label}"
                shutil.copytree(source_payload, payload)
                claim_path = payload / "claim/manifest.json"
                claim = PUBLICATION.parse_canonical_object(
                    claim_path.read_bytes(), "component claim"
                )
                trees = claim["trees"]
                if label == "missing":
                    trees[:] = [
                        item
                        for item in trees
                        if item["role"] != "successor-package"
                    ]
                elif label == "duplicate":
                    trees[1]["role"] = "incumbent-package"
                elif label == "swapped":
                    trees[0]["role"], trees[1]["role"] = (
                        trees[1]["role"],
                        trees[0]["role"],
                    )
                    trees.sort(key=lambda item: item["role"])
                else:
                    extra = copy.deepcopy(trees[0])
                    extra["role"] = "candidate-package"
                    trees.append(extra)
                    trees.sort(key=lambda item: item["role"])
                claim_path.write_bytes(PUBLICATION.canonical_json(claim))
                self.resign_component_payload(payload)
                archive = self.inputs / f"component-tree-{label}.tar"
                PUBLICATION.ARCHIVE.write_archive(payload, archive, 0)
                objects = copy.deepcopy(self.objects)
                next(
                    item
                    for item in objects
                    if item["role"] == "component-release-archive"
                )["path"] = str(archive)
                objects.sort(key=PUBLICATION.object_identity)
                spec = self.write_spec(
                    objects,
                    path=self.root / f"component-tree-{label}-spec.json",
                )
                with self.assert_publication_error(expected_error):
                    PUBLICATION.prepare(
                        spec,
                        self.root / f"component-tree-{label}-staging",
                    )

    def test_native_snapshot_dependencies_and_physical_witness_are_required(
        self,
    ) -> None:
        item = next(
            value
            for value in self.objects
            if value["role"] == "native-attestation"
            and value["target"] == self.targets[0]
        )
        path = Path(item["path"])
        original = path.read_bytes()

        attestation = PUBLICATION.parse_canonical_object(original, "attestation")
        attestation["source"]["snapshot_manifest"]["sha256"] = "sha256:" + "ff" * 32
        path.write_bytes(PUBLICATION.canonical_json(attestation))
        with (
            self.subTest("snapshot"),
            self.assert_publication_error("source snapshot differs"),
        ):
            PUBLICATION.prepare(self.spec_path, self.root / "staging-snapshot")

        attestation = PUBLICATION.parse_canonical_object(original, "attestation")
        attestation["native_artifact"]["runtime_dependencies"] = [
            {"name": "libSystem", "version": "1"},
            {"name": "libSystem", "version": "2"},
        ]
        path.write_bytes(PUBLICATION.canonical_json(attestation))
        with (
            self.subTest("dependencies"),
            self.assert_publication_error("duplicate dependency names"),
        ):
            PUBLICATION.prepare(self.spec_path, self.root / "staging-dependencies")

        attestation = PUBLICATION.parse_canonical_object(original, "attestation")
        attestation["witness"]["physical_machine"] = False
        path.write_bytes(PUBLICATION.canonical_json(attestation))
        with (
            self.subTest("physical witness"),
            self.assert_publication_error("named physical witness"),
        ):
            PUBLICATION.prepare(self.spec_path, self.root / "staging-witness")

    def test_content_addressed_object_substitution_fails_closed(self) -> None:
        staging = self.prepare()
        _, object_path = self.entry(staging, "component-release-archive")
        object_path.write_bytes(b"substituted component release archive\n")
        with self.assert_publication_error("content differs from claim"):
            PUBLICATION.assemble(
                staging,
                self.policy_path,
                self.release_public_key_path,
                self.signatures(staging, (0, 1)),
                self.root / "published",
            )

    def test_one_signature_cannot_publish_and_leaves_no_final_directory(self) -> None:
        staging = self.prepare()
        publish_root = self.root / "published"
        with self.assert_publication_error("at least 2"):
            PUBLICATION.assemble(
                staging,
                self.policy_path,
                self.release_public_key_path,
                self.signatures(staging, (0,)),
                publish_root,
            )
        self.assertFalse(publish_root.exists())

    def test_tampered_detached_signature_is_rejected(self) -> None:
        publication = self.publish()
        signature_path = sorted(
            (publication / PUBLICATION.SIGNATURE_DIRECTORY).iterdir()
        )[0]
        signature, _ = PUBLICATION.read_canonical_file(signature_path, "signature")
        ending = signature["signature_hex"][-2:]
        signature["signature_hex"] = signature["signature_hex"][:-2] + (
            "00" if ending != "00" else "01"
        )
        signature_path.write_bytes(PUBLICATION.canonical_json(signature))
        with self.assert_publication_error("detached release quorum is invalid"):
            PUBLICATION.verify(
                publication, self.policy_path, self.release_public_key_path
            )

    def test_independent_policy_cannot_be_substituted(self) -> None:
        publication = self.publish()
        other_policy = self.make_policy((1, 2, 3))
        other_path = self.root / "other-policy.json"
        other_path.write_bytes(GOVERNANCE.canonical_json(other_policy))
        with self.assert_publication_error(
            "differs from the independent genesis policy"
        ):
            PUBLICATION.verify(
                publication, other_path, self.release_public_key_path
            )

    def test_independent_release_public_key_cannot_be_substituted(self) -> None:
        publication = self.publish()
        other_key = self.root / "other-release-public-key.raw"
        other_key.write_bytes(bytes.fromhex(self.key_entries[1]["public_key_hex"]))
        with self.assert_publication_error(
            "differs from the independently supplied key"
        ):
            PUBLICATION.verify(publication, self.policy_path, other_key)

    def test_valid_signature_inventory_substitution_changes_publication_root(
        self,
    ) -> None:
        publication = self.publish()
        payload, _ = PUBLICATION.read_canonical_file(
            publication / PUBLICATION.SIGNING_PAYLOAD_NAME, "signing payload"
        )
        replacement_signatures = [
            GOVERNANCE.sign_detached(
                self.policy,
                GOVERNANCE.RELEASE_DOMAIN,
                payload,
                self.private_keys[index],
            )
            for index in (0, 2)
        ]
        signature_directory = publication / PUBLICATION.SIGNATURE_DIRECTORY
        for path in signature_directory.iterdir():
            path.unlink()
        for signature in replacement_signatures:
            path = signature_directory / f"{signature['key_id'][7:]}.json"
            path.write_bytes(GOVERNANCE.canonical_json(signature))
            path.chmod(0o644)

        claim, claim_bytes = PUBLICATION.read_canonical_file(
            publication / PUBLICATION.CLAIM_NAME, "claim"
        )
        root_value = PUBLICATION.publication_root_descriptor(
            claim,
            claim_bytes,
            payload,
            self.policy_path.read_bytes(),
            replacement_signatures,
        )
        root_path = publication / PUBLICATION.PUBLICATION_ROOT_NAME
        root_path.write_bytes(PUBLICATION.canonical_json(root_value))
        root_path.chmod(0o644)
        with self.assert_publication_error("directory name does not match"):
            PUBLICATION.verify(
                publication, self.policy_path, self.release_public_key_path
            )

    def test_root_name_mode_and_extra_file_are_verified(self) -> None:
        publication = self.publish()
        renamed = publication.with_name("sha256-" + "00" * 32)
        publication.rename(renamed)
        with (
            self.subTest("root"),
            self.assert_publication_error("directory name does not match"),
        ):
            PUBLICATION.verify(
                renamed, self.policy_path, self.release_public_key_path
            )

        renamed.rename(publication)
        _, source_object = self.entry(publication, "source-archive")
        source_object.chmod(0o600)
        with self.subTest("mode"), self.assert_publication_error("non-canonical mode"):
            PUBLICATION.verify(
                publication, self.policy_path, self.release_public_key_path
            )

        source_object.chmod(0o644)
        (publication / "EXTRA").write_text("not in closure", encoding="utf-8")
        with (
            self.subTest("extra"),
            self.assert_publication_error("file closure differs"),
        ):
            PUBLICATION.verify(
                publication, self.policy_path, self.release_public_key_path
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
