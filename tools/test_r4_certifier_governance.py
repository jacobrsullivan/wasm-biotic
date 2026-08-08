#!/usr/bin/env python3
"""Adversarial tests for the R4 operator certifier-governance tool."""

from __future__ import annotations

import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


TOOL = Path(__file__).with_name("r4-certifier-governance.py")
SPEC = importlib.util.spec_from_file_location("r4_certifier_governance", TOOL)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - import machinery guard
    raise RuntimeError(f"cannot import {TOOL}")
GOV = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GOV)


class CertifierGovernanceTests(unittest.TestCase):
    """Exercise closed policy, quorum, and transition semantics."""

    @classmethod
    def setUpClass(cls) -> None:
        openssl = shutil.which("openssl")
        if openssl is None:
            raise unittest.SkipTest("openssl is not installed")
        cls._temporary = tempfile.TemporaryDirectory(prefix="r4-governance-test-")
        cls.root = Path(cls._temporary.name)
        cls.private_keys: list[Path] = []
        cls.key_entries: list[dict[str, str]] = []
        for index in range(8):
            private_key = cls.root / f"operator-{index}.der"
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
            public_key = GOV.public_key_from_private(private_key)
            cls.private_keys.append(private_key)
            cls.key_entries.append(
                {
                    "algorithm": GOV.ALGORITHM,
                    "key_id": GOV.digest_bytes(public_key),
                    "public_key_hex": public_key.hex(),
                }
            )

    @classmethod
    def tearDownClass(cls) -> None:
        cls._temporary.cleanup()

    def setUp(self) -> None:
        self.genesis = self.policy((0, 1, 2))
        self.release = {
            "schema": "wasm-biotic.release-approval.v1",
            "release_digest": "sha256:" + "ab" * 32,
            "version": "4.0.0-test",
        }
        self.publication = {
            "schema": "wasm-biotic.publication-approval.v1",
            "channel": "stable",
            "release_digest": "sha256:" + "ab" * 32,
        }

    def policy(
        self,
        key_indexes: tuple[int, int, int],
        *,
        generation: int = 1,
        predecessor: str | None = None,
        revoked: tuple[str, ...] = (),
    ) -> dict[str, object]:
        return {
            "schema": GOV.POLICY_SCHEMA,
            "generation": generation,
            "threshold": GOV.THRESHOLD,
            "keys": sorted(
                (copy.deepcopy(self.key_entries[index]) for index in key_indexes),
                key=lambda key: key["key_id"],
            ),
            "revoked_key_ids": sorted(revoked),
            "predecessor_policy_digest": predecessor,
        }

    def signatures(
        self,
        policy: dict[str, object],
        domain: str,
        payload: dict[str, object],
        key_indexes: tuple[int, ...],
    ) -> list[dict[str, object]]:
        return sorted(
            (
                GOV.sign_detached(
                    policy, domain, payload, self.private_keys[index]
                )
                for index in key_indexes
            ),
            key=lambda signature: signature["key_id"],
        )

    def rotate_policy(self) -> dict[str, object]:
        return self.policy(
            (1, 2, 3),
            generation=2,
            predecessor=GOV.policy_digest(self.genesis),
        )

    def transition(
        self,
        old_policy: dict[str, object],
        new_policy: dict[str, object],
        kind: str,
        old_indexes: tuple[int, ...] = (0, 1),
        successor_indexes: tuple[int, ...] = (1, 3),
    ) -> dict[str, object]:
        statement = GOV.transition_statement(old_policy, new_policy, kind)
        return {
            "schema": GOV.TRANSITION_SCHEMA,
            "statement": statement,
            "old_policy_signatures": self.signatures(
                old_policy, GOV.TRANSITION_OLD_DOMAIN, statement, old_indexes
            ),
            "successor_policy_signatures": self.signatures(
                new_policy,
                GOV.TRANSITION_SUCCESSOR_DOMAIN,
                statement,
                successor_indexes,
            ),
        }

    def assert_governance_error(self, pattern: str):
        return self.assertRaisesRegex(GOV.GovernanceError, pattern)

    def test_genesis_policy_is_canonical_and_self_identifying(self) -> None:
        self.assertIs(GOV.validate_policy(self.genesis, require_genesis=True), self.genesis)
        encoded = GOV.canonical_json(self.genesis)
        self.assertEqual(GOV.parse_canonical_json(encoded, "policy"), self.genesis)
        self.assertEqual(GOV.policy_digest(self.genesis), GOV.digest_bytes(encoded))

    def test_policy_file_requires_exact_canonical_json(self) -> None:
        with self.assert_governance_error("not canonical JSON"):
            GOV.parse_canonical_json(GOV.canonical_json(self.genesis) + b"\n", "policy")
        duplicate = b'{"generation":1,"generation":2}'
        with self.assert_governance_error("duplicate key"):
            GOV.parse_canonical_json(duplicate, "policy")

    def test_policy_schema_and_closed_shape_are_enforced(self) -> None:
        cases: list[tuple[str, dict[str, object], str]] = []
        wrong_schema = copy.deepcopy(self.genesis)
        wrong_schema["schema"] = "wasm-biotic.certifier-trust-policy.v0"
        cases.append(("schema", wrong_schema, "schema"))
        extra = copy.deepcopy(self.genesis)
        extra["package_policy"] = True
        cases.append(("extra", extra, "unknown fields"))
        wrong_threshold = copy.deepcopy(self.genesis)
        wrong_threshold["threshold"] = 1
        cases.append(("threshold", wrong_threshold, "threshold"))
        two_keys = copy.deepcopy(self.genesis)
        two_keys["keys"] = two_keys["keys"][:2]
        cases.append(("two keys", two_keys, "exactly 3"))
        for label, policy, error in cases:
            with self.subTest(label=label), self.assert_governance_error(error):
                GOV.validate_policy(policy)

    def test_policy_key_inventory_is_sorted_unique_and_bound_to_bytes(self) -> None:
        unsorted = copy.deepcopy(self.genesis)
        unsorted["keys"] = list(reversed(unsorted["keys"]))
        with self.assert_governance_error("sorted bytewise"):
            GOV.validate_policy(unsorted)

        wrong_id = copy.deepcopy(self.genesis)
        wrong_id["keys"][0]["key_id"] = "sha256:" + "00" * 32
        with self.assert_governance_error("does not match"):
            GOV.validate_policy(wrong_id)

        duplicate_bytes = copy.deepcopy(self.genesis)
        duplicate_bytes["keys"][1]["public_key_hex"] = duplicate_bytes["keys"][0][
            "public_key_hex"
        ]
        duplicate_bytes["keys"][1]["key_id"] = duplicate_bytes["keys"][0]["key_id"]
        duplicate_bytes["keys"] = sorted(
            duplicate_bytes["keys"], key=lambda key: key["key_id"]
        )
        with self.assert_governance_error("duplicate"):
            GOV.validate_policy(duplicate_bytes)

    def test_genesis_and_predecessor_rules_are_closed(self) -> None:
        predecessor = copy.deepcopy(self.genesis)
        predecessor["predecessor_policy_digest"] = "sha256:" + "00" * 32
        with self.assert_governance_error("null predecessor"):
            GOV.validate_policy(predecessor)

        revoked = copy.deepcopy(self.genesis)
        revoked["revoked_key_ids"] = [self.key_entries[3]["key_id"]]
        with self.assert_governance_error("genesis must have no revocations"):
            GOV.validate_policy(revoked)

        later = copy.deepcopy(self.genesis)
        later["generation"] = 2
        with self.assert_governance_error("non-empty string"):
            GOV.validate_policy(later)

        with self.assert_governance_error("not a generation-1 genesis"):
            GOV.validate_policy(self.rotate_policy(), require_genesis=True)

    def test_revocation_inventory_is_sorted_unique_and_disjoint(self) -> None:
        rotated = self.rotate_policy()
        ids = (self.key_entries[4]["key_id"], self.key_entries[5]["key_id"])
        rotated["revoked_key_ids"] = list(reversed(sorted(ids)))
        with self.assert_governance_error("sorted bytewise"):
            GOV.validate_policy(rotated)

        rotated["revoked_key_ids"] = [ids[0], ids[0]]
        with self.assert_governance_error("duplicates"):
            GOV.validate_policy(rotated)

        rotated["revoked_key_ids"] = [self.key_entries[1]["key_id"]]
        with self.assert_governance_error("active keys as revoked"):
            GOV.validate_policy(rotated)

    def test_release_and_publication_accept_exact_two_of_three(self) -> None:
        release_signatures = self.signatures(
            self.genesis, GOV.RELEASE_DOMAIN, self.release, (0, 2)
        )
        publication_signatures = self.signatures(
            self.genesis, GOV.PUBLICATION_DOMAIN, self.publication, (1, 2)
        )
        self.assertEqual(
            GOV.verify_release_quorum(self.genesis, self.release, release_signatures),
            [signature["key_id"] for signature in release_signatures],
        )
        self.assertEqual(
            GOV.verify_publication_quorum(
                self.genesis, self.publication, publication_signatures
            ),
            [signature["key_id"] for signature in publication_signatures],
        )

    def test_one_of_three_is_not_a_quorum(self) -> None:
        signatures = self.signatures(
            self.genesis, GOV.RELEASE_DOMAIN, self.release, (0,)
        )
        with self.assert_governance_error("at least 2"):
            GOV.verify_release_quorum(self.genesis, self.release, signatures)

    def test_duplicate_signer_cannot_satisfy_quorum(self) -> None:
        signature = self.signatures(
            self.genesis, GOV.RELEASE_DOMAIN, self.release, (0,)
        )[0]
        with self.assert_governance_error("duplicates"):
            GOV.verify_release_quorum(
                self.genesis, self.release, [signature, copy.deepcopy(signature)]
            )

    def test_unknown_signer_is_rejected_even_with_valid_signature(self) -> None:
        unknown = GOV._detached_signature_for_context(
            self.genesis,
            GOV.RELEASE_DOMAIN,
            self.release,
            self.private_keys[7],
        )
        known = self.signatures(
            self.genesis, GOV.RELEASE_DOMAIN, self.release, (0,)
        )[0]
        signatures = sorted((unknown, known), key=lambda value: value["key_id"])
        with self.assert_governance_error("unknown policy key"):
            GOV.verify_release_quorum(self.genesis, self.release, signatures)

    def test_revoked_signer_is_rejected_even_with_valid_signature(self) -> None:
        successor = self.policy(
            (1, 2, 3),
            generation=2,
            predecessor=GOV.policy_digest(self.genesis),
            revoked=(self.key_entries[0]["key_id"],),
        )
        revoked = GOV._detached_signature_for_context(
            successor,
            GOV.RELEASE_DOMAIN,
            self.release,
            self.private_keys[0],
        )
        known = self.signatures(successor, GOV.RELEASE_DOMAIN, self.release, (1,))[0]
        signatures = sorted((revoked, known), key=lambda value: value["key_id"])
        with self.assert_governance_error("revoked key"):
            GOV.verify_release_quorum(successor, self.release, signatures)

    def test_domains_are_not_interchangeable(self) -> None:
        signatures = self.signatures(
            self.genesis, GOV.RELEASE_DOMAIN, self.release, (0, 1)
        )
        with self.assert_governance_error("different domain"):
            GOV.verify_publication_quorum(self.genesis, self.release, signatures)

    def test_mixed_policy_signatures_do_not_form_a_quorum(self) -> None:
        rotated = self.rotate_policy()
        old_signature = self.signatures(
            self.genesis, GOV.RELEASE_DOMAIN, self.release, (0,)
        )[0]
        new_signature = self.signatures(
            rotated, GOV.RELEASE_DOMAIN, self.release, (3,)
        )[0]
        signatures = sorted(
            (old_signature, new_signature), key=lambda value: value["key_id"]
        )
        with self.assert_governance_error("different policy"):
            GOV.verify_release_quorum(rotated, self.release, signatures)

    def test_payload_mutation_and_signature_tampering_are_rejected(self) -> None:
        signatures = self.signatures(
            self.genesis, GOV.RELEASE_DOMAIN, self.release, (0, 1)
        )
        changed = copy.deepcopy(self.release)
        changed["version"] = "4.0.1-replayed"
        with self.assert_governance_error("different payload"):
            GOV.verify_release_quorum(self.genesis, changed, signatures)

        tampered = copy.deepcopy(signatures)
        final = tampered[0]["signature_hex"][-2:]
        tampered[0]["signature_hex"] = tampered[0]["signature_hex"][:-2] + (
            "00" if final != "00" else "01"
        )
        with self.assert_governance_error("openssl failed"):
            GOV.verify_release_quorum(self.genesis, self.release, tampered)

    def test_valid_rotation_requires_old_quorum_and_successor_possession(self) -> None:
        rotated = self.rotate_policy()
        transition = self.transition(self.genesis, rotated, "rotate")
        self.assertIs(
            GOV.verify_transition(self.genesis, rotated, transition), transition
        )
        assembled = GOV.assemble_transition(
            self.genesis,
            rotated,
            "rotate",
            list(reversed(transition["old_policy_signatures"])),
            list(reversed(transition["successor_policy_signatures"])),
        )
        self.assertEqual(
            [item["key_id"] for item in assembled["old_policy_signatures"]],
            sorted(item["key_id"] for item in transition["old_policy_signatures"]),
        )

    def test_valid_revocation_is_cumulative_and_tombstones_removed_key(self) -> None:
        rotated = self.rotate_policy()
        successor = self.policy(
            (2, 3, 4),
            generation=3,
            predecessor=GOV.policy_digest(rotated),
            revoked=(self.key_entries[1]["key_id"],),
        )
        transition = self.transition(
            rotated,
            successor,
            "revoke",
            old_indexes=(1, 2),
            successor_indexes=(2, 4),
        )
        GOV.verify_transition(rotated, successor, transition)

    def test_transition_rejects_one_of_three_on_either_side(self) -> None:
        rotated = self.rotate_policy()
        statement = GOV.transition_statement(self.genesis, rotated, "rotate")
        old_one = self.transition(self.genesis, rotated, "rotate")
        old_one["old_policy_signatures"] = self.signatures(
            self.genesis, GOV.TRANSITION_OLD_DOMAIN, statement, (0,)
        )
        with self.assert_governance_error("at least 2"):
            GOV.verify_transition(self.genesis, rotated, old_one)

        successor_one = self.transition(self.genesis, rotated, "rotate")
        successor_one["successor_policy_signatures"] = self.signatures(
            rotated, GOV.TRANSITION_SUCCESSOR_DOMAIN, statement, (1,)
        )
        with self.assert_governance_error("at least 2"):
            GOV.verify_transition(self.genesis, rotated, successor_one)

    def test_successor_quorum_must_prove_possession_of_introduced_key(self) -> None:
        rotated = self.rotate_policy()
        statement = GOV.transition_statement(self.genesis, rotated, "rotate")
        envelope = self.transition(self.genesis, rotated, "rotate")
        envelope["successor_policy_signatures"] = self.signatures(
            rotated, GOV.TRANSITION_SUCCESSOR_DOMAIN, statement, (1, 2)
        )
        with self.assert_governance_error("proof-of-possession"):
            GOV.verify_transition(self.genesis, rotated, envelope)

    def test_rotate_and_revoke_have_distinct_tombstone_semantics(self) -> None:
        removed = self.key_entries[0]["key_id"]
        rotation_with_tombstone = self.policy(
            (1, 2, 3),
            generation=2,
            predecessor=GOV.policy_digest(self.genesis),
            revoked=(removed,),
        )
        with self.assert_governance_error("rotation must not change"):
            GOV.transition_statement(
                self.genesis, rotation_with_tombstone, "rotate"
            )

        revocation_without_tombstone = self.rotate_policy()
        with self.assert_governance_error("tombstone exactly"):
            GOV.transition_statement(
                self.genesis, revocation_without_tombstone, "revoke"
            )

    def test_cumulative_revocations_cannot_be_removed(self) -> None:
        old = self.policy(
            (1, 2, 3),
            generation=2,
            predecessor="sha256:" + "01" * 32,
            revoked=(self.key_entries[0]["key_id"],),
        )
        successor = self.policy(
            (2, 3, 4),
            generation=3,
            predecessor=GOV.policy_digest(old),
        )
        with self.assert_governance_error("removed a cumulative"):
            GOV.transition_statement(old, successor, "rotate")

    def test_transition_replay_downgrade_and_fork_shapes_are_rejected(self) -> None:
        rotated = self.rotate_policy()
        envelope = self.transition(self.genesis, rotated, "rotate")
        next_policy = self.policy(
            (2, 3, 4),
            generation=3,
            predecessor=GOV.policy_digest(rotated),
        )
        with self.subTest("replay"), self.assert_governance_error(
            "does not exactly describe"
        ):
            GOV.verify_transition(rotated, next_policy, envelope)

        with self.subTest("downgrade"), self.assert_governance_error(
            "exactly one greater"
        ):
            GOV.transition_statement(rotated, self.genesis, "rotate")

        fork = self.policy(
            (2, 3, 4),
            generation=3,
            predecessor=GOV.policy_digest(self.genesis),
        )
        with self.subTest("fork"), self.assert_governance_error(
            "predecessor does not match"
        ):
            GOV.transition_statement(rotated, fork, "rotate")

    def test_transition_domains_and_policy_proofs_cannot_be_mixed(self) -> None:
        rotated = self.rotate_policy()
        statement = GOV.transition_statement(self.genesis, rotated, "rotate")
        envelope = self.transition(self.genesis, rotated, "rotate")
        envelope["successor_policy_signatures"] = self.signatures(
            rotated, GOV.TRANSITION_OLD_DOMAIN, statement, (1, 2)
        )
        with self.assert_governance_error("different domain"):
            GOV.verify_transition(self.genesis, rotated, envelope)

        envelope = self.transition(self.genesis, rotated, "rotate")
        envelope["successor_policy_signatures"] = self.signatures(
            self.genesis, GOV.TRANSITION_SUCCESSOR_DOMAIN, statement, (0, 1)
        )
        with self.assert_governance_error("different policy"):
            GOV.verify_transition(self.genesis, rotated, envelope)

    def test_transition_requires_replacement_and_exact_statement(self) -> None:
        no_replacement = self.policy(
            (0, 1, 2),
            generation=2,
            predecessor=GOV.policy_digest(self.genesis),
        )
        with self.assert_governance_error("replace at least one"):
            GOV.transition_statement(self.genesis, no_replacement, "rotate")

        rotated = self.rotate_policy()
        envelope = self.transition(self.genesis, rotated, "rotate")
        envelope["statement"]["old_generation"] = 0
        with self.assert_governance_error("does not exactly describe"):
            GOV.verify_transition(self.genesis, rotated, envelope)

        boolean_generation = self.transition(self.genesis, rotated, "rotate")
        boolean_generation["statement"]["old_generation"] = True
        with self.assert_governance_error("does not exactly describe"):
            GOV.verify_transition(self.genesis, rotated, boolean_generation)

    def test_cli_validates_policy_and_release_quorum(self) -> None:
        policy_path = self.root / "policy.json"
        payload_path = self.root / "release.json"
        signature_paths = [self.root / f"release-{index}.sig.json" for index in (0, 1)]
        policy_path.write_bytes(GOV.canonical_json(self.genesis))
        payload_path.write_bytes(GOV.canonical_json(self.release))
        signatures = self.signatures(
            self.genesis, GOV.RELEASE_DOMAIN, self.release, (0, 1)
        )
        self.assertEqual(len(signature_paths), len(signatures))
        for path, signature in zip(signature_paths, signatures):
            path.write_bytes(GOV.canonical_json(signature))

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(
                GOV.main(["validate-policy", "--genesis", str(policy_path)]), 0
            )
            self.assertEqual(
                GOV.main(
                    [
                        "verify-release",
                        "--policy",
                        str(policy_path),
                        "--payload",
                        str(payload_path),
                        "--signature",
                        str(signature_paths[0]),
                        "--signature",
                        str(signature_paths[1]),
                    ]
                ),
                0,
            )
        self.assertIn("verified 2-of-3 quorum", output.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
