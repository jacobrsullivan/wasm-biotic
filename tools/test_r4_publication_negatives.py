#!/usr/bin/env python3
"""End-to-end tests for public-only R4 publication negative controls."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest
from unittest import mock

from tools import test_r4_publication as publication_fixture


TOOL = Path(__file__).with_name("r4-publication-negatives.py")
SPEC = importlib.util.spec_from_file_location("r4_publication_negatives", TOOL)
if SPEC is None or SPEC.loader is None:  # pragma: no cover
    raise RuntimeError(f"cannot import {TOOL}")
NEGATIVES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NEGATIVES)


class R4PublicationNegativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        publication_fixture.R4PublicationTests.setUpClass()

    @classmethod
    def tearDownClass(cls) -> None:
        publication_fixture.R4PublicationTests.tearDownClass()

    def setUp(self) -> None:
        self.fixture = publication_fixture.R4PublicationTests(
            methodName="test_prepare_assemble_and_independently_verify"
        )
        self.fixture.setUp()
        self._component_bundle_verifier = mock.patch.object(
            NEGATIVES.PUBLICATION.COMPONENT_RELEASE,
            "verify_bundle",
            side_effect=lambda root, _key, require_root_name=False: (
                NEGATIVES.PUBLICATION.digest_bytes(
                    (root / "release.json").read_bytes()
                )
            ),
        )
        self._component_bundle_verifier.start()
        self.staging = self.fixture.prepare()
        self.publication = NEGATIVES.PUBLICATION.assemble(
            self.staging,
            self.fixture.policy_path,
            self.fixture.release_public_key_path,
            self.fixture.signatures(self.staging, (0, 1)),
            self.fixture.root / "publication",
        )
        self.alternate = self.fixture.signatures(self.staging, (2,))[0]

    def tearDown(self) -> None:
        self._component_bundle_verifier.stop()
        self.fixture.tearDown()

    def test_all_mutations_execute_and_report_is_deterministic(self) -> None:
        report = NEGATIVES.run_controls(
            self.publication,
            self.fixture.policy_path,
            self.fixture.release_public_key_path,
            [self.alternate],
        )
        self.assertEqual(report["schema"], NEGATIVES.SCHEMA)
        self.assertEqual(set(report["controls"]), set(NEGATIVES.CONTROL_NAMES))
        self.assertTrue(all(report["controls"].values()))
        self.assertFalse(report["private_key_dependency"])
        self.assertEqual(report["blockers"], [])
        self.assertEqual(
            NEGATIVES.canonical_json(report),
            NEGATIVES.canonical_json(
                NEGATIVES.run_controls(
                    self.publication,
                    self.fixture.policy_path,
                    self.fixture.release_public_key_path,
                    [self.alternate],
                )
            ),
        )

        out = self.fixture.root / "publication-negatives.json"
        self.assertEqual(
            NEGATIVES.main(
                [
                    "--publication",
                    str(self.publication),
                    "--policy",
                    str(self.fixture.policy_path),
                    "--release-public-key",
                    str(self.fixture.release_public_key_path),
                    "--alternate-signature",
                    str(self.alternate),
                    "--out",
                    str(out),
                ]
            ),
            0,
        )
        self.assertEqual(out.read_bytes(), NEGATIVES.canonical_json(report))

    def test_alternate_valid_public_signature_is_mandatory_for_two_signature_root(
        self,
    ) -> None:
        with self.assertRaisesRegex(
            NEGATIVES.NegativeControlError, "no alternate valid signature inventory"
        ):
            NEGATIVES.run_controls(
                self.publication,
                self.fixture.policy_path,
                self.fixture.release_public_key_path,
                [],
            )

    def test_private_key_bytes_are_not_accepted_as_an_alternate_signature(self) -> None:
        with self.assertRaisesRegex(
            NEGATIVES.NegativeControlError, "cannot load alternate signature"
        ):
            NEGATIVES.run_controls(
                self.publication,
                self.fixture.policy_path,
                self.fixture.release_public_key_path,
                [self.fixture.private_keys[2]],
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
