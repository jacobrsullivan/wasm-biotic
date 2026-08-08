#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("r3-http-constraints.py")
SPEC = importlib.util.spec_from_file_location("r3_http_constraints", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class Arguments:
    host = "127.0.0.1"
    port = 9443
    origin_id = "exchange-origin"
    path_prefix = "/exchange"
    public_only = False
    exact_cidr = ["127.0.0.1/32"]
    credential_handle = "exchange-api"
    max_url_bytes = 2048
    max_body_bytes = 1_048_576
    max_timeout_ms = 10_000
    max_concurrency = 2


class ConstraintGeneratorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.spki = Path(self.temporary.name) / "peer-spki.der"
        self.spki.write_bytes(b"public subject public key info")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def arguments(self) -> Arguments:
        value = Arguments()
        value.peer_spki_der = self.spki
        return value

    def test_exact_local_constraint_is_canonical_and_public_only_is_distinct(self) -> None:
        document = MODULE.build(self.arguments())
        payload = MODULE.canonical_json(document)
        self.assertEqual(payload, MODULE.canonical_json(json.loads(payload)))
        self.assertEqual(
            document["origins"][0]["tls"]["peer_spki_sha256"],
            ["sha256:" + hashlib.sha256(self.spki.read_bytes()).hexdigest()],
        )
        self.assertEqual(document["origins"][0]["dns"]["cidrs"], ["127.0.0.1/32"])
        self.assertEqual(document["credential_bindings"][0]["value_prefix"], "Bearer ")

        public = self.arguments()
        public.public_only = True
        public.exact_cidr = []
        public.host = "exchange.example"
        self.assertEqual(MODULE.build(public)["origins"][0]["dns"], {
            "policy": "public-only", "cidrs": []
        })

    def test_broad_noncanonical_and_unsafe_inputs_fail(self) -> None:
        cases = (
            ("exact_cidr", ["0.0.0.0/0"]),
            ("exact_cidr", ["127.0.0.2/8"]),
            ("path_prefix", "/exchange neighbor"),
            ("path_prefix", "/exchange/../secret"),
            ("host", "EXAMPLE.com"),
            ("credential_handle", "../secret"),
        )
        for field, value in cases:
            with self.subTest(field=field, value=value):
                arguments = self.arguments()
                setattr(arguments, field, value)
                with self.assertRaises(MODULE.ConstraintError):
                    MODULE.build(arguments)

    def test_python_network_parser_agrees_on_retained_exact_cidr(self) -> None:
        document = MODULE.build(self.arguments())
        cidr = document["origins"][0]["dns"]["cidrs"][0]
        self.assertEqual(str(ipaddress.ip_network(cidr, strict=True)), cidr)


if __name__ == "__main__":
    unittest.main()
