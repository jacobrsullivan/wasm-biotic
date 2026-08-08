from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest


SCRIPT = Path(__file__).with_name("r3-local-tls-peer.py")
SPEC = importlib.util.spec_from_file_location("r3_local_tls_peer", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class LocalTlsPeerTests(unittest.TestCase):
    def request(self, extra: bytes = b"") -> bytes:
        secret = b"fixture-secret-123456"
        body = b'{"schema":"test"}'
        return (
            b"POST /exchange HTTP/1.1\r\n"
            b"Host: 127.0.0.1:18443\r\n"
            b"Connection: close\r\n"
            b"content-type: application/json\r\n"
            b"authorization: Bearer "
            + secret
            + b"\r\nContent-Length: "
            + str(len(body)).encode()
            + b"\r\n"
            + extra
            + b"\r\n"
            + body
        )

    def test_exact_component_and_framing_headers_pass(self) -> None:
        facts = MODULE.inspect_request(
            self.request(), "127.0.0.1", 18443, "/exchange", b"fixture-secret-123456"
        )
        self.assertEqual(facts["result"], "pass")
        self.assertEqual(facts["body_size_bytes"], 17)

    def test_ambient_or_wrong_credential_headers_fail(self) -> None:
        with self.assertRaisesRegex(MODULE.PeerError, "header set differs"):
            MODULE.inspect_request(
                self.request(b"Accept: */*\r\n"),
                "127.0.0.1",
                18443,
                "/exchange",
                b"fixture-secret-123456",
            )
        with self.assertRaisesRegex(MODULE.PeerError, "credential injection"):
            MODULE.inspect_request(
                self.request(), "127.0.0.1", 18443, "/exchange", b"another-secret-value"
            )


if __name__ == "__main__":
    unittest.main()
