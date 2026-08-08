#!/usr/bin/env python3
"""One-shot TLS 1.3 peer for the exact signed R3 transport gate.

This is test infrastructure, not a factory service.  It accepts one HTTP/1.1
request, requires only the component-selected headers plus the three necessary
framing headers, checks the opaque credential injection without recording its
bytes, returns a bounded response, and exits.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import socket
import ssl
import sys
from typing import Any


class PeerError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PeerError(message)


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def read_request(connection: ssl.SSLSocket, maximum: int = 1_114_112) -> bytes:
    request = bytearray()
    terminal = -1
    while terminal < 0:
        require(len(request) < 65_536, "request head exceeds the fixture bound")
        chunk = connection.recv(4096)
        require(bool(chunk), "peer closed before the HTTP request head")
        request.extend(chunk)
        terminal = request.find(b"\r\n\r\n")
    head = bytes(request[:terminal])
    lines = head.split(b"\r\n")
    content_lengths = []
    for line in lines[1:]:
        name, separator, value = line.partition(b":")
        require(bool(separator), "request header has no delimiter")
        if name.lower() == b"content-length":
            content_lengths.append(value.strip())
    require(len(content_lengths) == 1, "request must have one content-length")
    require(content_lengths[0].isdigit(), "content-length is not decimal")
    length = int(content_lengths[0])
    require(length <= maximum, "request body exceeds the fixture bound")
    body_start = terminal + 4
    while len(request) - body_start < length:
        chunk = connection.recv(min(4096, length - (len(request) - body_start)))
        require(bool(chunk), "peer closed before the HTTP request body")
        request.extend(chunk)
    require(len(request) - body_start == length, "request contains bytes beyond content-length")
    return bytes(request)


def inspect_request(data: bytes, host: str, port: int, path: str, secret: bytes) -> dict[str, Any]:
    terminal = data.find(b"\r\n\r\n")
    require(terminal >= 0, "request head terminator is absent")
    head = data[:terminal]
    body = data[terminal + 4 :]
    lines = head.split(b"\r\n")
    require(lines[0] == f"POST {path} HTTP/1.1".encode(), "request line is not exact")
    headers: dict[str, bytes] = {}
    ordered_names: list[str] = []
    for line in lines[1:]:
        raw_name, separator, raw_value = line.partition(b":")
        require(bool(separator), "request header has no delimiter")
        try:
            name = raw_name.decode("ascii").lower()
        except UnicodeDecodeError as error:
            raise PeerError("request header name is not ASCII") from error
        require(name not in headers, f"duplicate request header {name!r}")
        headers[name] = raw_value.strip()
        ordered_names.append(name)
    expected_names = {"authorization", "connection", "content-length", "content-type", "host"}
    require(set(headers) == expected_names, f"request header set differs: {sorted(headers)}")
    require(headers["host"] == f"{host}:{port}".encode(), "Host is not exact")
    require(headers["connection"].lower() == b"close", "Connection is not close")
    require(headers["content-type"] == b"application/json", "Content-Type is not component selected")
    require(headers["authorization"] == b"Bearer " + secret, "credential injection is not exact")
    require(headers["content-length"] == str(len(body)).encode(), "Content-Length differs from body")
    require(bool(body), "exchange envelope body is empty")
    require(secret not in body, "credential bytes escaped into the exchange envelope body")
    require(
        all(secret not in value for name, value in headers.items() if name != "authorization"),
        "credential bytes escaped into a non-credential header",
    )
    json.loads(body)
    return {
        "body_sha256": "sha256:" + hashlib.sha256(body).hexdigest(),
        "body_size_bytes": len(body),
        "component_header_names": ["authorization", "content-type"],
        "credential_header_exact": True,
        "framing_header_names": ["connection", "content-length", "host"],
        "observed_header_order": ordered_names,
        "request_line": f"POST {path} HTTP/1.1",
        "result": "pass",
    }


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(description=__doc__)
    command.add_argument("--bind", default="127.0.0.1")
    command.add_argument("--port", type=int, required=True)
    command.add_argument("--path", default="/exchange")
    command.add_argument("--cert", type=Path, required=True)
    command.add_argument("--key", type=Path, required=True)
    command.add_argument("--secret-file", type=Path, required=True)
    command.add_argument("--ready-file", type=Path, required=True)
    command.add_argument("--report", type=Path, required=True)
    command.add_argument(
        "--accept-timeout-seconds",
        type=int,
        default=600,
        help="bounded wait for the exact release-gate client after slow component compilation",
    )
    return command


def main(arguments: list[str] | None = None) -> int:
    options = parser().parse_args(arguments)
    try:
        require(options.bind == "127.0.0.1", "release fixture binds only exact IPv4 loopback")
        require(1 <= options.port <= 65535, "port is outside the TCP range")
        require(
            1 <= options.accept_timeout_seconds <= 1800,
            "accept timeout is outside the release-fixture bound",
        )
        secret = options.secret_file.read_bytes()
        require(16 <= len(secret) <= 4096, "credential fixture length is outside the bound")
        require(b"\r" not in secret and b"\n" not in secret, "credential fixture is not a safe header value")

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(options.cert, options.key)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((options.bind, options.port))
            listener.listen(1)
            listener.settimeout(options.accept_timeout_seconds)
            options.ready_file.parent.mkdir(parents=True, exist_ok=True)
            options.ready_file.write_bytes(canonical_json({"port": options.port, "ready": True}))
            raw, _ = listener.accept()
            with raw:
                raw.settimeout(30)
                with context.wrap_socket(raw, server_side=True) as connection:
                    facts = inspect_request(
                        read_request(connection), options.bind, options.port, options.path, secret
                    )
                    response_body = b'{"accepted":true}'
                    connection.sendall(
                        b"HTTP/1.1 201 Created\r\n"
                        b"Content-Type: application/json\r\n"
                        + f"Content-Length: {len(response_body)}\r\n".encode()
                        + b"Connection: close\r\n\r\n"
                        + response_body
                    )
                    facts.update(
                        {
                            "schema": "wasm-biotic.r3-local-tls-peer-report.v1",
                            "tls_cipher": connection.cipher()[0] if connection.cipher() else None,
                            "tls_version": connection.version(),
                        }
                    )
        options.report.parent.mkdir(parents=True, exist_ok=True)
        options.report.write_bytes(canonical_json(facts))
        print("r3 local TLS peer: pass")
        return 0
    except (OSError, PeerError, ValueError, json.JSONDecodeError) as error:
        print(f"r3-local-tls-peer: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
