# Factory submit blob ABI v1

`factory-control.submit` accepts a content-addressed blob whose media type is
`application/json` and whose compact UTF-8 JSON has this shape:

```json
{
  "schema": "wasm-biotic.factory-submit.v1",
  "graph_digest": {
    "algorithm": "sha256",
    "hex": "<64 lower-case hexadecimal characters>"
  },
  "initial_state": {
    "schema": "wasm-biotic.supervisor-state.v1",
    "blob": {
      "content_digest": {
        "algorithm": "sha256",
        "hex": "<64 lower-case hexadecimal characters>"
      },
      "size_bytes": 1234,
      "media_type": "application/json"
    }
  },
  "source": {
    "content_digest": {
      "algorithm": "sha256",
      "hex": "<64 lower-case hexadecimal characters>"
    },
    "size_bytes": 5678,
    "media_type": "application/octet-stream"
  }
}
```

The initial supervisor state is itself an immutable blob so its exact bytes
remain independently content-addressed. It must bind the graph digest, all six
worker components and all seven service components. The imported supervisor
reducer validates that state before the driver journals or dispatches work.

The source digest determines the job identifier:

```text
job-sha256-<source SHA-256 hex>
```

All objects reject unknown fields. Digests use only SHA-256 and lower-case hex.
The root resolves and checks the exact size, media type and digest of the submit
blob, initial-state blob and source blob before proceeding.

Recovery uses a second versioned JSON blob:

```json
{
  "schema": "wasm-biotic.factory-recovery.v1",
  "job_id": "job-sha256-<source SHA-256 hex>"
}
```

Neither ABI tells native code how to run a factory. The generic blob and
transaction substrates store opaque bytes; this component owns their schemas.

