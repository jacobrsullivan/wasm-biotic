# Worker task blob ABI v1

This is the byte contract between the graph-owned worker router and every
worker's uniform `component-task.run` export. The native component runner sees
only blob references and component digests; it does not decode this document.

## Encoding

- Media type: `application/json`.
- Text encoding: UTF-8.
- Request schema: `wasm-biotic.worker-task-request.v1`.
- Response schema: `wasm-biotic.worker-task-response.v1`.
- Producers emit compact JSON with no insignificant whitespace and fields in
  the order below. The Rust reference encoder is `serde_json::to_vec` over the
  declared structs. This deterministic v1 representation, rather than a
  general-purpose JSON canonicalisation standard, defines the addressed bytes.
- Consumers reject malformed JSON, an unknown schema string and unknown object
  fields. Integers are JSON integers. Optional values are present and `null`
  when absent.
- Struct field names are `snake_case`. Enum names are lower-case kebab-case.
  A variant carrying data uses Serde's external form, for example
  `{"completed": { ...blob... }}`; a unit variant is a string such as
  `"cancelled"`.

## Request

```json
{
  "schema": "wasm-biotic.worker-task-request.v1",
  "request": {
    "execution_id": "execution-1",
    "job_id": "job-1",
    "role": "builder",
    "worker": {
      "id": "builder",
      "component_digest": { "algorithm": "sha256", "hex": "<64 lower-case hex>" }
    },
    "service_bindings": [
      {
        "family": "build",
        "component_digest": { "algorithm": "sha256", "hex": "<64 lower-case hex>" }
      }
    ],
    "input": {
      "content_digest": { "algorithm": "sha256", "hex": "<64 lower-case hex>" },
      "size_bytes": 8,
      "media_type": "application/octet-stream"
    },
    "checkpoint": null,
    "lease_digest": { "algorithm": "sha256", "hex": "<64 lower-case hex>" },
    "attempt": 1,
    "deadline_ms": null
  }
}
```

`role` is one of `planner`, `builder`, `validator`, `reviewer`, `packager`, or
`continuity-worker`. A worker rejects a request unless its role matches and its
service bindings are exactly those required by that role. Every digest is
`sha256` plus exactly 64 lower-case hexadecimal characters.

## Response

```json
{
  "schema": "wasm-biotic.worker-task-response.v1",
  "response": {
    "execution_id": "execution-1",
    "worker_component": { "algorithm": "sha256", "hex": "<64 lower-case hex>" },
    "outcome": {
      "completed": {
        "content_digest": { "algorithm": "sha256", "hex": "<64 lower-case hex>" },
        "size_bytes": 8,
        "media_type": "application/octet-stream"
      }
    },
    "checkpoint": null,
    "receipts": [],
    "evidence": []
  }
}
```

Worker outcomes are `{"completed": blob}`, `{"blocked": blob}`,
`{"rejected": failure}`, `{"failed": failure}`, or `"cancelled"`.

`failure` is
`{"code": string, "message": string, "retryable": boolean, "evidence": blob|null}`.
Each receipt is
`{"receipt_id": string, "request_digest": digest, "executor_digest": digest,
"started_at_ms": u64, "finished_at_ms": u64, "outcome_digest": digest,
"audit_sequence": u64}`. `evidence` is a list of blobs.

## Identity boundary

The router selects the worker from the activated graph and passes that exact
digest both to `component-runner.run-request.component-digest` and to
`request.worker.component_digest`. The native runner verifies the component
bytes against the former. The worker validates the digest's shape and returns
the latter unchanged as `response.worker_component`; the router must compare
the response to the activated graph identity. A component cannot securely hash
its own bytes, so byte-identity enforcement stays in the generic native
substrate while role and workflow validation stay in components.

