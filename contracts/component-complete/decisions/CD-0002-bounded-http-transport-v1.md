# CD-0002: Bounded HTTP transport v1

Status: accepted and frozen for the completed R3 release contract  
Decision ID: `CD-0002-bounded-http-transport-v1`

## Decision

R3 enables external HTTP only as a byte-transport mechanism. The enabled
factory remains a versioned, content-addressed graph of Wasm-Biotic components.
The native substrate may resolve, connect, authenticate the peer, meter bytes,
append a non-exportable credential, persist an operation and return opaque HTTP
status, header and body bytes. It may not implement a provider, request policy,
response meaning, retries, fallback, workflow or success policy.

The signed R3 closure uses:

- `wasm-biotic.factory-substrate-profile.v3`;
- the unchanged `wasm-biotic.component-derivation-descriptor.v2` principal and
  scoped-component provenance model;
- the unchanged shared `wasm-biotic.capability-constraints.v1` ceilings; and
- one separate `wasm-biotic.http-transport-constraints.v1` document conforming
  to
  [`http-transport-constraints-v1.schema.json`](../http-transport-constraints-v1.schema.json).

R2 profile bytes and meaning are unchanged. In a v1 or v2 substrate profile,
HTTP remains disabled even though the interface exists and its generic timeout
ceiling is present. Only the exact v3 mode and binding below may enable it.

## Profile v3 wire contract

`factory-substrate-profile.v3` retains every v2 field byte-for-byte in meaning:

```text
schema
wit_package
primitives
static_grant_model
root_node
import_alias_scheme
principal_id_scheme
principals
ceilings
```

It adds this closed member:

```json
{
  "http_transport": {
    "mode": "bounded-external",
    "bindings": [
      {
        "consumer": "exchange-service",
        "alias": "wasm-biotic:factory/host-<64-lowercase-hex>@0.1.0",
        "constraints": "sha256:<64-lowercase-hex>"
      }
    ]
  }
}
```

The canonical profile has exactly one R3 HTTP binding. It is the exact
projection of the `exchange-service` principal's `http-transport` host import:
the same consumer, generated alias and constraint digest. Bindings are unique
and sorted by `(consumer, alias, constraints)`. Missing, extra, reordered,
cross-consumer or digest-swapped bindings fail admission.

Every non-HTTP host import in the v3 principal inventory continues to reference
the digest of the exact canonical embedded `ceilings` document. The
`exchange-service` HTTP grant, principal import and v3 HTTP binding all
reference the separate HTTP constraint digest. There is no union grant,
canonical-import fallback or mutable alias lookup.

The component derivation descriptor remains v2 because R3 does not change the
raw-to-scoped rewrite, principal seed, alias derivation, static closure or
executable provenance algorithm. Inventing descriptor v3 would imply a change
that did not occur.

## HTTP constraint wire contract

The constraint object is closed: every object rejects unknown members. Its
fields are:

```text
schema
origins[]
methods[]
request_headers
response_headers
max_url_bytes
max_request_body_bytes
max_response_body_bytes
max_timeout_ms
max_concurrency
redirects
credential_bindings[]
```

An origin contains:

```text
id, scheme, host, port, path_prefixes[], dns, tls
```

Only canonical `https` origins are accepted. The host is lower-case ASCII or a
canonical IP spelling, the port is explicit and non-zero, and every path prefix
is an absolute visible-ASCII path without percent encoding, backslashes,
queries, fragments, repeated slashes or `.`/`..` segments. Origins are unique
by `(scheme, host, port)` and strictly sorted by `id`.

DNS is one of:

- `{"policy":"public-only","cidrs":[]}`; or
- `{"policy":"exact-cidrs","cidrs":[...]}`.

Exact CIDRs are non-empty, canonical network addresses with non-zero prefixes.
`0.0.0.0/0` and `::/0` are forbidden: broad public reach belongs to
`public-only`, while private, loopback or link-local reach requires explicit
reviewed ranges. At dispatch, every resolved address must pass the signed
policy, and the connection must be made to a checked address while preserving
the signed hostname. A later DNS answer cannot widen the grant.

TLS is exactly:

```json
{
  "minimum_version": "tls-1.3",
  "server_name": "the-exact-origin-host",
  "peer_spki_sha256": ["sha256:<64-lowercase-hex>"]
}
```

`server_name` must equal the origin host because the selected HTTP client uses
the URL host for hostname verification and SNI. At least one exact peer SPKI
pin is required. Pins are unique and sorted.

Methods use the closed lexical vocabulary `delete`, `get`, `head`, `patch`,
`post`, `put`; the array is non-empty, unique and wire-name sorted. Redirects
are always `deny`. Native redirect following, authentication discovery,
cookies, ambient proxies and automatic request replay are forbidden.

Request headers contain a closed lower-case allowlist plus positive count and
total-byte limits. The substrate rejects CR/LF and non-token names. These names
are forbidden even if a document attempts to allow them:

```text
connection
content-length
host
proxy-authorization
proxy-connection
te
trailer
transfer-encoding
upgrade
via
```

Response headers contain a closed lower-case exposure list plus positive count
and total-byte limits. Headers not on the exposure list do not enter component
memory. Status codes and permitted response bytes remain opaque to native
code; the component decides what they mean.

URL, body, timeout, header and concurrency bounds are positive. Timeout and
request/response body bounds cannot exceed the shared v1 ceiling that contains
the HTTP grant. The effective runtime bound is the intersection of these
signed limits and smaller operator capacity limits.

All arrays whose order does not carry meaning are canonical: origins by `id`,
methods by wire name, paths/header names/CIDRs/SPKI digests lexically, and
credential bindings by `(handle, origin_id, header_name)`. Duplicates or
non-canonical JSON bytes fail strict admission.

## Credential placement

A credential binding contains:

```json
{
  "handle": "exchange-api",
  "origin_id": "exchange-origin",
  "header_name": "authorization",
  "value_prefix": "Bearer ",
  "placement": "append-to-header-value"
}
```

The handle is an opaque non-secret identifier. The binding fixes its exact
origin and header placement. Each handle appears exactly once in the document;
one secret handle cannot authorize multiple origins or headers. The header must
be in the signed request allowlist and must not be a permanently forbidden
header. The visible-ASCII prefix is non-empty, so the component-authored
credential skeleton cannot disappear during HTTP normalization.

When the component requests this handle, it also supplies the named header
with a value exactly equal to the signed prefix. For the current exchange
component that is the non-secret `authorization: Bearer ` skeleton. Only after
URL, origin, DNS and TLS authorization may native credential custody append the
secret bytes. It must never replace component-authored request structure,
select another header, forward the credential to a redirect or expose the
secret through WIT values, blobs, journals, logs, receipts or audit bytes.

Operator configuration may disable or narrow transport, reduce concurrency or
other capacity, and declare whether a signed handle is available in credential
custody. It may not add an origin, method, header, CIDR, pin, handle binding or
credential placement absent from the signed constraint.

## WIT and operation semantics

The existing `http-transport` WIT already carries method, URL, headers, an
optional body blob, timeout, idempotency digest, optional credential handle,
operation ID, status, response headers/body and receipt. No ABI change is
required for R3, so the WIT package bytes remain unchanged.

One `start` is one durable dispatch attempt. The native substrate must not add
retries. Request meaning, provider choice, accounting, status interpretation,
parsing, retry, cancellation, fallback and terminal policy stay in the
`exchange-service` component. Native code returns 4xx, 5xx and malformed
application bodies as transport facts, not as provider-aware failures.

Operation and idempotency identity are qualified by exact graph digest,
principal seed and idempotency key and bind the exact request digest. Reuse with
changed bytes is a conflict. The request intent is durable before dispatch and
the terminal receipt is durable before later reduction. If a crash occurs
after bytes may have escaped but before a durable response fact exists, the
truthful result is an ambiguous non-retryable transport outcome; native code
must not silently redispatch. Cancellation is best-effort and cannot claim to
undo bytes already sent.

## Native non-authority

Permitted native decisions are limited to parsing the closed substrate
envelope, validating exact signed bytes and digests, resolving and filtering
addresses, enforcing TLS/pins/header/size/time/concurrency limits, using the
requested credential handle, dispatching bytes, persisting generic operation
facts and returning opaque transport bytes.

Native code must not contain or infer:

- provider or model identity;
- prompt or application request construction;
- response schemas or parsing;
- meaningful success status sets;
- retry, backoff, fallback or cancellation policy;
- budgets, accounting or workflow transitions; or
- a native service or role selected because the consumer is called
  `exchange-service`.

The offline graph validator may verify that the bounded R3 release assigns its
single enabled alias to the component whose manifest identity is
`exchange-service`. The runtime substrate treats the consumer, alias and digest
as opaque signed authority data.

## Admission and release consequences

The package writes both constraint documents at
`constraints/sha256-<digest>.json`. The shared ceiling is linked by all
non-HTTP grants. The HTTP document is linked independently by the exchange
grant, principal import and profile-v3 binding. The release certificate signs
both digests through its existing constraint closure; `package.json` and the
derivation descriptor formats do not change.

Changing an origin, pin, method, header, limit, credential placement, profile
mode or alias changes a content digest and therefore the graph/certificate
closure. Missing bytes, unknown fields, non-canonical order, a ceiling/profile
swap, an extra constraint, or a v1/v2 profile claiming enabled transport must
fail closed.

## R3 implementation disposition

R3 completed this decision for incumbent graph
`sha256:ef9c8aac3b08848d3df56d069df0df405251786e4afb3dd95e1098dd08195eb4`
and successor graph
`sha256:f98f2f8b6be93e3d9342472a54c08ffa7e976d49a796e8f300a116650d6bbebd`.
Their certificates bind HTTP constraint
`sha256:1c8129a9af4cd3fdd7d1a355de8f82182255d160ce65ddf2a6f499490f746bf8`,
compiled exchange component
`sha256:896c0760707a661933ad6f4af8c60e01a7cd6eb855545c586e161311d57c43f8`
and native TCB inventory
`sha256:3b7cf13a9308e94d4847d3cfceb80e6a4304f00482f4a83507091f4c24fbebf0`.

Production and independent substrates, exchange durability, adversarial
transport controls, exact signed dispatch/restart replay, lifecycle evidence
and reopened C0–C7 gates pass for the same closure. The signed aggregate
manifest is authoritative for report and bundle identities; it hashes this
decision, so the aggregate root is intentionally not copied here.

The qualification uses a deliberately exact pinned TLS peer and proves the
bounded mechanism, not a general provider. Enabling bounded transport does not
satisfy live-provider qualification, external custody, independent review,
publication authority or the external North Star. That broader claim remains
false.
