# CD-0001: Component factory contract v1

Status: accepted for the bounded local component graph  
Decision ID: `CD-0001-component-factory-contract-v1`

## Decision

The production contract is the typed component graph, not the transitional
native implementation's internal Rust state model. The native oracle remains a
differential reference for observable outcomes, authority boundaries and
failure behaviour. It is not a source of production factory roles or a hidden
fallback.

The component implementation deliberately replaces one generic native job
effect with six graph-bound worker stages. Consequently its internal state,
command and evidence digests are expected to differ. A difference is permitted
only when the frozen corpus identifies it and the differential report binds it
to this decision. Valid admission, terminal outcome class, content lineage and
fail-closed behaviour remain comparison obligations.

For capability routing, service-family ownership remains identical. The
component contract intentionally uses its four-class authority lattice and
operation-specific approval requirement. Where the old oracle differs, the
component value is authoritative and the exact row must appear in the report;
an unlisted difference fails the harness.

The component approval contract also adds cryptographic meaning absent from the
transitional oracle: an approval must carry an Ed25519 signature over the exact
length-delimited capability decision digest, and one approval ID may be reused
only for the identical stored binding. The native oracle remains useful for the
common idempotent-replay/conflicting-reuse behavior; its lack of a signer model
does not weaken the component requirement. The frozen report must bind the
compiled router bytes and enumerate valid first use, exact replay, altered
request reuse, forged signer and forged signature outcomes.

Exchange replay retains the shared externally observable rule: byte-exact
replay is idempotent and changed bytes under the same durable identity are a
conflict. The component exchange policy owns that classification. The native
coordinator journal is exercised only as a differential oracle and is not
reachable from production.

Lifecycle policy—promotion, observation, rollback and closure—must be executed
by components. Native lifecycle results are reference observations only. This
decision does not waive those corpus cases: they remain blockers until the
same-event differential report contains them.

For the bounded v1 differential contract, the common lifecycle observations
are initialization, successor activation, regressed observation, rollback to
the exact incumbent and restart preservation. The component artifact
additionally contains three completed full six-role cycles. The
transitional native deployment oracle has no six-role graph execution model;
agreement on the common transition classes plus exact component graph
provenance is therefore conformance, not a missing comparison.

Closure has the same deliberately versioned boundary. The compiled
closure-evaluator component decides over the six named component-complete
evidence classes, exact graph and native-TCB digests, declared blockers and a
non-external scope. The native closure-inventory evaluator is compared only for
the common `closed`/`not-yet` class on complete and incomplete evidence. Its
different private inventory model is neither imported into the component nor
treated as production policy.

Receipt comparison removes only the declared clock fields
`started_at_ms`, `finished_at_ms` and `committed_at_ms`. The report must consume
the exact component-issued initialization, activation and rollback receipts and
every six-role mechanism completion; validate unique receipt identities,
digests, executor provenance and graph bindings; and enumerate cardinality.
The component graph's three lifecycle receipts plus eighteen cycle receipts
intentionally differ from the native oracle's one generic effect receipt under
this decision. Equal committed/completed outcome classes and valid content
bindings are the shared contract; equal receipt count or receipt digest is not.

## Why

Byte-for-byte reproduction of native private state would preserve the old
control plane rather than replace it. What must remain compatible is the
declared contract and observable truth, while orchestration and policy move
into content-addressed components.

## Non-waivers

This decision does not permit:

- native domain dispatch or fallback;
- suppressing an unclassified mismatch;
- describing an untested category as equivalent;
- treating a hand-written report as execution without binding its exercised
  component bytes and test identity;
- converting a component failure into success; or
- claiming `component-complete` while the report says `report_complete=false`.
