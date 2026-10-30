# Exchange service component

This component owns factory-to-factory envelope, expiry, signing, verification,
replay, revocation and optional transport policy. Native code receives only
generic blob, transaction, clock, HTTP and key operations.

Version 0.1.0 uses deterministic Ed25519 signatures over canonical compact JSON
envelope material. Optional HTTP delivery is performed before the durable
transfer commit and uses the same content-derived idempotency key on replay, so
a crash cannot authorize a different body. Receiving verifies signature,
expiry, artifact availability, revocation and replay state before committing.

The component does not import a shell, process, ambient filesystem, raw socket,
environment or credential bytes.

Run its host and compiled-component coverage from the repository root with
`./scripts/verify.sh components`. The verifier builds the ignored
`wasm32-wasip2` adapter fixture before running tests, so no hidden workspace
artifact is required.
