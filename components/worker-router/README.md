# Worker router component

The router converts the typed worker request to the versioned worker task blob
ABI, asks the generic substrate to run the exact graph-bound worker digest,
then decodes and verifies the typed response. Worker selection, per-role host
grant policy, limits and response identity checks therefore execute in this
component—not in native Rust.

The native runner sees only a digest, opaque blob reference, primitive grants,
resource ceilings and an idempotency digest. It rejects non-admitted bytes but
does not parse role, workflow or worker result meaning.
