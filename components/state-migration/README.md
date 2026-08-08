# State migration component

This package owns the factory's version-to-version supervisor-state
transformation. It is a `wasm32-wasip2` Component Model implementation of
`state-migration-component`; no native migration code is involved.

The typed `migrate(document)` path is pure. The world also imports the generic
blob store solely for the uniform `component-task.run(blob-ref)` adapter. The
adapter reads exact input bytes, runs the same pure policy, and stores exact
output bytes. The host never sees or branches on the state schema.

Version `0.1.0` accepts the current `wasm-biotic.supervisor-state.v1` form and
the bounded predecessor `v0`. It canonicalizes v1 JSON and upgrades the v0
`sequence` field while creating only the empty runtime-ledger maps. It requires
and preserves the exact six worker and seven service digest bindings; it never
invents component identities. Unknown fields and unknown schema versions fail
closed.
