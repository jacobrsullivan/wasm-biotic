# Factory evolution component

This component owns bounded graph-change proposal, exact-digest shadow
invocation and promotion assessment policy. It never builds or selects a
candidate in native code.

The v1 shadow profile deliberately admits only a pure, no-grant candidate
`component-task`; broader candidate authority requires a versioned policy
change. The generic native component runner verifies and meters the requested
digest but does not interpret the candidate, expected output or recommendation.

`component-task.run` is an adapter for `propose`; typed callers use `propose`,
`shadow` and `assess` directly.
