# Acceptance Spec: `supervisor-run-history-comparison-ledger`

This scenario validates the durable run-history and comparison-ledger surface.

Expected behavior:

- repeated local runs appear in deterministic history order,
- comparison-ledger entries connect a newer run to an older local baseline when one exists,
- and the history surface stays linked to real evidence references rather than browser-only summaries.
