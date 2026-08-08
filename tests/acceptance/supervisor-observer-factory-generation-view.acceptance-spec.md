# Acceptance Spec: `supervisor-observer-factory-generation-view`

This scenario validates the Factory view as the main operator-facing generation view.

Expected behavior:

- the view exposes incumbent and challenger context,
- campaign, promotion, canary/release, quarantine, and rollback state are summarized together,
- and the rendered state is derived from current factory evidence rather than browser-local truth.
