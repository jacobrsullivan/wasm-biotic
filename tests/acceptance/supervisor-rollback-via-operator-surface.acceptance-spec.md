# Acceptance Spec: `supervisor-rollback-via-operator-surface`

This scenario validates rollback handling through the local operator surface.

Expected behavior:

- a local run can surface quarantine and rollback availability,
- the HTTP operator surface can execute rollback,
- the run transitions into a rolled-back state,
- and rollback activity remains visible in the event and audit view.
