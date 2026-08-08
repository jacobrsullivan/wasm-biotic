# Acceptance Spec: `supervisor-operator-runbook-steering-context`

This scenario validates durable operator runbook and steering context.

Expected behavior:

- governed operator actions are persisted as runbook entries,
- the latest steering context survives after the action completes,
- and the runbook remains local operator-support metadata linked to real runs and evidence.
