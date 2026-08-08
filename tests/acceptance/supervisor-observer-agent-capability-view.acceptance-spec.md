# Acceptance Spec: `supervisor-observer-agent-capability-view`

This scenario validates the Agent view as the main operator-facing role and capability view.

Expected behavior:

- the supervisor and worker paths are surfaced as distinct cards,
- capability, task, approval, and ownership state are visible from the live run model,
- and blocked approval state is legible without reconstructing raw events.
