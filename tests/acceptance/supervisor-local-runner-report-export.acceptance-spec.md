# Acceptance Spec: `supervisor-local-runner-report-export`

This scenario validates the report-first local export bundle.

Expected behavior:

- a headless local run produces an exportable bundle,
- `summary.json`, `events.jsonl`, and `report.html` are present,
- and snapshot data for approvals, checkpoints, memory, promotion, and runtime state is persisted alongside the bundle.
