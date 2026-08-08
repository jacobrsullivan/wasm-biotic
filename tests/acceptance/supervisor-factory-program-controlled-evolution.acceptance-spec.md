# Supervisor Factory Program Controlled Evolution

## Goal

Prove that the local runtime can create a governed factory program as a first-class ledger entry, advance it through bounded later-factory campaigns, derive lineage health from recorded ticks, and stop cleanly at the configured recursion boundary.

## Acceptance Criteria

1. `POST /api/programs` creates a durable program spec and live instance rooted in one incumbent factory.
2. `POST /api/programs/{id}/tick` records governed campaign evidence and updates generation depth, campaign count, continuity, and incumbent selection.
3. Adopted ticks advance lineage depth; refused or rolled-back ticks preserve the incumbent while still consuming bounded campaign budget.
4. The runtime reconstructs recurring-program, lineage-ledger, regression-review, and longitudinal-lineage views from the stored program ticks.
5. When the configured recursion boundary is reached, further ticks fail closed with a bad-request posture.
6. Program state, receipts, and derived lineage views survive service reload from the same workspace.
