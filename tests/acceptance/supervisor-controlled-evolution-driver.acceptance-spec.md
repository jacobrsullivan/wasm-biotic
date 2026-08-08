# Supervisor Controlled Evolution Driver

## Goal

Prove that the local runtime can launch the bounded controlled-evolution lineage in one operator action, without requiring one manual tick request per campaign.

## Acceptance Criteria

1. `POST /api/programs/controlled-evolution/drive` creates a fresh bounded factory program and advances the full built-in `G0 -> G1 -> rollback -> G2` sequence.
2. The final returned program view is `completed` with generation depth `2`, campaign count `3`, and incumbent factory `factory:g2`.
3. The returned program view carries the three stored tick receipts plus derived lineage, regression, and longitudinal lineage artifacts.
4. The driven program is visible in the general `/api/programs` ledger.
5. Program state and derived artifacts survive service reload from the same workspace.
