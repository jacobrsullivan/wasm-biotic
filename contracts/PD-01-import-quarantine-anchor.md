# PD-01 Import Quarantine Anchor

## 1. Purpose

This anchor freezes the minimum conceptual semantics for imported-artifact quarantine in Phase D.

## 2. Frozen Field Set

The quarantine packet must carry:

- `quarantine_packet_id`
- `exchange_ref`
- `affected_refs`
- `review_requirements`
- `rollback_refs`
- `summary`

## 3. Frozen Rules

- imported packets begin quarantined
- retained imported content must remain attributable to its envelope and compatibility context
- quarantine must preserve an explicit discard or rollback posture
- quarantine-first import remains local-first and pre-federation
